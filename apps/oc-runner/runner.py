from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


KUBECONFIG_PATH = Path("/tmp/podpilot-agent-kubeconfig")
RUNNER_STARTED_AT = time.monotonic()
ACTIVE_COMMANDS: dict[str, tuple[str, str, float]] = {}
ACTIVE_COMMANDS_LOCK = threading.Lock()


def _positive_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


COMMAND_TIMEOUT_SECONDS = _positive_env("PODPILOT_AGENT_COMMAND_TIMEOUT_SECONDS", 300.0)
HEARTBEAT_SECONDS = _positive_env("PODPILOT_AGENT_HEARTBEAT_SECONDS", 10.0)


def _write_incluster_kubeconfig() -> None:
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    KUBECONFIG_PATH.write_text(
        "\n".join(
            (
                "apiVersion: v1",
                "kind: Config",
                "clusters:",
                "- name: in-cluster",
                "  cluster:",
                f"    server: https://{host}:{port}",
                "    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                "users:",
                "- name: pod-service-account",
                "  user:",
                "    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token",
                "contexts:",
                "- name: in-cluster",
                "  context:",
                "    cluster: in-cluster",
                "    user: pod-service-account",
                "current-context: in-cluster",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.chmod(KUBECONFIG_PATH, 0o600)


def _remote_kubeconfig(cluster: object) -> tuple[Path, str, str, bool]:
    if not isinstance(cluster, dict):
        raise ValueError("cluster must be an object")
    cluster_id = str(cluster.get("id") or "").strip()
    cluster_name = str(cluster.get("name") or "").strip()
    api_url = str(cluster.get("api_url") or "").strip()
    token = str(cluster.get("token") or "").strip()
    tls_verify = cluster.get("tls_verify")
    parsed = urlsplit(api_url)
    if (
        not cluster_id or not cluster_name or not token
        or parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("cluster connection is incomplete or invalid")
    if not isinstance(tls_verify, bool):
        raise ValueError("cluster tls_verify must be a boolean")
    fd, raw_path = tempfile.mkstemp(prefix="podpilot-agent-", suffix=".kubeconfig", dir="/tmp")
    path = Path(raw_path)
    stream_open = False
    try:
        config = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "name": "target",
                "cluster": {
                    "server": api_url.rstrip("/"),
                    "insecure-skip-tls-verify": not tls_verify,
                },
            }],
            "users": [{"name": "target", "user": {"token": token}}],
            "contexts": [{
                "name": "target",
                "context": {"cluster": "target", "user": "target"},
            }],
            "current-context": "target",
        }
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream_open = True
            json.dump(config, stream)
        os.chmod(path, 0o600)
    except Exception:
        if not stream_open:
            os.close(fd)
        path.unlink(missing_ok=True)
        raise
    return path, cluster_id, cluster_name, tls_verify


def _event(name: str, **details: object) -> None:
    print(json.dumps({"event": name, **details}, sort_keys=True), flush=True)


def _runner_heartbeat() -> None:
    while True:
        time.sleep(HEARTBEAT_SECONDS)
        now = time.monotonic()
        with ACTIVE_COMMANDS_LOCK:
            active = [
                {
                    "request_id": request_id,
                    "cluster_id": details[0],
                    "cluster_name": details[1],
                    "elapsed_seconds": round(now - details[2], 1),
                }
                for request_id, details in ACTIVE_COMMANDS.items()
            ]
        _event(
            "runner_heartbeat",
            uptime_seconds=round(now - RUNNER_STARTED_AT, 1),
            active_command_count=len(active),
            active_commands=active,
        )


def _terminate_process_group(process: subprocess.Popen[str], request_id: str) -> tuple[str, str]:
    _event("command_terminating", request_id=request_id, pid=process.pid)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.communicate()


def _run_command(
    command: str,
    env: dict[str, str],
    *,
    request_id: str,
    cluster_id: str,
    cluster_name: str,
    started: float,
) -> tuple[int, str, str, bool]:
    process = subprocess.Popen(
        ["/bin/bash", "-lc", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    timed_out = False
    while True:
        elapsed = time.monotonic() - started
        remaining = COMMAND_TIMEOUT_SECONDS - elapsed
        if remaining <= 0:
            timed_out = True
            stdout, stderr = _terminate_process_group(process, request_id)
            break
        try:
            stdout, stderr = process.communicate(
                timeout=min(HEARTBEAT_SECONDS, remaining)
            )
            break
        except subprocess.TimeoutExpired:
            _event(
                "command_heartbeat",
                request_id=request_id,
                cluster_id=cluster_id,
                cluster_name=cluster_name,
                elapsed_seconds=round(time.monotonic() - started, 1),
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            )
    exit_code = 124 if timed_out else process.returncode
    if timed_out:
        timeout_detail = (
            f"PodPilot oc-runner terminated the command after "
            f"{COMMAND_TIMEOUT_SECONDS:g} seconds."
        )
        stderr = f"{stderr.rstrip()}\n{timeout_detail}\n" if stderr else timeout_detail + "\n"
    return exit_code, stdout, stderr, timed_out


class RunnerHandler(BaseHTTPRequestHandler):
    server_version = "PodPilotOcRunner/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self.send_error(404)
            return
        with ACTIVE_COMMANDS_LOCK:
            active_count = len(ACTIVE_COMMANDS)
        self._send_json(200, {
            "status": "ok",
            "uptime_seconds": round(time.monotonic() - RUNNER_STARTED_AT, 1),
            "active_commands": active_count,
            "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        })

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/execute":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            command = payload["command"]
            if not isinstance(command, str) or not command.strip():
                raise ValueError("command must be a non-empty string")
            cluster_payload = payload.get("cluster")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        env = dict(os.environ)
        kubeconfig_path = KUBECONFIG_PATH
        cluster_id = "runtime"
        cluster_name = "Runtime cluster"
        tls_verify = True
        temporary_kubeconfig = False
        try:
            if cluster_payload is not None:
                kubeconfig_path, cluster_id, cluster_name, tls_verify = _remote_kubeconfig(
                    cluster_payload
                )
                temporary_kubeconfig = True
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        env["KUBECONFIG"] = str(kubeconfig_path)
        request_id = str(uuid4())
        started = time.monotonic()
        with ACTIVE_COMMANDS_LOCK:
            ACTIVE_COMMANDS[request_id] = (cluster_id, cluster_name, started)
        _event(
            "command_start",
            request_id=request_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            tls_verify=tls_verify,
            command_bytes=len(command.encode("utf-8", errors="replace")),
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )
        try:
            exit_code, stdout, stderr, timed_out = _run_command(
                command,
                env,
                request_id=request_id,
                cluster_id=cluster_id,
                cluster_name=cluster_name,
                started=started,
            )
        except OSError as exc:
            _event(
                "command_error",
                request_id=request_id,
                cluster_id=cluster_id,
                cluster_name=cluster_name,
                error_type=type(exc).__name__,
            )
            self._send_json(500, {"error": f"command execution failed ({type(exc).__name__})"})
            return
        finally:
            with ACTIVE_COMMANDS_LOCK:
                ACTIVE_COMMANDS.pop(request_id, None)
            if temporary_kubeconfig:
                kubeconfig_path.unlink(missing_ok=True)
        _event(
            "command_complete",
            request_id=request_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            exit_code=exit_code,
            timed_out=timed_out,
            duration_ms=round((time.monotonic() - started) * 1000),
            stdout_bytes=len(stdout.encode("utf-8", errors="replace")),
            stderr_bytes=len(stderr.encode("utf-8", errors="replace")),
        )
        self._send_json(
            200,
            {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": timed_out,
            },
        )

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    _write_incluster_kubeconfig()
    _event(
        "runner_ready",
        bind="127.0.0.1:8090",
        runtime_cluster_tls_verify=True,
        remote_connections="api-brokered-per-command",
        command_timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        heartbeat_seconds=HEARTBEAT_SECONDS,
    )
    threading.Thread(target=_runner_heartbeat, name="runner-heartbeat", daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8090), RunnerHandler).serve_forever()
