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
from uuid import UUID, uuid4


KUBECONFIG_PATH = Path("/tmp/podpilot-agent-kubeconfig")
RUNNER_STARTED_AT = time.monotonic()
ACTIVE_COMMANDS: dict[str, dict[str, object]] = {}
ACTIVE_COMMANDS_LOCK = threading.Lock()


def _positive_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


COMMAND_TIMEOUT_SECONDS = _positive_env("PODPILOT_AGENT_COMMAND_TIMEOUT_SECONDS", 300.0)
HEARTBEAT_SECONDS = _positive_env("PODPILOT_AGENT_HEARTBEAT_SECONDS", 10.0)
MAX_OUTPUT_BYTES = int(_positive_env("PODPILOT_AGENT_COMMAND_MAX_OUTPUT_BYTES", 262_144))


class _BoundedStreamCollector:
    def __init__(self, *, name: str, limit: int) -> None:
        self.name = name
        self.limit = limit
        self.retained = bytearray()
        self.total_bytes = 0

    def consume(self, stream) -> None:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            self.total_bytes += len(chunk)
            remaining = self.limit - len(self.retained)
            if remaining > 0:
                self.retained.extend(chunk[:remaining])

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self.retained)

    def text(self) -> str:
        rendered = bytes(self.retained).decode("utf-8", errors="replace")
        if not self.truncated:
            return rendered
        omitted = self.total_bytes - len(self.retained)
        marker = (
            f"\n[PodPilot oc-runner truncated {self.name} after {self.limit} bytes; "
            f"{omitted} additional bytes were discarded.]\n"
        )
        return rendered.rstrip() + marker


def _remote_kubeconfig(cluster: object) -> tuple[Path, str, str, bool]:
    if not isinstance(cluster, dict):
        raise ValueError("cluster must be an object")
    cluster_id = str(cluster.get("id") or "").strip()
    cluster_name = str(cluster.get("name") or "").strip()
    api_url = str(cluster.get("api_url") or "").strip()
    token = str(cluster.get("token") or "").strip()
    proxy_url = str(cluster.get("proxy_url") or "").strip()
    tls_verify = cluster.get("tls_verify")
    parsed = urlsplit(api_url)
    if (
        not cluster_id or not cluster_name
        or (
            proxy_url
            and not proxy_url.startswith("http://127.0.0.1:8080/internal/delegated-proxy/")
        )
        or (
            not proxy_url
            and (
                not token or parsed.scheme != "https" or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}
            )
        )
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
                    "server": proxy_url.rstrip("/") if proxy_url else api_url.rstrip("/"),
                    **({"insecure-skip-tls-verify": True} if proxy_url else {
                        "insecure-skip-tls-verify": not tls_verify,
                    }),
                },
            }],
            "users": [{"name": "target", "user": {}}] if proxy_url else [
                {"name": "target", "user": {"token": token}}
            ],
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


def _terminate_process_group(process: subprocess.Popen[bytes], request_id: str) -> None:
    _event("command_terminating", request_id=request_id, pid=process.pid)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _cancel_requested(request_id: str) -> bool:
    with ACTIVE_COMMANDS_LOCK:
        state = ACTIVE_COMMANDS.get(request_id)
        return bool(state and state.get("cancel_requested"))


def _run_command(
    command: str,
    env: dict[str, str],
    *,
    request_id: str,
    started: float,
) -> tuple[int, str, str, bool, int, int]:
    process = subprocess.Popen(
        ["/bin/bash", "-lc", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    with ACTIVE_COMMANDS_LOCK:
        state = ACTIVE_COMMANDS.get(request_id)
        if state is not None:
            state["process"] = process
            cancel_immediately = bool(state.get("cancel_requested"))
        else:
            cancel_immediately = False
    if cancel_immediately:
        _terminate_process_group(process, request_id)
    assert process.stdout is not None and process.stderr is not None
    stdout_collector = _BoundedStreamCollector(name="stdout", limit=MAX_OUTPUT_BYTES)
    stderr_collector = _BoundedStreamCollector(name="stderr", limit=MAX_OUTPUT_BYTES)
    collector_threads = [
        threading.Thread(
            target=stdout_collector.consume,
            args=(process.stdout,),
            name=f"runner-stdout-{request_id}",
            daemon=True,
        ),
        threading.Thread(
            target=stderr_collector.consume,
            args=(process.stderr,),
            name=f"runner-stderr-{request_id}",
            daemon=True,
        ),
    ]
    for collector_thread in collector_threads:
        collector_thread.start()
    timed_out = False
    while True:
        elapsed = time.monotonic() - started
        remaining = COMMAND_TIMEOUT_SECONDS - elapsed
        if remaining <= 0:
            timed_out = True
            _terminate_process_group(process, request_id)
            break
        try:
            process.wait(timeout=min(HEARTBEAT_SECONDS, remaining))
            break
        except subprocess.TimeoutExpired:
            continue
    for collector_thread in collector_threads:
        collector_thread.join(timeout=5)
    stdout = stdout_collector.text()
    stderr = stderr_collector.text()
    cancelled = _cancel_requested(request_id)
    exit_code = 130 if cancelled else (124 if timed_out else process.returncode)
    if timed_out:
        timeout_detail = (
            f"PodPilot oc-runner terminated the command after "
            f"{COMMAND_TIMEOUT_SECONDS:g} seconds."
        )
        stderr = f"{stderr.rstrip()}\n{timeout_detail}\n" if stderr else timeout_detail + "\n"
    elif cancelled:
        cancel_detail = "PodPilot oc-runner cancelled the command at the operator's request."
        stderr = f"{stderr.rstrip()}\n{cancel_detail}\n" if stderr else cancel_detail + "\n"
    return (
        exit_code,
        stdout,
        stderr,
        timed_out,
        stdout_collector.total_bytes,
        stderr_collector.total_bytes,
    )


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
            "command_max_output_bytes": MAX_OUTPUT_BYTES,
        })

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/cancel":
            self._cancel_command()
            return
        if self.path != "/v1/execute":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            command = payload["command"]
            if not isinstance(command, str) or not command.strip():
                raise ValueError("command must be a non-empty string")
            request_id = str(UUID(str(payload.get("request_id") or uuid4())))
            cluster_payload = payload["cluster"]
            if cluster_payload is None:
                raise ValueError("a brokered remote cluster connection is required")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        env = dict(os.environ)
        kubeconfig_path = KUBECONFIG_PATH
        cluster_id = ""
        cluster_name = ""
        tls_verify = True
        temporary_kubeconfig = False
        try:
            kubeconfig_path, cluster_id, cluster_name, tls_verify = _remote_kubeconfig(
                cluster_payload
            )
            temporary_kubeconfig = True
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        env["KUBECONFIG"] = str(kubeconfig_path)
        started = time.monotonic()
        with ACTIVE_COMMANDS_LOCK:
            if request_id in ACTIVE_COMMANDS:
                if temporary_kubeconfig:
                    kubeconfig_path.unlink(missing_ok=True)
                self._send_json(409, {"error": "request_id is already active"})
                return
            ACTIVE_COMMANDS[request_id] = {
                "cluster_id": cluster_id,
                "cluster_name": cluster_name,
                "started": started,
                "process": None,
                "cancel_requested": False,
            }
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
            exit_code, stdout, stderr, timed_out, stdout_bytes, stderr_bytes = _run_command(
                command,
                env,
                request_id=request_id,
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
        duration_ms = round((time.monotonic() - started) * 1000)
        cancelled = exit_code == 130
        _event(
            "command_complete",
            request_id=request_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            exit_code=exit_code,
            timed_out=timed_out,
            cancelled=cancelled,
            duration_ms=duration_ms,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_bytes > MAX_OUTPUT_BYTES,
            stderr_truncated=stderr_bytes > MAX_OUTPUT_BYTES,
        )
        self._send_json(
            200,
            {
                "request_id": request_id,
                "duration_ms": duration_ms,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": timed_out,
                "cancelled": cancelled,
                "stdout_truncated": stdout_bytes > MAX_OUTPUT_BYTES,
                "stderr_truncated": stderr_bytes > MAX_OUTPUT_BYTES,
            },
        )

    def _cancel_command(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            request_id = str(UUID(str(payload["request_id"])))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "request_id must be a UUID"})
            return
        with ACTIVE_COMMANDS_LOCK:
            state = ACTIVE_COMMANDS.get(request_id)
            if state is None:
                self._send_json(404, {"status": "not_found", "request_id": request_id})
                return
            state["cancel_requested"] = True
            process = state.get("process")
            cluster_id = str(state.get("cluster_id") or "")
            cluster_name = str(state.get("cluster_name") or "")
        _event(
            "command_cancel_requested",
            request_id=request_id,
            cluster_id=cluster_id,
            cluster_name=cluster_name,
        )
        if isinstance(process, subprocess.Popen) and process.poll() is None:
            _terminate_process_group(process, request_id)
        self._send_json(202, {
            "status": "cancellation_requested",
            "request_id": request_id,
        })

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
    _event(
        "runner_ready",
        bind="127.0.0.1:8090",
        service_account_access=False,
        remote_connections="api-brokered-per-command-only",
        command_timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        command_max_output_bytes=MAX_OUTPUT_BYTES,
        command_poll_seconds=HEARTBEAT_SECONDS,
    )
    ThreadingHTTPServer(("127.0.0.1", 8090), RunnerHandler).serve_forever()
