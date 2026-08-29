from __future__ import annotations

import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


KUBECONFIG_PATH = Path("/tmp/podpilot-agent-kubeconfig")


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


class RunnerHandler(BaseHTTPRequestHandler):
    server_version = "PodPilotOcRunner/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self.send_error(404)
            return
        self._send_json(200, {"status": "ok"})

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
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        env = dict(os.environ)
        env["KUBECONFIG"] = str(KUBECONFIG_PATH)
        completed = subprocess.run(
            ["/bin/bash", "-lc", command],
            capture_output=True,
            check=False,
            env=env,
            text=True,
            errors="replace",
        )
        self._send_json(
            200,
            {
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
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
    ThreadingHTTPServer(("127.0.0.1", 8090), RunnerHandler).serve_forever()
