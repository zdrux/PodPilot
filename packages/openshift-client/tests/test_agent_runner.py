from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest

from podpilot_openshift.agent_runner import (
    AgentClusterConnection,
    AgentRunnerError,
    OcAgentRunnerClient,
    strip_managed_fields_from_yaml_output,
)


def _runner_module():
    path = Path(__file__).resolve().parents[3] / "apps" / "oc-runner" / "runner.py"
    spec = importlib.util.spec_from_file_location("podpilot_oc_runner_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_runner_client_returns_unbounded_command_result(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, *, json, timeout):
        captured.update({"url": url, "json": json, "timeout": timeout})
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            request=request,
            json={"exit_code": 0, "stdout": "pod-a\n", "stderr": ""},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    result = OcAgentRunnerClient("http://127.0.0.1:8090/").execute(
        "oc get pods",
        request_id="00000000-0000-0000-0000-000000000101",
    )

    assert result.exit_code == 0
    assert result.stdout == "pod-a\n"
    assert captured == {
        "url": "http://127.0.0.1:8090/v1/execute",
        "json": {
            "command": "oc get pods",
            "request_id": "00000000-0000-0000-0000-000000000101",
        },
        "timeout": 310.0,
    }


def test_yaml_get_output_strips_managed_fields_from_objects_and_list_items() -> None:
    output = """apiVersion: v1
kind: List
metadata:
  managedFields:
  - manager: cluster
items:
- apiVersion: v1
  kind: Pod
  metadata:
    name: pod-a
    managedFields:
    - manager: kubelet
  status:
    phase: Running
"""

    compact = strip_managed_fields_from_yaml_output(
        "oc get pods -n payments -o yaml", output,
    )

    assert "managedFields" not in compact
    assert "name: pod-a" in compact
    assert "phase: Running" in compact


@pytest.mark.parametrize("command", [
    "oc get pods -o json",
    "oc create configmap example --dry-run=client -o yaml",
    "printf 'metadata: managedFields'",
])
def test_non_get_yaml_output_is_not_rewritten(command: str) -> None:
    output = "metadata:\n  managedFields:\n  - manager: retained\n"

    assert strip_managed_fields_from_yaml_output(command, output) == output


def test_agent_runner_client_brokers_one_remote_cluster_credential(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, *, json, timeout):
        captured.update({"url": url, "json": json, "timeout": timeout})
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            request=request,
            json={"exit_code": 0, "stdout": "kafka-a\n", "stderr": ""},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    connection = AgentClusterConnection(
        cluster_id="cluster-east",
        cluster_name="East DEV",
        api_url="https://api.east.example:6443",
        token="sensitive-token",
        tls_verify=False,
    )
    result = OcAgentRunnerClient("http://127.0.0.1:8090").execute(
        "oc get kafka -A",
        connection,
        request_id="00000000-0000-0000-0000-000000000102",
    )

    assert result.stdout == "kafka-a\n"
    assert captured["json"] == {
        "command": "oc get kafka -A",
        "request_id": "00000000-0000-0000-0000-000000000102",
        "cluster": {
            "id": "cluster-east",
            "name": "East DEV",
            "api_url": "https://api.east.example:6443",
            "token": "sensitive-token",
            "tls_verify": False,
        },
    }


def test_agent_runner_client_requests_correlated_command_cancellation(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, *, json, timeout):
        captured.update({"url": url, "json": json, "timeout": timeout})
        return httpx.Response(
            202,
            request=httpx.Request("POST", url),
            json={
                "status": "cancellation_requested",
                "request_id": json["request_id"],
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    cancelled = OcAgentRunnerClient("http://127.0.0.1:8090").cancel(
        "00000000-0000-0000-0000-000000000103"
    )

    assert cancelled is True
    assert captured == {
        "url": "http://127.0.0.1:8090/v1/cancel",
        "json": {"request_id": "00000000-0000-0000-0000-000000000103"},
        "timeout": 10.0,
    }


def test_runner_cancel_endpoint_marks_only_the_correlated_command() -> None:
    runner = _runner_module()
    request_id = "00000000-0000-0000-0000-000000000105"
    other_request_id = "00000000-0000-0000-0000-000000000106"
    runner.ACTIVE_COMMANDS[request_id] = {
        "cluster_id": "cluster-east",
        "cluster_name": "East DEV",
        "started": time.monotonic(),
        "process": None,
        "cancel_requested": False,
    }
    runner.ACTIVE_COMMANDS[other_request_id] = {
        "cluster_id": "cluster-central",
        "cluster_name": "Central DEV",
        "started": time.monotonic(),
        "process": None,
        "cancel_requested": False,
    }
    server = runner.ThreadingHTTPServer(("127.0.0.1", 0), runner.RunnerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        host, port = server.server_address
        response = httpx.post(
            f"http://{host}:{port}/v1/cancel",
            json={"request_id": request_id},
            timeout=2,
        )
        assert response.status_code == 202
        assert response.json()["status"] == "cancellation_requested"
        assert runner.ACTIVE_COMMANDS[request_id]["cancel_requested"] is True
        assert runner.ACTIVE_COMMANDS[other_request_id]["cancel_requested"] is False
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        runner.ACTIVE_COMMANDS.clear()


def test_agent_runner_client_sends_capability_without_delegated_token(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url, *, json, timeout):
        captured["payload"] = json
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"exit_code": 0, "stdout": "ok\n", "stderr": ""},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    connection = AgentClusterConnection(
        cluster_id="cluster-east",
        cluster_name="East DEV",
        api_url="https://api.east.example:6443",
        tls_verify=True,
        proxy_url=(
            "http://127.0.0.1:8080/internal/delegated-proxy/"
            "opaque-capability"
        ),
    )

    OcAgentRunnerClient("http://127.0.0.1:8090").execute("oc apply -f object.yaml", connection)

    serialized = json.dumps(captured["payload"])
    assert "token" not in serialized
    assert "api.east.example" not in serialized
    assert "opaque-capability" in serialized


def test_agent_runner_client_preserves_runner_diagnostics(monkeypatch, caplog) -> None:
    def fake_post(url, *, json, timeout):
        request = httpx.Request("POST", url)
        return httpx.Response(200, request=request, json={
            "request_id": "runner-request-1",
            "duration_ms": 812,
            "exit_code": 1,
            "stdout": "partial",
            "stderr": "oc: forbidden",
            "timed_out": False,
            "stdout_truncated": True,
            "stderr_truncated": False,
        })

    monkeypatch.setattr(httpx, "post", fake_post)
    caplog.set_level("INFO", logger="podpilot_openshift.agent_runner")
    result = OcAgentRunnerClient("http://127.0.0.1:8090").execute("oc get pods")

    assert result.request_id == "runner-request-1"
    assert result.duration_ms == 812
    assert result.stdout_truncated is True
    assert result.stderr_truncated is False
    assert result.timed_out is False
    assert "status_code=200" in caplog.text
    assert "response_bytes=" in caplog.text


def test_agent_runner_client_surfaces_redacted_http_failure(monkeypatch) -> None:
    def fake_post(url, *, json, timeout):
        request = httpx.Request("POST", url)
        return httpx.Response(
            400,
            request=request,
            json={"error": "invalid token=sensitive-token"},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    with pytest.raises(AgentRunnerError, match=r"HTTP 400.*token=\[REDACTED\]"):
        OcAgentRunnerClient("http://127.0.0.1:8090").execute("oc get pods")


def test_agent_runner_client_logs_http_failure_status_without_body(monkeypatch, caplog) -> None:
    body = "token=sensitive-token " + ("router unavailable " * 300)
    caplog.set_level("INFO", logger="podpilot_openshift.agent_runner")

    def fake_post(url, *, json, timeout):
        return httpx.Response(
            503,
            request=httpx.Request("POST", url),
            text=body,
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    with pytest.raises(AgentRunnerError, match=r"HTTP 503"):
        OcAgentRunnerClient("http://127.0.0.1:8090").execute(
            "oc get pods",
            request_id="00000000-0000-0000-0000-000000000107",
        )

    assert "status_code=503" in caplog.text
    assert "sensitive-token" not in caplog.text
    assert "response_preview" not in caplog.text


def test_remote_runner_kubeconfig_disables_tls_and_is_removable() -> None:
    runner = _runner_module()
    path, cluster_id, cluster_name, tls_verify = runner._remote_kubeconfig({
        "id": "cluster-east",
        "name": "East DEV",
        "api_url": "https://api.east.example:6443",
        "token": "sensitive-token",
        "tls_verify": False,
    })
    try:
        payload = json.loads(path.read_text())
        assert cluster_id == "cluster-east"
        assert cluster_name == "East DEV"
        assert tls_verify is False
        assert payload["clusters"][0]["cluster"] == {
            "server": "https://api.east.example:6443",
            "insecure-skip-tls-verify": True,
        }
        assert payload["users"][0]["user"]["token"] == "sensitive-token"
    finally:
        path.unlink(missing_ok=True)
    assert not path.exists()


def test_remote_runner_rejects_plain_http_cluster() -> None:
    runner = _runner_module()
    with pytest.raises(ValueError, match="invalid"):
        runner._remote_kubeconfig({
            "id": "cluster-east",
            "name": "East DEV",
            "api_url": "http://api.east.example:6443",
            "token": "sensitive-token",
            "tls_verify": False,
        })


def test_remote_runner_builds_tokenless_delegated_proxy_kubeconfig() -> None:
    runner = _runner_module()
    path, _, _, _ = runner._remote_kubeconfig({
        "id": "cluster-east",
        "name": "East DEV",
        "proxy_url": (
            "http://127.0.0.1:8080/internal/delegated-proxy/opaque-capability"
        ),
        "tls_verify": True,
    })
    try:
        payload = json.loads(path.read_text())
        assert payload["clusters"][0]["cluster"]["server"].endswith("opaque-capability")
        assert payload["users"][0]["user"] == {}
        assert "token" not in path.read_text()
    finally:
        path.unlink(missing_ok=True)


def test_runner_polls_silently_and_terminates_timed_out_process_group(monkeypatch) -> None:
    runner = _runner_module()
    events: list[tuple[str, dict[str, object]]] = []

    class FakeProcess:
        pid = 4321
        returncode = -15
        terminated = False
        stdout = io.BytesIO(b"partial output")
        stderr = io.BytesIO(b"terminated")

        def wait(self, timeout=None):
            if self.terminated:
                return self.returncode
            raise subprocess.TimeoutExpired(cmd="synthetic", timeout=timeout)

    process = FakeProcess()
    monkeypatch.setattr(runner, "COMMAND_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(runner, "HEARTBEAT_SECONDS", 0.001)
    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", 8)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: setattr(process, "terminated", True),
        raising=False,
    )
    monkeypatch.setattr(
        runner,
        "_event",
        lambda name, **details: events.append((name, details)),
    )

    exit_code, stdout, stderr, timed_out, stdout_bytes, stderr_bytes = runner._run_command(
        "sleep forever",
        {},
        request_id="request-1",
        started=time.monotonic(),
    )

    assert exit_code == 124
    assert stdout.startswith("partial")
    assert "truncated stdout" in stdout
    assert "terminated the command" in stderr
    assert timed_out is True
    assert stdout_bytes == len(b"partial output")
    assert stderr_bytes == len(b"terminated")
    assert not any("heartbeat" in name for name, _ in events)
    assert any(name == "command_terminating" for name, _ in events)
