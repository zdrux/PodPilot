from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from podpilot_openshift.agent_runner import (
    AgentClusterConnection,
    AgentRunnerError,
    OcAgentRunnerClient,
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
    result = OcAgentRunnerClient("http://127.0.0.1:8090/").execute("oc get pods")

    assert result.exit_code == 0
    assert result.stdout == "pod-a\n"
    assert captured == {
        "url": "http://127.0.0.1:8090/v1/execute",
        "json": {"command": "oc get pods"},
        "timeout": 310.0,
    }


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
    )

    assert result.stdout == "kafka-a\n"
    assert captured["json"] == {
        "command": "oc get kafka -A",
        "cluster": {
            "id": "cluster-east",
            "name": "East DEV",
            "api_url": "https://api.east.example:6443",
            "token": "sensitive-token",
            "tls_verify": False,
        },
    }


def test_agent_runner_client_preserves_runner_diagnostics(monkeypatch) -> None:
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
    result = OcAgentRunnerClient("http://127.0.0.1:8090").execute("oc get pods")

    assert result.request_id == "runner-request-1"
    assert result.duration_ms == 812
    assert result.stdout_truncated is True
    assert result.stderr_truncated is False
    assert result.timed_out is False


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
