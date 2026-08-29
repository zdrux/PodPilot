from __future__ import annotations

import httpx

from podpilot_openshift.agent_runner import OcAgentRunnerClient


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
        "timeout": None,
    }
