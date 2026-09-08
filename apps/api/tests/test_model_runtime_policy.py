import json
from dataclasses import replace

import httpx
import pytest
from datetime import datetime, timezone

from podpilot_api.model_provider import (
    ModelProfileConfig, ModelProviderError, _enforce_model_window,
    _estimated_serialized_tokens, _prepare_chat_input, _prepare_incident_payload,
    incident_evidence_batches,
)
from podpilot_diagnostics.incident_policy import IncidentPolicy
from podpilot_openshift.incidents import IncidentReader


def profile(**kwargs):
    return ModelProfileConfig(provider_label="test", base_url="https://model.test/v1",
        chat_model="test", embedding_model=None, timeout_seconds=30,
        max_output_tokens=16000, **kwargs)


def test_global_context_reserves_output_for_both_workflows():
    config = profile(max_input_tokens=128000)
    assert config.effective_input_tokens == 45952
    small = replace(config, context_window_tokens=8192, max_output_tokens=4096)
    assert small.effective_input_tokens == 2048
    with pytest.raises(ModelProviderError):
        _prepare_chat_input(small, [{"role": "system", "content": "instruction " * 10000}])
    with pytest.raises(ModelProviderError):
        _prepare_incident_payload(small, {"objective": "instruction " * 10000, "evidence": []})


@pytest.mark.parametrize("path,field", [("responses", "input"), ("chat/completions", "messages")])
def test_http_boundary_checks_both_provider_apis(path, field):
    config = profile(max_input_tokens=1024)
    request = httpx.Request("POST", f"https://model.test/v1/{path}",
        json={field: "oversized " * 2000, "max_output_tokens": 16000})
    with pytest.raises(ModelProviderError, match="global effective input budget"):
        _enforce_model_window(config, request)


def test_specialist_batches_preserve_all_collection_rows_and_source_ids():
    config = profile(max_input_tokens=3000)
    rows = [{"name": f"object-{index}", "message": "failure " * 80} for index in range(150)]
    item = {"id": "E7", "source": "nodes", "data": {"rows": rows}}
    batches = list(incident_evidence_batches(config, item))
    assert len(batches) > 1
    assert [row for batch in batches for row in batch["data"]["rows"]] == rows
    assert all(batch["id"] == "E7" for batch in batches)
    assert all(_estimated_serialized_tokens(batch) <= 2100 for batch in batches)
    assert item["data"]["rows"] == rows


def test_log_partitions_preserve_entire_stream():
    config = profile(max_input_tokens=3000)
    logs = "failure trace\n" * 5000
    batches = list(incident_evidence_batches(config, {"id": "E1", "data": {"logs": logs}}))
    assert len(batches) > 1
    assert "".join(batch["data"]["logs"] for batch in batches) == logs


def test_pagination_failure_retains_earlier_objects():
    calls = []
    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json={"items": [{"metadata": {"name": "first"}}],
                "metadata": {"continue": "opaque"}})
        assert request.url.params["continue"] == "opaque"
        return httpx.Response(503)
    reader = IncidentReader("https://cluster.test", "credential", transport=httpx.MockTransport(respond))
    result = reader.collect("nodes")
    assert result["rows"][0]["name"] == "first"
    assert result["partial"]
    assert "503" in result["limitations"][0]
    reader.close()


def test_collection_byte_ceiling_is_explicit():
    rows = [{"metadata": {"name": f"node-{i}"}, "status": {
        "conditions": [{"type": "Ready", "message": "x" * 4000}]}} for i in range(40)]
    reader = IncidentReader("https://cluster.test", "credential",
        policy=IncidentPolicy(max_collection_bytes=65536),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"items": rows})))
    result = reader.collect("nodes")
    assert 0 < len(result["rows"]) < len(rows)
    assert result["partial"]
    assert "65536-byte" in result["limitations"][0]
    reader.close()


def test_argocd_keeps_matches_after_sixty_unrelated_applications():
    items = [{"metadata": {"name": f"app-{i}"}, "spec": {"project": "platform",
        "destination": {"server": "https://other.test" if i < 65 else "https://target.test"}}}
        for i in range(105)]
    reader = IncidentReader("https://argo.test", "credential",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"items": items})))
    result = reader.argocd(["platform"], {"https://target.test"}, set(), datetime.now(timezone.utc))
    assert len(result["applications"]) == 40
    assert result["applications"][-1]["application"] == "app-104"
    assert result["partial"] is False
    reader.close()


def test_github_reads_all_pr_pages():
    def respond(request):
        if "/git/commits/" in request.url.path:
            return httpx.Response(200, json={"message": "Commit"})
        page = int(request.url.params["page"])
        return httpx.Response(200, json=[{"number": i, "title": f"PR {i}"}
            for i in range((page - 1) * 2 + 1, min(page * 2 + 1, 8))])
    reader = IncidentReader("https://git.test", "credential", policy=IncidentPolicy(page_size=2),
        transport=httpx.MockTransport(respond))
    result = reader.github("platform/config", "a" * 40, "")
    assert [item["number"] for item in result["pull_requests"]] == list(range(1, 8))
    assert result["partial"] is False
    reader.close()


def test_log_capabilities_are_not_capped_at_thirty_containers():
    items = [{"metadata": {"name": f"pod-{i}", "namespace": "team"},
        "spec": {"containers": [{"name": "app"}]}} for i in range(50)]
    reader = IncidentReader("https://cluster.test", "credential", namespaces=["team"],
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"items": items})))
    reader.collect("pods:team")
    assert len([key for key in reader.catalog() if key.startswith("logs:")]) == 50
    reader.close()
