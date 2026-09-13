import asyncio
import json
from types import SimpleNamespace

import pytest

from podpilot_api.ask_logs import AskLogAnalyst, LogExcerptCache, log_mode
from podpilot_api.model_provider import AdHocLogAnalysis, ModelProfileConfig
from podpilot_diagnostics.adhoc import ReadIntent


PROFILE = ModelProfileConfig(provider_label="test", base_url="https://model.invalid",
                            chat_model="test", embedding_model=None,
                            timeout_seconds=60, max_output_tokens=3000)


@pytest.mark.parametrize("question,expected", [
    ("Show me the logs in pod dns-1", "display"),
    ("last 50 lines of logs", "display"),
    ("Check the 20 DNS pods for errors", "analyze"),
    ("Show me why pod dns-1 is crashing", "analyze"),
])
def test_log_routing(question, expected):
    assert log_mode(ReadIntent(tool="pod_logs"), question) == expected


def test_cache_expiry_eviction_and_byte_bound():
    now = [100]
    cache = LogExcerptCache(max_bytes=8, ttl_seconds=10, clock=lambda: now[0])
    first = cache.put("12345")
    second = cache.put("67890")
    assert cache.get(first["id"]) is None
    assert cache.get(second["id"]) == "67890"
    assert cache.size <= 8
    now[0] = 111
    assert cache.get(second["id"]) is None
    assert cache.size == 0


def process(analyst, observations, provider, mode="analyze"):
    return asyncio.run(analyst.process(
        observations, intent=ReadIntent(tool="pod_logs", log_mode=mode),
        question="Check DNS pods for errors", provider=provider, profile=PROFILE, api_key="test",
    ))


def test_twenty_pods_are_isolated_and_raw_loki_entries_never_reach_coordinator():
    cache = LogExcerptCache()
    analyst = AskLogAnalyst(cache)
    calls = []

    def analyze(profile, key, context):
        calls.append(context)
        assert len(context["logs"]) == 1
        assert "history" not in context
        assert profile.max_retries == 0
        return AdHocLogAnalysis(overview="No anomalies in the supplied excerpt.")

    observations = [{"id": f"log-{n}", "tool": "pod_logs", "source": f"pod/dns-{n}",
                     "data": {"tail": f"raw-unique-{n}\n" * 1000,
                              "entries": [{"message": f"raw-unique-{n}"}]}}
                    for n in range(20)]
    results, limitations = process(analyst, observations, SimpleNamespace(analyze_logs=analyze))
    assert len(calls) == 20
    assert not limitations
    assert "raw-unique" not in json.dumps(results)
    assert len(json.dumps(results)) < 16000
    for n, result in enumerate(results):
        ref = result["data"]["raw_log_excerpt"]
        assert cache.get(ref["id"]) == observations[n]["data"]["tail"]
        assert result["data"]["log_analysis"]["status"] == "completed"


@pytest.mark.parametrize("failure", ["exception", "fabricated_quote", "budget"])
def test_failed_or_skipped_analysis_retains_logs_without_raw_context_fallback(failure):
    def analyze(*args):
        if failure == "exception":
            raise RuntimeError("untrusted provider error")
        return SimpleNamespace(model_dump=lambda: {
            "overview": "Invented finding", "issues": [{"evidence_ids": ["log-1"],
            "supporting_excerpt": "not in supplied logs"}],
        })

    cache = LogExcerptCache()
    analyst = AskLogAnalyst(cache, max_calls=0 if failure == "budget" else 20)
    results, limitations = process(analyst, [{"id": "log-1", "tool": "pod_logs",
        "data": {"tail": "raw evidence"}}], SimpleNamespace(analyze_logs=analyze))
    assert limitations
    assert "raw evidence" not in json.dumps(results)
    assert cache.get(results[0]["data"]["raw_log_excerpt"]["id"]) == "raw evidence"
    assert results[0]["data"]["log_analysis"]["status"] == "unavailable"


def test_direct_display_preserves_lines_without_model_call():
    observation = {"id": "log-1", "tool": "pod_logs", "data": {"tail": "line one\nline two"}}
    results, limitations = process(AskLogAnalyst(), [observation], object(), mode="display")
    assert results == [observation]
    assert not limitations


def test_explicit_viewing_line_count_is_preserved_when_planner_omits_it():
    from podpilot_api.ask_logs import prepare_log_intent
    intent = ReadIntent(tool="pod_logs")
    assert prepare_log_intent(intent, "Show the last 50 lines of logs").tail_lines == 50
    assert prepare_log_intent(intent, "Check the last 50 lines for errors").tail_lines is None


def test_specialist_progress_names_four_targets_without_implying_twenty_pods():
    messages = []
    async def progress(phase, message):
        messages.append(message)
    async def run():
        analyst = AskLogAnalyst()
        provider = SimpleNamespace(analyze_logs=lambda *args: AdHocLogAnalysis(overview="No anomalies."))
        for n in range(4):
            await analyst.process([{"id": f"log-{n}", "tool": "pod_logs", "data": {"tail": "healthy"}}],
                intent=ReadIntent(tool="pod_logs", namespace="marketplace", name=f"running-{n}", container="app"),
                question="Check the four running pods", provider=provider, profile=PROFILE, api_key="test",
                progress=progress)
    asyncio.run(run())
    assert len(messages) == 4
    assert all(f"marketplace/running-{n}" in message for n, message in enumerate(messages))
    assert all("/20" not in message and "container app" in message for message in messages)
