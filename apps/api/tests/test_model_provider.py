import json
from types import SimpleNamespace

import pytest

from podpilot_api.model_provider import (
    AdHocAnswer,
    CapabilityReport,
    ModelProfileConfig,
    ModelProviderError,
    OpenAIChatCompletionsProvider,
    OpenAIProviderRouter,
)
from podpilot_diagnostics.adhoc import ReadPlan


def profile(**overrides) -> ModelProfileConfig:
    values = {
        "provider_label": "Enterprise gateway",
        "base_url": "https://models.example.test/v1",
        "chat_model": "gemma-4-31b-it",
        "embedding_model": None,
        "timeout_seconds": 30,
        "max_output_tokens": 1000,
        "api_type": "chat-completions",
    }
    values.update(overrides)
    return ModelProfileConfig(**values)


class RecordingCompletions:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        content = json.dumps({
            "answer_mode": "evidence_based",
            "answer": "The supplied Pod is pending.",
            "cited_evidence_ids": ["cluster-pod-1"],
            "limitations": [],
        })
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


class InvalidPlanCompletions:
    def create(self, **_kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
                "scope_summary": "",
                "intents": [],
                "limitations": [],
            })))]
        )


class CorrectingPlanCompletions:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if len(self.requests) == 1:
            content = json.dumps({"scope_summary": "", "intents": [], "limitations": []})
        else:
            content = json.dumps({
                "scope_summary": "No cluster reads are needed.",
                "intents": [],
                "limitations": [],
            })
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


class MissingSummaryPlanCompletions:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        content = json.dumps({"intents": [], "limitations": []})
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


def test_chat_completions_adapter_requests_and_validates_strict_json_schema() -> None:
    completions = RecordingCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIChatCompletionsProvider()
    provider._client = lambda _profile, _key: client  # type: ignore[method-assign]

    answer = provider.answer_ad_hoc(
        profile(), "secret-token", {"observations": [{"id": "cluster-pod-1"}]}
    )

    assert isinstance(answer, AdHocAnswer)
    assert answer.cited_evidence_ids == ["cluster-pod-1"]
    request = completions.requests[0]
    assert request["model"] == "gemma-4-31b-it"
    assert request["response_format"]["type"] == "json_schema"
    assert request["response_format"]["json_schema"]["strict"] is True
    assert request["max_tokens"] == 1000


def test_router_selects_chat_completions_for_catalog_api_type() -> None:
    router = OpenAIProviderRouter()
    assert router._provider(profile()) is router.chat_completions
    assert router._provider(profile(api_type="responses")) is router.responses


def test_invalid_custom_ca_is_reported_as_provider_error() -> None:
    provider = OpenAIChatCompletionsProvider()
    with pytest.raises(ModelProviderError, match="TLS configuration is invalid"):
        provider._client(
            profile(tls_mode="custom_ca", custom_ca_pem="not a certificate"),
            "secret-token",
        )


def test_chat_completions_schema_failure_names_contract_without_echoing_content() -> None:
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=InvalidPlanCompletions())
    )
    provider = OpenAIChatCompletionsProvider()
    provider._client = lambda _profile, _key: client  # type: ignore[method-assign]

    with pytest.raises(ModelProviderError) as caught:
        provider.plan_ad_hoc(profile(), "secret-token", {"question": "Inspect storage"})

    message = str(caught.value)
    assert "ReadPlan" in message
    assert "scope_summary" in message
    assert "string_too_short" in message
    assert '"scope_summary"' not in message
    assert "secret-token" not in message


def test_chat_completions_retries_one_schema_correction_without_rejected_content() -> None:
    completions = CorrectingPlanCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIChatCompletionsProvider()
    provider._client = lambda _profile, _key: client  # type: ignore[method-assign]

    plan = provider.plan_ad_hoc(profile(), "secret-token", {"question": "Inspect storage"})

    assert plan.scope_summary == "No cluster reads are needed."
    assert len(completions.requests) == 2
    correction_messages = completions.requests[1]["messages"]
    assert "scope_summary: string_too_short" in correction_messages[-1]["content"]
    assert '"scope_summary": ""' not in correction_messages[-1]["content"]


def test_missing_descriptive_plan_summary_gets_safe_default_without_retry() -> None:
    completions = MissingSummaryPlanCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIChatCompletionsProvider()
    provider._client = lambda _profile, _key: client  # type: ignore[method-assign]

    plan = provider.plan_ad_hoc(profile(), "secret-token", {"question": "Show Pods"})

    assert plan.scope_summary == "Bounded read-only cluster investigation."
    assert len(completions.requests) == 1


def test_ask_answer_probe_uses_smaller_output_budget_and_forbids_operator_commands() -> None:
    completions = RecordingCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIChatCompletionsProvider()
    provider._client = lambda _profile, _key: client  # type: ignore[method-assign]

    provider.answer_ad_hoc(
        profile(max_output_tokens=4096),
        "secret-token",
        {"capability_probe": True, "observations": [{"id": "cluster-pod-1"}]},
    )

    request = completions.requests[0]
    assert request["max_tokens"] == 1400
    assert "Do not tell the operator to run kubectl" in request["messages"][0]["content"]


def test_capability_report_requires_ask_schemas_for_ready_state() -> None:
    base = dict(
        reachable=True,
        tls_valid=True,
        authenticated=True,
        model_available=True,
        structured_output=True,
    )
    assert CapabilityReport(**base, ask_schemas=False).ready is False
    assert CapabilityReport(**base, ask_schemas=True).ready is True


def test_ask_schema_probe_reports_operational_contract_failure() -> None:
    provider = OpenAIChatCompletionsProvider()
    provider.plan_ad_hoc = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ModelProviderError("Provider response does not match ReadPlan.")
    )

    passed, detail = provider._probe_ask_schemas(profile(), "secret-token")

    assert passed is False
    assert detail == "ReadPlan probe failed. Provider response does not match ReadPlan."


def test_ask_schema_probe_identifies_answer_phase() -> None:
    provider = OpenAIChatCompletionsProvider()
    provider.plan_ad_hoc = lambda *_args: ReadPlan(  # type: ignore[method-assign]
        scope_summary="No reads are required.", intents=[]
    )
    provider.answer_ad_hoc = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ModelProviderError("Provider request failed (InternalServerError, HTTP 504).")
    )

    passed, detail = provider._probe_ask_schemas(profile(), "secret-token")

    assert passed is False
    assert detail == (
        "AdHocAnswer probe failed. "
        "Provider request failed (InternalServerError, HTTP 504)."
    )
