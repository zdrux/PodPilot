import json
from types import SimpleNamespace

import pytest

from podpilot_api.model_provider import (
    AdHocAnswer,
    ModelProfileConfig,
    ModelProviderError,
    OpenAIChatCompletionsProvider,
    OpenAIProviderRouter,
)


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
