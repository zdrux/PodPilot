import json

import pytest
import yaml

from podpilot_api.main import (
    _agent_tool_ledger_entry,
    _bounded_agent_provider_result,
    _read_only_proxy_allows,
    _recover_serialized_agent_completion,
)
from podpilot_api.secret_policy import redact_secret_output
from podpilot_api.settings import Settings


@pytest.mark.parametrize("access", [True, False])
@pytest.mark.parametrize("redaction", [True, False])
def test_secret_flags_are_independent(monkeypatch, access, redaction):
    monkeypatch.setenv("PODPILOT_SECRET_ACCESS_ENABLED", str(access))
    monkeypatch.setenv("PODPILOT_SECRET_CHAT_REDACTION_ENABLED", str(redaction))
    settings = Settings(_env_file=None)
    assert settings.secret_access_enabled is access
    assert settings.secret_chat_redaction_enabled is redaction
    assert _read_only_proxy_allows(
        "GET", "/api/v1/namespaces/operators/secrets/tls",
        secret_access_enabled=settings.secret_access_enabled,
    ) is access
    assert not _read_only_proxy_allows(
        "PATCH", "/api/v1/namespaces/operators/secrets/tls",
        secret_access_enabled=access,
    )


def test_secret_policy_defaults():
    settings = Settings(_env_file=None)
    assert settings.secret_access_enabled
    assert settings.secret_chat_redaction_enabled


@pytest.mark.parametrize("serialize", [json.dumps, yaml.safe_dump])
def test_redacts_secret_exports_in_lists_and_markdown(serialize):
    secret = {"kind": "Secret", "data": {"tls.key": "opaque-base64"},
              "stringData": {"custom-field": "opaque-plaintext"},
              "metadata": {"name": "tls", "annotations": {
                  "kubectl.kubernetes.io/last-applied-configuration": "opaque-export"}}}
    for value in (secret, {"kind": "SecretList", "items": [secret]}):
        output = serialize(value)
        for text in (output, f"Certificate configuration:\n```\n{output}\n```"):
            redacted = redact_secret_output(text)
            assert "opaque-" not in redacted
            assert "[REDACTED]" in redacted


def test_private_keys_redacted_but_public_certificates_preserved():
    private = "-----BEGIN RSA PRIVATE KEY-----\nfake-private\n-----END RSA PRIVATE KEY-----"
    public = "-----BEGIN CERTIFICATE-----\nfake-public\n-----END CERTIFICATE-----"
    output = redact_secret_output(private + "\n" + public)
    assert "fake-private" not in output
    assert public in output


def test_provider_and_completion_honor_display_override_but_ledger_stays_redacted():
    stdout = json.dumps({"kind": "Secret", "data": {"custom": "opaque-value"}})
    result = {"stdout": stdout, "exit_code": 0}
    assert "opaque-value" not in _bounded_agent_provider_result(result)
    assert "opaque-value" in _bounded_agent_provider_result(result, redact_secrets=False)
    completion = json.dumps({"stop_reason": "complete", "answer": "password=synthetic-value",
                             "unresolved_safe_reads": []})
    assert "synthetic-value" not in _recover_serialized_agent_completion(completion)[1]
    assert "synthetic-value" in _recover_serialized_agent_completion(completion, redact_secrets=False)[1]
    ledger = _agent_tool_ledger_entry(sequence=1, tool_name="execute_shell", tool_call_id="call",
        cluster_id="test", cluster_name="test", status="completed", request="oc get secret tls -o json",
        result=result)
    assert "opaque-value" not in json.dumps(ledger)
