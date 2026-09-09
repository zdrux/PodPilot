from podpilot_diagnostics.redaction import redact_text


def test_redaction_covers_quoted_json_values_and_embedded_spaces():
    text = '{"message":"worker failed", "password":"very secret value", "access_token":"abc123"}'
    result = redact_text(text)
    assert "worker failed" in result
    assert "very secret value" not in result and "abc123" not in result


def test_redact_text_removes_unlabelled_jwt() -> None:
    token = (
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxhYiJ9."
        "eyJpc3MiOiJrdWJlcm5ldGVzIiwic3ViIjoic2VydmljZWFjY291bnQifQ."
        "c2lnbmF0dXJlLXZhbHVl"
    )

    assert redact_text(f"before {token} after") == "before [REDACTED] after"


def test_redact_text_removes_shell_credential_options() -> None:
    command = (
        "curl --token sensitive-token --client-secret='client secret' "
        "-u user:password https://example.test"
    )

    assert redact_text(command) == (
        "curl --token [REDACTED] --client-secret=[REDACTED] "
        "-u [REDACTED] https://example.test"
    )
