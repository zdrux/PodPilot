from podpilot_diagnostics.redaction import redact_text


def test_redact_text_removes_unlabelled_jwt() -> None:
    token = (
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxhYiJ9."
        "eyJpc3MiOiJrdWJlcm5ldGVzIiwic3ViIjoic2VydmljZWFjY291bnQifQ."
        "c2lnbmF0dXJlLXZhbHVl"
    )

    assert redact_text(f"before {token} after") == "before [REDACTED] after"
