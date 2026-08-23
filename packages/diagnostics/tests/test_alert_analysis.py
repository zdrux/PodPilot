import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from podpilot_diagnostics.alerts import AlertEvidence, analyze_alert
from podpilot_diagnostics.redaction import redact_mapping

FIXTURES = Path(__file__).resolve().parents[3] / "evals" / "fixtures"


@pytest.mark.parametrize(
    ("fixture_name", "expected_check"),
    [
        ("crashloop.json", "previous container logs"),
        ("image-waiting.json", "pull-secret values"),
        ("unscheduled.json", "allocatable capacity"),
    ],
)
def test_capability_pack_one_triage_fixtures(fixture_name: str, expected_check: str) -> None:
    payload = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    alert = AlertEvidence(
        fingerprint=payload["fingerprint"],
        name=payload["name"],
        state="active",
        severity=payload["severity"],
        namespace=payload["namespace"],
        starts_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
        labels=payload["labels"],
        annotations=payload["annotations"],
    )
    result = analyze_alert(alert, now=datetime(2026, 8, 23, tzinfo=timezone.utc))
    assert result.hypotheses[0].confidence == "low"
    assert result.hypotheses[0].evidence_ids == ("alertmanager-alert",)
    assert any(expected_check in check for check in result.next_checks)
    assert any("untrusted evidence" in limitation for limitation in result.limitations)


def test_alert_evidence_redacts_secret_like_text() -> None:
    redacted = redact_mapping(
        {
            "description": "failed request Authorization: Bearer abc.def.ghi",
            "summary": "password=synthetic-do-not-store",
        }
    )
    assert "abc.def.ghi" not in redacted["description"]
    assert "synthetic-do-not-store" not in redacted["summary"]
    assert redacted["description"].endswith("[REDACTED]")
