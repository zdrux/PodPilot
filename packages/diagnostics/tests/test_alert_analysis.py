import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from podpilot_diagnostics.alerts import AlertEvidence, analyze_alert
from podpilot_diagnostics.redaction import redact_mapping
from podpilot_diagnostics.workloads import (
    ContainerEvidence,
    EventEvidence,
    NodeEvidence,
    OwnerEvidence,
    WorkloadEvidence,
)

FIXTURES = Path(__file__).resolve().parents[3] / "evals" / "fixtures"


@pytest.mark.parametrize(
    ("fixture_name", "expected_title"),
    [
        ("crashloop.json", "repeatedly exits"),
        ("image-waiting.json", "does not exist"),
        ("unscheduled.json", "lack requested CPU"),
    ],
)
def test_capability_pack_one_evidence_fixtures(fixture_name: str, expected_title: str) -> None:
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
    item = payload["workload"]
    owner = OwnerEvidence(**item["owner"]) if item.get("owner") else None
    workload = WorkloadEvidence(
        namespace=payload["namespace"],
        pod_name=item["pod_name"],
        pod_uid="synthetic-pod-uid",
        phase=item["phase"],
        node_name=item["node_name"],
        requests=item["requests"],
        conditions=(),
        containers=tuple(ContainerEvidence(**value) for value in item["containers"]),
        events=tuple(
            EventEvidence(observed_at=None, **value) for value in item["events"]
        ),
        owners=(owner,) if owner else (),
        nodes=tuple(NodeEvidence(**value) for value in item.get("nodes", [])),
        current_logs=item.get("current_logs", {}),
        previous_logs=item.get("previous_logs", {}),
        collected_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
        failures=(),
    )
    result = analyze_alert(
        alert,
        workload=workload,
        now=datetime(2026, 8, 23, tzinfo=timezone.utc),
    )
    assert result.hypotheses[0].confidence in {"medium", "high"}
    assert expected_title in result.hypotheses[0].title
    assert result.hypotheses[0].evidence_ids
    assert any("untrusted evidence" in limitation for limitation in result.limitations)


def test_missing_live_workload_evidence_still_abstains() -> None:
    alert = AlertEvidence(
        fingerprint="missing",
        name="KubePodCrashLooping",
        state="active",
        severity="warning",
        namespace="demo",
        starts_at=None,
        labels={"pod": "demo"},
        annotations={},
    )
    result = analyze_alert(alert, now=datetime(2026, 8, 23, tzinfo=timezone.utc))
    assert result.hypotheses[0].confidence == "low"
    assert result.hypotheses[0].evidence_ids == ("alertmanager-alert",)


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
