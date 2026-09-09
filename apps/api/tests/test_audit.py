import json
from datetime import datetime, timezone

from podpilot_api.audit import export_event, safe_details
from podpilot_api.models import AuditEvent


def test_export_redacts_nested_credentials_and_preserves_attribution():
    event = AuditEvent(
        id=42, occurred_at=datetime(2026, 9, 9, tzinfo=timezone.utc),
        actor="operator", action="cluster.request", outcome="accepted",
        details_json=json.dumps({
            "delegated_username": "cluster-user", "status_code": 200,
            "nested": [{"authorization": "raw-value", "note": "token=unsafe"}],
        }),
    )
    exported = export_event(event)
    assert exported["event_category"] == "audit"
    assert exported["event_id"] == 42
    assert exported["details"]["delegated_username"] == "cluster-user"
    assert "raw-value" not in json.dumps(exported)
    assert "unsafe" not in json.dumps(exported)


def test_malformed_and_deep_details_do_not_break_export():
    event = AuditEvent(
        id=1, occurred_at=datetime(2026, 9, 9), actor="operator",
        action="legacy", outcome="read", details_json="not json",
    )
    assert "limitation" in export_event(event)["details"]
    assert export_event(event)["occurred_at"].endswith("+00:00")
    assert len(safe_details(list(range(200)))) == 100
    assert "depth limit" in str(safe_details([[[[[[[["nested"]]]]]]]]))
