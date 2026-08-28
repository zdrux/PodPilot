import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_openshift.audit_logs import (
    AuditLogEntries,
    AuditQueryError,
    BoundedAuditEventReader,
)
from podpilot_openshift.log_metrics import LokiQueryClient


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


class FakeAuditSource:
    def __init__(self, entries: tuple[tuple[str, str], ...]) -> None:
        self.entries = entries
        self.calls: list[dict[str, object]] = []

    def query_audit_entries(self, logql, *, start, end, limit):
        self.calls.append({"logql": logql, "start": start, "end": end, "limit": limit})
        return AuditLogEntries(entries=self.entries, is_complete=True)


def _event(username: str, *, verb: str = "get", code: int = 200) -> str:
    return json.dumps({
        "auditID": f"audit-{verb}-{code}",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-08-27T11:59:00Z",
        "user": {"username": username},
        "verb": verb,
        "objectRef": {
            "apiVersion": "v1", "resource": "configmaps",
            "namespace": "payments", "name": "settings",
        },
        "responseStatus": {"code": code},
        "requestObject": {"sensitive": "must-not-persist"},
    })


def test_reader_matches_username_case_insensitively_and_projects_safe_fields() -> None:
    source = FakeAuditSource((("1787831940000000000", _event("DRUCIARE-ADM", verb="patch")),))
    reader = BoundedAuditEventReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_audit_events",
        audit_username="druciare-adm",
        audit_operation_scope="mutations",
        audit_outcome="successful",
        range_seconds=7200,
        limit=5,
    ))

    query = str(source.calls[0]["logql"])
    assert r'audit_username=~"(?i)^druciare\\-adm$"' in query
    assert source.calls[0]["limit"] == 20
    event = result.observations[0].data["events"][0]
    assert event["username"] == "DRUCIARE-ADM"
    assert event["verb"] == "patch"
    assert event["resource"] == "configmaps"
    assert "requestObject" not in event
    assert result.observations[0].data["rawLinesPersisted"] is False


def test_reader_escapes_username_regex_and_filters_semantic_scope() -> None:
    source = FakeAuditSource((
        ("1787831940000000000", _event("user.*", verb="get")),
        ("1787831930000000000", _event("user.*", verb="delete", code=403)),
        ("1787831920000000000", _event("someone-else", verb="delete", code=403)),
    ))
    reader = BoundedAuditEventReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_audit_events",
        audit_username="user.*",
        audit_operation_scope="mutations",
        audit_outcome="failed",
    ))

    assert r'user\\.\\*' in str(source.calls[0]["logql"])
    assert [event["verb"] for event in result.observations[0].data["events"]] == ["delete"]


def _client(tmp_path: Path, handler) -> LokiQueryClient:
    token = tmp_path / "token"
    token.write_text("fixture-token", encoding="utf-8")
    return LokiQueryClient(
        base_url="https://logging.example.test/api/logs/v1/application",
        tenant="audit",
        token_path=token,
        transport=httpx.MockTransport(handler),
    )


def test_loki_audit_client_uses_audit_tenant_and_query_range(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/logs/v1/audit/loki/api/v1/query_range"
        assert request.url.params["direction"] == "backward"
        assert request.url.params["limit"] == "5"
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "streams", "result": [{
                "stream": {"log_type": "audit"},
                "values": [["1787831940000000000", _event("Druciare-Adm")]],
            }]},
        })

    result = _client(tmp_path, handler).query_audit_entries(
        "fixed", start=NOW, end=NOW, limit=5,
    )

    assert len(result.entries) == 1


def test_loki_audit_denial_names_required_role(tmp_path: Path) -> None:
    client = _client(tmp_path, lambda _request: httpx.Response(403))

    with pytest.raises(AuditQueryError, match="cluster-logging-audit-view"):
        client.query_audit_entries("fixed", start=NOW, end=NOW, limit=5)
