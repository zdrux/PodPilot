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
        "auditID": f"audit-{username}-{verb}-{code}",
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
    assert "| line_format `" in query
    assert 'audit_resource="objectRef.resource"' in query
    assert "requestObject" not in query
    assert source.calls[0]["limit"] == 5
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


def test_delete_scope_excludes_other_mutations() -> None:
    source = FakeAuditSource((
        ("1787831940000000000", _event("druciare-adm", verb="patch")),
        ("1787831930000000000", _event("druciare-adm", verb="delete")),
        ("1787831920000000000", _event("druciare-adm", verb="deletecollection")),
    ))
    reader = BoundedAuditEventReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_audit_events",
        audit_username="druciare-adm",
        audit_operation_scope="deletes",
        audit_outcome="all",
        limit=10,
    ))

    assert 'audit_verb=~"^(?:delete|deletecollection)$"' in str(source.calls[0]["logql"])
    assert [event["verb"] for event in result.observations[0].data["events"]] == [
        "delete", "deletecollection",
    ]


def test_cluster_wide_delete_query_filters_in_loki_and_returns_all_users() -> None:
    source = FakeAuditSource((
        ("1787831940000000000", _event("alice", verb="delete")),
        ("1787831930000000000", _event("bob", verb="deletecollection")),
        ("1787831920000000000", _event("carol", verb="patch")),
    ))
    reader = BoundedAuditEventReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_audit_events",
        audit_operation_scope="deletes",
        audit_outcome="all",
        range_seconds=3600,
        limit=10,
    ))

    query = str(source.calls[0]["logql"])
    assert "audit_username=~" not in query
    assert '| audit_stage="ResponseComplete"' in query
    assert 'audit_verb=~"^(?:delete|deletecollection)$"' in query
    assert "| line_format `" in query
    assert source.calls[0]["limit"] == 10
    assert [event["username"] for event in result.observations[0].data["events"]] == [
        "alice", "bob",
    ]
    assert result.observations[0].data["username"] is None
    assert result.observations[0].summary.endswith("across all users.")


def test_namespace_audit_query_filters_in_loki_and_projection() -> None:
    payments = _event("alice", verb="patch")
    other = json.loads(_event("bob", verb="patch"))
    other["objectRef"]["namespace"] = "other"
    source = FakeAuditSource((
        ("1787831940000000000", payments),
        ("1787831930000000000", json.dumps(other)),
    ))

    result = BoundedAuditEventReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_audit_events", namespace="payments",
        audit_operation_scope="all", audit_outcome="all", limit=5,
    ))

    query = str(source.calls[0]["logql"])
    assert r'audit_namespace=~"(?i)^payments$"' in query
    assert [event["namespace"] for event in result.observations[0].data["events"]] == [
        "payments"
    ]
    assert result.observations[0].data["namespace"] == "payments"
    assert result.observations[0].summary.endswith("in namespace payments.")


def test_last_n_query_expands_backward_until_it_finds_requested_events() -> None:
    class ExpandingSource:
        def __init__(self) -> None:
            self.ranges: list[int] = []

        def query_audit_entries(self, _logql, *, start, end, limit):
            searched = int((end - start).total_seconds())
            self.ranges.append(searched)
            entries = (
                (("1787831940000000000", _event("druciare-adm", verb="patch")),)
                if searched >= 7200 else ()
            )
            return AuditLogEntries(entries=entries, is_complete=True)

    source = ExpandingSource()
    reader = BoundedAuditEventReader(
        source, max_range_seconds=86_400, clock=lambda: NOW,
    )

    result = reader.execute(ReadIntent(
        tool="query_audit_events", audit_username="druciare-adm",
        audit_operation_scope="all", audit_outcome="all",
        audit_search_until_limit=True, range_seconds=3600, limit=1,
    ))

    assert source.ranges == [3600, 7200]
    assert result.observations[0].data["rangeSeconds"] == 7200
    assert result.observations[0].data["rangeExpanded"] is True
    assert result.observations[0].data["count"] == 1


def test_last_n_query_stops_at_configured_ceiling_and_reports_it() -> None:
    source = FakeAuditSource(())
    reader = BoundedAuditEventReader(
        source, max_range_seconds=14_400, clock=lambda: NOW,
    )

    result = reader.execute(ReadIntent(
        tool="query_audit_events", audit_username="druciare-adm",
        audit_operation_scope="all", audit_outcome="all",
        audit_search_until_limit=True, range_seconds=3600, limit=5,
    ))

    searched = [int((call["end"] - call["start"]).total_seconds()) for call in source.calls]
    assert searched == [3600, 7200, 14_400]
    assert any("configured 14400-second audit ceiling" in item for item in result.limitations)


def _client(tmp_path: Path, handler, **kwargs) -> LokiQueryClient:
    token = tmp_path / "token"
    token.write_text("fixture-token", encoding="utf-8")
    return LokiQueryClient(
        base_url="https://logging.example.test/api/logs/v1/application",
        tenant="audit",
        token_path=token,
        transport=httpx.MockTransport(handler),
        **kwargs,
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


def test_loki_audit_client_accepts_verbose_requested_entries_with_audit_ceiling(
    tmp_path: Path,
) -> None:
    events = []
    for index in range(10):
        event = json.loads(_event("Druciare-Adm", verb="delete"))
        event["requestObject"] = {"padding": "x" * 8_000}
        events.append([str(1787831940000000000 - index), json.dumps(event)])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "streams", "result": [{
                "stream": {"log_type": "audit"}, "values": events,
            }]},
        })

    result = _client(
        tmp_path, handler, max_response_bytes=1_048_576,
    ).query_audit_entries("fixed", start=NOW, end=NOW, limit=10)

    assert len(result.entries) == 10


def test_reader_accepts_compact_loki_line_projection() -> None:
    compact = json.dumps({
        "auditID": "compact-delete-1",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-08-27T11:59:00Z",
        "user": {"username": "druciare-adm"},
        "verb": "delete",
        "objectRef": {
            "apiGroup": "apps", "apiVersion": "v1", "resource": "deployments",
            "subresource": "", "namespace": "payments", "name": "api",
        },
        "responseStatus": {"code": "200"},
    })
    source = FakeAuditSource((("1787831940000000000", compact),))

    result = BoundedAuditEventReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_audit_events", audit_username="druciare-adm",
        audit_operation_scope="deletes", audit_outcome="all", limit=10,
    ))

    event = result.observations[0].data["events"][0]
    assert event == {
        "timestamp": "2026-08-27T11:59:00+00:00",
        "username": "druciare-adm",
        "verb": "delete",
        "apiGroup": "apps",
        "apiVersion": "v1",
        "resource": "deployments",
        "subresource": None,
        "namespace": "payments",
        "name": "api",
        "responseCode": 200,
        "outcome": "succeeded",
        "auditID": "compact-delete-1",
    }


def test_loki_audit_denial_names_required_role(tmp_path: Path) -> None:
    client = _client(tmp_path, lambda _request: httpx.Response(403))

    with pytest.raises(AuditQueryError, match="cluster-logging-audit-view"):
        client.query_audit_entries("fixed", start=NOW, end=NOW, limit=5)
