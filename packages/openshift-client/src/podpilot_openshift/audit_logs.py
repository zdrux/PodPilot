from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import uuid4

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_text


class AuditQueryError(RuntimeError):
    """A normalized, browser-safe audit-query failure."""


@dataclass(frozen=True)
class AuditLogEntries:
    entries: tuple[tuple[str, str], ...]
    is_complete: bool


class AuditQuerySource(Protocol):
    def query_audit_entries(
        self,
        logql: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> AuditLogEntries: ...


def _logql_regex_literal(value: str) -> str:
    """Encode an exact case-insensitive value without granting regex syntax."""

    pattern = f"(?i)^{re.escape(value)}$"
    return json.dumps(pattern, ensure_ascii=True)


def _nested_audit_event(value: object, *, depth: int = 0) -> dict[str, object] | None:
    if depth > 3:
        return None
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return None
        return _nested_audit_event(decoded, depth=depth + 1)
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("user"), dict) and value.get("verb"):
        return value
    for key in ("message", "body", "log", "event"):
        nested = _nested_audit_event(value.get(key), depth=depth + 1)
        if nested is not None:
            return nested
    return None


def _timestamp(value: object, fallback_ns: str) -> datetime | None:
    raw = str(value or "").strip()
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.fromtimestamp(int(fallback_ns) / 1_000_000_000, tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


class BoundedAuditEventReader:
    """Compile typed user-activity semantics into a server-owned audit query."""

    _MUTATING_VERBS = {"create", "delete", "deletecollection", "patch", "update"}

    def __init__(
        self,
        source: AuditQuerySource,
        *,
        max_range_seconds: int = 86_400,
        clock=lambda: datetime.now(timezone.utc),
    ) -> None:
        self._source = source
        self._max_range_seconds = max_range_seconds
        self._clock = clock

    def execute(self, intent: ReadIntent) -> ReadResult:
        if intent.tool != "query_audit_events" or not intent.audit_username:
            raise ValueError("BoundedAuditEventReader requires a typed audit event intent.")
        username = intent.audit_username.strip()
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        end = self._clock()
        start = end - timedelta(seconds=range_seconds)
        query = (
            '{log_type="audit"} '
            '| json audit_username="user.username", audit_stage="stage" '
            f'| audit_username=~{_logql_regex_literal(username)} '
            '| audit_stage="ResponseComplete"'
        )
        snapshot = self._source.query_audit_entries(
            query, start=start, end=end, limit=min(100, max(intent.limit * 4, intent.limit))
        )
        events: list[dict[str, object]] = []
        seen: set[str] = set()
        for timestamp_ns, line in snapshot.entries:
            event = _nested_audit_event(line)
            if event is None:
                continue
            user = event.get("user") if isinstance(event.get("user"), dict) else {}
            observed_username = str(user.get("username") or "")
            if observed_username.casefold() != username.casefold():
                continue
            if str(event.get("stage") or "") != "ResponseComplete":
                continue
            verb = str(event.get("verb") or "").lower()
            if intent.audit_operation_scope == "mutations" and verb not in self._MUTATING_VERBS:
                continue
            response_status = (
                event.get("responseStatus")
                if isinstance(event.get("responseStatus"), dict) else {}
            )
            try:
                response_code = int(response_status.get("code") or 0)
            except (TypeError, ValueError):
                response_code = 0
            successful = bool(response_code and response_code < 400)
            if intent.audit_outcome == "successful" and not successful:
                continue
            if intent.audit_outcome == "failed" and successful:
                continue
            audit_id = str(event.get("auditID") or "")[:128]
            identity = audit_id or f"{timestamp_ns}:{verb}:{len(events)}"
            if identity in seen:
                continue
            seen.add(identity)
            occurred_at = _timestamp(event.get("requestReceivedTimestamp"), timestamp_ns)
            object_ref = event.get("objectRef") if isinstance(event.get("objectRef"), dict) else {}
            events.append({
                "timestamp": occurred_at.isoformat() if occurred_at else "unknown",
                "username": redact_text(observed_username)[:512],
                "verb": verb[:64] or "unknown",
                "apiGroup": str(object_ref.get("apiGroup") or "")[:128] or None,
                "apiVersion": str(object_ref.get("apiVersion") or "")[:128] or None,
                "resource": str(object_ref.get("resource") or "")[:128] or None,
                "subresource": str(object_ref.get("subresource") or "")[:128] or None,
                "namespace": str(object_ref.get("namespace") or "")[:253] or None,
                "name": str(object_ref.get("name") or "")[:253] or None,
                "responseCode": response_code or None,
                "outcome": "succeeded" if successful else "failed",
                "auditID": audit_id or None,
            })
        events.sort(
            key=lambda item: (
                item.get("timestamp") != "unknown",
                str(item.get("timestamp") or ""),
            ),
            reverse=True,
        )
        events = events[: intent.limit]
        limitations: list[str] = []
        if range_seconds != intent.range_seconds:
            limitations.append(
                f"The requested audit period was reduced to {range_seconds} seconds by policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The bounded Loki audit result reached its collection ceiling; older matching events may exist."
            )
        if not events:
            limitations.append(
                "No matching completed audit events were observed during the requested period."
            )
        return ReadResult(observations=(AdHocObservation(
            id=f"audit-{uuid4()}",
            tool="query_audit_events",
            summary=(
                f"Read {len(events)} completed audit event"
                f"{'s' if len(events) != 1 else ''} for user {username}."
            ),
            source="loki:audit/query/user_actions",
            collected_at=self._clock(),
            data={
                "username": redact_text(username)[:512],
                "caseInsensitive": True,
                "operationScope": intent.audit_operation_scope,
                "outcomeFilter": intent.audit_outcome,
                "rangeSeconds": range_seconds,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "limit": intent.limit,
                "events": events,
                "count": len(events),
                "complete": snapshot.is_complete and len(events) < intent.limit,
                "rawLinesPersisted": False,
            },
        ),), limitations=tuple(limitations))
