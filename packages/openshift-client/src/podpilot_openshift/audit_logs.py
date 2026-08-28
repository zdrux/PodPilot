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


_COMPACT_AUDIT_LINE_TEMPLATE = (
    '{"auditID":{{printf "%q" .audit_id}},'
    '"stage":"ResponseComplete",'
    '"requestReceivedTimestamp":{{printf "%q" .audit_timestamp}},'
    '"user":{"username":{{printf "%q" .audit_username}}},'
    '"verb":{{printf "%q" .audit_verb}},'
    '"objectRef":{'
    '"apiGroup":{{printf "%q" .audit_api_group}},'
    '"apiVersion":{{printf "%q" .audit_api_version}},'
    '"resource":{{printf "%q" .audit_resource}},'
    '"subresource":{{printf "%q" .audit_subresource}},'
    '"namespace":{{printf "%q" .audit_namespace}},'
    '"name":{{printf "%q" .audit_name}}},'
    '"responseStatus":{"code":{{printf "%q" .audit_code}}}}'
)


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
        if intent.tool != "query_audit_events":
            raise ValueError("BoundedAuditEventReader requires a typed audit event intent.")
        username = intent.audit_username.strip() if intent.audit_username else None
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        end = self._clock()
        query = (
            '{log_type="audit"} '
            '| json audit_id="auditID", audit_timestamp="requestReceivedTimestamp", '
            'audit_username="user.username", audit_stage="stage", '
            'audit_verb="verb", audit_code="responseStatus.code", '
            'audit_api_group="objectRef.apiGroup", audit_api_version="objectRef.apiVersion", '
            'audit_resource="objectRef.resource", audit_subresource="objectRef.subresource", '
            'audit_namespace="objectRef.namespace", audit_name="objectRef.name" '
        )
        if username:
            query += f'| audit_username=~{_logql_regex_literal(username)} '
        query += '| audit_stage="ResponseComplete"'
        if intent.audit_operation_scope == "mutations":
            query += ' | audit_verb=~"^(?:create|delete|deletecollection|patch|update)$"'
        elif intent.audit_operation_scope == "deletes":
            query += ' | audit_verb=~"^(?:delete|deletecollection)$"'
        if intent.audit_outcome == "successful":
            query += ' | audit_code=~"^[123][0-9]{2}$"'
        elif intent.audit_outcome == "failed":
            query += ' | audit_code=~"^[45][0-9]{2}$"'
        # Rewrite matching audit lines inside Loki so large request/response objects never
        # cross the network. The HTTP limit and backward direction then apply to these compact,
        # server-filtered projections rather than pages of raw audit payloads.
        query += f" | line_format `{_COMPACT_AUDIT_LINE_TEMPLATE}`"
        snapshot = AuditLogEntries(entries=(), is_complete=True)
        events: list[dict[str, object]] = []
        while True:
            start = end - timedelta(seconds=range_seconds)
            snapshot = self._source.query_audit_entries(
                query,
                start=start,
                end=end,
                # Loki already applies the username, stage, operation, and outcome
                # filters. Asking for four times the requested count only inflates
                # verbose raw audit payloads and can trip the bounded HTTP ceiling.
                limit=intent.limit,
            )
            events = self._project_events(
                snapshot,
                username=username,
                operation_scope=str(intent.audit_operation_scope),
                outcome=str(intent.audit_outcome),
                limit=intent.limit,
            )
            if (
                not intent.audit_search_until_limit
                or len(events) >= intent.limit
                or range_seconds >= self._max_range_seconds
            ):
                break
            range_seconds = min(self._max_range_seconds, range_seconds * 2)
        limitations: list[str] = []
        if intent.range_seconds > self._max_range_seconds:
            limitations.append(
                f"The requested audit period was reduced to {range_seconds} seconds by policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The bounded Loki audit result reached its collection ceiling; older matching events may exist."
            )
        if (
            intent.audit_search_until_limit
            and range_seconds >= self._max_range_seconds
            and len(events) < intent.limit
        ):
            limitations.append(
                f"PodPilot searched the configured {range_seconds}-second audit ceiling but "
                f"found fewer than the requested {intent.limit} matching events."
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
                f"{'s' if len(events) != 1 else ''} "
                + (f"for user {username}." if username else "across all users.")
            ),
            source="loki:audit/query/user_actions",
            collected_at=self._clock(),
            data={
                "username": redact_text(username)[:512] if username else None,
                "caseInsensitive": bool(username),
                "operationScope": intent.audit_operation_scope,
                "outcomeFilter": intent.audit_outcome,
                "rangeSeconds": range_seconds,
                "rangeExpanded": bool(
                    intent.audit_search_until_limit and range_seconds > intent.range_seconds
                ),
                "start": start.isoformat(),
                "end": end.isoformat(),
                "limit": intent.limit,
                "events": events,
                "count": len(events),
                "complete": snapshot.is_complete and len(events) < intent.limit,
                "rawLinesPersisted": False,
            },
        ),), limitations=tuple(limitations))

    def _project_events(
        self,
        snapshot: AuditLogEntries,
        *,
        username: str | None,
        operation_scope: str,
        outcome: str,
        limit: int,
    ) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []
        seen: set[str] = set()
        for timestamp_ns, line in snapshot.entries:
            event = _nested_audit_event(line)
            if event is None:
                continue
            user = event.get("user") if isinstance(event.get("user"), dict) else {}
            observed_username = str(user.get("username") or "")
            if username and observed_username.casefold() != username.casefold():
                continue
            if str(event.get("stage") or "") != "ResponseComplete":
                continue
            verb = str(event.get("verb") or "").lower()
            if operation_scope == "mutations" and verb not in self._MUTATING_VERBS:
                continue
            if operation_scope == "deletes" and verb not in {"delete", "deletecollection"}:
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
            if outcome == "successful" and not successful:
                continue
            if outcome == "failed" and successful:
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
        return events[:limit]
