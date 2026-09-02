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

_AUDIT_RECORD_PROFILES = ("top_level", "message", "structured")


def _audit_logql(
    *,
    profile: str,
    username: str | None,
    namespace: str | None,
    resource: str | None,
    operation_scope: str,
    outcome: str,
) -> str:
    """Build one reviewed audit-record profile with a compact server-side projection."""

    if profile not in _AUDIT_RECORD_PROFILES:
        raise ValueError("Unsupported audit record profile.")
    prefix = "structured." if profile == "structured" else ""
    query = '{log_type="audit"} '
    if profile == "message":
        query += '| json audit_payload="message" | line_format "{{.audit_payload}}" '
    query += (
        f'| json audit_id="{prefix}auditID", '
        f'audit_timestamp="{prefix}requestReceivedTimestamp", '
        f'audit_username="{prefix}user.username", audit_stage="{prefix}stage", '
        f'audit_verb="{prefix}verb", audit_code="{prefix}responseStatus.code", '
        f'audit_api_group="{prefix}objectRef.apiGroup", '
        f'audit_api_version="{prefix}objectRef.apiVersion", '
        f'audit_resource="{prefix}objectRef.resource", '
        f'audit_subresource="{prefix}objectRef.subresource", '
        f'audit_namespace="{prefix}objectRef.namespace", '
        f'audit_name="{prefix}objectRef.name" '
    )
    if username:
        query += f'| audit_username=~{_logql_regex_literal(username)} '
    if namespace:
        query += f'| audit_namespace=~{_logql_regex_literal(namespace)} '
    if resource:
        query += f'| audit_resource=~{_logql_regex_literal(resource)} '
    query += '| audit_stage="ResponseComplete"'
    if operation_scope == "mutations":
        query += ' | audit_verb=~"^(?:create|delete|deletecollection|patch|update)$"'
    elif operation_scope == "deletes":
        query += ' | audit_verb=~"^(?:delete|deletecollection)$"'
    if outcome == "successful":
        query += ' | audit_code=~"^[123][0-9]{2}$"'
    elif outcome == "failed":
        query += ' | audit_code=~"^[45][0-9]{2}$"'
    return query + f" | line_format `{_COMPACT_AUDIT_LINE_TEMPLATE}`"


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
        namespace = intent.namespace.strip() if intent.namespace else None
        resource = intent.audit_resource.strip() if intent.audit_resource else None
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        end = self._clock()
        snapshot = AuditLogEntries(entries=(), is_complete=True)
        events: list[dict[str, object]] = []
        matched_profiles: list[str] = []
        while True:
            start = end - timedelta(seconds=range_seconds)
            profile_snapshots: list[AuditLogEntries] = []
            matched_profiles = []
            for profile in _AUDIT_RECORD_PROFILES:
                profile_snapshot = self._source.query_audit_entries(
                    _audit_logql(
                        profile=profile,
                        username=username,
                        namespace=namespace,
                        resource=resource,
                        operation_scope=str(intent.audit_operation_scope),
                        outcome=str(intent.audit_outcome),
                    ),
                    start=start,
                    end=end,
                    # Every profile filters and projects inside Loki, so verbose
                    # request/response objects never cross this boundary.
                    limit=intent.limit,
                )
                profile_snapshots.append(profile_snapshot)
                if profile_snapshot.entries:
                    matched_profiles.append(profile)
                    # One OpenShift Logging deployment uses one record envelope.
                    # Stop after the first matching reviewed profile to avoid
                    # multiplying successful audit-query latency.
                    break
            snapshot = AuditLogEntries(
                entries=tuple(
                    sorted(
                        (
                            entry
                            for item in profile_snapshots
                            for entry in item.entries
                        ),
                        key=lambda item: item[0],
                        reverse=True,
                    )
                ),
                is_complete=all(item.is_complete for item in profile_snapshots),
            )
            events = self._project_events(
                snapshot,
                username=username,
                namespace=namespace,
                resource=resource,
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
                "Loki returned no matching completed audit events across the supported OpenShift "
                "audit record profiles. This does not prove that no cluster activity occurred; "
                "verify that audit logs are forwarded to this LokiStack and retained for the "
                "requested period."
            )
        return ReadResult(observations=(AdHocObservation(
            id=f"audit-{uuid4()}",
            tool="query_audit_events",
            summary=(
                f"Read {len(events)} completed audit event"
                f"{'s' if len(events) != 1 else ''} "
                + (f"for user {username}" if username else "across all users")
                + (f" in namespace {namespace}." if namespace else ".")
            ),
            source="loki:audit/query/user_actions",
            collected_at=self._clock(),
            data={
                "username": redact_text(username)[:512] if username else None,
                "namespace": namespace,
                "resource": resource,
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
                "matchedRecordProfiles": matched_profiles,
            },
        ),), limitations=tuple(limitations))

    def _project_events(
        self,
        snapshot: AuditLogEntries,
        *,
        username: str | None,
        namespace: str | None,
        resource: str | None,
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
            object_ref = event.get("objectRef") if isinstance(event.get("objectRef"), dict) else {}
            observed_namespace = str(object_ref.get("namespace") or "")
            if namespace and observed_namespace.casefold() != namespace.casefold():
                continue
            observed_resource = str(object_ref.get("resource") or "")
            if resource and observed_resource.casefold() != resource.casefold():
                continue
            audit_id = str(event.get("auditID") or "")[:128]
            identity = audit_id or f"{timestamp_ns}:{verb}:{len(events)}"
            if identity in seen:
                continue
            seen.add(identity)
            occurred_at = _timestamp(event.get("requestReceivedTimestamp"), timestamp_ns)
            events.append({
                "timestamp": occurred_at.isoformat() if occurred_at else "unknown",
                "username": redact_text(observed_username)[:512],
                "verb": verb[:64] or "unknown",
                "apiGroup": str(object_ref.get("apiGroup") or "")[:128] or None,
                "apiVersion": str(object_ref.get("apiVersion") or "")[:128] or None,
                "resource": observed_resource[:128] or None,
                "subresource": str(object_ref.get("subresource") or "")[:128] or None,
                "namespace": observed_namespace[:253] or None,
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
