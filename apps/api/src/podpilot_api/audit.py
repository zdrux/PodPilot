"""Portable, bounded audit export. Audit is an event category, not a log level."""
from __future__ import annotations

import json
import re
from datetime import timezone

from podpilot_diagnostics.redaction import redact_text
from podpilot_api.models import AuditEvent

_SENSITIVE = re.compile(r"token|password|credential|secret|authorization|cookie|private.?key|api.?key", re.I)


def safe_details(value: object, *, depth: int = 0) -> object:
    if depth >= 6:
        return "[depth limit]"
    if isinstance(value, dict):
        return {
            redact_text(str(key))[:128]: "[redacted]" if _SENSITIVE.search(str(key)) else
            safe_details(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [safe_details(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return redact_text(value)[:4096]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return "[unsupported value]"


def export_event(event: AuditEvent) -> dict[str, object]:
    try:
        details = json.loads(event.details_json)
    except (ValueError, TypeError):
        details = {"limitation": "Stored event details were not valid JSON."}
    timestamp = event.occurred_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return {
        "schema_version": 1,
        "event_category": "audit",
        "event_id": event.id,
        "occurred_at": timestamp.astimezone(timezone.utc).isoformat(),
        "actor": redact_text(event.actor),
        "action": event.action,
        "outcome": event.outcome,
        "details": safe_details(details),
    }
