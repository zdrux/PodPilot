"""Deterministic memory/event timeline; temporal association is not causality."""
from datetime import datetime, timezone


def timestamp(value):
    if not isinstance(value, (str, datetime)):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except ValueError:
        return None


def memory_timeline(data: dict, pod: dict, events: list[dict], logs: list[dict] | None = None) -> dict:
    metadata = pod.get("metadata") or {}
    namespace, name, uid = metadata.get("namespace"), metadata.get("name"), metadata.get("uid")
    start, end = timestamp(data.get("start")), timestamp(data.get("end"))
    limitations = [
        "Working-set samples are not a continuous measurement of all memory charged to the container.",
        "Event/termination timing alone does not prove the cause of a failure.",
        "Historical metric series without Pod UID labels may span a replacement with the same name.",
    ]
    if not uid or namespace != data.get("namespace") or name != data.get("name") or not start or not end:
        return {"markers": [], "limitations": ["Exact Pod identity or metric time window is unavailable."]}
    markers = []

    def add(at, reason, source, container="", timing="occurrence"):
        observed = timestamp(at)
        if observed and start <= observed <= end:
            markers.append({"timestamp": observed.isoformat(), "reason": str(reason or "Unknown")[:80],
                            "source": source, "pod_uid": uid, "container": str(container)[:253], "timing": timing})

    status = pod.get("status") or {}
    for container in status.get("containerStatuses", status.get("container_statuses", []))[:30]:
        container_name = container.get("name") or ""
        if data.get("container") and container_name != data["container"]:
            continue
        for state_key in ("state", "lastState", "last_state"):
            terminated = (container.get(state_key) or {}).get("terminated") or {}
            add(terminated.get("finishedAt") or terminated.get("finished_at"), terminated.get("reason"),
                f"kubernetes:Pod:{namespace}/{name}:{uid}:{state_key}", container_name)
    for event in events[:50]:
        target = event.get("involvedObject") or event.get("involved_object") or event.get("regarding") or {}
        if target.get("uid") != uid or target.get("kind") != "Pod":
            continue
        event_metadata = event.get("metadata") or {}
        source = f"kubernetes:Event:{namespace}/{event_metadata.get('name', '')}:{event_metadata.get('uid', '')}"
        series = event.get("series") or {}
        last = (series.get("lastObservedTime") or series.get("last_observed_time") or
                event.get("lastTimestamp") or event.get("last_timestamp") or event.get("eventTime") or event.get("event_time"))
        add(last, event.get("reason"), source, timing="last observed occurrence")
    for entry in (logs or [])[-6:]:
        if entry.get("pod_uid") != uid:
            continue
        observed = timestamp(entry.get("timestamp"))
        if observed and start <= observed <= end:
            markers.append({"timestamp": observed.isoformat(), "reason": "Previous log" if entry.get("previous") else "Container log",
                            "source": entry["source"], "pod_uid": uid, "container": entry.get("container", ""),
                            "timing": "container log timestamp", "message": str(entry.get("message", ""))[:240]})
    unique = {(m["timestamp"], m["source"], m["reason"]): m for m in markers}
    ordered = sorted(unique.values(), key=lambda marker: marker["timestamp"])
    if len(ordered) > 30:
        limitations.append("Only the latest 30 timeline markers are shown.")
    return {"markers": ordered[-30:], "pod_uid": uid, "limitations": limitations}
