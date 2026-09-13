"""Isolated Ask log analysis and bounded, volatile evidence storage."""
from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict
from dataclasses import replace
from threading import Lock
from uuid import uuid4

from starlette.concurrency import run_in_threadpool

from podpilot_diagnostics.redaction import redact_text


class LogExcerptCache:
    """Process-local cache; access authorization belongs to the conversation route."""

    def __init__(self, max_bytes=32 * 1024 * 1024, ttl_seconds=86400, clock=time.time):
        self.max_bytes, self.ttl_seconds, self.clock = max_bytes, ttl_seconds, clock
        self.entries = OrderedDict()
        self.size = 0
        self.lock = Lock()

    def _expire(self):
        for key, (expiry, text, size) in list(self.entries.items()):
            if expiry <= self.clock():
                self.entries.pop(key)
                self.size -= size

    def put(self, text):
        text = redact_text(text).encode("utf-8")[-65536:].decode("utf-8", "ignore")
        size = len(text.encode("utf-8"))
        with self.lock:
            self._expire()
            if size > self.max_bytes:
                return None
            while self.entries and (self.size + size > self.max_bytes or len(self.entries) >= 512):
                _, (_, _, removed) = self.entries.popitem(last=False)
                self.size -= removed
            key = uuid4().hex
            expiry = self.clock() + self.ttl_seconds
            self.entries[key] = (expiry, text, size)
            self.size += size
            return {"id": key, "expires_at": expiry, "bytes": size}

    def get(self, key):
        with self.lock:
            self._expire()
            entry = self.entries.get(key)
            return entry[1] if entry else None


LOG_EXCERPTS = LogExcerptCache()


def log_mode(intent, question):
    if intent.log_mode != "auto":
        return intent.log_mode
    # Default ambiguous requests to investigation; simple viewing stays direct.
    diagnostic = re.search(r"\b(error|errors|fail\w*|crash\w*|why|diagnos\w*|troubleshoot\w*|analy[sz]\w*|check|investigat\w*)\b", question, re.I)
    viewing = re.search(r"\b(show|display|print|tail|last\s+\d+\s+lines)\b", question, re.I)
    return "display" if viewing and not diagnostic else "analyze"


def prepare_log_intent(intent, question):
    """Preserve an explicit viewing line count when the planner omitted it."""
    if intent.tool == "pod_logs" and intent.tail_lines is None and log_mode(intent, question) == "display":
        count = re.search(r"\b(?:last|tail)\s+(\d+)\s+(?:log\s+)?lines\b", question, re.I)
        if count and 1 <= int(count[1]) <= 1000:
            return intent.model_copy(update={"tail_lines": int(count[1])})
    return intent


class AskLogAnalyst:
    """One bounded specialist call per excerpt, with no inherited chat history."""

    def __init__(self, cache=LOG_EXCERPTS, max_calls=20):
        self.cache, self.max_calls, self.calls = cache, max_calls, 0

    async def process(self, observations, *, intent, question, provider, profile, api_key, progress=None, deadline=None):
        if intent.tool != "pod_logs" or log_mode(intent, question) == "display":
            return observations, []
        output, limitations = [], []
        for item in observations:
            if item.get("tool") != "pod_logs":
                output.append(item)
                continue
            data = dict(item.get("data") or {})
            original = redact_text(str(data.pop("tail", "")))
            excerpt = original.encode("utf-8")[-65536:].decode("utf-8", "ignore")
            data["excerpt_truncated"] = len(excerpt) < len(original)
            data.pop("entries", None)  # Loki duplicates the raw text here.
            reference = self.cache.put(excerpt)
            if reference:
                data["raw_log_excerpt"] = reference
            data["log_analysis"] = {"status": "unavailable"}
            data["coverage"] = "Only the collected bounded excerpt; not the complete log stream or all discovered Pods."
            result = {**item, "data": data}
            output.append(result)
            remaining = deadline - asyncio.get_running_loop().time() - 15 if deadline else 30
            if remaining < 3:
                issue = "Investigation deadline reached; this excerpt was retained but not analyzed."
            elif not excerpt.strip():
                issue = "No log text was collected; absence of errors is not established."
            elif self.calls >= self.max_calls:
                issue = "Log specialist budget exhausted; this excerpt was retained but not analyzed."
            elif not callable(getattr(provider, "analyze_logs", None)):
                issue = "Log specialist unavailable; inspect the retained excerpt."
            else:
                self.calls += 1
                if progress:
                    target = "/".join(value for value in (intent.namespace, intent.name) if value)
                    if intent.container:
                        target += f" (container {intent.container})"
                    target = redact_text(target) or "the selected Pod"
                    await progress("collecting", f"Analyzing logs for {target} with a log specialist.")
                try:
                    analysis = await run_in_threadpool(
                        provider.analyze_logs,
                        replace(profile, timeout_seconds=min(profile.timeout_seconds, 30, remaining),
                                max_output_tokens=min(profile.max_output_tokens, 1600), max_retries=0),
                        api_key,
                        {"operator_request": redact_text(question)[:2000],
                         "logs": [{"evidence_id": item["id"], "source": item.get("source"),
                                   "cluster_id": item.get("cluster_id"), "container": data.get("container"),
                                   "excerpt": excerpt}]},
                    )
                    report = analysis.model_dump()
                    issues = report.get("issues", [])
                    # Reject invented citations or excerpts before coordinator consumption.
                    if any(i.get("evidence_ids") != [item["id"]] or
                           not i.get("supporting_excerpt") or i["supporting_excerpt"] not in excerpt
                           for i in issues):
                        raise ValueError("Unsupported log finding")
                    compact_issues = [{
                        "evidence_ids": i["evidence_ids"], "severity": i["severity"],
                        "category": i["category"], "summary": i["summary"][:200],
                        "supporting_excerpt": i["supporting_excerpt"][:200],
                        "confidence": i["confidence"],
                    } for i in issues[:3]]
                    data["log_analysis"] = {
                        "status": "completed", "overview": report["overview"],
                        "issues": compact_issues, "issues_omitted": max(0, len(issues) - 3),
                        "limitations": report.get("limitations", []),
                    }
                    result["summary"] = report["overview"]
                    continue
                except Exception:
                    issue = "Log specialist failed; this excerpt was retained but not analyzed."
            data["log_analysis"]["limitation"] = issue
            limitations.append(f"{item.get('id')}: {issue}")
        return output, limitations
