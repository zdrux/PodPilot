from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator


_DEFERRED_TARGET = re.compile(
    r"(?i)(?:"
    r"[<>{}\[\]]|"
    r"\b(?:first|next|previous|selected|replace|insert)[-_ ]+"
    r"(?:pod|resource|object|deployment|container|namespace|name)\b|"
    r"\b(?:pod|resource|object|deployment|container|namespace)[-_ ]+name[-_ ]+"
    r"(?:from|in)[-_ ]+(?:previous[-_ ])?list\b"
    r")"
)
_METRIC_IDENTIFIER = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
_VALID_API_VERSION = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]*(?:/[A-Za-z0-9][A-Za-z0-9.-]*)?$"
)
_SEARCH_FIELD_PATH = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$"
)
_POD_LOG_SOURCE = re.compile(
    r"^kubernetes:v1:Pod/log:(?P<namespace>[^/]+)/(?P<pod>[^?]+)"
)
_LOG_SIGNAL_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "crash_or_exception", "critical",
        re.compile(
            r"(?i)\b(?:fatal|panic|unhandled exception|traceback|segmentation fault|"
            r"core dumped|crashloopbackoff|back-off restarting)\b",
        ),
    ),
    (
        "resource_pressure", "critical",
        re.compile(
            r"(?i)\b(?:oomkilled|out of memory|cannot allocate memory|no space left|"
            r"disk full|too many open files|resource exhausted)\b",
        ),
    ),
    (
        "tls_or_certificate", "error",
        re.compile(
            r"(?i)\b(?:tls|ssl|x509|certificate|certs?|cert(?:ificate)?|handshake|unknown authority|"
            r"unknown ca|self-signed)\b[^\n]{0,180}\b(?:error|failed|failure|invalid|expired|"
            r"missing|refused|unknown|no such file|unable|denied)\b|"
            r"\b(?:error|failed|failure|invalid|expired|missing|refused|unknown|no such file|"
            r"unable|denied)\b[^\n]{0,180}\b(?:tls|ssl|x509|certificate|certs?)\b",
        ),
    ),
    (
        "dns_resolution", "error",
        re.compile(
            r"(?i)\b(?:nxdomain|servfail|no such host|name or service not known|"
            r"temporary failure in name resolution|dns lookup failed|could not resolve)\b",
        ),
    ),
    (
        "network_connectivity", "error",
        re.compile(
            r"(?i)\b(?:connection refused|connection reset|reset by peer|context deadline exceeded|"
            r"i/o timeout|connect timeout|read timeout|no route to host|network is unreachable|"
            r"broken pipe|upstream connect error|connection failure)\b",
        ),
    ),
    (
        "authentication_or_authorization", "error",
        re.compile(
            r"(?i)\b(?:unauthorized|forbidden|authentication failed|authorization failed|"
            r"access[_ -]denied|permission[_ -]denied|invalid[_ -]token|token[_ -]expired|"
            r"http(?:\s+|[_ .-]?(?:status[_ .-]?code)?[=:]?\s*)(?:401|403))\b",
        ),
    ),
    (
        "storage_or_mount", "error",
        re.compile(
            r"(?i)\b(?:failedmount|mount failed|failed to mount|unmount failed|i/o error|"
            r"read-only file system|volume attach failed|filesystem error)\b",
        ),
    ),
    (
        "dependency_or_upstream", "error",
        re.compile(
            r"(?i)\b(?:upstream|backend|dependency|database|broker)\b[^\n]{0,160}"
            r"\b(?:unavailable|failed|failure|error|timeout|refused|http\s+(?:502|503|504))\b|"
            r"\bhttp\s+(?:502|503|504)\b",
        ),
    ),
    (
        "application_error", "error",
        re.compile(r"(?i)\b(?:error|exception|failed|failure)\b"),
    ),
    (
        "warning", "warning",
        re.compile(r"(?i)\b(?:warn|warning|degraded|retrying|backoff)\b"),
    ),
)
_TLS_LOG_SIGNAL_RULE = next(
    rule for rule in _LOG_SIGNAL_RULES if rule[0] == "tls_or_certificate"
)
_LOG_TIMESTAMP = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b"
)
_LOG_PATH = re.compile(r"(?<![A-Za-z0-9])/[A-Za-z0-9_.\-/]+")
_LOG_ENDPOINT = re.compile(
    r"(?i)\b(?:https?://[^\s\"'<>]+|[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?:\d{2,5})\b"
)
_TLS_TRUST_ERROR_MARKERS = (
    "certificate verify failed", "self-signed certificate", "unknown ca",
    "unable to get local issuer certificate", "certificate signed by unknown authority",
)
_TLS_FILE_MARKER = re.compile(
    r"(?i)(?:\b(?:tls|ssl|x509|certificate|certs?|private\s+key)\b|"
    r"\.(?:pem|crt|cer|key)\b)",
)
_FILE_ACCESS_ERROR_MARKER = re.compile(
    r"(?i)\b(?:file\s*not\s*found|filenotfounderror|no\s+such\s+file|does\s+not\s+exist|"
    r"missing|enoent|cannot\s+open|can't\s+open|failed\s+to\s+open|permission\s+denied)\b",
)


def looks_like_deferred_target(value: str | None) -> bool:
    """Identify model placeholders that are not observed Kubernetes coordinates."""
    return bool(value and _DEFERRED_TARGET.search(value))


class ReadIntent(BaseModel):
    """A model-selected request whose final scope is validated by normal code."""

    tool: Literal[
        "discover_resources", "get_resource", "list_resources", "search_resources",
        "watch_resources", "pod_logs", "http_probe", "query_metrics",
        "query_audit_events",
    ]
    discovery_query: str | None = Field(default=None, max_length=253)
    resource: str | None = Field(default=None, max_length=253)
    api_version: str | None = Field(default=None, max_length=128)
    kind: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=253)
    label_selector: str | None = Field(default=None, max_length=512)
    match_field: str | None = Field(default=None, max_length=512)
    match_value: str | None = Field(default=None, max_length=512)
    match_operator: Literal["exact", "contains"] = "exact"
    container: str | None = Field(default=None, max_length=253)
    candidate_id: str | None = Field(default=None, max_length=80)
    url: str | None = Field(default=None, max_length=2048)
    connect_host: str | None = Field(default=None, max_length=253)
    method: Literal["HEAD", "GET"] = "HEAD"
    tls_verify: bool = True
    metric: Literal[
        "cpu_usage", "cpu_requests", "cpu_limits", "cpu_throttling",
        "memory_working_set", "memory_requests", "memory_limits",
        "network_receive", "network_transmit", "container_restarts",
        "persistent_volume_usage", "pod_readiness", "top_cpu_consumers",
        "top_memory_consumers", "top_log_volume_by_namespace",
        "node_cpu_utilization", "node_memory_utilization",
    ] | None = None
    metric_scope: Literal[
        "cluster", "pod", "namespace", "deployment", "node", "persistent_volume_claim"
    ] | None = None
    audit_username: str | None = Field(default=None, max_length=512)
    audit_operation_scope: Literal["all", "mutations", "deletes"] | None = None
    audit_outcome: Literal["all", "successful", "failed"] | None = None
    audit_search_until_limit: bool = False
    range_seconds: int = Field(default=3600, ge=300, le=7_776_000)
    step_seconds: int = Field(default=60, ge=15, le=3600)
    previous: bool = False
    since_seconds: int | None = Field(default=None, ge=1, le=2_592_000)
    watch_seconds: int = Field(default=10, ge=1, le=15)
    limit: int = Field(default=20, ge=1, le=1000)

    @field_validator(
        "resource", "api_version", "kind", "namespace", "name", "container", "candidate_id"
    )
    @classmethod
    def require_exact_target(cls, value: str | None) -> str | None:
        if looks_like_deferred_target(value):
            raise ValueError("must be an exact target, not a deferred placeholder")
        return value

    @field_validator("match_field")
    @classmethod
    def require_search_field_path(cls, value: str | None) -> str | None:
        if value is not None and not _SEARCH_FIELD_PATH.fullmatch(value):
            raise ValueError("must be a dot-separated Kubernetes object field path")
        return value

    @model_validator(mode="after")
    def validate_candidate_usage(self) -> "ReadIntent":
        if self.candidate_id and self.tool != "pod_logs":
            raise ValueError("candidate_id is valid only for pod_logs")
        if self.tool == "http_probe":
            if any(ord(character) < 32 or ord(character) == 127 for character in (self.url or "")):
                raise ValueError("http_probe URL must not contain control characters")
            parsed = urlsplit(self.url or "")
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("http_probe requires an absolute HTTP or HTTPS URL")
            try:
                parsed.port
            except ValueError as exc:
                raise ValueError("http_probe URL contains an invalid port") from exc
            if parsed.username or parsed.password:
                raise ValueError("http_probe URLs must not contain credentials")
            if not self.tls_verify and parsed.scheme != "https":
                raise ValueError("tls_verify may be disabled only for HTTPS probes")
            if self.connect_host and (
                any(character.isspace() for character in self.connect_host)
                or any(character in self.connect_host for character in "/?#@")
            ):
                raise ValueError("connect_host must be a hostname or IP address")
        elif self.url or self.connect_host or not self.tls_verify:
            raise ValueError("url, connect_host, and tls_verify=false are valid only for http_probe")
        if self.tool == "search_resources":
            if not self.match_field or not self.match_value:
                raise ValueError("search_resources requires match_field and match_value")
            if any(ord(character) < 32 or ord(character) == 127 for character in self.match_value):
                raise ValueError("search_resources match_value must not contain control characters")
        elif self.match_field or self.match_value:
            raise ValueError("match_field and match_value are valid only for search_resources")
        if self.tool == "query_metrics":
            if not self.metric or not self.metric_scope:
                raise ValueError("query_metrics requires metric and metric_scope")
            if self.metric_scope not in {"cluster", "node"} and not self.namespace:
                raise ValueError("the selected metric scope requires an exact namespace")
            if self.metric_scope in {
                "pod", "deployment", "node", "persistent_volume_claim"
            } and not self.name:
                raise ValueError("the selected metric scope requires an exact name")
            if (self.namespace and not _METRIC_IDENTIFIER.fullmatch(self.namespace)) or (
                self.name and not _METRIC_IDENTIFIER.fullmatch(self.name)
            ):
                raise ValueError("metric scope coordinates must be exact Kubernetes identifiers")
            if self.metric in {
                "top_cpu_consumers", "top_memory_consumers",
            }:
                if self.metric_scope not in {"cluster", "namespace", "deployment", "node"}:
                    raise ValueError(
                        "the selected top-consumer metric requires cluster, namespace, deployment, or node scope"
                    )
            if self.metric == "top_log_volume_by_namespace" and self.metric_scope != "cluster":
                raise ValueError(
                    "top_log_volume_by_namespace requires cluster scope"
                )
            if self.metric in {"node_cpu_utilization", "node_memory_utilization"}:
                if self.metric_scope != "node":
                    raise ValueError("the selected node utilization metric requires node scope")
            if self.metric == "persistent_volume_usage":
                if self.metric_scope != "persistent_volume_claim":
                    raise ValueError("persistent_volume_usage requires persistent_volume_claim scope")
            elif self.metric_scope == "persistent_volume_claim":
                raise ValueError("persistent_volume_claim scope supports only persistent_volume_usage")
        elif self.metric or self.metric_scope:
            raise ValueError("metric and metric_scope are valid only for query_metrics")
        if self.tool == "query_audit_events":
            if not self.audit_username:
                raise ValueError("query_audit_events requires an exact audit username")
            if any(
                ord(character) < 32 or ord(character) == 127
                for character in self.audit_username
            ):
                raise ValueError("audit username must not contain control characters")
            if self.audit_operation_scope is None or self.audit_outcome is None:
                raise ValueError(
                    "query_audit_events requires operation scope and outcome semantics"
                )
        elif any((
            self.audit_username,
            self.audit_operation_scope,
            self.audit_outcome,
            self.audit_search_until_limit,
        )):
            raise ValueError("audit fields are valid only for query_audit_events")
        if self.tool == "discover_resources":
            if not self.discovery_query:
                raise ValueError("discover_resources requires a discovery_query")
            if any((self.resource, self.api_version, self.kind, self.namespace, self.name)):
                raise ValueError("discover_resources accepts only a discovery_query and limit")
        elif self.discovery_query:
            raise ValueError("discovery_query is valid only for discover_resources")
        if self.tool != "watch_resources" and self.watch_seconds != 10:
            raise ValueError("watch_seconds is valid only for watch_resources")
        if self.tool != "pod_logs" and self.since_seconds is not None:
            raise ValueError("since_seconds is valid only for pod_logs")
        return self


class ReadPlan(BaseModel):
    _selection_incomplete: bool = PrivateAttr(default=False)
    _discarded_intent_count: int = PrivateAttr(default=0)

    goal_type: Literal[
        "inventory", "health", "diagnose", "logs", "compare", "explain"
    ] = "diagnose"
    decision: Literal[
        "collect", "answer_from_evidence", "needs_clarification"
    ] | None = None
    scope_summary: str = Field(min_length=1, max_length=500)
    candidate_ids: list[str] = Field(default_factory=list, max_length=6)
    intents: list[ReadIntent] = Field(default_factory=list, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=5)
    clarification: str | None = Field(default=None, max_length=500)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=12)
    working_hypothesis: str | None = Field(default=None, max_length=500)
    next_step_summary: str | None = Field(default=None, max_length=500)
    stop_reason: Literal[
        "evidence_sufficient", "no_material_read", "budget_exhausted", "blocked"
    ] | None = None

    @field_validator("candidate_ids")
    @classmethod
    def require_exact_candidate_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(r"read-[a-f0-9]{20}", value):
                raise ValueError("candidate_ids must contain exact supplied read candidate IDs")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def normalize_decision(self) -> "ReadPlan":
        # Intents and clarification are the authoritative output. Deriving this
        # redundant discriminator server-side avoids rejecting otherwise usable
        # plans from smaller structured-output models.
        if self.candidate_ids or self.intents:
            self.decision = "collect"
        elif self.clarification:
            self.decision = "needs_clarification"
        elif self.decision in {None, "collect"}:
            self.decision = "answer_from_evidence"
        return self


class CandidateReadPlan(BaseModel):
    """Small model contract for selecting server-grounded reads without tool synthesis."""

    goal_type: Literal[
        "inventory", "health", "diagnose", "logs", "compare", "explain"
    ] = "diagnose"
    decision: Literal[
        "collect", "answer_from_evidence", "needs_clarification"
    ] | None = None
    scope_summary: str = Field(min_length=1, max_length=500)
    candidate_ids: list[str] = Field(default_factory=list, max_length=6)
    clarification: str | None = Field(default=None, max_length=500)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=12)
    working_hypothesis: str | None = Field(default=None, max_length=500)
    next_step_summary: str | None = Field(default=None, max_length=500)
    stop_reason: Literal[
        "evidence_sufficient", "no_material_read", "budget_exhausted", "blocked"
    ] | None = None

    @field_validator("candidate_ids")
    @classmethod
    def require_exact_candidate_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(r"read-[a-f0-9]{20}", value):
                raise ValueError("candidate_ids must contain exact supplied read candidate IDs")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def normalize_decision(self) -> "CandidateReadPlan":
        if self.candidate_ids:
            self.decision = "collect"
        elif self.clarification:
            self.decision = "needs_clarification"
        elif self.decision in {None, "collect"}:
            self.decision = "answer_from_evidence"
        return self

    def to_read_plan(self) -> ReadPlan:
        return ReadPlan.model_validate(self.model_dump())


class InvestigationGap(BaseModel):
    """A model-identified evidence question; never an executable instruction."""

    question: str = Field(min_length=1, max_length=500)
    capability: Literal[
        "resource_read", "service_spec", "endpoints", "pod_spec", "pod_logs",
        "metrics", "http_probe", "other",
    ] = "resource_read"
    priority: Literal["low", "medium", "high"] = "medium"
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=8)
    reason: str | None = Field(default=None, max_length=500)


class PodLogCandidate(BaseModel):
    """An exact server-derived Pod/container target a model may select by opaque ID."""

    id: str = Field(min_length=8, max_length=80)
    evidence_id: str = Field(min_length=1, max_length=128)
    namespace: str = Field(min_length=1, max_length=253)
    pod: str = Field(min_length=1, max_length=253)
    container: str | None = Field(default=None, max_length=253)
    phase: str | None = Field(default=None, max_length=64)
    ready: bool | None = None
    restart_count: int = Field(default=0, ge=0)
    investigation_priority: Literal["normal", "elevated", "high"] = "normal"
    trigger_reasons: list[str] = Field(default_factory=list, max_length=4)


def _candidate_id(evidence_id: str, namespace: str, pod: str, container: str | None) -> str:
    digest = sha256(
        f"{evidence_id}\0{namespace}\0{pod}\0{container or ''}".encode("utf-8")
    ).hexdigest()[:20]
    return f"podlog-{digest}"


def pod_log_candidates_from_evidence(
    evidence: list[dict[str, object]],
) -> list[PodLogCandidate]:
    """Extract exact Pod/container targets from normalized list observations."""

    candidates: list[PodLogCandidate] = []
    seen: set[tuple[str, str, str | None]] = set()

    def add(
        *, evidence_id: str, namespace: object, pod: object, container: object = None,
        phase: object = None, ready: object = None, restart_count: object = 0,
    ) -> None:
        namespace_text = str(namespace or "")[:253]
        pod_text = str(pod or "")[:253]
        container_text = str(container)[:253] if container else None
        if not namespace_text or namespace_text == "cluster" or not pod_text:
            return
        key = (namespace_text, pod_text, container_text)
        if key in seen:
            return
        seen.add(key)
        try:
            restarts = max(0, int(restart_count or 0))
        except (TypeError, ValueError):
            restarts = 0
        trigger_reasons: list[str] = []
        phase_text = str(phase)[:64] if phase else None
        if phase_text and phase_text not in {"Running", "Succeeded"}:
            trigger_reasons.append(f"Pod phase is {phase_text}")
        if ready is False and phase_text != "Succeeded":
            trigger_reasons.append("container is not Ready")
        if restarts:
            trigger_reasons.append(f"container restart count is {restarts}")
        priority = (
            "high" if (
                (ready is False and phase_text != "Succeeded")
                or (phase_text and phase_text not in {"Running", "Succeeded"})
            )
            else "elevated" if restarts else "normal"
        )
        candidates.append(PodLogCandidate(
            id=_candidate_id(evidence_id, namespace_text, pod_text, container_text),
            evidence_id=evidence_id,
            namespace=namespace_text,
            pod=pod_text,
            container=container_text,
            phase=phase_text,
            ready=ready if isinstance(ready, bool) else None,
            restart_count=restarts,
            investigation_priority=priority,
            trigger_reasons=trigger_reasons,
        ))

    for observation in evidence:
        if observation.get("tool") not in {
            "list_resources", "search_resources", "get_resource",
        }:
            continue
        evidence_id = str(observation.get("id") or "")[:128]
        data = observation.get("data")
        if not evidence_id or not isinstance(data, dict):
            continue
        explicit = data.get("logCandidates")
        if isinstance(explicit, list):
            for item in explicit:
                if not isinstance(item, dict):
                    continue
                containers = item.get("containers") or [None]
                if not isinstance(containers, list):
                    containers = [None]
                raw_statuses = item.get("containerStatuses") or []
                statuses_by_name = {
                    str(status.get("name")): status
                    for status in raw_statuses
                    if isinstance(status, dict) and status.get("name")
                }
                for container in containers or [None]:
                    container_status = statuses_by_name.get(str(container), {})
                    add(
                        evidence_id=evidence_id,
                        namespace=item.get("namespace") or data.get("scope"),
                        pod=item.get("pod") or item.get("name"),
                        container=container,
                        phase=item.get("phase"),
                        ready=(
                            container_status.get("ready")
                            if container_status else item.get("ready")
                        ),
                        restart_count=(
                            container_status.get("restartCount")
                            if container_status else item.get("restartCount")
                        ),
                    )
            continue

        if observation.get("tool") == "get_resource" and str(data.get("kind")) == "Pod":
            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
            status = data.get("status") if isinstance(data.get("status"), dict) else {}
            statuses = status.get("containerStatuses") or status.get("container_statuses") or []
            containers = [
                item.get("name") for item in statuses
                if isinstance(item, dict) and item.get("name")
            ]
            if not containers:
                raw_containers = spec.get("containers") or []
                containers = [
                    item.get("name") for item in raw_containers
                    if isinstance(item, dict) and item.get("name")
                ]
            statuses_by_name = {
                str(item.get("name")): item
                for item in statuses
                if isinstance(item, dict) and item.get("name")
            }
            for container in containers or [None]:
                container_status = statuses_by_name.get(str(container), {})
                add(
                    evidence_id=evidence_id,
                    namespace=metadata.get("namespace"),
                    pod=metadata.get("name"),
                    container=container,
                    phase=status.get("phase"),
                    ready=container_status.get("ready"),
                    restart_count=(
                        container_status.get("restartCount")
                        or container_status.get("restart_count")
                        or 0
                    ),
                )
            continue

        source = str(observation.get("source") or "")
        legacy_pod_list = (
            observation.get("tool") == "list_resources"
            and ":Pod:" in source
            and bool(data.get("namespace") or data.get("scope"))
            and bool(data.get("pod") or data.get("name"))
        )
        if str(data.get("kind") or "") != "Pod" and not legacy_pod_list:
            continue
        items = data.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                status = item.get("status") if isinstance(item.get("status"), dict) else {}
                statuses = status.get("containerStatuses")
                if isinstance(statuses, list) and statuses:
                    for container_status in statuses:
                        if not isinstance(container_status, dict):
                            continue
                        add(
                            evidence_id=evidence_id,
                            namespace=metadata.get("namespace") or data.get("scope"),
                            pod=metadata.get("name"),
                            container=container_status.get("name"),
                            phase=status.get("phase"),
                            ready=container_status.get("ready"),
                            restart_count=container_status.get("restartCount"),
                        )
                else:
                    add(
                        evidence_id=evidence_id,
                        namespace=metadata.get("namespace") or data.get("scope"),
                        pod=metadata.get("name"),
                        phase=status.get("phase"),
                    )
            continue

        containers = data.get("containers") or [None]
        if not isinstance(containers, list):
            containers = [None]
        for container in containers or [None]:
            add(
                evidence_id=evidence_id,
                namespace=data.get("namespace") or data.get("scope"),
                pod=data.get("pod") or data.get("name"),
                container=container,
                phase=data.get("phase"),
            )
    return candidates


def derive_evidence_relationship_graph(
    evidence: list[dict[str, object]],
    *,
    max_nodes: int = 120,
    max_edges: int = 240,
) -> dict[str, object]:
    """Build a bounded graph from explicit Kubernetes references in normalized evidence."""

    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []
    edge_keys: set[tuple[str, str, str]] = set()

    def node_key(
        kind: object, namespace: object, name: object, *, selector: str | None = None
    ) -> str:
        scope = str(namespace or "cluster")[:253]
        coordinate = str(name or (f"selector:{selector}" if selector else "unknown"))[:512]
        return f"{str(kind or 'Resource')[:128]}:{scope}/{coordinate}"

    def add_node(
        kind: object,
        namespace: object,
        name: object,
        *,
        evidence_id: str | None = None,
        observed: bool = False,
        selector: str | None = None,
    ) -> str:
        key = node_key(kind, namespace, name, selector=selector)
        node = nodes.setdefault(key, {
            "id": key,
            "kind": str(kind or "Resource")[:128],
            "namespace": str(namespace or "cluster")[:253],
            "name": str(name)[:253] if name else None,
            "selector": selector,
            "observed": False,
            "evidence_ids": [],
        })
        node["observed"] = bool(node["observed"] or observed)
        if evidence_id and evidence_id not in node["evidence_ids"]:
            node["evidence_ids"].append(evidence_id)
        return key

    def add_edge(
        source: str,
        target: str,
        relation: str,
        evidence_id: str,
        read_hint: dict[str, object] | None = None,
    ) -> None:
        key = (source, target, relation)
        if key in edge_keys or len(edges) >= max_edges:
            return
        edge_keys.add(key)
        edges.append({
            "source": source,
            "target": target,
            "relation": relation,
            "evidence_ids": [evidence_id],
            "target_observed": bool(nodes.get(target, {}).get("observed")),
            "read_hint": read_hint,
        })

    def objects_from_observation(
        observation: dict[str, object],
    ) -> list[dict[str, object]]:
        data = observation.get("data")
        if not isinstance(data, dict):
            return []
        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        if isinstance(data.get("metadata"), dict):
            return [data]
        return []

    for observation in evidence:
        evidence_id = str(observation.get("id") or "")[:128]
        if not evidence_id:
            continue
        for obj in objects_from_observation(observation):
            metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
            spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
            kind = str(obj.get("kind") or (
                observation.get("data", {}).get("kind")
                if isinstance(observation.get("data"), dict) else "Resource"
            ) or "Resource")
            namespace = metadata.get("namespace") or "cluster"
            name = metadata.get("name")
            if not name:
                continue
            source = add_node(
                kind, namespace, name, evidence_id=evidence_id, observed=True
            )

            owners = metadata.get("ownerReferences") or metadata.get("owner_references")
            if isinstance(owners, list):
                for owner in owners:
                    if not isinstance(owner, dict) or not owner.get("name"):
                        continue
                    owner_kind = owner.get("kind") or "Resource"
                    target = add_node(owner_kind, namespace, owner.get("name"))
                    add_edge(source, target, "owned_by", evidence_id, {
                        "tool": "get_resource", "kind": owner_kind,
                        "api_version": owner.get("apiVersion") or owner.get("api_version"),
                        "namespace": namespace, "name": owner.get("name"),
                    })

            if kind == "Route":
                backends: list[dict[str, object]] = []
                if isinstance(spec.get("to"), dict):
                    backends.append(spec["to"])
                if isinstance(spec.get("alternateBackends"), list):
                    backends.extend(
                        item for item in spec["alternateBackends"] if isinstance(item, dict)
                    )
                for backend in backends:
                    if not backend.get("name"):
                        continue
                    target = add_node("Service", namespace, backend.get("name"))
                    add_edge(source, target, "routes_to", evidence_id, {
                        "tool": "get_resource", "resource": "services",
                        "api_version": "v1", "kind": "Service",
                        "namespace": namespace, "name": backend.get("name"),
                    })

            if kind == "Service":
                selector = spec.get("selector") if isinstance(spec.get("selector"), dict) else {}
                selector_text = ",".join(
                    f"{key}={value}" for key, value in sorted(selector.items())
                )
                if selector_text:
                    target = add_node("Pod", namespace, None, selector=selector_text)
                    add_edge(source, target, "selects", evidence_id, {
                        "tool": "list_resources", "resource": "pods", "api_version": "v1",
                        "kind": "Pod", "namespace": namespace,
                        "label_selector": selector_text,
                    })
                endpoint_selector = f"kubernetes.io/service-name={name}"
                target = add_node("EndpointSlice", namespace, None, selector=endpoint_selector)
                add_edge(source, target, "has_endpoints", evidence_id, {
                    "tool": "list_resources", "resource": "endpointslices",
                    "api_version": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                    "namespace": namespace, "label_selector": endpoint_selector,
                })

            if kind in {"EndpointSlice", "Endpoints"}:
                target_refs: list[dict[str, object]] = []
                endpoints = obj.get("endpoints")
                if not isinstance(endpoints, list):
                    endpoints = spec.get("endpoints") if isinstance(spec.get("endpoints"), list) else []
                for endpoint in endpoints:
                    if not isinstance(endpoint, dict):
                        continue
                    target_ref = endpoint.get("targetRef") or endpoint.get("target_ref")
                    if isinstance(target_ref, dict):
                        target_refs.append(target_ref)
                subsets = obj.get("subsets") if isinstance(obj.get("subsets"), list) else []
                for subset in subsets:
                    if not isinstance(subset, dict):
                        continue
                    for address in [
                        *list(subset.get("addresses") or []),
                        *list(subset.get("notReadyAddresses") or []),
                    ]:
                        if not isinstance(address, dict):
                            continue
                        target_ref = address.get("targetRef") or address.get("target_ref")
                        if isinstance(target_ref, dict):
                            target_refs.append(target_ref)
                for target_ref in target_refs:
                    if not target_ref.get("name"):
                        continue
                    target_kind = target_ref.get("kind") or "Pod"
                    target_namespace = target_ref.get("namespace") or namespace
                    target = add_node(target_kind, target_namespace, target_ref.get("name"))
                    add_edge(source, target, "targets", evidence_id, {
                        "tool": "get_resource", "kind": target_kind,
                        "api_version": target_ref.get("apiVersion") or "v1",
                        "namespace": target_namespace, "name": target_ref.get("name"),
                    })

            mounts = obj.get("podpilotMounts")
            if isinstance(mounts, list):
                source_kinds = {
                    "ConfigMap": ("ConfigMap", "configmaps", "v1"),
                    "PersistentVolumeClaim": ("PersistentVolumeClaim", "persistentvolumeclaims", "v1"),
                    "Secret": ("Secret", "secrets", "v1"),
                }
                for mount in mounts:
                    if not isinstance(mount, dict) or not mount.get("sourceName"):
                        continue
                    source_type = str(mount.get("sourceType") or "Resource")
                    target_kind, resource, api_version = source_kinds.get(
                        source_type, (source_type, None, None)
                    )
                    target = add_node(target_kind, namespace, mount.get("sourceName"))
                    read_hint = None if target_kind == "Secret" else {
                        "tool": "get_resource", "resource": resource,
                        "api_version": api_version, "kind": target_kind,
                        "namespace": namespace, "name": mount.get("sourceName"),
                    }
                    add_edge(source, target, "mounts_from", evidence_id, read_hint)

            config_references = obj.get("podpilotConfigReferences")
            if isinstance(config_references, list):
                for reference in config_references:
                    if not isinstance(reference, dict) or not reference.get("sourceName"):
                        continue
                    source_type = str(reference.get("sourceType") or "Resource")
                    target = add_node(source_type, namespace, reference.get("sourceName"))
                    read_hint = None
                    if source_type == "ConfigMap":
                        read_hint = {
                            "tool": "get_resource", "resource": "configmaps",
                            "api_version": "v1", "kind": "ConfigMap",
                            "namespace": namespace, "name": reference.get("sourceName"),
                        }
                    add_edge(source, target, "configures_from", evidence_id, read_hint)

    bounded_nodes = list(nodes.values())[:max_nodes]
    bounded_ids = {str(node["id"]) for node in bounded_nodes}
    bounded_edges = []
    for edge in edges:
        if edge["source"] not in bounded_ids or edge["target"] not in bounded_ids:
            continue
        normalized_edge = dict(edge)
        normalized_edge["target_observed"] = bool(
            nodes.get(str(edge["target"]), {}).get("observed")
        )
        bounded_edges.append(normalized_edge)
        if len(bounded_edges) >= max_edges:
            break
    frontier = [
        edge for edge in bounded_edges
        if not edge["target_observed"] and edge.get("read_hint") is not None
    ]
    return {
        "nodes": bounded_nodes,
        "edges": bounded_edges,
        "frontier": frontier,
        "truncated": len(nodes) > max_nodes or len(edges) > max_edges,
    }


def plan_needs_evidence_repair(
    plan: ReadPlan,
    *,
    known_evidence_ids: set[str],
    has_completed_reads: bool,
) -> bool:
    """Reject an unsupported no-read answer for a model-classified operational goal."""

    actionable = {"inventory", "health", "diagnose", "logs", "compare", "explain"}
    has_valid_support = bool(known_evidence_ids.intersection(plan.supporting_evidence_ids))
    return (
        plan.goal_type in actionable
        and plan.decision == "answer_from_evidence"
        and not has_valid_support
        and not has_completed_reads
    )


_BUILTIN_RESOURCE_TYPES: dict[str, tuple[str, str]] = {
    "configmap": ("v1", "ConfigMap"), "configmaps": ("v1", "ConfigMap"),
    "daemonset": ("apps/v1", "DaemonSet"), "daemonsets": ("apps/v1", "DaemonSet"),
    "deployment": ("apps/v1", "Deployment"), "deployments": ("apps/v1", "Deployment"),
    "event": ("v1", "Event"), "events": ("v1", "Event"),
    "ingresscontroller": ("operator.openshift.io/v1", "IngressController"),
    "ingresscontrollers": ("operator.openshift.io/v1", "IngressController"),
    "namespace": ("v1", "Namespace"), "namespaces": ("v1", "Namespace"),
    "networkpolicy": ("networking.k8s.io/v1", "NetworkPolicy"),
    "networkpolicies": ("networking.k8s.io/v1", "NetworkPolicy"),
    "node": ("v1", "Node"), "nodes": ("v1", "Node"),
    "persistentvolume": ("v1", "PersistentVolume"),
    "persistentvolumeclaim": ("v1", "PersistentVolumeClaim"),
    "pod": ("v1", "Pod"), "pods": ("v1", "Pod"),
    "replicaset": ("apps/v1", "ReplicaSet"), "replicasets": ("apps/v1", "ReplicaSet"),
    "route": ("route.openshift.io/v1", "Route"), "routes": ("route.openshift.io/v1", "Route"),
    "service": ("v1", "Service"), "services": ("v1", "Service"),
    "statefulset": ("apps/v1", "StatefulSet"), "statefulsets": ("apps/v1", "StatefulSet"),
    "storageclass": ("storage.k8s.io/v1", "StorageClass"),
    "storageclasses": ("storage.k8s.io/v1", "StorageClass"),
}
_KIND_RESOURCE_NAMES = {
    "ConfigMap": "configmaps", "DaemonSet": "daemonsets", "Deployment": "deployments",
    "Event": "events", "IngressController": "ingresscontrollers", "Namespace": "namespaces",
    "NetworkPolicy": "networkpolicies", "Node": "nodes", "PersistentVolume": "persistentvolumes",
    "PersistentVolumeClaim": "persistentvolumeclaims", "Pod": "pods", "ReplicaSet": "replicasets",
    "Route": "routes", "Service": "services", "StatefulSet": "statefulsets",
    "StorageClass": "storageclasses",
}


def normalize_read_intent(intent: ReadIntent) -> ReadIntent:
    """Canonicalize trusted built-in resource coordinates before broker validation."""

    updates: dict[str, object] = {}
    if (
        intent.namespace is not None
        and intent.namespace.strip() == "*"
        and intent.tool in {"list_resources", "search_resources", "watch_resources"}
    ):
        # Models commonly use ``*`` to mean every namespace. Kubernetes does not
        # accept it as a namespace identifier; the broker represents cluster-wide
        # collection with an omitted namespace instead.
        updates["namespace"] = None
    if intent.tool == "pod_logs" or not intent.kind:
        return intent.model_copy(update=updates) if updates else intent
    coordinates = _BUILTIN_RESOURCE_TYPES.get(intent.kind.lower())
    if not coordinates:
        return intent.model_copy(update=updates) if updates else intent
    api_version, kind = coordinates
    if (intent.resource and "." in intent.resource) or (
        intent.api_version
        and _VALID_API_VERSION.fullmatch(intent.api_version)
        and intent.api_version != api_version
    ):
        return intent.model_copy(update=updates) if updates else intent
    return intent.model_copy(update={
        **updates,
        "resource": _KIND_RESOURCE_NAMES[kind],
        "api_version": api_version,
        "kind": kind,
    })


_NAMESPACE_RESOURCE_QUERY = re.compile(
    r"\b(?:show|list|display|what|which)\b.*?\b"
    r"(?P<kind>pods?|services?|deployments?|statefulsets?|daemonsets?|configmaps?|routes?)\b"
    r".*?\b(?:in|from)\s+(?:the\s+)?(?:namespace\s+)?(?P<namespace>[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\b",
    re.IGNORECASE,
)
_URL_QUERY = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_NAMESPACE_TOP_CONSUMERS_QUERY = re.compile(
    r"\b(?:most|top|highest|largest|biggest)\b.*?\b(?P<metric>cpu|memory)\b"
    r".*?\b(?:in|from|within)\s+(?:the\s+)?(?:namespace\s+)?"
    r"(?P<namespace>[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\b|"
    r"\b(?P<metric_first>cpu|memory)\b.*?\b(?:most|top|highest|largest|biggest)\b"
    r".*?\b(?:in|from|within)\s+(?:the\s+)?(?:namespace\s+)?"
    r"(?P<namespace_second>[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\b",
    re.IGNORECASE,
)
_CLUSTER_LOG_VOLUME_QUERY = re.compile(
    r"\b(?:which|what)\s+(?:namespaces?|projects?)\b.*?"
    r"\b(?:producing|generating|writing)\b.*?\b(?:logs?|logging)\b|"
    r"\b(?:top|rank|show|list)\b.*?\b(?:namespaces?|projects?)\b.*?"
    r"\bby\s+(?:application[- ]?)?(?:log|logging)\s+(?:volume|bytes?|traffic)\b|"
    r"\b(?:application[- ]?)?(?:log|logging)\s+(?:volume|bytes?|traffic)\b.*?"
    r"\bby\s+(?:namespaces?|projects?)\b",
    re.IGNORECASE,
)
_METRIC_DURATION_QUERY = re.compile(
    r"\b(?:last|past|previous)\s+"
    r"(?:(?P<count>\d{1,3}|one|a|an)\s*)?"
    r"(?P<unit>seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\b",
    re.IGNORECASE,
)
_METRIC_TOP_LIMIT_QUERY = re.compile(
    r"\btop\s+(?P<limit>\d{1,3})\b",
    re.IGNORECASE,
)
_DEFAULT_METRIC_RANGE_SECONDS = 3600
_MIN_METRIC_RANGE_SECONDS = 300
_MAX_METRIC_RANGE_SECONDS = 7_776_000
_DEFAULT_METRIC_RESULT_LIMIT = 10
_KUBERNETES_NAME_PATTERN = r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?"
_NODE_LABEL_TARGET_QUERIES = (
    re.compile(
        rf"\blabels?\b.*?\b(?:on|for|of)\s+(?:the\s+)?nodes?\s+"
        rf"[`'\"]?(?P<name>{_KUBERNETES_NAME_PATTERN})[`'\"]?",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bnodes?\s+(?:named\s+|called\s+)?"
        rf"[`'\"]?(?P<name>{_KUBERNETES_NAME_PATTERN})[`'\"]?"
        rf"(?:'s)?\s+labels?\b",
        re.IGNORECASE,
    ),
)
_POD_IN_NAMESPACE_QUERY = re.compile(
    rf"\bpod\s+[`'\"]?(?P<pod>{_KUBERNETES_NAME_PATTERN})[`'\"]?\s+"
    rf"(?:in|from)\s+(?:the\s+)?(?:namespace\s+)?"
    rf"[`'\"]?(?P<namespace>{_KUBERNETES_NAME_PATTERN})[`'\"]?",
    re.IGNORECASE,
)
_NAMESPACE_POD_COORDINATE_QUERY = re.compile(
    rf"\b(?:from|to|between)\s+(?:the\s+)?(?:pod\s+)?"
    rf"[`'\"]?(?P<namespace>{_KUBERNETES_NAME_PATTERN})/"
    rf"(?P<pod>{_KUBERNETES_NAME_PATTERN})[`'\"]?",
    re.IGNORECASE,
)
_CROSS_NAMESPACE_CONNECTIVITY_QUERY = re.compile(
    r"\b(?:tcp|connect(?:ion|ivity|ing)?|timeout|timed\s+out|unreachable|refused)\b",
    re.IGNORECASE,
)
_POD_LOG_WORD_QUERY = re.compile(r"\b(?:logs?|logging)\b", re.IGNORECASE)
_EXPLICIT_NAMESPACE_QUERY = re.compile(
    rf"\b(?:in|from)\s+(?:the\s+)?(?:"
    rf"namespace\s+(?P<prefix>{_KUBERNETES_NAME_PATTERN})|"
    rf"(?P<suffix>{_KUBERNETES_NAME_PATTERN})\s+namespace"
    rf")\b",
    re.IGNORECASE,
)
_POD_HINT_BEFORE_KIND_QUERY = re.compile(
    rf"\b(?:an?\s+|the\s+)?(?P<hint>{_KUBERNETES_NAME_PATTERN})\s+pods?\b",
    re.IGNORECASE,
)
_POD_HINT_AFTER_KIND_QUERY = re.compile(
    rf"\bpods?\s+(?:named\s+|called\s+)?(?P<hint>{_KUBERNETES_NAME_PATTERN})\b",
    re.IGNORECASE,
)


def _requested_metric_range_seconds(
    question: str,
    *,
    now: datetime | None = None,
) -> int:
    """Parse a bounded operator-requested relative metric period."""

    if re.search(r"\btoday\b", question, re.IGNORECASE):
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        seconds = int((current - start).total_seconds())
        return min(_MAX_METRIC_RANGE_SECONDS, max(_MIN_METRIC_RANGE_SECONDS, seconds))
    match = _METRIC_DURATION_QUERY.search(question)
    if match is None:
        return _DEFAULT_METRIC_RANGE_SECONDS
    raw_count = (match.group("count") or "1").lower()
    count = 1 if raw_count in {"one", "a", "an"} else int(raw_count)
    unit = match.group("unit").lower()
    multiplier = (
        1 if unit in {"s", "sec", "secs", "second", "seconds"} else
        60 if unit in {"m", "min", "mins", "minute", "minutes"} else
        3600 if unit in {"h", "hr", "hrs", "hour", "hours"} else
        86_400
    )
    return min(
        _MAX_METRIC_RANGE_SECONDS,
        max(_MIN_METRIC_RANGE_SECONDS, count * multiplier),
    )


def _requested_metric_result_limit(question: str, *, default: int) -> int:
    match = _METRIC_TOP_LIMIT_QUERY.search(question)
    if match is None:
        return default
    return min(100, max(1, int(match.group("limit"))))


def _pod_log_discovery_plan(question: str) -> ReadPlan | None:
    """Compile a bounded Pod-name search before any exact container-log read."""

    if not re.search(r"\bpods?\b", question, re.IGNORECASE):
        return None
    namespace_match = _EXPLICIT_NAMESPACE_QUERY.search(question)
    if namespace_match is None:
        return None
    question_without_namespace = (
        question[:namespace_match.start()] + " " + question[namespace_match.end():]
    )
    if not _POD_LOG_WORD_QUERY.search(question_without_namespace):
        return None
    ignored_hints = {
        "a", "an", "any", "for", "from", "in", "of", "on", "some", "that",
        "the", "this", "to",
    }
    hint = None
    for pattern in (_POD_HINT_BEFORE_KIND_QUERY, _POD_HINT_AFTER_KIND_QUERY):
        for hint_match in pattern.finditer(question):
            candidate = hint_match.group("hint").lower()
            if candidate not in ignored_hints:
                hint = candidate
                break
        if hint is not None:
            break
    if hint is None:
        return None
    namespace = (
        namespace_match.group("prefix") or namespace_match.group("suffix")
    ).lower()
    return ReadPlan(
        goal_type="logs",
        scope_summary=(
            f"Find Pods containing {hint} in namespace {namespace} before reading exact logs."
        ),
        intents=[ReadIntent(
            tool="search_resources",
            resource="pods",
            api_version="v1",
            kind="Pod",
            namespace=namespace,
            match_field="metadata.name",
            match_value=hint,
            match_operator="contains",
            limit=20,
        )],
    )


def _cross_namespace_network_policy_plan(question: str) -> ReadPlan | None:
    """Compile an explicit cross-namespace Pod pair into bounded policy evidence reads."""

    if not _CROSS_NAMESPACE_CONNECTIVITY_QUERY.search(question):
        return None
    references: list[tuple[int, str, str]] = []
    for pattern in (_POD_IN_NAMESPACE_QUERY, _NAMESPACE_POD_COORDINATE_QUERY):
        references.extend(
            (match.start(), match.group("namespace"), match.group("pod"))
            for match in pattern.finditer(question)
        )
    references.sort(key=lambda item: item[0])
    pods_by_namespace: dict[str, str] = {}
    for _, namespace, pod in references:
        pods_by_namespace.setdefault(namespace.lower(), pod.lower())
    if len(pods_by_namespace) != 2:
        return None
    endpoints = list(pods_by_namespace.items())
    intents: list[ReadIntent] = []
    for namespace, pod in endpoints:
        intents.append(ReadIntent(
            tool="get_resource", resource="pods", api_version="v1",
            kind="Pod", namespace=namespace, name=pod,
        ))
    for namespace, _ in endpoints:
        intents.append(ReadIntent(
            tool="get_resource", resource="namespaces", api_version="v1",
            kind="Namespace", name=namespace,
        ))
    for namespace, _ in endpoints:
        intents.append(ReadIntent(
            tool="list_resources", resource="networkpolicies",
            api_version="networking.k8s.io/v1", kind="NetworkPolicy",
            namespace=namespace, limit=100,
        ))
    source_namespace, source_pod = endpoints[0]
    destination_namespace, destination_pod = endpoints[1]
    return ReadPlan(
        goal_type="diagnose",
        scope_summary=(
            f"Inspect cross-namespace policy selectors for {source_namespace}/{source_pod} "
            f"and {destination_namespace}/{destination_pod}."
        ),
        intents=intents,
    )


def plan_known_read(
    question: str,
    *,
    inventory_limit: int = 500,
    alert_name: str | None = None,
    alert_labels: dict[str, object] | None = None,
    now: datetime | None = None,
) -> tuple[ReadPlan, bool] | None:
    """Compile unambiguous inventory and alert-scoped reads without model syntax."""

    lowered = question.lower()
    metric_range_seconds = _requested_metric_range_seconds(question, now=now)
    metric_result_limit = _requested_metric_result_limit(
        question, default=_DEFAULT_METRIC_RESULT_LIMIT,
    )
    if _CLUSTER_LOG_VOLUME_QUERY.search(question):
        return (
            ReadPlan(
                goal_type="compare",
                scope_summary=(
                    "Rank namespaces by application-log payload volume across the cluster "
                    f"over {metric_range_seconds} seconds."
                ),
                intents=[ReadIntent(
                    tool="query_metrics",
                    metric="top_log_volume_by_namespace",
                    metric_scope="cluster",
                    range_seconds=metric_range_seconds,
                    limit=metric_result_limit,
                )],
            ),
            True,
        )
    for pattern in _NODE_LABEL_TARGET_QUERIES:
        node_match = pattern.search(question)
        if node_match is None:
            continue
        node_name = node_match.group("name").lower()
        return (
            ReadPlan(
                goal_type="explain",
                scope_summary=f"Read labels from the exact Node {node_name}.",
                intents=[ReadIntent(
                    tool="get_resource",
                    resource="nodes",
                    api_version="v1",
                    kind="Node",
                    name=node_name,
                )],
            ),
            True,
        )
    network_policy_plan = _cross_namespace_network_policy_plan(question)
    if network_policy_plan is not None:
        return network_policy_plan, False
    pod_log_plan = _pod_log_discovery_plan(question)
    if pod_log_plan is not None:
        return pod_log_plan, False
    top_consumers = _NAMESPACE_TOP_CONSUMERS_QUERY.search(question)
    if top_consumers:
        metric_result_limit = _requested_metric_result_limit(question, default=20)
        metric_name = top_consumers.group("metric") or top_consumers.group("metric_first")
        namespace = (
            top_consumers.group("namespace") or top_consumers.group("namespace_second")
        )
        metric = (
            "top_cpu_consumers" if metric_name.lower() == "cpu"
            else "top_memory_consumers"
        )
        return (
            ReadPlan(
                goal_type="compare",
                scope_summary=(
                    f"Rank monitored {metric_name.upper()} consumers in namespace {namespace}."
                ),
                intents=[ReadIntent(
                    tool="query_metrics",
                    metric=metric,
                    metric_scope="namespace",
                    namespace=namespace,
                    range_seconds=metric_range_seconds,
                    limit=metric_result_limit,
                )],
            ),
            True,
        )
    url_match = _URL_QUERY.search(question)
    if url_match and "route" in lowered:
        try:
            hostname = urlsplit(url_match.group(0).rstrip(".,);]}")).hostname
        except ValueError:
            hostname = None
        if hostname:
            return (
                ReadPlan(
                    goal_type="diagnose",
                    scope_summary=f"Find the OpenShift Route for host {hostname}.",
                    intents=[ReadIntent(
                        tool="search_resources",
                        resource="routes.route.openshift.io",
                        api_version="route.openshift.io/v1",
                        kind="Route",
                        match_field="spec.host",
                        match_value=hostname,
                        match_operator="exact",
                        limit=5,
                    )],
                ),
                False,
            )
    if "storageclass" in lowered or "storage class" in lowered:
        return (
            ReadPlan(
                scope_summary="List cluster StorageClasses.",
                intents=[ReadIntent(
                    tool="list_resources",
                    resource="storageclasses",
                    api_version="storage.k8s.io/v1",
                    kind="StorageClass",
                    limit=inventory_limit,
                )],
            ),
            True,
        )

    match = _NAMESPACE_RESOURCE_QUERY.search(question)
    if match:
        proposed = ReadIntent(
            tool="list_resources",
            kind=match.group("kind"),
            namespace=match.group("namespace"),
            limit=inventory_limit,
        )
        intent = normalize_read_intent(proposed)
        terminal_inventory = match.group("kind").lower().endswith("s")
        return (
            ReadPlan(
                goal_type="inventory" if terminal_inventory else "diagnose",
                scope_summary=f"List {intent.kind} resources in {intent.namespace}.",
                intents=[intent],
            ),
            terminal_inventory,
        )

    labels = alert_labels or {}
    namespace = str(labels.get("namespace") or "")
    job_name = str(labels.get("job_name") or labels.get("jobName") or "")
    if (
        alert_name in {"KubeJobFailed", "KubeJobCompletion"}
        and "job" in lowered
        and namespace
        and job_name
    ):
        return (
            ReadPlan(
                scope_summary=f"Inspect alert-scoped Job {namespace}/{job_name}.",
                intents=[ReadIntent(
                    tool="get_resource",
                    resource="jobs",
                    api_version="batch/v1",
                    kind="Job",
                    namespace=namespace,
                    name=job_name,
                )],
            ),
            False,
        )
    return None


def plan_catalog_read(
    question: str,
    resource_catalog: list[dict[str, object]],
    *,
    inventory_limit: int = 500,
) -> tuple[ReadPlan, bool] | None:
    """Compile a generic inventory/health fallback against the live safe catalog."""

    inventory_request = bool(re.search(
        r"\b(?:show|list|display|what|which)\b", question, re.IGNORECASE
    ))
    health_request = bool(re.search(
        r"\b(?:check|inspect|status|health|healthy|degraded)\b", question, re.IGNORECASE
    ))
    if not inventory_request and not health_request:
        return None
    lowered = question.lower()
    namespace_match = re.search(
        r"\b(?:in|from)\s+(?:the\s+)?(?:namespace\s+)?"
        r"(?P<namespace>[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\b",
        question,
        re.IGNORECASE,
    )
    namespace = namespace_match.group("namespace") if namespace_match else None
    normalized_question = re.sub(r"[^a-z0-9]", "", lowered)
    question_terms = set(re.findall(r"[a-z0-9]+", lowered))
    matches: list[tuple[tuple[int, int, int, int], dict[str, object]]] = []
    for entry in resource_catalog:
        resource = str(entry.get("resource") or "")
        kind = str(entry.get("kind") or "")
        api_version = str(entry.get("apiVersion") or "")
        if not resource or not kind or not api_version:
            continue
        unqualified = resource.split(".", 1)[0]
        kind_words = re.sub(r"(?<!^)(?=[A-Z])", " ", kind).lower()
        aliases = {unqualified.lower(), kind.lower(), kind_words}
        for alias in aliases:
            if re.search(rf"\b{re.escape(alias)}s?\b", lowered):
                normalized_kind = re.sub(r"[^a-z0-9]", "", kind.lower())
                group = api_version.split("/", 1)[0] if "/" in api_version else "core"
                group_terms = {
                    term for term in re.findall(r"[a-z0-9]+", group.lower())
                    if len(term) >= 3 and term not in {"k8s", "io"}
                }
                # Prefer the resource whose complete Kind is explicitly named. This
                # distinguishes core Node from NodeMetrics when both advertise the
                # plural ``nodes``. A group word in the question similarly resolves
                # same-Kind CRDs such as OpenShift and Cluster API Machines.
                exact_kind = int(bool(
                    normalized_kind and normalized_kind in normalized_question
                ))
                group_overlap = len(question_terms.intersection(group_terms))
                platform_preference = (
                    2 if group == "core" else
                    1 if "openshift.io" in group else
                    0
                )
                matches.append(((
                    exact_kind, group_overlap, platform_preference, len(alias)
                ), entry))
                break
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    entry = matches[0][1]
    namespaced = bool(entry.get("namespaced"))
    if not namespaced and namespace:
        return None
    resource = str(entry["resource"])
    api_version = str(entry["apiVersion"])
    kind = str(entry["kind"])
    return (
        ReadPlan(
            goal_type="health" if health_request else "inventory",
            scope_summary=f"List {kind} resources in {namespace or 'the cluster'}.",
            intents=[ReadIntent(
                tool="list_resources",
                resource=resource,
                api_version=api_version,
                kind=kind,
                namespace=namespace,
                limit=inventory_limit,
            )],
        ),
        True,
    )


@dataclass(frozen=True)
class AdHocObservation:
    id: str
    tool: str
    summary: str
    source: str
    collected_at: datetime
    data: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReadResult:
    observations: tuple[AdHocObservation, ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AutomaticReadFollowup:
    """A deterministic, evidence-derived continuation within the existing read budget."""

    code: Literal[
        "tls_trust_retry", "traffic_path_investigation", "pod_log_investigation",
        "log_signal_investigation", "configuration_detail",
    ]
    reason: str
    intent: ReadIntent
    evidence_ids: tuple[str, ...]


def _log_signature(line: str) -> str:
    """Normalize volatile log values so repeated messages consume one finding sample."""

    normalized = _LOG_TIMESTAMP.sub("<time>", line).lower()
    normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    return re.sub(r"\s+", " ", normalized).strip()[:500]


def _recommended_log_followups(category: str) -> list[str]:
    recommendations = [
        "Read the exact Pod specification to inspect status, probes, ports, mounts, and owner references.",
        "Search namespace Events for the exact Pod name.",
    ]
    if category in {"crash_or_exception", "resource_pressure"}:
        recommendations.insert(0, "Read previous logs for the same container when a terminated instance exists.")
    if category in {"network_connectivity", "dns_resolution", "dependency_or_upstream"}:
        recommendations.append(
            "Resolve any exact observed Service or endpoint and correlate it with a bounded connectivity probe."
        )
    elif category == "tls_or_certificate":
        recommendations.append(
            "Correlate the signal with a verified HTTPS probe and a trust-only retry when required."
        )
    elif category == "resource_pressure":
        recommendations.append(
            "Correlate termination state with bounded workload and node CPU or memory metrics."
        )
    elif category == "storage_or_mount":
        recommendations.append(
            "Inspect referenced volume and claim status without reading Secret contents."
        )
    recommendations.append("Treat log matches as signals; require corroborating evidence before claiming causality.")
    return recommendations


def derive_adhoc_findings(evidence: list[dict[str, object]]) -> list[dict[str, object]]:
    """Classify bounded log signals for any container without executing log text."""

    findings: list[dict[str, object]] = []
    for observation in evidence:
        if observation.get("tool") != "pod_logs":
            continue
        data = observation.get("data")
        if not isinstance(data, dict):
            continue
        tail = str(data.get("tail") or "")[:32_768]
        if not tail:
            continue
        source = str(observation.get("source") or "")
        coordinate = _POD_LOG_SOURCE.match(source)
        namespace = coordinate.group("namespace") if coordinate else None
        pod = coordinate.group("pod") if coordinate else None
        container = str(data.get("container") or "default")[:253]
        evidence_id = str(observation.get("id") or "unknown")
        grouped: dict[str, dict[str, object]] = {}
        lines = [raw_line.strip()[:500] for raw_line in tail.splitlines()]
        for index, line in enumerate(lines):
            if not line:
                continue
            context = " ".join(
                item for item in lines[max(0, index - 2):index + 3] if item
            )[:1500]
            correlated_tls_file_error = (
                _FILE_ACCESS_ERROR_MARKER.search(line) is not None
                and _TLS_FILE_MARKER.search(context) is not None
            )
            matched_rule = (
                _TLS_LOG_SIGNAL_RULE
                if correlated_tls_file_error else
                next((rule for rule in _LOG_SIGNAL_RULES if rule[2].search(line)), None)
            )
            if matched_rule is None:
                continue
            category, severity, _pattern = matched_rule
            signal_text = context if correlated_tls_file_error else line
            group = grouped.setdefault(category, {
                "severity": severity, "occurrences": 0, "samples": [],
                "signatures": [], "timestamps": [], "paths": [], "endpoints": [],
            })
            group["occurrences"] = int(group["occurrences"]) + 1
            signature = _log_signature(line)
            if signature not in group["signatures"] and len(group["signatures"]) < 8:
                group["signatures"].append(signature)
            sample = re.sub(r"\s+", " ", signal_text).strip()[:500]
            if sample not in group["samples"] and len(group["samples"]) < 3:
                group["samples"].append(sample)
            for timestamp in _LOG_TIMESTAMP.findall(signal_text):
                if timestamp not in group["timestamps"] and len(group["timestamps"]) < 4:
                    group["timestamps"].append(timestamp)
            for path in _LOG_PATH.findall(signal_text):
                bounded = path.rstrip(".,:;)")[:300]
                if bounded not in group["paths"] and len(group["paths"]) < 8:
                    group["paths"].append(bounded)
            for endpoint in _LOG_ENDPOINT.findall(signal_text):
                bounded = endpoint.rstrip(".,:;)")[:300]
                if re.match(r"^\d{4}-\d{2}-\d{2}T", bounded):
                    continue
                if bounded not in group["endpoints"] and len(group["endpoints"]) < 8:
                    group["endpoints"].append(bounded)

        for category, group in grouped.items():
            completed_checks: list[str] = []
            related_evidence_ids = [evidence_id]
            mount_correlations: list[dict[str, object]] = []
            for candidate in evidence:
                candidate_data = candidate.get("data")
                if not isinstance(candidate_data, dict):
                    continue
                candidate_source = str(candidate.get("source") or "")
                candidate_id = str(candidate.get("id") or "")
                if (
                    namespace and pod
                    and candidate.get("tool") == "get_resource"
                    and candidate_source == f"kubernetes:v1:Pod:{namespace}/{pod}"
                ):
                    completed_checks.append("exact_pod_specification")
                    mounts = candidate_data.get("podpilotMounts")
                    if isinstance(mounts, list):
                        completed_checks.append("pod_mount_configuration")
                        for path in group["paths"]:
                            matches = [
                                mount for mount in mounts
                                if isinstance(mount, dict)
                                and str(mount.get("mountPath") or "")
                                and (
                                    str(path) == str(mount.get("mountPath"))
                                    or str(path).startswith(
                                        str(mount.get("mountPath")).rstrip("/") + "/"
                                    )
                                )
                            ]
                            if matches:
                                mount_correlations.extend({
                                    "path": path,
                                    "mounted": True,
                                    "container": mount.get("container"),
                                    "mountPath": mount.get("mountPath"),
                                    "volume": mount.get("volume"),
                                    "sourceType": mount.get("sourceType"),
                                    "sourceName": mount.get("sourceName"),
                                } for mount in matches)
                            else:
                                mount_correlations.append({"path": path, "mounted": False})
                    if candidate_id:
                        related_evidence_ids.append(candidate_id)
                if (
                    namespace and pod
                    and candidate.get("tool") == "search_resources"
                    and candidate_data.get("kind") == "Event"
                    and candidate_data.get("scope") == namespace
                    and candidate_data.get("matchField") == "involvedObject.name"
                    and candidate_data.get("matchValue") == pod
                ):
                    completed_checks.append("pod_events")
                    if candidate_id:
                        related_evidence_ids.append(candidate_id)
                if (
                    namespace and pod
                    and candidate.get("tool") == "pod_logs"
                    and candidate_source.startswith(
                        f"kubernetes:v1:Pod/log:{namespace}/{pod}?"
                    )
                    and candidate_data.get("container") == container
                    and candidate_data.get("previous") is True
                ):
                    completed_checks.append("previous_container_logs")
                    if candidate_id:
                        related_evidence_ids.append(candidate_id)
            occurrences = int(group["occurrences"])
            target = f" in Pod {namespace}/{pod}" if namespace and pod else ""
            required_checks = {"exact_pod_specification", "pod_events"}
            if group["paths"] and category in {"tls_or_certificate", "storage_or_mount"}:
                required_checks.add("pod_mount_configuration")
            findings.append({
                "id": "log-signal-" + sha256(
                    f"{evidence_id}\0{category}".encode()
                ).hexdigest()[:12],
                "kind": "log_signal",
                "category": category,
                "severity": group["severity"],
                "status": (
                    "investigated"
                    if required_checks.issubset(completed_checks)
                    else "open"
                ),
                "summary": (
                    f"Container {container}{target} emitted {occurrences} "
                    f"{category.replace('_', ' ')} signal{'s' if occurrences != 1 else ''} "
                    "in the bounded log excerpt."
                ),
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "previous_logs": bool(data.get("previous")),
                "occurrences_in_excerpt": occurrences,
                "distinct_signatures": len(group["signatures"]),
                "first_observed_timestamp": (
                    group["timestamps"][0] if group["timestamps"] else None
                ),
                "last_observed_timestamp": (
                    group["timestamps"][-1] if group["timestamps"] else None
                ),
                "paths": group["paths"],
                "endpoints": group["endpoints"],
                "error_samples": group["samples"],
                "mount_correlations": mount_correlations,
                "evidence_ids": list(dict.fromkeys(related_evidence_ids)),
                "completed_checks": list(dict.fromkeys(completed_checks)),
                "recommended_followups": _recommended_log_followups(category),
            })
    severity_order = {"critical": 0, "error": 1, "warning": 2}
    findings.sort(key=lambda item: (
        severity_order.get(str(item["severity"]), 3),
        -int(item["occurrences_in_excerpt"]),
        str(item["id"]),
    ))
    return findings[:20]


def automatic_read_followups(
    intent: ReadIntent,
    observations: tuple[AdHocObservation, ...],
    *,
    question: str = "",
    goal_type: str | None = None,
) -> tuple[AutomaticReadFollowup, ...]:
    """Plan narrow retries and evidence expansion from normalized observations."""

    traffic_question = bool(re.search(
        r"(?i)(?:https?://|\broute\b|\btraffic\b|\b(?:http|tls|ssl)\b|"
        r"\b(?:status|error)\s*5\d\d\b|\binternal server error\b|"
        r"\b(?:connect(?:ion|ivity)?|reachable|backend|endpoint)\b)",
        question,
    ))

    def observed_objects(kind: str) -> list[tuple[dict[str, object], str]]:
        matched: list[tuple[dict[str, object], str]] = []
        for observation in observations:
            data = observation.data
            if str(data.get("kind") or "") == kind:
                matched.append((data, observation.id))
            items = data.get("items")
            if isinstance(items, list):
                matched.extend(
                    (item, observation.id)
                    for item in items
                    if isinstance(item, dict)
                    and str(item.get("kind") or data.get("kind") or "") == kind
                )
        return matched

    if traffic_question and intent.tool in {
        "get_resource", "list_resources", "search_resources",
    }:
        traffic_followups: list[AutomaticReadFollowup] = []
        for route, evidence_id in observed_objects("Route")[:2]:
            metadata = route.get("metadata") if isinstance(route.get("metadata"), dict) else {}
            spec = route.get("spec") if isinstance(route.get("spec"), dict) else {}
            target = spec.get("to") if isinstance(spec.get("to"), dict) else {}
            namespace = str(metadata.get("namespace") or "")
            service = str(target.get("name") or "")
            if namespace and service and str(target.get("kind") or "Service") == "Service":
                traffic_followups.append(AutomaticReadFollowup(
                    code="traffic_path_investigation",
                    reason=(
                        f"Read the exact backend Service {namespace}/{service} referenced by the "
                        "observed OpenShift Route."
                    ),
                    intent=ReadIntent(
                        tool="get_resource", resource="services", api_version="v1",
                        kind="Service", namespace=namespace, name=service,
                    ),
                    evidence_ids=(evidence_id,),
                ))
        if traffic_followups:
            return tuple(traffic_followups)

        for service, evidence_id in observed_objects("Service")[:2]:
            metadata = service.get("metadata") if isinstance(service.get("metadata"), dict) else {}
            spec = service.get("spec") if isinstance(service.get("spec"), dict) else {}
            namespace = str(metadata.get("namespace") or "")
            name = str(metadata.get("name") or "")
            selector = spec.get("selector") if isinstance(spec.get("selector"), dict) else {}
            if not namespace or not name:
                continue
            if selector:
                label_selector = ",".join(
                    f"{key}={value}" for key, value in sorted(selector.items())
                    if key and value is not None
                )
                if label_selector and len(label_selector) <= 512:
                    traffic_followups.append(AutomaticReadFollowup(
                        code="traffic_path_investigation",
                        reason=(
                            f"List the bounded Pods selected by backend Service {namespace}/{name}."
                        ),
                        intent=ReadIntent(
                            tool="list_resources", resource="pods", api_version="v1",
                            kind="Pod", namespace=namespace, label_selector=label_selector,
                            limit=20,
                        ),
                        evidence_ids=(evidence_id,),
                    ))
            traffic_followups.extend((
                AutomaticReadFollowup(
                    code="traffic_path_investigation",
                    reason=f"Inspect EndpointSlices for backend Service {namespace}/{name}.",
                    intent=ReadIntent(
                        tool="list_resources", resource="endpointslices",
                        api_version="discovery.k8s.io/v1", kind="EndpointSlice",
                        namespace=namespace,
                        label_selector=f"kubernetes.io/service-name={name}", limit=20,
                    ),
                    evidence_ids=(evidence_id,),
                ),
                AutomaticReadFollowup(
                    code="traffic_path_investigation",
                    reason=f"Inspect the legacy Endpoints object for backend Service {namespace}/{name}.",
                    intent=ReadIntent(
                        tool="get_resource", resource="endpoints", api_version="v1",
                        kind="Endpoints", namespace=namespace, name=name,
                    ),
                    evidence_ids=(evidence_id,),
                ),
            ))
        if traffic_followups:
            return tuple(traffic_followups[:6])

        endpoint_pods: list[AutomaticReadFollowup] = []

        def endpoint_targets(endpoint_object: dict[str, object]) -> list[dict[str, object]]:
            targets = endpoint_object.get("podTargets")
            discovered = [item for item in targets if isinstance(item, dict)] if isinstance(
                targets, list
            ) else []
            endpoints = endpoint_object.get("endpoints")
            if isinstance(endpoints, list):
                discovered.extend(
                    target
                    for endpoint in endpoints
                    if isinstance(endpoint, dict)
                    for target in [endpoint.get("targetRef") or endpoint.get("target_ref")]
                    if isinstance(target, dict)
                )
            subsets = endpoint_object.get("subsets")
            if isinstance(subsets, list):
                discovered.extend(
                    target
                    for subset in subsets
                    if isinstance(subset, dict)
                    for address in [
                        *(subset.get("addresses") or []),
                        *(subset.get("notReadyAddresses") or subset.get("not_ready_addresses") or []),
                    ]
                    if isinstance(address, dict)
                    for target in [address.get("targetRef") or address.get("target_ref")]
                    if isinstance(target, dict)
                )
            return discovered

        for kind in ("EndpointSlice", "Endpoints"):
            for endpoint_object, evidence_id in observed_objects(kind):
                metadata = (
                    endpoint_object.get("metadata")
                    if isinstance(endpoint_object.get("metadata"), dict) else {}
                )
                default_namespace = str(metadata.get("namespace") or "")
                for target in endpoint_targets(endpoint_object):
                    if not isinstance(target, dict) or str(target.get("kind") or "Pod") != "Pod":
                        continue
                    namespace = str(target.get("namespace") or default_namespace)
                    name = str(target.get("name") or "")
                    if namespace and name:
                        endpoint_pods.append(AutomaticReadFollowup(
                            code="traffic_path_investigation",
                            reason=(
                                f"Read backend Pod {namespace}/{name} referenced by {kind} evidence."
                            ),
                            intent=ReadIntent(
                                tool="get_resource", resource="pods", api_version="v1",
                                kind="Pod", namespace=namespace, name=name,
                            ),
                            evidence_ids=(evidence_id,),
                        ))
        if endpoint_pods:
            return tuple(endpoint_pods[:3])

    if intent.tool == "http_probe" and intent.tls_verify:
        trust_failures = [
            observation for observation in observations
            if observation.data.get("stage") == "tls"
            and any(
                marker in str(observation.data.get("error") or "").lower()
                for marker in _TLS_TRUST_ERROR_MARKERS
            )
        ]
        if trust_failures:
            return (AutomaticReadFollowup(
                code="tls_trust_retry",
                reason=(
                    "The verified HTTPS probe reached certificate validation but could not trust "
                    "the presented chain; repeat the same bounded probe once without verification "
                    "to separate trust failure from endpoint behavior."
                ),
                intent=intent.model_copy(update={"tls_verify": False}),
                evidence_ids=tuple(item.id for item in trust_failures),
            ),)

    detail_question = (goal_type is not None and goal_type != "inventory") or bool(re.search(
        r"(?i)\b(?:configur(?:e|ed|ation)|set\s*up|setup|settings?|details?|"
        r"forward(?:ed|ing)?|routing?|pipeline|outputs?|inputs?|destinations?|"
        r"connect(?:ed|ion)?|integrat(?:e|ed|ion)|how\s+(?:does|do|is|are))\b",
        question,
    ))
    if detail_question and intent.tool in {"list_resources", "search_resources"}:
        detail_reads: list[AutomaticReadFollowup] = []
        seen_targets: set[tuple[str, str]] = set()
        for observation in observations:
            data = observation.data
            refs = data.get("objects") if isinstance(data.get("objects"), list) else []
            api_version = str(data.get("apiVersion") or intent.api_version or "") or None
            kind = str(data.get("kind") or intent.kind or "") or None
            resource = str(data.get("resource") or intent.resource or "") or None
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                name = str(ref.get("name") or "")[:253]
                namespace = str(ref.get("namespace") or "")[:253] or None
                if not name or (namespace or "", name) in seen_targets:
                    continue
                seen_targets.add((namespace or "", name))
                detail_reads.append(AutomaticReadFollowup(
                    code="configuration_detail",
                    reason=(
                        f"Read the exact {kind or 'resource'} {namespace + '/' if namespace else ''}"
                        f"{name} discovered by the bounded list so its material configuration can be explained."
                    ),
                    intent=ReadIntent(
                        tool="get_resource", resource=resource, api_version=api_version,
                        kind=kind, namespace=namespace, name=name,
                    ),
                    evidence_ids=(observation.id,),
                ))
                if len(detail_reads) >= 3:
                    return tuple(detail_reads)
        if detail_reads:
            return tuple(detail_reads)

    if intent.tool in {"get_resource", "list_resources", "search_resources"}:
        candidates = pod_log_candidates_from_evidence(
            [item.to_dict() for item in observations]
        )
        prioritized = sorted(
            (
                candidate for candidate in candidates
                if candidate.investigation_priority != "normal"
                or (
                    traffic_question
                    and candidate.phase != "Succeeded"
                )
            ),
            key=lambda candidate: (
                0 if candidate.investigation_priority == "high" else 1,
                -candidate.restart_count,
                candidate.namespace,
                candidate.pod,
                candidate.container or "",
            ),
        )[:3]
        if prioritized:
            return tuple(AutomaticReadFollowup(
                code="pod_log_investigation",
                reason=(
                    f"Inspect {candidate.namespace}/{candidate.pod} container "
                    f"{candidate.container or 'default'} because "
                    + (
                        "; ".join(candidate.trigger_reasons)
                        if candidate.trigger_reasons
                        else "it serves the backend traffic path under investigation"
                    )
                    + "."
                ),
                intent=ReadIntent(
                    tool="pod_logs", namespace=candidate.namespace, name=candidate.pod,
                    container=candidate.container, candidate_id=candidate.id,
                ),
                evidence_ids=(candidate.evidence_id,),
            ) for candidate in prioritized)

    if intent.tool != "pod_logs":
        return ()
    findings = derive_adhoc_findings([item.to_dict() for item in observations])
    followups: list[AutomaticReadFollowup] = []
    for finding in findings:
        if (
            finding.get("severity") == "warning"
            and int(finding.get("occurrences_in_excerpt") or 0) < 2
        ):
            continue
        namespace = finding.get("namespace")
        pod = finding.get("pod")
        evidence_ids = tuple(str(item) for item in finding["evidence_ids"])
        if not namespace or not pod:
            continue
        reason = str(finding["summary"])
        category = str(finding.get("category") or "")
        if (
            category in {"crash_or_exception", "resource_pressure"}
            and intent.candidate_id
            and not intent.previous
        ):
            followups.append(AutomaticReadFollowup(
                code="log_signal_investigation",
                reason=reason,
                intent=intent.model_copy(update={"previous": True}),
                evidence_ids=evidence_ids,
            ))
        followups.extend((
            AutomaticReadFollowup(
                code="log_signal_investigation",
                reason=reason,
                intent=ReadIntent(
                    tool="get_resource", resource="pods", api_version="v1", kind="Pod",
                    namespace=str(namespace), name=str(pod),
                ),
                evidence_ids=evidence_ids,
            ),
            AutomaticReadFollowup(
                code="log_signal_investigation",
                reason=reason,
                intent=ReadIntent(
                    tool="search_resources", resource="events", api_version="v1", kind="Event",
                    namespace=str(namespace), match_field="involvedObject.name",
                    match_value=str(pod), match_operator="exact", limit=20,
                ),
                evidence_ids=evidence_ids,
            ),
        ))
    return tuple(followups)


class ReadOnlyExplorer(Protocol):
    def execute(self, intent: ReadIntent) -> ReadResult: ...
