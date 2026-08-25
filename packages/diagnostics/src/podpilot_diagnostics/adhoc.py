from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
from typing import Literal, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator


_DEFERRED_TARGET = re.compile(
    r"(?i)(?:"
    r"[<>{}\[\]]|"
    r"\b(?:first|next|previous|selected|replace|insert)[-_ ]+"
    r"(?:pod|resource|object|deployment|container|namespace|name)\b|"
    r"\b(?:pod|resource|object|deployment|container|namespace)[-_ ]+name[-_ ]+"
    r"(?:from|in)[-_ ]+(?:previous[-_ ])?list\b"
    r")"
)


def looks_like_deferred_target(value: str | None) -> bool:
    """Identify model placeholders that are not observed Kubernetes coordinates."""
    return bool(value and _DEFERRED_TARGET.search(value))


class ReadIntent(BaseModel):
    """A model-selected request whose final scope is validated by normal code."""

    tool: Literal["get_resource", "list_resources", "pod_logs"]
    resource: str | None = Field(default=None, max_length=253)
    api_version: str | None = Field(default=None, max_length=128)
    kind: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=253)
    label_selector: str | None = Field(default=None, max_length=512)
    container: str | None = Field(default=None, max_length=253)
    candidate_id: str | None = Field(default=None, max_length=80)
    previous: bool = False
    limit: int = Field(default=20, ge=1, le=500)

    @field_validator(
        "resource", "api_version", "kind", "namespace", "name", "container", "candidate_id"
    )
    @classmethod
    def require_exact_target(cls, value: str | None) -> str | None:
        if looks_like_deferred_target(value):
            raise ValueError("must be an exact target, not a deferred placeholder")
        return value

    @model_validator(mode="after")
    def validate_candidate_usage(self) -> "ReadIntent":
        if self.candidate_id and self.tool != "pod_logs":
            raise ValueError("candidate_id is valid only for pod_logs")
        return self


class ReadPlan(BaseModel):
    goal_type: Literal[
        "inventory", "health", "diagnose", "logs", "compare", "explain"
    ] = "diagnose"
    decision: Literal[
        "collect", "answer_from_evidence", "needs_clarification"
    ] | None = None
    scope_summary: str = Field(min_length=1, max_length=500)
    intents: list[ReadIntent] = Field(default_factory=list, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=5)
    clarification: str | None = Field(default=None, max_length=500)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode="after")
    def normalize_decision(self) -> "ReadPlan":
        if self.decision is None:
            self.decision = "collect" if self.intents else "answer_from_evidence"
        if self.decision == "collect" and not self.intents:
            raise ValueError("collect decisions require at least one read intent")
        if self.decision != "collect" and self.intents:
            raise ValueError("read intents require a collect decision")
        return self


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
        candidates.append(PodLogCandidate(
            id=_candidate_id(evidence_id, namespace_text, pod_text, container_text),
            evidence_id=evidence_id,
            namespace=namespace_text,
            pod=pod_text,
            container=container_text,
            phase=str(phase)[:64] if phase else None,
            ready=ready if isinstance(ready, bool) else None,
            restart_count=restarts,
        ))

    for observation in evidence:
        if observation.get("tool") not in {"list_resources", "get_resource"}:
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
                for container in containers or [None]:
                    add(
                        evidence_id=evidence_id,
                        namespace=item.get("namespace") or data.get("scope"),
                        pod=item.get("pod") or item.get("name"),
                        container=container,
                        phase=item.get("phase"),
                        ready=item.get("ready"),
                        restart_count=item.get("restartCount"),
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


def plan_needs_evidence_repair(
    plan: ReadPlan,
    *,
    known_evidence_ids: set[str],
    has_completed_reads: bool,
) -> bool:
    """Reject an unsupported no-read answer for a model-classified operational goal."""

    actionable = {"inventory", "health", "diagnose", "logs", "compare"}
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

    if intent.tool == "pod_logs" or not intent.kind:
        return intent
    coordinates = _BUILTIN_RESOURCE_TYPES.get(intent.kind.lower())
    if not coordinates:
        return intent
    api_version, kind = coordinates
    return intent.model_copy(update={
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


def plan_known_read(
    question: str,
    *,
    inventory_limit: int = 250,
    alert_name: str | None = None,
    alert_labels: dict[str, object] | None = None,
) -> tuple[ReadPlan, bool] | None:
    """Compile unambiguous inventory and alert-scoped reads without model syntax."""

    lowered = question.lower()
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
        return (
            ReadPlan(
                scope_summary=f"List {intent.kind} resources in {intent.namespace}.",
                intents=[intent],
            ),
            True,
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
    inventory_limit: int = 250,
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
    matches: list[tuple[int, dict[str, object]]] = []
    for entry in resource_catalog:
        resource = str(entry.get("resource") or "")
        kind = str(entry.get("kind") or "")
        if not resource or not kind:
            continue
        unqualified = resource.split(".", 1)[0]
        kind_words = re.sub(r"(?<!^)(?=[A-Z])", " ", kind).lower()
        aliases = {unqualified.lower(), kind.lower(), kind_words}
        for alias in aliases:
            if re.search(rf"\b{re.escape(alias)}s?\b", lowered):
                matches.append((len(alias), entry))
                break
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    entry = matches[0][1]
    namespaced = bool(entry.get("namespaced"))
    if not namespaced and namespace:
        return None
    resource = str(entry["resource"])
    kind = str(entry["kind"])
    return (
        ReadPlan(
            goal_type="health" if health_request else "inventory",
            scope_summary=f"List {kind} resources in {namespace or 'the cluster'}.",
            intents=[ReadIntent(
                tool="list_resources",
                resource=resource,
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


class ReadOnlyExplorer(Protocol):
    def execute(self, intent: ReadIntent) -> ReadResult: ...
