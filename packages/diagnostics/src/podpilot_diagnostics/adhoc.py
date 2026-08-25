from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, Field


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
    previous: bool = False
    limit: int = Field(default=20, ge=1, le=100)


class ReadPlan(BaseModel):
    scope_summary: str = Field(min_length=1, max_length=500)
    intents: list[ReadIntent] = Field(default_factory=list, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=5)


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
                    limit=50,
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
            limit=50,
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
) -> tuple[ReadPlan, bool] | None:
    """Compile an explicit inventory question against the live safe resource catalog."""

    if not re.search(r"\b(?:show|list|display|what|which)\b", question, re.IGNORECASE):
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
            scope_summary=f"List {kind} resources in {namespace or 'the cluster'}.",
            intents=[ReadIntent(
                tool="list_resources",
                resource=resource,
                namespace=namespace,
                limit=100,
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
