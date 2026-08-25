from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import BaseModel, Field


class ReadIntent(BaseModel):
    """A model-selected request whose final scope is validated by normal code."""

    tool: Literal["get_resource", "list_resources", "pod_logs"]
    api_version: str | None = Field(default=None, max_length=128)
    kind: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=253)
    name: str | None = Field(default=None, max_length=253)
    label_selector: str | None = Field(default=None, max_length=512)
    container: str | None = Field(default=None, max_length=253)
    previous: bool = False
    limit: int = Field(default=20, ge=1, le=50)


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


def normalize_read_intent(intent: ReadIntent) -> ReadIntent:
    """Canonicalize trusted built-in resource coordinates before broker validation."""

    if intent.tool == "pod_logs" or not intent.kind:
        return intent
    coordinates = _BUILTIN_RESOURCE_TYPES.get(intent.kind.lower())
    if not coordinates:
        return intent
    api_version, kind = coordinates
    return intent.model_copy(update={"api_version": api_version, "kind": kind})


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
