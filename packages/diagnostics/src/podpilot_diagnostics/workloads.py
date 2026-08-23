from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass(frozen=True)
class ContainerEvidence:
    name: str
    image: str
    ready: bool
    restart_count: int
    state: str
    reason: str | None
    message: str | None
    last_reason: str | None
    last_exit_code: int | None


@dataclass(frozen=True)
class EventEvidence:
    id: str
    reason: str
    message: str
    event_type: str
    observed_at: datetime | None
    source: str


@dataclass(frozen=True)
class OwnerEvidence:
    api_version: str
    kind: str
    name: str
    desired_replicas: int | None
    ready_replicas: int | None
    updated_replicas: int | None
    uid: str = ""
    resource_version: str = ""


@dataclass(frozen=True)
class NodeEvidence:
    name: str
    allocatable: dict[str, str]
    taints: tuple[str, ...]
    unschedulable: bool


@dataclass(frozen=True)
class WorkloadEvidence:
    namespace: str
    pod_name: str
    pod_uid: str
    phase: str
    node_name: str | None
    requests: dict[str, str]
    conditions: tuple[str, ...]
    containers: tuple[ContainerEvidence, ...]
    events: tuple[EventEvidence, ...]
    owners: tuple[OwnerEvidence, ...]
    nodes: tuple[NodeEvidence, ...]
    current_logs: dict[str, str]
    previous_logs: dict[str, str]
    collected_at: datetime
    failures: tuple[str, ...]
    pod_resource_version: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
