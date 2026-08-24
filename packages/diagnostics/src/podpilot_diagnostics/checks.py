from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import uuid4


CheckStatus = Literal["queued", "running", "succeeded", "failed", "skipped"]


@dataclass(frozen=True)
class DiagnosticCheckSpec:
    id: str
    investigation_id: str
    position: int
    tool_name: Literal["inspect_service_topology", "inspect_target_events"]
    title: str
    purpose: str
    namespace: str
    service_name: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CheckObservation:
    id: str
    title: str
    detail: str
    source: str
    observed_at: datetime


@dataclass(frozen=True)
class DiagnosticCheckResult:
    status: Literal["succeeded", "failed"]
    summary: str
    observations: tuple[CheckObservation, ...]
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class DiagnosticCheckExecutor(Protocol):
    def run(self, spec: DiagnosticCheckSpec) -> DiagnosticCheckResult: ...


def plan_diagnostic_checks(
    *,
    investigation_id: str,
    alert_name: str,
    labels: dict[str, str],
) -> tuple[DiagnosticCheckSpec, ...]:
    """Return a server-owned, bounded check plan for a supported alert.

    Model output and browser input never supply tool names or Kubernetes targets.
    The target comes only from the normalized alert snapshot and this registry.
    """

    if alert_name != "TargetDown":
        return ()
    namespace = labels.get("namespace", "")[:253]
    service_name = (labels.get("service") or labels.get("job") or "")[:253]
    if not namespace or not service_name:
        return ()
    common = {
        "investigation_id": investigation_id,
        "namespace": namespace,
        "service_name": service_name,
    }
    return (
        DiagnosticCheckSpec(
            id=str(uuid4()),
            position=1,
            tool_name="inspect_service_topology",
            title="Resolve the target Service and endpoints",
            purpose=(
                "Compare the Service selector with EndpointSlices and current Pod readiness."
            ),
            **common,
        ),
        DiagnosticCheckSpec(
            id=str(uuid4()),
            position=2,
            tool_name="inspect_target_events",
            title="Inspect bounded events for target Pods",
            purpose=(
                "Look for recent readiness, scheduling, restart, or networking symptoms on Pods selected by the Service."
            ),
            **common,
        ),
    )
