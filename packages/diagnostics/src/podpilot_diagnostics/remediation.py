from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol
from uuid import uuid4

from podpilot_diagnostics.workloads import WorkloadEvidence

ActionType = Literal["delete_controller_owned_pod", "restart_workload_rollout"]
PROTECTED_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease", "openshift", "ai-ops"}


@dataclass(frozen=True)
class ActionProposal:
    id: str
    investigation_id: str
    action_type: ActionType
    cluster: str
    namespace: str
    target_api_version: str
    target_kind: str
    target_name: str
    target_uid: str
    target_resource_version: str
    direct_owner_uid: str | None
    direct_owner_kind: str | None
    direct_owner_name: str | None
    risk: Literal["low", "moderate"]
    reason: str
    uncertainty: str
    expected_impact: str
    operation: str
    verification: str
    recovery: str
    rollout_annotation: str | None
    verification_timeout_seconds: int
    created_at: datetime
    expires_at: datetime

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ActionResult:
    outcome: Literal["resolved", "unresolved", "failed", "stale"]
    summary: str
    before: dict[str, object]
    api_result: dict[str, object]
    verification: dict[str, object]
    after: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ActionValidation:
    status: Literal["current", "stale", "missing", "unavailable"]
    detail: str


class RemediationExecutor(Protocol):
    def preview(self, proposal: ActionProposal) -> dict[str, object]: ...
    def validate(self, proposal: ActionProposal) -> ActionValidation: ...
    def execute(self, proposal: ActionProposal) -> ActionResult: ...


def propose_actions(
    *,
    investigation_id: str,
    alert_name: str,
    cluster: str,
    workload: WorkloadEvidence,
    now: datetime | None = None,
) -> tuple[ActionProposal, ...]:
    """Return only allowlisted actions derived from trusted normalized fields."""
    created_at = now or datetime.now(timezone.utc)
    expires_at = created_at + timedelta(minutes=10)
    protected_namespace = (
        workload.namespace in PROTECTED_NAMESPACES
        or workload.namespace.startswith("openshift-")
        or workload.namespace.startswith("kube-")
    )
    if alert_name != "KubePodCrashLooping" or not workload.owners or protected_namespace:
        return ()
    crashlooping = any(
        item.reason == "CrashLoopBackOff"
        or item.last_reason in {"Error", "OOMKilled"}
        or (item.last_exit_code is not None and item.last_exit_code != 0)
        for item in workload.containers
    )
    direct_owner = workload.owners[0]
    if (
        not crashlooping
        or not workload.pod_uid
        or not workload.pod_resource_version
        or not direct_owner.uid
    ):
        return ()

    proposals: list[ActionProposal] = [
        ActionProposal(
            id=str(uuid4()),
            investigation_id=investigation_id,
            action_type="delete_controller_owned_pod",
            cluster=cluster,
            namespace=workload.namespace,
            target_api_version="v1",
            target_kind="Pod",
            target_name=workload.pod_name,
            target_uid=workload.pod_uid,
            target_resource_version=workload.pod_resource_version,
            direct_owner_uid=direct_owner.uid,
            direct_owner_kind=direct_owner.kind,
            direct_owner_name=direct_owner.name,
            risk="low",
            reason="The selected Pod is crash-looping and has a controller that can recreate it.",
            uncertainty="Replacement will not help if the controller configuration or image remains faulty.",
            expected_impact="One failed Pod is deleted; its controller should create one replacement.",
            operation=f"DELETE v1/namespaces/{workload.namespace}/pods/{workload.pod_name}",
            verification="Confirm the old UID disappears and a Ready Pod owned by the same direct controller appears.",
            recovery="The controller recreates the Pod. If it does not, inspect the controller before any further action.",
            rollout_annotation=None,
            verification_timeout_seconds=45,
            created_at=created_at,
            expires_at=expires_at,
        )
    ]

    controller = next(
        (
            owner
            for owner in reversed(workload.owners)
            if owner.kind in {"Deployment", "StatefulSet", "DaemonSet"}
            and owner.uid
            and owner.resource_version
        ),
        None,
    )
    if controller:
        annotation = created_at.isoformat()
        proposals.append(
            ActionProposal(
                id=str(uuid4()),
                investigation_id=investigation_id,
                action_type="restart_workload_rollout",
                cluster=cluster,
                namespace=workload.namespace,
                target_api_version=controller.api_version,
                target_kind=controller.kind,
                target_name=controller.name,
                target_uid=controller.uid,
                target_resource_version=controller.resource_version,
                direct_owner_uid=None,
                direct_owner_kind=None,
                direct_owner_name=None,
                risk="moderate",
                reason="The crash loop may reflect stale runtime configuration across the workload.",
                uncertainty="A restart cannot repair invalid configuration, missing dependencies, or a broken image.",
                expected_impact="All Pods in the workload roll according to its update strategy and availability policy.",
                operation=(
                    f"PATCH {controller.api_version} {controller.kind}/{workload.namespace}/{controller.name} "
                    f"spec.template.metadata.annotations[podpilot.io/restartedAt]={annotation}"
                ),
                verification="Confirm the new template annotation is observed and desired replicas become updated and Ready.",
                recovery="No configuration is changed beyond the restart annotation; investigate or roll back the owning release if new Pods fail.",
                rollout_annotation=annotation,
                verification_timeout_seconds=90,
                created_at=created_at,
                expires_at=expires_at,
            )
        )
    return tuple(proposals)
