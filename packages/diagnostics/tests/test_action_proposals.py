from dataclasses import replace
from datetime import datetime, timezone

from podpilot_diagnostics.remediation import propose_actions
from podpilot_diagnostics.workloads import ContainerEvidence, OwnerEvidence, WorkloadEvidence


def workload() -> WorkloadEvidence:
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)
    return WorkloadEvidence(
        namespace="demo",
        pod_name="api-abc",
        pod_uid="pod-uid",
        phase="Running",
        node_name="worker",
        requests={},
        conditions=("Ready=False",),
        containers=(ContainerEvidence("api", "example/api:v1", False, 9, "waiting", "CrashLoopBackOff", None, "Error", 1),),
        events=(),
        owners=(
            OwnerEvidence("apps/v1", "ReplicaSet", "api-abc", 1, 0, 1, "rs-uid", "rs-rv"),
            OwnerEvidence("apps/v1", "Deployment", "api", 1, 0, 1, "deploy-uid", "deploy-rv"),
        ),
        nodes=(),
        current_logs={},
        previous_logs={},
        collected_at=now,
        failures=(),
        pod_resource_version="pod-rv",
    )


def test_crashloop_proposes_only_two_registered_actions() -> None:
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)
    actions = propose_actions(
        investigation_id="investigation-id",
        alert_name="KubePodCrashLooping",
        cluster="test",
        workload=workload(),
        now=now,
    )
    assert [item.action_type for item in actions] == [
        "delete_controller_owned_pod",
        "restart_workload_rollout",
    ]
    assert actions[0].target_uid == "pod-uid"
    assert actions[0].direct_owner_uid == "rs-uid"
    assert actions[1].target_kind == "Deployment"
    assert actions[1].target_resource_version == "deploy-rv"
    assert (actions[0].expires_at - now).total_seconds() == 600


def test_non_crashloop_or_missing_preconditions_proposes_nothing() -> None:
    assert propose_actions(
        investigation_id="id", alert_name="KubeContainerWaiting", cluster="test", workload=workload()
    ) == ()
    missing = replace(workload(), pod_resource_version="")
    assert propose_actions(
        investigation_id="id", alert_name="KubePodCrashLooping", cluster="test", workload=missing
    ) == ()
    protected = replace(workload(), namespace="openshift-monitoring")
    assert propose_actions(
        investigation_id="id", alert_name="KubePodCrashLooping", cluster="test", workload=protected
    ) == ()
