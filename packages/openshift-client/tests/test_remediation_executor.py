from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from podpilot_diagnostics.remediation import ActionProposal
from podpilot_openshift.remediation import KubernetesRemediationExecutor


def ns(**values):
    return SimpleNamespace(**values)


def proposal(action_type="delete_controller_owned_pod") -> ActionProposal:
    now = datetime.now(timezone.utc)
    rollout = action_type == "restart_workload_rollout"
    return ActionProposal(
        id="action-id",
        investigation_id="investigation-id",
        action_type=action_type,
        cluster="test",
        namespace="demo",
        target_api_version="apps/v1" if rollout else "v1",
        target_kind="Deployment" if rollout else "Pod",
        target_name="api" if rollout else "api-old",
        target_uid="deploy-uid" if rollout else "old-uid",
        target_resource_version="deploy-rv" if rollout else "old-rv",
        direct_owner_uid=None if rollout else "rs-uid",
        direct_owner_kind=None if rollout else "ReplicaSet",
        direct_owner_name=None if rollout else "api-rs",
        risk="moderate" if rollout else "low",
        reason="reason",
        uncertainty="uncertainty",
        expected_impact="impact",
        operation="operation",
        verification="verification",
        recovery="recovery",
        rollout_annotation=now.isoformat() if rollout else None,
        verification_timeout_seconds=1,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


class FakeCore:
    def __init__(self, stale=False):
        self.old = ns(metadata=ns(name="api-old", uid="old-uid", resource_version="changed" if stale else "old-rv", owner_references=[ns(controller=True, uid="rs-uid")]), status=ns(conditions=[]))
        self.replacement = ns(
            metadata=ns(
                name="api-new",
                uid="new-uid",
                resource_version="new-rv",
                owner_references=[ns(controller=True, uid="rs-uid")],
            ),
            status=ns(conditions=[ns(type="Ready", status="True")]),
        )
        self.deletes = []
        self.deleted = False

    def read_namespaced_pod(self, name, namespace):
        return self.old

    def delete_namespaced_pod(self, name, namespace, **kwargs):
        self.deletes.append(kwargs)
        if "dry_run" not in kwargs:
            self.deleted = True
        return ns(status="Success")

    def list_namespaced_pod(self, namespace, limit):
        return ns(items=[self.replacement] if self.deleted else [self.old])


class FakeResource:
    def __init__(self, annotation):
        self.annotation = annotation
        self.patches = []

    def get(self, name, namespace):
        return ns(
            metadata=ns(
                name="api",
                uid="deploy-uid",
                resourceVersion="deploy-rv",
                generation=2,
            ),
            spec=ns(
                replicas=1,
                template=ns(
                    metadata=ns(
                        annotations={"podpilot.io/restartedAt": self.annotation}
                    )
                ),
            ),
            status=ns(updatedReplicas=1, readyReplicas=1, observedGeneration=2),
        )

    def patch(self, **kwargs):
        self.patches.append(kwargs)
        return self.get(kwargs["name"], kwargs["namespace"])


class FakeDynamic:
    def __init__(self, resource):
        self.resources = ns(get=lambda **kwargs: resource)


def test_pod_delete_dry_run_preconditions_and_replacement_verification() -> None:
    core = FakeCore()
    executor = KubernetesRemediationExecutor(core_api=core, dynamic_client=FakeDynamic(None), sleep=lambda _: None)
    plan = proposal()
    preview = executor.preview(plan)
    assert preview["server_dry_run"] == "passed"
    assert core.deletes[0]["dry_run"] == "All"
    assert core.deletes[0]["body"].dry_run == ["All"]
    assert core.deletes[0]["body"].preconditions.uid == "old-uid"
    result = executor.execute(plan)
    assert result.outcome == "resolved"
    assert result.after["uid"] == "new-uid"
    assert len(core.deletes) == 2


def test_changed_resource_version_fails_closed_without_delete() -> None:
    core = FakeCore(stale=True)
    executor = KubernetesRemediationExecutor(core_api=core, dynamic_client=FakeDynamic(None))
    result = executor.execute(proposal())
    assert result.outcome == "stale"
    assert "resourceVersion changed" in result.summary
    assert core.deletes == []


def test_protected_namespace_fails_closed_before_kubernetes_call() -> None:
    core = FakeCore()
    executor = KubernetesRemediationExecutor(core_api=core, dynamic_client=FakeDynamic(None))
    result = executor.execute(replace(proposal(), namespace="openshift-monitoring"))
    assert result.outcome == "stale"
    assert "protected system namespaces" in result.summary
    assert core.deletes == []


def test_rollout_patch_is_fixed_and_verified() -> None:
    plan = proposal("restart_workload_rollout")
    resource = FakeResource(plan.rollout_annotation)
    executor = KubernetesRemediationExecutor(core_api=FakeCore(), dynamic_client=FakeDynamic(resource), sleep=lambda _: None)
    preview = executor.preview(plan)
    assert preview["server_dry_run"] == "passed"
    assert resource.patches[0]["dry_run"] == "All"
    patch = resource.patches[0]["body"]
    assert patch["metadata"]["uid"] == "deploy-uid"
    assert patch["metadata"]["resourceVersion"] == "deploy-rv"
    assert patch["spec"]["template"]["metadata"]["annotations"]["podpilot.io/restartedAt"] == plan.rollout_annotation
    result = executor.execute(plan)
    assert result.outcome == "resolved"
    assert result.verification["rollout_ready"] is True
