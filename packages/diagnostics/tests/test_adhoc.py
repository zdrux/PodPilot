import pytest
from pydantic import ValidationError

from podpilot_diagnostics.adhoc import (
    ReadIntent,
    ReadPlan,
    normalize_read_intent,
    plan_catalog_read,
    plan_known_read,
    plan_needs_evidence_repair,
    pod_log_candidates_from_evidence,
)


def test_known_resource_coordinates_are_canonicalized() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        api_version="core/v1/invalid",
        kind="pods",
        namespace="ai-ops",
        limit=3,
    )

    normalized = normalize_read_intent(proposed)

    assert normalized.api_version == "v1"
    assert normalized.kind == "Pod"
    assert normalized.resource == "pods"
    assert normalized.namespace == "ai-ops"
    assert normalized.limit == 3


def test_custom_resource_coordinates_remain_model_proposed_for_broker_validation() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        api_version="example.io/v1",
        kind="Widget",
    )

    assert normalize_read_intent(proposed) == proposed


def test_pod_log_coordinates_are_not_rewritten() -> None:
    proposed = ReadIntent(
        tool="pod_logs", kind="pods", namespace="ai-ops", name="podpilot-1"
    )

    assert normalize_read_intent(proposed) == proposed


def test_pod_log_candidates_are_exact_stable_targets_from_list_evidence() -> None:
    evidence = [{
        "id": "cluster-pods-1",
        "tool": "list_resources",
        "data": {
            "scope": "openshift-kube-apiserver",
            "logCandidates": [{
                "namespace": "openshift-kube-apiserver",
                "pod": "kube-apiserver-master-0",
                "containers": ["kube-apiserver", "kube-apiserver-cert-syncer"],
                "phase": "Running",
                "ready": True,
                "restartCount": 2,
            }],
        },
    }]

    first = pod_log_candidates_from_evidence(evidence)
    second = pod_log_candidates_from_evidence(evidence)

    assert [item.id for item in first] == [item.id for item in second]
    assert [(item.namespace, item.pod, item.container) for item in first] == [
        ("openshift-kube-apiserver", "kube-apiserver-master-0", "kube-apiserver"),
        ("openshift-kube-apiserver", "kube-apiserver-master-0", "kube-apiserver-cert-syncer"),
    ]
    assert first[0].restart_count == 2


def test_storageclass_inventory_is_deterministic_and_terminal() -> None:
    planned = plan_known_read("What StorageClasses are available on the cluster?")

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.intents[0] == ReadIntent(
        tool="list_resources",
        resource="storageclasses",
        api_version="storage.k8s.io/v1",
        kind="StorageClass",
        limit=250,
    )


def test_namespace_pod_inventory_is_deterministic_and_terminal() -> None:
    planned = plan_known_read("Show pods in the namespace ai-ops")

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.intents[0].api_version == "v1"
    assert plan.intents[0].kind == "Pod"
    assert plan.intents[0].resource == "pods"
    assert plan.intents[0].namespace == "ai-ops"
    assert plan.intents[0].limit == 250


def test_failed_job_alert_seeds_exact_job_read_then_allows_followup() -> None:
    planned = plan_known_read(
        "Can you inspect the Job object and find clues?",
        alert_name="KubeJobFailed",
        alert_labels={"namespace": "operators", "job_name": "status-check-abc"},
    )

    assert planned is not None
    plan, terminal = planned
    assert terminal is False
    assert plan.intents[0] == ReadIntent(
        tool="get_resource",
        resource="jobs",
        api_version="batch/v1",
        kind="Job",
        namespace="operators",
        name="status-check-abc",
    )


def test_live_catalog_compiles_common_cluster_scoped_inventory_without_model() -> None:
    planned = plan_catalog_read("Which ClusterOperators are available?", [{
        "resource": "clusteroperators",
        "apiVersion": "config.openshift.io/v1",
        "kind": "ClusterOperator",
        "namespaced": False,
    }])

    assert planned is not None
    plan, terminal = planned
    assert plan.intents == [ReadIntent(
        tool="list_resources", resource="clusteroperators", limit=250,
    )]
    assert terminal is True


def test_live_catalog_allows_cluster_wide_list_for_namespaced_inventory() -> None:
    catalog = [{
        "resource": "widgets.example.io",
        "apiVersion": "example.io/v1",
        "kind": "Widget",
        "namespaced": True,
    }]

    cluster_wide = plan_catalog_read("Show widgets", catalog)
    assert cluster_wide is not None
    assert cluster_wide[0].intents[0].namespace is None
    planned = plan_catalog_read("Show widgets in namespace payments", catalog)
    assert planned is not None
    assert planned[0].intents[0].namespace == "payments"


def test_inventory_limit_can_be_increased_within_broker_ceiling() -> None:
    planned = plan_known_read(
        "List Pods in namespace openshift-logging",
        inventory_limit=500,
    )

    assert planned is not None
    assert planned[0].intents[0].limit == 500


def test_actionable_model_goal_requires_reads_or_valid_supporting_evidence() -> None:
    empty_health_plan = ReadPlan(
        goal_type="health",
        decision="answer_from_evidence",
        scope_summary="Assess ClusterOperator health.",
        supporting_evidence_ids=[],
    )

    assert plan_needs_evidence_repair(
        empty_health_plan,
        known_evidence_ids=set(),
        has_completed_reads=False,
    ) is True
    supported = empty_health_plan.model_copy(update={
        "supporting_evidence_ids": ["cluster-operators-1"],
    })
    assert plan_needs_evidence_repair(
        supported,
        known_evidence_ids={"cluster-operators-1"},
        has_completed_reads=False,
    ) is False


def test_collect_decision_requires_a_typed_read_intent() -> None:
    try:
        ReadPlan(
            goal_type="health",
            decision="collect",
            scope_summary="Assess ClusterOperator health.",
        )
    except ValidationError as exc:
        assert "collect decisions require at least one read intent" in str(exc)
    else:
        raise AssertionError("An empty collect decision must fail schema validation")


def test_log_candidate_id_is_rejected_for_non_log_tools() -> None:
    with pytest.raises(ValidationError, match="candidate_id is valid only for pod_logs"):
        ReadIntent(
            tool="get_resource",
            candidate_id="podlog-1234567890",
            resource="pods",
            namespace="payments",
            name="api",
        )


def test_live_catalog_health_fallback_uses_discovered_cluster_operator() -> None:
    planned = plan_catalog_read("Check the status of the cluster operators", [{
        "resource": "clusteroperators",
        "apiVersion": "config.openshift.io/v1",
        "kind": "ClusterOperator",
        "namespaced": False,
    }])

    assert planned is not None
    plan, terminal = planned
    assert plan.goal_type == "health"
    assert plan.decision == "collect"
    assert plan.intents[0].resource == "clusteroperators"
    assert terminal is True
