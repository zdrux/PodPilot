from podpilot_diagnostics.adhoc import (
    ReadIntent,
    normalize_read_intent,
    plan_catalog_read,
    plan_known_read,
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
        limit=50,
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
    assert plan.intents[0].limit == 50


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
        tool="list_resources", resource="clusteroperators", limit=100,
    )]
    assert terminal is True


def test_live_catalog_requires_namespace_for_namespaced_inventory() -> None:
    catalog = [{
        "resource": "widgets.example.io",
        "apiVersion": "example.io/v1",
        "kind": "Widget",
        "namespaced": True,
    }]

    assert plan_catalog_read("Show widgets", catalog) is None
    planned = plan_catalog_read("Show widgets in namespace payments", catalog)
    assert planned is not None
    assert planned[0].intents[0].namespace == "payments"
