from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from podpilot_diagnostics.adhoc import (
    AdHocObservation,
    ReadIntent,
    ReadPlan,
    automatic_read_followups,
    derive_adhoc_findings,
    normalize_read_intent,
    plan_catalog_read,
    plan_known_read,
    plan_needs_evidence_repair,
    pod_log_candidates_from_evidence,
)


def test_verified_tls_trust_failure_plans_one_matching_insecure_retry() -> None:
    intent = ReadIntent(
        tool="http_probe", url="https://route.apps.example.test/v1/models",
        connect_host="192.0.2.50", method="GET",
    )
    observation = AdHocObservation(
        id="network-trust-1", tool="http_probe", summary="TLS trust failed.",
        source="https://route.apps.example.test/v1/models via 192.0.2.50:443",
        collected_at=datetime.now(timezone.utc),
        data={
            "outcome": "failed", "stage": "tls",
            "error": "certificate verify failed: self-signed certificate in certificate chain",
        },
    )

    followups = automatic_read_followups(intent, (observation,))

    assert len(followups) == 1
    assert followups[0].code == "tls_trust_retry"
    assert followups[0].intent.url == intent.url
    assert followups[0].intent.connect_host == intent.connect_host
    assert followups[0].intent.method == "GET"
    assert followups[0].intent.tls_verify is False
    assert followups[0].evidence_ids == ("network-trust-1",)
    assert automatic_read_followups(followups[0].intent, (observation,)) == ()


def test_certificate_log_signals_work_for_any_container_and_plan_exact_followups() -> None:
    observation = AdHocObservation(
        id="cluster-proxy-log-1", tool="pod_logs", summary="Collected proxy logs.",
        source=(
            "kubernetes:v1:Pod/log:openshift-ingress/"
            "maas-default-gateway-5cc7b765cf-b6qtq?current"
        ),
        collected_at=datetime.now(timezone.utc),
        data={
            "container": "gateway",
            "tail": (
                "failed to generate secret for file-root: open /etc/certs/server.pem: "
                "no such file or directory\nfailed to generate secret for file-root: "
                "open /etc/certs/ca-cert.pem: no such file or directory"
            ),
        },
    )

    findings = derive_adhoc_findings([observation.to_dict()])
    followups = automatic_read_followups(
        ReadIntent(tool="pod_logs", candidate_id="podlog-proxy"), (observation,)
    )

    assert findings[0]["status"] == "open"
    assert findings[0]["namespace"] == "openshift-ingress"
    assert findings[0]["pod"] == "maas-default-gateway-5cc7b765cf-b6qtq"
    assert findings[0]["kind"] == "log_signal"
    assert findings[0]["category"] == "tls_or_certificate"
    assert findings[0]["container"] == "gateway"
    assert findings[0]["occurrences_in_excerpt"] == 2
    assert findings[0]["distinct_signatures"] == 2
    assert findings[0]["paths"] == [
        "/etc/certs/server.pem", "/etc/certs/ca-cert.pem",
    ]
    assert [item.intent.tool for item in followups] == ["get_resource", "search_resources"]
    assert all(item.code == "log_signal_investigation" for item in followups)
    assert followups[0].intent.name == "maas-default-gateway-5cc7b765cf-b6qtq"
    assert followups[1].intent.match_field == "involvedObject.name"
    assert followups[1].intent.match_value == "maas-default-gateway-5cc7b765cf-b6qtq"


def test_log_signal_finding_records_completed_pod_and_event_followups() -> None:
    base = {
        "id": "cluster-proxy-log-1", "tool": "pod_logs",
        "summary": "Collected proxy logs.",
        "source": "kubernetes:v1:Pod/log:mesh/gateway-1?current",
        "collected_at": datetime.now(timezone.utc),
        "data": {
            "container": "istio-proxy",
            "tail": "failed to generate secret: open /etc/certs/server.pem: no such file or directory",
        },
    }
    evidence = [
        base,
        {
            "id": "cluster-pod-1", "tool": "get_resource",
            "source": "kubernetes:v1:Pod:mesh/gateway-1", "data": {"kind": "Pod"},
        },
        {
            "id": "cluster-events-1", "tool": "search_resources",
            "source": "kubernetes:v1:Event:mesh/*",
            "data": {
                "kind": "Event", "scope": "mesh", "matchField": "involvedObject.name",
                "matchValue": "gateway-1",
            },
        },
    ]

    finding = derive_adhoc_findings(evidence)[0]

    assert finding["status"] == "investigated"
    assert finding["completed_checks"] == ["exact_pod_specification", "pod_events"]
    assert finding["evidence_ids"] == [
        "cluster-proxy-log-1", "cluster-pod-1", "cluster-events-1",
    ]


def test_general_application_log_signals_are_classified_scored_and_deduplicated() -> None:
    observation = AdHocObservation(
        id="cluster-api-log-1", tool="pod_logs", summary="Collected API logs.",
        source="kubernetes:v1:Pod/log:payments/api-7d9f?current",
        collected_at=datetime.now(timezone.utc),
        data={
            "container": "api", "previous": False,
            "tail": (
                "2026-08-26T12:41:03Z ERROR request 192 failed: connection refused payments-db:5432\n"
                "2026-08-26T12:41:04Z ERROR request 193 failed: connection refused payments-db:5432\n"
                "2026-08-26T12:41:05Z WARNING retrying dependency request\n"
                "normal health check completed"
            ),
        },
    )

    findings = derive_adhoc_findings([observation.to_dict()])

    network = next(item for item in findings if item["category"] == "network_connectivity")
    warning = next(item for item in findings if item["category"] == "warning")
    assert network["severity"] == "error"
    assert network["occurrences_in_excerpt"] == 2
    assert network["distinct_signatures"] == 1
    assert network["first_observed_timestamp"] == "2026-08-26T12:41:03Z"
    assert network["last_observed_timestamp"] == "2026-08-26T12:41:04Z"
    assert network["endpoints"] == ["payments-db:5432"]
    assert len(network["error_samples"]) == 2
    assert warning["occurrences_in_excerpt"] == 1


def test_unhealthy_pod_evidence_automatically_selects_bounded_exact_logs() -> None:
    observation = AdHocObservation(
        id="cluster-pods-1", tool="list_resources", summary="Read Pods.",
        source="kubernetes:v1:Pod:payments/*", collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Pod", "scope": "payments",
            "logCandidates": [{
                "namespace": "payments", "pod": "api-7d9f", "containers": ["api"],
                "phase": "Running", "ready": False, "restartCount": 3,
            }],
        },
    )

    followups = automatic_read_followups(
        ReadIntent(tool="list_resources", resource="pods", namespace="payments"),
        (observation,),
    )

    assert len(followups) == 1
    assert followups[0].code == "pod_log_investigation"
    assert followups[0].intent.namespace == "payments"
    assert followups[0].intent.name == "api-7d9f"
    assert followups[0].intent.container == "api"
    assert followups[0].intent.candidate_id.startswith("podlog-")
    assert "not Ready" in followups[0].reason
    assert "restart count is 3" in followups[0].reason


def test_log_priority_is_scoped_to_the_affected_container() -> None:
    evidence = [{
        "id": "cluster-pods-2", "tool": "list_resources",
        "data": {
            "kind": "Pod", "scope": "payments",
            "logCandidates": [{
                "namespace": "payments", "pod": "api-7d9f",
                "containers": ["api", "telemetry"], "phase": "Running",
                "ready": False, "restartCount": 5,
                "containerStatuses": [
                    {"name": "api", "ready": False, "restartCount": 5},
                    {"name": "telemetry", "ready": True, "restartCount": 0},
                ],
            }],
        },
    }]

    candidates = pod_log_candidates_from_evidence(evidence)

    assert [(item.container, item.investigation_priority) for item in candidates] == [
        ("api", "high"), ("telemetry", "normal"),
    ]


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


def test_qualified_same_kind_resource_is_not_rewritten_to_builtin_api() -> None:
    knative = ReadIntent(
        tool="list_resources",
        resource="routes.serving.knative.dev",
        api_version="serving.knative.dev/v1",
        kind="Route",
    )

    assert normalize_read_intent(knative) == knative


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
        limit=500,
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
    assert plan.intents[0].limit == 500


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
        tool="list_resources", resource="clusteroperators", limit=500,
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


def test_plan_decision_is_derived_from_typed_intents() -> None:
    empty = ReadPlan(
        goal_type="health",
        decision="collect",
        scope_summary="Assess ClusterOperator health.",
    )
    collecting = ReadPlan(
        goal_type="health",
        decision="answer_from_evidence",
        scope_summary="Assess ClusterOperator health.",
        intents=[ReadIntent(tool="list_resources", resource="clusteroperators")],
    )

    assert empty.decision == "answer_from_evidence"
    assert collecting.decision == "collect"


def test_http_probe_requires_safe_typed_url_shape() -> None:
    probe = ReadIntent(
        tool="http_probe",
        url="https://console.apps.example.test/healthz",
        connect_host="192.0.2.20",
        method="GET",
    )

    assert probe.url == "https://console.apps.example.test/healthz"
    assert probe.connect_host == "192.0.2.20"
    with pytest.raises(ValidationError, match="absolute HTTP or HTTPS URL"):
        ReadIntent(tool="http_probe", url="file:///etc/passwd")
    with pytest.raises(ValidationError, match="must not contain credentials"):
        ReadIntent(tool="http_probe", url="https://user:password@example.test/")


def test_https_probe_may_explicitly_disable_tls_verification() -> None:
    intent = ReadIntent(
        tool="http_probe", url="https://mesh-control.example.test/ready", tls_verify=False,
    )

    assert intent.tls_verify is False
    with pytest.raises(ValidationError, match="only for HTTPS"):
        ReadIntent(tool="http_probe", url="http://mesh-control.example.test/", tls_verify=False)


def test_resource_search_accepts_a_valid_field_path_and_requires_a_value() -> None:
    intent = ReadIntent(
        tool="search_resources", resource="services", match_field="spec.type",
        match_value="NodePort", limit=5,
    )

    assert intent.match_operator == "exact"
    with pytest.raises(ValidationError, match="requires match_field and match_value"):
        ReadIntent(tool="search_resources", resource="routes")
    with pytest.raises(ValidationError, match="dot-separated Kubernetes object field path"):
        ReadIntent(
            tool="search_resources", resource="services", match_field="spec..type",
            match_value="NodePort",
        )


def test_metrics_query_requires_typed_scope_and_registered_metric() -> None:
    intent = ReadIntent(
        tool="query_metrics",
        metric="cpu_usage",
        metric_scope="pod",
        namespace="payments",
        name="api-7d9",
        range_seconds=21_600,
        step_seconds=300,
    )

    assert intent.metric == "cpu_usage"
    with pytest.raises(ValidationError, match="requires metric and metric_scope"):
        ReadIntent(tool="query_metrics")
    with pytest.raises(ValidationError, match="persistent_volume_usage requires"):
        ReadIntent(
            tool="query_metrics", metric="persistent_volume_usage",
            metric_scope="namespace", namespace="payments",
        )
    node = ReadIntent(
        tool="query_metrics", metric="top_cpu_consumers",
        metric_scope="node", name="worker-2",
    )
    assert node.namespace is None
    namespace = ReadIntent(
        tool="query_metrics", metric="top_memory_consumers",
        metric_scope="namespace", namespace="payments",
    )
    assert namespace.name is None
    with pytest.raises(ValidationError, match="requires namespace, deployment, or node scope"):
        ReadIntent(
            tool="query_metrics", metric="top_memory_consumers",
            metric_scope="pod", namespace="payments", name="api-1",
        )


@pytest.mark.parametrize(
    ("question", "metric", "namespace"),
    [
        (
            "What workloads are using the most CPU in openshift-logging?",
            "top_cpu_consumers",
            "openshift-logging",
        ),
        (
            "Show the top memory users within namespace payments",
            "top_memory_consumers",
            "payments",
        ),
    ],
)
def test_namespace_top_consumer_question_compiles_to_typed_metric_query(
    question: str, metric: str, namespace: str,
) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "compare"
    assert plan.intents == [ReadIntent(
        tool="query_metrics",
        metric=metric,
        metric_scope="namespace",
        namespace=namespace,
    )]


def test_route_url_question_compiles_to_exact_host_search() -> None:
    planned = plan_known_read(
        'Is this route HTTP or HTTPS? "https://maas.apps.example.test/v1/models"'
    )

    assert planned is not None
    plan, terminal = planned
    assert terminal is False
    assert plan.intents == [ReadIntent(
        tool="search_resources",
        resource="routes.route.openshift.io",
        api_version="route.openshift.io/v1",
        kind="Route",
        match_field="spec.host",
        match_value="maas.apps.example.test",
        match_operator="exact",
        limit=5,
    )]


def test_log_candidate_id_is_rejected_for_non_log_tools() -> None:
    with pytest.raises(ValidationError, match="candidate_id is valid only for pod_logs"):
        ReadIntent(
            tool="get_resource",
            candidate_id="podlog-1234567890",
            resource="pods",
            namespace="payments",
            name="api",
        )


@pytest.mark.parametrize(
    "placeholder",
    [
        "<FIRST_CRASHING_POD_NAME_FROM_PREVIOUS_LIST>",
        "{pod-name-from-list}",
        "first-pod-name-from-list",
    ],
)
def test_deferred_model_targets_are_rejected_by_contract(placeholder: str) -> None:
    with pytest.raises(ValidationError, match="exact target, not a deferred placeholder"):
        ReadIntent(
            tool="get_resource", resource="pods", namespace="payments", name=placeholder,
        )


def test_exact_kubernetes_names_are_not_mistaken_for_placeholders() -> None:
    intent = ReadIntent(
        tool="get_resource", resource="deployments", namespace="telemetry",
        name="opentelemetry-collector-operated",
    )
    assert intent.name == "opentelemetry-collector-operated"


def test_exact_log_candidates_can_be_derived_from_named_pod_evidence() -> None:
    candidates = pod_log_candidates_from_evidence([{
        "id": "cluster-pod-1",
        "tool": "get_resource",
        "data": {
            "api_version": "v1",
            "kind": "Pod",
            "metadata": {"namespace": "payments", "name": "api-7d9"},
            "spec": {"containers": [{"name": "api"}]},
            "status": {
                "phase": "Running",
                "container_statuses": [{"name": "api", "restart_count": 2}],
            },
        },
    }])

    assert len(candidates) == 1
    assert candidates[0].namespace == "payments"
    assert candidates[0].pod == "api-7d9"
    assert candidates[0].container == "api"
    assert candidates[0].restart_count == 2


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
