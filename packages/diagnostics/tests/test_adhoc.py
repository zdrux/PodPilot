from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from podpilot_diagnostics.adhoc import (
    AdHocObservation,
    ReadIntent,
    ReadPlan,
    automatic_read_followups,
    derive_adhoc_findings,
    derive_evidence_relationship_graph,
    normalize_read_intent,
    plan_catalog_read,
    plan_kafka_topic_storage_metrics,
    plan_known_read,
    plan_needs_evidence_repair,
    pod_log_candidates_from_evidence,
)


def test_relationship_graph_exposes_typed_route_service_endpoint_pod_frontier() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "route-1",
        "tool": "search_resources",
        "data": {
            "kind": "Route",
            "items": [{
                "apiVersion": "route.openshift.io/v1",
                "kind": "Route",
                "metadata": {"namespace": "maas", "name": "gateway"},
                "spec": {"to": {"kind": "Service", "name": "gateway-service"}},
            }],
        },
    }, {
        "id": "service-1",
        "tool": "get_resource",
        "data": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"namespace": "maas", "name": "gateway-service"},
            "spec": {"selector": {"app": "gateway"}},
        },
    }])

    relations = {(edge["relation"], edge["target"]) for edge in graph["edges"]}
    assert ("routes_to", "Service:maas/gateway-service") in relations
    assert any(relation == "selects" for relation, _target in relations)
    assert any(relation == "has_endpoints" for relation, _target in relations)
    route_edge = next(edge for edge in graph["edges"] if edge["relation"] == "routes_to")
    assert route_edge["target_observed"] is True
    frontier_relations = {edge["relation"] for edge in graph["frontier"]}
    assert frontier_relations == {"selects", "has_endpoints"}


def test_relationship_graph_exposes_configmap_reference_but_not_secret_read() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "deployment-1",
        "tool": "get_resource",
        "data": {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"namespace": "kuadrant-system", "name": "authorino"},
            "podpilotConfigReferences": [
                {"sourceType": "ConfigMap", "sourceName": "authorino-config"},
                {"sourceType": "Secret", "sourceName": "authorino-credentials"},
            ],
        },
    }])

    edges = {edge["target"]: edge for edge in graph["edges"]}
    assert edges["ConfigMap:kuadrant-system/authorino-config"]["read_hint"] == {
        "tool": "get_resource", "resource": "configmaps", "api_version": "v1",
        "kind": "ConfigMap", "namespace": "kuadrant-system", "name": "authorino-config",
    }
    assert edges["Secret:kuadrant-system/authorino-credentials"]["read_hint"] is None
    assert {edge["target"] for edge in graph["frontier"]} == {
        "ConfigMap:kuadrant-system/authorino-config",
    }


def test_relationship_graph_follows_nested_custom_resource_configmap_reference() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "kafka-1",
        "tool": "get_resource",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2",
            "kind": "Kafka",
            "metadata": {
                "namespace": "kafka-observability",
                "name": "kafka-observability-cluster",
            },
            "spec": {
                "kafka": {
                    "metricsConfig": {
                        "type": "jmxPrometheusExporter",
                        "valueFrom": {
                            "configMapKeyRef": {
                                "name": "kafka-observability-metrics-config",
                                "key": "metrics-config.yml",
                            },
                        },
                    },
                },
            },
        },
    }])

    edge = next(
        item for item in graph["frontier"]
        if item["target"] == (
            "ConfigMap:kafka-observability/kafka-observability-metrics-config"
        )
    )
    assert edge["relation"] == "configures_from"
    assert edge["read_hint"] == {
        "tool": "get_resource", "resource": "configmaps", "api_version": "v1",
        "kind": "ConfigMap", "namespace": "kafka-observability",
        "name": "kafka-observability-metrics-config",
    }


def test_relationship_graph_derives_machine_node_reference() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "machine-1", "tool": "get_resource",
        "data": {
            "apiVersion": "machine.openshift.io/v1beta1", "kind": "Machine",
            "resource": "machines.machine.openshift.io",
            "metadata": {"namespace": "openshift-machine-api", "name": "worker-0"},
            "status": {"nodeRef": {"apiVersion": "v1", "kind": "Node", "name": "worker-0-node"}},
        },
    }])

    edge = next(item for item in graph["frontier"] if item["relation"] == "represents")
    assert edge["target"] == "Node:cluster/worker-0-node"
    assert edge["read_hint"] == {
        "tool": "get_resource", "resource": "nodes", "api_version": "v1",
        "kind": "Node", "namespace": None, "name": "worker-0-node",
    }


def test_relationship_graph_derives_machineconfigpool_selector_collections() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "mcp-worker", "tool": "get_resource",
        "data": {
            "apiVersion": "machineconfiguration.openshift.io/v1",
            "kind": "MachineConfigPool",
            "resource": "machineconfigpools.machineconfiguration.openshift.io",
            "metadata": {"name": "worker"},
            "spec": {
                "nodeSelector": {"matchLabels": {"node-role.kubernetes.io/worker": ""}},
                "machineConfigSelector": {"matchExpressions": [{
                    "key": "machineconfiguration.openshift.io/role",
                    "operator": "In", "values": ["worker", "infra"],
                }]},
            },
        },
    }])

    by_relation = {item["relation"]: item for item in graph["frontier"]}
    assert by_relation["selects"]["read_hint"] == {
        "tool": "list_resources", "resource": "nodes", "api_version": "v1",
        "kind": "Node", "namespace": None,
        "label_selector": "node-role.kubernetes.io/worker=", "limit": 20,
    }
    assert by_relation["selects_configuration"]["read_hint"] == {
        "tool": "list_resources",
        "resource": "machineconfigs.machineconfiguration.openshift.io",
        "api_version": "machineconfiguration.openshift.io/v1",
        "kind": "MachineConfig", "namespace": None,
        "label_selector": "machineconfiguration.openshift.io/role in (worker,infra)",
        "limit": 20,
    }


def test_relationship_graph_exposes_reverse_source_when_target_is_observed() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "kafka-1", "tool": "get_resource",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "resource": "kafkas.kafka.strimzi.io",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            "spec": {"metricsConfig": {"configMapKeyRef": {"name": "kafka-metrics"}}},
        },
    }, {
        "id": "config-1", "tool": "get_resource",
        "data": {
            "apiVersion": "v1", "kind": "ConfigMap", "resource": "configmaps",
            "metadata": {"namespace": "vc-streams", "name": "kafka-metrics"},
            "data": {"metrics.yml": "rules: []"},
        },
    }])

    edge = next(item for item in graph["reverse_frontier"] if item["relation"] == "configures_from")
    assert edge["source_read_hint"] == {
        "tool": "get_resource", "resource": "kafkas.kafka.strimzi.io",
        "api_version": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
        "namespace": "vc-streams", "name": "vc-cluster",
    }


def test_relationship_graph_advances_owner_chain_one_bounded_hop_at_a_time() -> None:
    graph = derive_evidence_relationship_graph([{
        "id": "pod-1", "tool": "get_resource",
        "data": {
            "apiVersion": "v1", "kind": "Pod", "resource": "pods",
            "metadata": {
                "namespace": "payments", "name": "api-abc",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-123",
                    "uid": "rs-uid",
                }],
            },
        },
    }, {
        "id": "rs-1", "tool": "get_resource",
        "data": {
            "apiVersion": "apps/v1", "kind": "ReplicaSet", "resource": "replicasets",
            "metadata": {
                "namespace": "payments", "name": "api-123",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "Deployment", "name": "api",
                    "uid": "deployment-uid",
                }],
            },
        },
    }])

    assert {
        (item["source"], item["target"], item["relation"])
        for item in graph["edges"]
    } >= {
        ("Pod:payments/api-abc", "ReplicaSet:payments/api-123", "owned_by"),
        ("ReplicaSet:payments/api-123", "Deployment:payments/api", "owned_by"),
    }
    assert [item["target"] for item in graph["frontier"] if item["relation"] == "owned_by"] == [
        "Deployment:payments/api"
    ]


def test_candidate_selection_normalizes_plan_to_collect() -> None:
    plan = ReadPlan(
        scope_summary="Select the grounded backend Service read.",
        candidate_ids=["read-0123456789abcdefabcd"],
    )

    assert plan.decision == "collect"
    assert plan.intents == []


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


def test_missing_pem_traceback_is_correlated_across_neighboring_log_lines() -> None:
    observation = AdHocObservation(
        id="cluster-gateway-log", tool="pod_logs", summary="Collected gateway logs.",
        source="kubernetes:v1:Pod/log:maas/gateway-abc?current",
        collected_at=datetime.now(timezone.utc),
        data={
            "container": "gateway",
            "tail": (
                "ssl_context.load_cert_chain(\n"
                "    certfile='/etc/certs/server.pem',\n"
                "FileNotFoundError: [Errno 2] No such file or directory\n"
            ),
        },
    )

    findings = derive_adhoc_findings([observation.to_dict()])
    followups = automatic_read_followups(
        ReadIntent(tool="pod_logs", candidate_id="podlog-gateway"), (observation,)
    )

    assert len(findings) == 1
    assert findings[0]["category"] == "tls_or_certificate"
    assert findings[0]["occurrences_in_excerpt"] == 1
    assert findings[0]["paths"] == ["/etc/certs/server.pem"]
    assert "FileNotFoundError" in findings[0]["error_samples"][0]
    assert [item.intent.tool for item in followups] == ["get_resource", "search_resources"]


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
            "source": "kubernetes:v1:Pod:mesh/gateway-1",
            "data": {
                "kind": "Pod",
                "podpilotMounts": [{
                    "container": "istio-proxy", "mountPath": "/etc/certs",
                    "volume": "gateway-certs", "sourceType": "Secret",
                    "sourceName": "gateway-client-tls",
                }],
            },
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
    assert finding["completed_checks"] == [
        "exact_pod_specification", "pod_mount_configuration", "pod_events",
    ]
    assert finding["mount_correlations"][0]["sourceName"] == "gateway-client-tls"
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


def test_route_traffic_evidence_deterministically_follows_service_and_backend_pods() -> None:
    route = AdHocObservation(
        id="cluster-route-1", tool="search_resources", summary="Found Route.",
        source="kubernetes:route.openshift.io/v1:Route:maas/*",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Route",
            "items": [{
                "metadata": {"name": "maas", "namespace": "maas"},
                "spec": {"to": {"kind": "Service", "name": "model-server"}},
            }],
        },
    )

    service_reads = automatic_read_followups(
        ReadIntent(
            tool="search_resources", resource="routes.route.openshift.io",
            match_field="spec.host", match_value="maas.apps.example.test",
        ),
        (route,),
        question="Why does https://maas.apps.example.test return Internal Server Error?",
    )

    assert len(service_reads) == 1
    assert service_reads[0].code == "traffic_path_investigation"
    assert service_reads[0].intent.tool == "get_resource"
    assert service_reads[0].intent.namespace == "maas"
    assert service_reads[0].intent.name == "model-server"

    service = AdHocObservation(
        id="cluster-service-1", tool="get_resource", summary="Read Service.",
        source="kubernetes:v1:Service:maas/model-server",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Service", "metadata": {"name": "model-server", "namespace": "maas"},
            "spec": {"selector": {"app": "model-server"}},
        },
    )
    backend_reads = automatic_read_followups(
        service_reads[0].intent, (service,),
        question="Why does https://maas.apps.example.test return Internal Server Error?",
    )

    assert [item.intent.tool for item in backend_reads] == [
        "list_resources", "list_resources", "get_resource",
    ]
    assert backend_reads[0].intent.kind == "Pod"
    assert backend_reads[0].intent.label_selector == "app=model-server"
    assert backend_reads[1].intent.kind == "EndpointSlice"
    assert backend_reads[2].intent.kind == "Endpoints"


def test_traffic_investigation_reads_healthy_backend_logs_and_endpoint_targets() -> None:
    pods = AdHocObservation(
        id="cluster-pods-healthy", tool="list_resources", summary="Read backend Pods.",
        source="kubernetes:v1:Pod:maas/*", collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Pod", "scope": "maas",
            "logCandidates": [{
                "namespace": "maas", "pod": "model-server-abc", "containers": ["server"],
                "phase": "Running", "ready": True, "restartCount": 0,
            }],
        },
    )

    log_reads = automatic_read_followups(
        ReadIntent(
            tool="list_resources", resource="pods", api_version="v1", kind="Pod",
            namespace="maas", label_selector="app=model-server",
        ),
        (pods,),
        question="The Route returns HTTP 500; inspect its backend.",
    )

    assert len(log_reads) == 1
    assert log_reads[0].code == "pod_log_investigation"
    assert log_reads[0].intent.name == "model-server-abc"
    assert "backend traffic path" in log_reads[0].reason

    endpoint_slice = AdHocObservation(
        id="cluster-slice-1", tool="list_resources", summary="Read EndpointSlice.",
        source="kubernetes:discovery.k8s.io/v1:EndpointSlice:maas/*",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "EndpointSlice",
            "items": [{
                "metadata": {"namespace": "maas"},
                "podTargets": [{"kind": "Pod", "name": "model-server-abc"}],
            }],
        },
    )
    pod_reads = automatic_read_followups(
        ReadIntent(tool="list_resources", resource="endpointslices"),
        (endpoint_slice,),
        question="The Route returns HTTP 500; inspect its backend.",
    )

    assert len(pod_reads) == 1
    assert pod_reads[0].intent.kind == "Pod"
    assert pod_reads[0].intent.name == "model-server-abc"

    legacy_endpoints = AdHocObservation(
        id="cluster-endpoints-1", tool="get_resource", summary="Read Endpoints.",
        source="kubernetes:v1:Endpoints:maas/model-server",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Endpoints", "metadata": {"namespace": "maas"},
            "subsets": [{
                "addresses": [{
                    "ip": "10.0.0.8",
                    "targetRef": {"kind": "Pod", "name": "model-server-abc"},
                }],
            }],
        },
    )
    legacy_pod_reads = automatic_read_followups(
        ReadIntent(
            tool="get_resource", resource="endpoints", api_version="v1", kind="Endpoints",
            namespace="maas", name="model-server",
        ),
        (legacy_endpoints,),
        question="The Route returns HTTP 500; inspect its backend.",
    )
    assert legacy_pod_reads[0].intent.name == "model-server-abc"


def test_configuration_question_expands_inventory_to_exact_object_reads() -> None:
    inventory = AdHocObservation(
        id="cluster-clf-list", tool="list_resources",
        summary="Read ClusterLogForwarder resources.",
        source="kubernetes:observability.openshift.io/v1:ClusterLogForwarder:cluster/*",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "observability.openshift.io/v1",
            "kind": "ClusterLogForwarder",
            "resource": "clusterlogforwarders.observability.openshift.io",
            "objects": [{"namespace": "openshift-logging", "name": "instance"}],
        },
    )

    followups = automatic_read_followups(
        ReadIntent(
            tool="list_resources",
            resource="clusterlogforwarders.observability.openshift.io",
            api_version="observability.openshift.io/v1",
            kind="ClusterLogForwarder",
        ),
        (inventory,),
        question="Are the cluster log forwarders set up to forward logs?",
        goal_type="explain",
    )

    assert len(followups) == 1
    assert followups[0].code == "configuration_detail"
    assert followups[0].evidence_ids == ("cluster-clf-list",)
    assert followups[0].intent == ReadIntent(
        tool="get_resource",
        resource="clusterlogforwarders.observability.openshift.io",
        api_version="observability.openshift.io/v1",
        kind="ClusterLogForwarder",
        namespace="openshift-logging",
        name="instance",
    )


def test_explicit_config_display_follows_exact_observed_configmap_reference() -> None:
    kafka = AdHocObservation(
        id="cluster-kafka", tool="get_resource", summary="Read Kafka.",
        source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:vc-streams/vc-cluster",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            "spec": {"kafka": {"metricsConfig": {"valueFrom": {
                "configMapKeyRef": {"name": "kafka-metrics", "key": "metrics.yml"},
            }}}},
        },
    )

    followups = automatic_read_followups(
        ReadIntent(
            tool="get_resource", resource="kafkas.kafka.strimzi.io",
            api_version="kafka.strimzi.io/v1beta2", kind="Kafka",
            namespace="vc-streams", name="vc-cluster",
        ),
        (kafka,),
        question="Show me the config.",
        goal_type="explain",
    )

    assert len(followups) == 1
    assert followups[0].code == "referenced_configmap"
    assert followups[0].evidence_ids == ("cluster-kafka",)
    assert followups[0].intent == ReadIntent(
        tool="get_resource", resource="configmaps", api_version="v1",
        kind="ConfigMap", namespace="vc-streams", name="kafka-metrics",
    )


def test_configmap_reference_is_not_automatically_followed_without_display_request() -> None:
    kafka = AdHocObservation(
        id="cluster-kafka", tool="get_resource", summary="Read Kafka.",
        source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:vc-streams/vc-cluster",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Kafka",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            "spec": {"metricsConfig": {
                "configMapKeyRef": {"name": "kafka-metrics", "key": "metrics.yml"},
            }},
        },
    )

    assert automatic_read_followups(
        ReadIntent(
            tool="get_resource", resource="kafkas.kafka.strimzi.io",
            api_version="kafka.strimzi.io/v1beta2", kind="Kafka",
            namespace="vc-streams", name="vc-cluster",
        ),
        (kafka,),
        question="Is Prometheus export configured?",
        goal_type="explain",
    ) == ()


def test_source_cr_display_does_not_automatically_follow_supporting_configmap() -> None:
    kafka = AdHocObservation(
        id="cluster-kafka", tool="get_resource", summary="Read Kafka.",
        source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:vc-streams/vc-cluster",
        collected_at=datetime.now(timezone.utc),
        data={
            "kind": "Kafka",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            "spec": {"metricsConfig": {
                "configMapKeyRef": {"name": "kafka-metrics", "key": "metrics.yml"},
            }},
        },
    )

    assert automatic_read_followups(
        ReadIntent(
            tool="get_resource", resource="kafkas.kafka.strimzi.io",
            api_version="kafka.strimzi.io/v1beta2", kind="Kafka",
            namespace="vc-streams", name="vc-cluster",
        ),
        (kafka,),
        question="Show the Kafka CR configuration that references the ConfigMap.",
        goal_type="explain", primary_kind="Kafka",
    ) == ()


def test_plain_inventory_question_does_not_expand_every_object() -> None:
    inventory = AdHocObservation(
        id="cluster-widget-list", tool="list_resources", summary="Read Widgets.",
        source="kubernetes:example.io/v1:Widget:apps/*",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "example.io/v1", "kind": "Widget", "resource": "widgets",
            "objects": [{"namespace": "apps", "name": "one"}],
        },
    )

    assert automatic_read_followups(
        ReadIntent(
            tool="list_resources", resource="widgets",
            api_version="example.io/v1", kind="Widget",
        ),
        (inventory,),
        question="List the Widgets in the cluster.",
        goal_type="inventory",
    ) == ()


def test_non_inventory_health_question_expands_inventory_to_details() -> None:
    inventory = AdHocObservation(
        id="cluster-operator-list", tool="list_resources", summary="Read operators.",
        source="kubernetes:config.openshift.io/v1:ClusterOperator:cluster/*",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "config.openshift.io/v1", "kind": "ClusterOperator",
            "resource": "clusteroperators", "objects": [{"name": "ingress"}],
        },
    )

    followups = automatic_read_followups(
        ReadIntent(
            tool="list_resources", resource="clusteroperators",
            api_version="config.openshift.io/v1", kind="ClusterOperator",
        ),
        (inventory,),
        question="Are the cluster operators healthy?",
        goal_type="health",
    )

    assert [item.code for item in followups] == ["configuration_detail"]
    assert followups[0].intent.name == "ingress"


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


def test_pod_health_summary_accepts_only_scope_and_result_limit() -> None:
    assert ReadIntent(
        tool="pod_health_summary", namespace="payments", limit=50
    ).namespace == "payments"

    with pytest.raises(ValueError, match="accept only their typed scope"):
        ReadIntent(
            tool="pod_health_summary", resource="pods", namespace="payments"
        )


@pytest.mark.parametrize("question", [
    "Are any pods on the cluster crashing currently?",
    "Show unhealthy pods",
    "What is the health status of the pods?",
])
def test_known_pod_health_questions_compile_to_typed_summary(question: str) -> None:
    planned = plan_known_read(question, inventory_limit=500)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "health"
    assert plan.intents == [ReadIntent(tool="pod_health_summary", limit=200)]


@pytest.mark.parametrize("question", [
    "Are pods crashing in namespace payments?",
    "Show crashing pods in payments",
    'Show crashing pods in "my-namespace"',
    "Show unhealthy pods from project team-a",
])
def test_known_pod_health_question_preserves_explicit_namespace(question: str) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    expected = (
        "my-namespace" if "my-namespace" in question else
        "team-a" if "team-a" in question else "payments"
    )
    assert planned[0].intents == [ReadIntent(
        tool="pod_health_summary", namespace=expected, limit=200,
    )]


def test_pod_health_cluster_word_is_not_treated_as_a_namespace() -> None:
    planned = plan_known_read("Show crashing pods in the cluster")

    assert planned is not None
    assert planned[0].intents == [ReadIntent(tool="pod_health_summary", limit=200)]


@pytest.mark.parametrize(("question", "expected"), [
    ("Show unhealthy nodes", ReadIntent(tool="node_health_summary", limit=200)),
    (
        "Show degraded cluster operators",
        ReadIntent(tool="cluster_operator_health_summary", limit=200),
    ),
    (
        "Show failed machines in openshift-machine-api",
        ReadIntent(
            tool="machine_health_summary", namespace="openshift-machine-api", limit=200,
        ),
    ),
    (
        'Show unhealthy deployments in "my-namespace"',
        ReadIntent(
            tool="workload_health_summary", kind="Deployment",
            namespace="my-namespace", limit=200,
        ),
    ),
    (
        "Show unhealthy stateful sets in payments",
        ReadIntent(
            tool="workload_health_summary", kind="StatefulSet",
            namespace="payments", limit=200,
        ),
    ),
    (
        "Show daemon set health in platform",
        ReadIntent(
            tool="workload_health_summary", kind="DaemonSet",
            namespace="platform", limit=200,
        ),
    ),
])
def test_known_resource_health_questions_compile_to_typed_summary(
    question: str, expected: ReadIntent,
) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    assert planned[1] is True
    assert planned[0].intents == [expected]


def test_health_summary_scope_validation_matches_resource_scope() -> None:
    assert ReadIntent(
        tool="workload_health_summary", kind="StatefulSet", namespace="payments",
    ).namespace == "payments"
    assert ReadIntent(
        tool="machine_health_summary", namespace="openshift-machine-api",
    ).namespace == "openshift-machine-api"
    with pytest.raises(ValidationError, match="does not accept a namespace"):
        ReadIntent(tool="node_health_summary", namespace="payments")
    with pytest.raises(ValidationError, match="does not accept a namespace"):
        ReadIntent(tool="cluster_operator_health_summary", namespace="payments")
    with pytest.raises(ValidationError, match="kind must be"):
        ReadIntent(tool="workload_health_summary", kind="ReplicaSet")


def test_pod_log_request_does_not_compile_to_health_summary() -> None:
    planned = plan_known_read("Show logs for crashing pods")

    assert planned is None


def test_cluster_wide_namespace_placeholder_is_omitted_for_list_reads() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        resource="kafkas.kafka.strimzi.io",
        api_version="kafka.strimzi.io/v1beta2",
        kind="Kafka",
        namespace="*",
    )

    normalized = normalize_read_intent(proposed)

    assert normalized.namespace is None
    assert normalized.resource == "kafkas.kafka.strimzi.io"


def test_custom_resource_coordinates_remain_model_proposed_for_broker_validation() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        api_version="example.io/v1",
        kind="Widget",
    )

    assert normalize_read_intent(proposed) == proposed


def test_metric_intent_without_explicit_range_normalizes_to_five_minutes() -> None:
    proposed = ReadIntent(
        tool="query_metrics", metric="node_cpu_utilization",
        metric_scope="node_role", name="worker",
    )

    normalized = normalize_read_intent(proposed)

    assert proposed.range_seconds == 3600
    assert "range_seconds" not in proposed.model_fields_set
    assert normalized.range_seconds == 300


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


@pytest.mark.parametrize("question", [
    (
        "There is an authorino pod in kuadrant-system namespace, check its logs "
        "for errors that could generate a 401."
    ),
    "Check logs for pod authorino in namespace kuadrant-system.",
    "Inspect the authorino pod logs from the kuadrant-system namespace.",
])
def test_pod_log_request_compiles_bounded_name_discovery(question: str) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is False
    assert plan.goal_type == "logs"
    assert plan.intents == [ReadIntent(
        tool="search_resources",
        resource="pods",
        api_version="v1",
        kind="Pod",
        namespace="kuadrant-system",
        match_field="metadata.name",
        match_value="authorino",
        match_operator="contains",
        limit=20,
    )]


@pytest.mark.parametrize(("period", "expected_seconds"), [
    ("last 5m", 300),
    ("past 30 minutes", 1800),
    ("previous 2 hours", 7200),
    ("last 7d", 604800),
    ("past hour", 3600),
    ("last week", 604800),
    ("previous 2 weeks", 1209600),
    ("last 30 seconds", 300),
    ("last 999 days", 7_776_000),
])
def test_cluster_log_volume_preserves_bounded_requested_period(
    period: str, expected_seconds: int,
) -> None:
    planned = plan_known_read(
        f"Rank namespaces by application log volume in the {period}"
    )

    assert planned is not None
    assert planned[0].intents[0].range_seconds == expected_seconds


def test_cluster_log_volume_today_uses_elapsed_utc_day_and_requested_top_n() -> None:
    planned = plan_known_read(
        "Show the top 7 namespaces by application log volume today",
        now=datetime(2026, 8, 27, 12, 30, tzinfo=timezone.utc),
    )

    assert planned is not None
    intent = planned[0].intents[0]
    assert intent.range_seconds == 45_000
    assert intent.limit == 7


def test_pod_log_request_requires_explicit_namespace_and_name_hint() -> None:
    assert plan_known_read("Check the pod logs for errors") is None
    assert plan_known_read("Check authorino pod logs") is None


def test_singular_namespaced_resource_phrase_is_discovery_not_terminal_inventory() -> None:
    planned = plan_known_read(
        "Show the image on pod api-123 in namespace payments."
    )

    assert planned is not None
    plan, terminal = planned
    assert terminal is False
    assert plan.goal_type == "diagnose"
    assert plan.intents[0].tool == "list_resources"


def test_service_account_phrase_is_not_terminal_service_inventory() -> None:
    planned = plan_known_read(
        "What permissions does service account builder have in namespace payments?"
    )

    assert planned is not None
    assert planned[1] is False
    assert planned[0].intents[0].kind == "Service"


@pytest.mark.parametrize("question", [
    'show the labels on the node "devocp4cmspc-wtlkr-worker-canadacentral1-vk96r"',
    "Show node devocp4cmspc-wtlkr-worker-canadacentral1-vk96r labels",
])
def test_exact_node_label_request_compiles_to_terminal_get(question: str) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "explain"
    assert plan.intents == [ReadIntent(
        tool="get_resource",
        resource="nodes",
        api_version="v1",
        kind="Node",
        name="devocp4cmspc-wtlkr-worker-canadacentral1-vk96r",
    )]


def test_pod_search_evidence_exposes_exact_container_log_candidates() -> None:
    candidates = pod_log_candidates_from_evidence([{
        "id": "cluster-authorino-pods",
        "tool": "search_resources",
        "data": {
            "kind": "Pod",
            "scope": "kuadrant-system",
            "logCandidates": [{
                "namespace": "kuadrant-system",
                "pod": "authorino-7fbbd96d8b-z2x9k",
                "containers": ["authorino"],
                "phase": "Running",
                "ready": True,
                "restartCount": 0,
            }],
        },
    }])

    assert [(item.namespace, item.pod, item.container) for item in candidates] == [
        ("kuadrant-system", "authorino-7fbbd96d8b-z2x9k", "authorino"),
    ]


@pytest.mark.parametrize("question", [
    (
        "Investigate TCP timeouts from pod client-7d9 in namespace frontend "
        "to pod database-0 in namespace data on port 5432."
    ),
    "Why is the connection from pod frontend/client-7d9 to data/database-0 timing out?",
])
def test_cross_namespace_pod_connectivity_collects_policy_selector_evidence(
    question: str,
) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is False
    assert len(plan.intents) == 6
    assert [intent.kind for intent in plan.intents] == [
        "Pod", "Pod", "Namespace", "Namespace", "NetworkPolicy", "NetworkPolicy",
    ]
    assert [(intent.namespace, intent.name) for intent in plan.intents[:2]] == [
        ("frontend", "client-7d9"), ("data", "database-0"),
    ]
    assert [intent.name for intent in plan.intents[2:4]] == ["frontend", "data"]
    assert [intent.namespace for intent in plan.intents[4:]] == ["frontend", "data"]
    assert all(intent.limit == 100 for intent in plan.intents[4:])


def test_network_policy_plan_requires_exact_pods_in_two_namespaces() -> None:
    assert plan_known_read("Investigate TCP timeouts between pods in different namespaces") is None
    assert plan_known_read(
        "Investigate TCP from pod client in namespace frontend to pod api in namespace frontend"
    ) is None


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
        tool="list_resources", resource="clusteroperators",
        api_version="config.openshift.io/v1", kind="ClusterOperator", limit=500,
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


def test_live_catalog_pins_exact_coordinates_and_prefers_node_over_node_metrics() -> None:
    catalog = [{
        "resource": "nodes.metrics.k8s.io",
        "apiVersion": "metrics.k8s.io/v1beta1",
        "kind": "NodeMetrics",
        "namespaced": False,
    }, {
        "resource": "nodes.core",
        "apiVersion": "v1",
        "kind": "Node",
        "namespaced": False,
    }]

    planned = plan_catalog_read("Show me a list of nodes on the cluster", catalog)

    assert planned is not None
    assert planned[0].intents == [ReadIntent(
        tool="list_resources", resource="nodes.core", api_version="v1",
        kind="Node", limit=500,
    )]


def test_live_catalog_can_explicitly_select_node_metrics() -> None:
    catalog = [{
        "resource": "nodes.metrics.k8s.io",
        "apiVersion": "metrics.k8s.io/v1beta1",
        "kind": "NodeMetrics",
        "namespaced": False,
    }, {
        "resource": "nodes.core",
        "apiVersion": "v1",
        "kind": "Node",
        "namespaced": False,
    }]

    planned = plan_catalog_read("Show node metrics", catalog)

    assert planned is not None
    assert planned[0].intents[0].api_version == "metrics.k8s.io/v1beta1"
    assert planned[0].intents[0].kind == "NodeMetrics"


def test_live_catalog_uses_group_hint_for_same_kind_custom_resources() -> None:
    catalog = [{
        "resource": "machines.cluster.x-k8s.io",
        "apiVersion": "cluster.x-k8s.io/v1beta1",
        "kind": "Machine",
        "namespaced": True,
    }, {
        "resource": "machines.machine.openshift.io",
        "apiVersion": "machine.openshift.io/v1beta1",
        "kind": "Machine",
        "namespaced": True,
    }]

    planned = plan_catalog_read("List OpenShift machines", catalog)

    assert planned is not None
    assert planned[0].intents[0].resource == "machines.machine.openshift.io"
    assert planned[0].intents[0].api_version == "machine.openshift.io/v1beta1"
    assert planned[0].intents[0].kind == "Machine"

    default = plan_catalog_read("List machines", catalog)
    assert default is not None
    assert default[0].intents[0].resource == "machines.machine.openshift.io"

    cluster_api = plan_catalog_read("List Cluster API machines", catalog)
    assert cluster_api is not None
    assert cluster_api[0].intents[0].resource == "machines.cluster.x-k8s.io"


def test_live_catalog_pins_configmap_coordinates() -> None:
    planned = plan_catalog_read("List configmaps", [{
        "resource": "configmaps",
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "namespaced": True,
    }])

    assert planned is not None
    assert planned[0].intents[0] == ReadIntent(
        tool="list_resources", resource="configmaps", api_version="v1",
        kind="ConfigMap", limit=500,
    )


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


def test_dynamic_discovery_and_bounded_watch_have_strict_contracts() -> None:
    discovery = ReadIntent(tool="discover_resources", discovery_query="Authorino policy")
    watch = ReadIntent(
        tool="watch_resources", resource="authconfigs.authorino.kuadrant.io",
        namespace="kuadrant-system", name="maas", watch_seconds=15,
    )

    assert discovery.discovery_query == "Authorino policy"
    assert watch.watch_seconds == 15
    with pytest.raises(ValidationError, match="requires a discovery_query"):
        ReadIntent(tool="discover_resources")
    with pytest.raises(ValidationError, match="only for watch_resources"):
        ReadIntent(tool="get_resource", resource="pods", watch_seconds=3)


def test_authorino_permission_denied_log_is_a_deterministic_signal() -> None:
    observation = AdHocObservation(
        id="cluster-authorino-log-1", tool="pod_logs", summary="Collected Authorino logs.",
        source="kubernetes:v1:Pod/log:kuadrant-system/authorino-1?current",
        collected_at=datetime.now(timezone.utc),
        data={
            "container": "authorino",
            "tail": "request rejected: PERMISSION_DENIED (HTTP 401) by authorization policy",
        },
    )

    findings = derive_adhoc_findings([observation.to_dict()])

    assert findings[0]["category"] == "authentication_or_authorization"
    assert findings[0]["severity"] == "error"


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
    namespace_volumes = ReadIntent(
        tool="query_metrics", metric="persistent_volume_usage",
        metric_scope="namespace", namespace="payments",
        metric_operation="rank", limit=5,
    )
    assert namespace_volumes.limit == 5
    with pytest.raises(ValidationError, match="claim, namespace, or cluster"):
        ReadIntent(
            tool="query_metrics", metric="persistent_volume_usage",
            metric_scope="pod", namespace="payments", name="api-1",
        )
    node = ReadIntent(
        tool="query_metrics", metric="top_cpu_consumers",
        metric_scope="node", name="worker-2",
    )
    assert node.namespace is None
    worker_role = ReadIntent(
        tool="query_metrics", metric="node_cpu_utilization",
        metric_scope="node_role", name="worker",
    )
    assert worker_role.name == "worker"
    namespace = ReadIntent(
        tool="query_metrics", metric="top_memory_consumers",
        metric_scope="namespace", namespace="payments",
    )
    assert namespace.name is None
    cluster = ReadIntent(
        tool="query_metrics", metric="top_cpu_consumers",
        metric_scope="cluster", limit=5,
    )
    assert cluster.namespace is None and cluster.name is None and cluster.limit == 5
    node_ranking = ReadIntent(
        tool="query_metrics", metric="node_cpu_utilization",
        metric_scope="cluster", metric_operation="rank",
        metric_group_by=["node"], limit=5,
    )
    assert node_ranking.name is None and node_ranking.limit == 5
    with pytest.raises(ValidationError, match="cluster ranking grouped by node"):
        ReadIntent(
            tool="query_metrics", metric="node_cpu_utilization",
            metric_scope="cluster",
        )
    with pytest.raises(ValidationError, match="requires cluster, namespace, workload, or node scope"):
        ReadIntent(
            tool="query_metrics", metric="top_memory_consumers",
            metric_scope="pod", namespace="payments", name="api-1",
        )
    log_volume = ReadIntent(
        tool="query_metrics", metric="top_log_volume_by_namespace",
        metric_scope="cluster", limit=10,
    )
    assert log_volume.namespace is None
    with pytest.raises(ValidationError, match="requires cluster scope"):
        ReadIntent(
            tool="query_metrics", metric="top_log_volume_by_namespace",
            metric_scope="namespace", namespace="payments",
        )


def test_platform_metric_scopes_require_typed_coordinates() -> None:
    kafka = ReadIntent(
        tool="query_metrics", metric="kafka_consumer_lag",
        metric_scope="kafka_cluster", kind="Kafka",
        namespace="vc-streams", name="vc-cluster",
        metric_operation="rank", metric_group_by=["topic", "consumer_group"],
    )
    assert kafka.kind == "Kafka"
    route = ReadIntent(
        tool="query_metrics", metric="ingress_request_rate",
        metric_scope="route", kind="Route",
        namespace="payments", name="api",
    )
    assert route.name == "api"
    monitoring = ReadIntent(
        tool="query_metrics", metric="monitoring_targets_down",
        metric_scope="monitoring", metric_operation="rank",
        metric_group_by=["job", "instance"],
    )
    assert monitoring.namespace is None
    logging = ReadIntent(
        tool="query_metrics", metric="logging_ingestion_rate",
        metric_scope="logging", metric_group_by=["tenant"],
    )
    assert logging.metric_scope == "logging"
    with pytest.raises(ValidationError, match="requires kind Kafka"):
        ReadIntent(
            tool="query_metrics", metric="kafka_topic_storage",
            metric_scope="kafka_cluster", kind="Route",
            namespace="vc-streams", name="vc-cluster",
        )
    with pytest.raises(ValidationError, match="does not support"):
        ReadIntent(
            tool="query_metrics", metric="etcd_db_size",
            metric_scope="route", kind="Route", namespace="payments", name="api",
        )
    with pytest.raises(ValidationError, match="does not support"):
        ReadIntent(
            tool="query_metrics", metric="logging_query_latency",
            metric_scope="monitoring",
        )


@pytest.mark.parametrize(("question", "expected_limit"), [
    ("Which namespaces are producing the biggest volume of logs on the cluster?", 10),
    ("Rank namespaces by application log volume", 10),
    ("Show log bytes by namespace", 10),
    ("Show me the top 5 namespaces that produce the most amount of logs", 5),
    ("Show the namespaces that produced the most logs", 10),
])
def test_cluster_log_volume_question_compiles_to_typed_metric_query(
    question: str, expected_limit: int,
) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="query_metrics",
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        range_seconds=300,
        limit=expected_limit,
    )]


def test_exact_weekly_log_producer_question_is_a_terminal_registered_read() -> None:
    planned = plan_known_read(
        "which namespaces produce the most amount of logs over the last week?"
    )

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="query_metrics",
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        range_seconds=604_800,
        limit=10,
    )]


@pytest.mark.parametrize(
    "question",
    [
        "are there Kafka clusters deployed here?",
        "are there Kafka instances installed on the selected OpenShift clusters?",
        "are any Kafka deployments running here?",
        "Show me all the deployed Kafka clusters",
        "List deployed Kafka clusters on the selected OpenShift clusters",
    ],
)
def test_kafka_existence_question_compiles_terminal_inventory(question: str) -> None:
    planned = plan_known_read(question, inventory_limit=250)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "inventory"
    assert plan.intents == [ReadIntent(
        tool="list_resources",
        resource="kafkas.kafka.strimzi.io",
        kind="Kafka",
        limit=250,
    )]


@pytest.mark.parametrize(
    "question",
    [
        "show Kafka cluster metrics",
        "why is the Kafka cluster unhealthy?",
        "show Kafka topics",
    ],
)
def test_kafka_non_inventory_question_does_not_use_inventory_shortcut(
    question: str,
) -> None:
    assert plan_known_read(question) is None


def test_namespace_kafka_topic_storage_compiles_discovery_then_metric_reads() -> None:
    planned = plan_known_read(
        "show me the disk usage of kafka topics in kafka-observability namespace",
        inventory_limit=250,
    )

    assert planned is not None
    discovery, terminal = planned
    assert terminal is True
    assert discovery.intents == [ReadIntent(
        tool="list_resources",
        resource="kafkas.kafka.strimzi.io",
        kind="Kafka",
        namespace="kafka-observability",
        limit=250,
    )]
    metric_plan = plan_kafka_topic_storage_metrics(
        "show me the disk usage of kafka topics in kafka-observability namespace",
        [("kafka-observability", "logs-kafka")],
    )
    assert metric_plan is not None
    assert metric_plan.intents == [ReadIntent(
        tool="query_metrics",
        metric="kafka_topic_storage",
        metric_scope="kafka_cluster",
        kind="Kafka",
        namespace="kafka-observability",
        name="logs-kafka",
        range_seconds=300,
        limit=10,
        metric_group_by=["topic"],
    )]
    assert plan_kafka_topic_storage_metrics(
        "show me the disk usage of kafka topics in kafka-observability namespace",
        [],
    ) is None


def test_worker_node_cpu_and_memory_utilization_compiles_to_two_role_queries() -> None:
    planned = plan_known_read(
        "show me the current cpu/mem utilization for worker nodes in the cluster"
    )

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "compare"
    assert plan.intents == [
        ReadIntent(
            tool="query_metrics", metric="node_cpu_utilization",
            metric_scope="node_role", name="worker", range_seconds=300,
        ),
        ReadIntent(
            tool="query_metrics", metric="node_memory_utilization",
            metric_scope="node_role", name="worker", range_seconds=300,
        ),
    ]


@pytest.mark.parametrize(
    ("question", "metric", "scope", "name", "limit"),
    [
        (
            "show me the top 5 cpu consuming nodes on the cluster",
            "node_cpu_utilization", "cluster", None, 5,
        ),
        (
            "rank the 3 worker nodes with the highest memory usage",
            "node_memory_utilization", "node_role", "worker", 3,
        ),
    ],
)
def test_node_utilization_ranking_compiles_to_bounded_metric_query(
    question: str, metric: str, scope: str, name: str | None, limit: int,
) -> None:
    planned = plan_known_read(question)

    assert planned is not None
    plan, terminal = planned
    assert terminal is True
    assert plan.goal_type == "compare"
    assert plan.intents == [ReadIntent(
        tool="query_metrics", metric=metric, metric_scope=scope,
        name=name, range_seconds=300, limit=limit,
        metric_operation="rank", metric_group_by=["node"],
    )]


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
        range_seconds=300,
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


def test_audit_query_requires_complete_semantics() -> None:
    with pytest.raises(ValidationError, match="operation scope and outcome"):
        ReadIntent(tool="query_audit_events", audit_username="operator")


def test_audit_query_accepts_exact_username_and_filters() -> None:
    intent = ReadIntent(
        tool="query_audit_events",
        audit_username="Druciare-Adm",
        audit_operation_scope="mutations",
        audit_outcome="successful",
        range_seconds=7200,
        limit=5,
    )

    assert intent.audit_username == "Druciare-Adm"


def test_audit_query_accepts_cluster_wide_filters_without_username() -> None:
    intent = ReadIntent(
        tool="query_audit_events",
        audit_operation_scope="deletes",
        audit_outcome="all",
        audit_search_until_limit=True,
        range_seconds=3600,
        limit=10,
    )

    assert intent.audit_username is None
    assert intent.audit_operation_scope == "deletes"


@pytest.mark.parametrize("metric", ["ingress_bytes_in", "ingress_bytes_out"])
def test_ingress_bandwidth_accepts_cluster_route_and_namespace_scopes(metric: str) -> None:
    cluster = ReadIntent(
        tool="query_metrics", metric=metric, metric_scope="cluster",
        metric_operation="trend", range_seconds=259_200,
    )
    namespace = ReadIntent(
        tool="query_metrics", metric=metric, metric_scope="namespace",
        namespace="payments", metric_operation="trend",
    )
    route = ReadIntent(
        tool="query_metrics", metric=metric, metric_scope="route", kind="Route",
        namespace="payments", name="api", metric_operation="trend",
    )

    assert cluster.range_seconds == 259_200
    assert namespace.namespace == "payments"
    assert route.name == "api"


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
