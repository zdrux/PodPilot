from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import InsecureRequestWarning

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_diagnostics.adhoc import AdHocObservation, ReadResult
from podpilot_openshift.explorer import (
    KubernetesReadOnlyExplorer,
    ReadOnlyExplorerError,
    _list_projection,
    _remote_discovery_error,
)


class FakeObject:
    def __init__(self, name="api", namespace="payments", payload=None):
        self.metadata = SimpleNamespace(name=name, namespace=namespace)
        self._payload = payload or {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": namespace, "managedFields": ["large"]},
            "data": {"UPSTREAM_DNS": "10.0.0.2", "password": "do-not-leak"},
        }

    def to_dict(self):
        return self._payload


@pytest.mark.parametrize(("status", "expected"), [
    (401, "rejected the configured bearer token"),
    (403, "denied read-only API discovery"),
    (500, "could not complete read-only discovery"),
])
def test_remote_discovery_errors_are_actionable_without_raw_headers(status, expected):
    exc = ApiException(status=status, reason="Forbidden")
    exc.headers = {"Audit-Id": "do-not-display"}

    detail = _remote_discovery_error(exc)

    assert expected in detail
    assert "Audit-Id" not in detail
    assert "do-not-display" not in detail


@pytest.mark.parametrize("tls_verify", [True, False])
def test_remote_cluster_client_sends_bearer_scheme_and_honors_tls_mode(
    monkeypatch, tls_verify,
):
    captured = {}
    suppressed = []

    class FakeDynamicClient:
        def __init__(self, api_client):
            captured["configuration"] = api_client.configuration
            self.resources = SimpleNamespace(search=lambda **_kwargs: [])

    monkeypatch.setattr(
        "podpilot_openshift.explorer.DynamicClient",
        FakeDynamicClient,
    )
    monkeypatch.setattr(
        "podpilot_openshift.explorer.urllib3.disable_warnings",
        suppressed.append,
    )

    KubernetesReadOnlyExplorer.for_remote_cluster(
        api_url="https://api.remote.example:6443",
        token="eyJ.test.jwt",
        tls_verify=tls_verify,
    )

    configuration = captured["configuration"]
    bearer = configuration.auth_settings()["BearerToken"]
    assert bearer["key"] == "authorization"
    assert bearer["value"] == "Bearer eyJ.test.jwt"
    assert configuration.verify_ssl is tls_verify
    assert configuration.assert_hostname is tls_verify
    assert suppressed == ([] if tls_verify else [InsecureRequestWarning])


def test_audit_query_routes_to_dedicated_reader_without_kubernetes_discovery() -> None:
    class AuditReader:
        def __init__(self) -> None:
            self.intent = None

        def execute(self, intent):
            self.intent = intent
            return ReadResult((AdHocObservation(
                id="audit-1", tool="query_audit_events", summary="Read audit events.",
                source="loki:audit/query/user_actions",
                collected_at=datetime.now(timezone.utc),
                data={"events": []},
            ),))

    reader = AuditReader()
    explorer = KubernetesReadOnlyExplorer(audit_reader=reader)
    intent = ReadIntent(
        tool="query_audit_events", audit_username="operator",
        audit_operation_scope="all", audit_outcome="all",
    )

    result = explorer.execute(intent)

    assert reader.intent == intent
    assert result.observations[0].tool == "query_audit_events"


def test_endpoint_projections_preserve_bounded_pod_targets_for_traffic_traversal() -> None:
    endpoint_slice = _list_projection("EndpointSlice", {
        "metadata": {"name": "api-1", "namespace": "payments"},
        "addressType": "IPv4",
        "ports": [{"name": "http", "port": 8080}],
        "endpoints": [{
            "addresses": ["10.0.0.8"], "conditions": {"ready": True},
            "targetRef": {"kind": "Pod", "namespace": "payments", "name": "api-abc"},
        }],
    })
    endpoints = _list_projection("Endpoints", {
        "metadata": {"name": "api", "namespace": "payments"},
        "subsets": [{
            "addresses": [{
                "ip": "10.0.0.8",
                "targetRef": {"kind": "Pod", "namespace": "payments", "name": "api-abc"},
            }],
            "ports": [{"name": "http", "port": 8080}],
        }],
    })

    assert endpoint_slice["podTargets"] == [
        {"kind": "Pod", "namespace": "payments", "name": "api-abc"}
    ]
    assert endpoints["podTargets"] == [
        {"kind": "Pod", "namespace": "payments", "name": "api-abc"}
    ]


def test_network_policy_projection_preserves_selectors_peers_ports_and_policy_types() -> None:
    projected = _list_projection("NetworkPolicy", {
        "metadata": {
            "name": "allow-frontend", "namespace": "data",
            "labels": {"owner": "platform"},
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": "database"}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{"namespaceSelector": {"matchLabels": {"team": "frontend"}}}],
                "ports": [{"protocol": "TCP", "port": 5432}],
            }],
            "egress": [],
        },
    })

    assert projected["metadata"]["labels"] == {"owner": "platform"}
    assert projected["spec"] == {
        "podSelector": {"matchLabels": {"app": "database"}},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [{
            "from": [{"namespaceSelector": {"matchLabels": {"team": "frontend"}}}],
            "ports": [{"protocol": "TCP", "port": 5432}],
        }],
        "egress": [],
    }


class FakeResource:
    def __init__(self, items):
        self.items = items
        self.calls = []
        self.watch_calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        if "name" in kwargs:
            return self.items[0]
        return SimpleNamespace(items=self.items)

    def watch(self, **kwargs):
        self.watch_calls.append(kwargs)
        watcher = kwargs["watcher"]
        stream_kwargs = {"timeout_seconds": kwargs["timeout"]}
        if kwargs.get("namespace"):
            stream_kwargs["namespace"] = kwargs["namespace"]
        if kwargs.get("label_selector"):
            stream_kwargs["label_selector"] = kwargs["label_selector"]
        if kwargs.get("name"):
            stream_kwargs["field_selector"] = f"metadata.name={kwargs['name']}"
        return watcher.stream(self.get, **stream_kwargs)


class FakeResources:
    def __init__(self, resource, discovered=()):
        self.resource = resource
        self.discovered = discovered
        self.calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        return self.resource

    def search(self, **_kwargs):
        return self.discovered


class FakePagedResource:
    def __init__(self):
        self.calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        if "_continue" not in kwargs:
            return SimpleNamespace(
                items=[FakeObject(name="a")],
                metadata=SimpleNamespace(continue_="next-page"),
            )
        return SimpleNamespace(
            items=[FakeObject(name="b")],
            metadata=SimpleNamespace(continue_=""),
        )


class FakeLargePagedResource:
    def __init__(self, total: int):
        self.total = total
        self.calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        start = int(str(kwargs.get("_continue") or "0"))
        size = int(kwargs["limit"])
        end = min(start + size, self.total)
        items = [FakeObject(name=f"item-{index}") for index in range(start, end)]
        token = str(end) if end < self.total else ""
        return SimpleNamespace(items=items, metadata=SimpleNamespace(continue_=token))


class FakeRouteSearchResource:
    def __init__(self):
        self.calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        page = int(str(kwargs.get("_continue") or "0"))
        start = page * 100
        items = [FakeObject(name=f"route-{index}", namespace="tenant", payload={
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "metadata": {"name": f"route-{index}", "namespace": "tenant"},
            "spec": {
                "host": "maas.apps.example.test" if index == 275 else f"app-{index}.example.test",
                "to": {"kind": "Service", "name": f"service-{index}"},
                "alternateBackends": (
                    [{"kind": "Service", "name": "fallback-service", "weight": 10}]
                    if index == 275 else []
                ),
                "tls": {"termination": "passthrough" if index == 275 else "edge"},
            },
            "status": {},
        }) for index in range(start, min(start + 100, 300))]
        next_token = str(page + 1) if page < 2 else ""
        return SimpleNamespace(items=items, metadata=SimpleNamespace(continue_=next_token))


class FakeCore:
    def read_namespaced_pod_log(self, *args, **kwargs):
        return "token=do-not-leak\nserver started"


class FakeWatch:
    def __init__(self):
        self.calls = []
        self.stopped = False

    def stream(self, operation, **kwargs):
        self.calls.append((operation, kwargs))
        yield {"type": "MODIFIED", "object": FakeObject()}

    def stop(self):
        self.stopped = True


class PreviousLogsMissingCore:
    def __init__(self):
        self.calls = []

    def read_namespaced_pod_log(self, *args, **kwargs):
        self.calls.append(kwargs)
        if kwargs["previous"]:
            error = ApiException(status=400, reason="Bad Request")
            error.body = 'previous terminated container "alertmanager" not found'
            raise error
        return b"current alertmanager log\n"


class ForbiddenLogsCore:
    def read_namespaced_pod_log(self, *args, **kwargs):
        raise ApiException(status=403, reason="Forbidden")


def explorer(resource=None):
    resource = resource or FakeResource([FakeObject()])
    dynamic = SimpleNamespace(resources=FakeResources(resource))
    return KubernetesReadOnlyExplorer(dynamic_client=dynamic, core_api=FakeCore()), resource, dynamic


def test_get_configmap_preserves_configuration_and_redacts_sensitive_keys():
    target, resource, dynamic = explorer()
    result = target.execute(ReadIntent(
        tool="get_resource", api_version="v1", kind="ConfigMap",
        namespace="payments", name="api",
    ))
    assert len(result.observations) == 1
    assert result.observations[0].data["data"] == {
        "UPSTREAM_DNS": "10.0.0.2", "password": "[REDACTED]"
    }
    assert "managedFields" not in result.observations[0].data["metadata"]
    assert dynamic.resources.calls == [{"api_version": "v1", "kind": "ConfigMap"}]
    assert resource.calls == [{"name": "api", "namespace": "payments"}]


def test_get_pod_exposes_mount_wiring_without_secret_contents():
    pod = FakeObject(name="gateway", namespace="maas", payload={
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "gateway", "namespace": "maas"},
        "spec": {
            "containers": [{
                "name": "istio-proxy",
                "volume_mounts": [{
                    "name": "gateway-certs", "mount_path": "/etc/certs", "read_only": True,
                }],
            }],
            "volumes": [{
                "name": "gateway-certs",
                "secret": {"secret_name": "gateway-client-tls", "optional": False},
            }],
        },
    })
    target, _, _ = explorer(FakeResource([pod]))

    result = target.execute(ReadIntent(
        tool="get_resource", api_version="v1", kind="Pod",
        namespace="maas", name="gateway",
    ))

    assert result.observations[0].data["spec"]["volumes"][0]["secret"] == "[REDACTED]"
    assert result.observations[0].data["podpilotMounts"] == [{
        "containerType": "container",
        "container": "istio-proxy",
        "mountPath": "/etc/certs",
        "volume": "gateway-certs",
        "readOnly": True,
        "sourceType": "Secret",
        "sourceName": "gateway-client-tls",
    }]


def test_get_deployment_projects_config_references_without_values():
    deployment = FakeObject(name="authorino", namespace="kuadrant-system", payload={
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "authorino", "namespace": "kuadrant-system"},
        "spec": {"template": {"spec": {"containers": [{
            "name": "authorino",
            "envFrom": [
                {"configMapRef": {"name": "authorino-config"}},
                {"secretRef": {"name": "authorino-credentials"}},
            ],
            "env": [{
                "name": "ISSUER",
                "valueFrom": {"configMapKeyRef": {
                    "name": "authorino-realms", "key": "issuer",
                }},
            }],
        }]}}},
    })
    target, _, _ = explorer(FakeResource([deployment]))

    result = target.execute(ReadIntent(
        tool="get_resource", api_version="apps/v1", kind="Deployment",
        namespace="kuadrant-system", name="authorino",
    ))

    assert result.observations[0].data["podpilotConfigReferences"] == [
        {
            "sourceType": "ConfigMap", "sourceName": "authorino-config",
            "container": "authorino", "mechanism": "container.envFrom",
        },
        {
            "sourceType": "Secret", "sourceName": "authorino-credentials",
            "container": "authorino", "mechanism": "container.envFrom",
        },
        {
            "sourceType": "ConfigMap", "sourceName": "authorino-realms",
            "container": "authorino", "mechanism": "container.env",
        },
    ]
    assert "issuer" not in str(result.observations[0].data["podpilotConfigReferences"])


def test_list_supports_grouped_api_versions_and_enforces_limit():
    target, resource, _ = explorer(FakeResource([FakeObject(name="a"), FakeObject(name="b")]))
    result = target.execute(ReadIntent(
        tool="list_resources", api_version="apps/v1", kind="Deployment",
        namespace="payments", label_selector="app=api", limit=2,
    ))
    assert len(result.observations) == 1
    assert result.observations[0].data["count"] == 2
    assert len(result.observations[0].data["items"]) == 2
    assert resource.calls == [{"limit": 2, "namespace": "payments", "label_selector": "app=api"}]


def test_adaptive_discovery_returns_policy_filtered_resource_coordinates():
    discovered = [
        SimpleNamespace(
            name="authconfigs", group_version="authorino.kuadrant.io/v1beta3",
            kind="AuthConfig", namespaced=True, verbs=("get", "list", "watch"),
            singular_name="authconfig", short_names=(),
        ),
        SimpleNamespace(
            name="secrets", group_version="v1", kind="Secret", namespaced=True,
            verbs=("get", "list", "watch"), singular_name="secret", short_names=(),
        ),
    ]
    dynamic = SimpleNamespace(resources=FakeResources(FakeResource([]), discovered=discovered))
    target = KubernetesReadOnlyExplorer(dynamic_client=dynamic, core_api=FakeCore())

    result = target.execute(ReadIntent(
        tool="discover_resources", discovery_query="Authorino policy", limit=10,
    ))

    resources = result.observations[0].data["resources"]
    assert [item["kind"] for item in resources] == ["AuthConfig"]
    assert resources[0]["verbs"] == ["get", "list", "watch"]


def test_watch_is_bounded_and_projects_events_without_secret_fields():
    resource = FakeResource([])
    watcher = FakeWatch()
    dynamic = SimpleNamespace(resources=FakeResources(resource))
    target = KubernetesReadOnlyExplorer(
        dynamic_client=dynamic, core_api=FakeCore(), watch_factory=lambda: watcher,
    )

    result = target.execute(ReadIntent(
        tool="watch_resources", api_version="v1", kind="ConfigMap",
        namespace="payments", name="api", watch_seconds=4, limit=5,
    ))

    event = result.observations[0].data["events"][0]
    assert event["type"] == "MODIFIED"
    assert event["object"]["metadata"]["name"] == "api"
    assert event["object"]["metadata"]["namespace"] == "payments"
    assert "data" not in event["object"]
    assert watcher.calls[0][1] == {
        "timeout_seconds": 4,
        "namespace": "payments",
        "field_selector": "metadata.name=api",
    }
    assert resource.watch_calls[0]["timeout"] == 4
    assert resource.watch_calls[0]["name"] == "api"
    assert watcher.stopped is True


def test_resource_name_resolves_from_discovery_and_compacts_list_payload():
    resource = FakeResource([FakeObject(payload={
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": "api", "namespace": "payments"},
        "spec": {"host": "api.example.test", "to": {"kind": "Service", "name": "api"}},
        "status": {"ingress": [{"conditions": [{"type": "Admitted", "status": "True"}]}]},
    })])
    descriptor = SimpleNamespace(
        name="routes", group_version="route.openshift.io/v1", kind="Route",
        namespaced=True, verbs=("get", "list"), singular_name="route", short_names=(),
    )
    resources = FakeResources(resource, discovered=(descriptor,))
    dynamic = SimpleNamespace(resources=resources)
    target = KubernetesReadOnlyExplorer(dynamic_client=dynamic, core_api=FakeCore())

    result = target.execute(ReadIntent(
        tool="list_resources", resource="routes", namespace="payments", limit=20,
    ))

    assert resources.calls == [{"api_version": "route.openshift.io/v1", "kind": "Route"}]
    assert result.observations[0].data["kind"] == "Route"
    assert result.observations[0].data["items"][0]["spec"]["host"] == "api.example.test"


def test_route_search_selects_openshift_api_when_knative_route_is_also_installed():
    route = FakeResource([FakeObject(payload={
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": "maas", "namespace": "models"},
        "spec": {"host": "maas.apps.example.test", "tls": {"termination": "passthrough"}},
        "status": {},
    })])
    descriptors = (
        SimpleNamespace(
            name="routes", group_version="route.openshift.io/v1", kind="Route",
            namespaced=True, verbs=("get", "list"), singular_name="route", short_names=(),
        ),
        SimpleNamespace(
            name="routes", group_version="serving.knative.dev/v1", kind="Route",
            namespaced=True, verbs=("get", "list"), singular_name="route", short_names=(),
        ),
    )
    resources = FakeResources(route, discovered=descriptors)
    target = KubernetesReadOnlyExplorer(
        dynamic_client=SimpleNamespace(resources=resources), core_api=FakeCore()
    )
    intent = ReadIntent(
        tool="search_resources",
        resource="routes.route.openshift.io",
        api_version="route.openshift.io/v1",
        kind="Route",
        match_field="spec.host",
        match_value="maas.apps.example.test",
        limit=5,
    )

    target.preflight(intent)
    result = target.execute(intent)

    assert resources.calls == [{"api_version": "route.openshift.io/v1", "kind": "Route"}]
    assert result.observations[0].data["count"] == 1


def test_catalog_client_failure_is_contained_as_safe_explorer_error():
    class FailingCatalog:
        def prompt_entries(self, **_kwargs):
            raise RuntimeError("unexpected dynamic client failure")

    target, _, _ = explorer()
    target._catalog = FailingCatalog()

    with pytest.raises(ReadOnlyExplorerError, match="temporarily unavailable"):
        target.resource_catalog(query="show ingress controllers")


def test_bounded_list_follows_continue_tokens_until_complete():
    resource = FakePagedResource()
    target, _, _ = explorer(resource)

    result = target.execute(ReadIntent(
        tool="list_resources", api_version="v1", kind="Pod", namespace="payments", limit=2,
    ))

    assert result.observations[0].data["count"] == 2
    assert result.observations[0].data["truncated"] is False
    assert resource.calls == [
        {"limit": 2, "namespace": "payments"},
        {"limit": 1, "namespace": "payments", "_continue": "next-page"},
    ]


def test_inventory_can_collect_six_hundred_objects_across_pages() -> None:
    resource = FakeLargePagedResource(total=600)
    target, _, _ = explorer(resource)

    result = target.execute(ReadIntent(
        tool="list_resources", api_version="v1", kind="ConfigMap", limit=600,
    ))

    observation = result.observations[0]
    assert observation.data["count"] == 600
    assert len(observation.data["names"]) == 600
    assert len(observation.data["objects"]) == 600
    assert observation.data["objects"][0] == {
        "name": "item-0", "namespace": "payments",
    }
    assert observation.data["objectListComplete"] is True
    assert len(resource.calls) == 6
    assert all(call["limit"] == 100 for call in resource.calls)


def test_bounded_search_finds_route_host_beyond_inventory_ceiling() -> None:
    resource = FakeRouteSearchResource()
    target, _, _ = explorer(resource)
    target._max_search_scan_objects = 300

    result = target.execute(ReadIntent(
        tool="search_resources",
        api_version="route.openshift.io/v1",
        kind="Route",
        match_field="spec.host",
        match_value="MAAS.APPS.EXAMPLE.TEST",
        limit=5,
    ))

    observation = result.observations[0]
    assert observation.tool == "search_resources"
    assert observation.data["scannedCount"] == 300
    assert observation.data["count"] == 1
    assert observation.data["items"][0]["metadata"]["name"] == "route-275"
    assert observation.data["items"][0]["metadata"]["namespace"] == "tenant"
    assert observation.data["items"][0]["spec"]["tls"]["termination"] == "passthrough"
    assert observation.data["items"][0]["spec"]["alternateBackends"] == [{
        "kind": "Service", "name": "fallback-service", "weight": 10,
    }]
    assert observation.data["searchComplete"] is True


def test_cluster_wide_service_search_matches_spec_type() -> None:
    services = [
        FakeObject(name="internal", namespace="payments", payload={
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "internal", "namespace": "payments"},
            "spec": {"type": "ClusterIP", "ports": [{"port": 8080}]},
            "status": {},
        }),
        FakeObject(name="public", namespace="operators", payload={
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "public", "namespace": "operators"},
            "spec": {
                "type": "NodePort",
                "ports": [{"port": 443, "nodePort": 30443}],
            },
            "status": {},
        }),
    ]
    target, resource, _ = explorer(FakeResource(services))

    result = target.execute(ReadIntent(
        tool="search_resources", api_version="v1", kind="Service",
        match_field="spec.type", match_value="NodePort", limit=20,
    ))

    observation = result.observations[0]
    assert observation.data["scope"] == "cluster"
    assert observation.data["names"] == ["public"]
    assert observation.data["items"][0]["spec"]["type"] == "NodePort"
    assert resource.calls == [{"limit": 100}]


def test_resource_search_traverses_lists_in_field_paths() -> None:
    service = FakeObject(name="public", namespace="operators", payload={
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "public", "namespace": "operators"},
        "spec": {"ports": [{"port": 443, "nodePort": 30443}]},
        "status": {},
    })
    target, _, _ = explorer(FakeResource([service]))

    result = target.execute(ReadIntent(
        tool="search_resources", api_version="v1", kind="Service",
        match_field="spec.ports.nodePort", match_value="30443", limit=20,
    ))

    assert result.observations[0].data["names"] == ["public"]


def test_event_search_preserves_operator_relevant_event_details() -> None:
    event = FakeObject(name="gateway-failed-mount", namespace="openshift-ingress", payload={
        "apiVersion": "v1", "kind": "Event",
        "metadata": {"name": "gateway-failed-mount", "namespace": "openshift-ingress"},
        "type": "Warning", "reason": "FailedMount", "count": 7,
        "message": "MountVolume.SetUp failed for volume gateway-certs",
        "lastTimestamp": "2026-08-26T01:28:00Z",
        "involvedObject": {
            "apiVersion": "v1", "kind": "Pod", "namespace": "openshift-ingress",
            "name": "gateway-1", "uid": "pod-uid-1",
        },
        "source": {"component": "kubelet", "host": "worker-1"},
    })
    target, _, _ = explorer(FakeResource([event]))

    result = target.execute(ReadIntent(
        tool="search_resources", api_version="v1", kind="Event",
        namespace="openshift-ingress", match_field="involvedObject.name",
        match_value="gateway-1", limit=20,
    ))

    item = result.observations[0].data["items"][0]
    assert item["type"] == "Warning"
    assert item["reason"] == "FailedMount"
    assert item["count"] == 7
    assert item["message"] == "MountVolume.SetUp failed for volume gateway-certs"
    assert item["involvedObject"]["name"] == "gateway-1"
    assert item["source"] == {"component": "kubelet", "host": "worker-1"}


def test_pod_list_exposes_compact_exact_log_candidates():
    pod = FakeObject(payload={
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "kube-apiserver-master-0",
            "namespace": "openshift-kube-apiserver",
        },
        "spec": {"containers": [{"name": "kube-apiserver"}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [{
                "name": "kube-apiserver",
                "ready": True,
                "restartCount": 1,
                "state": {"running": {}},
            }],
        },
    })
    target, _, _ = explorer(FakeResource([pod]))

    result = target.execute(ReadIntent(
        tool="list_resources", api_version="v1", kind="Pod",
        namespace="openshift-kube-apiserver", limit=20,
    ))

    assert result.observations[0].data["logCandidates"] == [{
        "namespace": "openshift-kube-apiserver",
        "pod": "kube-apiserver-master-0",
        "containers": ["kube-apiserver"],
        "containerStatuses": [{
            "name": "kube-apiserver", "ready": True, "restartCount": 1,
            "state": {"running": {}},
        }],
        "phase": "Running",
        "ready": True,
        "restartCount": 1,
    }]
    assert result.observations[0].data["logCandidatesTruncated"] is False


def test_compact_list_enforces_payload_budget_with_explicit_truncation():
    objects = [FakeObject(name=f"pod-{index}", payload={
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"pod-{index}", "namespace": "payments",
            "labels": {"diagnostic.example.io/detail": "x" * 500},
        },
        "status": {"phase": "Running"},
    }) for index in range(5)]
    target, _, _ = explorer(FakeResource(objects))
    target._max_payload_bytes = 900

    result = target.execute(ReadIntent(
        tool="list_resources", api_version="v1", kind="Pod",
        namespace="payments", limit=5,
    ))

    assert result.observations[0].data["truncated"] is False
    assert result.observations[0].data["objectListComplete"] is True
    assert result.observations[0].data["detailsTruncated"] is True
    assert result.observations[0].data["names"] == [f"pod-{index}" for index in range(5)]
    assert len(result.observations[0].data["items"]) < 5
    assert "retained all 5 collected Pod names" in result.limitations[0]


def test_logs_are_bounded_and_redacted():
    target, _, _ = explorer()
    result = target.execute(ReadIntent(
        tool="pod_logs", namespace="payments", name="api", container="app"
    ))
    assert "do-not-leak" not in result.observations[0].data["tail"]
    assert "server started" in result.observations[0].data["tail"]


def test_missing_previous_logs_fall_back_to_bounded_current_logs():
    target, _, _ = explorer()
    core = PreviousLogsMissingCore()
    target._core = core
    result = target.execute(ReadIntent(
        tool="pod_logs", namespace="openshift-monitoring", name="alertmanager-main-0",
        container="alertmanager", previous=True,
    ))
    assert [call["previous"] for call in core.calls] == [True, False]
    assert result.observations[0].data["previous"] is False
    assert result.observations[0].data["tail"] == "current alertmanager log\n"
    assert "current" in result.observations[0].summary
    assert "Previous logs were not retained" in result.limitations[0]


def test_log_permission_errors_are_reported_as_authorization_failures():
    target, _, _ = explorer()
    target._core = ForbiddenLogsCore()
    with pytest.raises(ReadOnlyExplorerError, match="OpenShift RBAC denied.*pods/log"):
        target.execute(ReadIntent(
            tool="pod_logs", namespace="payments", name="api", container="app"
        ))


def test_resource_permission_error_names_cluster_identity_action_and_scope():
    class ForbiddenResource:
        def get(self, **_kwargs):
            raise ApiException(status=403, reason="Forbidden")

    target, _, _ = explorer(ForbiddenResource())

    with pytest.raises(
        ReadOnlyExplorerError,
        match=(
            "configured cluster identity permission to list IngressController "
            "at cluster-wide scope"
        ),
    ):
        target.execute(ReadIntent(
            tool="list_resources",
            api_version="operator.openshift.io/v1",
            kind="IngressController",
            limit=20,
        ))


@pytest.mark.parametrize("intent", [
    ReadIntent(tool="get_resource", api_version="v1", kind="Secret", namespace="default", name="x"),
    ReadIntent(tool="get_resource", api_version="apps/v1/extra", kind="Deployment", namespace="default", name="x"),
    ReadIntent(tool="get_resource", api_version="v1", kind="Pod/exec", namespace="default", name="x"),
])
def test_sensitive_or_invalid_targets_are_denied(intent):
    target, _, _ = explorer()
    with pytest.raises(ReadOnlyExplorerError):
        target.execute(intent)
