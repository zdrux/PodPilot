from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_openshift.explorer import KubernetesReadOnlyExplorer, ReadOnlyExplorerError


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


class FakeResource:
    def __init__(self, items):
        self.items = items
        self.calls = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        if "name" in kwargs:
            return self.items[0]
        return SimpleNamespace(items=self.items)


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


class FakeCore:
    def read_namespaced_pod_log(self, *args, **kwargs):
        return "token=do-not-leak\nserver started"


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


def test_compact_list_enforces_payload_budget_with_explicit_truncation():
    objects = [FakeObject(name=f"pod-{index}", payload={
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": f"pod-{index}", "namespace": "payments"},
        "status": {"phase": "Running", "conditions": [{"message": "x" * 500}]},
    }) for index in range(5)]
    target, _, _ = explorer(FakeResource(objects))
    target._max_payload_bytes = 900

    result = target.execute(ReadIntent(
        tool="list_resources", api_version="v1", kind="Pod",
        namespace="payments", limit=5,
    ))

    assert result.observations[0].data["truncated"] is True
    assert len(result.observations[0].data["items"]) < 5
    assert "additional matching data exists" in result.limitations[0]


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
    with pytest.raises(ReadOnlyExplorerError, match="not authorized"):
        target.execute(ReadIntent(
            tool="pod_logs", namespace="payments", name="api", container="app"
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
