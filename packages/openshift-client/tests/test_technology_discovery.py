from types import SimpleNamespace

import pytest
from kubernetes.client.exceptions import ApiException

from podpilot_openshift.technology_discovery import discover_technologies, repository_url


def test_loki_api_group_does_not_claim_a_grafana_dashboard_installation():
    def resource_get(*, api_version, kind):
        return SimpleNamespace(get=lambda **_: {"items": [{"metadata": {"name": "lokistacks.loki.grafana.com"}}] if kind == "CustomResourceDefinition" else [], "metadata": {}})
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(get=resource_get)))
    assert [item["id"] for item in result["technologies"]] == ["loki"]


@pytest.mark.parametrize("value,expected", [
    ("git@github.com:org/repo.git", "https://github.com/org/repo"),
    ("ssh://git@github.com/org/repo.git", "https://github.com/org/repo"),
    ("https://github.com/org/repo", "https://github.com/org/repo"),
    ("https://token@github.com/org/repo", None),
    ("https://github.com/org/repo?token=private", None),
    ("file:///etc/password", None), ("http://github.com/org/repo", None),
    ("https://github.com/../repo", None), ("https://github.com:8443/org/repo", None),
])
def test_repository_identity_validation(value, expected):
    assert repository_url(value) == expected


def test_inventory_records_partial_access_endpoints_and_repository_provenance():
    calls = []
    def resource_get(*, api_version, kind):
        assert kind not in {"Secret", "ConfigMap"}
        if kind == "DaemonSet":
            raise ApiException(status=403, reason="secret-server-message")
        def get(**kwargs):
            calls.append((kind, kwargs))
            items = {
                "Service": [{"metadata": {"name": "thanos-querier", "namespace": "openshift-monitoring", "uid": "svc-uid"},
                             "spec": {"ports": [{"name": "https", "port": 9091}]}}],
                "Application": [{"metadata": {"name": "example", "namespace": "argocd", "uid": "app-uid"},
                                 "spec": {"source": {"repoURL": "git@github.com:org/repo.git"},
                                          "sources": [{"repoURL": "https://github.com/org/repo"}]}}],
                "CustomResourceDefinition": [{"metadata": {"name": "widgets.unknown.example"}}],
            }.get(kind, [])
            return {"items": items, "metadata": {}}
        return SimpleNamespace(get=get)
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(get=resource_get)))
    assert result["status"] == "partial"
    assert result["endpoints"][0]["url"] == "https://thanos-querier.openshift-monitoring.svc:9091"
    assert result["endpoints"][0]["verified"] is False
    assert len(result["repositories"]) == 1
    assert result["repositories"][0]["references"][0]["uid"] == "app-uid"
    assert result["api_extensions"] == ["widgets.unknown.example"]
    assert "secret-server-message" not in str(result)
    denied = next(c for c in result["checks"] if c["kind"] == "DaemonSet")
    assert denied["api_version"] == "apps/v1" and denied["verb"] == "list" and denied["http_status"] == 403
    assert all(kwargs["limit"] <= 50 and kwargs["_request_timeout"] <= 5 for _, kwargs in calls)


def test_repeating_pagination_token_is_bounded_and_partial():
    calls = []
    def get(**kwargs):
        calls.append(kwargs)
        return {"items": [], "metadata": {"continue": "repeated"}}
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(
        get=lambda **kwargs: SimpleNamespace(get=get),
    )))
    assert result["status"] == "partial"
    list_checks = [check for check in result["checks"] if check["verb"] == "list"]
    assert len(calls) == 2 * len(list_checks)
    assert all(check["status"] == "partial" for check in list_checks)


def test_deadline_before_first_list_is_unknown_not_an_empty_success(monkeypatch):
    from podpilot_openshift import technology_discovery
    times = iter([0, 0, 3])
    monkeypatch.setattr(technology_discovery.time, "monotonic", lambda: next(times, 99))
    def forbidden_call(**kwargs):
        raise AssertionError("List must not run after deadline")
    dynamic = SimpleNamespace(resources=SimpleNamespace(get=lambda **kw: SimpleNamespace(get=forbidden_call)))
    result = discover_technologies(dynamic, timeout_seconds=2)
    assert result["status"] == "partial"
    assert next(c for c in result["checks"] if c["verb"] == "list")["status"] == "time_limit"
    assert not any(c["status"] == "read" for c in result["checks"])


def test_dynakube_instances_discovered_without_crd_permission_or_pod_labels():
    from podpilot_openshift.discovery import ResourceCatalog
    catalog = ResourceCatalog(lambda: [SimpleNamespace(
        name="dynakubes", group_version="dynatrace.com/v1beta5", kind="DynaKube",
        namespaced=True, verbs=["get", "list"],
    )])
    calls = []
    def resource_get(*, api_version, kind):
        if kind == "CustomResourceDefinition":
            raise ApiException(status=403)
        def get(**kwargs):
            calls.append((api_version, kind, kwargs))
            items = {
                "DynaKube": [{"metadata": {"name": "dynakube", "namespace": "dynatrace", "uid": "cr-1"},
                              "spec": {"token": "must-not-leak", "apiUrl": "https://private.example"},
                              "status": {"phase": "Deploying"}}],
                "Namespace": [{"metadata": {"name": "dynatrace"}}],
                "DaemonSet": [{"metadata": {"name": "agent", "namespace": "dynatrace"},
                               "spec": {"template": {"spec": {"containers": [{"image": "dynatrace/oneagent:1"}]}}}}],
            }.get(kind, [])
            return {"items": items, "metadata": {}}
        return SimpleNamespace(get=get, namespaced=kind != "Namespace")
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(get=resource_get)),
                                   query="dynatrace", catalog=catalog)
    assert calls[0][:2] == ("dynatrace.com/v1beta5", "DynaKube")
    assert {item["kind"] for item in result["objects"]} == {"DynaKube", "Namespace", "DaemonSet"}
    assert result["objects"][0]["evidence_type"] == "custom_resource"
    assert result["technologies"][0]["id"] == "dynatrace"
    assert result["status"] == "partial" and result["absence_supported"] is False
    assert "must-not-leak" not in str(result) and "private.example" not in str(result)
    assert any(kwargs.get("namespace") == "dynatrace" for _, _, kwargs in calls)


def test_unknown_vendor_and_paginated_inventory_reports_truncation():
    from podpilot_openshift.discovery import ResourceCatalog
    catalog = ResourceCatalog(lambda: [SimpleNamespace(
        name="widgets", group_version="newvendor.example/v1", kind="Widget",
        namespaced=True, verbs=["list"],
    )])
    def resource_get(*, api_version, kind):
        return SimpleNamespace(get=lambda **kwargs: {
            "items": [{"metadata": {"name": "one"}}, {"metadata": {"name": "two"}}]
                     if kind == "Widget" else [],
            "metadata": {"continue": "more"} if kind == "Widget" else {},
        })
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(get=resource_get)),
                                   query="newvendor", catalog=catalog, max_objects=2, result_limit=1)
    assert result["objects"][0]["kind"] == "Widget"
    assert result["matched_count"] == 2 and len(result["objects"]) == 1
    assert result["status"] == "partial" and result["absence_supported"] is False
    assert any(c.get("reason") == "result_limit" for c in result["checks"])


def test_empty_inventory_does_not_claim_absence():
    from podpilot_openshift.discovery import ResourceCatalog
    dynamic = SimpleNamespace(resources=SimpleNamespace(
        get=lambda **_: SimpleNamespace(get=lambda **kw: {"items": [], "metadata": {}})))
    result = discover_technologies(dynamic, query="dynatrace", catalog=ResourceCatalog(lambda: []))
    assert result["status"] == "complete"
    assert result["objects"] == [] and result["absence_supported"] is False


def test_namespace_scoped_cr_permission_recovers_from_cluster_wide_denial():
    from podpilot_openshift.discovery import ResourceCatalog
    catalog = ResourceCatalog(lambda: [SimpleNamespace(
        name="dynakubes", group_version="dynatrace.com/v1beta5", kind="DynaKube",
        namespaced=True, verbs=["list"],
    )])
    def resource_get(*, api_version, kind):
        def get(**kwargs):
            if kind == "DynaKube" and not kwargs.get("namespace"):
                raise ApiException(status=403)
            return {"items": [{"metadata": {"name": "dynatrace"}}] if kind == "Namespace" else
                    [{"metadata": {"name": "agent", "namespace": "dynatrace"}}] if kind == "DynaKube" else [],
                    "metadata": {}}
        return SimpleNamespace(get=get, namespaced=kind != "Namespace")
    result = discover_technologies(SimpleNamespace(resources=SimpleNamespace(get=resource_get)),
                                   query="dynatrace", catalog=catalog)
    assert any(item["kind"] == "DynaKube" for item in result["objects"])
    cr_checks = [c for c in result["checks"] if c["kind"] == "DynaKube"]
    assert [c["status"] for c in cr_checks] == ["denied", "read"]
    assert cr_checks[1]["namespace"] == "dynatrace"
    assert result["status"] == "partial"


def test_api_discovery_failure_preserves_namespace_evidence():
    from podpilot_openshift.discovery import ResourceCatalog
    def unavailable():
        raise ApiException(status=503)
    dynamic = SimpleNamespace(resources=SimpleNamespace(get=lambda **coords: SimpleNamespace(
        get=lambda **kw: {"items": [{"metadata": {"name": "dynatrace"}}]
                         if coords["kind"] == "Namespace" else [], "metadata": {}})))
    result = discover_technologies(dynamic, query="dynatrace", catalog=ResourceCatalog(unavailable))
    assert result["objects"][0]["kind"] == "Namespace"
    assert result["checks"][0]["status"] == "unavailable"
    assert result["status"] == "partial"
