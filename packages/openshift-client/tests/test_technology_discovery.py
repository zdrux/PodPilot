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
    assert len(calls) == 2 * len(result["checks"])
    assert all(check["status"] == "partial" for check in result["checks"])


def test_deadline_before_first_list_is_unknown_not_an_empty_success(monkeypatch):
    from podpilot_openshift import technology_discovery
    times = iter([0, 0, 3])
    monkeypatch.setattr(technology_discovery.time, "monotonic", lambda: next(times, 99))
    def forbidden_call(**kwargs):
        raise AssertionError("List must not run after deadline")
    dynamic = SimpleNamespace(resources=SimpleNamespace(get=lambda **kw: SimpleNamespace(get=forbidden_call)))
    result = discover_technologies(dynamic, timeout_seconds=2)
    assert result["status"] == "partial"
    assert result["checks"][0]["status"] == "time_limit"
    assert not any(c["status"] == "read" for c in result["checks"])
