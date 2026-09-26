from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import pytest

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_openshift.log_metrics import (
    BoundedLogVolumeReader,
    LogMetricsQueryError,
    LogVolumeSample,
    LogVolumeSnapshot,
    LokiQueryClient,
    ContainerLogSnapshot, ContainerLogEntry,
    container_log_tenant,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("namespace,tenant", [
    ("openshift-machine-api", "infrastructure"), ("openshift", "infrastructure"),
    ("kube-system", "infrastructure"), ("default", "infrastructure"),
    ("payments", "application"),
])
def test_namespace_log_routing(namespace, tenant):
    assert container_log_tenant(namespace) == tenant


def retained_intent(**kwargs):
    return ReadIntent(tool="pod_logs", namespace="openshift-machine-api", name="controller",
                      container="manager", log_backend="loki", **kwargs)


def routed_client(handler):
    return LokiQueryClient(base_url="https://logs.example/api/logs/v1/application", token="fixture",
                           transport=httpx.MockTransport(handler))


def log_response(values=()):
    return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams",
        "result": [{"stream": {}, "values": list(values)}] if values else []}})


def test_historical_scaling_search_reaches_twenty_hour_old_activity_and_marks_busy_slices():
    requests = []
    old_time = NOW - timedelta(hours=20, minutes=15)
    old_stamp = str(int(old_time.timestamp() * 1e9))
    def handler(request):
        requests.append(request)
        assert "/infrastructure/" in request.url.path
        assert "scale" in request.url.params["query"] and "|~" in request.url.params["query"]
        start, end = int(request.url.params["start"]), int(request.url.params["end"])
        if start <= int(old_stamp) <= end:
            return log_response([[old_stamp, "scale-down: removing node worker-3 token=secret-value"]])
        # A busy newest window must not crowd out the historical slice.
        if end == int(NOW.timestamp() * 1e9):
            return log_response([[str(end-i), f"scaling status {i}"] for i in range(int(request.url.params["limit"]))])
        return log_response()
    client = routed_client(handler)
    result = BoundedLogVolumeReader(client, clock=lambda: NOW).container_logs(
        retained_intent(range_seconds=86400, log_activity="node_scaling"))
    data = result.observations[0].data
    assert len(requests) == 12
    assert "worker-3" in data["tail"] and "secret-value" not in str(result)
    assert data["log_coverage"]["partial"] is True
    assert len(data["log_coverage"]["windows"]) == 12
    assert client._tenant == "application" and client._timeout_seconds == 90
    assert all(request.headers["authorization"] == "Bearer fixture" for request in requests)


def test_empty_primary_falls_back_with_separate_provenance():
    requests = []
    def handler(request):
        requests.append(request)
        if "/infrastructure/" in request.url.path:
            return log_response()
        return log_response([[str(int(NOW.timestamp()*1e9)), "custom forwarded controller log"]])
    result = BoundedLogVolumeReader(routed_client(handler), clock=lambda: NOW).container_logs(retained_intent())
    assert len(requests) == 2
    assert [o.data["tenant"] for o in result.observations] == ["infrastructure", "application"]
    assert result.observations[1].data["log_coverage"]["selection"] == "empty_primary_fallback"
    assert "custom forwarded" in result.observations[1].data["tail"]


@pytest.mark.parametrize("routing,expected_calls", [("auto", 1), ("check_both", 2)])
def test_tenant_denial_is_visible_and_never_changes_credentials(routing, expected_calls):
    requests = []
    def handler(request):
        requests.append(request)
        if "/infrastructure/" in request.url.path:
            return httpx.Response(403)
        return log_response([[str(int(NOW.timestamp()*1e9)), "application evidence"]])
    result = BoundedLogVolumeReader(routed_client(handler), clock=lambda: NOW).container_logs(
        retained_intent(log_routing=routing))
    assert len(requests) == expected_calls
    assert result.observations[0].data["log_coverage"]["failure"] == "forbidden"
    assert result.observations[0].data["log_coverage"]["partial"] is True
    assert "403" in " ".join(result.limitations)
    assert all(r.headers["authorization"] == "Bearer fixture" for r in requests)


def test_both_tenants_share_budgets_and_retain_tenant_identity():
    def handler(request):
        count = int(request.url.params["limit"])
        stamp = int(request.url.params["end"])
        return log_response([[str(stamp-i), "x"*1900] for i in range(count)])
    source = routed_client(handler)
    source._max_response_bytes = 1024 * 1024
    result = BoundedLogVolumeReader(source, clock=lambda: NOW).container_logs(
        retained_intent(log_routing="check_both", range_seconds=86400))
    assert len(result.observations) == 2
    assert all(o.data["entries"] for o in result.observations)
    assert sum(len(o.data["tail"].encode()) for o in result.observations) <= 61440
    assert all(o.data["log_coverage"]["partial"] for o in result.observations)
    assert sum(len(o.data["log_coverage"]["windows"]) for o in result.observations) <= 24


def test_registered_filter_rejects_arbitrary_patterns_and_kubernetes_usage():
    with pytest.raises(ValueError):
        retained_intent(log_activity='.* | json')
    with pytest.raises(ValueError):
        ReadIntent(tool="pod_logs", log_activity="node_scaling")
    with pytest.raises(ValueError):
        ReadIntent(tool="query_metrics", log_routing="check_both")


def test_direct_loki_endpoint_uses_selected_tenant_header():
    def handler(request):
        assert request.headers["X-Scope-OrgID"] == "infrastructure"
        return log_response([[str(int(NOW.timestamp()*1e9)), "node log"]])
    source = LokiQueryClient(base_url="https://logs.example", token="fixture",
                            transport=httpx.MockTransport(handler))
    result = BoundedLogVolumeReader(source, clock=lambda: NOW).container_logs(retained_intent())
    assert result.observations[0].data["tenant"] == "infrastructure"


def test_display_retains_latest_bounded_lines_without_history_slicing():
    requests = []
    def handler(request):
        requests.append(request)
        assert int(request.url.params["limit"]) == 10
        assert request.url.params["direction"] == "backward"
        stamp = int(NOW.timestamp()*1e9)
        return log_response([[str(stamp-i*10**9), f"line {i}"] for i in range(10)])
    result = BoundedLogVolumeReader(routed_client(handler), clock=lambda: NOW).container_logs(
        retained_intent(range_seconds=86400, log_mode="display", tail_lines=10))
    assert len(requests) == 1 and len(result.observations[0].data["entries"]) == 10
    assert result.observations[0].data["log_coverage"]["partial"] is True


def test_incident_history_uses_shared_namespace_routing():
    from types import SimpleNamespace
    from podpilot_openshift.incidents import IncidentReader
    calls = []
    class Source:
        def for_tenant(self, tenant):
            calls.append(tenant)
            return self
        def query_container_logs(self, **kwargs):
            return SimpleNamespace(entries=(), is_complete=True)
    reader = IncidentReader("https://api.example", "fixture", namespaces=["payments"],
                            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    reader.loki = Source()
    try:
        result = reader._collect_loki_logs("payments", "worker", "app")
        assert calls == ["application"]
        assert result["tenant"] == "application"
        assert result["mechanism"] == "loki-application-query"
    finally:
        reader.close()


def test_remote_tenant_routing_preserves_discovery_and_fresh_credential_provider():
    requests, tokens = [], []
    def token():
        tokens.append(True)
        return "delegated-fixture"
    def handler(request):
        requests.append(request)
        if request.url.host == "api.example":
            return httpx.Response(200, json={"spec": {"host": "logs.example"}})
        assert "/infrastructure/" in request.url.path
        return log_response([[str(int(NOW.timestamp()*1e9)), "controller output"]])
    client = LokiQueryClient.for_remote_cluster(api_url="https://api.example", token_provider=token,
                                               transport=httpx.MockTransport(handler))
    result = BoundedLogVolumeReader(client, clock=lambda: NOW).container_logs(retained_intent())
    assert result.observations[0].data["tenant"] == "infrastructure"
    assert len(tokens) == 1 and len(requests) == 2
    assert client._tenant == "application"


def test_deadline_stops_history_with_explicit_partial_coverage(monkeypatch):
    ticks = iter([0, 0, 31])
    monkeypatch.setattr("podpilot_openshift.log_metrics.time.monotonic", lambda: next(ticks))
    from types import SimpleNamespace
    source = SimpleNamespace(query_container_logs=lambda **kw: ContainerLogSnapshot(
        entries=(ContainerLogEntry(str(int(kw["end"].timestamp()*1e9)), "evidence"),),
        collected_at=NOW, is_complete=True))
    intent = ReadIntent(tool="pod_logs", namespace="payments", name="api", container="app",
                        log_backend="loki", range_seconds=86400)
    result = BoundedLogVolumeReader(source, clock=lambda: NOW).container_logs(intent)
    coverage = result.observations[0].data["log_coverage"]
    assert coverage["partial"] and len(coverage["windows"]) == 1


def test_retained_log_tool_preserves_times_redacts_and_rejects_unbounded_scope():
    from types import SimpleNamespace
    def logs(**kwargs):
        assert kwargs["namespace"] == "payments" and kwargs["container"] == "app"
        assert kwargs["limit"] == 200
        assert (kwargs["end"] - kwargs["start"]).total_seconds() == 3600
        return ContainerLogSnapshot(entries=(ContainerLogEntry(timestamp_ns=str(int(NOW.timestamp() * 1e9)),
            line='{"message":"ERROR token=do-not-keep", "password":"also-secret"}'),), collected_at=NOW, is_complete=True)
    reader = BoundedLogVolumeReader(SimpleNamespace(query_container_logs=logs), clock=lambda: NOW)
    result = reader.container_logs(ReadIntent(tool="pod_logs", namespace="payments", name="worker", container="app", log_backend="loki", limit=1000))
    assert result.observations[0].data["entries"][0]["timestamp"] == NOW.isoformat()
    assert "do-not-keep" not in str(result) and "also-secret" not in str(result)
    assert "without UID" in " ".join(result.limitations)
    with pytest.raises(ValueError):
        ReadIntent(tool="pod_logs", namespace="payments", log_backend="loki")
    with pytest.raises(ValueError):
        ReadIntent(tool="pod_logs", namespace="payments", name="worker", container="app", log_backend="loki", range_seconds=86401)


def test_loki_endpoint_probe_is_bounded_and_checks_protocol() -> None:
    def handler(request):
        assert request.url.path.endswith("/loki/api/v1/labels")
        assert int(request.url.params["end"]) - int(request.url.params["start"]) <= 61 * 10**9
        return httpx.Response(200, json={"status": "success", "data": []})
    source = LokiQueryClient(base_url="https://loki.example.test", token="fixture", transport=httpx.MockTransport(handler))
    assert source.endpoint_status()["verified"] is True
    source = LokiQueryClient(base_url="https://loki.example.test", token="fixture", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": []})))
    assert source.endpoint_status()["verified"] is False


class FakeLogSource:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query_log_volume(self, logql: str) -> LogVolumeSnapshot:
        self.queries.append(logql)
        return LogVolumeSnapshot(
            samples=(
                LogVolumeSample(namespace="payments", bytes=4096),
                LogVolumeSample(namespace="catalog", bytes=8192),
            ),
            collected_at=NOW,
            is_complete=True,
        )


class ScopedLogSource:
    def __init__(self, *samples: LogVolumeSample) -> None:
        self.queries: list[str] = []
        self.samples = samples

    def query_log_volume(self, logql: str) -> LogVolumeSnapshot:
        self.queries.append(logql)
        return LogVolumeSnapshot(
            samples=self.samples, collected_at=NOW, is_complete=True,
        )


def test_reader_uses_server_owned_logql_and_returns_only_aggregates() -> None:
    source = FakeLogSource()
    reader = BoundedLogVolumeReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        metric_operation="rank",
        metric_group_by=["namespace"],
        range_seconds=3600,
        limit=10,
    ))

    assert source.queries == [
        'topk(10, sum by (kubernetes_namespace_name) '
        '(bytes_over_time({log_type="application"}[3600s])))'
    ]
    observation = result.observations[0]
    assert observation.source == "loki:application/query/top_log_volume_by_namespace"
    assert observation.data["ranking"][0] == {
        "labels": {"namespace": "catalog"},
        "current": 8192,
        "average": 8192 / 3600,
        "maximum": None,
    }
    assert "logql" not in observation.data
    assert "lines" not in observation.data


def test_reader_caps_requested_period() -> None:
    source = FakeLogSource()
    reader = BoundedLogVolumeReader(
        source, max_range_seconds=3600, clock=lambda: NOW,
    )

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="application_log_volume",
        metric_scope="cluster",
        metric_operation="rank",
        metric_group_by=["namespace"],
        range_seconds=86_400,
    ))

    assert "[3600s]" in source.queries[0]
    assert "reduced to 3600 seconds" in result.limitations[0]


def test_default_log_volume_policy_accepts_three_day_window() -> None:
    source = FakeLogSource()

    result = BoundedLogVolumeReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="cluster", metric_operation="rank",
        metric_group_by=["namespace"], range_seconds=259_200, limit=10,
    ))

    assert "[259200s]" in source.queries[0]
    assert result.observations[0].data["rangeSeconds"] == 259_200
    assert not any("reduced" in item for item in result.limitations)


def test_reader_returns_ungrouped_cluster_total() -> None:
    source = ScopedLogSource(LogVolumeSample(bytes=12_345))

    result = BoundedLogVolumeReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="cluster", range_seconds=3600,
    ))

    assert source.queries == [
        'sum(bytes_over_time({log_type="application"}[3600s]))'
    ]
    assert result.observations[0].data["ranking"][0]["current"] == 12_345


def test_reader_ranks_pods_within_one_namespace() -> None:
    source = ScopedLogSource(
        LogVolumeSample(bytes=4096, namespace="payments", pod="api-1"),
        LogVolumeSample(bytes=8192, namespace="payments", pod="worker-1"),
    )

    result = BoundedLogVolumeReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="namespace", namespace="payments",
        metric_operation="rank", metric_group_by=["pod"],
        range_seconds=300, limit=5,
    ))

    assert source.queries == [
        'topk(5, sum by (kubernetes_pod_name) '
        '(bytes_over_time({log_type="application",'
        'kubernetes_namespace_name="payments"}[300s])))'
    ]
    observation = result.observations[0]
    assert observation.data["groupBy"] == ["pod"]
    assert observation.data["ranking"][0]["labels"] == {
        "namespace": "payments", "pod": "worker-1",
    }


def test_reader_ranks_pods_and_nodes_across_cluster() -> None:
    pod_source = ScopedLogSource(LogVolumeSample(
        bytes=2048, namespace="payments", pod="api-1",
    ))
    node_source = ScopedLogSource(LogVolumeSample(bytes=1024, node="worker-0"))
    reader = BoundedLogVolumeReader(pod_source, clock=lambda: NOW)

    pod_result = reader.execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="cluster", metric_operation="rank",
        metric_group_by=["namespace", "pod"], range_seconds=300,
    ))
    node_result = BoundedLogVolumeReader(node_source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="cluster", metric_operation="rank",
        metric_group_by=["node"], range_seconds=300,
    ))

    assert "sum by (kubernetes_namespace_name, kubernetes_pod_name)" in pod_source.queries[0]
    assert pod_result.observations[0].data["ranking"][0]["labels"]["pod"] == "api-1"
    assert "sum by (kubernetes_host)" in node_source.queries[0]
    assert node_result.observations[0].data["ranking"][0]["labels"] == {
        "node": "worker-0",
    }


@pytest.mark.parametrize(("scope", "namespace", "name", "selector", "labels"), [
    (
        "namespace", "payments", None,
        'kubernetes_namespace_name="payments"', {"namespace": "payments"},
    ),
    (
        "pod", "payments", "api-1",
        'kubernetes_pod_name="api-1"', {"namespace": "payments", "pod": "api-1"},
    ),
    (
        "node", None, "worker-0",
        'kubernetes_host="worker-0"', {"node": "worker-0"},
    ),
])
def test_reader_reads_exact_log_volume_target(
    scope: str, namespace: str | None, name: str | None,
    selector: str, labels: dict[str, str],
) -> None:
    source = ScopedLogSource(LogVolumeSample(bytes=1234))

    result = BoundedLogVolumeReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope=scope, namespace=namespace, name=name, range_seconds=300,
    ))

    assert source.queries[0].startswith("sum(bytes_over_time(")
    assert selector in source.queries[0]
    assert result.observations[0].data["ranking"][0]["labels"] == labels


def _client(tmp_path: Path, handler, **overrides) -> LokiQueryClient:
    token = tmp_path / "token"
    token.write_text("fixture-token", encoding="utf-8")
    ca = tmp_path / "ca.crt"
    ca.write_text("fixture-ca", encoding="utf-8")
    return LokiQueryClient(
        base_url="https://logging.example.test/api/logs/v1/application",
        token_path=token,
        ca_path=ca,
        transport=httpx.MockTransport(handler),
        **overrides,
    )


def test_loki_client_authenticates_bounds_and_normalizes(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert request.url.path == "/api/logs/v1/application/loki/api/v1/query"
        return httpx.Response(200, json={
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"kubernetes_namespace_name": "payments"},
                        "value": [1_777_000_000, "1234"],
                    },
                    {
                        "metric": {"kubernetes_namespace_name": "ignored"},
                        "value": [1_777_000_000, "99"],
                    },
                ],
            },
        })

    snapshot = _client(tmp_path, handler, max_series=1).query_namespace_volume("fixed")

    assert snapshot.is_complete is False
    assert snapshot.samples == (LogVolumeSample(namespace="payments", bytes=1234),)


def test_loki_client_normalizes_pod_and_node_dimensions(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": {
                        "kubernetes_namespace_name": "payments",
                        "kubernetes_pod_name": "api-1",
                        "kubernetes_host": "worker-0",
                    },
                    "value": [1_777_000_000, "1234"],
                }],
            },
        })

    snapshot = _client(tmp_path, handler).query_log_volume("fixed")

    assert snapshot.samples == (LogVolumeSample(
        bytes=1234, namespace="payments", pod="api-1", node="worker-0",
    ),)


def test_loki_client_reads_only_exact_bounded_container_history(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/logs/v1/infrastructure/loki/api/v1/query_range"
        assert request.url.params["query"] == (
            '{kubernetes_namespace_name="openshift-etcd",'
            'kubernetes_pod_name="etcd-0",kubernetes_container_name="etcd"}'
        )
        assert request.url.params["limit"] == "2"
        assert request.url.params["direction"] == "backward"
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "streams", "result": [{"stream": {}, "values": [
                ["1", "older"], ["2", "newer"],
            ]}]},
        })

    snapshot = _client(tmp_path, handler, tenant="infrastructure").query_container_logs(
        namespace="openshift-etcd", pod="etcd-0", container="etcd",
        start=NOW, end=NOW.replace(hour=13), limit=2,
    )

    assert [entry.line for entry in snapshot.entries] == ["newer", "older"]
    assert snapshot.is_complete is False


def test_loki_container_history_rejects_untrusted_coordinates_before_request(tmp_path: Path) -> None:
    calls = []
    client = _client(tmp_path, lambda request: calls.append(request), tenant="infrastructure")

    with pytest.raises(LogMetricsQueryError, match="exact Kubernetes resource names"):
        client.query_container_logs(
            namespace='openshift-etcd"} |= "secret"', pod="etcd-0", container="etcd",
            start=NOW, end=NOW.replace(hour=13), limit=100,
        )

    assert calls == []


def test_remote_client_discovers_standard_lokistack_route() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.remote.example":
            assert request.url.path.endswith(
                "/namespaces/openshift-logging/routes/logging-loki"
            )
            return httpx.Response(200, json={"spec": {"host": "logs.apps.remote.example"}})
        assert request.url.path == "/api/logs/v1/application/loki/api/v1/query"
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "vector", "result": []},
        })

    client = LokiQueryClient.for_remote_cluster(
        api_url="https://api.remote.example:6443",
        token="remote-token",
        api_tls_verify=False,
        transport=httpx.MockTransport(handler),
    )

    assert client._route_discovery_tls_verify is False
    assert client._tls_verify is False
    assert client.query_namespace_volume("fixed").samples == ()


def test_loki_client_resolves_a_fresh_bearer_token_for_each_request() -> None:
    supplied = iter(("delegated-one", "delegated-two"))
    observed: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers["authorization"])
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "vector", "result": []},
        })

    client = LokiQueryClient(
        base_url="https://logs.example.test/api/logs/v1/application",
        token_provider=lambda: next(supplied),
        transport=httpx.MockTransport(handler),
    )

    client.query_log_volume("fixed")
    client.query_log_volume("fixed")

    assert observed == ["Bearer delegated-one", "Bearer delegated-two"]


def test_loki_denial_has_actionable_role_guidance(tmp_path: Path) -> None:
    client = _client(tmp_path, lambda _request: httpx.Response(403))

    with pytest.raises(
        LogMetricsQueryError,
        match=r"application-log analytics access \(HTTP 403\).*cluster-logging-application-view",
    ):
        client.query_namespace_volume("fixed")


def test_infrastructure_loki_denial_names_required_role(tmp_path: Path) -> None:
    client = _client(
        tmp_path, lambda _request: httpx.Response(403), tenant="infrastructure",
    )

    with pytest.raises(
        LogMetricsQueryError,
        match=r"infrastructure-log access \(HTTP 403\).*cluster-logging-infrastructure-view",
    ):
        client.query_container_logs(
            namespace="openshift-etcd", pod="etcd-0", container="etcd",
            start=NOW, end=NOW.replace(hour=13), limit=100,
        )


def test_remote_loki_route_denial_preserves_http_403() -> None:
    client = LokiQueryClient.for_remote_cluster(
        api_url="https://api.remote.example:6443",
        token="remote-token",
        transport=httpx.MockTransport(lambda _request: httpx.Response(403)),
    )

    with pytest.raises(LogMetricsQueryError, match=r"LokiStack Route \(HTTP 403\)"):
        client.query_namespace_volume("fixed")


def test_loki_timeout_reports_configured_deadline(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow fixture", request=request)

    client = _client(tmp_path, handler, timeout_seconds=17)

    with pytest.raises(LogMetricsQueryError, match="configured 17-second timeout"):
        client.query_namespace_volume("fixed")


def test_loki_tls_verification_failure_preserves_category(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain",
            request=request,
        )

    client = _client(tmp_path, handler)

    with pytest.raises(
        LogMetricsQueryError, match="TLS certificate verification failed",
    ) as raised:
        client.query_namespace_volume("fixed")

    assert raised.value.failure_category == "tls_verification_failed"
