from datetime import datetime, timezone
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
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


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
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        range_seconds=86_400,
    ))

    assert "[3600s]" in source.queries[0]
    assert "reduced to 3600 seconds" in result.limitations[0]


def test_default_log_volume_policy_accepts_three_day_window() -> None:
    source = FakeLogSource()

    result = BoundedLogVolumeReader(source, clock=lambda: NOW).execute(ReadIntent(
        tool="query_metrics", metric="top_log_volume_by_namespace",
        metric_scope="cluster", range_seconds=259_200, limit=10,
    ))

    assert "[259200s]" in source.queries[0]
    assert result.observations[0].data["rangeSeconds"] == 259_200
    assert not any("reduced" in item for item in result.limitations)


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
