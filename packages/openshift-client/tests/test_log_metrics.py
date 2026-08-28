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

    def query_namespace_volume(self, logql: str) -> LogVolumeSnapshot:
        self.queries.append(logql)
        return LogVolumeSnapshot(
            samples=(
                LogVolumeSample(namespace="payments", bytes=4096),
                LogVolumeSample(namespace="catalog", bytes=8192),
            ),
            collected_at=NOW,
            is_complete=True,
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


def test_loki_denial_has_actionable_role_guidance(tmp_path: Path) -> None:
    client = _client(tmp_path, lambda _request: httpx.Response(403))

    with pytest.raises(LogMetricsQueryError, match="cluster-logging-application-view"):
        client.query_namespace_volume("fixed")
