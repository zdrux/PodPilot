import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from podpilot_openshift.metrics import MonitoringQueryError, ThanosQueryClient


def client(tmp_path: Path, handler, **overrides) -> ThanosQueryClient:
    token = tmp_path / "token"
    token.write_text("fixture-token", encoding="utf-8")
    ca = tmp_path / "ca.crt"
    ca.write_text("fixture-ca", encoding="utf-8")
    return ThanosQueryClient(
        base_url="https://thanos.example.test",
        token_path=token,
        ca_path=ca,
        transport=httpx.MockTransport(handler),
        **overrides,
    )


def test_query_is_authenticated_bounded_and_normalized(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert request.url.path == "/api/v1/query"
        assert request.url.params["query"] == 'up{namespace="demo"}'
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {
                                "namespace": "demo",
                                "instance": "10.0.0.1:8443",
                                "note": "token=do-not-retain",
                            },
                            "value": [1_777_000_000, "0"],
                        },
                        {
                            "metric": {"namespace": "demo", "instance": "second"},
                            "value": [1_777_000_001, "NaN"],
                        },
                    ],
                },
            },
        )

    snapshot = client(tmp_path, handler, max_series=1).query('up{namespace="demo"}')

    assert snapshot.is_complete is False
    assert len(snapshot.samples) == 1
    assert snapshot.samples[0].value == 0
    assert snapshot.samples[0].labels["note"] == "token=[REDACTED]"


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "error", "data": {}},
        {"status": "success", "data": {"resultType": "matrix", "result": []}},
        {"status": "success", "data": {"resultType": "vector", "result": {}}},
    ],
)
def test_query_rejects_unexpected_response_shapes(tmp_path: Path, payload) -> None:
    query_client = client(
        tmp_path,
        lambda request: httpx.Response(200, json=payload),
    )

    with pytest.raises(MonitoringQueryError):
        query_client.query("up")


def test_query_rejects_oversized_response_before_json_parsing(tmp_path: Path) -> None:
    payload = json.dumps({"status": "success", "data": {"resultType": "vector", "result": []}})
    query_client = client(
        tmp_path,
        lambda request: httpx.Response(200, content=payload.encode() + b" " * 200),
        max_response_bytes=64,
    )

    with pytest.raises(MonitoringQueryError, match="more data"):
        query_client.query("up")


def test_query_default_response_ceiling_accepts_payload_larger_than_64_kib(
    tmp_path: Path,
) -> None:
    padding = "x" * 70_000
    query_client = client(
        tmp_path,
        lambda request: httpx.Response(200, json={
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": {"namespace": "demo", "padding": padding},
                    "value": [1_777_000_000, "1"],
                }],
            },
        }),
    )

    snapshot = query_client.query("up")

    assert snapshot.samples[0].value == 1
    assert snapshot.samples[0].labels["padding"].startswith("x")
    assert len(snapshot.samples[0].labels["padding"]) < len(padding)


def test_range_query_is_authenticated_bounded_and_normalized(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer fixture-token"
        assert request.url.path == "/api/v1/query_range"
        assert request.url.params["query"] == "sum(rate(cpu[5m]))"
        assert request.url.params["step"] == "60"
        return httpx.Response(200, json={
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"namespace": "demo", "note": "token=do-not-retain"},
                    "values": [
                        [1_777_000_000, "0.5"],
                        [1_777_000_060, "NaN"],
                        [1_777_000_120, "0.8"],
                    ],
                }],
            },
        })

    start = datetime.fromtimestamp(1_777_000_000, tz=timezone.utc)
    snapshot = client(tmp_path, handler, max_points_per_series=2).query_range(
        "sum(rate(cpu[5m]))",
        start=start,
        end=start + timedelta(minutes=2),
        step_seconds=60,
    )

    assert snapshot.is_complete is False
    assert [point.value for point in snapshot.series[0].points] == [0.5, None]
    assert snapshot.series[0].labels["note"] == "token=[REDACTED]"


def test_remote_query_discovers_route_and_uses_in_memory_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer remote-fixture-token"
        if request.url.host == "api.remote.example":
            assert request.url.path == (
                "/apis/route.openshift.io/v1/namespaces/openshift-monitoring/"
                "routes/thanos-querier"
            )
            return httpx.Response(200, json={
                "spec": {"host": "thanos.apps.remote.example"},
            })
        assert request.url.host == "thanos.apps.remote.example"
        assert request.url.path == "/api/v1/query_range"
        return httpx.Response(200, json={
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        })

    query_client = ThanosQueryClient.for_remote_cluster(
        api_url="https://api.remote.example:6443",
        token="remote-fixture-token",
        api_tls_verify=False,
        transport=httpx.MockTransport(handler),
    )
    start = datetime.fromtimestamp(1_777_000_000, tz=timezone.utc)

    snapshot = query_client.query_range(
        "up", start=start, end=start + timedelta(minutes=1), step_seconds=60,
    )

    assert snapshot.series == ()


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (401, "Kubernetes API rejected"),
        (403, r"denied access to the Thanos Route.*HTTP 403"),
        (404, "does not expose a Thanos Querier Route"),
    ],
)
def test_remote_route_discovery_errors_are_actionable(
    status_code: int, message: str,
) -> None:
    query_client = ThanosQueryClient.for_remote_cluster(
        api_url="https://api.remote.example:6443",
        token="remote-fixture-token",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(status_code, json={"message": "sensitive"})
        ),
    )

    with pytest.raises(MonitoringQueryError, match=message):
        query_client.query("up")


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (401, "rejected the configured bearer token"),
        (403, r"HTTP 403.*cluster-monitoring-view"),
        (404, "expected Thanos API"),
    ],
)
def test_remote_monitoring_http_errors_are_actionable(
    status_code: int, message: str,
) -> None:
    query_client = ThanosQueryClient(
        base_url="https://api.remote.example:6443/proxy",
        token="remote-fixture-token",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(status_code, json={"message": "sensitive"})
        ),
    )

    with pytest.raises(MonitoringQueryError, match=message):
        query_client.query("up")


def test_query_requires_exactly_one_token_source(tmp_path: Path) -> None:
    token_path = tmp_path / "token"

    with pytest.raises(ValueError, match="exactly one"):
        ThanosQueryClient(base_url="https://thanos.example.test")
    with pytest.raises(ValueError, match="exactly one"):
        ThanosQueryClient(
            base_url="https://thanos.example.test",
            token_path=token_path,
            token="duplicate",
        )
