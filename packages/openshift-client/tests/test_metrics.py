import json
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
