import json
from pathlib import Path

import certifi
import httpx

from podpilot_openshift.alerts import AlertmanagerClient


def test_alertmanager_client_normalizes_alerts(tmp_path: Path, monkeypatch) -> None:
    token_path = tmp_path / "token"
    token_path.write_text("test-token", encoding="utf-8")
    payload = [{
        "fingerprint": "abc123",
        "status": {"state": "suppressed", "silencedBy": ["silence-1"]},
        "labels": {"alertname": "ExampleAlert", "severity": "warning", "namespace": "demo"},
        "annotations": {"summary": "Synthetic alert"},
        "startsAt": "2026-08-23T00:00:00Z",
    }]
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=json.dumps(payload), request=request)
    )
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    client = AlertmanagerClient(
        base_url="https://alertmanager.example",
        token_path=token_path,
        ca_path=Path(certifi.where()),
        max_alerts=10,
    )

    alert = client.fetch().alerts[0]
    assert alert.name == "ExampleAlert"
    assert alert.namespace == "demo"
    assert alert.is_silenced is True
    assert alert.is_inhibited is False


def test_alertmanager_snapshot_reports_when_the_bound_truncates_results(
    tmp_path: Path, monkeypatch
) -> None:
    token_path = tmp_path / "token"
    token_path.write_text("test-token", encoding="utf-8")
    payload = [
        {"fingerprint": str(index), "status": {"state": "active"}, "labels": {}}
        for index in range(3)
    ]
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=json.dumps(payload), request=request)
    )
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    snapshot = AlertmanagerClient(
        base_url="https://alertmanager.example",
        token_path=token_path,
        ca_path=Path(certifi.where()),
        max_alerts=2,
    ).fetch()
    assert len(snapshot.alerts) == 2
    assert snapshot.is_complete is False
