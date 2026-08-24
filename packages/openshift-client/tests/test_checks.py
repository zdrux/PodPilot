from datetime import datetime, timezone
from types import SimpleNamespace

from podpilot_diagnostics.checks import DiagnosticCheckSpec
from podpilot_openshift.checks import KubernetesDiagnosticCheckExecutor
from podpilot_openshift.metrics import MetricSample, MetricSnapshot, MonitoringQueryError


def ns(**values):
    return SimpleNamespace(**values)


class FakeCoreApi:
    def read_namespaced_service(self, name, namespace):
        return ns(
            metadata=ns(name=name),
            spec=ns(
                selector={"app": "check-endpoints"},
                ports=[ns(name="https", port=8443, protocol="TCP")],
            ),
        )

    def list_namespaced_pod(self, namespace, *, label_selector, limit):
        return ns(items=[
            ns(
                metadata=ns(name="target-0", uid="pod-uid", labels={"app": "check-endpoints"}),
                status=ns(
                    conditions=[ns(type="Ready", status="True")],
                    container_statuses=[ns(restart_count=2)],
                ),
            )
        ])

    def list_namespaced_event(self, namespace, *, field_selector, limit):
        return ns(items=[
            ns(
                metadata=ns(
                    name="ready.1",
                    creation_timestamp=datetime(2026, 8, 23, tzinfo=timezone.utc),
                ),
                event_time=None,
                last_timestamp=None,
                reason="Ready",
                message="token=do-not-retain",
            )
        ])


class FakeDiscoveryApi:
    def list_namespaced_endpoint_slice(self, namespace, *, label_selector, limit):
        return ns(items=[ns(endpoints=[ns(conditions=ns(ready=True))])])


class FakeMonitoringSource:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.queries = []

    def query(self, promql):
        self.queries.append(promql)
        if self.fail:
            raise MonitoringQueryError("Synthetic Thanos outage.")
        now = datetime(2026, 8, 23, tzinfo=timezone.utc)
        if promql.startswith("ALERTS"):
            samples = (
                MetricSample(
                    labels={
                        "alertname": "TargetDown",
                        "alertstate": "firing",
                        "namespace": "demo",
                        "service": "check-endpoints",
                    },
                    value=1,
                    observed_at=now,
                ),
            )
        else:
            samples = (
                MetricSample(
                    labels={
                        "namespace": "demo",
                        "service": "check-endpoints",
                        "instance": "10.0.0.10:8443",
                    },
                    value=0,
                    observed_at=now,
                ),
            )
        return MetricSnapshot(samples=samples, collected_at=now, is_complete=True)


def spec(tool_name):
    return DiagnosticCheckSpec(
        id="check-1",
        investigation_id="investigation-1",
        position=1,
        tool_name=tool_name,
        title="Check",
        purpose="Bounded fixture check",
        namespace="demo",
        service_name="check-endpoints",
        service_label="check-endpoints",
        job_name="check-endpoints",
        instance="10.0.0.10:8443",
    )


def test_topology_check_normalizes_service_endpoints_and_pods() -> None:
    executor = KubernetesDiagnosticCheckExecutor(
        core_api=FakeCoreApi(), discovery_api=FakeDiscoveryApi()
    )
    result = executor.run(spec("inspect_service_topology"))

    assert result.status == "succeeded"
    assert "appear ready" in result.summary
    assert len(result.observations) == 3
    assert "app=check-endpoints" in result.observations[0].detail
    assert "1 EndpointSlices with 1 endpoints" in result.observations[1].detail
    assert "1 are Ready" in result.observations[2].detail


def test_event_check_is_bounded_and_redacted() -> None:
    executor = KubernetesDiagnosticCheckExecutor(
        core_api=FakeCoreApi(), discovery_api=FakeDiscoveryApi(), max_events=3
    )
    result = executor.run(spec("inspect_target_events"))

    assert result.status == "succeeded"
    assert len(result.observations) == 1
    assert result.observations[0].detail == "token=[REDACTED]"


def test_monitoring_check_correlates_rule_and_up_without_active_probe() -> None:
    monitoring = FakeMonitoringSource()
    executor = KubernetesDiagnosticCheckExecutor(monitoring_source=monitoring)

    result = executor.run(spec("inspect_monitoring_signal"))

    assert result.status == "succeeded"
    assert "confirms" in result.summary
    assert len(result.observations) == 2
    assert "1 matching firing" in result.observations[0].detail
    assert "1 down" in result.observations[1].detail
    assert monitoring.queries == [
        'ALERTS{alertname="TargetDown",namespace="demo",service="check-endpoints",job="check-endpoints",instance="10.0.0.10:8443"}',
        'up{namespace="demo",service="check-endpoints",job="check-endpoints",instance="10.0.0.10:8443"}',
    ]
    assert any("did not connect" in item for item in result.limitations)


def test_monitoring_check_escapes_alert_labels_and_normalizes_outage() -> None:
    monitoring = FakeMonitoringSource(fail=True)
    raw = spec("inspect_monitoring_signal")
    object.__setattr__(raw, "instance", 'bad"} or vector(1) #')
    executor = KubernetesDiagnosticCheckExecutor(monitoring_source=monitoring)

    result = executor.run(raw)

    assert result.status == "failed"
    assert result.summary == "Synthetic Thanos outage."
    assert '\\"} or vector(1) #' in monitoring.queries[0]
    assert "No target connection" in result.limitations[0]


def test_unregistered_check_fails_without_kubernetes_request() -> None:
    raw = spec("inspect_service_topology")
    object.__setattr__(raw, "tool_name", "arbitrary_shell")
    executor = KubernetesDiagnosticCheckExecutor(
        core_api=FakeCoreApi(), discovery_api=FakeDiscoveryApi()
    )
    result = executor.run(raw)

    assert result.status == "failed"
    assert "not registered" in result.summary
