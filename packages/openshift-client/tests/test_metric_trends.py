from datetime import datetime, timezone

import pytest

from podpilot_diagnostics.adhoc import ReadIntent
from podpilot_openshift.metric_trends import BoundedMetricTrendReader
from podpilot_openshift.metrics import MetricPoint, MetricRange, MetricSeries


NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


class FakeRangeSource:
    def __init__(self, series=None) -> None:
        self.calls = []
        self.series = series or (MetricSeries(labels={}, points=(
            MetricPoint(NOW, 0.2),
            MetricPoint(NOW, 0.5),
        )),)

    def query_range(self, promql, *, start, end, step_seconds):
        self.calls.append({
            "promql": promql, "start": start, "end": end, "step_seconds": step_seconds,
        })
        return MetricRange(
            series=self.series,
            collected_at=NOW,
            is_complete=True,
        )


def test_pod_cpu_trend_uses_server_owned_query_and_statistics() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="cpu_usage",
        metric_scope="pod",
        namespace="payments",
        name="api-7d9",
        range_seconds=21_600,
        step_seconds=300,
    ))

    call = source.calls[0]
    assert call["promql"] == (
        'sum(rate(container_cpu_usage_seconds_total{namespace="payments",pod="api-7d9",'
        'container!="",container!="POD",image!=""}[900s]))'
    )
    assert call["step_seconds"] == 300
    observation = result.observations[0]
    assert observation.data["unit"] == "cores"
    assert observation.data["statistics"] == {
        "minimum": 0.2,
        "maximum": 0.5,
        "average": 0.35,
        "current": 0.5,
        "trend": "increasing",
    }
    assert "promql" not in observation.data


def test_metric_resolution_is_increased_to_bound_points() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(
        source, max_points_per_series=100, clock=lambda: NOW,
    )

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="memory_working_set",
        metric_scope="namespace",
        namespace="payments",
        range_seconds=86_400,
        step_seconds=60,
    ))

    assert source.calls[0]["step_seconds"] == 873
    assert "increased to 873 seconds" in result.limitations[0]


def test_pvc_usage_uses_exact_namespace_and_claim() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="persistent_volume_usage",
        metric_scope="persistent_volume_claim",
        namespace="payments",
        name="database-data",
    ))

    assert source.calls[0]["promql"] == (
        '100 * sum(kubelet_volume_stats_used_bytes{namespace="payments",'
        'persistentvolumeclaim="database-data"}) / '
        'clamp_min(sum(kubelet_volume_stats_capacity_bytes{namespace="payments",'
        'persistentvolumeclaim="database-data"}), 1)'
    )


@pytest.mark.parametrize(("metric", "needle"), [
    ("cpu_requests", "kube_pod_container_resource_requests"),
    ("cpu_limits", "kube_pod_container_resource_limits"),
    ("cpu_throttling", "container_cpu_cfs_throttled_periods_total"),
    ("memory_working_set", "container_memory_working_set_bytes"),
    ("memory_requests", 'resource="memory",unit="byte"'),
    ("memory_limits", "kube_pod_container_resource_limits"),
    ("network_receive", "container_network_receive_bytes_total"),
    ("network_transmit", "container_network_transmit_bytes_total"),
    ("container_restarts", "kube_pod_container_status_restarts_total"),
    ("pod_readiness", "kube_pod_status_ready"),
])
def test_registered_pod_and_namespace_templates_are_server_owned(metric, needle) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric=metric,
        metric_scope="namespace",
        namespace="payments",
    ))

    assert needle in source.calls[0]["promql"]
    assert 'namespace="payments"' in source.calls[0]["promql"]


def test_deployment_scope_joins_replicaset_and_pod_ownership() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="cpu_usage",
        metric_scope="deployment",
        namespace="payments",
        name="api",
    ))

    query = source.calls[0]["promql"]
    assert "kube_pod_owner" in query
    assert "kube_replicaset_owner" in query
    assert 'owner_kind="Deployment",owner_name="api"' in query
    assert "on(namespace, pod)" in query


def test_node_top_cpu_ranks_monitored_pods() -> None:
    source = FakeRangeSource(series=(
        MetricSeries(labels={"namespace": "payments", "pod": "api-1", "container": "api"}, points=(
            MetricPoint(NOW, 0.9),
        )),
        MetricSeries(labels={"namespace": "logging", "pod": "collector-1", "container": "collector"}, points=(
            MetricPoint(NOW, 0.4),
        )),
    ))
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="top_cpu_consumers",
        metric_scope="node",
        name="worker-2",
    ))

    query = source.calls[0]["promql"]
    assert "topk(20" in query
    assert 'kube_pod_info{node="worker-2"}' in query
    assert result.observations[0].data["ranking"][0]["labels"]["pod"] == "api-1"
    assert result.observations[0].data["ranking"][0]["current"] == 0.9


def test_node_top_memory_uses_working_set_not_host_process_metrics() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="top_memory_consumers",
        metric_scope="node",
        name="worker-2",
    ))

    query = source.calls[0]["promql"]
    assert "topk(20" in query
    assert "container_memory_working_set_bytes" in query
    assert "process" not in query


@pytest.mark.parametrize(
    ("metric", "metric_name"),
    [
        ("top_cpu_consumers", "container_cpu_usage_seconds_total"),
        ("top_memory_consumers", "container_memory_working_set_bytes"),
    ],
)
def test_namespace_top_consumers_are_ranked_within_exact_namespace(
    metric: str, metric_name: str,
) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric=metric,
        metric_scope="namespace",
        namespace="openshift-logging",
    ))

    query = source.calls[0]["promql"]
    assert query.startswith("topk(20")
    assert metric_name in query
    assert 'namespace="openshift-logging"' in query
    assert "sum by (namespace, pod)" in query


def test_cluster_top_cpu_honors_limit_and_aggregates_by_pod() -> None:
    source = FakeRangeSource(series=tuple(
        MetricSeries(
            labels={"namespace": "payments", "pod": f"api-{index}"},
            points=(MetricPoint(NOW, float(10 - index)),),
        )
        for index in range(7)
    ))
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    result = reader.execute(ReadIntent(
        tool="query_metrics",
        metric="top_cpu_consumers",
        metric_scope="cluster",
        limit=5,
    ))

    query = source.calls[0]["promql"]
    assert query.startswith("topk(5")
    assert "sum by (namespace, pod)" in query
    assert "container" not in query.split("sum by", 1)[1].split(")", 1)[0]
    observation = result.observations[0]
    assert observation.data["scope"] == "cluster"
    assert observation.data["limit"] == 5
    assert len(observation.data["ranking"]) == 5


def test_deployment_top_consumers_use_owner_membership() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="top_cpu_consumers",
        metric_scope="deployment",
        namespace="payments",
        name="api",
    ))

    query = source.calls[0]["promql"]
    assert "topk(20" in query
    assert "kube_pod_owner" in query
    assert 'owner_kind="Deployment",owner_name="api"' in query


@pytest.mark.parametrize(("metric", "needles"), [
    ("node_cpu_utilization", ("node_cpu_seconds_total", 'node_uname_info{nodename="worker-2"}')),
    ("node_memory_utilization", ("node_memory_MemAvailable_bytes", "node_memory_MemTotal_bytes")),
])
def test_overall_node_utilization_uses_node_exporter_metrics(metric, needles) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric=metric,
        metric_scope="node",
        name="worker-2",
    ))

    query = source.calls[0]["promql"]
    assert all(needle in query for needle in needles)


@pytest.mark.parametrize(("metric", "needle"), [
    ("node_cpu_utilization", "avg by (nodename)"),
    ("node_memory_utilization", "sum by (nodename)"),
])
def test_node_role_utilization_joins_worker_role_and_groups_by_node(metric, needle) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric=metric,
        metric_scope="node_role",
        name="worker",
    ))

    query = source.calls[0]["promql"]
    assert needle in query
    assert 'kube_node_role{role="worker"}' in query
    assert "label_replace(" in query


@pytest.mark.parametrize(("metric", "needle"), [
    ("node_cpu_utilization", "avg by (nodename)"),
    ("node_memory_utilization", "sum by (nodename)"),
])
def test_cluster_node_utilization_ranking_uses_topk_grouped_by_node(metric, needle) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics", metric=metric, metric_scope="cluster",
        metric_operation="rank", metric_group_by=["node"], limit=5,
    ))

    query = source.calls[0]["promql"]
    assert query.startswith("topk(5, 100 *")
    assert needle in query
    assert "kube_node_role" not in query


@pytest.mark.parametrize("kind", ["StatefulSet", "DaemonSet", "Job"])
def test_workload_scope_joins_direct_controller_owned_pods(kind) -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="cpu_usage",
        metric_scope="workload",
        kind=kind,
        namespace="payments",
        name="worker",
    ))

    query = source.calls[0]["promql"]
    assert "kube_pod_owner" in query
    assert f'owner_kind="{kind}"' in query
    assert 'owner_name="worker"' in query


def test_namespace_cpu_can_be_grouped_by_pod_and_container() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="cpu_usage",
        metric_scope="namespace",
        namespace="payments",
        metric_group_by=["pod", "container"],
    ))

    query = source.calls[0]["promql"]
    assert "sum by (pod, container)" in query
    assert 'namespace="payments"' in query


def test_exact_pod_container_metric_adds_server_owned_container_selector() -> None:
    source = FakeRangeSource()
    reader = BoundedMetricTrendReader(source, clock=lambda: NOW)

    reader.execute(ReadIntent(
        tool="query_metrics",
        metric="memory_working_set",
        metric_scope="pod",
        namespace="payments",
        name="api-1",
        container="server",
    ))

    query = source.calls[0]["promql"]
    assert 'pod="api-1"' in query
    assert 'container="server"' in query
