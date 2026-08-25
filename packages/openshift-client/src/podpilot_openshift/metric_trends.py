from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from statistics import fmean
from typing import Callable
from uuid import uuid4

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_openshift.metrics import MonitoringQueryError, MonitoringRangeQuerySource


class MetricTrendError(RuntimeError):
    """A safe failure from the typed metrics evidence boundary."""


_UNITS = {
    "cpu_usage": "cores",
    "cpu_requests": "cores",
    "cpu_limits": "cores",
    "cpu_throttling": "percent",
    "memory_working_set": "bytes",
    "memory_requests": "bytes",
    "memory_limits": "bytes",
    "network_receive": "bytes_per_second",
    "network_transmit": "bytes_per_second",
    "container_restarts": "restarts",
    "persistent_volume_usage": "percent",
    "pod_readiness": "ratio",
    "top_cpu_consumers": "cores",
    "top_memory_consumers": "bytes",
    "node_cpu_utilization": "percent",
    "node_memory_utilization": "percent",
}


def _selector(intent: ReadIntent, *, container: bool = False) -> str:
    labels = []
    if intent.namespace:
        labels.append(f"namespace={json.dumps(intent.namespace)}")
    if intent.metric_scope == "pod":
        labels.append(f"pod={json.dumps(intent.name)}")
    if container:
        labels.extend(['container!=""', 'container!="POD"', 'image!=""'])
    return ",".join(labels)


def _membership(intent: ReadIntent) -> str | None:
    if intent.metric_scope == "deployment":
        namespace = json.dumps(intent.namespace)
        deployment = json.dumps(intent.name)
        return (
            "max by (namespace, pod) ("
            f'label_replace(kube_pod_owner{{namespace={namespace},owner_kind="ReplicaSet"}}, '
            '"replicaset", "$1", "owner_name", "(.*)") '
            "* on(namespace, replicaset) group_left "
            f'kube_replicaset_owner{{namespace={namespace},owner_kind="Deployment",owner_name={deployment}}}'
            ")"
        )
    if intent.metric_scope == "node":
        labels = [f"node={json.dumps(intent.name)}"]
        if intent.namespace:
            labels.append(f"namespace={json.dumps(intent.namespace)}")
        return f"max by (namespace, pod) (kube_pod_info{{{','.join(labels)}}})"
    return None


def _scoped(expression: str, intent: ReadIntent) -> str:
    membership = _membership(intent)
    if not membership:
        return expression
    return f"({expression}) * on(namespace, pod) group_left ({membership})"


def _with_labels(selector: str, *labels: str) -> str:
    return ",".join(value for value in (selector, *labels) if value)


def _promql(intent: ReadIntent, *, rate_window_seconds: int) -> str:
    metric = intent.metric
    container = _selector(intent, container=True)
    workload = _selector(intent)
    window = f"{rate_window_seconds}s"
    if metric == "cpu_usage":
        expression = f"rate(container_cpu_usage_seconds_total{{{container}}}[{window}])"
        return f"sum({_scoped(expression, intent)})"
    if metric == "cpu_requests":
        labels = _with_labels(workload, 'resource="cpu"', 'unit="core"')
        expression = f"kube_pod_container_resource_requests{{{labels}}}"
        return f"sum({_scoped(expression, intent)})"
    if metric == "cpu_limits":
        labels = _with_labels(workload, 'resource="cpu"', 'unit="core"')
        expression = f"kube_pod_container_resource_limits{{{labels}}}"
        return f"sum({_scoped(expression, intent)})"
    if metric == "cpu_throttling":
        throttled = _scoped(
            f"rate(container_cpu_cfs_throttled_periods_total{{{container}}}[{window}])", intent,
        )
        periods = _scoped(
            f"rate(container_cpu_cfs_periods_total{{{container}}}[{window}])", intent,
        )
        return (
            f"100 * sum({throttled}) / clamp_min(sum({periods}), 0.000000001)"
        )
    if metric == "memory_working_set":
        return f"sum({_scoped(f'container_memory_working_set_bytes{{{container}}}', intent)})"
    if metric == "memory_requests":
        labels = _with_labels(workload, 'resource="memory"', 'unit="byte"')
        expression = f"kube_pod_container_resource_requests{{{labels}}}"
        return f"sum({_scoped(expression, intent)})"
    if metric == "memory_limits":
        labels = _with_labels(workload, 'resource="memory"', 'unit="byte"')
        expression = f"kube_pod_container_resource_limits{{{labels}}}"
        return f"sum({_scoped(expression, intent)})"
    if metric == "network_receive":
        expression = f"rate(container_network_receive_bytes_total{{{workload}}}[{window}])"
        return f"sum({_scoped(expression, intent)})"
    if metric == "network_transmit":
        expression = f"rate(container_network_transmit_bytes_total{{{workload}}}[{window}])"
        return f"sum({_scoped(expression, intent)})"
    if metric == "container_restarts":
        return f"sum({_scoped(f'kube_pod_container_status_restarts_total{{{workload}}}', intent)})"
    if metric == "pod_readiness":
        aggregation = "max" if intent.metric_scope == "pod" else "avg"
        labels = _with_labels(workload, 'condition="true"')
        expression = f"kube_pod_status_ready{{{labels}}}"
        return f"{aggregation}({_scoped(expression, intent)})"
    if metric == "persistent_volume_usage":
        selector = (
            f"namespace={json.dumps(intent.namespace)},"
            f"persistentvolumeclaim={json.dumps(intent.name)}"
        )
        return (
            f"100 * sum(kubelet_volume_stats_used_bytes{{{selector}}}) "
            f"/ clamp_min(sum(kubelet_volume_stats_capacity_bytes{{{selector}}}), 1)"
        )
    if metric == "top_cpu_consumers":
        expression = _scoped(
            f"rate(container_cpu_usage_seconds_total{{{container}}}[{window}])", intent,
        )
        return f"topk(10, sum by (namespace, pod, container) ({expression}))"
    if metric == "top_memory_consumers":
        expression = _scoped(f"container_memory_working_set_bytes{{{container}}}", intent)
        return f"topk(10, sum by (namespace, pod, container) ({expression}))"
    if metric == "node_cpu_utilization":
        node = json.dumps(intent.name)
        return (
            "100 * (1 - avg("
            f'rate(node_cpu_seconds_total{{mode="idle"}}[{window}]) '
            f'* on(instance) group_left(nodename) node_uname_info{{nodename={node}}}'
            "))"
        )
    if metric == "node_memory_utilization":
        node = json.dumps(intent.name)
        membership = f'on(instance) group_left(nodename) node_uname_info{{nodename={node}}}'
        return (
            f"100 * (1 - sum(node_memory_MemAvailable_bytes * {membership}) "
            f"/ clamp_min(sum(node_memory_MemTotal_bytes * {membership}), 1))"
        )
    raise MetricTrendError("The requested metric is not registered.")


class BoundedMetricTrendReader:
    """Compile typed metric intents into bounded server-owned PromQL range queries."""

    def __init__(
        self,
        source: MonitoringRangeQuerySource,
        *,
        max_range_seconds: int = 2_592_000,
        max_points_per_series: int = 300,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._source = source
        self._max_range_seconds = max_range_seconds
        self._max_points_per_series = max_points_per_series
        self._clock = clock

    def execute(self, intent: ReadIntent) -> ReadResult:
        if intent.tool != "query_metrics" or not intent.metric:
            raise ValueError("BoundedMetricTrendReader requires a query_metrics intent.")
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        step_seconds = max(
            intent.step_seconds,
            math.ceil(range_seconds / max(1, self._max_points_per_series - 1)),
        )
        rate_window_seconds = max(60, min(900, step_seconds * 5))
        end = self._clock()
        start = end - timedelta(seconds=range_seconds)
        try:
            snapshot = self._source.query_range(
                _promql(intent, rate_window_seconds=rate_window_seconds),
                start=start,
                end=end,
                step_seconds=step_seconds,
            )
        except MonitoringQueryError as exc:
            raise MetricTrendError(str(exc)) from exc

        rendered_series = []
        ranking = []
        all_values: list[float] = []
        for series in snapshot.series:
            points = [{
                "timestamp": point.observed_at.isoformat(),
                "value": point.value,
            } for point in series.points]
            values = [point.value for point in series.points if point.value is not None]
            all_values.extend(values)
            series_stats = self._statistics(values)
            rendered_series.append({
                "labels": series.labels, "points": points, "statistics": series_stats,
            })
            ranking.append({
                "labels": series.labels,
                "current": series_stats["current"],
                "average": series_stats["average"],
                "maximum": series_stats["maximum"],
            })

        ranking.sort(
            key=lambda item: item["current"] if isinstance(item["current"], (int, float)) else -math.inf,
            reverse=True,
        )
        stats = self._statistics(all_values)
        if intent.metric in {"top_cpu_consumers", "top_memory_consumers"} and ranking:
            stats["current"] = ranking[0]["current"]
        limitations: list[str] = []
        if range_seconds != intent.range_seconds:
            limitations.append(
                f"The requested period was reduced to {range_seconds} seconds by the metrics range policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The metric result reached its configured series or point ceiling; the trend may be incomplete."
            )
        if not all_values:
            limitations.append("Thanos returned no finite samples for the requested metric and scope.")
        if step_seconds != intent.step_seconds:
            limitations.append(
                f"The requested resolution was increased to {step_seconds} seconds to keep the trend bounded."
            )
        target = (
            intent.namespace if intent.metric_scope == "namespace" else
            intent.name if intent.metric_scope == "node" else
            f"{intent.namespace}/{intent.name}"
        )
        return ReadResult(observations=(AdHocObservation(
            id=f"metric-{uuid4()}",
            tool="query_metrics",
            summary=f"Read {intent.metric} trend for {intent.metric_scope} {target}.",
            source=f"thanos:query_range/{intent.metric}",
            collected_at=snapshot.collected_at,
            data={
                "metric": intent.metric,
                "scope": intent.metric_scope,
                "namespace": intent.namespace,
                "name": intent.name,
                "unit": _UNITS[intent.metric],
                "rangeSeconds": range_seconds,
                "stepSeconds": step_seconds,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "series": rendered_series,
                "ranking": ranking,
                "statistics": stats,
                "complete": snapshot.is_complete,
            },
        ),), limitations=tuple(limitations))

    @staticmethod
    def _trend(values: list[float]) -> str:
        if len(values) < 2:
            return "unknown"
        first, last = values[0], values[-1]
        tolerance = max(abs(first) * 0.05, 1e-9)
        if last > first + tolerance:
            return "increasing"
        if last < first - tolerance:
            return "decreasing"
        return "flat"

    @classmethod
    def _statistics(cls, values: list[float]) -> dict[str, float | str | None]:
        return {
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "average": fmean(values) if values else None,
            "current": values[-1] if values else None,
            "trend": cls._trend(values),
        }
