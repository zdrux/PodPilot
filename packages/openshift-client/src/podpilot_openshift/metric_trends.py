from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from statistics import fmean
from typing import Callable
from uuid import uuid4

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_openshift.metrics import (
    MetricRange,
    MonitoringQueryError,
    MonitoringRangeQuerySource,
)


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
    "kafka_topic_messages_in": "messages_per_second",
    "kafka_topic_bytes_in": "bytes_per_second",
    "kafka_topic_bytes_out": "bytes_per_second",
    "kafka_topic_disk_utilization": "percent",
    "kafka_consumer_lag": "records",
    "kafka_under_replicated_partitions": "partitions",
    "ingress_request_rate": "requests_per_second",
    "ingress_error_rate": "requests_per_second",
    "ingress_bytes_in": "bytes_per_second",
    "ingress_bytes_out": "bytes_per_second",
    "machineconfigpool_updated": "percent",
    "machineconfigpool_degraded": "machines",
    "hpa_current_replicas": "replicas",
    "hpa_desired_replicas": "replicas",
    "hpa_max_replicas": "replicas",
    "workload_availability": "percent",
    "persistent_volume_inode_usage": "percent",
    "cluster_operator_available": "ratio",
    "cluster_operator_degraded": "ratio",
    "cluster_operator_progressing": "ratio",
    "apiserver_request_rate": "requests_per_second",
    "apiserver_error_rate": "requests_per_second",
    "apiserver_latency": "seconds",
    "etcd_db_size": "bytes",
    "etcd_fsync_latency": "seconds",
    "apiserver_inflight_requests": "requests",
    "scheduler_pending_pods": "pods",
    "scheduler_attempt_rate": "requests_per_second",
    "scheduler_error_rate": "requests_per_second",
    "scheduler_latency": "seconds",
    "etcd_has_leader": "ratio",
    "etcd_leader_changes": "events_per_second",
    "monitoring_targets_up": "targets",
    "monitoring_targets_down": "targets",
    "prometheus_head_series": "series",
    "prometheus_ingestion_rate": "samples_per_second",
    "prometheus_rule_evaluation_failures": "events_per_second",
    "alertmanager_active_alerts": "alerts",
    "logging_ingestion_rate": "bytes_per_second",
    "logging_query_latency": "seconds",
}

_PREREQUISITES = {
    "kafka_topic_messages_in": "Strimzi broker JMX Prometheus metrics",
    "kafka_topic_bytes_in": "Strimzi broker JMX Prometheus metrics",
    "kafka_topic_bytes_out": "Strimzi broker JMX Prometheus metrics",
    "kafka_topic_disk_utilization": (
        "Strimzi broker JMX log-size metrics and kubelet Kafka PVC capacity metrics"
    ),
    "kafka_consumer_lag": "Strimzi Kafka Exporter metrics",
    "kafka_under_replicated_partitions": "Strimzi Kafka Exporter metrics",
    "ingress_request_rate": "OpenShift router HAProxy metrics",
    "ingress_error_rate": "OpenShift router HAProxy metrics",
    "ingress_bytes_in": "OpenShift router HAProxy metrics",
    "ingress_bytes_out": "OpenShift router HAProxy metrics",
    "machineconfigpool_updated": "Machine Config Operator metrics",
    "machineconfigpool_degraded": "Machine Config Operator metrics",
    "hpa_current_replicas": "kube-state-metrics HPA metrics",
    "hpa_desired_replicas": "kube-state-metrics HPA metrics",
    "hpa_max_replicas": "kube-state-metrics HPA metrics",
    "workload_availability": "kube-state-metrics workload metrics",
    "persistent_volume_inode_usage": "kubelet volume statistics",
    "cluster_operator_available": "openshift-state-metrics ClusterOperator metrics",
    "cluster_operator_degraded": "openshift-state-metrics ClusterOperator metrics",
    "cluster_operator_progressing": "openshift-state-metrics ClusterOperator metrics",
    "apiserver_request_rate": "Kubernetes API server metrics",
    "apiserver_error_rate": "Kubernetes API server metrics",
    "apiserver_latency": "Kubernetes API server metrics",
    "etcd_db_size": "etcd metrics",
    "etcd_fsync_latency": "etcd metrics",
    "apiserver_inflight_requests": "Kubernetes API server metrics",
    "scheduler_pending_pods": "Kubernetes scheduler metrics",
    "scheduler_attempt_rate": "Kubernetes scheduler metrics",
    "scheduler_error_rate": "Kubernetes scheduler metrics",
    "scheduler_latency": "Kubernetes scheduler metrics",
    "etcd_has_leader": "etcd metrics",
    "etcd_leader_changes": "etcd metrics",
    "monitoring_targets_up": "OpenShift cluster-monitoring target metrics",
    "monitoring_targets_down": "OpenShift cluster-monitoring target metrics",
    "prometheus_head_series": "OpenShift Prometheus self-metrics or recording rules",
    "prometheus_ingestion_rate": "OpenShift Prometheus self-metrics or recording rules",
    "prometheus_rule_evaluation_failures": "OpenShift Prometheus rule-evaluation metrics",
    "alertmanager_active_alerts": "OpenShift Alertmanager self-metrics",
    "logging_ingestion_rate": "LokiStack distributor metrics scraped by cluster monitoring",
    "logging_query_latency": "LokiStack query metrics scraped by cluster monitoring",
}


def _selector(intent: ReadIntent, *, container: bool = False) -> str:
    labels = []
    if intent.namespace:
        labels.append(f"namespace={json.dumps(intent.namespace)}")
    if intent.metric_scope == "pod":
        labels.append(f"pod={json.dumps(intent.name)}")
    if intent.container:
        labels.append(f"container={json.dumps(intent.container)}")
    if container:
        labels.extend(['container!=""', 'container!="POD"', 'image!=""'])
    return ",".join(labels)


def _membership(intent: ReadIntent) -> str | None:
    if intent.metric_scope in {"deployment", "workload"}:
        namespace = json.dumps(intent.namespace)
        kind = "Deployment" if intent.metric_scope == "deployment" else intent.kind
        owner = json.dumps(intent.name)
        if kind == "Deployment":
            return (
                "max by (namespace, pod) ("
                f'label_replace(kube_pod_owner{{namespace={namespace},owner_kind="ReplicaSet"}}, '
                '"replicaset", "$1", "owner_name", "(.*)") '
                "* on(namespace, replicaset) group_left "
                f'kube_replicaset_owner{{namespace={namespace},owner_kind="Deployment",owner_name={owner}}}'
                ")"
            )
        return (
            "max by (namespace, pod) ("
            f"kube_pod_owner{{namespace={namespace},owner_kind={json.dumps(kind)},"
            f"owner_name={owner}}}"
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


def _aggregate(
    expression: str,
    intent: ReadIntent,
    *,
    function: str = "sum",
    supported: set[str] | None = None,
) -> str:
    label_map = {
        "namespace": "namespace",
        "pod": "pod",
        "container": "container",
    }
    selected = [
        label_map[grouping]
        for grouping in intent.metric_group_by
        if grouping in label_map and (supported is None or grouping in supported)
    ]
    if selected:
        return f"{function} by ({', '.join(selected)}) ({expression})"
    return f"{function}({expression})"


def _domain_aggregate(
    expression: str,
    intent: ReadIntent,
    *,
    default_labels: tuple[str, ...] = (),
    function: str = "sum",
    apply_rank: bool = True,
) -> str:
    label_map = {
        "namespace": "namespace", "topic": "topic", "partition": "partition",
        "consumer_group": "consumergroup", "route": "route", "pool": "pool",
        "operator": "name", "code": "code", "node": "node",
        "job": "job", "instance": "instance", "queue": "queue", "result": "result",
        "component": "component", "tenant": "tenant", "request_kind": "request_kind",
    }
    labels = [
        label_map[value] for value in intent.metric_group_by if value in label_map
    ] or list(default_labels)
    aggregate = (
        f"{function} by ({', '.join(labels)}) ({expression})"
        if labels else f"{function}({expression})"
    )
    return (
        f"topk({intent.limit}, {aggregate})"
        if apply_rank and intent.metric_operation == "rank" else aggregate
    )


def _metric_selector(**values: str | None) -> str:
    return ",".join(
        f"{key}={json.dumps(value)}" for key, value in values.items() if value
    )


def _kafka_broker_metric(
    metric_names: tuple[str, ...], intent: ReadIntent, *, extra_selector: str,
) -> str:
    """Select one exact Strimzi cluster across supported scrape profiles."""
    namespace = json.dumps(intent.namespace)
    cluster = json.dumps(intent.name)
    cluster_pattern = re.escape(str(intent.name)).replace(r"\-", "-")
    pod_pattern = json.dumps(rf"{cluster_pattern}-.+-[0-9]+")
    expressions: list[str] = []
    for metric_name in metric_names:
        expressions.extend([
            f"{metric_name}{{namespace={namespace},strimzi_io_cluster={cluster},{extra_selector}}}",
            (
                f"{metric_name}{{namespace={namespace},strimzi_io_cluster=\"\","
                f"pod=~{pod_pattern},{extra_selector}}}"
            ),
        ])
    return f"({' or '.join(expressions)})"


def _kafka_topic_storage_detail_query(
    intent: ReadIntent,
    *,
    topics: list[str],
    partitions: bool,
) -> str:
    """Build a bounded companion query for topic bytes or partition replicas."""

    topic_pattern = "^(?:" + "|".join(re.escape(topic) for topic in topics) + ")$"
    log_size = _kafka_broker_metric(
        ("kafka_log_log_size", "kafka_log_log_size_value"),
        intent,
        extra_selector=f"topic=~{json.dumps(topic_pattern)}",
    )
    if not partitions:
        return f"topk({len(topics)}, sum by (topic) ({log_size}))"
    # One selected internal topic can legitimately have dozens of partitions
    # (for example, __consumer_offsets defaults to 50). Use the reader's
    # reviewed series ceiling so the common case is not silently truncated.
    replica_limit = 100
    return (
        f"topk({replica_limit}, sum by (topic, partition, pod, kubernetes_pod_name) "
        f"({log_size}))"
    )


def _latest_metric_value(series: object) -> float | None:
    points = getattr(series, "points", ())
    values = [point.value for point in points if point.value is not None]
    return values[-1] if values else None


def _kafka_topic_storage_data(
    ranking: list[dict[str, object]],
    *,
    topic_snapshot: MetricRange | None,
    partition_snapshot: MetricRange | None,
    selected_topics: list[str],
    selected_topics_complete: bool,
    primary_complete: bool,
    incomplete_partition_topics: set[str] | None = None,
) -> dict[str, object] | None:
    if not selected_topics:
        return None

    topic_bytes: dict[str, float] = {}
    for series in topic_snapshot.series if topic_snapshot is not None else ():
        topic = str(series.labels.get("topic") or "")
        current = _latest_metric_value(series)
        if topic and current is not None:
            topic_bytes[topic] = current

    partitions_by_topic: dict[str, list[dict[str, object]]] = {
        topic: [] for topic in selected_topics
    }
    for series in partition_snapshot.series if partition_snapshot is not None else ():
        topic = str(series.labels.get("topic") or "")
        if topic not in partitions_by_topic:
            continue
        current = _latest_metric_value(series)
        if current is None:
            continue
        partition = str(series.labels.get("partition") or "")
        broker_pod = str(
            series.labels.get("pod")
            or series.labels.get("kubernetes_pod_name")
            or ""
        )
        broker_match = re.search(r"-(\d+)$", broker_pod)
        partitions_by_topic[topic].append({
            "partition": partition,
            "brokerPod": broker_pod,
            "brokerId": broker_match.group(1) if broker_match else None,
            "currentBytes": current,
        })

    def partition_key(item: dict[str, object]) -> tuple[int, int | str, str]:
        partition = str(item.get("partition") or "")
        try:
            return (0, int(partition), str(item.get("brokerPod") or ""))
        except ValueError:
            return (1, partition, str(item.get("brokerPod") or ""))

    utilization_by_topic = {
        str(item.get("labels", {}).get("topic")): item.get("current")
        for item in ranking
        if isinstance(item.get("labels"), dict)
        and item.get("labels", {}).get("topic") not in (None, "")
    }
    incomplete_topics = incomplete_partition_topics or set()
    topics: list[dict[str, object]] = []
    for topic in selected_topics:
        partitions = sorted(partitions_by_topic.get(topic, []), key=partition_key)
        topics.append({
            "topic": topic,
            "internal": topic.startswith("__"),
            "currentBytes": topic_bytes.get(topic),
            "utilizationPercent": utilization_by_topic.get(topic),
            "partitionCount": len({
                str(item.get("partition")) for item in partitions
                if item.get("partition") not in (None, "")
            }),
            "replicaCount": len(partitions),
            "partitionsComplete": (
                partition_snapshot is not None and topic not in incomplete_topics
            ),
            "partitions": partitions,
        })
    return {
        "unit": "bytes",
        "topics": topics,
        "topicBytesComplete": topic_snapshot is not None and topic_snapshot.is_complete,
        "partitionDetailsComplete": (
            partition_snapshot is not None and partition_snapshot.is_complete
        ),
        "selectedTopicsComplete": selected_topics_complete,
        "primaryComplete": primary_complete,
        "complete": bool(
            primary_complete
            and topic_snapshot is not None
            and topic_snapshot.is_complete
            and partition_snapshot is not None
            and partition_snapshot.is_complete
            and selected_topics_complete
        ),
    }


def _promql(intent: ReadIntent, *, rate_window_seconds: int) -> str:
    metric = intent.metric
    container = _selector(intent, container=True)
    workload = _selector(intent)
    window = f"{rate_window_seconds}s"
    if metric == "cpu_usage":
        expression = f"rate(container_cpu_usage_seconds_total{{{container}}}[{window}])"
        return _aggregate(_scoped(expression, intent), intent)
    if metric == "cpu_requests":
        labels = _with_labels(workload, 'resource="cpu"', 'unit="core"')
        expression = f"kube_pod_container_resource_requests{{{labels}}}"
        return _aggregate(_scoped(expression, intent), intent)
    if metric == "cpu_limits":
        labels = _with_labels(workload, 'resource="cpu"', 'unit="core"')
        expression = f"kube_pod_container_resource_limits{{{labels}}}"
        return _aggregate(_scoped(expression, intent), intent)
    if metric == "cpu_throttling":
        throttled = _scoped(
            f"rate(container_cpu_cfs_throttled_periods_total{{{container}}}[{window}])", intent,
        )
        periods = _scoped(
            f"rate(container_cpu_cfs_periods_total{{{container}}}[{window}])", intent,
        )
        return (
            f"100 * {_aggregate(throttled, intent)} / "
            f"clamp_min({_aggregate(periods, intent)}, 0.000000001)"
        )
    if metric == "memory_working_set":
        return _aggregate(
            _scoped(f"container_memory_working_set_bytes{{{container}}}", intent), intent,
        )
    if metric == "memory_requests":
        labels = _with_labels(workload, 'resource="memory"', 'unit="byte"')
        expression = f"kube_pod_container_resource_requests{{{labels}}}"
        return _aggregate(_scoped(expression, intent), intent)
    if metric == "memory_limits":
        labels = _with_labels(workload, 'resource="memory"', 'unit="byte"')
        expression = f"kube_pod_container_resource_limits{{{labels}}}"
        return _aggregate(_scoped(expression, intent), intent)
    if metric == "network_receive":
        expression = f"rate(container_network_receive_bytes_total{{{workload}}}[{window}])"
        return _aggregate(
            _scoped(expression, intent), intent, supported={"namespace", "pod"},
        )
    if metric == "network_transmit":
        expression = f"rate(container_network_transmit_bytes_total{{{workload}}}[{window}])"
        return _aggregate(
            _scoped(expression, intent), intent, supported={"namespace", "pod"},
        )
    if metric == "container_restarts":
        return _aggregate(
            _scoped(f"kube_pod_container_status_restarts_total{{{workload}}}", intent), intent,
        )
    if metric == "pod_readiness":
        aggregation = "max" if intent.metric_scope == "pod" else "avg"
        labels = _with_labels(workload, 'condition="true"')
        expression = f"kube_pod_status_ready{{{labels}}}"
        return _aggregate(
            _scoped(expression, intent), intent, function=aggregation,
            supported={"namespace", "pod"},
        )
    if metric == "persistent_volume_usage":
        selector = _metric_selector(
            namespace=intent.namespace, persistentvolumeclaim=intent.name,
        )
        labels = (
            "namespace", "persistentvolumeclaim"
        ) if intent.metric_scope != "persistent_volume_claim" else ()
        used = _domain_aggregate(
            f"kubelet_volume_stats_used_bytes{{{selector}}}", intent,
            default_labels=labels, apply_rank=False,
        )
        capacity = _domain_aggregate(
            f"kubelet_volume_stats_capacity_bytes{{{selector}}}", intent,
            default_labels=labels, apply_rank=False,
        )
        expression = f"100 * {used} / clamp_min({capacity}, 1)"
        return (
            f"topk({intent.limit}, {expression})"
            if intent.metric_operation == "rank" else expression
        )
    if metric == "persistent_volume_inode_usage":
        selector = _metric_selector(
            namespace=intent.namespace, persistentvolumeclaim=intent.name,
        )
        labels = (
            "namespace", "persistentvolumeclaim"
        ) if intent.metric_scope != "persistent_volume_claim" else ()
        used = _domain_aggregate(
            f"kubelet_volume_stats_inodes_used{{{selector}}}", intent,
            default_labels=labels, apply_rank=False,
        )
        total = _domain_aggregate(
            f"kubelet_volume_stats_inodes{{{selector}}}", intent,
            default_labels=labels, apply_rank=False,
        )
        expression = f"100 * {used} / clamp_min({total}, 1)"
        return (
            f"topk({intent.limit}, {expression})"
            if intent.metric_operation == "rank" else expression
        )
    if metric == "top_cpu_consumers":
        expression = _scoped(
            f"rate(container_cpu_usage_seconds_total{{{container}}}[{window}])", intent,
        )
        return f"topk({intent.limit}, sum by (namespace, pod) ({expression}))"
    if metric == "top_memory_consumers":
        expression = _scoped(f"container_memory_working_set_bytes{{{container}}}", intent)
        return f"topk({intent.limit}, sum by (namespace, pod) ({expression}))"
    if metric == "node_cpu_utilization":
        if intent.metric_scope in {"cluster", "node_role"}:
            membership = ""
            if intent.metric_scope == "node_role":
                role = json.dumps(intent.name)
                membership = (
                    "on(nodename) group_left label_replace("
                    f'kube_node_role{{role={role}}}, "nodename", "$1", "node", "(.*)"'
                    ")"
                )
            expression = (
                "100 * (1 - avg by (nodename) ("
                f'rate(node_cpu_seconds_total{{mode="idle"}}[{window}]) '
                "* on(instance) group_left(nodename) node_uname_info "
                f"{'* ' + membership if membership else ''}"
                "))"
            )
            return (
                f"topk({intent.limit}, {expression})"
                if intent.metric_operation == "rank" else expression
            )
        node = json.dumps(intent.name)
        return (
            "100 * (1 - avg("
            f'rate(node_cpu_seconds_total{{mode="idle"}}[{window}]) '
            f'* on(instance) group_left(nodename) node_uname_info{{nodename={node}}}'
            "))"
        )
    if metric == "node_memory_utilization":
        if intent.metric_scope in {"cluster", "node_role"}:
            membership = ""
            if intent.metric_scope == "node_role":
                role = json.dumps(intent.name)
                membership = (
                    "on(nodename) group_left label_replace("
                    f'kube_node_role{{role={role}}}, "nodename", "$1", "node", "(.*)"'
                    ")"
                )
            membership_suffix = f"* {membership}" if membership else ""
            available = (
                "node_memory_MemAvailable_bytes "
                "* on(instance) group_left(nodename) node_uname_info "
                f"{membership_suffix}"
            )
            total = (
                "node_memory_MemTotal_bytes "
                "* on(instance) group_left(nodename) node_uname_info "
                f"{membership_suffix}"
            )
            expression = (
                f"100 * (1 - sum by (nodename) ({available}) / "
                f"clamp_min(sum by (nodename) ({total}), 1))"
            )
            return (
                f"topk({intent.limit}, {expression})"
                if intent.metric_operation == "rank" else expression
            )
        node = json.dumps(intent.name)
        membership = f'on(instance) group_left(nodename) node_uname_info{{nodename={node}}}'
        return (
            f"100 * (1 - sum(node_memory_MemAvailable_bytes * {membership}) "
            f"/ clamp_min(sum(node_memory_MemTotal_bytes * {membership}), 1))"
        )
    if metric in {
        "kafka_topic_messages_in", "kafka_topic_bytes_in", "kafka_topic_bytes_out",
    }:
        source_metric = {
            "kafka_topic_messages_in": "kafka_server_brokertopicmetrics_messagesin_total",
            "kafka_topic_bytes_in": "kafka_server_brokertopicmetrics_bytesin_total",
            "kafka_topic_bytes_out": "kafka_server_brokertopicmetrics_bytesout_total",
        }[metric]
        selector = _metric_selector(
            namespace=intent.namespace, strimzi_io_cluster=intent.name,
        )
        return _domain_aggregate(
            f"rate({source_metric}{{{selector},topic!=\"\"}}[{window}])",
            intent, default_labels=("topic",),
        )
    if metric == "kafka_topic_disk_utilization":
        log_size = _kafka_broker_metric(
            ("kafka_log_log_size", "kafka_log_log_size_value"), intent,
            extra_selector='topic!=""',
        )
        usage = _domain_aggregate(
            log_size, intent,
            default_labels=("topic",), apply_rank=False,
        )
        cluster_name = re.escape(str(intent.name)).replace(r"\-", "-")
        pvc_pattern = (
            rf"data(?:-[0-9]+)?-{cluster_name}-"
            r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?-[0-9]+"
        )
        capacity_selector = _metric_selector(
            namespace=intent.namespace, persistentvolumeclaim=f"~{pvc_pattern}",
        ).replace("persistentvolumeclaim=\"~", "persistentvolumeclaim=~\"")
        ratio = (
            f"100 * ({usage}) / ignoring(topic, partition) group_left "
            "clamp_min(sum("
            f"kubelet_volume_stats_capacity_bytes{{{capacity_selector}}}"
            "), 1)"
        )
        return f"topk({intent.limit}, {ratio})" if intent.metric_operation == "rank" else ratio
    if metric == "kafka_consumer_lag":
        selector = _metric_selector(
            namespace=intent.namespace, strimzi_io_cluster=intent.name,
        )
        return _domain_aggregate(
            f"kafka_consumergroup_lag{{{selector},topic!=\"\"}}",
            intent, default_labels=("topic", "consumergroup"),
        )
    if metric == "kafka_under_replicated_partitions":
        selector = _metric_selector(
            namespace=intent.namespace, strimzi_io_cluster=intent.name,
        )
        return _domain_aggregate(
            f"kafka_topic_partition_under_replicated_partition{{{selector},topic!=\"\"}}",
            intent, default_labels=("topic",),
        )
    if metric in {"ingress_request_rate", "ingress_error_rate"}:
        selectors = ['namespace="openshift-ingress"']
        if intent.metric_scope == "route":
            selectors.extend([
                f"exported_namespace={json.dumps(intent.namespace)}",
                f"route={json.dumps(intent.name)}",
            ])
        else:
            controller = re.escape(str(intent.name))
            selectors.append(f'pod=~"router-{controller}-.*"')
        if metric == "ingress_error_rate":
            selectors.append('code=~"5.."')
        expression = (
            "clamp_min(rate(haproxy_server_http_responses_total{"
            f"{','.join(selectors)}}}[{window}]), 0)"
        )
        expression = (
            f'label_replace({expression}, "namespace", "$1", '
            '"exported_namespace", "(.+)")'
        )
        return _domain_aggregate(
            expression,
            intent, default_labels=("namespace", "route"),
        )
    if metric in {"ingress_bytes_in", "ingress_bytes_out"}:
        direction = "in" if metric == "ingress_bytes_in" else "out"
        route_dimensions = (
            intent.metric_scope in {"namespace", "route"}
            or any(value in {"namespace", "route"} for value in intent.metric_group_by)
        )
        family = "backend" if route_dimensions else "frontend"
        selectors = ['namespace="openshift-ingress"']
        if intent.metric_scope == "namespace":
            selectors.append(f"exported_namespace={json.dumps(intent.namespace)}")
        elif intent.metric_scope == "route":
            selectors.extend([
                f"exported_namespace={json.dumps(intent.namespace)}",
                f"route={json.dumps(intent.name)}",
            ])
        elif intent.metric_scope == "ingress_controller":
            controller = re.escape(str(intent.name))
            selectors.append(f'pod=~"router-{controller}-.*"')
        expression = (
            f"clamp_min(rate(haproxy_{family}_bytes_{direction}_total{{"
            f"{','.join(selectors)}}}[{window}]), 0)"
        )
        if family == "backend":
            expression = (
                f'label_replace({expression}, "namespace", "$1", '
                '"exported_namespace", "(.+)")'
            )
        default_labels = ("namespace", "route") if intent.metric_scope == "route" else ()
        return _domain_aggregate(
            expression, intent, default_labels=default_labels,
        )
    if metric in {"machineconfigpool_updated", "machineconfigpool_degraded"}:
        selector = f"pool={json.dumps(intent.name)}"
        if metric == "machineconfigpool_degraded":
            return f"max(mco_degraded_machine_count{{{selector}}})"
        return (
            f"100 * max(mco_updated_machine_count{{{selector}}}) / "
            f"clamp_min(max(mco_machine_count{{{selector}}}), 1)"
        )
    if metric in {"hpa_current_replicas", "hpa_desired_replicas", "hpa_max_replicas"}:
        source_metric = {
            "hpa_current_replicas": "kube_horizontalpodautoscaler_status_current_replicas",
            "hpa_desired_replicas": "kube_horizontalpodautoscaler_status_desired_replicas",
            "hpa_max_replicas": "kube_horizontalpodautoscaler_spec_max_replicas",
        }[metric]
        selector = _metric_selector(
            namespace=intent.namespace, horizontalpodautoscaler=intent.name,
        )
        return f"max({source_metric}{{{selector}}})"
    if metric == "workload_availability":
        selector_key = {
            "Deployment": "deployment", "StatefulSet": "statefulset",
            "DaemonSet": "daemonset",
        }.get(intent.kind)
        if not selector_key:
            raise MetricTrendError("Workload availability is not registered for this Kind.")
        selector = _metric_selector(namespace=intent.namespace, **{selector_key: intent.name})
        available_metric, desired_metric = {
            "Deployment": (
                "kube_deployment_status_replicas_available", "kube_deployment_spec_replicas",
            ),
            "StatefulSet": (
                "kube_statefulset_status_replicas_ready", "kube_statefulset_replicas",
            ),
            "DaemonSet": (
                "kube_daemonset_status_number_available",
                "kube_daemonset_status_desired_number_scheduled",
            ),
        }[intent.kind]
        return (
            f"100 * max({available_metric}{{{selector}}}) / "
            f"clamp_min(max({desired_metric}{{{selector}}}), 1)"
        )
    if metric in {
        "cluster_operator_available", "cluster_operator_degraded",
        "cluster_operator_progressing",
    }:
        condition = {
            "cluster_operator_available": "Available",
            "cluster_operator_degraded": "Degraded",
            "cluster_operator_progressing": "Progressing",
        }[metric]
        selector = _metric_selector(
            name=intent.name if intent.metric_scope == "cluster_operator" else None,
            condition=condition,
        )
        return _domain_aggregate(
            f"cluster_operator_conditions{{{selector}}}", intent,
            default_labels=("name",), function="max",
        )
    if metric in {"apiserver_request_rate", "apiserver_error_rate"}:
        code = ',code=~"5.."' if metric == "apiserver_error_rate" else ""
        return _domain_aggregate(
            f"rate(apiserver_request_total{{job=\"apiserver\"{code}}}[{window}])",
            intent, default_labels=("verb", "resource", "code"),
        )
    if metric == "apiserver_latency":
        labels = [
            value for value in intent.metric_group_by if value in {"verb", "resource"}
        ] or ["verb", "resource"]
        return (
            f"histogram_quantile(0.99, sum by (le, {', '.join(labels)}) ("
            f"rate(apiserver_request_duration_seconds_bucket{{job=\"apiserver\"}}[{window}])"
            "))"
        )
    if metric == "etcd_db_size":
        return "max(etcd_mvcc_db_total_size_in_bytes)"
    if metric == "etcd_fsync_latency":
        return (
            "histogram_quantile(0.99, sum by (le, instance) ("
            f"rate(etcd_disk_wal_fsync_duration_seconds_bucket[{window}])"
            "))"
        )
    if metric == "apiserver_inflight_requests":
        return _domain_aggregate(
            'apiserver_current_inflight_requests{job="apiserver"}', intent,
            default_labels=("request_kind",), function="max",
        )
    if metric == "scheduler_pending_pods":
        return _domain_aggregate(
            'scheduler_pending_pods{job=~".*scheduler.*"}', intent,
            default_labels=("queue",), function="max",
        )
    if metric in {"scheduler_attempt_rate", "scheduler_error_rate"}:
        result_selector = ',result="error"' if metric == "scheduler_error_rate" else ""
        return _domain_aggregate(
            "rate(scheduler_schedule_attempts_total{"
            f'job=~".*scheduler.*"{result_selector}}}[{window}])',
            intent, default_labels=("result",),
        )
    if metric == "scheduler_latency":
        labels = [
            value for value in intent.metric_group_by if value == "result"
        ] or ["result"]
        return (
            f"histogram_quantile(0.99, sum by (le, {', '.join(labels)}) ("
            "rate(scheduler_scheduling_attempt_duration_seconds_bucket{"
            f'job=~".*scheduler.*"}}[{window}])'
            "))"
        )
    if metric == "etcd_has_leader":
        return "min(etcd_server_has_leader)"
    if metric == "etcd_leader_changes":
        return _domain_aggregate(
            f"rate(etcd_server_leader_changes_seen_total[{window}])", intent,
            default_labels=("instance",),
        )
    if metric in {"monitoring_targets_up", "monitoring_targets_down"}:
        target = _domain_aggregate(
            'up{namespace=~"openshift-monitoring|openshift-user-workload-monitoring"}',
            intent, default_labels=("namespace", "job", "instance"),
            function="max", apply_rank=False,
        )
        expression = f"1 - ({target})" if metric == "monitoring_targets_down" else target
        return (
            f"topk({intent.limit}, {expression})"
            if intent.metric_operation == "rank" else expression
        )
    if metric == "prometheus_head_series":
        return "sum(openshift:prometheus_tsdb_head_series:sum)"
    if metric == "prometheus_ingestion_rate":
        return f"sum(rate(openshift:prometheus_tsdb_head_samples_appended_total:sum[{window}]))"
    if metric == "prometheus_rule_evaluation_failures":
        return _domain_aggregate(
            "rate(prometheus_rule_evaluation_failures_total{"
            'namespace=~"openshift-monitoring|openshift-user-workload-monitoring"}'
            f"[{window}])",
            intent, default_labels=("namespace", "pod"),
        )
    if metric == "alertmanager_active_alerts":
        return 'sum(alertmanager_alerts{namespace="openshift-monitoring"})'
    if metric == "logging_ingestion_rate":
        return _domain_aggregate(
            f"rate(loki_distributor_bytes_received_total[{window}])", intent,
            default_labels=("tenant",),
        )
    if metric == "logging_query_latency":
        labels = [
            value for value in intent.metric_group_by if value in {"job", "component", "tenant"}
        ] or ["job"]
        return (
            f"histogram_quantile(0.99, sum by (le, {', '.join(labels)}) ("
            f"rate(loki_logql_querystats_latency_seconds_bucket[{window}])"
            "))"
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
                "minimum": series_stats["minimum"],
                "average": series_stats["average"],
                "maximum": series_stats["maximum"],
            })

        ranking.sort(
            key=lambda item: item["current"] if isinstance(item["current"], (int, float)) else -math.inf,
            reverse=True,
        )
        is_ranking = (
            intent.metric_operation == "rank"
            or intent.metric in {"top_cpu_consumers", "top_memory_consumers"}
        )
        if is_ranking:
            ranking = ranking[:intent.limit]
        stats = self._statistics(all_values)
        if is_ranking and ranking:
            stats["current"] = ranking[0]["current"]
        limitations: list[str] = []
        topic_storage: dict[str, object] | None = None
        if (
            intent.metric == "kafka_topic_disk_utilization"
            and "topic" in intent.metric_group_by
            and "partition" not in intent.metric_group_by
        ):
            ranked_topic_names = list(dict.fromkeys(
                str(item.get("labels", {}).get("topic"))
                for item in ranking
                if isinstance(item.get("labels"), dict)
                and item.get("labels", {}).get("topic") not in (None, "")
            ))
            selected_topics = ranked_topic_names[: min(intent.limit, 5)]
            selected_topics_complete = len(selected_topics) == len(ranked_topic_names)
            topic_snapshot: MetricRange | None = None
            partition_snapshot: MetricRange | None = None
            if selected_topics:
                try:
                    topic_snapshot = self._source.query_range(
                        _kafka_topic_storage_detail_query(
                            intent, topics=selected_topics, partitions=False,
                        ),
                        start=start,
                        end=end,
                        step_seconds=step_seconds,
                    )
                except MonitoringQueryError as exc:
                    limitations.append(
                        "Kafka topic byte totals were unavailable; the utilization result "
                        f"remains valid. {str(exc)}"
                    )
                partition_series = []
                partition_complete = True
                incomplete_partition_topics: set[str] = set()
                partition_collected_at = snapshot.collected_at
                for topic in selected_topics:
                    try:
                        topic_partition_snapshot = self._source.query_range(
                            _kafka_topic_storage_detail_query(
                                intent, topics=[topic], partitions=True,
                            ),
                            start=start,
                            end=end,
                            step_seconds=step_seconds,
                        )
                        partition_series.extend(topic_partition_snapshot.series)
                        partition_complete = (
                            partition_complete and topic_partition_snapshot.is_complete
                        )
                        if not topic_partition_snapshot.is_complete:
                            incomplete_partition_topics.add(topic)
                        partition_collected_at = max(
                            partition_collected_at,
                            topic_partition_snapshot.collected_at,
                        )
                    except MonitoringQueryError as exc:
                        partition_complete = False
                        incomplete_partition_topics.add(topic)
                        limitations.append(
                            "Kafka partition placement details were unavailable for topic "
                            f"{topic}; the topic result remains valid. {str(exc)}"
                        )
                partition_snapshot = MetricRange(
                    series=tuple(partition_series),
                    collected_at=partition_collected_at,
                    is_complete=partition_complete,
                )
                topic_storage = _kafka_topic_storage_data(
                    ranking,
                    topic_snapshot=topic_snapshot,
                    partition_snapshot=partition_snapshot,
                    selected_topics=selected_topics,
                    selected_topics_complete=selected_topics_complete,
                    primary_complete=snapshot.is_complete,
                    incomplete_partition_topics=incomplete_partition_topics,
                )
                if not selected_topics_complete:
                    limitations.append(
                        "Partition details were retained for the first "
                        f"{len(selected_topics)} ranked topics."
                    )
                if topic_snapshot is not None and not topic_snapshot.is_complete:
                    limitations.append(
                        "Kafka topic byte totals reached the configured series or point ceiling."
                    )
                if partition_snapshot is not None and not partition_snapshot.is_complete:
                    limitations.append(
                        "Kafka partition details reached the configured series or point ceiling."
                    )
        if range_seconds != intent.range_seconds:
            limitations.append(
                f"The requested period was reduced to {range_seconds} seconds by the metrics range policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The metric result reached its configured series or point ceiling; the trend may be incomplete."
            )
        if not all_values:
            prerequisite = _PREREQUISITES.get(intent.metric)
            limitations.append(
                "Thanos returned no finite samples for the requested metric and scope."
                + (
                    f" This capability requires {prerequisite}; verify that it is enabled, "
                    "scraped, and uses the supported metric profile."
                    if prerequisite else ""
                )
            )
        if step_seconds != intent.step_seconds:
            limitations.append(
                f"The requested resolution was increased to {step_seconds} seconds to keep the trend bounded."
            )
        if intent.metric == "kafka_topic_disk_utilization":
            limitations.append(
                "Kafka topics share broker PVCs rather than receiving private disk allocations. "
                "This percentage compares replicated topic log bytes with aggregate allocated "
                "Kafka broker PVC capacity; inspect broker-local headroom when placement skew matters."
            )
        target = (
            "cluster" if intent.metric_scope == "cluster" else
            intent.namespace if intent.metric_scope == "namespace" else
            intent.name if intent.metric_scope in {"node", "node_role"} else
            intent.name if intent.namespace is None and intent.name else
            intent.metric_scope if intent.namespace is None and intent.name is None else
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
                "kind": intent.kind,
                "container": intent.container,
                "unit": _UNITS[intent.metric],
                "operation": intent.metric_operation,
                "statistic": intent.metric_statistic,
                "groupBy": intent.metric_group_by,
                "thresholdOperator": intent.threshold_operator,
                "thresholdValue": intent.threshold_value,
                "rangeSeconds": range_seconds,
                "stepSeconds": step_seconds,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "series": rendered_series,
                "ranking": ranking,
                "statistics": stats,
                "complete": snapshot.is_complete,
                "limit": intent.limit,
                **({"topicStorage": topic_storage} if topic_storage is not None else {}),
                **({
                    "capacityBasis": "aggregate_kafka_broker_pvc_capacity",
                    "consumptionBasis": "replicated_topic_log_bytes",
                } if intent.metric == "kafka_topic_disk_utilization" else {}),
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
