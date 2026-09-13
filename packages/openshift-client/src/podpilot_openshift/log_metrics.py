from __future__ import annotations

import json
import math
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

import httpx

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_mapping, redact_text
from podpilot_openshift.audit_logs import AuditLogEntries, AuditQueryError


class LogMetricsQueryError(RuntimeError):
    """A normalized, browser-safe Loki metric-query failure."""

    def __init__(self, message: str, *, failure_category: str = "query_failed") -> None:
        super().__init__(message)
        self.failure_category = failure_category


def _loki_transport_failure_category(exc: BaseException) -> str:
    """Classify transport failures without exposing endpoint or certificate details."""

    current: BaseException | None = exc
    seen: set[int] = set()
    details: list[str] = []
    while current is not None and id(current) not in seen and len(details) < 5:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return "tls_verification_failed"
        details.append(str(current).casefold())
        current = current.__cause__ or current.__context__
    combined = " ".join(details)
    if any(marker in combined for marker in (
        "certificate_verify_failed", "certificate verify failed",
        "self-signed certificate", "hostname mismatch",
    )):
        return "tls_verification_failed"
    return "transport_unavailable"


@dataclass(frozen=True)
class LogVolumeSample:
    bytes: float
    namespace: str | None = None
    pod: str | None = None
    node: str | None = None


@dataclass(frozen=True)
class LogVolumeSnapshot:
    samples: tuple[LogVolumeSample, ...]
    collected_at: datetime
    is_complete: bool


@dataclass(frozen=True)
class ContainerLogEntry:
    timestamp_ns: str
    line: str


@dataclass(frozen=True)
class ContainerLogSnapshot:
    entries: tuple[ContainerLogEntry, ...]
    collected_at: datetime
    is_complete: bool


class LogVolumeQuerySource(Protocol):
    def query_log_volume(self, logql: str) -> LogVolumeSnapshot: ...


class LokiQueryClient:
    """Run bounded server-authored queries through an OpenShift LokiStack gateway."""

    def __init__(
        self,
        *,
        base_url: str,
        token_path: Path | None = None,
        token: str | None = None,
        token_provider: Callable[[], str] | None = None,
        ca_path: Path | None = None,
        tls_verify: bool = True,
        route_discovery_url: str | None = None,
        route_discovery_tls_verify: bool = True,
        timeout_seconds: float = 90.0,
        max_series: int = 50,
        max_response_bytes: int = 65_536,
        tenant: str = "application",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if sum(source is not None for source in (token_path, token, token_provider)) != 1:
            raise ValueError("Configure exactly one Loki bearer-token source.")
        normalized_base_url = base_url.rstrip("/")
        self._token_path = token_path
        self._token = token
        self._token_provider = token_provider
        self._ca_path = ca_path
        self._tls_verify = tls_verify
        self._route_discovery_url = (
            route_discovery_url.rstrip("/") if route_discovery_url else None
        )
        self._route_discovery_tls_verify = route_discovery_tls_verify
        self._timeout_seconds = timeout_seconds
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_series = max_series
        self._max_response_bytes = max_response_bytes
        if tenant not in {"application", "infrastructure", "audit"}:
            raise ValueError("The Loki tenant must be application, infrastructure, or audit.")
        self._tenant = tenant
        tenant_marker = "/api/logs/v1/"
        if tenant_marker in normalized_base_url:
            tenant_root = normalized_base_url.split(tenant_marker, 1)[0]
            normalized_base_url = f"{tenant_root}{tenant_marker}{tenant}"
        self._base_url = normalized_base_url
        self._transport = transport

    @classmethod
    def for_remote_cluster(
        cls,
        *,
        api_url: str,
        token: str | None = None,
        token_provider: Callable[[], str] | None = None,
        api_tls_verify: bool = True,
        route_name: str = "logging-loki",
        tenant: str = "application",
        **kwargs: Any,
    ) -> "LokiQueryClient":
        """Discover the conventional LokiStack Route on one registered cluster."""
        kwargs.setdefault("tls_verify", api_tls_verify)
        return cls(
            base_url=f"https://logging-loki.invalid/api/logs/v1/{tenant}",
            token=token,
            token_provider=token_provider,
            tenant=tenant,
            route_discovery_url=(
                f"{api_url.rstrip('/')}"
                "/apis/route.openshift.io/v1/namespaces/openshift-logging/"
                f"routes/{route_name}"
            ),
            route_discovery_tls_verify=api_tls_verify,
            **kwargs,
        )

    def endpoint_status(self) -> dict:
        """Verify a bounded label query through the authorized adapter."""
        result = {"kind": "logging", "verified": False, "checked_at": datetime.now(timezone.utc).isoformat()}
        try:
            now = datetime.now(timezone.utc).timestamp()
            payload = self._request("/loki/api/v1/labels", {"start": str(int((now - 60) * 1e9)), "end": str(int(now * 1e9))})
            if not isinstance(payload, dict) or payload.get("status") != "success" or not isinstance(payload.get("data"), list):
                raise LogMetricsQueryError("Loki returned an unexpected label response.")
            result.update(verified=True, status="query_available")
        except Exception as exc:
            result.update(status="unavailable", error_type=type(exc).__name__)
        result["url"] = self._base_url if ".invalid" not in self._base_url else None
        return result

    def query_log_volume(self, logql: str) -> LogVolumeSnapshot:
        payload = self._request("/loki/api/v1/query", {"query": logql})
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise LogMetricsQueryError("Loki returned an unsuccessful query result.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resultType") != "vector":
            raise LogMetricsQueryError("Loki returned an unexpected query result type.")
        result = data.get("result")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise LogMetricsQueryError("Loki returned an unexpected response shape.")

        samples: list[LogVolumeSample] = []
        for item in result[: self._max_series]:
            labels = item.get("metric") if isinstance(item.get("metric"), dict) else {}
            labels = redact_mapping({
                str(key)[:128]: str(value)[:512]
                for key, value in list(labels.items())[:40]
            })
            namespace = str(
                labels.get("kubernetes_namespace_name")
                or labels.get("namespace")
                or ""
            ).strip() or None
            pod = str(
                labels.get("kubernetes_pod_name")
                or labels.get("pod")
                or ""
            ).strip() or None
            node = str(
                labels.get("kubernetes_host")
                or labels.get("kubernetes_node_name")
                or labels.get("node")
                or labels.get("nodename")
                or ""
            ).strip() or None
            raw_value = item.get("value")
            if not isinstance(raw_value, list) or len(raw_value) != 2:
                continue
            try:
                value = float(raw_value[1])
            except (TypeError, ValueError):
                continue
            if math.isfinite(value) and value >= 0:
                samples.append(LogVolumeSample(
                    bytes=value, namespace=namespace, pod=pod, node=node,
                ))
        return LogVolumeSnapshot(
            samples=tuple(samples),
            collected_at=datetime.now(timezone.utc),
            is_complete=len(result) <= self._max_series,
        )

    def query_namespace_volume(self, logql: str) -> LogVolumeSnapshot:
        """Compatibility wrapper for callers predating scoped log-volume metrics."""

        return self.query_log_volume(logql)

    def query_container_logs(
        self,
        *,
        namespace: str,
        pod: str,
        container: str,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> ContainerLogSnapshot:
        """Read exact-container logs without accepting arbitrary LogQL."""

        if self._tenant not in {"application", "infrastructure"}:
            raise LogMetricsQueryError("Container log queries require a Loki log tenant.")
        name_pattern = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")
        if not all(name_pattern.fullmatch(value or "") for value in (namespace, pod, container)):
            raise LogMetricsQueryError("Loki container logs require exact Kubernetes resource names.")
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise LogMetricsQueryError("Loki container logs require a valid timezone-aware range.")
        if (end - start).total_seconds() > 86_400:
            raise LogMetricsQueryError("Loki container log range exceeds the 24-hour safety limit.")
        if not 1 <= limit <= 5_000:
            raise LogMetricsQueryError("Loki container log limit must be between 1 and 5000 lines.")
        selectors = ",".join((
            f"kubernetes_namespace_name={json.dumps(namespace)}",
            f"kubernetes_pod_name={json.dumps(pod)}",
            f"kubernetes_container_name={json.dumps(container)}",
        ))
        payload = self._request("/loki/api/v1/query_range", {
            "query": "{" + selectors + "}",
            "start": str(int(start.timestamp() * 1_000_000_000)),
            "end": str(int(end.timestamp() * 1_000_000_000)),
            "limit": str(limit),
            "direction": "backward",
        })
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise LogMetricsQueryError("Loki returned an unsuccessful container log result.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resultType") != "streams":
            raise LogMetricsQueryError("Loki returned an unexpected container log result type.")
        result = data.get("result")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise LogMetricsQueryError("Loki returned an unexpected container log response shape.")
        entries = []
        for stream in result[:self._max_series]:
            values = stream.get("values")
            if not isinstance(values, list):
                continue
            for value in values:
                if (isinstance(value, list) and len(value) == 2
                        and isinstance(value[0], str) and isinstance(value[1], str)):
                    entries.append(ContainerLogEntry(timestamp_ns=value[0], line=value[1]))
        entries.sort(key=lambda item: item.timestamp_ns, reverse=True)
        complete = len(result) <= self._max_series and len(entries) < limit
        return ContainerLogSnapshot(
            entries=tuple(entries[:limit]),
            collected_at=datetime.now(timezone.utc),
            is_complete=complete,
        )

    def query_audit_entries(
        self,
        logql: str,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> AuditLogEntries:
        if self._tenant != "audit":
            raise AuditQueryError("Audit queries require the Loki audit tenant.")
        try:
            payload = self._request("/loki/api/v1/query_range", {
                "query": logql,
                "start": str(int(start.timestamp() * 1_000_000_000)),
                "end": str(int(end.timestamp() * 1_000_000_000)),
                "limit": str(limit),
                "direction": "backward",
            })
        except LogMetricsQueryError as exc:
            raise AuditQueryError(str(exc)) from exc
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise AuditQueryError("Loki returned an unsuccessful audit query result.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resultType") != "streams":
            raise AuditQueryError("Loki returned an unexpected audit query result type.")
        result = data.get("result")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise AuditQueryError("Loki returned an unexpected audit response shape.")
        complete = len(result) <= self._max_series
        entries: list[tuple[str, str]] = []
        for stream in result[: self._max_series]:
            values = stream.get("values")
            if not isinstance(values, list):
                continue
            for value in values:
                if (
                    isinstance(value, list)
                    and len(value) == 2
                    and isinstance(value[0], str)
                    and isinstance(value[1], str)
                ):
                    entries.append((value[0], value[1]))
        entries.sort(key=lambda item: item[0], reverse=True)
        if len(entries) >= limit:
            complete = False
        return AuditLogEntries(entries=tuple(entries[:limit]), is_complete=complete)

    def _request(self, path: str, params: dict[str, str]) -> Any:
        try:
            token = (
                self._token_path.read_text(encoding="utf-8").strip()
                if self._token_path is not None
                else self._token_provider().strip()
                if self._token_provider is not None
                else (self._token or "").strip()
            )
            if not token:
                raise LogMetricsQueryError("The logging bearer token is unavailable.")
            base_url = self._resolve_base_url(token)
            verify: bool | str = self._tls_verify
            if self._tls_verify and self._ca_path is not None:
                verify = str(self._ca_path)
            with httpx.Client(
                verify=verify,
                timeout=self._timeout,
                transport=self._transport,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            ) as client:
                with client.stream("GET", f"{base_url}{path}", params=params) as response:
                    response.raise_for_status()
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_response_bytes:
                            raise LogMetricsQueryError(
                                "Loki returned more data than this check permits."
                            )
            return json.loads(body)
        except LogMetricsQueryError:
            raise
        except httpx.TimeoutException as exc:
            raise LogMetricsQueryError(
                f"The Loki query exceeded the configured {self._timeout_seconds:g}-second timeout.",
                failure_category="timeout",
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                message = "The logging API rejected the configured bearer token."
            elif exc.response.status_code == 403:
                tenant_label = {
                    "audit": "audit-log",
                    "infrastructure": "infrastructure-log",
                    "application": "application-log analytics",
                }[self._tenant]
                role = {
                    "audit": "cluster-logging-audit-view",
                    "infrastructure": "cluster-logging-infrastructure-view",
                    "application": "cluster-logging-application-view",
                }[self._tenant]
                message = (
                    f"The cluster denied {tenant_label} access (HTTP 403). Grant the PodPilot identity "
                    f"{role} and verify LokiStack tenant authorization."
                )
            elif exc.response.status_code == 404:
                message = "The configured logging endpoint does not expose the expected Loki API."
            else:
                message = "The LokiStack gateway returned an HTTP error."
            raise LogMetricsQueryError(message) from exc
        except (OSError, httpx.HTTPError, ValueError) as exc:
            failure_category = _loki_transport_failure_category(exc)
            message = (
                "TLS certificate verification failed while connecting to the LokiStack gateway."
                if failure_category == "tls_verification_failed" else
                "The LokiStack gateway transport is unavailable."
            )
            raise LogMetricsQueryError(
                message, failure_category=failure_category,
            ) from exc

    def _resolve_base_url(self, token: str) -> str:
        if self._route_discovery_url is None:
            return self._base_url
        try:
            with httpx.Client(
                verify=self._route_discovery_tls_verify,
                timeout=self._timeout,
                transport=self._transport,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            ) as client:
                response = client.get(self._route_discovery_url)
                response.raise_for_status()
                payload = response.json()
        except httpx.TimeoutException as exc:
            raise LogMetricsQueryError(
                "The remote cluster's LokiStack Route discovery exceeded the configured "
                f"{self._timeout_seconds:g}-second timeout."
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                message = "The remote Kubernetes API rejected the configured bearer token."
            elif exc.response.status_code == 403:
                message = "The remote cluster denied access to the LokiStack Route (HTTP 403)."
            elif exc.response.status_code == 404:
                message = "The remote cluster does not expose the logging-loki Route."
            else:
                message = "The remote cluster could not return its LokiStack Route."
            raise LogMetricsQueryError(message) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise LogMetricsQueryError(
                "The remote cluster's LokiStack Route could not be discovered."
            ) from exc
        if not isinstance(payload, dict):
            raise LogMetricsQueryError("The remote cluster returned an invalid LokiStack Route.")
        spec = payload.get("spec") if isinstance(payload.get("spec"), dict) else {}
        host = spec.get("host")
        if not isinstance(host, str) or not host.strip():
            status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
            ingress = status.get("ingress") if isinstance(status.get("ingress"), list) else []
            first = ingress[0] if ingress and isinstance(ingress[0], dict) else {}
            host = first.get("host")
        if not isinstance(host, str) or not host.strip():
            raise LogMetricsQueryError("The remote LokiStack Route has no admitted host.")
        self._base_url = f"https://{host.strip()}/api/logs/v1/{self._tenant}"
        self._route_discovery_url = None
        return self._base_url


class BoundedLogVolumeReader:
    """Compile registered application-log volume intents into server-owned LogQL."""

    def __init__(
        self,
        source: LogVolumeQuerySource,
        *,
        max_range_seconds: int = 604_800,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._source = source
        self._max_range_seconds = max_range_seconds
        self._clock = clock

    def endpoint_status(self) -> dict:
        return self._source.endpoint_status()

    def container_logs(self, intent: ReadIntent) -> ReadResult:
        end = self._clock()
        start = end - timedelta(seconds=min(intent.range_seconds, 86400, self._max_range_seconds))
        snapshot = self._source.query_container_logs(namespace=intent.namespace, pod=intent.name,
            container=intent.container, start=start, end=end, limit=min(intent.tail_lines or intent.limit, 200))
        entries, remaining = [], 32768
        for entry in snapshot.entries:
            try:
                at = datetime.fromtimestamp(int(entry.timestamp_ns) / 1e9, timezone.utc)
            except (ValueError, OverflowError, OSError):
                continue
            if not start <= at <= end:
                continue
            line = entry.line
            try:
                document = json.loads(line)
                if isinstance(document, dict) and isinstance(document.get("message"), str):
                    line = document["message"]
            except ValueError:
                pass
            line = redact_text(line)[:2000]
            encoded = line.encode("utf-8")
            if len(encoded) > remaining:
                break
            remaining -= len(encoded)
            entries.append({"timestamp": at.isoformat(), "message": line})
        limitations = ["Retained logs may have gaps. Empty results do not prove the absence of failures.",
                      "Queries use exact namespace/Pod/container names; retained entries without UID may span Pod replacements."]
        if intent.tail_lines and intent.tail_lines > 200:
            limitations.append("Requested log line count exceeds the Loki collector cap of 200 entries.")
        if not snapshot.is_complete or len(entries) != len(snapshot.entries):
            limitations.append("Log collection reached a result, time, or byte boundary; history is partial.")
        return ReadResult((AdHocObservation(id=f"loki-{uuid4()}", tool="pod_logs",
            summary=f"Collected {len(entries)} retained log entries for {intent.namespace}/{intent.name}/{intent.container}.",
            source=f"loki:application:{intent.namespace}/{intent.name}/{intent.container}", collected_at=snapshot.collected_at,
            data={"backend": "loki", "namespace": intent.namespace, "name": intent.name, "container": intent.container,
                  "start": start.isoformat(), "end": end.isoformat(), "entries": entries,
                  "tail": "\n".join(e["timestamp"] + " " + e["message"] for e in entries)}),), tuple(limitations))

    def execute(self, intent: ReadIntent) -> ReadResult:
        namespace_ranking = (
            intent.metric == "top_log_volume_by_namespace"
            and intent.metric_scope == "cluster"
        )
        if intent.tool != "query_metrics" or not (
            namespace_ranking or intent.metric == "application_log_volume"
        ):
            raise ValueError(
                "BoundedLogVolumeReader requires a registered application-log volume intent."
            )
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        dimensions = (
            ("namespace",) if namespace_ranking else tuple(intent.metric_group_by)
        )
        loki_dimensions = {
            "namespace": "kubernetes_namespace_name",
            "pod": "kubernetes_pod_name",
            "node": "kubernetes_host",
        }
        selectors = ['log_type="application"']
        if intent.namespace:
            selectors.append(
                f'kubernetes_namespace_name={json.dumps(intent.namespace)}'
            )
        if intent.metric_scope == "pod" and intent.name:
            selectors.append(f'kubernetes_pod_name={json.dumps(intent.name)}')
        if intent.metric_scope == "node" and intent.name:
            selectors.append(f'kubernetes_host={json.dumps(intent.name)}')
        selector = "{" + ",".join(selectors) + "}"
        volume = f"bytes_over_time({selector}[{range_seconds}s])"
        if dimensions:
            group_labels = ", ".join(loki_dimensions[item] for item in dimensions)
            query = f"topk({intent.limit}, sum by ({group_labels}) ({volume}))"
        else:
            query = f"sum({volume})"
        snapshot = self._source.query_log_volume(query)
        ranked = sorted(snapshot.samples, key=lambda item: item.bytes, reverse=True)[: intent.limit]
        end = self._clock()
        start = end - timedelta(seconds=range_seconds)
        ranking: list[dict[str, object]] = []
        for item in ranked:
            labels = {
                key: value for key, value in {
                    "namespace": item.namespace,
                    "pod": item.pod,
                    "node": item.node,
                }.items() if value
            }
            if not dimensions:
                if intent.namespace:
                    labels.setdefault("namespace", intent.namespace)
                if intent.metric_scope == "pod" and intent.name:
                    labels.setdefault("pod", intent.name)
                if intent.metric_scope == "node" and intent.name:
                    labels.setdefault("node", intent.name)
            if dimensions and any(not labels.get(item) for item in dimensions):
                continue
            ranking.append({
                "labels": labels,
                "current": item.bytes,
                "average": item.bytes / range_seconds,
                "maximum": None,
            })
        limitations: list[str] = []
        if range_seconds != intent.range_seconds:
            limitations.append(
                f"The requested period was reduced to {range_seconds} seconds by the log analytics policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The Loki result reached its configured series ceiling; the result may be incomplete."
            )
        if not ranking:
            limitations.append(
                "Loki returned no application-log volume samples for the requested period."
            )
        metric = str(intent.metric)
        scope_label = str(intent.metric_scope).replace("_", " ")
        action = "Ranked" if dimensions else "Read"
        return ReadResult(observations=(AdHocObservation(
            id=f"log-metric-{uuid4()}",
            tool="query_metrics",
            summary=f"{action} application-log payload volume for the requested {scope_label} scope.",
            source=f"loki:application/query/{metric}",
            collected_at=snapshot.collected_at,
            data={
                "metric": metric,
                "scope": intent.metric_scope,
                "namespace": intent.namespace,
                "name": intent.name,
                "logType": "application",
                "unit": "bytes",
                "averageUnit": "bytes_per_second",
                "rangeSeconds": range_seconds,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "ranking": ranking,
                "operation": "rank" if dimensions else "show",
                "groupBy": list(dimensions),
                "complete": snapshot.is_complete,
                "limit": intent.limit if dimensions else 1,
            },
        ),), limitations=tuple(limitations))
