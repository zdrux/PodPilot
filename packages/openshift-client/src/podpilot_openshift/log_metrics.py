from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

import httpx

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_mapping
from podpilot_openshift.audit_logs import AuditLogEntries, AuditQueryError


class LogMetricsQueryError(RuntimeError):
    """A normalized, browser-safe Loki metric-query failure."""


@dataclass(frozen=True)
class LogVolumeSample:
    namespace: str
    bytes: float


@dataclass(frozen=True)
class LogVolumeSnapshot:
    samples: tuple[LogVolumeSample, ...]
    collected_at: datetime
    is_complete: bool


class LogVolumeQuerySource(Protocol):
    def query_namespace_volume(self, logql: str) -> LogVolumeSnapshot: ...


class LokiQueryClient:
    """Run bounded aggregate-only queries through an OpenShift LokiStack gateway."""

    def __init__(
        self,
        *,
        base_url: str,
        token_path: Path | None = None,
        token: str | None = None,
        ca_path: Path | None = None,
        tls_verify: bool = True,
        route_discovery_url: str | None = None,
        route_discovery_tls_verify: bool = True,
        timeout_seconds: float = 30.0,
        max_series: int = 50,
        max_response_bytes: int = 65_536,
        tenant: str = "application",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if (token_path is None) == (token is None):
            raise ValueError("Configure exactly one Loki bearer-token source.")
        normalized_base_url = base_url.rstrip("/")
        self._token_path = token_path
        self._token = token
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
        if tenant not in {"application", "audit"}:
            raise ValueError("The Loki tenant must be application or audit.")
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
        token: str,
        api_tls_verify: bool = True,
        route_name: str = "logging-loki",
        tenant: str = "application",
        **kwargs: Any,
    ) -> "LokiQueryClient":
        """Discover the conventional LokiStack Route on one registered cluster."""
        return cls(
            base_url=f"https://logging-loki.invalid/api/logs/v1/{tenant}",
            token=token,
            tenant=tenant,
            route_discovery_url=(
                f"{api_url.rstrip('/')}"
                "/apis/route.openshift.io/v1/namespaces/openshift-logging/"
                f"routes/{route_name}"
            ),
            route_discovery_tls_verify=api_tls_verify,
            **kwargs,
        )

    def query_namespace_volume(self, logql: str) -> LogVolumeSnapshot:
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
            ).strip()
            raw_value = item.get("value")
            if not namespace or not isinstance(raw_value, list) or len(raw_value) != 2:
                continue
            try:
                value = float(raw_value[1])
            except (TypeError, ValueError):
                continue
            if math.isfinite(value) and value >= 0:
                samples.append(LogVolumeSample(namespace=namespace, bytes=value))
        return LogVolumeSnapshot(
            samples=tuple(samples),
            collected_at=datetime.now(timezone.utc),
            is_complete=len(result) <= self._max_series,
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
                f"The Loki query exceeded the configured {self._timeout_seconds:g}-second timeout."
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                message = "The logging API rejected the configured bearer token."
            elif exc.response.status_code == 403:
                tenant_label = (
                    "audit-log" if self._tenant == "audit" else "application-log analytics"
                )
                role = (
                    "cluster-logging-audit-view"
                    if self._tenant == "audit" else "cluster-logging-application-view"
                )
                message = (
                    f"The cluster denied {tenant_label} access. Grant the PodPilot identity "
                    f"{role} and verify LokiStack tenant authorization."
                )
            elif exc.response.status_code == 404:
                message = "The configured logging endpoint does not expose the expected Loki API."
            else:
                message = "The LokiStack gateway returned an HTTP error."
            raise LogMetricsQueryError(message) from exc
        except (OSError, httpx.HTTPError, ValueError) as exc:
            raise LogMetricsQueryError("The LokiStack gateway is temporarily unavailable.") from exc

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
                message = "The remote cluster denied access to the LokiStack Route."
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
    """Compile the registered namespace-volume intent into server-owned LogQL."""

    def __init__(
        self,
        source: LogVolumeQuerySource,
        *,
        max_range_seconds: int = 86_400,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._source = source
        self._max_range_seconds = max_range_seconds
        self._clock = clock

    def execute(self, intent: ReadIntent) -> ReadResult:
        if (
            intent.tool != "query_metrics"
            or intent.metric != "top_log_volume_by_namespace"
            or intent.metric_scope != "cluster"
        ):
            raise ValueError(
                "BoundedLogVolumeReader requires a cluster top_log_volume_by_namespace intent."
            )
        range_seconds = min(intent.range_seconds, self._max_range_seconds)
        query = (
            f"topk({intent.limit}, sum by (kubernetes_namespace_name) "
            f"(bytes_over_time({{log_type=\"application\"}}[{range_seconds}s])))"
        )
        snapshot = self._source.query_namespace_volume(query)
        ranked = sorted(snapshot.samples, key=lambda item: item.bytes, reverse=True)[: intent.limit]
        end = self._clock()
        start = end - timedelta(seconds=range_seconds)
        ranking = [{
            "labels": {"namespace": item.namespace},
            "current": item.bytes,
            "average": item.bytes / range_seconds,
            "maximum": None,
        } for item in ranked]
        limitations: list[str] = []
        if range_seconds != intent.range_seconds:
            limitations.append(
                f"The requested period was reduced to {range_seconds} seconds by the log analytics policy."
            )
        if not snapshot.is_complete:
            limitations.append(
                "The Loki result reached its configured namespace ceiling; the ranking may be incomplete."
            )
        if not ranking:
            limitations.append(
                "Loki returned no application-log volume samples for the requested period."
            )
        return ReadResult(observations=(AdHocObservation(
            id=f"log-metric-{uuid4()}",
            tool="query_metrics",
            summary="Ranked namespaces by application-log payload volume.",
            source="loki:application/query/top_log_volume_by_namespace",
            collected_at=snapshot.collected_at,
            data={
                "metric": "top_log_volume_by_namespace",
                "scope": "cluster",
                "logType": "application",
                "unit": "bytes",
                "averageUnit": "bytes_per_second",
                "rangeSeconds": range_seconds,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "ranking": ranking,
                "complete": snapshot.is_complete,
                "limit": intent.limit,
            },
        ),), limitations=tuple(limitations))
