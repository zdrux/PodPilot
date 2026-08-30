from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

import httpx

from podpilot_diagnostics.redaction import redact_mapping


class MonitoringQueryError(RuntimeError):
    """A normalized, browser-safe monitoring query failure."""


@dataclass(frozen=True)
class MetricSample:
    labels: dict[str, str]
    value: float | None
    observed_at: datetime


@dataclass(frozen=True)
class MetricSnapshot:
    samples: tuple[MetricSample, ...]
    collected_at: datetime
    is_complete: bool


@dataclass(frozen=True)
class MetricPoint:
    observed_at: datetime
    value: float | None


@dataclass(frozen=True)
class MetricSeries:
    labels: dict[str, str]
    points: tuple[MetricPoint, ...]


@dataclass(frozen=True)
class MetricRange:
    series: tuple[MetricSeries, ...]
    collected_at: datetime
    is_complete: bool


class MonitoringQuerySource(Protocol):
    def query(self, promql: str) -> MetricSnapshot: ...


class MonitoringRangeQuerySource(Protocol):
    def query_range(
        self, promql: str, *, start: datetime, end: datetime, step_seconds: int
    ) -> MetricRange: ...


class ThanosQueryClient:
    """Run bounded instant and range queries against OpenShift Thanos Querier."""

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
        timeout_seconds: float = 8.0,
        max_series: int = 20,
        max_points_per_series: int = 300,
        max_response_bytes: int = 1_048_576,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if sum(source is not None for source in (token_path, token, token_provider)) != 1:
            raise ValueError("Configure exactly one Thanos bearer-token source.")
        self._base_url = base_url.rstrip("/")
        self._token_path = token_path
        self._token = token
        self._token_provider = token_provider
        self._ca_path = ca_path
        self._tls_verify = tls_verify
        self._route_discovery_url = (
            route_discovery_url.rstrip("/") if route_discovery_url else None
        )
        self._route_discovery_tls_verify = route_discovery_tls_verify
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_series = max_series
        self._max_points_per_series = max_points_per_series
        self._max_response_bytes = max_response_bytes
        self._transport = transport

    @classmethod
    def for_remote_cluster(
        cls,
        *,
        api_url: str,
        token: str | None = None,
        token_provider: Callable[[], str] | None = None,
        api_tls_verify: bool = True,
        **kwargs: Any,
    ) -> "ThanosQueryClient":
        """Discover and query the supported external Thanos Route on one cluster."""
        return cls(
            base_url="https://thanos-querier.invalid",
            token=token,
            token_provider=token_provider,
            route_discovery_url=(
                f"{api_url.rstrip('/')}"
                "/apis/route.openshift.io/v1/namespaces/openshift-monitoring/"
                "routes/thanos-querier"
            ),
            route_discovery_tls_verify=api_tls_verify,
            **kwargs,
        )

    def query(self, promql: str) -> MetricSnapshot:
        payload = self._request("/api/v1/query", {"query": promql})
        result = self._validate_payload(payload, result_type="vector")
        collected_at = datetime.now(timezone.utc)
        samples = tuple(
            self._normalize_sample(item, fallback_time=collected_at)
            for item in result[: self._max_series]
        )
        return MetricSnapshot(
            samples=samples,
            collected_at=collected_at,
            is_complete=len(result) <= self._max_series,
        )

    def query_range(
        self, promql: str, *, start: datetime, end: datetime, step_seconds: int
    ) -> MetricRange:
        payload = self._request("/api/v1/query_range", {
            "query": promql,
            "start": str(start.timestamp()),
            "end": str(end.timestamp()),
            "step": str(step_seconds),
        })
        result = self._validate_payload(payload, result_type="matrix")
        collected_at = datetime.now(timezone.utc)
        complete = len(result) <= self._max_series
        series: list[MetricSeries] = []
        for item in result[: self._max_series]:
            raw_values = item.get("values")
            if not isinstance(raw_values, list):
                raise MonitoringQueryError("Thanos returned an unexpected response shape.")
            if len(raw_values) > self._max_points_per_series:
                complete = False
            points = tuple(
                self._normalize_point(value, fallback_time=collected_at)
                for value in raw_values[: self._max_points_per_series]
            )
            series.append(MetricSeries(
                labels=self._normalize_labels(item),
                points=points,
            ))
        return MetricRange(tuple(series), collected_at, complete)

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
                raise MonitoringQueryError("The monitoring bearer token is unavailable.")
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
                with client.stream(
                    "GET",
                    f"{base_url}{path}",
                    params=params,
                ) as response:
                    response.raise_for_status()
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_response_bytes:
                            raise MonitoringQueryError(
                                "Thanos returned more data than this check permits."
                            )
            payload = json.loads(body)
        except MonitoringQueryError:
            raise
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                message = "The remote monitoring API rejected the configured bearer token."
            elif exc.response.status_code == 403:
                message = (
                    "The remote cluster denied monitoring access (HTTP 403). Grant the registered "
                    "identity the cluster-monitoring-view role."
                )
            elif exc.response.status_code == 404:
                message = (
                    "The configured monitoring endpoint does not expose the expected "
                    "Thanos API."
                )
            else:
                message = "Thanos Querier returned an HTTP error."
            raise MonitoringQueryError(message) from exc
        except (OSError, httpx.HTTPError, ValueError) as exc:
            raise MonitoringQueryError("Thanos Querier is temporarily unavailable.") from exc
        return payload

    def _resolve_base_url(self, token: str) -> str:
        if self._route_discovery_url is None:
            return self._base_url
        try:
            with httpx.Client(
                verify=self._route_discovery_tls_verify,
                timeout=self._timeout,
                transport=self._transport,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            ) as client:
                response = client.get(self._route_discovery_url)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                message = "The remote Kubernetes API rejected the configured bearer token."
            elif exc.response.status_code == 403:
                message = (
                    "The remote cluster denied access to the Thanos Route in "
                    "openshift-monitoring (HTTP 403)."
                )
            elif exc.response.status_code == 404:
                message = "The remote cluster does not expose a Thanos Querier Route."
            else:
                message = "The remote cluster could not return its Thanos Querier Route."
            raise MonitoringQueryError(message) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise MonitoringQueryError(
                "The remote cluster's Thanos Querier Route could not be discovered."
            ) from exc
        if not isinstance(payload, dict):
            raise MonitoringQueryError(
                "The remote cluster returned an invalid Thanos Querier Route."
            )
        spec = payload.get("spec") if isinstance(payload.get("spec"), dict) else {}
        host = spec.get("host")
        if not isinstance(host, str) or not host.strip():
            status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
            ingress = status.get("ingress") if isinstance(status.get("ingress"), list) else []
            first = ingress[0] if ingress and isinstance(ingress[0], dict) else {}
            host = first.get("host")
        if not isinstance(host, str) or not host.strip():
            raise MonitoringQueryError(
                "The remote Thanos Querier Route does not have an admitted host."
            )
        self._base_url = f"https://{host.strip()}"
        self._route_discovery_url = None
        return self._base_url

    @staticmethod
    def _validate_payload(payload: Any, *, result_type: str) -> list[dict[str, Any]]:
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise MonitoringQueryError("Thanos returned an unsuccessful query result.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resultType") != result_type:
            raise MonitoringQueryError("Thanos returned an unexpected query result type.")
        result = data.get("result")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise MonitoringQueryError("Thanos returned an unexpected response shape.")
        return result

    @staticmethod
    def _normalize_sample(item: dict[str, Any], *, fallback_time: datetime) -> MetricSample:
        raw_value = item.get("value")
        point = ThanosQueryClient._normalize_point(raw_value, fallback_time=fallback_time)
        return MetricSample(
            labels=ThanosQueryClient._normalize_labels(item),
            value=point.value,
            observed_at=point.observed_at,
        )

    @staticmethod
    def _normalize_labels(item: dict[str, Any]) -> dict[str, str]:
        metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
        return redact_mapping({
            str(key)[:128]: str(value)[:512]
            for key, value in list(metric.items())[:40]
        })

    @staticmethod
    def _normalize_point(raw_value: Any, *, fallback_time: datetime) -> MetricPoint:
        timestamp = fallback_time
        value: float | None = None
        if isinstance(raw_value, list) and len(raw_value) == 2:
            try:
                timestamp = datetime.fromtimestamp(float(raw_value[0]), tz=timezone.utc)
            except (TypeError, ValueError, OSError):
                timestamp = fallback_time
            try:
                parsed = float(raw_value[1])
                value = parsed if math.isfinite(parsed) else None
            except (TypeError, ValueError):
                value = None
        return MetricPoint(observed_at=timestamp, value=value)
