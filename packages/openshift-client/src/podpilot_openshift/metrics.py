from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

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


class MonitoringQuerySource(Protocol):
    def query(self, promql: str) -> MetricSnapshot: ...


class ThanosQueryClient:
    """Run bounded, instant PromQL queries against OpenShift Thanos Querier."""

    def __init__(
        self,
        *,
        base_url: str,
        token_path: Path,
        ca_path: Path,
        timeout_seconds: float = 8.0,
        max_series: int = 20,
        max_response_bytes: int = 65_536,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_path = token_path
        self._ca_path = ca_path
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_series = max_series
        self._max_response_bytes = max_response_bytes
        self._transport = transport

    def query(self, promql: str) -> MetricSnapshot:
        try:
            token = self._token_path.read_text(encoding="utf-8").strip()
            with httpx.Client(
                verify=str(self._ca_path),
                timeout=self._timeout,
                transport=self._transport,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            ) as client:
                with client.stream(
                    "GET",
                    f"{self._base_url}/api/v1/query",
                    params={"query": promql},
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
        except (OSError, httpx.HTTPError, ValueError) as exc:
            raise MonitoringQueryError("Thanos Querier is temporarily unavailable.") from exc

        result = self._validate_payload(payload)
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

    @staticmethod
    def _validate_payload(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise MonitoringQueryError("Thanos returned an unsuccessful query result.")
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("resultType") != "vector":
            raise MonitoringQueryError("Thanos returned an unexpected query result type.")
        result = data.get("result")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise MonitoringQueryError("Thanos returned an unexpected response shape.")
        return result

    @staticmethod
    def _normalize_sample(item: dict[str, Any], *, fallback_time: datetime) -> MetricSample:
        metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
        raw_value = item.get("value")
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
        labels = redact_mapping(
            {
                str(key)[:128]: str(value)[:512]
                for key, value in list(metric.items())[:40]
            }
        )
        return MetricSample(labels=labels, value=value, observed_at=timestamp)
