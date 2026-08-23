from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import httpx


class AlertSourceError(RuntimeError):
    """A normalized, browser-safe Alertmanager collection failure."""


@dataclass(frozen=True)
class AlertRecord:
    fingerprint: str
    state: str
    labels: dict[str, str]
    annotations: dict[str, str]
    starts_at: datetime | None
    ends_at: datetime | None
    updated_at: datetime | None
    silenced_by: tuple[str, ...]
    inhibited_by: tuple[str, ...]

    @property
    def name(self) -> str:
        return self.labels.get("alertname", "UnnamedAlert")

    @property
    def severity(self) -> str:
        return self.labels.get("severity", "unknown")

    @property
    def namespace(self) -> str | None:
        return self.labels.get("namespace")

    @property
    def is_watchdog(self) -> bool:
        return self.name == "Watchdog"

    @property
    def is_silenced(self) -> bool:
        return bool(self.silenced_by)

    @property
    def is_inhibited(self) -> bool:
        return bool(self.inhibited_by)


@dataclass(frozen=True)
class AlertSnapshot:
    alerts: tuple[AlertRecord, ...]
    collected_at: datetime


class AlertSource(Protocol):
    def fetch(self) -> AlertSnapshot: ...


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _bounded_strings(value: Any, *, limit: int) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in list(value.items())[:limit]:
        result[str(key)[:128]] = str(item)[:2048]
    return result


class AlertmanagerClient:
    def __init__(
        self,
        *,
        base_url: str,
        token_path: Path,
        ca_path: Path,
        timeout_seconds: float = 8.0,
        max_alerts: int = 250,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_path = token_path
        self._ca_path = ca_path
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_alerts = max_alerts

    def fetch(self) -> AlertSnapshot:
        try:
            token = self._token_path.read_text(encoding="utf-8").strip()
            with httpx.Client(
                verify=str(self._ca_path),
                timeout=self._timeout,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            ) as client:
                response = client.get(f"{self._base_url}/api/v2/alerts")
                response.raise_for_status()
                payload = response.json()
        except (OSError, httpx.HTTPError, ValueError) as exc:
            raise AlertSourceError("Alertmanager is temporarily unavailable.") from exc

        if not isinstance(payload, list):
            raise AlertSourceError("Alertmanager returned an unexpected response shape.")

        alerts = tuple(self._normalize(item) for item in payload[: self._max_alerts] if isinstance(item, dict))
        return AlertSnapshot(alerts=alerts, collected_at=datetime.now(timezone.utc))

    @staticmethod
    def _normalize(item: dict[str, Any]) -> AlertRecord:
        status = item.get("status") if isinstance(item.get("status"), dict) else {}
        fingerprint = str(item.get("fingerprint") or "")[:128]
        if not fingerprint:
            fingerprint = "missing-fingerprint"
        return AlertRecord(
            fingerprint=fingerprint,
            state=str(status.get("state") or "unknown")[:32],
            labels=_bounded_strings(item.get("labels"), limit=40),
            annotations=_bounded_strings(item.get("annotations"), limit=20),
            starts_at=_parse_datetime(item.get("startsAt")),
            ends_at=_parse_datetime(item.get("endsAt")),
            updated_at=_parse_datetime(item.get("updatedAt")),
            silenced_by=tuple(str(value)[:128] for value in (status.get("silencedBy") or [])[:20]),
            inhibited_by=tuple(str(value)[:128] for value in (status.get("inhibitedBy") or [])[:20]),
        )
