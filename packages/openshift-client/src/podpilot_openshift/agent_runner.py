from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from podpilot_diagnostics.redaction import redact_text


class AgentRunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentClusterConnection:
    cluster_id: str
    cluster_name: str
    api_url: str
    tls_verify: bool
    token: str | None = field(default=None, repr=False)
    proxy_url: str | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "id": self.cluster_id,
            "name": self.cluster_name,
            "tls_verify": self.tls_verify,
        }
        if self.proxy_url:
            payload["proxy_url"] = self.proxy_url
        else:
            payload["api_url"] = self.api_url
            payload["token"] = self.token or ""
        return payload


@dataclass(frozen=True)
class AgentCommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    request_id: str | None = None
    duration_ms: int | None = None
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "request_id": self.request_id,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


class AgentRunner(Protocol):
    def execute(
        self,
        command: str,
        connection: AgentClusterConnection | None = None,
    ) -> AgentCommandResult: ...


class OcAgentRunnerClient:
    """Call the localhost-only shell hosted by the oc runner sidecar."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 310.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def execute(
        self,
        command: str,
        connection: AgentClusterConnection | None = None,
    ) -> AgentCommandResult:
        try:
            payload: dict[str, object] = {"command": command}
            if connection is not None:
                payload["cluster"] = connection.to_payload()
            response = httpx.post(
                f"{self.base_url}/v1/execute",
                json=payload,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            return AgentCommandResult(
                command=command,
                exit_code=int(payload["exit_code"]),
                stdout=str(payload.get("stdout") or ""),
                stderr=str(payload.get("stderr") or ""),
                request_id=str(payload.get("request_id") or "") or None,
                duration_ms=(
                    int(payload["duration_ms"])
                    if payload.get("duration_ms") is not None else None
                ),
                timed_out=bool(payload.get("timed_out")),
                stdout_truncated=bool(payload.get("stdout_truncated")),
                stderr_truncated=bool(payload.get("stderr_truncated")),
            )
        except httpx.HTTPStatusError as exc:
            detail = ""
            try:
                response_payload = exc.response.json()
                if isinstance(response_payload, dict):
                    detail = redact_text(str(response_payload.get("error") or ""))[:500]
            except (TypeError, ValueError):
                pass
            suffix = f": {detail}" if detail else ""
            raise AgentRunnerError(
                "The unrestricted oc runner rejected the request "
                f"(HTTP {exc.response.status_code}){suffix}."
            ) from exc
        except httpx.RequestError as exc:
            raise AgentRunnerError(
                "The unrestricted oc runner request failed before a response was received "
                f"({type(exc).__name__})."
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentRunnerError(
                "The unrestricted oc runner returned an invalid response "
                f"({type(exc).__name__})."
            ) from exc
