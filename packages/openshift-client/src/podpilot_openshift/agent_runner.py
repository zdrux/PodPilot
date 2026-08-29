from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx


class AgentRunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentClusterConnection:
    cluster_id: str
    cluster_name: str
    api_url: str
    token: str = field(repr=False)
    tls_verify: bool

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.cluster_id,
            "name": self.cluster_name,
            "api_url": self.api_url,
            "token": self.token,
            "tls_verify": self.tls_verify,
        }


@dataclass(frozen=True)
class AgentCommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
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
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise AgentRunnerError(
                f"The unrestricted oc runner did not return a usable result ({type(exc).__name__})."
            ) from exc
