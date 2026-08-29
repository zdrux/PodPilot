from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx


class AgentRunnerError(RuntimeError):
    pass


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
    def execute(self, command: str) -> AgentCommandResult: ...


class OcAgentRunnerClient:
    """Call the localhost-only shell hosted by the oc runner sidecar."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def execute(self, command: str) -> AgentCommandResult:
        try:
            response = httpx.post(
                f"{self.base_url}/v1/execute",
                json={"command": command},
                timeout=None,
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
