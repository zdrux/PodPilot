from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Protocol
from uuid import uuid4

import httpx
import yaml

from podpilot_diagnostics.redaction import redact_text


LOGGER = logging.getLogger(__name__)
class AgentRunnerError(RuntimeError):
    pass


_YAML_GET_OUTPUT = re.compile(
    r"(?is)(?:^|[;&|])\s*(?:oc|kubectl)\s+get\b(?:(?![;&|]).)*?"
    r"(?:-o(?:=|\s*)yaml\b|--output(?:=|\s+)yaml\b)"
)


def strip_managed_fields_from_yaml_output(command: str, output: str) -> str:
    """Remove server-side apply ownership history before YAML reaches the model."""

    if not output or not _YAML_GET_OUTPUT.search(command):
        return output
    try:
        documents = list(yaml.safe_load_all(output))
    except yaml.YAMLError:
        return output

    changed = False

    def strip(value: object) -> None:
        nonlocal changed
        if isinstance(value, dict):
            metadata = value.get("metadata")
            if isinstance(metadata, dict) and "managedFields" in metadata:
                del metadata["managedFields"]
                changed = True
            for item in value.values():
                strip(item)
        elif isinstance(value, list):
            for item in value:
                strip(item)

    for document in documents:
        strip(document)
    if not changed:
        return output
    if len(documents) == 1:
        return yaml.safe_dump(documents[0], sort_keys=False)
    return yaml.safe_dump_all(documents, sort_keys=False, explicit_start=True)


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
        *,
        request_id: str | None = None,
    ) -> AgentCommandResult: ...

    def cancel(self, request_id: str) -> bool: ...


class OcAgentRunnerClient:
    """Call the localhost-only shell hosted by the oc runner sidecar."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 310.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def execute(
        self,
        command: str,
        connection: AgentClusterConnection | None = None,
        *,
        request_id: str | None = None,
    ) -> AgentCommandResult:
        correlation_id = request_id or str(uuid4())
        try:
            payload: dict[str, object] = {
                "command": command,
                "request_id": correlation_id,
            }
            if connection is not None:
                payload["cluster"] = connection.to_payload()
            response = httpx.post(
                f"{self.base_url}/v1/execute",
                json=payload,
                timeout=self.timeout_seconds,
            )
            response_bytes = len(response.content)
            LOGGER.info(
                "podpilot.agent_runner.http_response request_id=%s status_code=%s "
                "response_bytes=%s",
                correlation_id,
                response.status_code,
                response_bytes,
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
                "The oc runner rejected the request "
                f"(HTTP {exc.response.status_code}){suffix}."
            ) from exc
        except httpx.RequestError as exc:
            raise AgentRunnerError(
                "The oc runner request failed before a response was received "
                f"({type(exc).__name__})."
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentRunnerError(
                "The oc runner returned an invalid response "
                f"({type(exc).__name__})."
            ) from exc

    def cancel(self, request_id: str) -> bool:
        """Request best-effort termination of one correlated runner command."""
        try:
            response = httpx.post(
                f"{self.base_url}/v1/cancel",
                json={"request_id": request_id},
                timeout=10.0,
            )
            if response.status_code == 404:
                return False
            response.raise_for_status()
            payload = response.json()
            return payload.get("status") == "cancellation_requested"
        except httpx.HTTPStatusError as exc:
            raise AgentRunnerError(
                "The oc runner rejected the cancellation request "
                f"(HTTP {exc.response.status_code})."
            ) from exc
        except httpx.RequestError as exc:
            raise AgentRunnerError(
                "The oc runner cancellation request failed before a response was received "
                f"({type(exc).__name__})."
            ) from exc
        except (TypeError, ValueError) as exc:
            raise AgentRunnerError(
                "The oc runner returned an invalid cancellation response "
                f"({type(exc).__name__})."
            ) from exc
