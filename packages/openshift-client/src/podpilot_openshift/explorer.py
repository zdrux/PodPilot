from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.dynamic import DynamicClient

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_text


class ReadOnlyExplorerError(RuntimeError):
    """A safe error from the ad-hoc evidence boundary."""


_IDENTIFIER = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$")
_API_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*(?:/[A-Za-z0-9][A-Za-z0-9.-]*)?$")
_DENIED_KINDS = {
    "secret",
    "tokenrequest",
    "tokenreview",
    "subjectaccessreview",
    "selfsubjectaccessreview",
    "selfsubjectrulesreview",
    "localsubjectaccessreview",
}
_SENSITIVE_KEYS = re.compile(
    r"(?i)^(?:.*(?:password|passwd|token|secret|api[_-]?key|private[_-]?key).*)$"
)


def _safe_identifier(value: str | None, label: str, *, required: bool = True) -> str | None:
    if not value:
        if required:
            raise ReadOnlyExplorerError(f"The {label} is required for this read tool.")
        return None
    if not _IDENTIFIER.fullmatch(value):
        raise ReadOnlyExplorerError(f"The requested {label} is not a valid Kubernetes identifier.")
    return value


def _safe_api_version(value: str | None) -> str:
    if not value or not _API_VERSION.fullmatch(value):
        raise ReadOnlyExplorerError("The requested apiVersion is not valid.")
    return value


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 10:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:200]:
            text_key = str(key)[:253]
            if text_key == "managedFields":
                continue
            result[text_key] = (
                "[REDACTED]" if _SENSITIVE_KEYS.match(text_key) else _sanitize(item, depth=depth + 1)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return redact_text(value)[:8192]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))[:2048]


class KubernetesReadOnlyExplorer:
    """Executes a small, deny-by-default set of bounded Kubernetes reads."""

    def __init__(
        self,
        *,
        dynamic_client: DynamicClient | None = None,
        core_api: client.CoreV1Api | None = None,
        max_payload_bytes: int = 48_000,
        log_tail_lines: int = 250,
        max_log_bytes: int = 24_000,
    ) -> None:
        self._dynamic = dynamic_client
        self._core = core_api
        self._max_payload_bytes = max_payload_bytes
        self._log_tail_lines = log_tail_lines
        self._max_log_bytes = max_log_bytes

    def _ensure_clients(self) -> None:
        if self._dynamic is not None and self._core is not None:
            return
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        self._dynamic = DynamicClient(api_client)
        self._core = client.CoreV1Api(api_client)

    def execute(self, intent: ReadIntent) -> ReadResult:
        try:
            self._ensure_clients()
            if intent.tool == "pod_logs":
                return self._pod_logs(intent)
            return self._resource_read(intent)
        except ReadOnlyExplorerError:
            raise
        except ApiException as exc:
            target = (
                f"Pod {intent.namespace}/{intent.name} logs"
                if intent.tool == "pod_logs"
                else f"{intent.kind or 'resource'} {intent.namespace or 'cluster'}/{intent.name or '*'}"
            )
            if exc.status == 403:
                detail = f"The investigator identity is not authorized to read {target}."
            elif exc.status == 404:
                detail = f"The requested {target} was not found."
            elif exc.status == 400 and intent.tool == "pod_logs":
                detail = (
                    f"Kubernetes rejected the log request for {target}; verify the container name "
                    "and whether the requested current or previous log stream exists."
                )
            else:
                status = f" (HTTP {exc.status})" if exc.status else ""
                detail = f"The Kubernetes API could not provide {target}{status}."
            raise ReadOnlyExplorerError(detail) from exc
        except Exception as exc:
            raise ReadOnlyExplorerError(
                "The requested cluster evidence could not be collected because the Kubernetes API client failed."
            ) from exc

    def _resource_read(self, intent: ReadIntent) -> ReadResult:
        assert self._dynamic is not None
        api_version = _safe_api_version(intent.api_version)
        kind = _safe_identifier(intent.kind, "kind")
        namespace = _safe_identifier(intent.namespace, "namespace", required=False)
        name = _safe_identifier(intent.name, "resource name", required=intent.tool == "get_resource")
        assert kind
        if kind.lower() in _DENIED_KINDS or "/" in kind:
            raise ReadOnlyExplorerError("That resource type is outside the read-only evidence policy.")
        resource = self._dynamic.resources.get(api_version=api_version, kind=kind)
        if intent.tool == "get_resource":
            obj = resource.get(name=name, namespace=namespace)
            items = [obj]
        elif intent.tool == "list_resources":
            kwargs: dict[str, object] = {"limit": min(intent.limit, 50)}
            if namespace:
                kwargs["namespace"] = namespace
            if intent.label_selector:
                kwargs["label_selector"] = intent.label_selector
            response = resource.get(**kwargs)
            items = list(getattr(response, "items", []) or [])[: min(intent.limit, 50)]
        else:
            raise ReadOnlyExplorerError("The requested read tool is not registered.")

        observations: list[AdHocObservation] = []
        for obj in items:
            raw = obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)
            payload = _sanitize(raw)
            encoded = json.dumps(payload, sort_keys=True, default=str)
            truncated = len(encoded.encode("utf-8")) > self._max_payload_bytes
            if truncated:
                encoded = encoded.encode("utf-8")[: self._max_payload_bytes].decode("utf-8", "ignore")
                payload = {"truncated_json": encoded, "truncated": True}
            metadata = getattr(obj, "metadata", None)
            object_name = str(getattr(metadata, "name", None) or name or "unnamed")[:253]
            object_namespace = str(getattr(metadata, "namespace", None) or namespace or "cluster")[:253]
            observations.append(
                AdHocObservation(
                    id=f"cluster-{uuid4()}",
                    tool=intent.tool,
                    summary=f"Read {kind} {object_namespace}/{object_name}.",
                    source=f"kubernetes:{api_version}:{kind}:{object_namespace}/{object_name}",
                    collected_at=datetime.now(timezone.utc),
                    data=payload,
                )
            )
        limitation = () if observations else (f"No {kind} resources matched the bounded query.",)
        return ReadResult(tuple(observations), limitation)

    def _pod_logs(self, intent: ReadIntent) -> ReadResult:
        assert self._core is not None
        namespace = _safe_identifier(intent.namespace, "namespace")
        name = _safe_identifier(intent.name, "Pod name")
        container = _safe_identifier(intent.container, "container", required=False)
        assert namespace and name
        previous = bool(intent.previous)
        limitations: tuple[str, ...] = ()
        try:
            text = self._read_pod_log(
                name=name, namespace=namespace, container=container, previous=previous
            )
        except ApiException as exc:
            body = str(getattr(exc, "body", "") or "").lower()
            if not (previous and exc.status == 400 and "previous terminated container" in body):
                raise
            text = self._read_pod_log(
                name=name, namespace=namespace, container=container, previous=False
            )
            previous = False
            limitations = (
                "Previous logs were not retained for this Pod/container; bounded current logs were collected instead.",
            )
        decoded = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
        redacted = redact_text(decoded)[-self._max_log_bytes :]
        qualifier = "previous " if previous else "current "
        return ReadResult((AdHocObservation(
            id=f"cluster-{uuid4()}",
            tool="pod_logs",
            summary=f"Collected bounded {qualifier}logs for Pod {namespace}/{name}.",
            source=f"kubernetes:v1:Pod/log:{namespace}/{name}?{'previous' if previous else 'current'}",
            collected_at=datetime.now(timezone.utc),
            data={"container": container, "previous": previous, "tail": redacted},
        ),), limitations)

    def _read_pod_log(
        self, *, name: str, namespace: str, container: str | None, previous: bool
    ) -> str | bytes:
        assert self._core is not None
        return self._core.read_namespaced_pod_log(
            name,
            namespace,
            container=container,
            previous=previous,
            tail_lines=self._log_tail_lines,
            timestamps=True,
            _request_timeout=8,
        )
