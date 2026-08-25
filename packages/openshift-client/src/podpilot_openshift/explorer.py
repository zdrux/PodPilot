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
from podpilot_openshift.discovery import ResourceCatalog, ResourceCatalogError


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
    "oauthaccesstoken",
    "oauthauthorizetoken",
    "useroauthaccesstoken",
    "identity",
    "user",
    "group",
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


def _metadata_projection(raw: dict[str, Any]) -> dict[str, Any]:
    metadata = raw.get("metadata") or {}
    return _sanitize({
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "generation": metadata.get("generation"),
        "creationTimestamp": metadata.get("creationTimestamp") or metadata.get("creation_timestamp"),
        "labels": metadata.get("labels") or {},
        "ownerReferences": metadata.get("ownerReferences") or metadata.get("owner_references") or [],
    })


def _compact_conditions(conditions: object) -> list[dict[str, Any]]:
    if not isinstance(conditions, list):
        return []
    return [{
        key: condition.get(key) or condition.get(_camel_to_snake(key))
        for key in ("type", "status", "reason", "lastTransitionTime")
        if condition.get(key) is not None or condition.get(_camel_to_snake(key)) is not None
    } for condition in conditions[:20] if isinstance(condition, dict)]


def _camel_to_snake(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def _compact_container_statuses(statuses: object) -> list[dict[str, Any]]:
    if not isinstance(statuses, list):
        return []
    compact = []
    for status in statuses[:40]:
        if not isinstance(status, dict):
            continue
        state = status.get("state") or {}
        state_summary: dict[str, Any] = {}
        if isinstance(state, dict):
            for state_name in ("waiting", "running", "terminated"):
                state_value = state.get(state_name)
                if isinstance(state_value, dict):
                    state_summary[state_name] = {
                        key: state_value.get(key) or state_value.get(_camel_to_snake(key))
                        for key in ("reason", "exitCode", "signal", "startedAt", "finishedAt")
                        if state_value.get(key) is not None
                        or state_value.get(_camel_to_snake(key)) is not None
                    }
        compact.append({
            "name": status.get("name"),
            "ready": status.get("ready"),
            "restartCount": status.get("restartCount") or status.get("restart_count") or 0,
            "state": state_summary,
        })
    return compact


def _list_projection(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    metadata = _metadata_projection(raw)
    spec = raw.get("spec") or {}
    status = raw.get("status") or {}
    projected: dict[str, Any] = {"metadata": metadata}
    if kind == "Pod":
        projected["spec"] = {"nodeName": spec.get("nodeName") or spec.get("node_name")}
        projected["status"] = {
            "phase": status.get("phase"),
            "conditions": _compact_conditions(status.get("conditions") or []),
            "containerStatuses": _compact_container_statuses(
                status.get("containerStatuses") or status.get("container_statuses") or []
            ),
        }
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        projected["spec"] = {"replicas": spec.get("replicas")}
        projected["status"] = {
            key: status.get(key) for key in (
                "replicas", "readyReplicas", "availableReplicas", "updatedReplicas",
                "currentReplicas", "numberReady", "desiredNumberScheduled",
            ) if key in status
        }
        projected["status"]["conditions"] = status.get("conditions") or []
    elif kind == "Job":
        projected["spec"] = {
            "completions": spec.get("completions"),
            "parallelism": spec.get("parallelism"),
            "backoffLimit": spec.get("backoffLimit") or spec.get("backoff_limit"),
        }
        projected["status"] = {
            key: status.get(key) for key in ("active", "succeeded", "failed", "startTime", "completionTime")
            if key in status
        }
        projected["status"]["conditions"] = status.get("conditions") or []
    elif kind == "Route":
        projected["spec"] = {
            "host": spec.get("host"), "to": spec.get("to"), "port": spec.get("port"),
            "tls": {"termination": (spec.get("tls") or {}).get("termination")},
        }
        projected["status"] = {"ingress": status.get("ingress") or []}
    elif kind == "ClusterOperator":
        projected["status"] = {
            "versions": status.get("versions") or [],
            "conditions": status.get("conditions") or [],
        }
    elif kind in {"PersistentVolume", "PersistentVolumeClaim"}:
        projected["spec"] = {
            key: spec.get(key) for key in (
                "storageClassName", "capacity", "accessModes", "volumeName", "claimRef"
            ) if key in spec
        }
        projected["status"] = {"phase": status.get("phase"), "capacity": status.get("capacity")}
    elif kind == "StorageClass":
        projected.update({
            "provisioner": raw.get("provisioner"),
            "reclaimPolicy": raw.get("reclaimPolicy") or raw.get("reclaim_policy"),
            "volumeBindingMode": raw.get("volumeBindingMode") or raw.get("volume_binding_mode"),
            "allowVolumeExpansion": raw.get("allowVolumeExpansion") or raw.get("allow_volume_expansion"),
        })
    elif kind == "Node":
        projected["spec"] = {
            "unschedulable": spec.get("unschedulable"), "taints": spec.get("taints") or []
        }
        projected["status"] = {
            "conditions": status.get("conditions") or [],
            "capacity": status.get("capacity") or {},
            "allocatable": status.get("allocatable") or {},
        }
    else:
        projected["status"] = {"conditions": status.get("conditions") or []}
    return _sanitize(projected)


def _continue_token(response: object) -> str | None:
    metadata = getattr(response, "metadata", None)
    if metadata is None:
        return None
    if isinstance(metadata, dict):
        return str(metadata.get("continue") or metadata.get("continue_") or "") or None
    return str(getattr(metadata, "continue_", None) or getattr(metadata, "continue", None) or "") or None


class KubernetesReadOnlyExplorer:
    """Executes a small, deny-by-default set of bounded Kubernetes reads."""

    def __init__(
        self,
        *,
        dynamic_client: DynamicClient | None = None,
        core_api: client.CoreV1Api | None = None,
        resource_catalog: ResourceCatalog | None = None,
        max_payload_bytes: int = 48_000,
        log_tail_lines: int = 250,
        max_log_bytes: int = 24_000,
    ) -> None:
        self._dynamic = dynamic_client
        self._core = core_api
        self._catalog = resource_catalog
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
        self._catalog = ResourceCatalog(self._dynamic.resources.search)

    def resource_catalog(self, *, query: str = "", limit: int = 120) -> list[dict[str, object]]:
        self._ensure_clients()
        assert self._dynamic is not None
        if self._catalog is None:
            self._catalog = ResourceCatalog(self._dynamic.resources.search)
        try:
            return self._catalog.prompt_entries(query=query, limit=limit)
        except ResourceCatalogError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except Exception as exc:
            raise ReadOnlyExplorerError(
                "Kubernetes API discovery is temporarily unavailable."
            ) from exc

    def execute(self, intent: ReadIntent) -> ReadResult:
        try:
            self._ensure_clients()
            if intent.tool == "pod_logs":
                return self._pod_logs(intent)
            return self._resource_read(intent)
        except ReadOnlyExplorerError:
            raise
        except ResourceCatalogError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except ApiException as exc:
            resource_name = intent.resource or intent.kind or "resource"
            action = "get" if intent.tool in {"get_resource", "pod_logs"} else "list"
            if intent.tool == "pod_logs":
                resource_name = "pods/log"
            scope = (
                f"in namespace {intent.namespace}"
                if intent.namespace else "at cluster-wide scope"
            )
            target = f"{resource_name} {scope}"
            if intent.name:
                target += f" for {intent.name}"
            if exc.status == 403:
                detail = (
                    "OpenShift RBAC denied the podpilot-investigator ServiceAccount permission "
                    f"to {action} {target} (HTTP 403). An administrator must grant that read "
                    "permission before PodPilot can collect this evidence."
                )
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
        verb = "get" if intent.tool == "get_resource" else "list"
        namespaced: bool | None = None
        if intent.resource:
            if self._catalog is None:
                self._catalog = ResourceCatalog(self._dynamic.resources.search)
            descriptor = self._catalog.resolve(intent.resource, verb=verb)
            api_version = descriptor.api_version
            kind = descriptor.kind
            namespaced = descriptor.namespaced
        else:
            api_version = _safe_api_version(intent.api_version)
            kind = _safe_identifier(intent.kind, "kind")
        namespace = _safe_identifier(intent.namespace, "namespace", required=False)
        name = _safe_identifier(intent.name, "resource name", required=intent.tool == "get_resource")
        assert kind
        if kind.lower() in _DENIED_KINDS or "/" in kind:
            raise ReadOnlyExplorerError("That resource type is outside the read-only evidence policy.")
        if namespaced is False and namespace:
            raise ReadOnlyExplorerError("The requested cluster-scoped resource must not include a namespace.")
        if namespaced is True and intent.tool == "get_resource" and not namespace:
            raise ReadOnlyExplorerError("A namespace is required to read that namespaced resource by name.")
        resource = self._dynamic.resources.get(api_version=api_version, kind=kind)
        if intent.tool == "get_resource":
            obj = resource.get(name=name, namespace=namespace)
            items = [obj]
        elif intent.tool == "list_resources":
            items = []
            token: str | None = None
            seen_tokens: set[str] = set()
            while len(items) < intent.limit:
                kwargs: dict[str, object] = {"limit": min(100, intent.limit - len(items))}
                if namespace:
                    kwargs["namespace"] = namespace
                if intent.label_selector:
                    kwargs["label_selector"] = intent.label_selector
                if token:
                    kwargs["_continue"] = token
                response = resource.get(**kwargs)
                items.extend(list(getattr(response, "items", []) or []))
                token = _continue_token(response)
                if not token:
                    break
                if token in seen_tokens:
                    break
                seen_tokens.add(token)
        else:
            raise ReadOnlyExplorerError("The requested read tool is not registered.")

        if intent.tool == "list_resources":
            projections = []
            projected_bytes = 0
            payload_truncated = False
            bounded_items = items[: intent.limit]
            object_names: list[str] = []
            for obj in bounded_items:
                raw = obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)
                metadata = raw.get("metadata") or {}
                object_names.append(str(metadata.get("name") or "unnamed")[:253])
                projection = _list_projection(kind, raw)
                projection_bytes = len(json.dumps(
                    projection, sort_keys=True, default=str
                ).encode("utf-8"))
                if projected_bytes + projection_bytes > self._max_payload_bytes:
                    payload_truncated = True
                else:
                    projections.append(projection)
                    projected_bytes += projection_bytes
            scope = namespace or "cluster"
            collected_at = datetime.now(timezone.utc)
            limitations = []
            if token:
                limitations.append(
                    f"The {kind} list reached its {intent.limit}-object collection ceiling; "
                    "additional matching resources exist."
                )
            if payload_truncated:
                limitations.append(
                    f"PodPilot retained all {len(object_names)} collected {kind} names, but detailed "
                    f"status for only {len(projections)} objects fit the evidence payload ceiling."
                )
            if not bounded_items:
                limitations.append(f"No {kind} resources matched the bounded query.")
            return ReadResult((AdHocObservation(
                id=f"cluster-{uuid4()}",
                tool="list_resources",
                summary=f"Read {len(bounded_items)} {kind} resources in {scope}.",
                source=f"kubernetes:{api_version}:{kind}:{scope}/*",
                collected_at=collected_at,
                data={
                    "apiVersion": api_version,
                    "kind": kind,
                    "resource": intent.resource,
                    "scope": scope,
                    "count": len(bounded_items),
                    "names": object_names,
                    "items": projections,
                    "objectListComplete": not bool(token),
                    "detailsTruncated": payload_truncated,
                    "truncated": bool(token),
                },
            ),), tuple(limitations))

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
        return ReadResult(tuple(observations))

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
