from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import urllib3
from kubernetes import client, config, watch as kubernetes_watch
from kubernetes.client.exceptions import ApiException
from kubernetes.dynamic import DynamicClient
from urllib3.exceptions import InsecureRequestWarning

from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadResult
from podpilot_diagnostics.redaction import redact_text
from podpilot_openshift.audit_logs import AuditQueryError, BoundedAuditEventReader
from podpilot_openshift.discovery import ResourceCatalog, ResourceCatalogError
from podpilot_openshift.http_probe import BoundedHttpProbe
from podpilot_openshift.log_metrics import BoundedLogVolumeReader, LogMetricsQueryError
from podpilot_openshift.metric_trends import BoundedMetricTrendReader, MetricTrendError


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


def _remote_discovery_error(exc: ApiException) -> str:
    if exc.status == 401:
        return (
            "The remote Kubernetes API rejected the configured bearer token (HTTP 401). "
            "Replace the token and test the connection again."
        )
    if exc.status == 403:
        return (
            "The remote Kubernetes API denied read-only API discovery (HTTP 403). "
            "Grant the token identity Kubernetes discovery and cluster-reader access, then retry."
        )
    status = f" (HTTP {exc.status})" if exc.status else ""
    return f"The remote Kubernetes API could not complete read-only discovery{status}."


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


def _pod_log_candidate_projection(raw: dict[str, Any], namespace: str | None) -> dict[str, Any]:
    metadata = raw.get("metadata") or {}
    spec = raw.get("spec") or {}
    status = raw.get("status") or {}
    statuses = _compact_container_statuses(
        status.get("containerStatuses") or status.get("container_statuses") or []
    )
    container_names = [
        str(item.get("name"))[:253]
        for item in statuses
        if item.get("name")
    ]
    if not container_names:
        configured = spec.get("containers") or []
        if isinstance(configured, list):
            container_names = [
                str(item.get("name"))[:253]
                for item in configured
                if isinstance(item, dict) and item.get("name")
            ][:40]
    return _sanitize({
        "namespace": metadata.get("namespace") or metadata.get("namespace_") or namespace,
        "pod": metadata.get("name"),
        "containers": container_names,
        "containerStatuses": statuses,
        "phase": status.get("phase"),
        "ready": bool(statuses) and all(item.get("ready") is True for item in statuses),
        "restartCount": max(
            (int(item.get("restartCount") or 0) for item in statuses),
            default=0,
        ),
    })


def _pod_mount_projection(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose volume wiring without exposing Secret or ConfigMap contents."""

    spec = raw.get("spec") or {}
    volumes = spec.get("volumes") or []
    sources: dict[str, dict[str, Any]] = {}
    source_fields = (
        ("secret", "Secret", ("secretName", "secret_name")),
        ("configMap", "ConfigMap", ("name",)),
        ("config_map", "ConfigMap", ("name",)),
        ("persistentVolumeClaim", "PersistentVolumeClaim", ("claimName", "claim_name")),
        ("persistent_volume_claim", "PersistentVolumeClaim", ("claimName", "claim_name")),
        ("projected", "Projected", ()),
        ("csi", "CSI", ("driver",)),
        ("emptyDir", "EmptyDir", ()),
        ("empty_dir", "EmptyDir", ()),
    )
    for volume in volumes if isinstance(volumes, list) else []:
        if not isinstance(volume, dict) or not volume.get("name"):
            continue
        source_type = "Other"
        source_name = None
        for field, label, name_fields in source_fields:
            source = volume.get(field)
            if not isinstance(source, dict):
                continue
            source_type = label
            source_name = next((source.get(key) for key in name_fields if source.get(key)), None)
            break
        sources[str(volume["name"])] = {
            "sourceType": source_type,
            "sourceName": str(source_name)[:253] if source_name else None,
        }

    result: list[dict[str, Any]] = []
    for container_type, configured in (
        ("container", spec.get("containers") or []),
        ("initContainer", spec.get("initContainers") or spec.get("init_containers") or []),
    ):
        for container in configured if isinstance(configured, list) else []:
            if not isinstance(container, dict):
                continue
            mounts = container.get("volumeMounts") or container.get("volume_mounts") or []
            for mount in mounts if isinstance(mounts, list) else []:
                if not isinstance(mount, dict):
                    continue
                volume_name = str(mount.get("name") or "")[:253]
                source = sources.get(volume_name, {})
                result.append({
                    "containerType": container_type,
                    "container": str(container.get("name") or "")[:253],
                    "mountPath": str(mount.get("mountPath") or mount.get("mount_path") or "")[:1024],
                    "volume": volume_name,
                    "readOnly": bool(mount.get("readOnly") or mount.get("read_only")),
                    "sourceType": source.get("sourceType"),
                    "sourceName": source.get("sourceName"),
                })
    return result[:100]


def _workload_config_reference_projection(
    kind: str, raw: dict[str, Any]
) -> list[dict[str, Any]]:
    """Expose referenced object names without including configuration or Secret values."""

    spec = raw.get("spec") or {}
    if kind == "CronJob":
        spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get(
            "spec"
        ) or {}
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        spec = ((spec.get("template") or {}).get("spec") or {})
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(source_type: str, name: object, container: object, mechanism: str) -> None:
        name_text = str(name or "")[:253]
        if not name_text:
            return
        key = (source_type, name_text, str(container or "")[:253], mechanism)
        if key in seen:
            return
        seen.add(key)
        references.append({
            "sourceType": source_type,
            "sourceName": name_text,
            "container": key[2],
            "mechanism": mechanism,
        })

    for container_type, configured in (
        ("container", spec.get("containers") or []),
        ("initContainer", spec.get("initContainers") or spec.get("init_containers") or []),
    ):
        for container in configured if isinstance(configured, list) else []:
            if not isinstance(container, dict):
                continue
            container_name = container.get("name")
            for source in container.get("envFrom") or container.get("env_from") or []:
                if not isinstance(source, dict):
                    continue
                config_ref = source.get("configMapRef") or source.get("config_map_ref")
                secret_ref = source.get("secretRef") or source.get("secret_ref")
                if isinstance(config_ref, dict):
                    add("ConfigMap", config_ref.get("name"), container_name, f"{container_type}.envFrom")
                if isinstance(secret_ref, dict):
                    add("Secret", secret_ref.get("name"), container_name, f"{container_type}.envFrom")
            for env in container.get("env") or []:
                if not isinstance(env, dict):
                    continue
                value_from = env.get("valueFrom") or env.get("value_from") or {}
                if not isinstance(value_from, dict):
                    continue
                config_ref = value_from.get("configMapKeyRef") or value_from.get("config_map_key_ref")
                secret_ref = value_from.get("secretKeyRef") or value_from.get("secret_key_ref")
                if isinstance(config_ref, dict):
                    add("ConfigMap", config_ref.get("name"), container_name, f"{container_type}.env")
                if isinstance(secret_ref, dict):
                    add("Secret", secret_ref.get("name"), container_name, f"{container_type}.env")
    return references[:100]


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
            "alternateBackends": spec.get("alternateBackends") or [],
            "tls": {"termination": (spec.get("tls") or {}).get("termination")},
        }
        projected["status"] = {"ingress": status.get("ingress") or []}
    elif kind == "Service":
        projected["spec"] = {
            key: spec.get(key) for key in (
                "type", "selector", "clusterIP", "externalName", "ports"
            ) if key in spec
        }
        projected["status"] = {
            "conditions": status.get("conditions") or [],
            "loadBalancer": status.get("loadBalancer") or status.get("load_balancer") or {},
        }
    elif kind == "NetworkPolicy":
        projected["spec"] = {
            "podSelector": spec.get("podSelector") or spec.get("pod_selector") or {},
            "policyTypes": spec.get("policyTypes") or spec.get("policy_types") or [],
            "ingress": spec.get("ingress") or [],
            "egress": spec.get("egress") or [],
        }
    elif kind == "EndpointSlice":
        endpoints = raw.get("endpoints") or []
        projected.update({
            "addressType": raw.get("addressType") or raw.get("address_type"),
            "ports": raw.get("ports") or [],
            "endpoints": [{
                "addresses": endpoint.get("addresses") or [],
                "conditions": endpoint.get("conditions") or {},
                "targetRef": endpoint.get("targetRef") or endpoint.get("target_ref"),
                "nodeName": endpoint.get("nodeName") or endpoint.get("node_name"),
            } for endpoint in endpoints[:100] if isinstance(endpoint, dict)],
            "podTargets": [
                endpoint.get("targetRef") or endpoint.get("target_ref")
                for endpoint in endpoints[:100]
                if isinstance(endpoint, dict)
                and isinstance(endpoint.get("targetRef") or endpoint.get("target_ref"), dict)
                and str((endpoint.get("targetRef") or endpoint.get("target_ref")).get("kind") or "")
                == "Pod"
            ],
        })
    elif kind == "Endpoints":
        subsets = raw.get("subsets") or []
        addresses = [
            address
            for subset in subsets[:50]
            if isinstance(subset, dict)
            for address in [
                *(subset.get("addresses") or []),
                *(subset.get("notReadyAddresses") or subset.get("not_ready_addresses") or []),
            ]
            if isinstance(address, dict)
        ][:100]
        projected.update({
            "subsets": [{
                "addresses": subset.get("addresses") or [],
                "notReadyAddresses": (
                    subset.get("notReadyAddresses") or subset.get("not_ready_addresses") or []
                ),
                "ports": subset.get("ports") or [],
            } for subset in subsets[:50] if isinstance(subset, dict)],
            "podTargets": [
                address.get("targetRef") or address.get("target_ref")
                for address in addresses
                if isinstance(address.get("targetRef") or address.get("target_ref"), dict)
                and str((address.get("targetRef") or address.get("target_ref")).get("kind") or "")
                == "Pod"
            ],
        })
    elif kind == "ClusterOperator":
        projected["status"] = {
            "versions": status.get("versions") or [],
            "conditions": status.get("conditions") or [],
        }
    elif kind == "Event":
        involved = raw.get("involvedObject") or raw.get("involved_object") or {}
        source = raw.get("source") or {}
        projected.update({
            "type": raw.get("type"),
            "reason": raw.get("reason"),
            "message": raw.get("message"),
            "count": raw.get("count") or raw.get("deprecated_count"),
            "firstTimestamp": raw.get("firstTimestamp") or raw.get("first_timestamp"),
            "lastTimestamp": raw.get("lastTimestamp") or raw.get("last_timestamp"),
            "eventTime": raw.get("eventTime") or raw.get("event_time"),
            "source": source,
            "involvedObject": {
                key: involved.get(key) or involved.get(_camel_to_snake(key))
                for key in ("apiVersion", "kind", "namespace", "name", "uid")
                if involved.get(key) is not None
                or involved.get(_camel_to_snake(key)) is not None
            },
        })
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


def _search_values(raw: dict[str, Any], field: str) -> tuple[str, ...]:
    """Resolve a validated object path, traversing lists at any level."""

    values: list[object] = [raw]
    for segment in field.split("."):
        next_values: list[object] = []
        for value in values:
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, dict) and segment in candidate:
                    next_values.append(candidate[segment])
        values = next_values
        if not values:
            return ()
    flattened: list[str] = []
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        flattened.extend(str(candidate) for candidate in candidates if candidate is not None)
    return tuple(flattened)


def _matches_search(raw: dict[str, Any], intent: ReadIntent) -> bool:
    assert intent.match_field and intent.match_value
    expected = intent.match_value
    case_insensitive = intent.match_field == "spec.host" or intent.match_operator == "contains"
    if case_insensitive:
        expected = expected.casefold()
    for observed in _search_values(raw, intent.match_field):
        if case_insensitive:
            observed = observed.casefold()
        matches = (
            expected in observed
            if intent.match_operator == "contains"
            else observed == expected
        )
        if matches:
            return True
    return False


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
        max_search_scan_objects: int = 2_000,
        http_probe: BoundedHttpProbe | None = None,
        metric_reader: BoundedMetricTrendReader | None = None,
        log_metric_reader: BoundedLogVolumeReader | None = None,
        audit_reader: BoundedAuditEventReader | None = None,
        watch_factory: Any = kubernetes_watch.Watch,
    ) -> None:
        self._dynamic = dynamic_client
        self._core = core_api
        self._catalog = resource_catalog
        self._max_payload_bytes = max_payload_bytes
        self._log_tail_lines = log_tail_lines
        self._max_log_bytes = max_log_bytes
        self._max_search_scan_objects = max_search_scan_objects
        self._http_probe = http_probe or BoundedHttpProbe()
        self._metric_reader = metric_reader
        self._log_metric_reader = log_metric_reader
        self._audit_reader = audit_reader
        self._watch_factory = watch_factory

    @classmethod
    def for_remote_cluster(
        cls,
        *,
        api_url: str,
        token: str,
        tls_verify: bool = True,
        **kwargs: object,
    ) -> "KubernetesReadOnlyExplorer":
        configuration = client.Configuration()
        configuration.host = api_url.rstrip("/")
        # kubernetes-client 36.x generated clients look up the BearerToken key.
        # Its legacy `authorization` alias does not carry an alias-configured
        # prefix forward, which would send the JWT without the required
        # `Bearer` scheme and cause an authenticated API to reject the request.
        configuration.api_key = {"BearerToken": token}
        configuration.api_key_prefix = {"BearerToken": "Bearer"}
        configuration.verify_ssl = tls_verify
        configuration.assert_hostname = tls_verify
        if not tls_verify:
            # The accepted risk remains visible in settings, Ask limitations, and audit
            # events. Repeating urllib3's identical warning for every request only obscures
            # actionable logs.
            urllib3.disable_warnings(InsecureRequestWarning)
        api_client = client.ApiClient(configuration)
        try:
            dynamic = DynamicClient(api_client)
        except ApiException as exc:
            raise ReadOnlyExplorerError(_remote_discovery_error(exc)) from exc
        except Exception as exc:
            raise ReadOnlyExplorerError(
                "PodPilot could not establish a remote Kubernetes API discovery session. "
                "Verify the API URL, TLS setting, and network path."
            ) from exc
        return cls(
            dynamic_client=dynamic,
            core_api=client.CoreV1Api(api_client),
            resource_catalog=ResourceCatalog(dynamic.resources.search),
            **kwargs,
        )

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
            if intent.tool == "discover_resources":
                return self._discover_resources(intent)
            if intent.tool == "http_probe":
                return self._http_probe.execute(intent)
            if intent.tool == "query_audit_events":
                if self._audit_reader is None:
                    raise ReadOnlyExplorerError(
                        "The authenticated cluster audit adapter is unavailable."
                    )
                return self._audit_reader.execute(intent)
            if intent.tool == "query_metrics":
                if intent.metric == "top_log_volume_by_namespace":
                    if self._log_metric_reader is None:
                        raise ReadOnlyExplorerError(
                            "The authenticated log analytics adapter is unavailable."
                        )
                    return self._log_metric_reader.execute(intent)
                if self._metric_reader is None:
                    raise ReadOnlyExplorerError("The authenticated monitoring adapter is unavailable.")
                return self._metric_reader.execute(intent)
            self._ensure_clients()
            if intent.tool == "pod_logs":
                return self._pod_logs(intent)
            if intent.tool == "watch_resources":
                return self._resource_watch(intent)
            return self._resource_read(intent)
        except ReadOnlyExplorerError:
            raise
        except ResourceCatalogError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except MetricTrendError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except LogMetricsQueryError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except AuditQueryError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except ApiException as exc:
            resource_name = intent.resource or intent.kind or "resource"
            action = (
                "get" if intent.tool in {"get_resource", "pod_logs"} else
                "watch" if intent.tool == "watch_resources" else "list"
            )
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
                    "OpenShift RBAC denied the configured cluster identity permission "
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

    def preflight(self, intent: ReadIntent) -> None:
        """Validate resource discovery and scope without issuing an evidence read."""

        if intent.tool not in {
            "get_resource", "list_resources", "search_resources", "watch_resources"
        }:
            return
        try:
            self._ensure_clients()
            self._resolve_resource_read(intent)
        except ReadOnlyExplorerError:
            raise
        except ResourceCatalogError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
        except Exception as exc:
            raise ReadOnlyExplorerError(
                "Kubernetes API discovery is temporarily unavailable."
            ) from exc

    def _resolve_resource_read(
        self, intent: ReadIntent
    ) -> tuple[str, str, bool | None, str | None, str | None]:
        assert self._dynamic is not None
        verb = (
            "get" if intent.tool == "get_resource" else
            "watch" if intent.tool == "watch_resources" else "list"
        )
        namespaced: bool | None = None
        if intent.resource:
            if self._catalog is None:
                self._catalog = ResourceCatalog(self._dynamic.resources.search)
            descriptor = self._catalog.resolve(
                intent.resource,
                verb=verb,
                api_version=intent.api_version,
                kind=intent.kind,
            )
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
        return api_version, kind, namespaced, namespace, name

    def _discover_resources(self, intent: ReadIntent) -> ReadResult:
        entries = self.resource_catalog(
            query=str(intent.discovery_query or ""), limit=min(intent.limit, 50)
        )
        collected_at = datetime.now(timezone.utc)
        return ReadResult(observations=(AdHocObservation(
            id=f"cluster-discovery-{uuid4()}",
            tool="discover_resources",
            summary=(
                f"Discovered {len(entries)} readable API resource type"
                f"{'s' if len(entries) != 1 else ''} relevant to "
                f"{str(intent.discovery_query or 'the investigation')[:120]}."
            ),
            source="kubernetes:api-discovery",
            collected_at=collected_at,
            data={
                "query": str(intent.discovery_query or "")[:253],
                "resources": entries,
                "count": len(entries),
                "policy": "dynamic discovery with sensitive resource types excluded",
            },
        ),))

    def _resource_watch(self, intent: ReadIntent) -> ReadResult:
        assert self._dynamic is not None
        api_version, kind, _namespaced, namespace, name = self._resolve_resource_read(intent)
        resource = self._dynamic.resources.get(api_version=api_version, kind=kind)
        watcher = self._watch_factory()
        event_limit = min(intent.limit, 50)
        kwargs: dict[str, object] = {
            "timeout": intent.watch_seconds,
            "watcher": watcher,
        }
        if namespace:
            kwargs["namespace"] = namespace
        if intent.label_selector:
            kwargs["label_selector"] = intent.label_selector
        if name:
            kwargs["name"] = name
        events: list[dict[str, object]] = []
        try:
            for event in resource.watch(**kwargs):
                if not isinstance(event, dict):
                    continue
                obj = event.get("object")
                raw = obj.to_dict() if hasattr(obj, "to_dict") else (
                    dict(obj) if isinstance(obj, dict) else {}
                )
                events.append({
                    "type": str(event.get("type") or "UNKNOWN")[:32],
                    "object": _list_projection(kind, raw),
                })
                if len(events) >= event_limit:
                    break
        finally:
            watcher.stop()
        scope = namespace or "cluster"
        collected_at = datetime.now(timezone.utc)
        limitations = (
            (f"The bounded {kind} watch reached its {event_limit}-event ceiling.",)
            if len(events) >= event_limit else ()
        )
        return ReadResult(
            observations=(AdHocObservation(
                id=f"cluster-watch-{uuid4()}",
                tool="watch_resources",
                summary=(
                    f"Observed {len(events)} {kind} change event"
                    f"{'s' if len(events) != 1 else ''} during a bounded "
                    f"{intent.watch_seconds}-second watch in {scope}."
                ),
                source=f"kubernetes:{api_version}:{kind}/watch:{scope}/{name or '*'}",
                collected_at=collected_at,
                data={
                    "apiVersion": api_version,
                    "kind": kind,
                    "scope": scope,
                    "name": name,
                    "watchSeconds": intent.watch_seconds,
                    "eventLimit": event_limit,
                    "events": events,
                },
            ),),
            limitations=limitations,
        )

    def _resource_read(self, intent: ReadIntent) -> ReadResult:
        assert self._dynamic is not None
        api_version, kind, _namespaced, namespace, name = self._resolve_resource_read(intent)
        resource = self._dynamic.resources.get(api_version=api_version, kind=kind)
        if intent.tool == "get_resource":
            obj = resource.get(name=name, namespace=namespace)
            items = [obj]
        elif intent.tool in {"list_resources", "search_resources"}:
            items = []
            token: str | None = None
            seen_tokens: set[str] = set()
            scanned = 0
            scan_limit = (
                self._max_search_scan_objects
                if intent.tool == "search_resources" else intent.limit
            )
            while scanned < scan_limit and len(items) < intent.limit:
                kwargs: dict[str, object] = {"limit": min(100, scan_limit - scanned)}
                if namespace:
                    kwargs["namespace"] = namespace
                if intent.label_selector:
                    kwargs["label_selector"] = intent.label_selector
                if token:
                    kwargs["_continue"] = token
                response = resource.get(**kwargs)
                page = list(getattr(response, "items", []) or [])
                scanned += len(page)
                if intent.tool == "search_resources":
                    for obj in page:
                        raw = obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)
                        if _matches_search(raw, intent):
                            items.append(obj)
                            if len(items) >= intent.limit:
                                break
                else:
                    items.extend(page)
                token = _continue_token(response)
                if not token:
                    break
                if token in seen_tokens:
                    break
                seen_tokens.add(token)
        else:
            raise ReadOnlyExplorerError("The requested read tool is not registered.")

        if intent.tool in {"list_resources", "search_resources"}:
            projections = []
            projected_bytes = 0
            payload_truncated = False
            log_candidates: list[dict[str, Any]] = []
            log_candidates_truncated = False
            log_candidate_bytes = 0
            log_candidate_budget = max(512, min(32_768, self._max_payload_bytes // 3))
            bounded_items = items[: intent.limit]
            object_names: list[str] = []
            object_refs: list[dict[str, str | None]] = []
            for obj in bounded_items:
                raw = obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)
                metadata = raw.get("metadata") or {}
                object_name = str(metadata.get("name") or "unnamed")[:253]
                object_namespace = metadata.get("namespace") or metadata.get("namespace_")
                object_names.append(object_name)
                object_refs.append({
                    "name": object_name,
                    "namespace": str(object_namespace)[:253] if object_namespace else None,
                })
                if kind == "Pod":
                    log_candidate = _pod_log_candidate_projection(raw, namespace)
                    candidate_bytes = len(json.dumps(
                        log_candidate, sort_keys=True, default=str
                    ).encode("utf-8"))
                    if log_candidate_bytes + candidate_bytes <= log_candidate_budget:
                        log_candidates.append(log_candidate)
                        log_candidate_bytes += candidate_bytes
                    else:
                        log_candidates_truncated = True
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
            if token and intent.tool == "list_resources":
                limitations.append(
                    f"The {kind} list reached its {intent.limit}-object collection ceiling; "
                    "additional matching resources exist."
                )
            if token and intent.tool == "search_resources":
                reason = (
                    f"the {intent.limit}-match result ceiling"
                    if len(items) >= intent.limit else
                    f"the {self._max_search_scan_objects}-object scan ceiling"
                )
                limitations.append(
                    f"The bounded {kind} search stopped at {reason}; additional objects were not scanned."
                )
            if payload_truncated:
                limitations.append(
                    f"PodPilot retained all {len(object_names)} collected {kind} names, but detailed "
                    f"status for only {len(projections)} objects fit the evidence payload ceiling."
                )
            if log_candidates_truncated:
                limitations.append(
                    "The compact Pod log-target candidate list reached its evidence payload ceiling."
                )
            if not bounded_items:
                limitations.append(f"No {kind} resources matched the bounded query.")
            summary = (
                f"Found {len(bounded_items)} matching {kind} resources after scanning {scanned} in {scope}."
                if intent.tool == "search_resources" else
                f"Read {len(bounded_items)} {kind} resources in {scope}."
            )
            return ReadResult((AdHocObservation(
                id=f"cluster-{uuid4()}",
                tool=intent.tool,
                summary=summary,
                source=f"kubernetes:{api_version}:{kind}:{scope}/*",
                collected_at=collected_at,
                data={
                    "apiVersion": api_version,
                    "kind": kind,
                    "resource": intent.resource,
                    "scope": scope,
                    "count": len(bounded_items),
                    "scannedCount": scanned,
                    "matchField": intent.match_field,
                    "matchValue": intent.match_value,
                    "matchOperator": (
                        intent.match_operator if intent.tool == "search_resources" else None
                    ),
                    "names": object_names,
                    "objects": object_refs,
                    "items": projections,
                    "logCandidates": log_candidates,
                    "logCandidatesTruncated": log_candidates_truncated,
                    "objectListComplete": not bool(token),
                    "searchComplete": (
                        not bool(token) if intent.tool == "search_resources" else None
                    ),
                    "detailsTruncated": payload_truncated,
                    "truncated": bool(token),
                },
            ),), tuple(limitations))

        observations: list[AdHocObservation] = []
        for obj in items:
            raw = obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)
            payload = _sanitize(raw)
            if isinstance(payload, dict) and kind in {
                "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
            }:
                if kind == "Pod":
                    payload["podpilotMounts"] = _pod_mount_projection(raw)
                payload["podpilotConfigReferences"] = _workload_config_reference_projection(
                    kind, raw
                )
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
