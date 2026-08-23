from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from kubernetes import client, config
from kubernetes.dynamic import DynamicClient

from podpilot_diagnostics.redaction import redact_text
from podpilot_diagnostics.workloads import (
    ContainerEvidence,
    EventEvidence,
    NodeEvidence,
    OwnerEvidence,
    WorkloadEvidence,
)


class WorkloadEvidenceSource(Protocol):
    def collect(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str | None,
        include_logs: bool,
        include_nodes: bool,
    ) -> WorkloadEvidence: ...


class WorkloadEvidenceError(RuntimeError):
    """A normalized, browser-safe Kubernetes evidence collection failure."""


def _timestamp(value: Any) -> datetime | None:
    return value if isinstance(value, datetime) else None


def _state(status: Any) -> tuple[str, str | None, str | None]:
    state = getattr(status, "state", None)
    for name in ("waiting", "terminated", "running"):
        value = getattr(state, name, None)
        if value is not None:
            return (
                name,
                redact_text(str(getattr(value, "reason", "") or "")) or None,
                redact_text(str(getattr(value, "message", "") or "")) or None,
            )
    return "unknown", None, None


class KubernetesWorkloadClient:
    def __init__(
        self,
        *,
        core_api: client.CoreV1Api | None = None,
        dynamic_client: DynamicClient | None = None,
        max_events: int = 30,
        log_tail_lines: int = 200,
        max_log_bytes: int = 16_384,
    ) -> None:
        self._core = core_api
        self._dynamic = dynamic_client
        self._max_events = max_events
        self._log_tail_lines = log_tail_lines
        self._max_log_bytes = max_log_bytes

    def _ensure_clients(self) -> None:
        if self._core is not None and self._dynamic is not None:
            return
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        self._core = client.CoreV1Api(api_client)
        self._dynamic = DynamicClient(api_client)

    def collect(
        self,
        *,
        namespace: str,
        pod_name: str,
        container_name: str | None,
        include_logs: bool,
        include_nodes: bool,
    ) -> WorkloadEvidence:
        try:
            self._ensure_clients()
        except Exception as exc:
            raise WorkloadEvidenceError("The Kubernetes API is temporarily unavailable.") from exc
        assert self._core is not None
        failures: list[str] = []
        try:
            pod = self._core.read_namespaced_pod(pod_name, namespace)
        except Exception as exc:
            raise WorkloadEvidenceError(
                "The alert-selected Pod could not be read from the Kubernetes API."
            ) from exc
        statuses = tuple(
            self._container(item)
            for item in (getattr(pod.status, "container_statuses", None) or [])[:20]
        )
        selected = container_name or (statuses[0].name if statuses else None)

        events: tuple[EventEvidence, ...] = ()
        try:
            response = self._core.list_namespaced_event(
                namespace,
                field_selector=f"involvedObject.uid={pod.metadata.uid}",
                limit=self._max_events,
            )
            normalized = [self._event(item) for item in (response.items or [])]
            normalized.sort(
                key=lambda item: item.observed_at or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            events = tuple(normalized[: self._max_events])
        except Exception:
            failures.append("Recent Pod events could not be collected.")

        owners = self._owners(pod, namespace, failures)
        nodes = self._nodes(failures) if include_nodes else ()
        current_logs: dict[str, str] = {}
        previous_logs: dict[str, str] = {}
        if include_logs and selected:
            self._logs(namespace, pod_name, selected, current_logs, previous_logs, failures)

        conditions = tuple(
            f"{str(item.type)[:64]}={str(item.status)[:16]}"
            + (f" ({redact_text(str(item.reason))[:128]})" if item.reason else "")
            for item in (getattr(pod.status, "conditions", None) or [])[:20]
        )
        requests: dict[str, str] = {}
        for container_spec in (getattr(pod.spec, "containers", None) or [])[:20]:
            resources = getattr(container_spec, "resources", None)
            for key, value in (getattr(resources, "requests", None) or {}).items():
                requests[str(key)[:32]] = str(value)[:64]

        return WorkloadEvidence(
            namespace=namespace[:253],
            pod_name=pod_name[:253],
            pod_uid=str(pod.metadata.uid)[:128],
            phase=str(getattr(pod.status, "phase", "unknown"))[:32],
            node_name=(str(pod.spec.node_name)[:253] if pod.spec.node_name else None),
            requests=requests,
            conditions=conditions,
            containers=statuses,
            events=events,
            owners=owners,
            nodes=nodes,
            current_logs=current_logs,
            previous_logs=previous_logs,
            collected_at=datetime.now(timezone.utc),
            failures=tuple(failures),
            pod_resource_version=str(pod.metadata.resource_version)[:128],
        )

    @staticmethod
    def _container(item: Any) -> ContainerEvidence:
        state, reason, message = _state(item)
        last = getattr(getattr(item, "last_state", None), "terminated", None)
        return ContainerEvidence(
            name=str(item.name)[:253],
            image=redact_text(str(item.image))[:2048],
            ready=bool(item.ready),
            restart_count=max(0, int(item.restart_count or 0)),
            state=state,
            reason=reason,
            message=message,
            last_reason=(redact_text(str(last.reason))[:128] if last and last.reason else None),
            last_exit_code=(int(last.exit_code) if last and last.exit_code is not None else None),
        )

    @staticmethod
    def _event(item: Any) -> EventEvidence:
        observed_at = (
            _timestamp(getattr(item, "event_time", None))
            or _timestamp(getattr(item, "last_timestamp", None))
            or _timestamp(getattr(item.metadata, "creation_timestamp", None))
        )
        return EventEvidence(
            id=f"event-{str(item.metadata.uid)[:36]}",
            reason=redact_text(str(item.reason or "Unknown"))[:128],
            message=redact_text(str(item.message or ""))[:2048],
            event_type=str(item.type or "Unknown")[:32],
            observed_at=observed_at,
            source=f"kubernetes:event/{str(item.metadata.name)[:253]}",
        )

    def _owners(self, pod: Any, namespace: str, failures: list[str]) -> tuple[OwnerEvidence, ...]:
        assert self._dynamic is not None
        result: list[OwnerEvidence] = []
        current = pod
        for _ in range(3):
            metadata = getattr(current, "metadata", None)
            references = (
                getattr(metadata, "owner_references", None)
                or getattr(metadata, "ownerReferences", None)
                or []
            )
            reference = next(
                (item for item in references if getattr(item, "controller", False)),
                None,
            )
            if reference is None:
                break
            api_version = getattr(reference, "api_version", None) or getattr(
                reference, "apiVersion", None
            )
            base = OwnerEvidence(
                str(api_version)[:128],
                str(reference.kind)[:64],
                str(reference.name)[:253],
                None,
                None,
                None,
                str(getattr(reference, "uid", "") or "")[:128],
                "",
            )
            try:
                resource = self._dynamic.resources.get(
                    api_version=api_version,
                    kind=reference.kind,
                )
                current = resource.get(name=reference.name, namespace=namespace)
                spec = getattr(current, "spec", None)
                status = getattr(current, "status", None)
                result.append(
                    OwnerEvidence(
                        api_version=base.api_version,
                        kind=base.kind,
                        name=base.name,
                        desired_replicas=getattr(spec, "replicas", None),
                        ready_replicas=(
                            getattr(status, "readyReplicas", None)
                            if status is not None
                            else None
                        ),
                        updated_replicas=(
                            getattr(status, "updatedReplicas", None)
                            if status is not None
                            else None
                        ),
                        uid=str(getattr(current.metadata, "uid", "") or base.uid)[:128],
                        resource_version=str(
                            getattr(current.metadata, "resourceVersion", None)
                            or getattr(current.metadata, "resource_version", "")
                            or ""
                        )[:128],
                    )
                )
            except Exception:
                failures.append("The owning controller chain could not be fully collected.")
                result.append(base)
                break
        return tuple(result)

    def _nodes(self, failures: list[str]) -> tuple[NodeEvidence, ...]:
        assert self._core is not None
        try:
            response = self._core.list_node(limit=50)
        except Exception:
            failures.append("Node scheduling constraints could not be collected.")
            return ()
        result: list[NodeEvidence] = []
        for item in (response.items or [])[:50]:
            allocatable = getattr(item.status, "allocatable", None) or {}
            taints = tuple(
                f"{taint.key}={taint.value or ''}:{taint.effect}"
                for taint in (getattr(item.spec, "taints", None) or [])[:20]
            )
            result.append(
                NodeEvidence(
                    name=str(item.metadata.name)[:253],
                    allocatable={
                        key: str(allocatable[key])[:64]
                        for key in ("cpu", "memory", "pods")
                        if key in allocatable
                    },
                    taints=taints,
                    unschedulable=bool(getattr(item.spec, "unschedulable", False)),
                )
            )
        return tuple(result)

    def _logs(
        self,
        namespace: str,
        pod_name: str,
        container_name: str,
        current: dict[str, str],
        previous: dict[str, str],
        failures: list[str],
    ) -> None:
        assert self._core is not None
        for is_previous, target in ((False, current), (True, previous)):
            try:
                text = self._core.read_namespaced_pod_log(
                    pod_name,
                    namespace,
                    container=container_name,
                    previous=is_previous,
                    tail_lines=self._log_tail_lines,
                    timestamps=True,
                    _request_timeout=8,
                )
                target[container_name] = redact_text(str(text)[-self._max_log_bytes :])
            except Exception:
                label = "Previous" if is_previous else "Current"
                failures.append(f"{label} logs were unavailable for container {container_name[:253]}.")
