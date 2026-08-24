from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubernetes import client, config

from podpilot_diagnostics.checks import (
    CheckObservation,
    DiagnosticCheckResult,
    DiagnosticCheckSpec,
)
from podpilot_diagnostics.redaction import redact_text


def _ready(pod: Any) -> bool:
    return any(
        str(getattr(item, "type", "")) == "Ready"
        and str(getattr(item, "status", "")) == "True"
        for item in (getattr(getattr(pod, "status", None), "conditions", None) or [])
    )


class KubernetesDiagnosticCheckExecutor:
    """Execute only registered, read-only Kubernetes diagnostic checks."""

    def __init__(
        self,
        *,
        core_api: client.CoreV1Api | None = None,
        discovery_api: client.DiscoveryV1Api | None = None,
        max_pods: int = 20,
        max_events: int = 30,
    ) -> None:
        self._core = core_api
        self._discovery = discovery_api
        self._max_pods = max_pods
        self._max_events = max_events

    def _ensure_clients(self) -> None:
        if self._core is not None and self._discovery is not None:
            return
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        self._core = client.CoreV1Api(api_client)
        self._discovery = client.DiscoveryV1Api(api_client)

    def run(self, spec: DiagnosticCheckSpec) -> DiagnosticCheckResult:
        if spec.tool_name not in {"inspect_service_topology", "inspect_target_events"}:
            return DiagnosticCheckResult(
                status="failed",
                summary="The requested diagnostic tool is not registered.",
                observations=(),
                limitations=("No Kubernetes request was made.",),
            )
        try:
            self._ensure_clients()
            if spec.tool_name == "inspect_service_topology":
                return self._topology(spec)
            return self._events(spec)
        except Exception:
            return DiagnosticCheckResult(
                status="failed",
                summary="The Kubernetes API was unavailable for this bounded check.",
                observations=(),
                limitations=("Retry the check after cluster API health is restored.",),
            )

    def _service_and_pods(self, spec: DiagnosticCheckSpec) -> tuple[Any, list[Any], str]:
        assert self._core is not None
        service = self._core.read_namespaced_service(spec.service_name, spec.namespace)
        selector = getattr(getattr(service, "spec", None), "selector", None) or {}
        selector_text = ",".join(f"{key}={value}" for key, value in sorted(selector.items()))
        pods = (
            list(
                (
                    self._core.list_namespaced_pod(
                        spec.namespace,
                        label_selector=selector_text,
                        limit=self._max_pods,
                    ).items
                    or []
                )[: self._max_pods]
            )
            if selector_text
            else []
        )
        return service, pods, selector_text

    def _topology(self, spec: DiagnosticCheckSpec) -> DiagnosticCheckResult:
        assert self._discovery is not None
        now = datetime.now(timezone.utc)
        service, pods, selector_text = self._service_and_pods(spec)
        slices = list(
            (
                self._discovery.list_namespaced_endpoint_slice(
                    spec.namespace,
                    label_selector=f"kubernetes.io/service-name={spec.service_name}",
                    limit=20,
                ).items
                or []
            )[:20]
        )
        endpoints = [endpoint for item in slices for endpoint in (item.endpoints or [])[:100]]
        ready_endpoints = sum(
            getattr(getattr(item, "conditions", None), "ready", None) is not False
            for item in endpoints
        )
        ready_pods = sum(_ready(item) for item in pods)
        restarts = sum(
            int(getattr(status, "restart_count", 0) or 0)
            for pod in pods
            for status in (getattr(getattr(pod, "status", None), "container_statuses", None) or [])[:20]
        )
        ports = [
            f"{getattr(item, 'name', '') or 'unnamed'}:{getattr(item, 'port', '')}/{getattr(item, 'protocol', 'TCP')}"
            for item in (getattr(getattr(service, "spec", None), "ports", None) or [])[:20]
        ]
        source = f"kubernetes:service/{spec.namespace}/{spec.service_name}"
        observations = (
            CheckObservation(
                id=f"check-{spec.id[:8]}-service",
                title="Service selector and ports",
                detail=redact_text(
                    f"Selector: {selector_text or 'none'}. Ports: {', '.join(ports) or 'none'}."
                )[:2048],
                source=source,
                observed_at=now,
            ),
            CheckObservation(
                id=f"check-{spec.id[:8]}-endpoints",
                title="EndpointSlice readiness",
                detail=(
                    f"Found {len(slices)} EndpointSlices with {len(endpoints)} endpoints; "
                    f"{ready_endpoints} are ready or do not declare an unready condition."
                ),
                source=f"kubernetes:endpointslices/{spec.namespace}/{spec.service_name}",
                observed_at=now,
            ),
            CheckObservation(
                id=f"check-{spec.id[:8]}-pods",
                title="Selected Pod health",
                detail=(
                    f"The selector matched {len(pods)} bounded Pods; {ready_pods} are Ready "
                    f"and their containers report {restarts} total restarts."
                ),
                source=f"kubernetes:pods/{spec.namespace}?selector={selector_text or 'none'}",
                observed_at=now,
            ),
        )
        if not selector_text:
            summary = "The Service has no Pod selector; endpoint ownership requires a domain-specific check."
        elif not endpoints:
            summary = "The Service currently has no discovered endpoints, which can explain the down target."
        elif ready_endpoints == 0 or ready_pods == 0:
            summary = "The target topology exists but no selected endpoint or Pod is currently ready."
        else:
            summary = "Service discovery and selected Pods appear ready; investigate the scrape or network path next."
        return DiagnosticCheckResult(
            status="succeeded",
            summary=summary,
            observations=observations,
            limitations=(
                "This check does not perform an active network probe or read monitoring credentials.",
            ),
        )

    def _events(self, spec: DiagnosticCheckSpec) -> DiagnosticCheckResult:
        assert self._core is not None
        now = datetime.now(timezone.utc)
        _, pods, selector_text = self._service_and_pods(spec)
        events: list[Any] = []
        for pod in pods[:5]:
            remaining = self._max_events - len(events)
            if remaining <= 0:
                break
            response = self._core.list_namespaced_event(
                spec.namespace,
                field_selector=f"involvedObject.uid={pod.metadata.uid}",
                limit=remaining,
            )
            events.extend((response.items or [])[:remaining])
        events.sort(
            key=lambda item: (
                getattr(item, "event_time", None)
                or getattr(item, "last_timestamp", None)
                or getattr(item.metadata, "creation_timestamp", None)
                or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )
        observations = tuple(
            CheckObservation(
                id=f"check-{spec.id[:8]}-event-{index + 1}",
                title=redact_text(str(getattr(item, "reason", "Unknown")))[:128],
                detail=redact_text(str(getattr(item, "message", "")))[:2048],
                source=f"kubernetes:event/{str(item.metadata.name)[:253]}",
                observed_at=(
                    getattr(item, "event_time", None)
                    or getattr(item, "last_timestamp", None)
                    or getattr(item.metadata, "creation_timestamp", None)
                    or now
                ),
            )
            for index, item in enumerate(events[: self._max_events])
        )
        return DiagnosticCheckResult(
            status="succeeded",
            summary=(
                f"Collected {len(observations)} bounded recent events from {len(pods)} selected Pods."
                if pods
                else "The Service selector matched no Pods, so there were no target Pod events to collect."
            ),
            observations=observations,
            limitations=(
                f"At most 5 Pods and {self._max_events} events are inspected for selector {selector_text or 'none'}.",
            ),
        )
