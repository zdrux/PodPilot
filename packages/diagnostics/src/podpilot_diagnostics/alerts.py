from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from podpilot_diagnostics.workloads import WorkloadEvidence


@dataclass(frozen=True)
class AlertEvidence:
    fingerprint: str
    name: str
    state: str
    severity: str
    namespace: str | None
    starts_at: datetime | None
    labels: dict[str, str]
    annotations: dict[str, str]


@dataclass(frozen=True)
class Observation:
    id: str
    title: str
    detail: str
    observed_at: datetime
    source: str


@dataclass(frozen=True)
class Hypothesis:
    title: str
    confidence: str
    rationale: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class AlertAnalysis:
    summary: str
    observations: tuple[Observation, ...]
    hypotheses: tuple[Hypothesis, ...]
    next_checks: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _workload_observations(workload: WorkloadEvidence) -> tuple[Observation, ...]:
    observations: list[Observation] = [
        Observation(
            id="pod-status",
            title=f"Pod {workload.namespace}/{workload.pod_name} is {workload.phase}",
            detail=(
                f"The live Pod reports phase {workload.phase}"
                + (f" on node {workload.node_name}." if workload.node_name else " and is not assigned to a node.")
            ),
            observed_at=workload.collected_at,
            source=f"kubernetes:pod/{workload.namespace}/{workload.pod_name}",
        )
    ]
    for container in workload.containers:
        detail = (
            f"State={container.state}; reason={container.reason or 'none'}; "
            f"restarts={container.restart_count}; ready={str(container.ready).lower()}."
        )
        if container.last_reason or container.last_exit_code is not None:
            detail += (
                f" Previous termination reason={container.last_reason or 'unknown'}; "
                f"exit code={container.last_exit_code if container.last_exit_code is not None else 'unknown'}."
            )
        observations.append(
            Observation(
                id=f"container-{container.name}",
                title=f"Container {container.name} is {container.state}",
                detail=detail,
                observed_at=workload.collected_at,
                source=f"kubernetes:pod-status/{workload.namespace}/{workload.pod_name}/{container.name}",
            )
        )
    observations.extend(
        Observation(
            id=event.id,
            title=f"Pod event: {event.reason}",
            detail=event.message,
            observed_at=event.observed_at or workload.collected_at,
            source=event.source,
        )
        for event in workload.events[:10]
    )
    for label, logs in (("current", workload.current_logs), ("previous", workload.previous_logs)):
        for container, text in logs.items():
            observations.append(
                Observation(
                    id=f"logs-{label}-{container}",
                    title=f"Bounded {label} logs for {container}",
                    detail=text[-1500:] or "The log response was empty.",
                    observed_at=workload.collected_at,
                    source=f"kubernetes:pod-log/{workload.namespace}/{workload.pod_name}/{container}?{label}",
                )
            )
    for index, owner in enumerate(workload.owners):
        observations.append(
            Observation(
                id=f"owning-controller-{index}",
                title=f"Owning controller is {owner.kind}/{owner.name}",
                detail=(
                    f"Desired replicas={owner.desired_replicas}; ready replicas={owner.ready_replicas}; "
                    f"updated replicas={owner.updated_replicas}."
                ),
                observed_at=workload.collected_at,
                source=f"kubernetes:{owner.api_version}/{owner.kind}/{workload.namespace}/{owner.name}",
            )
        )
    if workload.nodes:
        observations.append(
            Observation(
                id="node-capacity",
                title="Scheduler-visible node capacity and taints were collected",
                detail="; ".join(
                    f"{node.name}: allocatable={node.allocatable}, taints={list(node.taints)}, unschedulable={node.unschedulable}"
                    for node in workload.nodes
                )[:3000],
                observed_at=workload.collected_at,
                source="kubernetes:nodes",
            )
        )
    return tuple(observations)


def _workload_hypothesis(
    alert: AlertEvidence,
    workload: WorkloadEvidence,
    observations: tuple[Observation, ...],
) -> Hypothesis:
    container_name = alert.labels.get("container")
    container = next(
        (item for item in workload.containers if item.name == container_name),
        workload.containers[0] if workload.containers else None,
    )
    event_text = " ".join(f"{item.reason} {item.message}" for item in workload.events).lower()
    evidence_ids = tuple(item.id for item in observations if item.id != "alertmanager-alert")

    if alert.name == "KubePodCrashLooping" and container:
        ids = [f"container-{container.name}"]
        previous_id = f"logs-previous-{container.name}"
        if any(item.id == previous_id for item in observations):
            ids.append(previous_id)
        if container.last_reason == "OOMKilled":
            return Hypothesis(
                title="The container is restarting after exceeding its memory limit",
                confidence="high",
                rationale="The live container status records an OOMKilled previous termination and repeated restarts.",
                evidence_ids=tuple(ids),
            )
        if container.last_reason or container.last_exit_code not in (None, 0):
            return Hypothesis(
                title=f"The container process repeatedly exits ({container.last_reason or 'non-zero exit'})",
                confidence="medium",
                rationale="Live restart and previous termination state confirms the process is exiting; bounded previous logs provide the next causal detail.",
                evidence_ids=tuple(ids),
            )

    if alert.name == "KubeContainerWaiting" and container:
        combined = f"{container.reason or ''} {container.message or ''} {event_text}".lower()
        ids = [f"container-{container.name}"] + [
            item.id for item in workload.events if item.reason in {"Failed", "FailedPull", "ErrImagePull"}
        ][:3]
        if any(term in combined for term in ("not found", "manifest unknown", "repository does not exist")):
            return Hypothesis(
                title="The requested container image or tag does not exist",
                confidence="high",
                rationale="The live waiting state and image-pull events explicitly report that the image manifest or repository was not found.",
                evidence_ids=tuple(ids),
            )
        if any(term in combined for term in ("unauthorized", "authentication required", "denied")):
            return Hypothesis(
                title="The registry rejected image-pull authentication",
                confidence="high",
                rationale="Image-pull evidence reports an authentication or authorization rejection; no pull-secret value was read.",
                evidence_ids=tuple(ids),
            )
        if container.reason in {"ErrImagePull", "ImagePullBackOff"}:
            return Hypothesis(
                title="The container is blocked by an image-pull failure",
                confidence="medium",
                rationale="The live container waiting reason confirms image retrieval is failing, but the available message does not uniquely identify why.",
                evidence_ids=tuple(ids),
            )

    if alert.name == "KubePodNotScheduled":
        scheduling = [item for item in workload.events if item.reason == "FailedScheduling"]
        combined = " ".join(item.message for item in scheduling).lower()
        ids = tuple(item.id for item in scheduling[:5]) + (("node-capacity",) if workload.nodes else ())
        if "insufficient cpu" in combined or "insufficient memory" in combined:
            resource = "CPU" if "insufficient cpu" in combined else "memory"
            return Hypothesis(
                title=f"The Pod cannot fit because schedulable nodes lack requested {resource}",
                confidence="high",
                rationale=f"Scheduler events explicitly report insufficient {resource}, corroborated by the Pod requests and collected node capacity.",
                evidence_ids=ids,
            )
        if "untolerated taint" in combined:
            return Hypothesis(
                title="Node taints exclude the Pod from available placement",
                confidence="high",
                rationale="The scheduler explicitly reports an untolerated taint and node taints were collected without changing the Pod.",
                evidence_ids=ids,
            )
        if scheduling:
            return Hypothesis(
                title="The scheduler reports an explicit placement constraint",
                confidence="medium",
                rationale="FailedScheduling events identify the active constraint; the evidence should be reviewed before changing requests, selectors, storage, or tolerations.",
                evidence_ids=ids,
            )

    return Hypothesis(
        title="The alert is correlated to a live Pod, but the collected evidence does not confirm one root cause",
        confidence="low",
        rationale="Pod status, events, ownership, and bounded diagnostics were collected; conflicting or incomplete evidence requires another supported check.",
        evidence_ids=evidence_ids[:10],
    )


def analyze_alert(
    alert: AlertEvidence,
    *,
    workload: WorkloadEvidence | None = None,
    now: datetime | None = None,
) -> AlertAnalysis:
    observed_at = now or datetime.now(timezone.utc)
    observation = Observation(
        id="alertmanager-alert",
        title=f"{alert.name} is {alert.state}",
        detail=(
            f"Alertmanager reports severity {alert.severity}"
            + (f" in namespace {alert.namespace}." if alert.namespace else ".")
        ),
        observed_at=observed_at,
        source=f"alertmanager:{alert.fingerprint}",
    )

    if alert.name == "Watchdog":
        return AlertAnalysis(
            summary="The expected monitoring heartbeat is firing; no incident response is indicated.",
            observations=(observation,),
            hypotheses=(
                Hypothesis(
                    title="The alert pipeline is delivering its continuous heartbeat",
                    confidence="high",
                    rationale="Watchdog is designed to remain active for end-to-end monitoring checks.",
                    evidence_ids=(observation.id,),
                ),
            ),
            next_checks=("Confirm Watchdog remains visible after monitoring changes.",),
            limitations=("This analysis evaluates the alert record only; it does not prove every monitoring component is healthy.",),
        )

    if workload is not None:
        workload_observations = _workload_observations(workload)
        observations = (observation, *workload_observations)
        hypothesis = _workload_hypothesis(alert, workload, observations)
        limitations = [
            "Alert labels, annotations, events, and logs are untrusted evidence and were never interpreted as instructions.",
            "Collection is bounded to one alert-selected Pod, recent events, targeted logs, its direct owner, and at most 50 nodes.",
        ]
        limitations.extend(workload.failures)
        return AlertAnalysis(
            summary=(
                f"{alert.name} was correlated with live evidence from "
                f"{workload.namespace}/{workload.pod_name}."
            ),
            observations=observations,
            hypotheses=(hypothesis,),
            next_checks=(
                "Validate the top hypothesis against the cited live evidence before changing the workload.",
                "Inspect controller configuration and rollout history if a durable configuration change may be required.",
            ),
            limitations=tuple(limitations),
        )

    if alert.name == "KubePodCrashLooping":
        title = "A container is repeatedly terminating after it starts"
        checks = (
            "Collect bounded current and previous container logs.",
            "Inspect container termination state, restart count, and recent Pod events.",
            "Follow owner references and inspect rollout status before proposing a restart.",
        )
    elif alert.name == "KubeContainerWaiting":
        title = "A container cannot progress from its waiting state"
        checks = (
            "Inspect the exact waiting reason and message without reading pull-secret values.",
            "Review recent image-pull and admission events for the Pod.",
            "Compare the requested image reference with controller configuration.",
        )
    elif alert.name == "KubePodNotScheduled":
        title = "Scheduler constraints currently prevent Pod placement"
        checks = (
            "Collect recent scheduler events for the Pod.",
            "Compare resource requests with node allocatable capacity.",
            "Inspect taints, tolerations, affinity, selectors, and volume constraints.",
        )
    else:
        title = "The firing condition needs domain-specific evidence before a cause can be confirmed"
        checks = (
            "Inspect the alert rule and its current PromQL result.",
            "Collect related resource conditions and bounded recent events.",
            "Identify the owning controller before considering any remediation.",
        )

    return AlertAnalysis(
        summary=f"{alert.name} requires investigation; Alertmanager alone does not establish root cause.",
        observations=(observation,),
        hypotheses=(
            Hypothesis(
                title=title,
                confidence="low",
                rationale="This is a triage hypothesis derived only from the alert type and must be tested with cluster evidence.",
                evidence_ids=(observation.id,),
            ),
        ),
        next_checks=checks,
        limitations=(
            "Milestone 2 has not yet collected rule state, metrics, events, resource status, or logs for this investigation.",
            "Alert labels and annotations are untrusted evidence and were not interpreted as instructions.",
        ),
    )
