from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


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


def analyze_alert(alert: AlertEvidence, *, now: datetime | None = None) -> AlertAnalysis:
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
