"""Platform-only incident policy and evidence contracts; no transport or model dependency."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, ConfigDict, AwareDatetime

DEFAULT_ALERTS = (
    "etcdNoLeader", "etcdInsufficientMembers", "etcdDatabaseQuotaLowSpace",
    "KubeAPIDown", "KubeAPIErrorBudgetBurn", "KubeControllerManagerDown",
    "KubeSchedulerDown", "ClusterOperatorDown", "NoRunningOvnControlPlane",
    "NoOvnClusterManagerLeader", "KubeletDown",
)
PLATFORM_NAMESPACES = (
    "openshift-etcd", "openshift-etcd-operator", "openshift-kube-apiserver",
    "openshift-kube-apiserver-operator", "openshift-kube-controller-manager",
    "openshift-kube-controller-manager-operator", "openshift-kube-scheduler",
    "openshift-kube-scheduler-operator", "openshift-ovn-kubernetes",
    "openshift-network-operator", "openshift-dns", "openshift-dns-operator",
    "openshift-ingress", "openshift-ingress-operator", "openshift-monitoring",
    "openshift-machine-config-operator", "openshift-cluster-version",
    "openshift-cluster-storage-operator", "openshift-authentication",
)


class WebhookAlert(BaseModel):
    status: Literal["firing", "resolved"]
    labels: dict[str, str] = Field(max_length=80)
    annotations: dict[str, str] = Field(default_factory=dict, max_length=40)
    startsAt: AwareDatetime
    endsAt: AwareDatetime | None = None
    fingerprint: str = Field(min_length=1, max_length=128)


class AlertWebhook(BaseModel):
    groupKey: str = Field(min_length=1, max_length=4096)
    status: Literal["firing", "resolved"]
    alerts: list[WebhookAlert] = Field(min_length=1, max_length=100)
    truncatedAlerts: int = Field(default=0, ge=0)


class IncidentDecision(BaseModel):
    """Model selects server-owned collectors or returns a cited preliminary briefing."""
    model_config = ConfigDict(extra="forbid")
    collect: list[str] = Field(default_factory=list, max_length=3)
    summary: str = Field(default="", max_length=4000)
    hypotheses: list[str] = Field(default_factory=list, max_length=5)
    evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    next_steps: list[str] = Field(default_factory=list, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=10)


def admitted(alert: WebhookAlert, allowed: list[str]) -> bool:
    return alert.labels.get("severity") == "critical" and alert.labels.get("alertname") in allowed
