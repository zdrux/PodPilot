from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PODPILOT_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = "development"
    cluster_name: str = "local"
    data_dir: Path = Path("/var/lib/podpilot")
    database_url: str = "sqlite:////var/lib/podpilot/podpilot.db"
    web_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parents[4] / "apps" / "web"
    )
    auth_mode: Literal["proxy", "test"] = "proxy"
    proxy_user_header: str = "x-forwarded-user"
    role_cache_seconds: int = Field(default=30, ge=0, le=300)
    role_investigator_groups: list[str] = Field(
        default_factory=lambda: ["podpilot-investigators"]
    )
    role_approver_groups: list[str] = Field(default_factory=lambda: ["podpilot-approvers"])
    role_breakglass_groups: list[str] = Field(default_factory=lambda: ["podpilot-breakglass"])
    alertmanager_url: str = "https://alertmanager-main.openshift-monitoring.svc:9094"
    service_account_token_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    service_ca_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    )
    alertmanager_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    alertmanager_max_alerts: int = Field(default=250, ge=1, le=1000)
    thanos_url: str = "https://thanos-querier.openshift-monitoring.svc:9091"
    thanos_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    thanos_max_series: int = Field(default=20, ge=1, le=100)
    workload_max_events: int = Field(default=30, ge=1, le=100)
    workload_log_tail_lines: int = Field(default=200, ge=10, le=1000)
    workload_max_log_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    diagnostic_max_checks: int = Field(default=4, ge=1, le=10)
    chat_max_messages: int = Field(default=20, ge=2, le=50)
    chat_max_chars: int = Field(default=1000, ge=100, le=4000)
    adhoc_max_evidence: int = Field(default=40, ge=5, le=100)
    adhoc_max_rounds: int = Field(default=10, ge=1, le=12)
    adhoc_max_reads_per_turn: int = Field(default=25, ge=1, le=50)
    adhoc_followup_reserve_units: int = Field(default=5, ge=0, le=15)
    adhoc_max_clusters_per_conversation: int = Field(default=10, ge=1, le=20)
    adhoc_http_probe_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    adhoc_http_probe_max_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    adhoc_inventory_max_objects: int = Field(default=500, ge=50, le=1000)
    adhoc_search_max_scan_objects: int = Field(default=2000, ge=250, le=5000)
    adhoc_metrics_max_range_seconds: int = Field(default=2_592_000, ge=3600, le=7_776_000)
    adhoc_metrics_max_points_per_series: int = Field(default=300, ge=50, le=1000)
    adhoc_context_messages: int = Field(default=10, ge=4, le=30)
    adhoc_context_summary_chars: int = Field(default=4000, ge=1000, le=12000)
    adhoc_rate_limit_per_minute: int = Field(default=10, ge=1, le=60)
    adhoc_display_messages: int = Field(default=100, ge=20, le=500)
    adhoc_job_worker_enabled: bool = True
    adhoc_run_timeout_seconds: float = Field(default=300.0, ge=1.0, le=900.0)
    model_timeout_max_seconds: float = Field(default=240.0, ge=30.0, le=300.0)
    model_credential_store: Literal["environment", "kubernetes"] = "environment"
    model_secret_namespace: str = "ai-ops"
    model_secret_name: str = "podpilot-model-credentials"
    model_secret_key: str = "api_key"
    cluster_credential_store: Literal["environment", "kubernetes"] = "environment"
    cluster_secret_namespace: str = "ai-ops"
    cluster_secret_name: str = "podpilot-cluster-credentials"
    poc_mode: bool = False

    @field_validator(
        "role_investigator_groups",
        "role_approver_groups",
        "role_breakglass_groups",
    )
    @classmethod
    def normalize_role_groups(cls, groups: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw_name in groups:
            name = raw_name.strip()
            if not name or len(name) > 253:
                raise ValueError("OpenShift role group names must contain 1 to 253 characters")
            if name not in normalized:
                normalized.append(name)
        return normalized

    @model_validator(mode="after")
    def validate_role_group_mapping(self) -> "Settings":
        role_groups = (
            self.role_investigator_groups,
            self.role_approver_groups,
            self.role_breakglass_groups,
        )
        configured = [name for groups in role_groups for name in groups]
        if len(configured) != len(set(configured)):
            raise ValueError("An OpenShift group may be mapped to only one PodPilot role")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
