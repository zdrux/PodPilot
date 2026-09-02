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
    role_read_write_groups: list[str] = Field(
        default_factory=lambda: ["podpilot-read-write"]
    )
    configuration_admin_groups: list[str] = Field(
        default_factory=lambda: ["podpilot-configuration-admins"]
    )
    role_approver_groups: list[str] = Field(default_factory=lambda: ["podpilot-approvers"])
    role_breakglass_groups: list[str] = Field(default_factory=lambda: ["podpilot-breakglass"])
    delegated_access_enabled: bool = False
    delegated_session_lifetime_seconds: int = Field(default=86_400, ge=300, le=86_400)
    delegated_login_timeout_seconds: float = Field(default=15.0, ge=3.0, le=60.0)
    delegated_login_attempts_per_minute: int = Field(default=5, ge=1, le=30)
    delegated_proxy_timeout_seconds: float = Field(default=310.0, ge=5.0, le=900.0)
    delegated_system_api_url: str = "https://kubernetes.default.svc"
    delegated_system_oauth_authorization_url: str = (
        "https://oauth-openshift.openshift-authentication.svc/oauth/authorize"
    )
    alertmanager_url: str = "https://alertmanager-main.openshift-monitoring.svc:9094"
    service_account_token_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    service_account_ca_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    )
    service_ca_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    )
    alertmanager_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    alertmanager_max_alerts: int = Field(default=250, ge=1, le=1000)
    thanos_url: str = "https://thanos-querier.openshift-monitoring.svc:9091"
    thanos_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    thanos_max_series: int = Field(default=20, ge=1, le=100)
    loki_url: str = (
        "https://logging-loki-gateway-http.openshift-logging.svc:8080"
        "/api/logs/v1/application"
    )
    loki_route_name: str = "logging-loki"
    loki_timeout_seconds: float = Field(default=90.0, ge=1.0, le=120.0)
    loki_max_series: int = Field(default=50, ge=1, le=100)
    workload_max_events: int = Field(default=30, ge=1, le=100)
    workload_log_tail_lines: int = Field(default=200, ge=10, le=1000)
    workload_max_log_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    diagnostic_max_checks: int = Field(default=4, ge=1, le=10)
    chat_max_messages: int = Field(default=20, ge=2, le=50)
    chat_max_chars: int = Field(default=4000, ge=100, le=4000)
    adhoc_max_evidence: int = Field(default=40, ge=5, le=100)
    adhoc_max_rounds: int = Field(default=10, ge=1, le=12)
    adhoc_max_reads_per_turn: int = Field(default=50, ge=1, le=100)
    adhoc_followup_reserve_units: int = Field(default=0, ge=0, le=15)
    adhoc_max_clusters_per_conversation: int = Field(default=10, ge=1, le=20)
    adhoc_http_probe_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    adhoc_http_probe_max_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    adhoc_inventory_max_objects: int = Field(default=500, ge=50, le=1000)
    adhoc_detail_fanout_max_objects: int = Field(default=10, ge=1, le=25)
    adhoc_max_payload_bytes: int = Field(default=48_000, ge=16_384, le=1_048_576)
    adhoc_search_max_scan_objects: int = Field(default=2000, ge=250, le=5000)
    adhoc_metrics_max_range_seconds: int = Field(default=2_592_000, ge=3600, le=7_776_000)
    adhoc_metrics_max_points_per_series: int = Field(default=300, ge=50, le=1000)
    adhoc_metrics_max_response_bytes: int = Field(
        default=1_048_576, ge=65_536, le=4_194_304
    )
    adhoc_logs_max_range_seconds: int = Field(default=604_800, ge=3600, le=2_592_000)
    adhoc_audit_initial_range_seconds: int = Field(default=3600, ge=300, le=2_592_000)
    adhoc_audit_max_range_seconds: int = Field(default=86_400, ge=3600, le=7_776_000)
    adhoc_audit_default_limit: int = Field(default=20, ge=1, le=100)
    adhoc_audit_max_response_bytes: int = Field(
        default=1_048_576, ge=65_536, le=4_194_304
    )
    adhoc_context_messages: int = Field(default=10, ge=4, le=30)
    adhoc_context_summary_chars: int = Field(default=4000, ge=1000, le=12000)
    adhoc_rate_limit_per_minute: int = Field(default=10, ge=1, le=60)
    adhoc_display_messages: int = Field(default=100, ge=20, le=500)
    adhoc_job_worker_enabled: bool = True
    adhoc_worker_concurrency: int = Field(default=3, ge=1, le=8)
    adhoc_max_concurrent_runs_per_user: int = Field(default=2, ge=1, le=8)
    adhoc_run_timeout_seconds: float = Field(default=900.0, ge=1.0, le=1800.0)
    adhoc_finalization_reserve_seconds: float = Field(default=60.0, ge=0.0, le=300.0)
    agent_mode: Literal["guarded", "unrestricted"] = "guarded"
    agent_runner_url: str = "http://127.0.0.1:8090"
    agent_command_timeout_seconds: float = Field(default=240.0, ge=5.0, le=600.0)
    agent_heartbeat_seconds: float = Field(default=10.0, ge=2.0, le=60.0)
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
        "role_read_write_groups",
        "configuration_admin_groups",
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
            self.role_read_write_groups,
            self.role_approver_groups,
            self.role_breakglass_groups,
        )
        configured = [name for groups in role_groups for name in groups]
        if len(configured) != len(set(configured)):
            raise ValueError("An OpenShift group may be mapped to only one PodPilot role")
        if self.adhoc_audit_initial_range_seconds > self.adhoc_audit_max_range_seconds:
            raise ValueError(
                "The initial audit search range must not exceed the maximum audit range"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
