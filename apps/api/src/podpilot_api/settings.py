from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
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
    alertmanager_url: str = "https://alertmanager-main.openshift-monitoring.svc:9094"
    service_account_token_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )
    service_ca_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
    )
    alertmanager_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    alertmanager_max_alerts: int = Field(default=250, ge=1, le=1000)
    workload_max_events: int = Field(default=30, ge=1, le=100)
    workload_log_tail_lines: int = Field(default=200, ge=10, le=1000)
    workload_max_log_bytes: int = Field(default=16_384, ge=1024, le=65_536)
    model_credential_store: Literal["environment", "kubernetes"] = "environment"
    model_secret_namespace: str = "ai-ops"
    model_secret_name: str = "podpilot-model-credentials"
    model_secret_key: str = "api_key"
    poc_mode: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
