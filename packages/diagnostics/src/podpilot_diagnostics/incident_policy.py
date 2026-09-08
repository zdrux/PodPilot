"""Administrator-owned incident collection policy, separate from Ask budgets."""
from pydantic import BaseModel, ConfigDict, Field


class IncidentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    coordinator_concurrency: int = Field(3, ge=1, le=8, title="Concurrent Incident investigations")
    change_range_seconds: int = Field(7200, ge=60, le=604800, title="Deployment-change lookback before alert (seconds)")
    history_lead_seconds: int = Field(1800, ge=0, le=86400, title="Loki history lead before alert (seconds)")
    run_timeout_seconds: int = Field(2700, ge=120, le=14400, title="Investigation deadline (seconds)")
    connector_timeout_seconds: int = Field(300, ge=30, le=3600, title="Connector enrichment deadline (seconds)")
    max_rounds: int = Field(10, ge=2, le=100, title="Coordinator turns")
    reads_per_turn: int = Field(3, ge=1, le=30, title="Collectors per turn")
    max_specialist_reports: int = Field(100, ge=1, le=1000, title="Specialist calls per investigation")
    evidence_input_percent: int = Field(70, ge=10, le=90, title="Input budget reserved for evidence (%)", description="The remainder accommodates instructions, schemas, collector descriptions and report metadata.")
    specialist_concurrency: int = Field(3, ge=1, le=8, title="Concurrent log specialists")
    max_evidence_bytes: int = Field(16_777_216, ge=98304, le=268_435_456, title="Retained evidence budget (bytes)")
    max_collection_bytes: int = Field(8_388_608, ge=65536, le=134_217_728, title="Projected collection budget (bytes)")
    max_response_bytes: int = Field(2_097_152, ge=65536, le=33_554_432, title="API response budget per page (bytes)")
    page_size: int = Field(60, ge=1, le=500, title="API page size", description="All pages are followed; this is not an object-count ceiling.")
    read_timeout_seconds: int = Field(15, ge=1, le=120, title="API read deadline (seconds)")
    max_namespaces: int = Field(0, ge=0, le=10000, title="Namespace ceiling", description="0 follows every discovered namespace within the investigation deadline.")
    log_tail_lines: int = Field(1000, ge=100, le=100000, title="Kubernetes log lines per stream")
    log_max_bytes: int = Field(98_304, ge=16384, le=8_388_608, title="Log bytes per stream")
    log_range_seconds: int = Field(7200, ge=60, le=604800, title="Kubernetes log lookback (seconds)")
    loki_log_limit: int = Field(2000, ge=100, le=100000, title="Loki lines per query")
    loki_range_seconds: int = Field(21600, ge=60, le=604800, title="Loki history window (seconds)")
    metric_series: int = Field(100, ge=1, le=10000, title="Metric series ceiling")
    metric_range_seconds: int = Field(1800, ge=60, le=86400, title="Metric lookback (seconds)")
    metric_step_seconds: int = Field(60, ge=1, le=3600, title="Metric interval (seconds)")
    event_range_seconds: int = Field(7200, ge=60, le=604800, title="Warning event lookback (seconds)")
