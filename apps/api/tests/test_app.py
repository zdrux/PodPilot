import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app
from podpilot_api.model_provider import CapabilityReport, ModelInterpretation, ModelProviderError
from podpilot_api.models import AuditEvent, Base, Investigation, ModelProfile
from podpilot_api.settings import Settings
from podpilot_diagnostics.workloads import (
    ContainerEvidence,
    EventEvidence,
    OwnerEvidence,
    WorkloadEvidence,
)
from podpilot_openshift.alerts import AlertRecord, AlertSnapshot, AlertSourceError
from podpilot_openshift.workloads import WorkloadEvidenceError

ROOT = Path(__file__).resolve().parents[3]


class FakeAlertSource:
    def __init__(self, alerts: tuple[AlertRecord, ...] = (), error: str | None = None) -> None:
        self.alerts = alerts
        self.error = error

    def fetch(self) -> AlertSnapshot:
        if self.error:
            raise AlertSourceError(self.error)
        return AlertSnapshot(self.alerts, datetime.now(timezone.utc))


class FakeWorkloadSource:
    def __init__(self, evidence: WorkloadEvidence) -> None:
        self.evidence = evidence
        self.calls: list[dict[str, object]] = []

    def collect(self, **kwargs) -> WorkloadEvidence:
        self.calls.append(kwargs)
        return self.evidence


class FailingWorkloadSource:
    def collect(self, **kwargs) -> WorkloadEvidence:
        raise WorkloadEvidenceError("The Kubernetes API is temporarily unavailable.")


class MemoryCredentialStore:
    def __init__(self, value: str | None = None) -> None:
        self.value = value

    def get(self) -> str | None:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class FakeModelProvider:
    def __init__(self, *, fail_interpretation: bool = False) -> None:
        self.fail_interpretation = fail_interpretation
        self.interpret_calls: list[dict[str, object]] = []

    def probe(self, profile, api_key: str) -> CapabilityReport:
        assert api_key == "test-api-token"
        return CapabilityReport(True, True, True, True, True, True, True, True)

    def interpret(self, profile, api_key: str, evidence: dict[str, object]) -> ModelInterpretation:
        if self.fail_interpretation:
            raise ModelProviderError("Provider request failed (synthetic outage).")
        self.interpret_calls.append(evidence)
        return ModelInterpretation(
            summary="The heartbeat evidence is consistent with expected operation.",
            operational_context="This interpretation is bounded to the supplied alert observation.",
            recommended_checks=["Keep the heartbeat visible after monitoring changes."],
            caveats=["This does not prove every monitoring component is healthy."],
        )


def watchdog() -> AlertRecord:
    return AlertRecord(
        fingerprint="watchdog-1",
        state="active",
        labels={"alertname": "Watchdog", "severity": "none"},
        annotations={"summary": "Continuous monitoring heartbeat. password=synthetic-secret"},
        starts_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
        ends_at=None,
        updated_at=None,
        silenced_by=(),
        inhibited_by=(),
    )


def crashloop() -> AlertRecord:
    return AlertRecord(
        fingerprint="crashloop-1",
        state="active",
        labels={
            "alertname": "KubePodCrashLooping",
            "severity": "warning",
            "namespace": "demo",
            "pod": "api-abc",
            "container": "api",
        },
        annotations={"summary": "Container restarts"},
        starts_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
        ends_at=None,
        updated_at=None,
        silenced_by=(),
        inhibited_by=(),
    )


def crashloop_evidence() -> WorkloadEvidence:
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)
    return WorkloadEvidence(
        namespace="demo",
        pod_name="api-abc",
        pod_uid="pod-uid",
        phase="Running",
        node_name="worker-0",
        requests={"memory": "128Mi"},
        conditions=("Ready=False",),
        containers=(
            ContainerEvidence(
                name="api",
                image="example.invalid/api:v1",
                ready=False,
                restart_count=8,
                state="waiting",
                reason="CrashLoopBackOff",
                message="back-off restarting",
                last_reason="OOMKilled",
                last_exit_code=137,
            ),
        ),
        events=(
            EventEvidence(
                id="event-backoff",
                reason="BackOff",
                message="Back-off restarting container api",
                event_type="Warning",
                observed_at=now,
                source="kubernetes:event/backoff",
            ),
        ),
        owners=(OwnerEvidence("apps/v1", "ReplicaSet", "api-abc", 1, 0, 1),),
        nodes=(),
        current_logs={"api": "starting"},
        previous_logs={"api": "process terminated"},
        collected_at=now,
        failures=(),
    )


def make_app(
    tmp_path: Path,
    *,
    assignments: dict[str, Role],
    source: FakeAlertSource,
    workload_source: FakeWorkloadSource | None = None,
    credential_store: MemoryCredentialStore | None = None,
    model_provider: FakeModelProvider | None = None,
):
    settings = Settings(
        environment="test",
        cluster_name="test-cluster",
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'podpilot.db'}",
        web_dir=ROOT / "apps" / "web",
        auth_mode="test",
        poc_mode=True,
    )
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    return (
        create_app(
            settings,
            StaticRoleResolver(assignments),
            source,
            workload_source,
            credential_store or MemoryCredentialStore(),
            model_provider or FakeModelProvider(),
        ),
        settings,
    )


def test_authenticated_dashboard_and_session(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource((watchdog(),)),
    )
    with TestClient(app) as client:
        assert client.get("/").status_code == 401
        response = client.get("/", headers={"x-forwarded-user": "ada"})
        assert response.status_code == 200
        assert "podpilot-csrf" in response.text
        assert "Watchdog is firing continuously" in response.text
        assert "Milestone 4 adds" in response.text
        assert "PodPilot 0.4.0" in response.text
        assert "Milestone 2 analysis" not in response.text
        assert "synthetic-secret" not in response.text
        assert "No actionable alerts" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        session = client.get("/api/v1/session", headers={"x-forwarded-user": "ada"})
        assert session.json() == {"username": "ada", "role": "approver"}
        assert client.get("/health/ready").json() == {"status": "ready", "database": True}


def test_analysis_creates_one_durable_investigation_and_audit_event(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.INVESTIGATOR},
        source=FakeAlertSource((watchdog(),)),
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        missing_csrf = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada"},
        )
        assert missing_csrf.status_code == 403
        created = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert created.status_code == 303
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert detail.status_code == 200
        assert "expected monitoring heartbeat" in detail.text
        assert "No ready model profile was used" in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.scalar(select(func.count()).select_from(Investigation)) == 1
        assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 1
    engine.dispose()


def test_workload_investigation_collects_and_persists_live_evidence(tmp_path: Path) -> None:
    workload_source = FakeWorkloadSource(crashloop_evidence())
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.INVESTIGATOR},
        source=FakeAlertSource((crashloop(),)),
        workload_source=workload_source,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert detail.status_code == 200
        assert "exceeding its memory limit" in detail.text
        assert "Evidence-first Milestone 4 analysis" in detail.text

    assert workload_source.calls == [{
        "namespace": "demo",
        "pod_name": "api-abc",
        "container_name": "api",
        "include_logs": True,
        "include_nodes": False,
    }]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        investigation = db_session.scalar(select(Investigation))
        assert investigation is not None
        snapshot = json.loads(investigation.alert_snapshot_json)
        assert snapshot["workload"]["pod_uid"] == "pod-uid"
        analysis = json.loads(investigation.analysis_json)
        assert analysis["hypotheses"][0]["confidence"] == "high"
    engine.dispose()


def test_workload_collection_failure_preserves_deterministic_triage(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.INVESTIGATOR},
        source=FakeAlertSource((crashloop(),)),
        workload_source=FailingWorkloadSource(),
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert detail.status_code == 200
        assert "Kubernetes API is temporarily unavailable" in detail.text
        assert "low confidence" in detail.text


def test_viewer_cannot_start_analysis(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.VIEWER},
        source=FakeAlertSource((watchdog(),)),
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        denied = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert denied.status_code == 403


def test_alertmanager_failure_is_explicitly_degraded(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.VIEWER},
        source=FakeAlertSource(error="Alertmanager is temporarily unavailable."),
    )
    with TestClient(app) as client:
        response = client.get("/", headers={"x-forwarded-user": "ada"})
        assert response.status_code == 200
        assert "Alert collection is degraded" in response.text
        assert "healthy empty queue" in response.text


def test_unknown_and_malformed_users_fail_closed(tmp_path: Path) -> None:
    app, _ = make_app(tmp_path, assignments={}, source=FakeAlertSource())
    with TestClient(app) as client:
        unknown = client.get("/", headers={"x-forwarded-user": "unknown"})
        assert unknown.status_code == 403
        assert 'href="/oauth/sign_out"' in unknown.text
        assert 'href="/oauth/sign_in"' not in unknown.text
        assert client.get("/", headers={"x-forwarded-user": "kube:admin"}).status_code == 403
        assert client.get("/", headers={"x-forwarded-user": "bad user"}).status_code == 401
        assert client.get("/health/live").json() == {"status": "ok"}


def test_colon_delimited_openshift_identity_can_receive_a_role(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"system:admin": Role.VIEWER},
        source=FakeAlertSource(),
    )
    with TestClient(app) as client:
        session = client.get(
            "/api/v1/session",
            headers={"x-forwarded-user": "system:admin"},
        )
        assert session.status_code == 200
        assert session.json() == {"username": "system:admin", "role": "viewer"}


def test_model_profile_is_role_gated_and_never_reads_token_back(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore()
    provider = FakeModelProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER, "vic": Role.VIEWER},
        source=FakeAlertSource((watchdog(),)),
        credential_store=credentials,
        model_provider=provider,
    )
    with TestClient(app) as client:
        viewer_page = client.get("/settings/model", headers={"x-forwarded-user": "vic"})
        assert viewer_page.status_code == 200
        assert "Approver role or higher" in viewer_page.text
        viewer_csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', viewer_page.text)
        assert viewer_csrf is not None
        denied = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "vic", "x-podpilot-csrf": viewer_csrf.group(1)},
            data={},
        )
        assert denied.status_code == 403

        page = client.get("/settings/model", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        saved = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "provider_label": "OpenAI",
                "base_url": "https://api.openai.com/v1",
                "chat_model": "gpt-5.6-terra",
                "embedding_model": "text-embedding-3-small",
                "api_token": "test-api-token",
                "timeout_seconds": "30",
                "max_output_tokens": "1200",
            },
        )
        assert saved.json() == {"status": "saved", "token_configured": True}
        rendered = client.get("/settings/model", headers={"x-forwarded-user": "ada"})
        assert "Token configured" in rendered.text
        assert "test-api-token" not in rendered.text
        probed = client.post(
            "/api/v1/model-profile/probe",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1), "content-type": "application/x-www-form-urlencoded"},
            content="",
        )
        assert probed.json()["status"] == "ready"

    engine = build_engine(settings)
    with Session(engine) as db_session:
        profile = db_session.get(ModelProfile, 1)
        assert profile is not None and profile.status == "ready"
        assert "test-api-token" not in profile.capabilities_json
        assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 2
    engine.dispose()


def test_ready_model_enriches_investigation_and_outage_falls_back(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore("test-api-token")
    provider = FakeModelProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource((watchdog(),)),
        credential_store=credentials,
        model_provider=provider,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="gpt-5.6-terra", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ada",
        ))
        db_session.commit()
    engine.dispose()
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert "schema-validated model interpretation" in detail.text
        assert "heartbeat evidence is consistent" in detail.text
        assert provider.interpret_calls

    failing_app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource((watchdog(),)),
        credential_store=credentials,
        model_provider=FakeModelProvider(fail_interpretation=True),
    )
    with TestClient(failing_app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert "Model interpretation unavailable" in detail.text
        assert "expected monitoring heartbeat" in detail.text


def test_failed_probe_reason_is_shown_with_deterministic_fallback(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore("test-api-token")
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource((watchdog(),)),
        credential_store=credentials,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.invalid/v1",
            chat_model="local-model", embedding_model=None, timeout_seconds=3,
            max_output_tokens=512, status="unavailable", capabilities_json="{}",
            last_error="Provider request failed (ConnectionError).", updated_by="ada",
        ))
        db_session.commit()
    engine.dispose()
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/watchdog-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ada"})
        assert "Provider request failed (ConnectionError)" in detail.text
        assert "expected monitoring heartbeat" in detail.text
