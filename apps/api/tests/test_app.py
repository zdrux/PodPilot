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
from podpilot_api.model_provider import (
    CapabilityReport,
    InvestigationChatAnswer,
    ModelInterpretation,
    ModelProviderError,
)
from podpilot_api.models import (
    AuditEvent,
    Base,
    ChatMessage,
    DiagnosticCheck,
    Investigation,
    ModelProfile,
    RemediationAction,
)
from podpilot_api.settings import Settings
from podpilot_diagnostics.workloads import (
    ContainerEvidence,
    EventEvidence,
    OwnerEvidence,
    WorkloadEvidence,
)
from podpilot_diagnostics.checks import CheckObservation, DiagnosticCheckResult
from podpilot_diagnostics.remediation import ActionResult, ActionValidation
from podpilot_openshift.alerts import AlertRecord, AlertSnapshot, AlertSourceError
from podpilot_openshift.workloads import WorkloadEvidenceError

ROOT = Path(__file__).resolve().parents[3]


class FakeAlertSource:
    def __init__(
        self,
        alerts: tuple[AlertRecord, ...] = (),
        error: str | None = None,
        is_complete: bool = True,
    ) -> None:
        self.alerts = alerts
        self.error = error
        self.is_complete = is_complete

    def fetch(self) -> AlertSnapshot:
        if self.error:
            raise AlertSourceError(self.error)
        return AlertSnapshot(self.alerts, datetime.now(timezone.utc), self.is_complete)


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
    def __init__(
        self,
        *,
        fail_interpretation: bool = False,
        fail_chat: bool = False,
        chat_answer: InvestigationChatAnswer | None = None,
    ) -> None:
        self.fail_interpretation = fail_interpretation
        self.fail_chat = fail_chat
        self.chat_answer = chat_answer
        self.interpret_calls: list[dict[str, object]] = []
        self.chat_calls: list[dict[str, object]] = []

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

    def chat(self, profile, api_key: str, context: dict[str, object]) -> InvestigationChatAnswer:
        if self.fail_chat:
            raise ModelProviderError("Provider request failed (synthetic chat outage).")
        self.chat_calls.append(context)
        return self.chat_answer or InvestigationChatAnswer(
            answer_mode="evidence_based",
            answer="The active alert is confirmed, but the queued topology checks are needed to narrow the cause.",
            cited_evidence_ids=["alertmanager-alert"],
            proposed_tool_intent="run_queued_checks",
            intent_reason="Collect the registered Service topology and Pod-event evidence.",
        )


class FakeRemediationExecutor:
    def __init__(self, outcome: str = "resolved", validation: str = "current") -> None:
        self.outcome = outcome
        self.validation = validation
        self.previews = []
        self.validations = []
        self.executions = []

    def preview(self, proposal):
        self.previews.append(proposal)
        return {
            "server_dry_run": "passed",
            "target_observed": {
                "uid": proposal.target_uid,
                "resource_version": proposal.target_resource_version,
            },
            "operation": proposal.operation,
        }

    def execute(self, proposal):
        self.executions.append(proposal)
        return ActionResult(
            outcome=self.outcome,
            summary="Synthetic verification completed.",
            before={"uid": proposal.target_uid},
            api_result={"accepted": True},
            verification={"replacement_ready": self.outcome == "resolved"},
            after={"uid": "replacement-uid"},
        )

    def validate(self, proposal):
        self.validations.append(proposal)
        details = {
            "current": "The exact target identity is still current.",
            "stale": "The target UID or resourceVersion changed.",
            "missing": "The exact target no longer exists.",
            "unavailable": "The Kubernetes API is temporarily unavailable.",
        }
        return ActionValidation(self.validation, details[self.validation])


class FakeDiagnosticExecutor:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = []

    def run(self, spec):
        self.calls.append(spec)
        if self.fail:
            return DiagnosticCheckResult(
                status="failed",
                summary="Synthetic Kubernetes read failed.",
                observations=(),
                limitations=("The fixture API was unavailable.",),
            )
        return DiagnosticCheckResult(
            status="succeeded",
            summary=f"Synthetic {spec.tool_name} completed.",
            observations=(
                CheckObservation(
                    id=f"check-{spec.id[:8]}-fixture",
                    title="Discovered one ready endpoint",
                    detail="The selected Service has one Ready Pod and one ready EndpointSlice address.",
                    source=f"kubernetes:service/{spec.namespace}/{spec.service_name}",
                    observed_at=datetime(2026, 8, 23, tzinfo=timezone.utc),
                ),
            ),
            limitations=("Synthetic bounded result.",),
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


def target_down() -> AlertRecord:
    return AlertRecord(
        fingerprint="target-down-1",
        state="active",
        labels={
            "alertname": "TargetDown",
            "severity": "warning",
            "namespace": "demo",
            "service": "check-endpoints",
            "job": "check-endpoints",
            "instance": "10.0.0.10:8443",
        },
        annotations={"summary": "One monitoring target is down"},
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
        owners=(
            OwnerEvidence("apps/v1", "ReplicaSet", "api-abc", 1, 0, 1, "rs-uid", "rs-rv"),
            OwnerEvidence("apps/v1", "Deployment", "api", 1, 0, 1, "deploy-uid", "deploy-rv"),
        ),
        nodes=(),
        current_logs={"api": "starting"},
        previous_logs={"api": "process terminated"},
        collected_at=now,
        failures=(),
        pod_resource_version="pod-rv",
    )


def make_app(
    tmp_path: Path,
    *,
    assignments: dict[str, Role],
    source: FakeAlertSource,
    workload_source: FakeWorkloadSource | None = None,
    credential_store: MemoryCredentialStore | None = None,
    model_provider: FakeModelProvider | None = None,
    remediation_executor: FakeRemediationExecutor | None = None,
    diagnostic_executor: FakeDiagnosticExecutor | None = None,
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
            remediation_executor or FakeRemediationExecutor(),
            diagnostic_executor or FakeDiagnosticExecutor(),
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
        assert "Milestone 9 adds" in response.text
        assert "PodPilot 0.9.0" in response.text
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
        assert "Evidence-first Milestone 9 investigation" in detail.text

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


def test_target_down_plan_runs_registered_checks_and_reanalyzes(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore("test-api-token")
    provider = FakeModelProvider()
    diagnostics = FakeDiagnosticExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "vic": Role.VIEWER},
        source=FakeAlertSource((target_down(),)),
        credential_store=credentials,
        model_provider=provider,
        diagnostic_executor=diagnostics,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="gpt-5.6-terra", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/alerts/target-down-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Safe diagnostic plan" in detail.text
        assert "Run 3 safe checks" in detail.text
        assert "Manual follow-up guidance" not in detail.text
        assert "PodPilot will perform these checks itself" in detail.text

        denied = client.post(
            f"/api/v1/investigations/{investigation_id}/checks/run",
            headers={"x-forwarded-user": "vic", "x-podpilot-csrf": csrf.group(1)},
        )
        assert denied.status_code == 403
        csrf_denied = client.post(
            f"/api/v1/investigations/{investigation_id}/checks/run",
            headers={"x-forwarded-user": "ivy"},
        )
        assert csrf_denied.status_code == 403
        completed = client.post(
            f"/api/v1/investigations/{investigation_id}/checks/run",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert completed.status_code == 303
        result_page = client.get(completed.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert result_page.text.count("Discovered one ready endpoint") >= 2
        assert "Updated after checks" in result_page.text
        assert "Run 3 safe checks" not in result_page.text
        repeated = client.post(
            f"/api/v1/investigations/{investigation_id}/checks/run",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
        )
        assert repeated.status_code == 409

    assert [item.tool_name for item in diagnostics.calls] == [
        "inspect_monitoring_signal",
        "inspect_service_topology",
        "inspect_target_events",
    ]
    assert len(provider.interpret_calls) == 2
    assert "diagnostic_results" in provider.interpret_calls[-1]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        checks = list(
            db_session.scalars(select(DiagnosticCheck).order_by(DiagnosticCheck.position))
        )
        assert [item.status for item in checks] == [
            "succeeded", "succeeded", "succeeded"
        ]
        analysis = json.loads(db_session.get(Investigation, investigation_id).analysis_json)
        assert any(item["title"] == "Discovered one ready endpoint" for item in analysis["observations"])
        actions = list(db_session.scalars(select(AuditEvent.action)))
        assert actions.count("diagnostic.execute") == 3
        assert "diagnostic.plan" in actions
        assert "investigation.reanalyze" in actions
    engine.dispose()


def test_investigation_chat_cites_evidence_and_proposes_registered_checks(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore("test-api-token")
    provider = FakeModelProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "vic": Role.VIEWER},
        source=FakeAlertSource((target_down(),)),
        credential_store=credentials,
        model_provider=provider,
    )
    settings.chat_max_messages = 2
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="gpt-5.6-terra", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/alerts/target-down-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        chat_url = f"/api/v1/investigations/{investigation_id}/chat"
        assert client.post(chat_url, headers={"x-forwarded-user": "ivy"}, data={"message": "Help"}).status_code == 403
        assert client.post(
            chat_url,
            headers={"x-forwarded-user": "vic", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Help"},
        ).status_code == 403
        assert client.post(
            chat_url,
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "x" * 1001},
        ).status_code == 422
        asked = client.post(
            chat_url,
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "What is confirmed? token=synthetic-secret"},
            follow_redirects=False,
        )
        assert asked.status_code == 303
        assert asked.headers["location"].endswith("#investigation-chat")
        detail = client.get(asked.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "queued topology checks are needed" in detail.text
        assert "href=\"#evidence-alertmanager-alert\"" in detail.text
        assert "Proposed safe-check intent" in detail.text
        assert "Review and run queued checks" in detail.text
        assert "synthetic-secret" not in detail.text
        assert "token=[REDACTED]" in detail.text
        assert "Chat budget reached" in detail.text
        assert client.post(
            chat_url,
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "One more question"},
        ).status_code == 409

    assert len(provider.chat_calls) == 1
    assert provider.chat_calls[0]["policy"]["available_tool_intents"] == ["run_queued_checks"]
    assert provider.chat_calls[0]["conversation"][-1]["content"].endswith("[REDACTED]")
    engine = build_engine(settings)
    with Session(engine) as db_session:
        messages = list(db_session.scalars(select(ChatMessage).order_by(ChatMessage.created_at)))
        assert [message.role for message in messages] == ["user", "assistant"]
        assert messages[0].content.endswith("[REDACTED]")
        assert json.loads(messages[1].citations_json) == ["alertmanager-alert"]
        assert json.loads(messages[1].tool_intent_json)["name"] == "run_queued_checks"
        events = list(db_session.scalars(select(AuditEvent).where(AuditEvent.action.like("chat.%"))))
        assert [event.action for event in events] == ["chat.message", "chat.answer"]
        assert all("synthetic-secret" not in event.details_json for event in events)
    engine.dispose()


def test_investigation_chat_withholds_uncited_factual_answer(tmp_path: Path) -> None:
    provider = FakeModelProvider(chat_answer=InvestigationChatAnswer(
        answer_mode="evidence_based",
        answer="The network policy definitely caused the outage.",
        cited_evidence_ids=["invented-evidence"],
    ))
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource((target_down(),)),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="gpt-5.6-terra", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/target-down-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        asked = client.post(
            f"/api/v1/investigations/{investigation_id}/chat",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "What caused this?"},
            follow_redirects=False,
        )
        detail = client.get(asked.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "withheld its factual answer" in detail.text
        assert "network policy definitely" not in detail.text
        assert "invented-evidence" not in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(ChatMessage).where(ChatMessage.role == "assistant"))
        assert assistant.answer_mode == "insufficient_evidence"
        assert json.loads(assistant.citations_json) == []
    engine.dispose()


def test_investigation_chat_degrades_safely_when_model_is_unavailable(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource((target_down(),)),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=FakeModelProvider(fail_chat=True),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="gpt-5.6-terra", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/target-down-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        asked = client.post(
            f"/api/v1/investigations/{investigation_id}/chat",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "What is known?"},
            follow_redirects=False,
        )
        detail = client.get(asked.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "model is temporarily unavailable" in detail.text
        assert "Safe diagnostic plan" in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(ChatMessage).where(ChatMessage.role == "assistant"))
        assert assistant.provider_status == "unavailable"
        assert assistant.answer_mode == "insufficient_evidence"
    engine.dispose()


def test_existing_target_down_investigation_gets_safe_plan_on_open(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(
            Investigation(
                id="00000000-0000-0000-0000-000000000007",
                created_by="ivy",
                status="recommendation_ready",
                alert_fingerprint="old-target-down",
                alert_name="TargetDown",
                alert_snapshot_json=json.dumps({
                    "state": "active",
                    "labels": {
                        "alertname": "TargetDown",
                        "severity": "warning",
                        "namespace": "demo",
                        "service": "check-endpoints",
                    },
                    "annotations": {},
                    "workload": None,
                }),
                analysis_json=json.dumps({
                    "summary": "TargetDown requires investigation.",
                    "observations": [],
                    "hypotheses": [],
                    "next_checks": ["Inspect the Service."],
                    "limitations": [],
                    "model": {"status": "not_configured"},
                }),
            )
        )
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        detail = client.get(
            "/investigations/00000000-0000-0000-0000-000000000007",
            headers={"x-forwarded-user": "ivy"},
        )
        assert detail.status_code == 200
        assert "Run 3 safe checks" in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.scalar(select(func.count()).select_from(DiagnosticCheck)) == 3
        event = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "diagnostic.plan")
        )
        assert json.loads(event.details_json)["reason"] == "milestone_9_backfill"
    engine.dispose()


def test_existing_milestone_seven_plan_gets_only_missing_monitoring_check(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
    )
    investigation_id = "00000000-0000-0000-0000-000000000009"
    snapshot = {
        "state": "active",
        "labels": {
            "alertname": "TargetDown",
            "namespace": "demo",
            "service": "check-endpoints",
            "job": "check-endpoints",
            "instance": "10.0.0.10:8443",
        },
        "annotations": {},
        "workload": None,
    }
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(Investigation(
            id=investigation_id, created_by="ivy", status="recommendation_ready",
            alert_fingerprint="m7-target-down", alert_name="TargetDown",
            alert_snapshot_json=json.dumps(snapshot),
            analysis_json=json.dumps({
                "summary": "TargetDown requires investigation.", "observations": [],
                "hypotheses": [], "next_checks": [], "limitations": [],
                "model": {"status": "not_configured"},
            }),
        ))
        for position, tool_name in enumerate(
            ("inspect_service_topology", "inspect_target_events"), start=1
        ):
            db_session.add(DiagnosticCheck(
                id=f"00000000-0000-0000-0000-00000000000{position}",
                investigation_id=investigation_id, position=position,
                tool_name=tool_name, title="Existing check", purpose="M7 fixture",
                status="succeeded",
                input_json=json.dumps({
                    "id": f"old-{position}", "investigation_id": investigation_id,
                    "position": position, "tool_name": tool_name, "title": "Existing check",
                    "purpose": "M7 fixture", "namespace": "demo",
                    "service_name": "check-endpoints",
                }),
                result_json=json.dumps({
                    "status": "succeeded", "summary": "Previously completed.",
                    "observations": [], "limitations": [],
                }),
            ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        detail = client.get(
            f"/investigations/{investigation_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert detail.status_code == 200
        assert "Run 1 safe checks" in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        checks = list(db_session.scalars(
            select(DiagnosticCheck).order_by(DiagnosticCheck.position)
        ))
        assert [item.tool_name for item in checks] == [
            "inspect_service_topology", "inspect_target_events", "inspect_monitoring_signal"
        ]
        assert [item.status for item in checks] == ["succeeded", "succeeded", "queued"]
        event = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "diagnostic.plan")
        )
        details = json.loads(event.details_json)
        assert details["tools"] == ["inspect_monitoring_signal"]
        assert details["reason"] == "milestone_9_backfill"
    engine.dispose()


def test_target_down_check_failures_remain_visible_and_model_free(tmp_path: Path) -> None:
    diagnostics = FakeDiagnosticExecutor(fail=True)
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource((target_down(),)),
        diagnostic_executor=diagnostics,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/target-down-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        completed = client.post(
            f"/api/v1/investigations/{investigation_id}/checks/run",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(completed.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert detail.text.count("Synthetic Kubernetes read failed") == 3
        assert "The fixture API was unavailable" in detail.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert all(item.status == "failed" for item in db_session.scalars(select(DiagnosticCheck)))
    engine.dispose()


def test_typed_actions_require_approver_and_execute_once(tmp_path: Path) -> None:
    workload_source = FakeWorkloadSource(crashloop_evidence())
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "ada": Role.APPROVER},
        source=FakeAlertSource((crashloop(),)),
        workload_source=workload_source,
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Approval-gated actions" in detail.text
        assert "Delete Controller Owned Pod" in detail.text
        assert "Restart Workload Rollout" in detail.text
        assert "Approver required" in detail.text
        assert "pod-rv" in detail.text
        assert len(remediation.previews) == 2
        queue = client.get("/", headers={"x-forwarded-user": "ivy"})
        assert "Awaiting approval" in queue.text
        assert re.search(r"Awaiting approval</span>.*?<strong class=\"metric-value\">2</strong>", queue.text, re.S)

        engine = build_engine(settings)
        with Session(engine) as db_session:
            action = db_session.scalar(
                select(RemediationAction).where(
                    RemediationAction.action_type == "delete_controller_owned_pod"
                )
            )
            investigation = db_session.scalar(select(Investigation))
            assert action is not None and investigation is not None
            action_id = action.id
            investigation_id = investigation.id
            assert investigation.status == "awaiting_approval"
        engine.dispose()

        denied = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
        )
        assert denied.status_code == 403
        approved = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert approved.status_code == 303
        result_page = client.get(approved.headers["location"], headers={"x-forwarded-user": "ada"})
        assert "Synthetic verification completed" in result_page.text
        assert "replacement_ready" in result_page.text
        repeated = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert repeated.status_code == 409

    assert len(remediation.executions) == 1
    engine = build_engine(settings)
    with Session(engine) as db_session:
        action = db_session.get(RemediationAction, action_id)
        investigation = db_session.get(Investigation, investigation_id)
        assert action is not None and action.status == "resolved"
        assert action.approved_by == "ada"
        assert investigation is not None and investigation.status == "resolved"
        sibling = db_session.scalar(
            select(RemediationAction).where(RemediationAction.id != action_id)
        )
        assert sibling is not None and sibling.status == "cancelled"
        audit_actions = list(db_session.scalars(select(AuditEvent.action)))
        assert "remediation.preview" in audit_actions
        assert "remediation.approve" in audit_actions
        assert "remediation.execute" in audit_actions
        assert "remediation.cancel_siblings" in audit_actions
    engine.dispose()


def test_investigation_creator_can_cancel_previews_without_execution(tmp_path: Path) -> None:
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "eve": Role.INVESTIGATOR, "ada": Role.APPROVER},
        source=FakeAlertSource((crashloop(),)),
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            action_ids = list(
                db_session.scalars(
                    select(RemediationAction.id).order_by(RemediationAction.created_at)
                )
            )
        engine.dispose()

        denied = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_ids[0]}/cancel",
            headers={"x-forwarded-user": "eve", "x-podpilot-csrf": csrf.group(1)},
        )
        assert denied.status_code == 403
        for action_id in action_ids:
            cancelled = client.post(
                f"/api/v1/investigations/{investigation_id}/actions/{action_id}/cancel",
                headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
                follow_redirects=False,
            )
            assert cancelled.status_code == 303
        rejected_approval = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_ids[0]}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert rejected_approval.status_code == 409

    assert remediation.executions == []
    engine = build_engine(settings)
    with Session(engine) as db_session:
        actions = list(db_session.scalars(select(RemediationAction)))
        investigation = db_session.get(Investigation, investigation_id)
        assert all(action.status == "cancelled" for action in actions)
        assert all(json.loads(action.result_json or "{}")["closure"]["actor"] == "ivy" for action in actions)
        assert investigation is not None and investigation.status == "cancelled"
        assert list(db_session.scalars(select(AuditEvent.action))).count("remediation.cancel") == 2
    engine.dispose()


def test_dashboard_cancels_previews_when_source_alert_resolves(tmp_path: Path) -> None:
    source = FakeAlertSource((crashloop(),))
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=source,
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        source.alerts = ()
        reconciled = client.get("/", headers={"x-forwarded-user": "ada"})
        assert re.search(
            r"Awaiting approval</span>.*?<strong class=\"metric-value\">0</strong>",
            reconciled.text,
            re.S,
        )

    engine = build_engine(settings)
    with Session(engine) as db_session:
        actions = list(db_session.scalars(select(RemediationAction)))
        investigation = db_session.get(Investigation, investigation_id)
        assert all(action.status == "cancelled" for action in actions)
        assert investigation is not None and investigation.status == "cancelled"
        events = list(
            db_session.scalars(
                select(AuditEvent).where(AuditEvent.action == "remediation.reconcile")
            )
        )
        assert len(events) == 2
        assert all(json.loads(event.details_json)["reason"] == "source_alert_not_active" for event in events)
    engine.dispose()


def test_missing_target_is_reconciled_on_investigation_view(tmp_path: Path) -> None:
    remediation = FakeRemediationExecutor(validation="missing")
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource((crashloop(),)),
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        detail = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert detail.status_code == 200
        assert detail.text.count("The preview was cancelled because its exact target is no longer current") == 2
        assert "Closed by system:reconciler" in detail.text

    assert len(remediation.validations) == 2
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert all(
            action.status == "cancelled"
            for action in db_session.scalars(select(RemediationAction))
        )
    engine.dispose()


def test_approval_fails_closed_when_source_alert_is_no_longer_active(tmp_path: Path) -> None:
    source = FakeAlertSource((crashloop(),))
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=source,
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            action_id = db_session.scalar(select(RemediationAction.id))
        engine.dispose()
        source.alerts = ()
        rejected = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert rejected.status_code == 409
        assert "source alert is no longer active" in rejected.text.lower()
    assert remediation.executions == []
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert all(
            action.status == "cancelled"
            for action in db_session.scalars(select(RemediationAction))
        )
    engine.dispose()


def test_truncated_alert_snapshot_neither_cancels_nor_authorizes(tmp_path: Path) -> None:
    source = FakeAlertSource((crashloop(),))
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=source,
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            action_id = db_session.scalar(select(RemediationAction.id))
        engine.dispose()
        source.alerts = ()
        source.is_complete = False
        client.get("/", headers={"x-forwarded-user": "ada"})
        rejected = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert rejected.status_code == 503
        assert "snapshot was truncated" in rejected.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.get(RemediationAction, action_id).status == "preview_ready"
    engine.dispose()
    assert remediation.executions == []


def test_expired_preview_fails_without_execution(tmp_path: Path) -> None:
    remediation = FakeRemediationExecutor()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource((crashloop(),)),
        workload_source=FakeWorkloadSource(crashloop_evidence()),
        remediation_executor=remediation,
    )
    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/crashloop-1/investigations",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            action = db_session.scalar(select(RemediationAction))
            assert action is not None
            action.expires_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
            action_id = action.id
            db_session.commit()
        engine.dispose()
        expired = client.post(
            f"/api/v1/investigations/{investigation_id}/actions/{action_id}/approve",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert expired.status_code == 409
        assert "preview expired" in expired.text.lower()
    assert remediation.executions == []


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
        assert "AI evidence interpretation" in detail.text
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
