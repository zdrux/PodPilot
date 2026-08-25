import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app
from podpilot_api.model_provider import (
    AdHocAnswer,
    CapabilityReport,
    InvestigationChatAnswer,
    ModelInterpretation,
    ModelProviderError,
)
from podpilot_api.models import (
    AdHocConversation,
    AdHocMessage,
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
from podpilot_diagnostics.adhoc import AdHocObservation, ReadIntent, ReadPlan, ReadResult
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
        self.values: dict[str, str] = {}

    def get(self, key: str | None = None) -> str | None:
        return self.values.get(key or "api_key", self.value)

    def set(self, value: str, key: str | None = None) -> None:
        self.value = value
        self.values[key or "api_key"] = value

    def delete(self, key: str | None = None) -> None:
        self.values.pop(key or "api_key", None)


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
        self.adhoc_plan_calls: list[dict[str, object]] = []
        self.adhoc_answer_calls: list[dict[str, object]] = []

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

    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if context.get("completed_reads"):
            return ReadPlan(scope_summary="The requested Pod evidence is sufficient.", intents=[])
        return ReadPlan(
            scope_summary="Inspect the selected Pod and its configuration.",
            intents=[ReadIntent(
                tool="get_resource", api_version="v1", kind="Pod",
                namespace="payments", name="api-7d9",
            )],
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        evidence_id = context["observations"][-1]["id"]
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer="The Pod selector does not match an available node.",
            cited_evidence_ids=[evidence_id],
            limitations=["No scheduler event was collected."],
        )


class FakeReadExplorer:
    def __init__(self):
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        return ReadResult((AdHocObservation(
            id="cluster-pod-1", tool=intent.tool,
            summary="Read Pod payments/api-7d9.", source="kubernetes:v1:Pod:payments/api-7d9",
            collected_at=datetime.now(timezone.utc),
            data={"spec": {"nodeSelector": {"tier": "missing"}}, "status": {"phase": "Pending"}},
        ),))


class DiscoveryThenLogsProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        round_number = context["investigation_round"]
        if round_number == 1:
            return ReadPlan(
                scope_summary="Discover kube-apiserver Pods.",
                limitations=["An exact Pod name is needed before logs can be read."],
                intents=[ReadIntent(
                    tool="list_resources", api_version="v1", kind="Pod",
                    namespace="openshift-kube-apiserver", limit=5,
                )],
            )
        if round_number == 2:
            assert context["observations"][-1]["data"]["containers"] == ["kube-apiserver"]
            return ReadPlan(scope_summary="Inspect the discovered kube-apiserver logs.", intents=[ReadIntent(
                tool="pod_logs", namespace="openshift-kube-apiserver",
                name="kube-apiserver-sno1", container="kube-apiserver",
            )])
        return ReadPlan(scope_summary="The log evidence is sufficient.", intents=[])

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        log = next(item for item in context["observations"] if item["tool"] == "pod_logs")
        return AdHocAnswer(
            answer_mode="evidence_based", answer="No error lines appeared in the bounded log tail.",
            cited_evidence_ids=[log["id"]], limitations=[],
        )


class DiscoveryThenLogsExplorer:
    def __init__(self):
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        if intent.tool == "list_resources":
            return ReadResult((AdHocObservation(
                id="cluster-pod-list", tool="list_resources",
                summary="Discovered kube-apiserver-sno1.",
                source="kubernetes:v1:Pod:openshift-kube-apiserver/kube-apiserver-sno1",
                collected_at=datetime.now(timezone.utc),
                data={"name": "kube-apiserver-sno1", "containers": ["kube-apiserver"]},
            ),))
        return ReadResult((AdHocObservation(
            id="cluster-api-logs", tool="pod_logs", summary="Collected kube-apiserver logs.",
            source="kubernetes:v1:Pod/log:openshift-kube-apiserver/kube-apiserver-sno1",
            collected_at=datetime.now(timezone.utc), data={"tail": "request completed successfully"},
        ),))


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
    read_explorer: FakeReadExplorer | None = None,
    settings_overrides: dict[str, object] | None = None,
):
    settings = Settings(
        environment="test",
        cluster_name="test-cluster",
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'podpilot.db'}",
        web_dir=ROOT / "apps" / "web",
        auth_mode="test",
        poc_mode=True,
        **(settings_overrides or {}),
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
            read_explorer or FakeReadExplorer(),
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
        assert "Milestone 10 adds" in response.text
        assert "PodPilot 0.11.0" in response.text
        assert "Milestone 2 analysis" not in response.text
        assert "synthetic-secret" not in response.text
        assert "No actionable alerts" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        session = client.get("/api/v1/session", headers={"x-forwarded-user": "ada"})
        assert session.json() == {"username": "ada", "role": "approver"}
        assert client.get("/health/ready").json() == {"status": "ready", "database": True}


def test_ask_podpilot_runs_bounded_reads_and_persists_cited_answer(tmp_path: Path) -> None:
    provider = FakeModelProvider()
    explorer = FakeReadExplorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert page.status_code == 200
        assert "Investigation mode cannot change the cluster" in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Why is pod api-7d9 pending in payments?"},
            follow_redirects=False,
        )
        assert created.status_code == 303
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "selector does not match" in rendered.text
        assert "Inspected 1 cluster target" in rendered.text
        assert "cluster-pod-1" in rendered.text

    assert len(explorer.calls) == 1
    assert explorer.calls[0].tool == "get_resource"
    assert provider.adhoc_plan_calls[0]["tool_policy"]["logs_and_configmaps_allowed"] is True
    assert provider.adhoc_answer_calls[0]["observations"][0]["id"] == "cluster-pod-1"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.scalar(select(func.count()).select_from(AdHocConversation)) == 1
        assert db_session.scalar(select(func.count()).select_from(AdHocMessage)) == 2
        actions = list(db_session.scalars(select(AuditEvent.action)))
        assert "adhoc.message" in actions and "adhoc.answer" in actions
    engine.dispose()


def test_ask_podpilot_discovers_pod_then_reads_exact_container_logs(tmp_path: Path) -> None:
    provider = DiscoveryThenLogsProvider()
    explorer = DiscoveryThenLogsExplorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Are there errors in the kube API server Pod logs?"},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert rendered.status_code == 200
        assert "No error lines appeared" in rendered.text
        assert "Inspected 2 cluster targets" in rendered.text
        assert "container=kube-apiserver" in rendered.text
        assert "cluster-api-logs" in rendered.text
        assert "exact Pod name is needed" not in rendered.text

    assert [call.tool for call in explorer.calls] == ["list_resources", "pod_logs"]
    assert provider.adhoc_plan_calls[1]["tool_policy"]["remaining_reads"] == 5
    assert provider.adhoc_plan_calls[1]["completed_reads"][0]["round"] == 1
    assert provider.adhoc_plan_calls[2]["observations"][-1]["tool"] == "pod_logs"


def test_ask_podpilot_is_investigator_gated(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path, assignments={"vic": Role.VIEWER}, source=FakeAlertSource()
    )
    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "vic"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        denied = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "vic", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Inspect everything"},
        )
        assert denied.status_code == 403


def test_adhoc_conversations_are_private_to_their_openshift_creator(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "ada": Role.APPROVER},
        source=FakeAlertSource(),
    )
    conversation_id = "00000000-0000-0000-0000-000000000088"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Private DNS question",
            status="active", evidence_json="[]",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        own = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        assert own.status_code == 200
        other_index = client.get("/ask", headers={"x-forwarded-user": "ada"})
        assert "Private DNS question" not in other_index.text
        assert client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ada"}
        ).status_code == 404


def test_owner_can_delete_conversation_and_evidence_with_audit_record(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource()
    )
    conversation_id = "00000000-0000-0000-0000-000000000089"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Delete me",
            status="active", evidence_json='[{"id":"evidence-to-delete"}]',
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000090",
            conversation_id=conversation_id, role="user", actor="ivy", content="Delete me",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        assert "Delete conversation" in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        deleted = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/delete",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert deleted.status_code == 303 and deleted.headers["location"] == "/ask"

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.get(AdHocConversation, conversation_id) is None
        assert db_session.scalar(
            select(func.count()).select_from(AdHocMessage).where(
                AdHocMessage.conversation_id == conversation_id
            )
        ) == 0
        event = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "adhoc.delete"))
        assert event is not None and event.actor == "ivy"
    engine.dispose()


def test_unlimited_conversation_uses_rolling_context_summary(tmp_path: Path) -> None:
    provider = FakeModelProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(), credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider, settings_overrides={"adhoc_context_messages": 10},
    )
    conversation_id = "00000000-0000-0000-0000-000000000091"
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenAI", base_url="https://api.openai.com/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Long-running incident",
            status="active", evidence_json="[]",
        ))
        for index in range(26):
            db_session.add(AdHocMessage(
                id=f"10000000-0000-0000-0000-{index:012d}", conversation_id=conversation_id,
                created_at=old + timedelta(seconds=index),
                role="user" if index % 2 == 0 else "assistant",
                actor="ivy" if index % 2 == 0 else None,
                content=f"historical message {index}",
            ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        continued = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Continue checking the same incident."},
            follow_redirects=False,
        )
        assert continued.status_code == 303

    assert len(provider.adhoc_plan_calls[0]["conversation"]) == 10
    assert "historical message 0" in provider.adhoc_plan_calls[0]["earlier_context_summary"]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        conversation = db_session.get(AdHocConversation, conversation_id)
        assert conversation is not None and conversation.summarized_message_count == 17
    engine.dispose()


def test_adhoc_rate_limit_is_per_user_not_per_conversation(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
        settings_overrides={"adhoc_rate_limit_per_minute": 1},
    )
    conversation_id = "00000000-0000-0000-0000-000000000092"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Rate limited",
            status="active", evidence_json="[]",
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000093",
            conversation_id=conversation_id, role="user", actor="ivy", content="First",
        ))
        db_session.commit()
    engine.dispose()
    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        limited = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Second"},
        )
        assert limited.status_code == 429


def test_ask_ui_documents_keyboard_and_unlimited_session_behavior() -> None:
    template = (ROOT / "apps" / "web" / "templates" / "ask.html").read_text()
    script = (ROOT / "apps" / "web" / "static" / "app.js").read_text()
    assert "Conversation budget reached" not in template
    assert "Enter to send" in template and "Shift+Enter for a new line" in template
    assert 'event.key === "Enter" && !event.shiftKey' in script
    assert "adhocForm.requestSubmit()" in script
    assert 'document.querySelectorAll(\'.chat-citations a[href^="#evidence-"]\')' in script
    assert "target.scrollIntoView" in script
    assert 'tabindex="-1"' in template
    assert "data-scroll-latest" in template
    assert "latestThread.scrollTop = latestThread.scrollHeight" in script
    assert "message.content | safe_markdown" in template


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
        rejected_ca = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "provider_label": "Unsafe CA",
                "base_url": "https://models.example.test/v1",
                "chat_model": "test-model",
                "api_token": "test-api-token",
                "tls_mode": "custom_ca",
                "custom_ca_pem": "-----BEGIN PRIVATE KEY-----",
            },
        )
        assert rejected_ca.status_code == 422
        assert "must not contain a private key" in rejected_ca.json()["detail"]
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
        assert saved.json()["status"] == "saved"
        assert saved.json()["token_configured"] is True
        assert saved.json()["profile_id"] == 1
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


def test_model_registry_uses_distinct_secret_keys_and_one_active_profile(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore()
    provider = FakeModelProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        credential_store=credentials,
        model_provider=provider,
    )
    with TestClient(app) as client:
        page = client.get("/settings/model", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        first = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                "provider_label": "Public OpenAI",
                "base_url": "https://api.openai.com/v1",
                "chat_model": "gpt-5.6-terra",
                "api_token": "test-api-token",
                "timeout_seconds": "30",
                "max_input_tokens": "128000",
                "max_output_tokens": "1200",
            },
        )
        second = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                "provider_label": "Enterprise gateway",
                "base_url": "https://models.example.test/v1",
                "chat_model": "gemma-4-31b-it",
                "api_type": "chat-completions",
                "api_token": "test-api-token",
                "tls_mode": "insecure",
                "timeout_seconds": "45",
                "max_input_tokens": "128000",
                "max_output_tokens": "10000",
                "tool_calling_hint": "true",
                "vision_hint": "true",
            },
        )
        first_id = first.json()["profile_id"]
        second_id = second.json()["profile_id"]
        assert first_id != second_id
        assert len(credentials.values) == 2
        credential_keys = set(credentials.values)

        probe = client.post(f"/api/v1/model-profiles/{second_id}/probe", headers=headers, data={})
        assert probe.json()["status"] == "ready"
        activated = client.post(
            f"/api/v1/model-profiles/{second_id}/activate", headers=headers, data={}
        )
        assert activated.json() == {"status": "active", "profile_id": second_id}
        deleted = client.post(
            f"/api/v1/model-profiles/{first_id}/delete", headers=headers, data={}
        )
        assert deleted.json() == {"status": "deleted"}

    engine = build_engine(settings)
    with Session(engine) as db_session:
        profiles = list(db_session.scalars(select(ModelProfile).order_by(ModelProfile.id)))
        assert len(profiles) == 1
        assert profiles[0].id == second_id
        assert profiles[0].is_active is True
        assert profiles[0].api_type == "chat-completions"
        assert profiles[0].tls_mode == "insecure"
        assert profiles[0].tool_calling_hint is True
        assert profiles[0].vision_hint is True
        assert profiles[0].credential_key in credentials.values
    assert len(credentials.values) == 1
    assert set(credentials.values) < credential_keys
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
