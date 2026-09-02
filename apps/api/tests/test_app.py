import asyncio
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.knowledge import index_document
from podpilot_api.main import (
    _adhoc_answer_quality_issue,
    _adhoc_answer_advisories,
    _adhoc_capability_wording_issue,
    _adhoc_evidence_view,
    _agent_collector_error_detail,
    _agent_collector_failure_category,
    _command_failure_category,
    _agent_duplicate_command_issue,
    _agent_tool_retry_guidance,
    _agent_final_answer_quality_issue,
    _recover_serialized_agent_completion,
    _agent_premature_deferral_issue,
    _bounded_agent_provider_result,
    _bind_plan_log_intents,
    _bounded_detail_fanout,
    _build_delegated_read_only_explorer,
    _make_delegated_read_only_explorer,
    _classify_ad_hoc_inquiry,
    _collection_object_analysis_requested,
    _collect_bounded_cluster_reads,
    _clean_adhoc_markdown,
    _compact_agent_knowledge,
    _compact_answer_evidence,
    _compile_grounded_candidate_plan,
    _current_reads_are_metric_rankings,
    _dedupe_limitations,
    _deterministic_evidence_fallback_answer,
    _deterministic_configuration_comparison_answer,
    _deterministic_configuration_comparison_unavailable_answer,
    _deterministic_audit_answer,
    _deterministic_access_review_answer,
    _deterministic_inventory_answer,
    _deterministic_metric_ranking_answer,
    _deterministic_metric_summary_answer,
    _deterministic_pod_health_answer,
    _deterministic_resource_health_answer,
    _deterministic_log_findings_section,
    _deterministic_provider_failure_answer,
    _deterministic_resource_detail_answer,
    _deterministic_route_tls_answer,
    _explicit_router_pod_metric_inquiry,
    _format_est_time,
    _summarize_tool_activity,
    _summarize_agent_command_failures,
    _stream_delegated_upstream,
    _grounded_read_candidates,
    _claims_complete_pod_health,
    _investigation_capability_ledger,
    _investigation_unit_cost,
    _jq_filters_from_shell_command,
    _jq_preflight_command,
    _inventory_plan_scope_errors,
    _is_access_review_question,
    _is_broad_pod_health_question,
    _latest_audit_query_semantics,
    _latest_metric_query_semantics,
    _latest_resource_query_semantics,
    _metric_trend_view,
    _merge_validated_recommendations,
    _model_fact_cards,
    _parse_tags,
    _preferred_metric_evidence_view,
    _profile_is_usable,
    _question_requires_agentic_investigation,
    _read_only_proxy_allows,
    _question_cluster_ids,
    _normalize_agent_collector_arguments,
    _recent_object_references,
    _resource_list_presentation,
    _resource_analysis_coverage,
    _resource_configuration_comparisons,
    _configuration_comparison_answer_issue,
    _inquiry_reference_cluster_ids,
    _semantic_metric_read_plan,
    _semantic_audit_read_plan,
    _semantic_resource_read_plan,
    _resolve_audit_inquiry,
    _resolve_metric_inquiry,
    _resolve_resource_inquiry,
    _resource_followup_reuses_snapshot,
    _reuse_prior_resource_evidence,
    _safe_exception_diagnostics,
    _validated_adhoc_answer,
    SYSTEM_CLUSTER_ID,
    create_app,
)
from podpilot_api.model_provider import (
    AgentStep,
    AgentToolCall,
    AdHocAnswer,
    AdHocLogAnalysis,
    LogAnalysisIssue,
    CapabilityReport,
    InvestigationChatAnswer,
    InquirySemantics,
    MetricRequestSemantics,
    MetricTargetSemantics,
    ModelProfileConfig,
    ModelInterpretation,
    ModelProviderError,
    ResourceFieldFilterSemantics,
)
from podpilot_api.models import (
    AdHocConversation,
    AdHocMessage,
    AdHocRun,
    AuditEvent,
    Base,
    ChatMessage,
    Cluster,
    DiagnosticCheck,
    Investigation,
    KnowledgeDocument,
    ModelProfile,
    RemediationAction,
    UserModelPreference,
)
from podpilot_api.settings import Settings
from podpilot_diagnostics.workloads import (
    ContainerEvidence,
    EventEvidence,
    OwnerEvidence,
    WorkloadEvidence,
)
from podpilot_diagnostics.checks import CheckObservation, DiagnosticCheckResult
from podpilot_diagnostics.adhoc import (
    AdHocObservation,
    InvestigationGap,
    ReadIntent,
    ReadPlan,
    ReadResult,
)
from podpilot_diagnostics.remediation import ActionResult, ActionValidation
from podpilot_openshift.alerts import AlertRecord, AlertSnapshot, AlertSourceError
from podpilot_openshift.agent_runner import AgentClusterConnection, AgentCommandResult
from podpilot_openshift.credentials import CredentialStoreError
from podpilot_openshift.explorer import KubernetesReadOnlyExplorer, ReadOnlyExplorerError
from podpilot_openshift.log_metrics import LokiQueryClient, LogMetricsQueryError
from podpilot_openshift.metric_trends import BoundedMetricTrendReader
from podpilot_openshift.metrics import ThanosQueryClient
from podpilot_openshift.workloads import WorkloadEvidenceError

ROOT = Path(__file__).resolve().parents[3]


def test_collection_analysis_expands_only_small_complete_inventory() -> None:
    inquiry = InquirySemantics(
        mode="investigate", cardinality="collection",
        resource_query="ClusterLogForwarder", needs_object_details=True,
        evidence_goal="Analyze every ClusterLogForwarder configuration.",
    )
    observations = (AdHocObservation(
        id="cluster-forwarders", tool="list_resources",
        summary="Listed ClusterLogForwarders.", source="cluster-api",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "observability.openshift.io/v1",
            "kind": "ClusterLogForwarder",
            "resource": "clusterlogforwarders.observability.openshift.io",
            "scope": "all-namespaces",
            "count": 2,
            "objectListComplete": True,
            "objects": [
                {"name": "instance", "namespace": "openshift-logging"},
                {"name": "application", "namespace": "team-a"},
            ],
        },
    ),)

    assert _collection_object_analysis_requested(
        "Analyze the cluster log forwarders", inquiry,
    ) is True
    intents, limitations = _bounded_detail_fanout(observations, max_objects=10)

    assert limitations == []
    assert intents == [
        ReadIntent(
            tool="get_resource",
            resource="clusterlogforwarders.observability.openshift.io",
            api_version="observability.openshift.io/v1",
            kind="ClusterLogForwarder",
            namespace="openshift-logging",
            name="instance",
        ),
        ReadIntent(
            tool="get_resource",
            resource="clusterlogforwarders.observability.openshift.io",
            api_version="observability.openshift.io/v1",
            kind="ClusterLogForwarder",
            namespace="team-a",
            name="application",
        ),
    ]


def test_explicit_comparison_overrides_plain_inventory_classification() -> None:
    inquiry = InquirySemantics(
        mode="inventory", operation="inventory", cardinality="collection",
        resource_query="ClusterLogForwarder", needs_object_details=False,
        evidence_goal="Locate ClusterLogForwarders.",
    )

    assert _collection_object_analysis_requested(
        "Compare the ClusterLogForwarder on each cluster and summarize the differences.",
        inquiry,
    ) is True


@pytest.mark.parametrize("classified_cardinality", ["collection", "unknown", "exact_one"])
def test_collection_configuration_guidance_does_not_compile_removed_list_helper(
    classified_cardinality: str,
) -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="explain", operation="configuration_guidance",
            cardinality=classified_cardinality, answer_goal="configuration",
            resource_query="ClusterLogForwarder", needs_object_details=False,
            evidence_goal="Compare ClusterLogForwarder configurations.",
        ),
        resource_catalog=[{
            "resource": "clusterlogforwarders.observability.openshift.io",
            "apiVersion": "observability.openshift.io/v1",
            "kind": "ClusterLogForwarder", "namespaced": True,
            "verbs": ["get", "list"],
        }],
        question="Compare the ClusterLogForwarder on each cluster.",
        conversation=[], inventory_limit=500,
    )

    assert compiled is None


def test_cross_cluster_comparison_overrides_erroneous_exact_one_classification() -> None:
    inquiry = InquirySemantics(
        mode="explain", operation="configuration_guidance",
        cardinality="exact_one", answer_goal="configuration",
        resource_query="ClusterLogForwarder", needs_object_details=False,
        evidence_goal="Compare ClusterLogForwarder configurations.",
    )

    assert _collection_object_analysis_requested(
        "Compare the ClusterLogForwarder configurations across the two clusters.",
        inquiry,
    ) is True


def test_collection_analysis_does_not_sample_large_inventory() -> None:
    observations = (AdHocObservation(
        id="cluster-namespaces", tool="list_resources",
        summary="Listed Namespaces.", source="cluster-api",
        collected_at=datetime.now(timezone.utc),
        data={
            "apiVersion": "v1", "kind": "Namespace", "resource": "namespaces",
            "scope": "cluster", "count": 11, "objectListComplete": True,
            "objects": [{"name": f"namespace-{index}"} for index in range(11)],
        },
    ),)

    intents, limitations = _bounded_detail_fanout(observations, max_objects=10)

    assert intents == []
    assert limitations == [
        "The Namespace LIST found 11 objects. Automatic object analysis is capped at 10, "
        "so PodPilot performed no blanket GET fan-out; narrow the scope or apply a filter "
        "for configuration-level analysis."
    ]


def test_configuration_comparison_does_not_invoke_removed_list_helper() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "clusterlogforwarders.observability.openshift.io",
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder",
                "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            if intent.tool == "list_resources":
                return ReadResult((AdHocObservation(
                    id="clf-list", tool="list_resources",
                    summary="Listed ClusterLogForwarders.", source="cluster-api",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "apiVersion": "observability.openshift.io/v1",
                        "kind": "ClusterLogForwarder",
                        "resource": "clusterlogforwarders.observability.openshift.io",
                        "scope": "cluster",
                        "count": 1,
                        "objectListComplete": True,
                        "objects": [{
                            "namespace": "openshift-logging", "name": "instance",
                        }],
                    },
                ),))
            assert intent.tool == "get_resource"
            return ReadResult((AdHocObservation(
                id="clf-detail", tool="get_resource",
                summary="Read ClusterLogForwarder openshift-logging/instance.",
                source="cluster-api", collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "observability.openshift.io/v1",
                    "kind": "ClusterLogForwarder",
                    "metadata": {"namespace": "openshift-logging", "name": "instance"},
                    "spec": {"pipelines": [{"name": "application", "outputRefs": ["default"]}]},
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="compare-clf",
        question="Compare the ClusterLogForwarder configurations across the two clusters.",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            capability="configuration_guidance", mode="explain",
            operation="configuration_guidance",
            cardinality="exact_one", answer_goal="configuration",
            resource_query="ClusterLogForwarder", needs_object_details=False,
            evidence_goal="Compare every ClusterLogForwarder specification.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []


def test_exact_cluster_configuration_comparison_detects_structural_differences() -> None:
    evidence = [
        {
            "id": "central-detail", "cluster_id": "central",
            "cluster_name": "Simplii Central DEV", "tool": "get_resource",
            "data": {
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder",
                "metadata": {"namespace": "openshift-logging", "name": "instance"},
                "spec": {
                    "outputs": [{"name": "default", "type": "lokistack"}],
                    "pipelines": [{"name": "application", "outputRefs": ["default"]}],
                },
            },
        },
        {
            "id": "east-detail", "cluster_id": "east",
            "cluster_name": "Simplii East DEV", "tool": "get_resource",
            "data": {
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder",
                "metadata": {"namespace": "openshift-logging", "name": "instance"},
                "spec": {
                    "outputs": [{"name": "east-loki", "type": "lokistack"}],
                    "pipelines": [{"name": "application", "outputRefs": ["east-loki"]}],
                },
            },
        },
    ]
    activity = [{
        "status": "succeeded", "evidence_ids": ["central-detail", "east-detail"],
    }]

    comparisons = _resource_configuration_comparisons(
        evidence=evidence, activity=activity,
    )

    assert len(comparisons) == 1
    assert comparisons[0]["specs_equal"] is False
    assert {item["path"] for item in comparisons[0]["differing_paths"]} == {
        "spec.outputs[0].name", "spec.pipelines[0].outputRefs[0]",
    }
    assert _configuration_comparison_answer_issue(
        content="Their specifications are identical.",
        citations=["central-list", "east-list"],
        comparisons=comparisons,
    ) == "missing_exact_configuration_citations"
    assert _configuration_comparison_answer_issue(
        content="No other status fields or configuration details differ.",
        citations=["central-detail", "east-detail"],
        comparisons=comparisons,
    ) == "configuration_comparison_contradicts_exact_evidence"
    rendered = _deterministic_configuration_comparison_answer(comparisons)
    assert rendered["citations"] == ["central-detail", "east-detail"]
    assert "The specifications differ at 2 field path(s)." in rendered["content"]
    assert "`spec.outputs[0].name`" in rendered["content"]


def test_incomplete_exact_configuration_comparison_refuses_inventory_equality() -> None:
    rendered = _deterministic_configuration_comparison_unavailable_answer(
        evidence=[
            {"id": "central-list", "tool": "list_resources"},
            {"id": "east-list", "tool": "list_resources"},
            {"id": "central-get", "tool": "get_resource"},
        ],
        activity=[{
            "status": "succeeded",
            "evidence_ids": ["central-list", "east-list", "central-get"],
        }],
    )

    assert rendered["answer_mode"] == "insufficient_evidence"
    assert rendered["citations"] == ["central-list", "east-list", "central-get"]
    assert "cannot establish that the specifications are identical" in rendered["content"]


def test_resource_analysis_coverage_requires_details_in_final_model_context() -> None:
    evidence = [{
        "id": "inventory", "cluster_id": "central", "cluster_name": "Central",
        "tool": "list_resources", "data": {
            "apiVersion": "example.io/v1", "kind": "Widget",
            "objectListComplete": True,
            "objects": [
                {"namespace": "one", "name": "first"},
                {"namespace": "two", "name": "second"},
            ],
        },
    }, {
        "id": "first-detail", "cluster_id": "central", "cluster_name": "Central",
        "tool": "get_resource", "data": {
            "apiVersion": "example.io/v1", "kind": "Widget",
            "metadata": {"namespace": "one", "name": "first"},
        },
    }, {
        "id": "second-detail", "cluster_id": "central", "cluster_name": "Central",
        "tool": "get_resource", "data": {
            "apiVersion": "example.io/v1", "kind": "Widget",
            "metadata": {"namespace": "two", "name": "second"},
        },
    }]
    activity = [{
        "status": "succeeded",
        "evidence_ids": ["inventory", "first-detail", "second-detail"],
    }]

    coverage = _resource_analysis_coverage(
        evidence=evidence, activity=activity, included_evidence_ids={"first-detail"},
    )

    assert coverage == [{
        "cluster_id": "central", "cluster_name": "Central",
        "api_version": "example.io/v1", "kind": "Widget",
        "inventory_complete": True, "discovered_count": 2,
        "inspected_count": 2, "details_supplied_count": 1,
        "analysis_complete": False,
    }]


def test_disabled_list_tool_is_not_offered_as_a_grounded_candidate() -> None:
    candidates = _grounded_read_candidates(
        question="List Widgets.", evidence=[], relationship_graph={},
        recovery_anchor_plan=ReadPlan(
            scope_summary="List Widgets.",
            intents=[ReadIntent(
                tool="list_resources", resource="widgets.example.io",
                api_version="example.io/v1", kind="Widget",
            )],
        ),
        seen_intents=set(),
    )

    assert candidates == []


def test_removed_list_tool_rejects_model_authored_list_without_execution() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return ReadPlan(
                scope_summary="List Widgets.",
                intents=[ReadIntent(
                    tool="list_resources", resource="widgets.example.io",
                    api_version="example.io/v1", kind="Widget",
                )],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            raise AssertionError("disabled list tool must not execute")

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="list-disabled", question="List Widgets.",
        conversation=[], existing_evidence=[],
    ))

    assert explorer.calls == []
    assert result.evidence == []
    assert any("removed list_resources helper" in item for item in result.limitations)


def _agent_accepts_seeded_evidence(*args, **kwargs) -> ReadPlan:
    context = kwargs.get("context") or args[-1]
    evidence_ids = [
        str(item["id"])
        for item in context.get("observations", [])
        if isinstance(item, dict) and item.get("id")
    ]
    if evidence_ids and context.get("completed_reads"):
        return ReadPlan(
            scope_summary="The agent considers the seeded evidence sufficient.",
            decision="answer_from_evidence",
            stop_reason="evidence_sufficient",
            supporting_evidence_ids=evidence_ids,
            intents=[],
        )
    candidates = [
        item for item in context.get("read_candidates", [])
        if isinstance(item, dict) and item.get("id")
    ]
    if candidates:
        return ReadPlan(
            scope_summary="The test agent selected the relevant bounded evidence candidates.",
            candidate_ids=[str(item["id"]) for item in candidates[:8]],
        )
    return ReadPlan(
        scope_summary="The agent considers the seeded evidence sufficient.",
        decision="answer_from_evidence",
        stop_reason="evidence_sufficient",
        supporting_evidence_ids=evidence_ids,
        intents=[],
    )


def _agent_final_step(content: str = "The agent interpreted the collected evidence.") -> AgentStep:
    return AgentStep(
        assistant_message={"role": "assistant", "content": content},
        content=content,
        tool_calls=(),
    )


def test_read_only_proxy_blocks_mutations_and_allows_access_reviews() -> None:
    assert _read_only_proxy_allows("GET", "/api") is True
    assert _read_only_proxy_allows("GET", "/apis") is True
    assert _read_only_proxy_allows("GET", "/apis/apps/v1") is True
    assert _read_only_proxy_allows("GET", "/api/v1/pods") is True
    assert _read_only_proxy_allows("GET", "/api/v1/secrets") is False
    assert _read_only_proxy_allows(
        "GET", "/api/v1/namespaces/dev/secrets/database"
    ) is False
    assert _read_only_proxy_allows(
        "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
    ) is True
    assert _read_only_proxy_allows("POST", "/api/v1/namespaces/dev/pods") is False
    assert _read_only_proxy_allows(
        "POST", "/api/v1/namespaces/dev/pods/api/exec"
    ) is False
    assert _read_only_proxy_allows(
        "POST", "/api/v1/namespaces/dev/pods/api/attach"
    ) is False
    assert _read_only_proxy_allows(
        "POST", "/api/v1/namespaces/dev/pods/api/portforward"
    ) is False
    assert _read_only_proxy_allows(
        "GET", "/api/v1/namespaces/dev/pods/api/proxy/metrics"
    ) is False
    assert _read_only_proxy_allows("PUT", "/api/v1/pods/api/status") is False
    assert _read_only_proxy_allows("PATCH", "/apis/apps/v1/deployments/api") is False
    assert _read_only_proxy_allows("DELETE", "/api/v1/pods/api") is False


def test_delegated_proxy_logs_bounded_redacted_upstream_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = ("token=sensitive-token " + ("router unavailable " * 300)).encode()
    upstream = httpx.Response(
        503,
        request=httpx.Request("GET", "https://api.example.test/apis/apps/v1/deployments"),
        content=body,
    )

    async def collect() -> bytes:
        chunks = bytearray()
        async for chunk in _stream_delegated_upstream(
            upstream,
            actor="ivy",
            cluster_id="cluster-east",
            method="GET",
            remote_target="/apis/apps/v1/deployments",
        ):
            chunks.extend(chunk)
        return bytes(chunks)

    streamed = asyncio.run(collect())

    assert streamed == body
    assert "status_code=503" in caplog.text
    assert "response_truncated=True" in caplog.text
    assert "body_complete=True" in caplog.text
    assert "response_sha256=" in caplog.text
    assert "token=[REDACTED]" in caplog.text
    assert "sensitive-token" not in caplog.text
    assert len(caplog.text) < 3_000


def test_agent_knowledge_is_bounded_deduplicated_and_cluster_attributed() -> None:
    knowledge = [
        {
            "chunk_id": f"chunk-{index}",
            "title": f"Runbook {index}",
            "content": "x" * 1600,
            "source": "Platform runbook",
            "rank": float(index),
            "applicable_cluster": {
                "id": f"cluster-{index}", "name": f"Cluster {index}",
            },
        }
        for index in range(6)
    ]
    knowledge.insert(1, {
        **knowledge[0],
        "applicable_cluster": {"id": "cluster-east", "name": "East"},
    })

    compact = _compact_agent_knowledge(knowledge)

    assert len(compact) == 4
    assert len(str(compact[0]["content"])) == 1200
    assert compact[0]["applicable_clusters"] == [
        {"id": "cluster-0", "name": "Cluster 0"},
        {"id": "cluster-east", "name": "East"},
    ]
    assert all("instructions" in str(item["trust"]) for item in compact)


@pytest.mark.parametrize("execution_mode", ["read_only", "action"])
def test_delegated_conversation_uses_uniform_agent_tools_and_mode_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, execution_mode: str,
) -> None:
    cluster_id = "30500000-0000-0000-0000-000000000001"
    constructor_threads: list[int] = []
    event_loop_threads: set[int] = set()
    explorer_kwargs: list[dict[str, object]] = []
    explorer_intents: list[ReadIntent] = []
    telemetry_calls: list[tuple[str, str, str]] = []
    telemetry_token_providers: list[Callable[[], str]] = []

    class Explorer:
        def preflight(self, _intent) -> None:
            return None

        def execute(self, intent) -> ReadResult:
            explorer_intents.append(intent)
            return ReadResult((AdHocObservation(
                id=f"delegated-{intent.tool}",
                tool=intent.tool,
                summary=f"Collected delegated {intent.tool} evidence.",
                source=f"test:{intent.tool}",
                collected_at=datetime.now(timezone.utc),
                data={"complete": True},
            ),))

    def build_explorer(**kwargs):
        constructor_threads.append(threading.get_ident())
        explorer_kwargs.append(kwargs)
        return Explorer()

    monkeypatch.setattr(
        KubernetesReadOnlyExplorer, "for_remote_cluster", build_explorer
    )
    monkeypatch.setattr(
        ThanosQueryClient,
        "for_remote_cluster",
        lambda **kwargs: (
            telemetry_token_providers.append(kwargs["token_provider"])
            or
            telemetry_calls.append((
                "metrics", kwargs["api_url"], kwargs["token_provider"](),
            ))
            or SimpleNamespace()
        ),
    )
    monkeypatch.setattr(
        LokiQueryClient,
        "for_remote_cluster",
        lambda **kwargs: (
            telemetry_token_providers.append(kwargs["token_provider"])
            or
            telemetry_calls.append((
                str(kwargs.get("tenant") or "application"),
                kwargs["api_url"],
                kwargs["token_provider"](),
            ))
            or SimpleNamespace()
        ),
    )

    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, _profile, _api_key, messages):
            self.agent_messages.append(list(messages))
            self.calls += 1
            if self.calls == 1:
                arguments = json.dumps({
                    "cluster_id": cluster_id,
                    "discovery_query": "cluster log forwarder",
                    "limit": 5,
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "discover-clf", "type": "function",
                            "function": {
                                "name": "discover_resources", "arguments": arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="discover-clf", name="discover_resources", arguments=arguments,
                    ),),
                )
            if self.calls == 2:
                arguments = json.dumps({
                    "cluster_id": cluster_id,
                    "metric": "top_log_volume_by_namespace",
                    "metric_scope": "cluster",
                    "metric_operation": "rank",
                    "metric_group_by": ["namespace"],
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "rank-logs", "type": "function",
                            "function": {
                                "name": "query_metrics", "arguments": arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="rank-logs", name="query_metrics", arguments=arguments,
                    ),),
                )
            if self.calls == 3:
                arguments = json.dumps({
                    "cluster_id": cluster_id,
                    "audit_operation_scope": "deletes",
                    "audit_outcome": "all",
                    "limit": 10,
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "audit-deletes", "type": "function",
                            "function": {
                                "name": "query_audit_events", "arguments": arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="audit-deletes", name="query_audit_events", arguments=arguments,
                    ),),
                )
            if self.calls == 4:
                arguments = json.dumps({
                    "command": (
                        "oc get clusterlogforwarders.observability.openshift.io "
                        "-A -o json"
                    ),
                    "cluster_id": cluster_id,
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "read-clf", "type": "function",
                            "function": {"name": "execute_shell", "arguments": arguments},
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="read-clf", name="execute_shell", arguments=arguments,
                    ),),
                )
            return _agent_final_step("The ClusterLogForwarder configuration was inspected.")

    class Runner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, AgentClusterConnection]] = []

        def execute(self, command, connection=None, **_kwargs):
            assert connection is not None
            self.calls.append((command, connection))
            return AgentCommandResult(
                command=command, exit_code=0,
                stdout='{"apiVersion":"v1","items":[]}', stderr="",
            )

    provider = Provider()
    runner = Runner()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.APPROVER},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("model-token"),
        model_provider=provider,
        agent_runner=runner,
        settings_overrides={"delegated_access_enabled": True},
    )

    @app.middleware("http")
    async def capture_event_loop_thread(request, call_next):
        event_loop_threads.add(threading.get_ident())
        return await call_next(request)

    engine = build_engine(settings)
    with TestClient(app) as client:
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            db_session.add(Cluster(
                id=cluster_id, name="Central DEV",
                api_url="https://api.central-dev.example:6443",
                credential_key=None, tags_json="{}", tls_verify=True,
                is_enabled=True, is_system=False, status="ready",
                created_by="ada", updated_by="ada", created_at=now, updated_at=now,
            ))
            db_session.add(ModelProfile(
                id=1, provider_label="OpenRouter",
                base_url="https://openrouter.ai/api/v1",
                chat_model="openai/gpt-oss-120b", api_type="chat-completions",
                embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
                status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
            ))
            knowledge = KnowledgeDocument(
                id="30500000-0000-0000-0000-000000000101",
                logical_id="30500000-0000-0000-0000-000000000102",
                version=1,
                created_at=now,
                created_by="ivy",
                title="ClusterLogForwarder configuration guidance",
                content=(
                    "Inspect the exact ClusterLogForwarder status and configured output "
                    "references before drawing a health conclusion."
                ),
                source="Reviewed platform runbook",
                source_type="runbook",
                cluster_id=cluster_id,
                target_cluster_ids_json=json.dumps([cluster_id]),
                target_tags_json="{}",
                namespace=None,
                resource_kind="ClusterLogForwarder",
                resource_name=None,
                owner="platform-team",
                verification_state="reviewed",
                sensitivity="internal",
                review_at=now,
                expires_at=None,
                is_enabled=True,
                is_current=True,
                content_sha256="a" * 64,
            )
            db_session.add(knowledge)
            db_session.flush()
            index_document(db_session, knowledge)
            db_session.commit()

        session_id = app.state.delegated_vault.new_session_id()
        connection = app.state.delegated_vault.put(
            session_id=session_id, owner="ivy", cluster_id=cluster_id,
            remote_username="ivy", remote_uid="uid-ivy", token="delegated-token",
        )
        client.cookies.set("podpilot_delegated_session", session_id)
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": "Compare the ClusterLogForwarder configuration.",
                "cluster_ids": json.dumps([cluster_id]),
                "execution_mode": execution_mode,
            },
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert "configuration was inspected" in rendered.text
    knowledge_message = next(
        str(item.get("content") or "")
        for item in provider.agent_messages[0]
        if "PodPilot curated-knowledge context" in str(item.get("content") or "")
    )
    assert "Reviewed platform runbook" in knowledge_message
    assert "exact ClusterLogForwarder status" in knowledge_message
    assert any(
        item.get("role") == "system"
        and "untrusted, non-executable guidance" in str(item.get("content") or "")
        for item in provider.agent_messages[0]
    )
    assert constructor_threads
    assert constructor_threads[0] not in event_loop_threads
    assert explorer_kwargs[0]["metric_reader"] is not None
    assert explorer_kwargs[0]["log_metric_reader"] is not None
    assert explorer_kwargs[0]["audit_reader"] is not None
    assert [intent.tool for intent in explorer_intents] == [
        "discover_resources", "query_metrics", "query_audit_events",
    ]
    assert explorer_intents[0].discovery_query == "cluster log forwarder"
    assert telemetry_calls == [
        ("metrics", "https://api.central-dev.example:6443", "delegated-token"),
        ("application", "https://api.central-dev.example:6443", "delegated-token"),
        ("audit", "https://api.central-dev.example:6443", "delegated-token"),
    ]
    assert len(runner.calls) == 1
    command, runner_connection = runner.calls[0]
    assert command.startswith("oc get clusterlogforwarders")
    assert runner_connection.proxy_url is not None
    expected_capability = (
        connection.read_only_proxy_capability
        if execution_mode == "read_only"
        else connection.action_proxy_capability
    )
    other_capability = (
        connection.action_proxy_capability
        if execution_mode == "read_only"
        else connection.read_only_proxy_capability
    )
    assert runner_connection.proxy_url.endswith(expected_capability)
    assert other_capability not in runner_connection.proxy_url
    system_prompt = str(provider.agent_messages[0][0]["content"])
    if execution_mode == "read_only":
        assert "delegated read-only investigation mode" in system_prompt
        assert "broker will reject Kubernetes writes" in system_prompt
    else:
        assert "delegated read-write mode" in system_prompt
    assert "same investigation tools" in system_prompt
    assert "search_resources helpers are unavailable" in system_prompt
    assert "discover_resources before guessing" in system_prompt
    assert "API discovery does not prove" in system_prompt
    assert "Inspect all IngressController resources" in system_prompt
    assert "rather than assuming one named default" in system_prompt
    assert "http_probe originates from the PodPilot application Pod" in system_prompt
    assert "never describe it as bidirectional inter-cluster connectivity" in system_prompt
    assert "delegated-token" not in json.dumps(provider.agent_messages)
    assert telemetry_token_providers
    # TestClient shutdown clears the in-memory delegated session; retained
    # telemetry adapters must no longer be able to resolve its bearer token.
    assert all(item() == "" for item in telemetry_token_providers)


def test_delegated_read_only_explorer_discovery_runs_off_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_loop_thread = threading.get_ident()
    constructor_thread: list[int] = []

    def build_explorer(**kwargs):
        constructor_thread.append(threading.get_ident())
        assert kwargs["api_url"].endswith("/opaque-capability")
        return SimpleNamespace()

    monkeypatch.setattr(
        KubernetesReadOnlyExplorer, "for_remote_cluster", build_explorer
    )
    explorer = asyncio.run(_build_delegated_read_only_explorer(
        proxy_url=(
            "http://127.0.0.1:8080/internal/delegated-proxy/opaque-capability"
        ),
        telemetry_api_url="https://api.remote.example:6443",
        token_provider=lambda: "delegated-token",
        telemetry_tls_verify=True,
        settings=Settings(),
    ))

    assert explorer is not None
    assert constructor_thread and constructor_thread[0] != event_loop_thread


def test_delegated_system_telemetry_uses_internal_services(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    constructed: dict[str, list[dict[str, object]]] = {
        "thanos": [], "loki": [], "explorer": [], "remote": [],
    }

    class FakeThanosClient:
        def __init__(self, **kwargs):
            constructed["thanos"].append(kwargs)

        @classmethod
        def for_remote_cluster(cls, **kwargs):
            constructed["remote"].append(kwargs)
            return cls(**kwargs)

    class FakeLokiClient:
        def __init__(self, **kwargs):
            constructed["loki"].append(kwargs)

        @classmethod
        def for_remote_cluster(cls, **kwargs):
            constructed["remote"].append(kwargs)
            return cls(**kwargs)

    def build_explorer(**kwargs):
        constructed["explorer"].append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr("podpilot_api.main.ThanosQueryClient", FakeThanosClient)
    monkeypatch.setattr("podpilot_api.main.LokiQueryClient", FakeLokiClient)
    monkeypatch.setattr(
        KubernetesReadOnlyExplorer, "for_remote_cluster", build_explorer,
    )
    service_ca = tmp_path / "service-ca.crt"
    token_provider = lambda: "delegated-user-token"
    settings = Settings(
        thanos_url="https://thanos.internal.test",
        loki_url="https://loki.internal.test/api/logs/v1/application",
        service_ca_path=service_ca,
    )

    explorer = _make_delegated_read_only_explorer(
        api_url="http://127.0.0.1:8080/internal/delegated-proxy/capability",
        telemetry_api_url="in-cluster://service-account",
        token_provider=token_provider,
        telemetry_tls_verify=True,
        telemetry_is_system=True,
        settings=settings,
    )

    assert explorer is not None
    assert constructed["remote"] == []
    assert constructed["thanos"] == [{
        "base_url": "https://thanos.internal.test",
        "ca_path": service_ca,
        "timeout_seconds": settings.thanos_timeout_seconds,
        "max_series": settings.thanos_max_series,
        "max_points_per_series": settings.adhoc_metrics_max_points_per_series,
        "max_response_bytes": settings.adhoc_metrics_max_response_bytes,
        "token_provider": token_provider,
    }]
    assert [item["base_url"] for item in constructed["loki"]] == [
        "https://loki.internal.test/api/logs/v1/application",
        "https://loki.internal.test/api/logs/v1/application",
    ]
    assert [item.get("tenant", "application") for item in constructed["loki"]] == [
        "application", "audit",
    ]
    assert all(item["ca_path"] == service_ca for item in constructed["loki"])
    assert all(item["token_provider"] is token_provider for item in constructed["loki"])


def test_delegated_access_question_routes_to_authorization_reviews() -> None:
    assert _is_access_review_question("Show my access") is True
    assert _is_access_review_question(
        "Summarize what my delegated OpenShift identity can access and report verbs."
    ) is True
    assert _is_access_review_question("List Namespace resources") is False


def test_access_review_answer_renders_one_matrix_per_cluster() -> None:
    resources = [{
        "kind": "Pods",
        "apiGroup": "core",
        "resource": "pods",
        "verbs": {
            "get": True, "list": True, "create": True, "patch": True, "delete": True,
        },
    }]
    evidence = [
        {
            "id": "access-central", "tool": "access_review_summary",
            "cluster_id": "central", "cluster_name": "CMSP Central DEV",
            "data": {
                "scope": "all_namespaces", "allPermissionsAllowed": True,
                "complete": True, "resources": resources,
            },
        },
        {
            "id": "access-east", "tool": "access_review_summary",
            "cluster_id": "east", "cluster_name": "CMSP East DEV",
            "data": {
                "scope": "all_namespaces", "allPermissionsAllowed": True,
                "complete": True, "resources": resources,
            },
        },
    ]
    activity = [{
        "tool": "access_review_summary", "status": "succeeded",
        "evidence_ids": ["access-central"],
    }, {
        "tool": "access_review_summary", "status": "succeeded",
        "evidence_ids": ["access-east"],
    }]

    answer = _deterministic_access_review_answer(
        evidence=evidence, activity=activity,
    )

    assert answer is not None
    assert answer["citations"] == ["access-central", "access-east"]
    assert answer["content"].count("### CMSP Central DEV") == 1
    assert answer["content"].count("### CMSP East DEV") == 1
    assert answer["content"].count("Namespace scope: all namespaces") == 2
    assert answer["content"].count("| Pods | Allowed | Allowed |") == 2


def test_access_question_bypasses_generic_resource_planner() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("authorization summaries must not use the model planner")

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="access-review-one",
                tool="access_review_summary",
                summary="Reviewed delegated permissions.",
                source="kubernetes:authorization.k8s.io/v1:SelfSubjectAccessReview",
                collected_at=datetime.now(timezone.utc),
                data={
                    "scope": "all_namespaces",
                    "allPermissionsAllowed": True,
                    "complete": True,
                    "resources": [],
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[],
            role_approver_groups=[], role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="access-review",
        question="Show my access",
        conversation=[], existing_evidence=[],
    ))

    assert [intent.tool for intent in explorer.calls] == ["access_review_summary"]
    assert result.units_used == 2
    assert result.activity[0]["status"] == "succeeded"
    assert result.evidence[0]["id"] == "access-review-one"


def test_reduced_model_is_usable_only_with_safe_core_capabilities() -> None:
    profile = ModelProfile(
        provider_label="Internal", base_url="https://models.example.test/v1",
        chat_model="test-model", embedding_model=None, timeout_seconds=30,
        max_output_tokens=1200, status="reduced_capability", updated_by="ivy",
        capabilities_json=json.dumps({
            "reachable": True, "tls_valid": True, "authenticated": True,
            "model_available": True, "structured_output": True, "ask_schemas": False,
        }),
    )

    assert _profile_is_usable(profile) is True
    profile.capabilities_json = json.dumps({"reachable": True, "structured_output": False})
    assert _profile_is_usable(profile) is False


def test_unrestricted_mode_accepts_reduced_profile_with_tool_calling() -> None:
    profile = ModelProfile(
        provider_label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        chat_model="openai/gpt-oss-120b",
        api_type="chat-completions",
        credential_key="openrouter_api_key",
        timeout_seconds=240,
        max_output_tokens=4096,
        status="reduced_capability",
        capabilities_json=json.dumps({
            "reachable": True,
            "authenticated": True,
            "model_available": True,
            "tls_valid": True,
            "tool_calls": True,
            "structured_output": False,
        }),
        updated_by="test",
    )

    assert _profile_is_usable(profile) is False
    assert _profile_is_usable(profile, "unrestricted") is True
    profile.status = "unavailable"
    assert _profile_is_usable(profile) is False


def test_est_time_formatter_uses_the_requested_fixed_utc_minus_four_display() -> None:
    assert _format_est_time(datetime(2026, 8, 26, 5, 41, tzinfo=timezone.utc)) == (
        "01:41 EST (-4)"
    )
    assert _format_est_time("2026-08-26T05:41:22+00:00", "%Y-%m-%d %H:%M:%S") == (
        "2026-08-26 01:41:22 EST (-4)"
    )


def test_cluster_tags_support_labels_and_key_value_pairs() -> None:
    assert _parse_tags(
        '{"environment":"prod","production":"","region":"toronto"}',
        field_name="Cluster tags",
    ) == {
        "environment": "prod",
        "production": "",
        "region": "toronto",
    }


def test_investigation_budget_weights_high_volume_operations() -> None:
    assert _investigation_unit_cost(ReadIntent(
        tool="discover_resources", discovery_query="Authorino",
    )) == 1
    assert _investigation_unit_cost(ReadIntent(
        tool="get_resource", resource="pods", namespace="payments", name="api",
    )) == 1
    assert _investigation_unit_cost(ReadIntent(
        tool="pod_logs", candidate_id="podlog-api",
    )) == 2
    assert _investigation_unit_cost(ReadIntent(
        tool="watch_resources", resource="pods", namespace="payments", watch_seconds=5,
    )) == 3
    assert _investigation_unit_cost(ReadIntent(tool="pod_health_summary")) == 2


def test_agent_provider_result_compacts_large_shell_output() -> None:
    rendered = _bounded_agent_provider_result({
        "command": "oc get routes -A -o json",
        "exit_code": 0,
        "stdout": "x" * 500_000,
        "stderr": "",
        "stdout_truncated": True,
    })

    payload = json.loads(rendered)
    assert payload["provider_payload_compacted"] is True
    assert payload["provider_payload_original_bytes"] > 400_000
    assert "compacted stdout" in payload["stdout"]
    assert len(rendered.encode()) <= 48 * 1024


def test_deterministic_pod_health_answer_reports_running_phase_crashloop() -> None:
    evidence = [{
        "id": "pod-health-1",
        "tool": "pod_health_summary",
        "cluster_name": "lab",
        "data": {
            "kind": "Pod", "scannedCount": 600, "scanComplete": True,
            "anomalyCount": 1, "returnedAnomalyCount": 1,
            "anomalies": [{
                "namespace": "payments", "name": "api-7d9", "phase": "Running",
                "readyContainers": 1, "totalContainers": 2, "restartCount": 3595,
                "issues": [{"reason": "CrashLoopBackOff"}],
            }],
        },
    }]
    activity = [{
        "tool": "pod_health_summary", "status": "succeeded",
        "evidence_ids": ["pod-health-1"],
    }]

    answer = _deterministic_pod_health_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert answer["conclusion_status"] == "confirmed"
    assert "found 1 Pod with current health anomalies" in answer["content"]
    assert "`payments` | `api-7d9` | Running | 1/2 | 3595 | CrashLoopBackOff" in answer["content"]
    assert answer["citations"] == ["pod-health-1"]


def test_deterministic_pod_health_answer_refuses_incomplete_absence_claim() -> None:
    evidence = [{
        "id": "pod-health-limited",
        "tool": "pod_health_summary",
        "data": {
            "kind": "Pod", "scannedCount": 2000, "scanComplete": False,
            "anomalyCount": 0, "returnedAnomalyCount": 0, "anomalies": [],
        },
    }]
    activity = [{
        "tool": "pod_health_summary", "status": "succeeded",
        "evidence_ids": ["pod-health-limited"],
    }]

    answer = _deterministic_pod_health_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert answer["conclusion_status"] == "unresolved"
    assert "scan was incomplete" in answer["content"]
    assert "cannot be concluded" in answer["content"]


def test_broad_pod_health_guard_detects_universal_claims_but_not_log_diagnosis() -> None:
    assert _is_broad_pod_health_question(
        "Are all the Loki pods in openshift-logging running healthy?"
    ) is True
    assert _is_broad_pod_health_question(
        "Why are the Loki pod logs showing errors?"
    ) is False
    assert _is_broad_pod_health_question("Show me crashing pods on the cluster") is True
    assert _is_broad_pod_health_question("Find failed, Pending, or Evicted pods") is True
    assert _is_broad_pod_health_question("Show only CrashLoopBackOff pods") is False
    assert _claims_complete_pod_health("All Loki Pods are running and healthy.") is True
    assert _claims_complete_pod_health("No unhealthy Pods were found.") is True
    assert _claims_complete_pod_health("Two Pods are not Ready.") is False


def test_deterministic_resource_health_answer_reports_anomaly() -> None:
    evidence = [{
        "id": "node-health-1", "tool": "node_health_summary", "cluster_name": "lab",
        "data": {
            "kind": "Node", "scannedCount": 3, "scanComplete": True,
            "anomalyCount": 1, "returnedAnomalyCount": 1, "unavailableKinds": [],
            "anomalies": [{
                "kind": "Node", "name": "worker-1", "state": "Ready=False",
                "issues": [{"reason": "ReadyFalse"}, {"reason": "DiskPressure"}],
            }],
        },
    }]
    activity = [{
        "tool": "node_health_summary", "status": "succeeded",
        "evidence_ids": ["node-health-1"],
    }]

    answer = _deterministic_resource_health_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert answer["conclusion_status"] == "confirmed"
    assert "found 1 Node health anomaly" in answer["content"]
    assert "Node | `—` | `worker-1` | Ready=False | DiskPressure, ReadyFalse" in answer["content"]


def test_deterministic_resource_health_answer_marks_unavailable_api_unresolved() -> None:
    evidence = [{
        "id": "machine-health-1", "tool": "machine_health_summary",
        "data": {
            "kind": "Machine", "scannedCount": 0, "scanComplete": False,
            "anomalyCount": 0, "returnedAnomalyCount": 0, "anomalies": [],
            "unavailableKinds": ["machine.openshift.io/v1beta1 Machine"],
        },
    }]
    activity = [{
        "tool": "machine_health_summary", "status": "succeeded",
        "evidence_ids": ["machine-health-1"],
    }]

    answer = _deterministic_resource_health_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert answer["conclusion_status"] == "unresolved"
    assert "required API was unavailable" in answer["content"]


def test_pod_health_heuristic_does_not_override_model_object_field_classification() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="pod-health-override", tool="pod_health_summary",
                summary="Detected one CrashLooping Pod.",
                source="kubernetes:v1:Pod/health:cluster",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Pod", "scannedCount": 600, "scanComplete": True,
                    "anomalyCount": 1, "returnedAnomalyCount": 1,
                    "anomalies": [], "objects": [],
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[],
            role_approver_groups=[], role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="pod-health-override",
        question="Are any pods on the cluster crashing currently?",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="collection",
            resource_query="Pod", needs_object_details=True,
            evidence_goal="Inspect Pod status fields.",
        ),
    ))

    assert explorer.calls == []
    assert result.units_used == 0
    assert result.activity == []
    assert result.evidence == []


def test_semantic_classification_is_one_small_call_for_all_selected_clusters() -> None:
    class Provider:
        def __init__(self) -> None:
            self.calls = []

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.calls.append(context)
            return InquirySemantics(
                mode="inventory", resource_query="Kafka", needs_object_details=False,
                evidence_goal="Identify Kafka resources by cluster.",
            )

    provider = Provider()
    result = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Tell me which environments contain Kafka.",
        conversation=[],
        cluster_names=["Central", "East", "West", "DR"],
    ))

    assert result is not None and result.mode == "inventory"
    assert len(provider.calls) == 1
    assert provider.calls[0]["selected_clusters"] == ["Central", "East", "West", "DR"]


def test_configuration_guidance_can_resolve_named_object_from_recent_context() -> None:
    class Provider:
        def __init__(self) -> None:
            self.context = None

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.context = context
            return InquirySemantics(
                mode="explain", operation="configuration_guidance",
                cardinality="exact_one", resource_query="Route",
                object_name="checkout", namespace="payments",
                needs_object_details=True,
                evidence_goal="Explain how to configure the previously named Route.",
            )

    provider = Provider()
    conversation = [
        {"role": "user", "content": "Inspect Route payments/checkout."},
        {"role": "assistant", "content": "Route payments/checkout terminates TLS at edge."},
        {"role": "user", "content": "What does that imply?"},
        {"role": "assistant", "content": "The observed Route uses edge termination."},
    ]
    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token", question="How should I configure it differently?",
        conversation=conversation, cluster_names=["Central"],
    ))

    assert inquiry is not None
    assert inquiry.capability == "configuration_guidance"
    assert inquiry.object_name == "checkout"
    assert len(provider.context["recent_context"]) == 4


def test_elliptical_configuration_followup_selects_grounded_object_reference() -> None:
    class Provider:
        def __init__(self) -> None:
            self.context = None

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.context = context
            reference = next(
                item for item in context["recent_object_references"]
                if item["relation"] == "configures_from"
            )
            return InquirySemantics(
                mode="explain", operation="configuration_guidance",
                object_reference_id=reference["id"],
                evidence_goal="Show the configuration from the referenced ConfigMap.",
            )

    evidence = [{
        "id": "cluster-kafka",
        "tool": "get_resource",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "metadata": {"namespace": "tm-streams-dev", "name": "tm-streams-dev-cluster"},
            "spec": {"kafka": {"metricsConfig": {"valueFrom": {
                "configMapKeyRef": {"name": "tm-streams-dev-metrics-config", "key": "metrics.yml"}
            }}}},
        },
    }]
    provider = Provider()
    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Show me that configuration in the ConfigMap.",
        conversation=[{
            "role": "assistant",
            "content": "The Kafka resource references tm-streams-dev-metrics-config.",
        }],
        cluster_names=["Central"],
        evidence=evidence,
    ))

    assert inquiry is not None
    assert inquiry.mode == "explain"
    assert inquiry.resource_query == "ConfigMap"
    assert inquiry.object_name == "tm-streams-dev-metrics-config"
    assert inquiry.namespace == "tm-streams-dev"
    assert inquiry.cardinality == "exact_one"
    assert provider.context["recent_object_references"][0]["name"] == (
        "tm-streams-dev-metrics-config"
    )


def test_related_inventory_followup_binds_parent_scope_and_selector_value() -> None:
    class Provider:
        def __init__(self) -> None:
            self.context = None

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.context = context
            parent = next(
                item for item in context["recent_object_references"]
                if item["kind"] == "Kafka"
                and item["name"] == "kafka-observability-cluster"
            )
            return InquirySemantics(
                mode="inventory", operation="inventory", cardinality="collection",
                resource_query="KafkaTopic", scope_reference_id=parent["id"],
                relationship_selector_key="strimzi.io/cluster",
                evidence_goal="List topics related to the selected Kafka cluster.",
            )

    evidence = [{
        "id": "cluster-kafka-inventory",
        "tool": "list_resources",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "scope": "cluster", "objectListComplete": True,
            "items": [{
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "metadata": {
                    "namespace": "kafka-observability",
                    "name": "kafka-observability-cluster",
                },
            }],
        },
    }]
    provider = Provider()
    conversation = [{
        "role": "assistant",
        "content": (
            "Kafka kafka-observability/kafka-observability-cluster is ready."
        ),
    }]
    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Show topics configured for the kafka-observability-cluster Kafka cluster.",
        conversation=conversation,
        cluster_names=["Central"],
        evidence=evidence,
    ))

    assert inquiry is not None
    assert inquiry.resource_query == "KafkaTopic"
    assert inquiry.namespace == "kafka-observability"
    assert inquiry.object_name is None
    assert inquiry.label_selector == (
        "strimzi.io/cluster=kafka-observability-cluster"
    )
    compiled = _semantic_resource_read_plan(
        inquiry,
        resource_catalog=[{
            "resource": "kafkatopics.kafka.strimzi.io",
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "KafkaTopic",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show topics configured for the kafka-observability-cluster Kafka cluster.",
        conversation=conversation,
        inventory_limit=500,
    )

    assert compiled is None


def test_semantic_relationship_followup_binds_reverse_kafka_target() -> None:
    class Provider:
        def classify_ad_hoc(self, _profile, _api_key, context):
            relationship = next(
                item for item in context["recent_relationship_references"]
                if item["direction"] == "reverse"
                and item["relation"] == "configures_from"
                and item["target_kind"] == "Kafka"
            )
            return InquirySemantics(
                mode="investigate", operation="object_fields",
                cardinality="exact_one", resource_query="Kafka",
                relationship_reference_id=relationship["id"],
                requested_fields=["spec.kafka.metricsConfig"],
                needs_object_details=True,
                evidence_goal="Show the Kafka CR that references the observed ConfigMap.",
            )

    evidence = [{
        "id": "cluster-kafka", "tool": "get_resource",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "resource": "kafkas.kafka.strimzi.io",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            "spec": {"kafka": {"metricsConfig": {"valueFrom": {
                "configMapKeyRef": {"name": "kafka-metrics", "key": "metrics.yml"},
            }}}},
        },
    }, {
        "id": "cluster-config", "tool": "get_resource",
        "data": {
            "apiVersion": "v1", "kind": "ConfigMap", "resource": "configmaps",
            "metadata": {"namespace": "vc-streams", "name": "kafka-metrics"},
            "data": {"metrics.yml": "rules: []"},
        },
    }]

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Show me the Kafka CR configuration that references the ConfigMap.",
        conversation=[], cluster_names=["Central"], evidence=evidence,
    ))

    assert inquiry is not None
    assert inquiry.resource_query == "Kafka"
    assert inquiry.namespace == "vc-streams"
    assert inquiry.object_name == "vc-cluster"
    assert inquiry.cardinality == "exact_one"

    compiled = _semantic_resource_read_plan(
        inquiry,
        resource_catalog=[{
            "resource": "kafkas.kafka.strimzi.io",
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show me the Kafka CR configuration that references the ConfigMap.",
        conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="get_resource", resource="kafkas.kafka.strimzi.io",
        api_version="kafka.strimzi.io/v1beta2", kind="Kafka",
        namespace="vc-streams", name="vc-cluster",
    )]


def test_semantic_relationship_followup_compiles_selector_collection() -> None:
    class Provider:
        def classify_ad_hoc(self, _profile, _api_key, context):
            relationship = next(
                item for item in context["recent_relationship_references"]
                if item["direction"] == "forward"
                and item["relation"] == "selects"
                and item["target_kind"] == "Node"
            )
            return InquirySemantics(
                mode="inventory", operation="inventory",
                cardinality="collection", resource_query="Node",
                relationship_reference_id=relationship["id"],
                evidence_goal="List Nodes selected by the observed MachineConfigPool.",
            )

    evidence = [{
        "id": "mcp-worker", "tool": "get_resource",
        "data": {
            "apiVersion": "machineconfiguration.openshift.io/v1",
            "kind": "MachineConfigPool",
            "resource": "machineconfigpools.machineconfiguration.openshift.io",
            "metadata": {"name": "worker"},
            "spec": {
                "nodeSelector": {
                    "matchLabels": {"node-role.kubernetes.io/worker": ""},
                },
            },
        },
    }]

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Which Nodes belong to that MachineConfigPool?",
        conversation=[], cluster_names=["Central"], evidence=evidence,
    ))

    assert inquiry is not None
    assert inquiry.resource_query == "Node"
    assert inquiry.label_selector == "node-role.kubernetes.io/worker="
    assert inquiry.cardinality == "collection"

    compiled = _semantic_resource_read_plan(
        inquiry,
        resource_catalog=[{
            "resource": "nodes", "apiVersion": "v1", "kind": "Node",
            "namespaced": False, "verbs": ["get", "list"],
        }],
        question="Which Nodes belong to that MachineConfigPool?",
        conversation=[], inventory_limit=500,
    )

    assert compiled is None


def test_semantic_classification_retries_invalid_json_and_supplies_prior_audit_query() -> None:
    class Provider:
        def __init__(self) -> None:
            self.calls = []

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.calls.append(dict(context))
            if len(self.calls) == 1:
                raise ModelProviderError("response: json_invalid")
            return InquirySemantics(
                mode="audit", needs_object_details=True,
                evidence_goal="Repeat the prior audit query over 24 hours.",
                result_limit=5, audit_username="druciare-adm",
                audit_operation_scope="all", audit_outcome="all",
                audit_range_seconds=86_400,
                continues_prior_audit_query=True,
            )

    provider = Provider()
    prior = {
        "username": "druciare-adm", "operation_scope": "all",
        "outcome": "all", "limit": 5, "range_seconds": 3600,
    }
    result = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="what about in the last 24hrs",
        conversation=[], cluster_names=["Central"], prior_audit_query=prior,
    ))

    assert result is not None and result.audit_range_seconds == 86_400
    assert len(provider.calls) == 2
    assert provider.calls[0]["prior_audit_query"] == prior
    assert "structured_response_retry" in provider.calls[1]


def test_semantic_classification_supplies_typed_prior_resource_query() -> None:
    class Provider:
        def __init__(self) -> None:
            self.context = None

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.context = dict(context)
            return InquirySemantics(
                mode="inventory", operation="inventory", cardinality="collection",
                resource_query="Route",
                resource_filter=ResourceFieldFilterSemantics(
                    field="spec.host", operator="contains", value=".az.cibc.com",
                ),
                continues_prior_resource_query=True,
                evidence_goal="Present the prior Route search.",
            )

    provider = Provider()
    prior = {
        "kind": "Route", "limit": 100,
        "resource_filter": {
            "field": "spec.host", "operator": "contains", "value": ".az.cibc.com",
        },
        "evidence_ids": ["central-routes"],
    }
    result = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show me these routes",
        conversation=[], cluster_names=["Central"], prior_resource_query=prior,
    ))

    assert result is not None and result.continues_prior_resource_query is True
    assert provider.context is not None
    assert provider.context["prior_resource_query"] == prior


def test_invalid_capability_selection_does_not_use_wording_specific_fallback() -> None:
    class Provider:
        def __init__(self) -> None:
            self.calls = 0

        def classify_ad_hoc(self, *_args, **_kwargs):
            self.calls += 1
            raise ModelProviderError("response: json_invalid")

    provider = Provider()
    result = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show the last 10 mutation actions by druciare-adm according to the audit log",
        conversation=[], cluster_names=["Central"],
    ))

    assert provider.calls == 2
    assert result is None


def test_capability_selection_retries_and_rejects_ungrounded_coordinate() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(dict(context))
            return InquirySemantics(
                mode="audit", operation="audit", namespace="invented-namespace",
                audit_operation_scope="all", audit_outcome="all",
                needs_object_details=True, evidence_goal="Read audit actions.",
            )

    provider = Provider()
    result = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show me recent audit actions",
        conversation=[], cluster_names=["Central"],
    ))

    assert result is None
    assert len(provider.contexts) == 2
    assert "ungrounded namespace" in provider.contexts[1]["structured_response_retry"]


def test_model_selected_audit_actions_request_compiles_grounded_namespace() -> None:
    class Provider:
        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(
                mode="audit", operation="audit", cardinality="collection",
                namespace="spt-llm",
                audit_operation_scope="all", audit_outcome="all",
                needs_object_details=True,
                evidence_goal="List the requested namespace audit actions.",
            )

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show me the last 5 audit actions on the namespace spt-llm",
        conversation=[], cluster_names=["Central"],
    ))

    compiled = _semantic_audit_read_plan(
        inquiry, default_limit=20, initial_range_seconds=3600,
    )
    assert compiled is not None
    assert compiled[0].intents == [ReadIntent(
        tool="query_audit_events", namespace="spt-llm",
        audit_operation_scope="all", audit_outcome="all",
        audit_search_until_limit=True, range_seconds=3600, limit=5,
    )]


def test_explicit_audit_constraints_override_broader_model_defaults() -> None:
    class Provider:
        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(
                mode="audit", operation="audit", cardinality="collection",
                result_limit=20, audit_operation_scope="all", audit_outcome="successful",
                needs_object_details=True,
                evidence_goal="List recent audit activity.",
            )

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show me the last 5 audit entries for failed delete operations",
        conversation=[], cluster_names=["Central"],
    ))

    assert inquiry is not None
    assert inquiry.result_limit == 5
    assert inquiry.audit_operation_scope == "deletes"
    assert inquiry.audit_outcome == "failed"
    compiled = _semantic_audit_read_plan(
        inquiry, default_limit=20, initial_range_seconds=3600,
    )
    assert compiled is not None
    assert compiled[0].intents == [ReadIntent(
        tool="query_audit_events", audit_operation_scope="deletes",
        audit_outcome="failed", audit_search_until_limit=True,
        range_seconds=3600, limit=5,
    )]


def test_recent_audit_request_does_not_expand_to_fill_model_default() -> None:
    class Provider:
        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(
                mode="audit", operation="audit", cardinality="collection",
                namespace="ai-ops", audit_username="druciare-adm",
                result_limit=20, audit_operation_scope="deletes", audit_outcome="all",
                evidence_goal="List recent matching delete operations.",
            )

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question=(
            'show me recent delete operations in the ai-ops namespace by the user "druciare-adm"'
        ),
        conversation=[], cluster_names=["Central"],
    ))

    assert inquiry is not None
    assert inquiry.result_limit is None
    compiled = _semantic_audit_read_plan(
        inquiry, default_limit=20, initial_range_seconds=3600,
    )
    assert compiled is not None
    assert compiled[0].intents == [ReadIntent(
        tool="query_audit_events", namespace="ai-ops",
        audit_username="druciare-adm", audit_operation_scope="deletes",
        audit_outcome="all", audit_search_until_limit=False,
        range_seconds=3600, limit=20,
    )]


def test_model_selected_audit_capability_without_username_queries_all_users() -> None:
    inquiry = InquirySemantics(
        mode="audit", operation="audit", cardinality="collection",
        needs_object_details=True,
        evidence_goal="List bounded cluster audit operations matching the supplied filters.",
        result_limit=10, audit_operation_scope="deletes", audit_outcome="all",
    )

    assert inquiry.mode == "audit"
    assert inquiry.audit_username is None
    assert inquiry.audit_operation_scope == "deletes"
    compiled = _semantic_audit_read_plan(
        inquiry, default_limit=20, initial_range_seconds=3600,
    )
    assert compiled is not None
    assert compiled[0].decision == "collect"
    assert compiled[0].scope_summary == (
        "List the last 10 delete audit operations across all users."
    )
    assert compiled[0].intents == [ReadIntent(
        tool="query_audit_events",
        audit_operation_scope="deletes",
        audit_outcome="all",
        audit_search_until_limit=True,
        range_seconds=3600,
        limit=10,
    )]


def test_audit_compiler_scopes_delete_query_to_explicit_resource_kind() -> None:
    compiled = _semantic_audit_read_plan(
        InquirySemantics(
            mode="audit", operation="audit", cardinality="collection",
            resource_query="Pod", namespace="ai-ops",
            audit_operation_scope="deletes", audit_outcome="all",
            evidence_goal="Find who deleted Pods in ai-ops.",
        ),
        default_limit=20,
        initial_range_seconds=3600,
    )

    assert compiled is not None
    assert compiled[0].scope_summary == (
        "List the last 20 delete audit operations on pods in namespace ai-ops "
        "across all users."
    )
    assert compiled[0].intents == [ReadIntent(
        tool="query_audit_events", namespace="ai-ops", audit_resource="pods",
        audit_operation_scope="deletes", audit_outcome="all",
        audit_search_until_limit=False, range_seconds=3600, limit=20,
    )]


def test_capability_ledger_distinguishes_available_uncollected_from_unavailable() -> None:
    ledger = _investigation_capability_ledger(
        evidence=[{
            "id": "route-1", "tool": "search_resources",
            "data": {"kind": "Route", "items": []},
        }],
        activity=[{
            "tool": "search_resources", "status": "succeeded",
            "evidence_ids": ["route-1"],
        }],
        remaining_units=12,
    )

    checks = {item["capability"]: item for item in ledger["checks"]}
    assert checks["service_spec"]["state"] == "available_not_attempted"
    assert checks["metrics"]["state"] == "available_not_attempted"
    assert checks["http_probe"]["state"] == "available_not_attempted"
    assert checks["pod_logs"]["state"] == "requires_target"
    assert "not collected" in ledger["language_rule"]
    assert _adhoc_capability_wording_issue(
        content="No logs, metrics, or probe results are available.",
        capability_ledger=ledger,
    ) == "available_check_described_as_unavailable"
    assert _adhoc_capability_wording_issue(
        content="Logs, metrics, and probes were not collected.",
        capability_ledger=ledger,
    ) is None


def test_capability_wording_rejects_collected_checks_listed_as_still_missing() -> None:
    ledger = _investigation_capability_ledger(
        evidence=[{
            "id": "service-1", "tool": "get_resource",
            "data": {"kind": "Service", "metadata": {"name": "gateway"}},
        }, {
            "id": "endpoint-1", "tool": "list_resources",
            "data": {"kind": "EndpointSlice", "items": []},
        }],
        activity=[
            {"tool": "get_resource", "status": "succeeded", "evidence_ids": ["service-1"]},
            {"tool": "list_resources", "status": "succeeded", "evidence_ids": ["endpoint-1"]},
        ],
        remaining_units=6,
    )

    assert _adhoc_capability_wording_issue(
        content=(
            "Investigation gaps: pod_logs, service_spec, endpoints. "
            "These are still not collected."
        ),
        capability_ledger=ledger,
    ) == "collected_check_described_as_uncollected"


def test_duplicate_plan_is_repaired_without_pinning_agent_goal() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if not context["completed_reads"]:
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Inspect the named Pod.",
                    intents=[ReadIntent(
                        tool="get_resource", resource="pods", api_version="v1",
                        kind="Pod", namespace="payments", name="api-7d9",
                    )],
                )
            if context.get("planner_feedback", {}).get("code") == "no_progress":
                return ReadPlan(
                    goal_type="inventory",
                    scope_summary="Use a novel Service read.",
                    intents=[ReadIntent(
                        tool="get_resource", resource="services", api_version="v1",
                        kind="Service", namespace="payments", name="api-service",
                    )],
                )
            if not any(item.get("target", "").startswith("services ") for item in context["completed_reads"]):
                return ReadPlan(
                    goal_type="inventory",
                    scope_summary="Accidentally repeat the Pod read.",
                    intents=[ReadIntent(
                        tool="get_resource", resource="pods", api_version="v1",
                        kind="Pod", namespace="payments", name="api-7d9",
                    )],
                )
            return ReadPlan(
                goal_type="inventory",
                decision="answer_from_evidence",
                scope_summary="The Pod and Service are available.",
                supporting_evidence_ids=["pod-1", "service-1"],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            kind = str(intent.kind)
            evidence_id = "pod-1" if kind == "Pod" else "service-1"
            return ReadResult((AdHocObservation(
                id=evidence_id,
                tool="get_resource",
                summary=f"Read {kind}.",
                source=f"kubernetes:{intent.api_version}:{kind}:payments/{intent.name}",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": intent.api_version,
                    "kind": kind,
                    "metadata": {"namespace": "payments", "name": intent.name},
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="duplicate-repair",
        question="Inspect Pod api-7d9 and Service api-service in namespace payments.",
        conversation=[], existing_evidence=[],
    ))

    assert [call.kind for call in explorer.calls] == ["Pod", "Service"]
    assert [item["id"] for item in result.evidence] == ["pod-1", "service-1"]
    assert any(
        context.get("planner_feedback", {}).get("code") == "no_progress"
        for context in provider.contexts
    )
    assert all("pinned_goal_type" not in context for context in provider.contexts)


def test_preflight_rejection_does_not_consume_cluster_read_budget() -> None:
    class RepairingProvider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if context["investigation_round"] == 1:
                return ReadPlan(
                    scope_summary="Try an ambiguous resource plural.",
                    intents=[ReadIntent(
                        tool="search_resources", resource="routes",
                        match_field="metadata.name", match_value="api",
                    )],
                )
            if context["investigation_round"] == 2:
                return ReadPlan(
                        scope_summary="Use an unambiguous safe resource.",
                        intents=[ReadIntent(
                            tool="search_resources", resource="pods", api_version="v1",
                            kind="Pod", namespace="payments", limit=5,
                            match_field="metadata.name", match_value="api",
                    )],
                )
            return ReadPlan(
                scope_summary="The collected evidence is sufficient.",
                supporting_evidence_ids=["cluster-pods-1"],
            )

    class PreflightingExplorer:
        def __init__(self) -> None:
            self.calls = []

        def preflight(self, intent):
            if intent.resource == "routes":
                raise ReadOnlyExplorerError(
                    "The API resource name 'routes' is ambiguous; use one of: "
                    "routes.route.openshift.io, routes.serving.knative.dev."
                )

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-pods-1",
                tool="search_resources",
                summary="Read Pods in payments.",
                source="kubernetes:v1:Pod:payments/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Pod", "scope": "payments", "names": ["api"]},
            ),))

    provider = RepairingProvider()
    explorer = PreflightingExplorer()
    settings = Settings(
        auth_mode="test",
        role_investigator_groups=[],
        role_approver_groups=[],
        role_breakglass_groups=[],
    )
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=settings,
        actor="ivy",
        workflow_id="workflow-preflight",
        question="Investigate application connectivity.",
        conversation=[],
        existing_evidence=[],
    ))

    assert provider.contexts[1]["tool_policy"]["remaining_reads"] == (
        settings.adhoc_max_reads_per_turn
    )
    assert result.activity[0]["status"] == "rejected_before_collection"
    assert result.activity[1]["status"] == "succeeded"
    assert len(explorer.calls) == 1


def test_collection_does_not_automatically_retry_tls_trust_failure() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if context["investigation_round"] == 1:
                return ReadPlan(
                    goal_type="diagnose", decision="collect",
                    scope_summary="Probe the HTTPS endpoint.",
                    intents=[ReadIntent(
                        tool="http_probe", url="https://model.apps.example.test/v1/models",
                        method="GET",
                    )],
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="Both probe results are available.",
                supporting_evidence_ids=[item["id"] for item in context["observations"]],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            if intent.tls_verify:
                return ReadResult((AdHocObservation(
                    id="network-trust-failed", tool="http_probe",
                    summary="Verified HTTPS probe failed during TLS.",
                    source="https://model.apps.example.test/v1/models",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "outcome": "failed", "stage": "tls",
                        "logicalHost": "model.apps.example.test",
                        "error": "certificate verify failed: self-signed certificate",
                        "tlsVerificationRequested": True,
                    },
                ),), ("The HTTPS probe could not verify the private certificate chain.",))
            return ReadResult((AdHocObservation(
                id="network-insecure-500", tool="http_probe",
                summary="Insecure HTTPS probe returned HTTP 500.",
                source="https://model.apps.example.test/v1/models",
                collected_at=datetime.now(timezone.utc),
                data={
                    "outcome": "completed", "statusCode": 500,
                    "logicalHost": "model.apps.example.test",
                    "tlsVerificationRequested": False,
                    "tls": {"verified": False, "verificationMode": "insecure"},
                },
            ),), ("TLS verification was bypassed; server identity was not verified.",))

    provider = Provider()
    explorer = Explorer()
    settings = Settings(
        auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
        role_breakglass_groups=[],
    )

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token", settings=settings, actor="ivy",
        workflow_id="workflow-tls-retry",
        question="Investigate HTTPS connectivity to https://model.apps.example.test/v1/models",
        conversation=[], existing_evidence=[],
    ))

    assert [call.tls_verify for call in explorer.calls] == [True]
    assert [item["id"] for item in result.evidence] == ["network-trust-failed"]
    assert all("automatic_followup" not in item for item in result.activity)


def test_collection_discards_removed_list_reads_but_retains_exact_reads() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if not context["completed_reads"]:
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Inspect both endpoint Pods, namespaces, and policy sets.",
                    intents=[
                        ReadIntent(tool="get_resource", resource="pods", api_version="v1", kind="Pod", namespace="frontend", name="client-7d9"),
                        ReadIntent(tool="get_resource", resource="pods", api_version="v1", kind="Pod", namespace="data", name="database-0"),
                        ReadIntent(tool="get_resource", resource="namespaces", api_version="v1", kind="Namespace", name="frontend"),
                        ReadIntent(tool="get_resource", resource="namespaces", api_version="v1", kind="Namespace", name="data"),
                        ReadIntent(tool="list_resources", resource="networkpolicies", api_version="networking.k8s.io/v1", kind="NetworkPolicy", namespace="frontend", limit=100),
                        ReadIntent(tool="list_resources", resource="networkpolicies", api_version="networking.k8s.io/v1", kind="NetworkPolicy", namespace="data", limit=100),
                    ],
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="The endpoint labels and policies are available.",
                supporting_evidence_ids=[item["id"] for item in context["observations"]],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id=f"evidence-{len(self.calls)}", tool=intent.tool,
                summary=f"Read {intent.kind} evidence.",
                source=(
                    f"kubernetes:{intent.api_version}:{intent.kind}:"
                    f"{intent.namespace or 'cluster'}/{intent.name or '*'}"
                ),
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": intent.api_version, "kind": intent.kind,
                    "scope": intent.namespace or "cluster",
                    "metadata": {
                        "namespace": intent.namespace, "name": intent.name,
                        "labels": {"app": intent.name or "policy"},
                    },
                    "items": [],
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    settings = Settings(
        auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
        role_breakglass_groups=[],
    )

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token", settings=settings, actor="ivy",
        workflow_id="workflow-network-policy",
        question=(
            "Investigate TCP timeouts from pod client-7d9 in namespace frontend "
            "to pod database-0 in namespace data on port 5432."
        ),
        conversation=[], existing_evidence=[],
    ))

    assert [call.kind for call in explorer.calls] == [
        "Pod", "Pod", "Namespace", "Namespace",
    ]
    assert len(result.activity) == 4
    assert all(item["status"] == "succeeded" for item in result.activity)
    assert any("removed list_resources helper" in item for item in result.limitations)
    assert len(provider.contexts) == 2
    assert "planner_feedback" not in provider.contexts[-1]
    assert provider.contexts[1]["investigation_round"] == 2
    assert len(provider.contexts[1]["observations"]) == 4


def test_collection_lets_model_investigate_repeated_certificate_log_signals() -> None:
    pod_name = "maas-default-gateway-5cc7b765cf-b6qtq"

    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if context["investigation_round"] == 1:
                candidate = context["tool_policy"]["pod_log_candidates"][0]
                return ReadPlan(
                    goal_type="diagnose", decision="collect",
                    scope_summary="Read the exact gateway proxy logs.",
                    intents=[ReadIntent(tool="pod_logs", candidate_id=candidate["id"])],
                )
            if context["investigation_round"] == 2:
                assert context["findings"][0]["status"] == "open"
                return ReadPlan(
                    goal_type="diagnose", decision="collect",
                    scope_summary="Inspect the Pod mounts and its Events.",
                    intents=[
                        ReadIntent(tool="get_resource", resource="pods", api_version="v1", kind="Pod", namespace="openshift-ingress", name=pod_name),
                        ReadIntent(tool="search_resources", resource="events", api_version="v1", kind="Event", namespace="openshift-ingress", match_field="involvedObject.name", match_value=pod_name),
                    ],
                )
            assert context["findings"][0]["status"] == "investigated"
            assert context["findings"][0]["completed_checks"] == [
                "exact_pod_specification", "pod_mount_configuration", "pod_events",
            ]
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="The log finding received its model-selected follow-up reads.",
                supporting_evidence_ids=context["findings"][0]["evidence_ids"],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            if intent.tool == "pod_logs":
                return ReadResult((AdHocObservation(
                    id="cluster-proxy-log", tool="pod_logs",
                    summary=f"Collected current logs for {pod_name}.",
                    source=f"kubernetes:v1:Pod/log:openshift-ingress/{pod_name}?current",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "container": "istio-proxy", "previous": False,
                        "tail": (
                            "failed to generate secret: open /etc/certs/server.pem: "
                            "no such file or directory\nfailed to generate secret: "
                            "open /etc/certs/ca-cert.pem: no such file or directory"
                        ),
                    },
                ),))
            if intent.tool == "get_resource":
                return ReadResult((AdHocObservation(
                    id="cluster-gateway-pod", tool="get_resource",
                    summary=f"Read Pod openshift-ingress/{pod_name}.",
                    source=f"kubernetes:v1:Pod:openshift-ingress/{pod_name}",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "api_version": "v1", "kind": "Pod",
                        "metadata": {"namespace": "openshift-ingress", "name": pod_name},
                        "spec": {
                            "containers": [{
                                "name": "istio-proxy",
                                "volume_mounts": [{"name": "gateway-certs", "mount_path": "/etc/certs"}],
                            }],
                            "volumes": [{"name": "gateway-certs", "secret": {"secret_name": "gateway-certs"}}],
                        },
                        "podpilotMounts": [{
                            "containerType": "container", "container": "istio-proxy",
                            "mountPath": "/etc/certs", "volume": "gateway-certs",
                            "sourceType": "Secret", "sourceName": "gateway-certs",
                        }],
                    },
                ),))
            assert intent.tool == "search_resources"
            return ReadResult((AdHocObservation(
                id="cluster-gateway-events", tool="search_resources",
                summary=f"Found Events for {pod_name}.",
                source="kubernetes:v1:Event:openshift-ingress/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "v1", "kind": "Event", "scope": "openshift-ingress",
                    "matchField": "involvedObject.name", "matchValue": pod_name,
                    "count": 1, "items": [{"reason": "FailedMount", "message": "Mount failed"}],
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    settings = Settings(
        auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
        role_breakglass_groups=[],
    )
    existing = [{
        "id": "cluster-gateway-pods", "tool": "list_resources",
        "summary": "Read gateway Pods.", "source": "kubernetes:v1:Pod:openshift-ingress/*",
        "collected_at": datetime.now(timezone.utc),
        "data": {
            "kind": "Pod", "scope": "openshift-ingress",
            "logCandidates": [{
                "namespace": "openshift-ingress", "pod": pod_name,
                "containers": ["istio-proxy"], "phase": "Running", "ready": True,
                "restartCount": 0,
            }],
        },
    }]

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token", settings=settings, actor="ivy",
        workflow_id="workflow-proxy-followup",
        question="Investigate errors in the discovered gateway proxy logs.",
        conversation=[], existing_evidence=existing,
    ))

    assert [call.tool for call in explorer.calls] == [
        "pod_logs", "get_resource", "search_resources",
    ]
    assert explorer.calls[1].namespace == "openshift-ingress"
    assert explorer.calls[1].name == pod_name
    assert explorer.calls[2].match_field == "involvedObject.name"
    assert [entry.get("automatic_followup") for entry in result.activity] == [None, None, None]
    final_finding = provider.contexts[2]["findings"][0]
    assert final_finding["kind"] == "log_signal"
    assert final_finding["category"] == "tls_or_certificate"
    assert final_finding["paths"] == [
        "/etc/certs/server.pem", "/etc/certs/ca-cert.pem",
    ]
    assert final_finding["evidence_ids"] == [
        "cluster-proxy-log", "cluster-gateway-pod", "cluster-gateway-events",
    ]
    assert final_finding["mount_correlations"][0]["sourceName"] == "gateway-certs"


def test_adhoc_answer_preserves_agent_text_without_injecting_rbac_prose() -> None:
    denial = (
        "OpenShift RBAC denied the podpilot-investigator ServiceAccount permission to list "
        "ingresscontrollers at cluster-wide scope (HTTP 403)."
    )
    answer = AdHocAnswer(
        answer_mode="insufficient_evidence",
        answer=(
            "No IngressController evidence was available.\n\n"
            "[observations.0.data.items[0].metadata.name]"
        ),
        cited_evidence_ids=[],
        limitations=[],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids=set(),
        collection_limitations=[denial],
    )

    assert str(validated["content"]) == "No IngressController evidence was available."
    assert denial not in str(validated["content"])
    assert "observations.0" not in str(validated["content"])


def test_adhoc_answer_does_not_call_unrelated_rbac_failure_blocking() -> None:
    denial = (
        "OpenShift RBAC denied the configured identity permission to list "
        "configs.operator.openshift.io at cluster-wide scope (HTTP 403)."
    )
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        answer="The exact ConfigMap contains the requested exporter configuration.",
        cited_evidence_ids=["cluster-configmap"],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={"cluster-configmap"},
        collection_limitations=[denial],
    )

    assert not str(validated["content"]).startswith("**Access blocked")


def test_empty_audit_evidence_cannot_be_presented_as_no_cluster_activity() -> None:
    evidence_id = "audit-empty"
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        conclusion_status="confirmed",
        answer="No audit entries were recorded and no users performed actions in the cluster.",
        cited_evidence_ids=[evidence_id],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={evidence_id},
        observations=[{
            "id": evidence_id,
            "tool": "query_audit_events",
            "data": {"count": 0, "events": [], "rangeSeconds": 86_400},
        }],
    )

    assert validated["conclusion_status"] == "unresolved"
    assert "does not establish that no cluster actions occurred" in str(validated["content"])
    assert any(
        "cannot prove an absence" in limitation
        for limitation in validated["limitations"]
    )


def test_adhoc_answer_removes_provider_recommendations_from_narrative() -> None:
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        answer=(
            "### Summary\n\nThe collector is restarting.\n\n"
            "### Recommended action\n\n- Correct the processor name.\n- Redeploy the collector."
        ),
        cited_evidence_ids=["cluster-pod-1"],
        limitations=[],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={"cluster-pod-1"},
    )

    assert validated["content"] == "### Summary\n\nThe collector is restarting."


def test_cited_unresolved_answer_remains_grounded_without_being_rejected() -> None:
    answer = AdHocAnswer(
        answer_mode="insufficient_evidence",
        conclusion_status="unresolved",
        answer=(
            "The proxy logs show missing certificate files, but the intended TLS termination "
            "point is not established by the collected configuration."
        ),
        cited_evidence_ids=["cluster-proxy-log"],
        limitations=["No relevant Gateway object was observed."],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={"cluster-proxy-log"},
    )

    assert validated["answer_mode"] == "evidence_based"
    assert validated["conclusion_status"] == "unresolved"
    assert validated["citations"] == ["cluster-proxy-log"]
    assert _adhoc_answer_quality_issue(
        content=str(validated["content"]),
        answer_mode=str(validated["answer_mode"]),
        has_evidence=True,
        has_citations=True,
    ) is None


def test_final_answer_quality_rejects_heading_only_but_accepts_concise_prose() -> None:
    assert _adhoc_answer_quality_issue(
        content="### Observed objects — what the cluster is actually doing",
    ) == "heading_only_response"
    assert _adhoc_answer_quality_issue(
        content="No errors.",
    ) is None
    assert _adhoc_answer_quality_issue(
        content=(
            "Inspect the full object with `kubectl get kafka example -n streaming -o yaml` "
            "and look under spec."
        ),
    ) == "operator_shell_command"
    assert _adhoc_answer_quality_issue(
        content="The evidence was collected through the Kubernetes API without a shell command.",
    ) is None


def test_final_answer_quality_rejects_unfinished_content() -> None:
    assert _adhoc_answer_quality_issue(
        content="The ConfigMap contains the following observed data:",
    ) == "incomplete_answer_ending"
    assert _adhoc_answer_quality_issue(
        content="The ConfigMap contains:\n\n```yaml\nrules:",
    ) == "incomplete_answer_ending"
    assert _adhoc_answer_quality_issue(
        content="The ConfigMap contains:\n\n```yaml\nrules: []",
    ) == "unclosed_code_fence"
    assert _adhoc_answer_quality_issue(
        content="The ConfigMap contains:\n\n```yaml\nrules: []\n```",
    ) is None


def test_final_answer_quality_rejects_embedded_schema_but_not_markdown_style() -> None:
    assert _adhoc_answer_quality_issue(
        content=(
            "## Investigation gaps ```json [{\"investigation_gaps\": []}] ```"
        ),
    ) == "structured_fields_embedded_in_answer"
    assert _adhoc_answer_quality_issue(
        content=(
            "## Recommended next evidence | Priority | Evidence needed | Why it matters | "
            "| High | service_spec | Verify targetPort |"
        ),
    ) == "heading_only_response"
    assert _adhoc_answer_quality_issue(
        content="There is not enough information to answer.",
        answer_mode="insufficient_evidence",
        has_evidence=True,
    ) == "insufficient_interpretation_with_available_evidence"
    assert _adhoc_answer_quality_issue(
        content=(
            "The Pod logs show missing certificate files, but the intended TLS termination "
            "point remains unresolved."
        ),
        answer_mode="insufficient_evidence",
        has_evidence=True,
        has_citations=True,
    ) is None


def test_agent_final_answer_quality_rejects_serialized_tool_arguments() -> None:
    command = json.dumps({
        "cluster_id": SYSTEM_CLUSTER_ID,
        "command": "oc get pods -n openshift-logging -o name",
    })

    assert _agent_final_answer_quality_issue(command) == (
        "execute_shell_arguments_as_answer"
    )
    assert _agent_final_answer_quality_issue(f"```json\n{command}\n```") == (
        "execute_shell_arguments_as_answer"
    )
    assert _agent_final_answer_quality_issue(
        "The LokiStack is healthy based on the collected Pod status."
    ) is None


def test_agent_completion_recovers_prose_from_serialized_finish_arguments() -> None:
    content = json.dumps({
        "answer": "## Loki datasource\n\nThe cluster uses `logging-loki`.",
        "stop_reason": "complete",
        "unresolved_safe_reads": [],
    })

    assert _recover_serialized_agent_completion(content) == (
        "complete",
        "## Loki datasource\n\nThe cluster uses `logging-loki`.",
        [],
    )
    assert _agent_final_answer_quality_issue(content) == (
        "finish_investigation_arguments_as_answer"
    )


def test_agent_completion_does_not_recover_malformed_finish_arguments() -> None:
    malformed = json.dumps({
        "answer": {"summary": "The cluster uses logging-loki."},
        "stop_reason": "complete",
        "unresolved_safe_reads": [],
    })

    assert _recover_serialized_agent_completion(malformed) is None
    assert _agent_final_answer_quality_issue(malformed) == (
        "finish_investigation_arguments_as_answer"
    )


def test_inline_bold_sections_and_unicode_bullets_become_readable_markdown() -> None:
    cleaned = _clean_adhoc_markdown(
        "**Observation** • The Route uses passthrough TLS. • The Service receives port 443. "
        "**Interpretation** • The backend must accept TLS. "
        "**Recommended next steps** • Inspect Pod logs for certificate errors."
    )

    assert cleaned.startswith("### Observed evidence\n\n- The Route")
    assert "\n\n### Interpretation\n\n- The backend" in cleaned
    assert "\n\n### Recommended next steps\n\n- Inspect Pod logs" in cleaned


def test_unicode_bullets_do_not_leave_later_markdown_headings_inline() -> None:
    cleaned = _clean_adhoc_markdown(
        "### Observed configuration • The Route uses passthrough TLS. "
        "### Runtime observations • Pod logs show a missing certificate. "
        "### Interpretation • The sidecar cannot load its TLS material. "
        "### Recommended next steps • Inspect the exact Pod mounts."
    )

    assert "\n\n### Runtime observations\n\n- Pod logs" in cleaned
    assert "\n\n### Interpretation\n\n- The sidecar" in cleaned
    assert "\n\n### Recommended next steps\n\n- Inspect" in cleaned


def test_recommendation_heading_is_not_a_quality_contract() -> None:
    content = "## Recommended next steps\n\n- Inspect the exact Pod mounts."

    assert _adhoc_answer_quality_issue(content=content) is None


def test_provider_recommendation_schema_tail_is_removed_before_markdown_rendering() -> None:
    cleaned = _clean_adhoc_markdown(
        "## Observation\n\nThe Pod is restarting.\n\n"
        'recommended_actions: [{"label": "Inspect logs"}]'
    )

    assert cleaned == "## Observation\n\nThe Pod is restarting."
    assert "recommended_actions" not in cleaned


def test_answer_correction_preserves_earlier_structured_recommendations() -> None:
    corrected = _merge_validated_recommendations(
        {"recommended_next_checks": ["Inspect the exact Pod mounts."]},
        {
            "content": "Corrected Markdown answer.",
            "recommended_next_checks": [],
        },
    )

    assert corrected["content"] == "Corrected Markdown answer."
    assert corrected["recommended_next_checks"] == [
        "Inspect the exact Pod mounts."
    ]


def test_flattened_heading_answer_is_normalized_before_quality_validation() -> None:
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        conclusion_status="probable",
        answer=(
            "### What the Route tells us today --- The Route uses TLS passthrough and "
            "forwards encrypted traffic to the backend Service. - The Service specification "
            "has not been collected, so its target port remains unverified. "
            "### Next evidence --- Read the referenced Service and its endpoints."
        ),
        cited_evidence_ids=["route-1"],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={"route-1"},
    )

    assert "### What the Route tells us today\n\nThe Route uses" in validated["content"]
    assert "\n- The Service specification" in validated["content"]
    assert "\n\n### Next evidence\n\nRead the referenced Service" in validated["content"]
    assert _adhoc_answer_quality_issue(
        content=str(validated["content"]),
        answer_mode=str(validated["answer_mode"]),
        has_evidence=True,
        has_citations=True,
    ) is None


def test_exact_resource_read_inherits_unique_namespace_from_inventory_evidence() -> None:
    plan = ReadPlan(
        goal_type="explain",
        scope_summary="Read the discovered forwarder configuration.",
        intents=[ReadIntent(
            tool="get_resource",
            resource="clusterlogforwarders.observability.openshift.io",
            api_version="observability.openshift.io/v1",
            kind="ClusterLogForwarder",
            name="instance",
        )],
    )

    bound, errors, rejected = _bind_plan_log_intents(
        plan,
        [],
        question="How is the ClusterLogForwarder instance configured?",
        evidence=[{
            "id": "cluster-clf-list",
            "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder",
                "names": ["instance"],
                "objects": [{"namespace": "openshift-logging", "name": "instance"}],
            },
        }],
    )

    assert errors == []
    assert rejected == []
    assert bound.intents[0].namespace == "openshift-logging"
    assert _adhoc_answer_quality_issue(
        content="The Route configuration was inspected and uses TLS passthrough.",
    ) is None
    assert _adhoc_answer_quality_issue(
        content="The configured forwarder objects were found in the selected clusters.",
    ) is None
    assert _adhoc_answer_quality_issue(
        content="The exact forwarder routes application logs through the configured Kafka output.",
    ) is None
    assert _adhoc_answer_quality_issue(
        content="The operator objects were found and report their current names.",
    ) is None
    assert _adhoc_answer_quality_issue(
        content="The following cluster operators are available: ingress and monitoring.",
    ) is None


def test_endpoint_slice_target_ref_grounds_exact_pod_read() -> None:
    plan = ReadPlan(
        goal_type="diagnose",
        scope_summary="Inspect the exact Pod referenced by the EndpointSlice.",
        intents=[ReadIntent(
            tool="get_resource",
            resource="pods",
            api_version="v1",
            kind="Pod",
            namespace="openshift-ingress",
            name="gateway-abc",
        )],
    )

    bound, errors, rejected = _bind_plan_log_intents(
        plan,
        [],
        question="Why is this Route returning an Internal Server Error?",
        evidence=[{
            "id": "cluster-gateway-slice",
            "tool": "list_resources",
            "data": {
                "kind": "EndpointSlice",
                "items": [{
                    "kind": "EndpointSlice",
                    "metadata": {
                        "name": "gateway-slice",
                        "namespace": "openshift-ingress",
                    },
                    "endpoints": [{
                        "addresses": ["10.0.0.8"],
                        "targetRef": {
                            "kind": "Pod",
                            "namespace": "openshift-ingress",
                            "name": "gateway-abc",
                        },
                    }],
                }],
            },
        }],
    )

    assert errors == []
    assert rejected == []
    assert bound.intents[0].name == "gateway-abc"
    assert bound.intents[0].namespace == "openshift-ingress"


def test_model_can_traverse_evidence_grounded_owner_references() -> None:
    pod_name = "gateway-7d9f"

    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if context["investigation_round"] == 1:
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Follow the Pod owner to its ReplicaSet.",
                    intents=[ReadIntent(
                        tool="get_resource", resource="replicasets", api_version="apps/v1",
                        kind="ReplicaSet", name="gateway-7d9f6b", namespace="maas",
                    )],
                )
            if context["investigation_round"] == 2:
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Follow the ReplicaSet owner to its Deployment.",
                    intents=[ReadIntent(
                        tool="get_resource", resource="deployments", api_version="apps/v1",
                        kind="Deployment", name="gateway", namespace="maas",
                    )],
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="The workload controller configuration is available.",
                supporting_evidence_ids=["cluster-rs", "cluster-deployment"],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            if intent.kind == "ReplicaSet":
                return ReadResult((AdHocObservation(
                    id="cluster-rs", tool="get_resource", summary="Read the owning ReplicaSet.",
                    source="kubernetes:apps/v1:ReplicaSet:maas/gateway-7d9f6b",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "kind": "ReplicaSet",
                        "metadata": {
                            "name": "gateway-7d9f6b", "namespace": "maas",
                            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "gateway"}],
                        },
                    },
                ),))
            return ReadResult((AdHocObservation(
                id="cluster-deployment", tool="get_resource",
                summary="Read the owning Deployment.",
                source="kubernetes:apps/v1:Deployment:maas/gateway",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Deployment", "metadata": {"name": "gateway", "namespace": "maas"}},
            ),))

    provider = Provider()
    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="owner-traversal",
        question=f"Why is Pod {pod_name} in namespace maas missing its certificates?",
        conversation=[],
        existing_evidence=[{
            "id": "cluster-pod", "tool": "get_resource",
            "summary": "Read the gateway Pod.",
            "source": f"kubernetes:v1:Pod:maas/{pod_name}",
            "collected_at": datetime.now(timezone.utc),
            "data": {
                "kind": "Pod",
                "metadata": {
                    "name": pod_name, "namespace": "maas",
                    "ownerReferences": [{
                        "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "gateway-7d9f6b",
                    }],
                },
            },
        }],
    ))

    assert [call.kind for call in explorer.calls] == ["ReplicaSet", "Deployment"]
    assert [item["id"] for item in result.evidence[-2:]] == ["cluster-rs", "cluster-deployment"]
    assert len(provider.contexts) == 3
    assert "planner_feedback" not in provider.contexts[-1]


def test_inventory_only_configuration_answer_gets_advisory_without_rejection() -> None:
    observations = [{
        "id": "cluster-clf-list",
        "tool": "list_resources",
        "data": {"kind": "ClusterLogForwarder", "names": ["instance"]},
    }]

    assert _adhoc_answer_advisories(
        citations=["cluster-clf-list"],
        question="How are the log forwarders configured?",
        observations=observations,
    ) == [
        "This answer relies on inventory-level evidence; exact-object spec/status "
        "evidence would be needed for a detailed configuration or health conclusion."
    ]


def test_deterministic_log_findings_render_missing_certificate_details() -> None:
    evidence = [{
        "id": "cluster-log-1", "tool": "pod_logs",
        "source": "kubernetes:v1:Pod/log:openshift-ingress/gateway-abc?current",
        "data": {
            "container": "istio-proxy", "previous": False,
            "tail": (
                "failed to generate secret for file-root: open /etc/certs/server.pem: "
                "no such file or directory\nfailed to generate secret for file-root: open "
                "/etc/certs/ca-cert.pem: no such file or directory"
            ),
        },
    }]
    activity = [{
        "tool": "pod_logs", "status": "succeeded", "evidence_ids": ["cluster-log-1"],
    }]

    section = _deterministic_log_findings_section(evidence=evidence, activity=activity)

    assert section is not None
    assert "Backend log findings" in section["content"]
    assert "`openshift-ingress/gateway-abc`" in section["content"]
    assert "`istio-proxy`" in section["content"]
    assert "tls or certificate" in section["content"]
    assert "`/etc/certs/server.pem`" in section["content"]
    assert "no such file or directory" in section["content"]
    assert section["citations"] == ["cluster-log-1"]
    assert section["required_log_citations"] == ["cluster-log-1"]


def test_final_answer_context_compacts_large_logs_and_prioritizes_current_reads() -> None:
    evidence = [
        {
            "id": "old-log", "tool": "pod_logs", "summary": "Old logs.",
            "source": "kubernetes:v1:Pod/log:old/api?current",
            "data": {"container": "api", "tail": "o" * 20_000},
        },
        {
            "id": "current-log", "tool": "pod_logs", "summary": "Current logs.",
            "source": "kubernetes:v1:Pod/log:payments/api?current",
            "data": {"container": "api", "tail": "c" * 20_000},
        },
    ]
    compacted, metadata = _compact_answer_evidence(
        evidence,
        activity=[{"evidence_ids": ["current-log"]}],
        total_byte_limit=20_000,
    )

    assert compacted[0]["id"] == "current-log"
    assert len(compacted[0]["data"]["tail"]) == 6_000
    assert compacted[0]["data"]["tailTruncatedForModel"] is True
    assert metadata["encoded_bytes"] <= 20_000
    assert metadata["observations_sent"] == len(compacted)


def test_model_fact_cards_replace_raw_observations_with_bounded_material_facts() -> None:
    cards = _model_fact_cards(
        [{
            "id": "route-1", "tool": "get_resource", "cluster_name": "east",
            "summary": "Read the matching Route.",
            "data": {
                "apiVersion": "route.openshift.io/v1", "kind": "Route",
                "metadata": {"namespace": "apps", "name": "frontend"},
                "spec": {
                    "host": "frontend.example.test",
                    "to": {"kind": "Service", "name": "frontend"},
                    "tls": {"termination": "edge"},
                },
            },
        }],
        activity=[{"status": "succeeded", "evidence_ids": ["route-1"]}],
    )

    assert cards[0]["id"] == "route-1"
    assert cards[0]["cluster"] == "east"
    facts = {item["label"]: item["value"] for item in cards[0]["facts"]}
    assert facts["Route host"] == "frontend.example.test"
    assert facts["TLS termination"] == "edge"
    assert "data" not in cards[0]
    assert len(json.dumps(cards[0])) < 3000


def test_model_fact_cards_include_bounded_exact_configmap_data() -> None:
    cards = _model_fact_cards(
        [{
            "id": "configmap-1", "tool": "get_resource", "cluster_name": "central",
            "summary": "Read the exporter ConfigMap.",
            "data": {
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "namespace": "kafka-observability",
                    "name": "kafka-observability-metrics-config",
                },
                "data": {
                    "metrics-config.yml": (
                        "lowercaseOutputName: true\nrules:\n"
                        "  - pattern: kafka.server<type=(.+), name=(.+)><>Value\n"
                    ),
                },
            },
        }],
        activity=[{"status": "succeeded", "evidence_ids": ["configmap-1"]}],
    )

    details = cards[0]["material_details"][0]
    assert details["kind"] == "ConfigMap"
    assert "kafka.server" in details["data"]["metrics-config.yml"]
    assert len(json.dumps(cards[0]).encode("utf-8")) <= 3_000


def test_model_fact_cards_preserve_requested_node_labels() -> None:
    cards = _model_fact_cards(
        [{
            "id": "node-1", "tool": "get_resource", "cluster_name": "central",
            "summary": "Read the exact Node.",
            "data": {
                "apiVersion": "v1", "kind": "Node",
                "metadata": {
                    "name": "worker-1",
                    "labels": {
                        "kubernetes.io/hostname": "worker-1",
                        "node-role.kubernetes.io/worker": "",
                    },
                },
                "spec": {"unschedulable": False},
            },
        }],
        activity=[{"status": "succeeded", "evidence_ids": ["node-1"]}],
        question="Show the labels on node worker-1.",
    )

    details = cards[0]["material_details"][0]
    assert details["metadata"]["labels"] == {
        "kubernetes.io/hostname": "worker-1",
        "node-role.kubernetes.io/worker": "",
    }
    assert len(json.dumps(cards[0]).encode("utf-8")) <= 3_000


def test_model_fact_cards_enforce_per_card_and_aggregate_payload_limits() -> None:
    evidence = [
        {
            "id": f"log-{index}",
            "tool": "pod_logs",
            "cluster_name": "east",
            "summary": "x" * 2_000,
            "data": {"tail": "y" * 20_000},
        }
        for index in range(20)
    ]

    cards = _model_fact_cards(evidence, activity=[], max_cards=12, total_byte_limit=5_000)

    assert len(cards) <= 12
    assert all(len(json.dumps(card).encode("utf-8")) <= 3_000 for card in cards)
    assert len(json.dumps(cards).encode("utf-8")) <= 5_200


def test_limitations_are_semantically_deduplicated() -> None:
    limitations = _dedupe_limitations([
        "TLS certificate verification was explicitly bypassed for this troubleshooting probe.",
        "TLS verification was intentionally bypassed for the probe.",
        "No Event resources matched the bounded query.",
        "No Event resources matched the pod.",
    ])

    assert len(limitations) == 2


def test_model_recovery_limitations_collapse_without_hiding_tls_warnings() -> None:
    limitations = _dedupe_limitations([
        "The model planner twice stopped before collecting evidence; PodPilot used one read.",
        "The model twice stopped despite an actionable structured evidence gap; PodPilot selected the highest-priority grounded read candidate.",
        "The model returned an incomplete final answer after one correction attempt; PodPilot used a deterministic evidence summary.",
        "TLS certificate verification was explicitly bypassed for this troubleshooting probe.",
    ])

    assert limitations == [
        "The model stopped early or repeated reads; PodPilot used grounded read candidates and deterministic evidence where needed.",
        "TLS certificate verification was explicitly bypassed for this troubleshooting probe.",
    ]


def test_deterministic_evidence_fallback_never_returns_an_empty_answer() -> None:
    fallback = _deterministic_evidence_fallback_answer(
        evidence=[{
            "id": "cluster-route-1", "tool": "search_resources",
            "summary": "Found the matching Route.",
        }],
        activity=[{"evidence_ids": ["cluster-route-1"]}],
    )

    assert fallback["answer_mode"] == "evidence_based"
    assert "Found the matching Route" in fallback["content"]
    assert fallback["citations"] == ["cluster-route-1"]


def test_deterministic_evidence_fallback_does_not_reuse_previous_turn_evidence() -> None:
    fallback = _deterministic_evidence_fallback_answer(
        evidence=[{
            "id": "old-node-list", "tool": "list_resources",
            "summary": "Read one Node resource.",
        }],
        activity=[],
    )

    assert fallback["answer_mode"] == "insufficient_evidence"
    assert fallback["citations"] == []
    assert "Node" not in fallback["content"]


def test_adhoc_answer_structures_inline_labels_and_removes_inline_citations() -> None:
    evidence_id = "cluster-pod-7"
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        answer=(
            f"The collector is repeatedly crashing [{evidence_id}]. "
            "Root cause: Its configuration names an unsupported processor. "
            "Remediation: Correct the processor name and redeploy the collector."
        ),
        cited_evidence_ids=[evidence_id],
        limitations=[],
    )

    validated = _validated_adhoc_answer(answer, known_evidence_ids={evidence_id})
    content = str(validated["content"])

    assert f"[{evidence_id}]" not in content
    assert "\n\n### Root cause\n\n" in content
    assert "\n\n### Remediation\n\n" in content


def test_adhoc_answer_recovers_exact_inline_evidence_id_from_empty_citation_array() -> None:
    evidence_id = "cluster-5f4d6f47-42fb-49f5-a3af-60db6d987c7f"
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        conclusion_status="probable",
        answer=(
            "**Confirmed observations** — The Route uses TLS passthrough "
            f"(cited_evidence_ids: {evidence_id}). The backend must accept TLS."
        ),
        cited_evidence_ids=[],
        limitations=[],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={evidence_id, "cluster-unrelated"},
    )

    assert validated["answer_mode"] == "evidence_based"
    assert validated["conclusion_status"] == "probable"
    assert validated["citations"] == [evidence_id]
    assert "cited_evidence_ids" not in str(validated["content"])
    assert evidence_id not in str(validated["content"])
    assert _adhoc_answer_quality_issue(
        content=str(validated["content"]),
        answer_mode=str(validated["answer_mode"]),
        has_evidence=True,
        has_citations=True,
    ) is None


def test_adhoc_answer_removes_comma_separated_internal_citation_marker() -> None:
    first = "cluster-0228778f-93f6-41b5-bddc-68597cfcce9f"
    second = "cluster-bca2be53-6576-49d0-9a1d-187a6a228d2f"
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        answer=(
            f"## Service and Endpoints (cited_evidence_ids:{first}, {second})\n\n"
            "The collected objects show the backend topology."
        ),
        cited_evidence_ids=[first, second],
    )

    validated = _validated_adhoc_answer(
        answer, known_evidence_ids={first, second},
    )

    assert validated["citations"] == [first, second]
    assert "cited_evidence_ids" not in str(validated["content"])
    assert first not in str(validated["content"])
    assert second not in str(validated["content"])


def test_adhoc_answer_does_not_recover_unknown_inline_evidence_id() -> None:
    answer = AdHocAnswer(
        answer_mode="evidence_based",
        answer="The Route is healthy (evidence ID: cluster-invented).",
        cited_evidence_ids=[],
        limitations=[],
    )

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={"cluster-real"},
    )

    assert validated["answer_mode"] == "insufficient_evidence"
    assert validated["citations"] == []
    assert validated["content"] == "The Route is healthy."
    assert "did not cite collected evidence" in " ".join(validated["limitations"])


def test_tls_claim_contradiction_is_labeled_without_rewriting_agent_text() -> None:
    answer = AdHocAnswer(
        answer_mode="insufficient_evidence",
        answer=(
            "The gateway pod is not terminating TLS and is likely serving only plain HTTP."
        ),
        cited_evidence_ids=["cluster-sidecar-1"],
        limitations=[],
    )
    observations = [
        {
            "id": "cluster-route-1",
            "tool": "search_resources",
            "data": {"kind": "Route", "items": [{
                "spec": {"tls": {"termination": "passthrough"}},
            }]},
        },
        {
            "id": "network-probe-1",
            "tool": "http_probe",
            "data": {
                "outcome": "failed",
                "stage": "tls",
                "logicalHost": "maas.apps.example.test",
                "connectHost": "10.0.0.12",
                "port": 443,
                "error": "certificate verify failed: self-signed certificate in certificate chain",
            },
        },
        {
            "id": "cluster-sidecar-1",
            "tool": "pod_logs",
            "data": {"container": "istio-proxy", "tail": "upstream reset"},
        },
        {
            "id": "network-probe-insecure-1",
            "tool": "http_probe",
            "data": {
                "outcome": "completed", "statusCode": 500,
                "logicalHost": "maas.apps.example.test",
                "tlsVerificationRequested": False,
                "tls": {"verified": False, "verificationMode": "insecure"},
            },
        },
    ]

    validated = _validated_adhoc_answer(
        answer,
        known_evidence_ids={item["id"] for item in observations},
        observations=observations,
    )

    assert validated["answer_mode"] == "evidence_based"
    assert validated["content"] == (
        "The gateway pod is not terminating TLS and is likely serving only plain HTTP."
    )
    assert validated["citations"] == [
        "network-probe-1", "network-probe-insecure-1", "cluster-route-1",
        "cluster-sidecar-1",
    ]
    assert "original response is preserved" in validated["limitations"][0]


def test_operator_evidence_view_surfaces_probe_diagnostics_and_redacted_payload() -> None:
    view = _adhoc_evidence_view({
        "id": "network-probe-1",
        "tool": "http_probe",
        "summary": "HTTP probe failed during TLS.",
        "source": "https://maas.apps.example.test via 10.0.0.12:443",
        "collected_at": "2026-08-26T00:00:00+00:00",
        "data": {
            "outcome": "failed",
            "stage": "tls",
            "logicalHost": "maas.apps.example.test",
            "connectHost": "10.0.0.12",
            "port": 443,
            "resolvedAddresses": ["10.0.0.12"],
            "tlsVerificationRequested": True,
            "error": "certificate verify failed",
            "elapsedMs": 41.2,
        },
    })

    facts = {item["label"]: item["value"] for item in view["facts"]}
    assert facts["Failure stage"] == "tls"
    assert facts["Logical host / SNI"] == "maas.apps.example.test"
    assert facts["Connected to"] == "10.0.0.12:443"
    assert facts["TLS verification requested"] == "true"
    assert facts["Probe error"] == "certificate verify failed"
    assert '"resolvedAddresses": [' in view["data_json"]


def test_operator_evidence_view_builds_metric_ranking_for_direct_rendering() -> None:
    view = _adhoc_evidence_view({
        "id": "metric-cpu-1",
        "tool": "query_metrics",
        "summary": "Ranked CPU consumers.",
        "source": "thanos:query_range/top_cpu_consumers",
        "data": {
            "metric": "top_cpu_consumers",
            "unit": "cores",
            "complete": True,
            "ranking": [{
                "labels": {"namespace": "logging", "pod": "collector-1", "container": "collector"},
                "average": 0.7, "current": 0.9, "maximum": 1.0,
            }],
        },
    })

    ranking = view["metric_ranking"]
    assert ranking["title"] == "Top CPU Consumers"
    assert ranking["scale_max"] == 0.9
    assert ranking["columns"] == [
        {"key": "namespace", "label": "Namespace"},
        {"key": "pod", "label": "Pod"},
        {"key": "container", "label": "Container"},
    ]
    assert ranking["rows"][0] == {
        "rank": 1, "dimensions": ["logging", "collector-1", "collector"],
        "identity": "logging / collector-1 / collector", "average": "0.700 cores",
        "current": "0.900 cores", "maximum": "1.000 cores", "progress": 0.9,
    }


def test_operator_evidence_view_builds_topic_first_kafka_storage_detail() -> None:
    view = _adhoc_evidence_view({
        "id": "metric-kafka-storage", "tool": "query_metrics",
        "source": "thanos:query_range/kafka_topic_disk_utilization",
        "data": {
            "metric": "kafka_topic_disk_utilization", "scope": "kafka_cluster",
            "namespace": "streams", "name": "orders", "unit": "percent",
            "complete": True,
            "ranking": [{
                "labels": {"topic": "orders"},
                "average": 0.005, "current": 0.008, "maximum": 0.009,
            }],
            "topicStorage": {
                "complete": True, "topicBytesComplete": True,
                "partitionDetailsComplete": True, "selectedTopicsComplete": True,
                "topics": [{
                    "topic": "orders", "internal": False,
                    "currentBytes": 3072.0, "utilizationPercent": 0.008,
                    "partitionCount": 2, "replicaCount": 2,
                    "partitionsComplete": True,
                    "partitions": [
                        {
                            "partition": "0", "brokerPod": "orders-broker-0",
                            "brokerId": "0", "currentBytes": 2048.0,
                        },
                        {
                            "partition": "1", "brokerPod": "orders-broker-1",
                            "brokerId": "1", "currentBytes": 1024.0,
                        },
                    ],
                }],
            },
        },
    })

    storage = view["kafka_topic_storage"]
    assert storage["title"] == "Kafka Topic Disk Usage"
    assert storage["complete"] is True
    assert storage["scale_max"] == 100.0
    assert storage["rows"][0]["current_bytes"] == "3.00 KiB"
    assert storage["rows"][0]["utilization"] == "<0.01%"
    assert storage["rows"][0]["placement_summary"] == "2 partitions · 2 replicas"
    assert storage["rows"][0]["partitions"][0] == {
        "partition": "0", "broker_pod": "orders-broker-0",
        "broker_id": "0", "current_bytes": "2.00 KiB",
    }


def test_operator_evidence_view_builds_scoped_log_volume_dimensions() -> None:
    view = _adhoc_evidence_view({
        "id": "metric-log-pods", "tool": "query_metrics",
        "source": "loki:application/query/application_log_volume",
        "data": {
            "metric": "application_log_volume", "scope": "namespace",
            "namespace": "payments", "groupBy": ["pod"],
            "unit": "bytes", "averageUnit": "bytes_per_second", "complete": True,
            "ranking": [{
                "labels": {"namespace": "payments", "pod": "api-1"},
                "average": 1024, "current": 1_048_576, "maximum": None,
            }],
        },
    })["metric_ranking"]

    assert view["title"] == "Top Application-Log Volume by Pod"
    assert view["columns"] == [
        {"key": "namespace", "label": "Namespace"},
        {"key": "pod", "label": "Pod"},
    ]
    assert view["average_label"] == "Average rate"
    assert view["current_label"] == "Payload volume"
    assert view["show_maximum"] is False


def test_metric_card_derives_node_and_generic_kafka_dimensions() -> None:
    node = _adhoc_evidence_view({
        "id": "metric-node-cpu", "tool": "query_metrics",
        "source": "thanos:query_range/node_cpu_utilization",
        "data": {
            "metric": "node_cpu_utilization", "scope": "node_role",
            "unit": "percent", "complete": True,
            "ranking": [{
                "labels": {"nodename": "worker-1"},
                "average": 18.2, "current": 18.4, "maximum": 18.8,
            }],
        },
    })["metric_ranking"]
    kafka = _adhoc_evidence_view({
        "id": "metric-kafka-lag", "tool": "query_metrics",
        "source": "thanos:query_range/kafka_topic_lag",
        "data": {
            "metric": "kafka_topic_lag", "scope": "cluster",
            "unit": "messages", "complete": True,
            "ranking": [{
                "labels": {
                    "namespace": "streams", "topic": "orders", "partition": 0,
                    "consumer_group": "fulfillment",
                },
                "average": 80, "current": 120, "maximum": 150,
            }],
        },
    })["metric_ranking"]

    assert node["title"] == "Node CPU Utilization"
    assert node["columns"] == [{"key": "node", "label": "Node"}]
    assert node["rows"][0]["dimensions"] == ["worker-1"]
    assert kafka["title"] == "Kafka Topic Lag"
    assert [column["label"] for column in kafka["columns"]] == [
        "Namespace", "Topic", "Partition", "Consumer group",
    ]
    assert kafka["rows"][0]["dimensions"] == [
        "streams", "orders", "0", "fulfillment",
    ]


def test_semantic_cluster_metric_plan_preserves_requested_top_n() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        resource_query="Pod",
        needs_object_details=True,
        evidence_goal="Rank CPU-consuming pods on each selected cluster.",
        metric_query="top_cpu_consumers",
        metric_scope="cluster",
        result_limit=5,
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.goal_type == "compare"
    assert len(plan.intents) == 1
    assert plan.intents[0].tool == "query_metrics"
    assert plan.intents[0].metric_scope == "cluster"
    assert plan.intents[0].limit == 5


def test_semantic_worker_node_utilization_expands_to_cpu_and_memory_queries() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        resource_query="Node",
        object_name="worker",
        needs_object_details=True,
        evidence_goal="Compare worker node CPU and memory utilization.",
        metric_query="node_cpu_memory_utilization",
        metric_scope="node_role",
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [
        ReadIntent(
            tool="query_metrics", metric="node_cpu_utilization",
            metric_scope="node_role", name="worker", range_seconds=300,
        ),
        ReadIntent(
            tool="query_metrics", metric="node_memory_utilization",
            metric_scope="node_role", name="worker", range_seconds=300,
        ),
    ]


def test_typed_metric_request_compiles_multi_signal_pod_comparison() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Compare CPU and memory for the supplied Pod.",
        metric_request=MetricRequestSemantics(
            signals=["cpu_usage", "memory_working_set"],
            target=MetricTargetSemantics(
                scope="pod", kind="Pod", namespace="payments", name="api-7d9",
            ),
            operation="compare",
            statistic="current",
            range_seconds=900,
        ),
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.goal_type == "compare"
    assert [(intent.metric, intent.metric_scope) for intent in plan.intents] == [
        ("cpu_usage", "pod"), ("memory_working_set", "pod"),
    ]
    assert all(intent.namespace == "payments" for intent in plan.intents)
    assert all(intent.name == "api-7d9" for intent in plan.intents)
    assert all(intent.range_seconds == 900 for intent in plan.intents)


def test_typed_metric_request_compiles_statefulset_metrics_through_workload_scope() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Show Kafka StatefulSet traffic and restarts.",
        metric_request=MetricRequestSemantics(
            signals=["network_receive", "network_transmit", "container_restarts"],
            target=MetricTargetSemantics(
                scope="workload", kind="StatefulSet", namespace="kafka", name="broker",
            ),
            operation="show",
            statistic="maximum",
        ),
    ))

    assert compiled is not None
    plan, _ = compiled
    assert [intent.kind for intent in plan.intents] == ["StatefulSet"] * 3
    assert all(intent.metric_scope == "workload" for intent in plan.intents)
    assert all(intent.metric_statistic == "maximum" for intent in plan.intents)
    assert all(intent.range_seconds == 300 for intent in plan.intents)


def test_typed_metric_rank_maps_signal_to_registered_bounded_ranking() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Rank memory consumers in payments.",
        metric_request=MetricRequestSemantics(
            signals=["memory_working_set"],
            target=MetricTargetSemantics(
                scope="namespace", kind="Namespace", namespace="payments",
            ),
            operation="rank",
            group_by=["pod"],
            result_limit=5,
        ),
    ))

    assert compiled is not None
    intent = compiled[0].intents[0]
    assert intent.metric == "top_memory_consumers"
    assert intent.metric_scope == "namespace"
    assert intent.limit == 5
    assert intent.metric_operation == "rank"


def test_typed_metric_rank_maps_cluster_node_cpu_to_node_utilization() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Rank Nodes by CPU utilization.",
        metric_request=MetricRequestSemantics(
            signals=["node_cpu_utilization"],
            target=MetricTargetSemantics(scope="cluster", kind="Cluster"),
            operation="rank", group_by=["node"], result_limit=5,
        ),
    ))

    assert compiled is not None
    intent = compiled[0].intents[0]
    assert intent == ReadIntent(
        tool="query_metrics", metric="node_cpu_utilization",
        metric_scope="cluster", range_seconds=300, limit=5,
        metric_operation="rank", metric_group_by=["node"],
    )


def test_kafka_topic_utilization_followup_binds_opaque_cluster_target() -> None:
    class Provider:
        def classify_ad_hoc(self, _profile, _api_key, context):
            kafka = next(
                item for item in context["recent_object_references"]
                if item["kind"] == "Kafka"
            )
            return InquirySemantics(
                mode="metrics", evidence_goal="Show utilization for those Kafka topics.",
                metric_request=MetricRequestSemantics(
                    signals=[
                        "kafka_topic_messages_in", "kafka_topic_storage",
                        "kafka_consumer_lag", "kafka_under_replicated_partitions",
                    ],
                    target=MetricTargetSemantics(
                        scope="kafka_cluster", kind="Kafka", reference_id=kafka["id"],
                    ),
                    operation="compare", group_by=["topic"], range_seconds=300,
                ),
            )

    evidence = [{
        "id": "cluster-kafka", "tool": "get_resource",
        "data": {
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "resource": "kafkas.kafka.strimzi.io",
            "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
        },
    }]
    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Can you show the utilization of those Kafka topics?",
        conversation=[], cluster_names=["Central"], evidence=evidence,
    ))

    assert inquiry is not None and inquiry.metric_request is not None
    target = inquiry.metric_request.target
    assert (target.kind, target.namespace, target.name, target.reference_id) == (
        "Kafka", "vc-streams", "vc-cluster", None,
    )
    compiled = _semantic_metric_read_plan(inquiry)
    assert compiled is not None
    assert [intent.metric for intent in compiled[0].intents] == [
        "kafka_topic_messages_in", "kafka_topic_storage",
        "kafka_consumer_lag", "kafka_under_replicated_partitions",
    ]
    assert all(intent.metric_scope == "kafka_cluster" for intent in compiled[0].intents)
    assert all(intent.namespace == "vc-streams" for intent in compiled[0].intents)
    assert all(intent.name == "vc-cluster" for intent in compiled[0].intents)


def test_explicit_metric_question_retries_inventory_classification() -> None:
    class Provider:
        calls = 0

        def classify_ad_hoc(self, _profile, _api_key, context):
            self.calls += 1
            if self.calls == 1:
                return InquirySemantics(
                    mode="inventory", evidence_goal="List KafkaTopic resources.",
                    resource_query="KafkaTopic",
                )
            assert "select metrics mode" in context["structured_response_retry"]
            kafka = next(
                item for item in context["recent_object_references"]
                if item["kind"] == "Kafka"
            )
            return InquirySemantics(
                mode="metrics", evidence_goal="Show Kafka topic throughput.",
                metric_request=MetricRequestSemantics(
                    signals=["kafka_topic_messages_in"],
                    target=MetricTargetSemantics(
                        scope="kafka_cluster", kind="Kafka", reference_id=kafka["id"],
                    ),
                    group_by=["topic"],
                ),
            )

    provider = Provider()
    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=provider,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="Show the throughput of those Kafka topics.",
        conversation=[], cluster_names=["Central"],
        evidence=[{
            "id": "cluster-kafka", "tool": "get_resource",
            "data": {
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "resource": "kafkas.kafka.strimzi.io",
                "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
            },
        }],
    ))

    assert provider.calls == 2
    assert inquiry is not None and inquiry.mode == "metrics"


@pytest.mark.parametrize(
    ("signal", "scope", "kind", "namespace", "name"),
    [
        ("ingress_request_rate", "route", "Route", "payments", "api"),
        (
            "machineconfigpool_updated", "machine_config_pool",
            "MachineConfigPool", None, "worker",
        ),
        (
            "hpa_current_replicas", "horizontal_pod_autoscaler",
            "HorizontalPodAutoscaler", "payments", "api",
        ),
        (
            "workload_availability", "workload", "Deployment", "payments", "api",
        ),
        (
            "cluster_operator_degraded", "cluster_operator",
            "ClusterOperator", None, "network",
        ),
        ("apiserver_request_rate", "control_plane", "APIServer", None, None),
        ("apiserver_inflight_requests", "control_plane", "APIServer", None, None),
        ("scheduler_pending_pods", "control_plane", "Scheduler", None, None),
        ("etcd_db_size", "control_plane", "Etcd", None, None),
        ("etcd_has_leader", "control_plane", "Etcd", None, None),
        ("monitoring_targets_down", "monitoring", "Prometheus", None, None),
        ("prometheus_ingestion_rate", "monitoring", "Prometheus", None, None),
        ("logging_ingestion_rate", "logging", "LokiStack", None, None),
        ("logging_query_latency", "logging", "LokiStack", None, None),
    ],
)
def test_platform_metric_semantics_compile_registered_scope(
    signal: str, scope: str, kind: str, namespace: str | None, name: str | None,
) -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", evidence_goal=f"Read {signal}.",
        metric_request=MetricRequestSemantics(
            signals=[signal],
            target=MetricTargetSemantics(
                scope=scope, kind=kind, namespace=namespace, name=name,
            ),
        ),
    ))

    assert compiled is not None
    intent = compiled[0].intents[0]
    assert intent.metric == signal
    assert intent.metric_scope == scope
    assert intent.namespace == namespace
    assert intent.name == name


@pytest.mark.parametrize(
    ("question", "inquiry", "expected"),
    [
        ("show me failing pods", None, False),
        ("why is pod api-7d9 Pending?", None, True),
        ("which PVC is blocking pod api-7d9?", None, True),
        ("investigate the degraded network operator", None, True),
        (
            "check pod api-7d9",
            InquirySemantics(
                mode="investigate", cardinality="exact_one",
                resource_query="Pod", object_name="api-7d9", namespace="payments",
                evidence_goal="Investigate the supplied Pod.",
            ),
            True,
        ),
        (
            "show pod api-7d9",
            InquirySemantics(
                mode="investigate", cardinality="exact_one",
                resource_query="Pod", object_name="api-7d9", namespace="payments",
                evidence_goal="Read the supplied Pod.",
            ),
            False,
        ),
        (
            "check pod api-7d9",
            InquirySemantics(
                mode="investigate", operation="object_fields",
                cardinality="exact_one", resource_query="Pod",
                object_name="api-7d9", namespace="payments",
                evidence_goal="Read the supplied Pod before investigating it.",
            ),
            True,
        ),
    ],
)
def test_agentic_completion_policy_prefers_causal_investigation(
    question: str, inquiry: InquirySemantics | None, expected: bool,
) -> None:
    assert _question_requires_agentic_investigation(question, inquiry) is expected


def test_health_summary_object_reference_retains_source_cluster() -> None:
    evidence = [{
        "id": "central-health", "tool": "pod_health_summary",
        "cluster_id": "cluster-central", "cluster_name": "Central DEV",
        "data": {
            "kind": "Pod",
            "objects": [{
                "namespace": "openshift-logging", "name": "logging-loki-ingester-1",
            }],
        },
    }]

    references = _recent_object_references(evidence)

    assert len(references) == 1
    assert references[0]["cluster_id"] == "cluster-central"
    inquiry = InquirySemantics(
        mode="investigate", cardinality="exact_one", resource_query="Pod",
        object_reference_id=references[0]["id"],
        evidence_goal="Investigate the observed Pending Pod.",
    )
    assert _inquiry_reference_cluster_ids(inquiry, evidence) == {"cluster-central"}


def test_kafka_metric_rank_preserves_top_n_and_topic_grouping() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", evidence_goal="Rank topics by disk utilization.",
        metric_request=MetricRequestSemantics(
            signals=["kafka_topic_disk_utilization"],
            target=MetricTargetSemantics(
                scope="kafka_cluster", kind="Kafka",
                namespace="vc-streams", name="vc-cluster",
            ),
            operation="rank", group_by=["topic"], result_limit=7,
        ),
    ))

    assert compiled is not None
    assert compiled[0].intents[0].limit == 7
    assert compiled[0].intents[0].metric_operation == "rank"


def test_kafka_disk_utilization_rejects_consumer_grouping() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", evidence_goal="Read disk utilization by consumer group.",
        metric_request=MetricRequestSemantics(
            signals=["kafka_topic_disk_utilization"],
            target=MetricTargetSemantics(
                scope="kafka_cluster", kind="Kafka",
                namespace="vc-streams", name="vc-cluster",
            ),
            group_by=["consumer_group"],
        ),
    ))

    assert compiled is None


def test_typed_metric_threshold_preserves_grouping_statistic_and_comparator() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Find Pods whose peak CPU exceeded 0.8 cores.",
        metric_request=MetricRequestSemantics(
            signals=["cpu_usage"],
            target=MetricTargetSemantics(
                scope="namespace", kind="Namespace", namespace="payments",
            ),
            operation="threshold",
            statistic="maximum",
            group_by=["pod"],
            threshold_operator="gt",
            threshold_value=0.8,
        ),
    ))

    assert compiled is not None
    intent = compiled[0].intents[0]
    assert intent.metric_operation == "threshold"
    assert intent.metric_statistic == "maximum"
    assert intent.metric_group_by == ["pod"]
    assert intent.threshold_operator == "gt"
    assert intent.threshold_value == 0.8


def test_typed_node_target_maps_generic_cpu_and_memory_to_node_utilization() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        evidence_goal="Show node utilization.",
        metric_request=MetricRequestSemantics(
            signals=["cpu_usage", "memory_working_set"],
            target=MetricTargetSemantics(
                scope="node", kind="Node", name="worker-2",
            ),
        ),
    ))

    assert compiled is not None
    assert [intent.metric for intent in compiled[0].intents] == [
        "node_cpu_utilization", "node_memory_utilization",
    ]


def test_deterministic_metric_summary_combines_signals_and_node_rows() -> None:
    evidence = [
        {
            "id": "metric-cpu", "tool": "query_metrics", "cluster_name": "Central",
            "data": {
                "metric": "node_cpu_utilization", "unit": "percent", "complete": True,
                "ranking": [{
                    "labels": {"nodename": "worker-1"},
                    "current": 41.0, "average": 35.0, "maximum": 62.0,
                }],
            },
        },
        {
            "id": "metric-memory", "tool": "query_metrics", "cluster_name": "Central",
            "data": {
                "metric": "node_memory_utilization", "unit": "percent", "complete": True,
                "ranking": [{
                    "labels": {"nodename": "worker-1"},
                    "current": 73.0, "average": 70.0, "maximum": 75.0,
                }],
            },
        },
    ]
    activity = [{
        "tool": "query_metrics", "status": "succeeded",
        "evidence_ids": ["metric-cpu", "metric-memory"],
    }]

    answer = _deterministic_metric_summary_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert "Node CPU utilization" in answer["content"]
    assert "Node memory utilization" in answer["content"]
    assert "`worker-1`" in answer["content"]
    assert "41.00%" in answer["content"]
    assert answer["citations"] == ["metric-cpu", "metric-memory"]


def test_deterministic_metric_ranking_combines_distinct_registered_rankings() -> None:
    evidence = [
        {
            "id": "top-cpu", "tool": "query_metrics", "cluster_name": "Central",
            "data": {
                "metric": "top_cpu_consumers", "unit": "cores", "complete": True,
                "limit": 5, "ranking": [{
                    "labels": {"namespace": "openshift-ingress", "pod": "router-a"},
                    "current": 0.25, "average": 0.2, "maximum": 0.3,
                }],
            },
        },
        {
            "id": "top-memory", "tool": "query_metrics", "cluster_name": "Central",
            "data": {
                "metric": "top_memory_consumers", "unit": "bytes", "complete": True,
                "limit": 5, "ranking": [{
                    "labels": {"namespace": "openshift-ingress", "pod": "router-a"},
                    "current": 268_435_456, "average": 250_000_000,
                    "maximum": 268_435_456,
                }],
            },
        },
    ]
    activity = [{
        "tool": "query_metrics", "status": "succeeded",
        "evidence_ids": ["top-cpu", "top-memory"],
    }]

    answer = _deterministic_metric_ranking_answer(
        evidence=evidence, activity=activity,
    )

    assert answer is not None
    assert "CPU-consuming pods" in answer["content"]
    assert "memory-consuming pods" in answer["content"]
    assert answer["citations"] == ["top-cpu", "top-memory"]


def test_deterministic_metric_summary_filters_threshold_rows() -> None:
    evidence = [{
        "id": "metric-threshold", "tool": "query_metrics", "cluster_name": "Central",
        "data": {
            "metric": "cpu_usage", "unit": "cores", "complete": True,
            "operation": "threshold", "statistic": "maximum",
            "thresholdOperator": "gt", "thresholdValue": 0.8,
            "ranking": [
                {
                    "labels": {"namespace": "payments", "pod": "hot"},
                    "current": 0.7, "average": 0.6, "maximum": 0.9,
                },
                {
                    "labels": {"namespace": "payments", "pod": "cool"},
                    "current": 0.4, "average": 0.3, "maximum": 0.5,
                },
            ],
        },
    }]
    activity = [{
        "tool": "query_metrics", "status": "succeeded",
        "evidence_ids": ["metric-threshold"],
    }]

    answer = _deterministic_metric_summary_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert "Metric threshold matches" in answer["content"]
    assert "payments/hot" in answer["content"]
    assert "payments/cool" not in answer["content"]


def test_model_metric_semantics_are_not_overridden_by_question_heuristics() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id=f"metric-{intent.metric}",
                tool="query_metrics",
                summary=f"Read {intent.metric} for worker nodes.",
                source=f"thanos:query_range/{intent.metric}",
                collected_at=datetime.now(timezone.utc),
                data={
                    "metric": intent.metric,
                    "scope": intent.metric_scope,
                    "name": intent.name,
                    "unit": "percent",
                    "ranking": [],
                    "series": [],
                    "complete": True,
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy",
        workflow_id="worker-node-utilization",
        question="show me the current cpu/mem utilization for worker nodes in the cluster",
        conversation=[],
        existing_evidence=[],
        # Reproduce the original bad but schema-valid classification.
        inquiry=InquirySemantics(
            mode="metrics", resource_query="Pod", needs_object_details=True,
            evidence_goal="Rank CPU-consuming pods.",
            metric_query="top_cpu_consumers", metric_scope="cluster",
        ),
    ))

    assert [
        (call.metric, call.metric_scope, call.name, call.range_seconds)
        for call in explorer.calls
    ] == [("top_cpu_consumers", "cluster", None, 300)]
    assert {item["data"]["metric"] for item in result.evidence} == {
        "top_cpu_consumers",
    }


def test_model_inventory_semantics_cannot_invoke_removed_list_helper() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "nodes", "apiVersion": "v1", "kind": "Node",
                "namespaced": False, "verbs": ["get", "list"],
            }]

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            assert intent.tool == "list_resources"
            return ReadResult((AdHocObservation(
                id="node-list", tool="list_resources",
                summary="Listed Nodes.", source="kubernetes:v1:Node:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Node", "names": ["worker-1"], "complete": True},
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="cluster-node-ranking",
        question="show me the top 5 cpu consuming nodes on the cluster",
        conversation=[], existing_evidence=[],
        # Reproduce the observed schema-valid inventory classification.
        inquiry=InquirySemantics(
            capability="resource_inventory", mode="inventory", operation="inventory",
            cardinality="collection", resource_query="Node",
            evidence_goal="List Nodes on the cluster.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []


def test_semantic_audit_plan_preserves_model_extracted_values() -> None:
    compiled = _semantic_audit_read_plan(
        InquirySemantics(
            mode="audit",
            needs_object_details=True,
            evidence_goal="List successful changes by the supplied user.",
            result_limit=5,
            audit_username="Druciare-Adm",
            audit_operation_scope="mutations",
            audit_outcome="successful",
            audit_range_seconds=7200,
        ),
        default_limit=20,
        initial_range_seconds=3600,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="query_audit_events",
        audit_username="Druciare-Adm",
        audit_operation_scope="mutations",
        audit_outcome="successful",
        range_seconds=7200,
        limit=5,
    )]


def test_semantic_audit_plan_compiles_missing_username_as_cluster_wide() -> None:
    compiled = _semantic_audit_read_plan(
        InquirySemantics(
            mode="audit",
            needs_object_details=True,
            evidence_goal="List user actions.",
            audit_operation_scope="all",
            audit_outcome="all",
        ),
        default_limit=20,
        initial_range_seconds=3600,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.decision == "collect"
    assert plan.scope_summary == "List the last 20 audit operations across all users."
    assert len(plan.intents) == 1
    assert plan.intents[0].audit_username is None


def test_model_selected_audit_followup_reuses_latest_cluster_wide_query() -> None:
    prior = _latest_audit_query_semantics([{
        "id": "audit-old", "tool": "query_audit_events", "data": {
            "username": None, "namespace": "payments", "operationScope": "deletes",
            "outcomeFilter": "all", "limit": 10, "rangeSeconds": 3600,
        },
    }])

    resolved = _resolve_audit_inquiry(
        question="what about in the last 24hrs",
        inquiry=InquirySemantics(
            mode="audit", operation="audit", needs_object_details=True,
            evidence_goal="Repeat the prior audit query over 24 hours.",
            audit_range_seconds=86_400, continues_prior_audit_query=True,
        ),
        prior_audit_query=prior,
        max_range_seconds=86_400,
    )

    assert resolved is not None
    assert resolved.namespace == "payments"
    assert resolved.audit_username is None
    assert resolved.audit_operation_scope == "deletes"
    assert resolved.result_limit == 10
    assert resolved.audit_range_seconds == 86_400


def test_audit_last_n_starts_bounded_search_and_expands_until_limit() -> None:
    compiled = _semantic_audit_read_plan(
        InquirySemantics(
            mode="audit",
            needs_object_details=True,
            evidence_goal="List the last five actions by the supplied user.",
            result_limit=5,
            audit_username="druciare-adm",
            audit_operation_scope="all",
            audit_outcome="all",
        ),
        default_limit=20,
        initial_range_seconds=3600,
    )

    assert compiled is not None
    intent = compiled[0].intents[0]
    assert intent.range_seconds == 3600
    assert intent.audit_search_until_limit is True


def test_model_selected_duration_followup_inherits_prior_audit_filters() -> None:
    prior = _latest_audit_query_semantics([{
        "id": "audit-old", "tool": "query_audit_events", "data": {
            "username": "druciare-adm", "operationScope": "mutations",
            "outcomeFilter": "successful", "limit": 5, "rangeSeconds": 3600,
        },
    }])

    resolved = _resolve_audit_inquiry(
        question="what about in the last 24hrs",
        inquiry=InquirySemantics(
            mode="audit", operation="audit", needs_object_details=True,
            evidence_goal="Repeat the prior audit query over 24 hours.",
            audit_range_seconds=86_400, continues_prior_audit_query=True,
        ),
        prior_audit_query=prior,
        max_range_seconds=86_400,
    )

    assert resolved is not None
    assert resolved.mode == "audit"
    assert resolved.audit_username == "druciare-adm"
    assert resolved.audit_operation_scope == "mutations"
    assert resolved.audit_outcome == "successful"
    assert resolved.result_limit == 5
    assert resolved.audit_range_seconds == 86_400
    assert resolved.continues_prior_audit_query is True


def test_unrelated_question_does_not_inherit_prior_audit_query() -> None:
    resolved = _resolve_audit_inquiry(
        question="list the cluster nodes",
        inquiry=None,
        prior_audit_query={
            "username": "druciare-adm", "operation_scope": "all",
            "outcome": "all", "limit": 5, "range_seconds": 3600,
        },
        max_range_seconds=86_400,
    )

    assert resolved is None


def test_new_audit_question_does_not_inherit_an_old_audit_target() -> None:
    inquiry = InquirySemantics(
        mode="audit", needs_object_details=True,
        evidence_goal="List actions for a newly supplied user.",
        result_limit=3, audit_username="another-user",
        audit_operation_scope="all", audit_outcome="all",
    )

    resolved = _resolve_audit_inquiry(
        question="show the last 3 actions by another-user",
        inquiry=inquiry,
        prior_audit_query={
            "username": "druciare-adm", "operation_scope": "mutations",
            "outcome": "successful", "limit": 5, "range_seconds": 3600,
        },
        max_range_seconds=86_400,
    )

    assert resolved == inquiry
    assert resolved.audit_range_seconds is None


def test_deterministic_audit_answer_uses_only_current_turn_audit_evidence() -> None:
    evidence = [
        {"id": "old-node", "tool": "list_resources", "summary": "Read Node resources."},
        {
            "id": "audit-current", "tool": "query_audit_events",
            "cluster_name": "Central", "data": {
                "username": "DRUCIARE-ADM", "rangeSeconds": 3600,
                "events": [{
                    "timestamp": "2026-08-27T11:59:00+00:00",
                    "username": "DRUCIARE-ADM", "verb": "patch",
                    "resource": "configmaps", "namespace": "payments",
                    "name": "settings", "responseCode": 200,
                }],
            },
        },
    ]

    answer = _deterministic_audit_answer(
        evidence=evidence,
        activity=[{
            "status": "succeeded", "tool": "query_audit_events",
            "evidence_ids": ["audit-current"],
        }],
    )

    assert answer is not None
    assert answer["citations"] == ["audit-current"]
    assert "configmaps/payments/settings" in answer["content"]
    assert "Node" not in answer["content"]


def test_deterministic_audit_answer_describes_all_user_resource_filter() -> None:
    evidence = [{
        "id": "audit-pods", "tool": "query_audit_events", "cluster_name": "Central",
        "data": {
            "username": None, "resource": "pods", "operationScope": "deletes",
            "rangeSeconds": 3600, "events": [{
                "timestamp": "2026-08-27T11:59:00+00:00", "username": "alice",
                "verb": "delete", "resource": "pods", "namespace": "ai-ops",
                "name": "api-7d9", "responseCode": 200,
            }],
        },
    }]

    answer = _deterministic_audit_answer(
        evidence=evidence,
        activity=[{
            "status": "succeeded", "tool": "query_audit_events",
            "evidence_ids": ["audit-pods"],
        }],
    )

    assert answer is not None
    assert "delete operation(s) on `pods` across all users" in answer["content"]
    assert "the supplied user" not in answer["content"]


def test_semantic_log_volume_plan_uses_registered_cluster_metric() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        resource_query="Namespace",
        needs_object_details=False,
        evidence_goal="Rank namespaces by application-log volume.",
        metric_request=MetricRequestSemantics(
            signals=["application_log_volume"],
            target=MetricTargetSemantics(scope="cluster", kind="Cluster"),
            operation="rank", group_by=["namespace"], result_limit=10,
            range_seconds=300,
        ),
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="query_metrics",
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        metric_operation="rank",
        metric_group_by=["namespace"],
        range_seconds=300,
        limit=10,
    )]


def test_semantic_log_volume_plan_ranks_pods_within_namespace() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", operation="metrics", resource_query="Pod",
        needs_object_details=True,
        evidence_goal="Rank Pods by application-log volume in payments.",
        metric_request=MetricRequestSemantics(
            target=MetricTargetSemantics(
                scope="namespace", kind="Namespace", namespace="payments",
            ),
            signals=["application_log_volume"], operation="rank",
            group_by=["pod"], result_limit=5, range_seconds=300,
        ),
    ))

    assert compiled is not None
    assert compiled[0].intents == [ReadIntent(
        tool="query_metrics", metric="application_log_volume",
        metric_scope="namespace", namespace="payments",
        metric_operation="rank", metric_group_by=["pod"],
        range_seconds=300, limit=5,
    )]


def test_semantic_log_volume_plan_reads_exact_pod_and_node() -> None:
    pod = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", operation="metrics", resource_query="Pod",
        needs_object_details=True, evidence_goal="Read Pod log volume.",
        metric_request=MetricRequestSemantics(
            target=MetricTargetSemantics(
                scope="pod", kind="Pod", namespace="payments", name="api-1",
            ),
            signals=["application_log_volume"], operation="show",
        ),
    ))
    node = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", operation="metrics", resource_query="Node",
        needs_object_details=True, evidence_goal="Read Node log volume.",
        metric_request=MetricRequestSemantics(
            target=MetricTargetSemantics(
                scope="node", kind="Node", name="worker-0",
            ),
            signals=["application_log_volume"], operation="show",
        ),
    ))

    assert pod is not None and pod[0].intents[0].metric_scope == "pod"
    assert pod[0].intents[0].name == "api-1"
    assert node is not None and node[0].intents[0].metric_scope == "node"
    assert node[0].intents[0].name == "worker-0"


def test_metric_period_followup_reuses_prior_log_volume_ranking() -> None:
    prior = _latest_metric_query_semantics([{
        "id": "log-volume-old", "tool": "query_metrics", "data": {
            "metric": "application_log_volume", "scope": "cluster",
            "operation": "rank", "groupBy": ["namespace"],
            "rangeSeconds": 300, "limit": 10,
        },
    }])

    resolved = _resolve_metric_inquiry(
        question="Can you show me the log volume over a 3 day period?",
        inquiry=InquirySemantics(
            mode="metrics", operation="metrics", resource_query="Namespace",
            needs_object_details=True, evidence_goal="Show log volume for three days.",
            metric_request=MetricRequestSemantics(
                target=MetricTargetSemantics(scope="cluster", kind="Cluster"),
                signals=["application_log_volume"], operation="show",
                range_seconds=259_200,
            ),
        ),
        prior_metric_query=prior,
    )

    assert resolved is not None
    assert resolved.metric_request is not None
    assert resolved.metric_request.signals == ["application_log_volume"]
    assert resolved.metric_request.range_seconds == 259_200
    compiled = _semantic_metric_read_plan(resolved)
    assert compiled is not None
    assert compiled[0].intents == [ReadIntent(
        tool="query_metrics", metric="top_log_volume_by_namespace",
        metric_scope="cluster", metric_operation="rank",
        metric_group_by=["namespace"], range_seconds=259_200, limit=10,
    )]


def test_metric_period_followup_reuses_ingress_bandwidth_as_both_directions() -> None:
    prior = _latest_metric_query_semantics([{
        "id": "ingress-out-old", "tool": "query_metrics", "data": {
            "metric": "ingress_bytes_out", "scope": "cluster",
            "operation": "trend", "groupBy": [], "rangeSeconds": 300, "limit": 10,
        },
    }])

    resolved = _resolve_metric_inquiry(
        question="Can you show that over a 3 day period to find a spike?",
        inquiry=None,
        prior_metric_query=prior,
    )

    assert prior is None
    assert resolved is None


def test_metric_period_followup_does_not_reuse_a_different_metric() -> None:
    prior = {
        "metric": "top_cpu_consumers", "scope": "namespace",
        "namespace": "payments", "name": None,
        "range_seconds": 300, "limit": 5,
    }
    inquiry = InquirySemantics(
        mode="metrics", operation="metrics", resource_query="Namespace",
        needs_object_details=True, evidence_goal="Show log volume.",
        metric_request=MetricRequestSemantics(
            signals=["application_log_volume"],
            target=MetricTargetSemantics(scope="cluster", kind="Cluster"),
            range_seconds=259_200,
        ),
    )

    assert _resolve_metric_inquiry(
        question="show log volume over three days",
        inquiry=inquiry,
        prior_metric_query=prior,
    ) == inquiry


def test_log_volume_evidence_view_and_deterministic_answer() -> None:
    evidence = [{
        "id": "log-metric-central", "tool": "query_metrics",
        "cluster_id": "central", "cluster_name": "Central DEV",
        "source": "loki:application/query/application_log_volume",
        "data": {
            "metric": "application_log_volume", "scope": "cluster",
            "groupBy": ["namespace"],
            "unit": "bytes", "limit": 10, "complete": True,
            "rangeSeconds": 3600,
            "ranking": [{
                "labels": {"namespace": "payments"},
                "current": 1048576, "average": 1024, "maximum": None,
            }],
        },
    }]
    activity = [{
        "tool": "query_metrics", "status": "succeeded",
        "evidence_ids": ["log-metric-central"],
    }]

    view = _adhoc_evidence_view(evidence[0])
    answer = _deterministic_metric_ranking_answer(evidence=evidence, activity=activity)

    assert view["metric_ranking"]["namespace_only"] is False
    assert view["metric_ranking"]["rows"][0]["average"] == "1.00 KiB/s"
    assert answer is not None
    assert "application-log volume by target and cluster" in answer["content"]
    assert "1.00 MiB" in answer["content"]
    assert "1.00 KiB/s" in answer["content"]
    assert "not compressed storage consumption" in answer["content"]


def test_deterministic_metric_ranking_renders_clusters_and_no_data() -> None:
    evidence = [
        {
            "id": "metric-central", "tool": "query_metrics",
            "cluster_id": "central", "cluster_name": "Central DEV",
            "data": {
                "metric": "top_cpu_consumers", "scope": "cluster",
                "unit": "cores", "limit": 5, "complete": True,
                "ranking": [{
                    "labels": {"namespace": "payments", "pod": "api-1"},
                    "current": 1.25,
                }],
            },
        },
        {
            "id": "metric-east", "tool": "query_metrics",
            "cluster_id": "east", "cluster_name": "East DEV",
            "data": {
                "metric": "top_cpu_consumers", "scope": "cluster",
                "unit": "cores", "limit": 5, "complete": True,
                "ranking": [],
            },
        },
    ]
    activity = [
        {"tool": "query_metrics", "status": "succeeded", "evidence_ids": ["metric-central"]},
        {"tool": "query_metrics", "status": "succeeded", "evidence_ids": ["metric-east"]},
    ]

    answer = _deterministic_metric_ranking_answer(evidence=evidence, activity=activity)

    assert answer is not None
    assert "top 5 CPU-consuming pods by cluster" in answer["content"]
    assert "Central DEV" in answer["content"]
    assert "`payments`" in answer["content"]
    assert "`api-1`" in answer["content"]
    assert "1.250 cores" in answer["content"]
    assert "East DEV" in answer["content"]
    assert "No finite samples returned" in answer["content"]
    assert answer["citations"] == ["metric-central", "metric-east"]


def test_metric_only_reads_are_recognized_without_model_classification() -> None:
    assert _current_reads_are_metric_rankings([
        {
            "tool": "query_metrics",
            "status": "succeeded",
            "evidence_ids": ["metric-central"],
        },
        {
            "tool": "query_metrics",
            "status": "succeeded",
            "evidence_ids": ["metric-east"],
        },
    ]) is True
    assert _current_reads_are_metric_rankings([
        {
            "tool": "query_metrics",
            "status": "succeeded",
            "evidence_ids": ["metric-central"],
        },
        {
            "tool": "get_resource",
            "status": "succeeded",
            "evidence_ids": ["pod-central"],
        },
    ]) is False
    assert _current_reads_are_metric_rankings([]) is False


@pytest.mark.parametrize(
    ("metric", "unit", "labels"),
    [
        ("node_cpu_utilization", "percent", {"nodename": "worker-1"}),
        ("memory_working_set", "bytes", {"namespace": "apps", "pod": "api-1"}),
        ("persistent_volume_usage", "percent", {"persistentvolumeclaim": "data"}),
        ("kafka_consumer_lag", "messages", {"topic": "orders", "consumergroup": "billing"}),
        ("ingress_request_rate", "requests_per_second", {"route": "store"}),
    ],
)
def test_native_metric_card_is_preferred_for_every_renderable_metric(
    metric: str,
    unit: str,
    labels: dict[str, str],
) -> None:
    evidence = [{
        "id": f"metric-{metric}",
        "tool": "query_metrics",
        "data": {
            "metric": metric,
            "scope": "cluster",
            "unit": unit,
            "complete": True,
            "ranking": [{
                "labels": labels,
                "current": 4.0,
                "average": 3.0,
                "maximum": 5.0,
            }],
        },
    }]
    activity = [{
        "tool": "query_metrics",
        "status": "succeeded",
        "evidence_ids": [f"metric-{metric}"],
    }]

    assert _preferred_metric_evidence_view(
        evidence=evidence,
        activity=activity,
    ) == "metric_ranking"


def test_native_metric_card_is_not_forced_for_empty_or_non_metric_evidence() -> None:
    assert _preferred_metric_evidence_view(
        evidence=[{
            "id": "metric-empty",
            "tool": "query_metrics",
            "data": {"metric": "cpu_usage", "ranking": []},
        }],
        activity=[{
            "tool": "query_metrics",
            "status": "succeeded",
            "evidence_ids": ["metric-empty"],
        }],
    ) is None
    assert _preferred_metric_evidence_view(
        evidence=[{"id": "pod-1", "tool": "get_resource", "data": {}}],
        activity=[{
            "tool": "get_resource",
            "status": "succeeded",
            "evidence_ids": ["pod-1"],
        }],
    ) is None


def test_metric_trend_view_renders_bounded_points_and_peak_timestamp() -> None:
    view = _metric_trend_view({
        "metric": "ingress_bytes_out",
        "scope": "cluster",
        "unit": "bytes_per_second",
        "operation": "trend",
        "rangeSeconds": 259_200,
        "series": [{
            "labels": {},
            "points": [
                {"timestamp": "2026-08-26T12:00:00+00:00", "value": 1024.0},
                {"timestamp": "2026-08-27T12:00:00+00:00", "value": 8192.0},
                {"timestamp": "2026-08-29T12:00:00+00:00", "value": 2048.0},
            ],
        }],
    })

    assert view is not None
    assert view["peak"] == "8.00 KiB/s"
    assert view["peak_at"] == "Aug 27 12:00 UTC"
    assert view["start"] == "Aug 26 12:00 UTC"
    assert view["end"] == "Aug 29 12:00 UTC"
    assert len(view["series"]) == 1
    assert str(view["series"][0]["polyline"]).count(" ") == 2


def test_ingress_bandwidth_semantics_compile_both_directions() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics", operation="metrics", resource_query="Cluster",
        needs_object_details=True, evidence_goal="Show ingress bandwidth for three days.",
        metric_request=MetricRequestSemantics(
            target=MetricTargetSemantics(scope="cluster", kind="Cluster"),
            signals=["ingress_bytes_in", "ingress_bytes_out"],
            operation="trend", range_seconds=259_200,
        ),
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert [(intent.metric, intent.metric_scope, intent.metric_operation) for intent in plan.intents] == [
        ("ingress_bytes_in", "cluster", "trend"),
        ("ingress_bytes_out", "cluster", "trend"),
    ]
    assert all(intent.range_seconds == 259_200 for intent in plan.intents)


def test_explicit_ingress_bandwidth_overrides_loose_classifier_output() -> None:
    resolved = _resolve_metric_inquiry(
        question="Show ingress bandwidth over a 3 day period and identify a spike",
        inquiry=InquirySemantics(
            mode="explain", operation="explain", cardinality="unknown",
            needs_object_details=False, evidence_goal="Explain bandwidth.",
        ),
        prior_metric_query=None,
    )

    assert resolved is not None
    assert resolved.mode == "metrics"
    assert resolved.metric_request is not None
    assert resolved.metric_request.signals == ["ingress_bytes_in", "ingress_bytes_out"]
    assert resolved.metric_request.operation == "trend"
    assert resolved.metric_request.range_seconds == 259_200
    assert resolved.metric_request.target.scope == "cluster"


def test_explicit_router_pod_metrics_compile_native_namespace_reads() -> None:
    resolved = _resolve_metric_inquiry(
        question="show me router pod metrics",
        inquiry=None,
        prior_metric_query=None,
    )

    assert resolved is not None
    assert resolved.mode == "metrics"
    assert resolved.namespace == "openshift-ingress"
    assert resolved.metric_request is not None
    assert resolved.metric_request.signals == ["cpu_usage", "memory_working_set"]
    assert resolved.metric_request.target == MetricTargetSemantics(
        scope="namespace", kind="Namespace", namespace="openshift-ingress",
    )
    assert resolved.metric_request.operation == "rank"
    assert resolved.metric_request.group_by == ["pod"]
    compiled = _semantic_metric_read_plan(resolved)
    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert [(intent.metric, intent.metric_scope) for intent in plan.intents] == [
        ("top_cpu_consumers", "namespace"),
        ("top_memory_consumers", "namespace"),
    ]
    assert all(intent.namespace == "openshift-ingress" for intent in plan.intents)
    assert all(intent.metric_group_by == ["pod"] for intent in plan.intents)


def test_explicit_router_pod_metrics_bypass_model_classifier() -> None:
    class Provider:
        def classify_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("the deterministic router metric route must run first")

    inquiry = asyncio.run(_classify_ad_hoc_inquiry(
        model_provider=Provider(),
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        question="show me router pod metrics",
        conversation=[], cluster_names=["Central"], evidence=[],
    ))

    assert inquiry is not None
    assert inquiry.metric_request is not None
    assert inquiry.metric_request.target.namespace == "openshift-ingress"


def test_router_traffic_question_stays_out_of_pod_resource_override() -> None:
    assert _explicit_router_pod_metric_inquiry(
        "show me router pod traffic metrics"
    ) is None


def test_ask_prefers_metric_card_and_keeps_markdown_as_render_fallback(
    tmp_path: Path,
) -> None:
    conversation_id = "00000000-0000-0000-0000-000000000181"
    evidence_id = "metric-log-volume-1"
    fallback_text = "Fallback metric ranking remains available."
    duplicate_row = "markdown-only-namespace"
    answer = (
        "## Top namespaces\n\n"
        "| Rank | Namespace | Volume |\n|---:|---|---:|\n"
        f"| 1 | {duplicate_row} | 1 MiB |\n\n"
        f"{fallback_text}"
    )
    evidence = [{
        "id": evidence_id,
        "tool": "query_metrics",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "cluster_name": "Runtime cluster",
        "summary": "Ranked namespaces by application-log volume.",
            "source": "loki:application/query/application_log_volume",
            "data": {
                "metric": "application_log_volume",
                "scope": "cluster",
                "groupBy": ["namespace"],
            "unit": "bytes",
            "limit": 10,
            "complete": True,
            "ranking": [{
                "labels": {"namespace": "payments"},
                "current": 1048576,
                "average": 1024,
                "maximum": None,
            }],
        },
    }]
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id,
            created_by="ivy",
            title="Log volume",
            status="active",
            cluster_ids_json=json.dumps([SYSTEM_CLUSTER_ID]),
            evidence_json=json.dumps(evidence),
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000182",
            conversation_id=conversation_id,
            role="assistant",
            actor=None,
            content=answer,
            answer_mode="evidence_based",
            citations_json=json.dumps([evidence_id]),
            tool_activity_json=json.dumps({
                "preferred_evidence_view": "metric_ranking",
            }),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        rendered = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert rendered.status_code == 200
        assert "Observed metric" in rendered.text
        assert (
            "Runtime cluster · Top Application-Log Volume by Namespace"
            in rendered.text
        )
        assert f"{SYSTEM_CLUSTER_ID} · Top Application-Log Volume" not in rendered.text
        assert fallback_text in rendered.text
        assert duplicate_row not in rendered.text
        assert 'class="answer-table-result"' not in rendered.text

        engine = build_engine(settings)
        with Session(engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            evidence[0]["data"]["ranking"] = []
            conversation.evidence_json = json.dumps(evidence)
            db_session.commit()
        engine.dispose()

        fallback = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert fallback.status_code == 200
        assert "Observed metric" not in fallback.text
        assert fallback_text in fallback.text
        assert duplicate_row in fallback.text
        assert 'class="answer-table-result"' in fallback.text


def test_ask_renders_grouped_resource_presentation_without_parsing_prose(
    tmp_path: Path,
) -> None:
    conversation_id = "00000000-0000-0000-0000-000000000191"
    message_id = "00000000-0000-0000-0000-000000000192"
    evidence_id = "resource-list-1"
    presentation = {
        "version": 1,
        "type": "grouped_resource_list",
        "title": "Filtered ConfigMap results",
        "filtered": True,
        "match_field": "data.environment",
        "show_kind": False,
        "total_count": 1,
        "displayed_count": 1,
        "omitted_count": 0,
        "suppress_markdown_table": True,
        "groups": [{
            "cluster_id": "central",
            "cluster_name": "Central <script>alert(1)</script>",
            "evidence_id": evidence_id,
            "kind": "ConfigMap",
            "count": 1,
            "displayed_count": 1,
            "omitted_count": 0,
            "scanned_count": 42,
            "complete": True,
            "match_field": "data.environment",
            "match_operator": "exact",
            "match_value": "production",
            "rows": [{
                "kind": "ConfigMap", "namespace": "platform",
                "name": "feature-flags", "matched_value": "production",
                "ready": "Unknown",
            }],
        }],
    }
    app, settings = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="ConfigMaps", status="active",
            cluster_ids_json=json.dumps([SYSTEM_CLUSTER_ID]),
            evidence_json=json.dumps([{
                "id": evidence_id, "tool": "search_resources",
                "summary": "Found one ConfigMap.", "data": {},
            }]),
        ))
        db_session.add(AdHocMessage(
            id=message_id, conversation_id=conversation_id, role="assistant", actor=None,
            content=(
                "## Legacy inventory\n\n"
                "| Namespace | Matching resource |\n|---|---|\n"
                "| platform | hostless-legacy-row |"
            ),
            answer_mode="evidence_based",
            citations_json=json.dumps([evidence_id]),
            tool_activity_json=json.dumps({"presentation": presentation}),
        ))
        rich_presentation = {
            **presentation,
            "title": "NetworkPolicy results",
            "suppress_markdown_table": False,
        }
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000193",
            conversation_id=conversation_id, role="assistant", actor=None,
            content=(
                "## Interpreted policies\n\n"
                "| Name | Ingress rules | Pod selector |\n|---|---|---|\n"
                "| deny-by-default | Blocks inbound traffic | `{}` |\n\n"
                "The policy effect remains visible."
            ),
            answer_mode="evidence_based",
            citations_json=json.dumps([evidence_id]),
            tool_activity_json=json.dumps({"presentation": rich_presentation}),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        rendered = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"},
        )

    assert rendered.status_code == 200
    assert 'class="resource-result"' in rendered.text
    assert 'class="resource-result-group" open' in rendered.text
    assert "Filtered ConfigMap results" in rendered.text
    assert "data.environment" in rendered.text
    assert "feature-flags" in rendered.text
    assert "Showing 1 of 1 matches" in rendered.text
    assert "Download CSV" in rendered.text
    assert "Rows are rendered from cited, normalized cluster evidence" in rendered.text
    assert "Central &lt;script&gt;alert(1)&lt;/script&gt;" in rendered.text
    assert "Central <script>alert(1)</script>" not in rendered.text
    assert "Legacy inventory" in rendered.text
    assert "hostless-legacy-row" not in rendered.text
    assert 'class="answer-table-result"' in rendered.text
    assert "Dynamic columns parsed from PodPilot’s safe Markdown response" in rendered.text
    assert "Answer-derived" in rendered.text
    assert "Interpreted policies" in rendered.text
    assert "Blocks inbound traffic" in rendered.text
    assert "The policy effect remains visible." in rendered.text


def test_model_targets_must_be_grounded_before_cluster_collection() -> None:
    invented = ReadPlan(
        scope_summary="Inspect a guessed collector.",
        intents=[ReadIntent(
            tool="get_resource", resource="deployments", namespace="telemetry",
            name="opentelemetry-collector-operated",
        )],
    )

    _, errors, _ = _bind_plan_log_intents(
        invented, [], question="Why is telemetry failing?", evidence=[]
    )
    assert errors == [
        "The named resource target was neither supplied by the operator nor present "
        "in collected evidence; discover it with a bounded list first."
    ]

    grounded, errors, _ = _bind_plan_log_intents(
        invented,
        [],
        question="Inspect opentelemetry-collector-operated in telemetry.",
        evidence=[],
    )
    assert errors == []
    assert grounded.intents[0].name == "opentelemetry-collector-operated"


def test_unscoped_exact_read_inherits_namespace_from_bounded_list_scope() -> None:
    plan = ReadPlan(
        scope_summary="Inspect the discovered Kafka resource.",
        intents=[ReadIntent(
            tool="get_resource", resource="kafkas.kafka.strimzi.io",
            api_version="kafka.strimzi.io/v1beta2", kind="Kafka", name="vc-cluster",
        )],
    )
    evidence = [{
        "id": "cluster-kafka-list", "tool": "list_resources",
        "data": {
            "resource": "kafkas.kafka.strimzi.io",
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
            "scope": "vc-streams", "objects": [{"name": "vc-cluster"}],
        },
    }]

    grounded, errors, _ = _bind_plan_log_intents(
        plan, [], question="Does this Kafka cluster export Prometheus metrics?", evidence=evidence,
    )

    assert errors == []
    assert grounded.intents[0].namespace == "vc-streams"


def test_model_authored_get_uses_exact_discovered_api_coordinates() -> None:
    plan = ReadPlan(
        scope_summary="Inspect the discovered Kafka resource.",
        intents=[ReadIntent(
            tool="get_resource", resource="Kafka", api_version="v1", kind="Kafka",
            namespace="vc-streams", name="vc-cluster",
        )],
    )
    evidence = [{
        "id": "cluster-kafka-list", "tool": "list_resources",
        "data": {
            "resource": "kafkas.kafka.strimzi.io",
            "apiVersion": "kafka.strimzi.io/v1", "kind": "Kafka",
            "scope": "vc-streams", "objects": [{"name": "vc-cluster"}],
        },
    }]

    grounded, errors, _ = _bind_plan_log_intents(
        plan, [], question="Does this Kafka cluster export Prometheus metrics?", evidence=evidence,
    )

    assert errors == []
    assert grounded.intents == [ReadIntent(
        tool="get_resource", resource="kafkas.kafka.strimzi.io",
        api_version="kafka.strimzi.io/v1", kind="Kafka",
        namespace="vc-streams", name="vc-cluster",
    )]


def test_ambiguous_unscoped_exact_read_requires_a_grounded_candidate() -> None:
    plan = ReadPlan(
        scope_summary="Inspect the discovered Kafka resource.",
        intents=[ReadIntent(
            tool="get_resource", resource="kafkas.kafka.strimzi.io",
            api_version="kafka.strimzi.io/v1beta2", kind="Kafka", name="shared-cluster",
        )],
    )
    evidence = [{
        "id": "cluster-kafka-list", "tool": "list_resources",
        "data": {
            "resource": "kafkas.kafka.strimzi.io",
            "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka", "scope": "cluster",
            "objects": [
                {"namespace": "payments", "name": "shared-cluster"},
                {"namespace": "orders", "name": "shared-cluster"},
            ],
        },
    }]

    _, errors, _ = _bind_plan_log_intents(
        plan, [], question="Does this Kafka cluster export Prometheus metrics?", evidence=evidence,
    )

    assert errors == [
        "The named resource exists in multiple observed namespaces; select an exact grounded "
        "candidate ID instead of issuing a cluster-scoped GET."
    ]


def test_route_backend_service_reference_grounds_exact_followup_read() -> None:
    followup = ReadPlan(
        scope_summary="Inspect the backend Service selected by the Route.",
        intents=[ReadIntent(
            tool="get_resource", resource="services", api_version="v1", kind="Service",
            namespace="maas", name="model-server",
        )],
    )
    route_evidence = [{
        "id": "cluster-route-1",
        "tool": "search_resources",
        "data": {
            "kind": "Route",
            "items": [{
                "kind": "Route",
                "metadata": {"name": "maas", "namespace": "maas"},
                "spec": {
                    "to": {"kind": "Service", "name": "model-server"},
                    "alternateBackends": [{
                        "kind": "Service", "name": "fallback-server", "weight": 10,
                    }],
                },
            }],
        },
    }]

    grounded, errors, _ = _bind_plan_log_intents(
        followup,
        [],
        question="Why does this Route return an internal server error?",
        evidence=route_evidence,
    )

    assert errors == []
    assert grounded.intents == followup.intents

    alternate = followup.model_copy(update={
        "intents": [followup.intents[0].model_copy(update={"name": "fallback-server"})],
    })
    grounded, errors, _ = _bind_plan_log_intents(
        alternate,
        [],
        question="Why does this Route return an internal server error?",
        evidence=route_evidence,
    )
    assert errors == []
    assert grounded.intents == alternate.intents


@pytest.mark.parametrize(
    ("termination", "expected"),
    [
        ("edge", "forwards unencrypted HTTP"),
        ("reencrypt", "creates a new TLS connection"),
        ("passthrough", "backend must terminate HTTPS/TLS"),
        (None, "routes unsecured HTTP"),
    ],
)
def test_route_tls_behavior_has_evidence_backed_deterministic_answer(
    termination: str | None, expected: str,
) -> None:
    evidence = [{
        "id": "cluster-route-1",
        "tool": "search_resources",
        "data": {
            "kind": "Route",
            "scope": "maas",
            "items": [{
                "kind": "Route",
                "metadata": {"name": "maas", "namespace": "maas"},
                "spec": {
                    "host": "maas.apps.example.test",
                    "to": {"kind": "Service", "name": "model-server"},
                    "port": {"targetPort": "http"},
                    "tls": {"termination": termination},
                },
            }],
        },
    }]
    activity = [{
        "tool": "search_resources",
        "status": "succeeded",
        "evidence_ids": ["cluster-route-1"],
    }]

    answer = _deterministic_route_tls_answer(
        question=(
            "This Route returns an error over HTTPS; does its backend endpoint use HTTP?"
        ),
        evidence=evidence,
        activity=activity,
    )

    assert answer is not None
    assert expected in answer["content"]
    assert "`maas/model-server`" in answer["content"]
    assert answer["citations"] == ["cluster-route-1"]


def test_route_tls_fallback_includes_verified_failure_and_insecure_retry() -> None:
    evidence = [
        {
            "id": "cluster-route-1", "tool": "search_resources",
            "data": {
                "kind": "Route", "scope": "maas", "items": [{
                    "kind": "Route", "metadata": {"name": "maas", "namespace": "maas"},
                    "spec": {
                        "host": "maas.apps.example.test",
                        "to": {"kind": "Service", "name": "model-server"},
                        "tls": {"termination": "passthrough"},
                    },
                }],
            },
        },
        {
            "id": "network-verified", "tool": "http_probe",
            "data": {
                "outcome": "failed", "stage": "tls",
                "logicalHost": "maas.apps.example.test",
                "error": "certificate verify failed: self-signed certificate",
                "tlsVerificationRequested": True,
            },
        },
        {
            "id": "network-insecure", "tool": "http_probe",
            "data": {
                "outcome": "completed", "statusCode": 500,
                "logicalHost": "maas.apps.example.test",
                "tlsVerificationRequested": False,
                "tls": {"verified": False},
            },
        },
    ]
    activity = [
        {"tool": "search_resources", "status": "succeeded", "evidence_ids": ["cluster-route-1"]},
        {"tool": "http_probe", "status": "failed", "evidence_ids": ["network-verified"]},
        {"tool": "http_probe", "status": "succeeded", "evidence_ids": ["network-insecure"]},
    ]

    answer = _deterministic_route_tls_answer(
        question="Why does this Route return HTTP 500 over HTTPS?",
        evidence=evidence, activity=activity,
    )

    assert answer is not None
    assert "Live probe results" in answer["content"]
    assert "could not trust the presented certificate chain" in answer["content"]
    assert "retry without certificate verification returned HTTP `500`" in answer["content"]
    assert answer["citations"] == [
        "cluster-route-1", "network-verified", "network-insecure",
    ]


def test_route_tls_fallback_composes_backend_topology_and_application_response() -> None:
    evidence = [
        {
            "id": "route-1", "tool": "search_resources", "cluster_id": "cluster-a",
            "data": {"kind": "Route", "items": [{
                "metadata": {"name": "gateway", "namespace": "ingress"},
                "spec": {
                    "host": "gateway.example.test",
                    "to": {"kind": "Service", "name": "gateway"},
                    "port": {"targetPort": "https"},
                    "tls": {"termination": "passthrough"},
                },
            }]},
        },
        {
            "id": "service-1", "tool": "get_resource", "cluster_id": "cluster-a",
            "data": {
                "kind": "Service",
                "metadata": {"name": "gateway", "namespace": "ingress"},
                "spec": {"ports": [
                    {"name": "http", "port": 80, "targetPort": 8080},
                    {"name": "https", "port": 443, "targetPort": 8443},
                ]},
            },
        },
        {
            "id": "endpoints-1", "tool": "list_resources", "cluster_id": "cluster-a",
            "data": {"kind": "EndpointSlice", "items": [{
                "metadata": {"labels": {"kubernetes.io/service-name": "gateway"}},
                "ports": [{"name": "https", "port": 8443}],
                "endpoints": [{"targetRef": {"kind": "Pod", "name": "gateway-abc"}}],
            }]},
        },
        {
            "id": "pod-1", "tool": "get_resource", "cluster_id": "cluster-a",
            "data": {
                "kind": "Pod", "metadata": {"name": "gateway-abc", "namespace": "ingress"},
                "spec": {"containers": [{
                    "name": "proxy", "ports": [{"containerPort": 8443}],
                }]},
            },
        },
        {
            "id": "probe-1", "tool": "http_probe", "cluster_id": "cluster-a",
            "data": {
                "logicalHost": "gateway.example.test", "statusCode": 401,
                "tlsVerificationRequested": False, "tls": {"verified": False},
            },
        },
    ]
    activity = [
        {"tool": item["tool"], "status": "succeeded", "evidence_ids": [item["id"]]}
        for item in evidence
    ]

    answer = _deterministic_route_tls_answer(
        question="Does this Route send HTTPS to a plain HTTP backend?",
        evidence=evidence,
        activity=activity,
    )

    assert answer is not None
    assert "Backend topology observed" in answer["content"]
    assert "`https:443 -> 8443`" in answer["content"]
    assert "`https:8443`" in answer["content"]
    assert "Pod `gateway-abc` contains `proxy` (declared ports 8443)" in answer["content"]
    assert "no TLS-capable termination point" in answer["content"]
    assert answer["citations"] == [
        "route-1", "probe-1", "service-1", "endpoints-1", "pod-1",
    ]


def test_direct_model_pod_log_target_requires_collected_candidate() -> None:
    direct = ReadPlan(
        scope_summary="Read a model-authored Pod name.",
        intents=[ReadIntent(
            tool="pod_logs", namespace="payments", name="api-guessed", container="app",
        )],
    )

    _, errors, _ = _bind_plan_log_intents(
        direct, [], question="Check payment logs.", evidence=[]
    )

    assert errors == [
        "Pod logs require an exact candidate from previously collected Pod evidence."
    ]


def test_explicit_inventory_is_rendered_from_evidence_as_a_cited_table() -> None:
    rendered = _deterministic_inventory_answer(
        evidence=[{
            "id": "cluster-pods-1",
            "tool": "list_resources",
            "data": {
                "kind": "Pod",
                "scope": "openshift-logging",
                "names": ["collector-a", "collector-b"],
                "objectListComplete": True,
                "detailsTruncated": True,
            },
        }],
        activity=[{
            "tool": "list_resources",
            "status": "succeeded",
            "evidence_ids": ["cluster-pods-1"],
        }],
    )

    assert rendered is not None
    assert "| 1 | `openshift-logging` | `collector-a` | Unknown |" in str(rendered["content"])
    assert "| 2 | `openshift-logging` | `collector-b` | Unknown |" in str(rendered["content"])
    assert "complete for this snapshot" in str(rendered["content"])
    assert rendered["citations"] == ["cluster-pods-1"]


def test_existence_question_renders_identifiable_multi_cluster_inventory() -> None:
    evidence = [
        {
            "id": "central-kafka", "cluster_id": "central",
            "cluster_name": "Simplii Central DEV", "tool": "list_resources",
            "data": {
                "kind": "Kafka", "scope": "cluster",
                "names": ["orders-kafka"],
                "objects": [{"namespace": "orders", "name": "orders-kafka"}],
                "objectListComplete": True,
            },
        },
        {
            "id": "east-kafka", "cluster_id": "east",
            "cluster_name": "Simplii East DEV", "tool": "list_resources",
            "data": {
                "kind": "Kafka", "scope": "cluster",
                "names": ["events-kafka"],
                "objects": [{"namespace": "events", "name": "events-kafka"}],
                "objectListComplete": True,
            },
        },
    ]
    rendered = _deterministic_inventory_answer(
        question="Which OpenShift clusters have Kafka instances running on them?",
        evidence=evidence,
        activity=[
            {"tool": "list_resources", "status": "succeeded", "evidence_ids": [item["id"]]}
            for item in evidence
        ],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "**Found:** 2 matching resources on 2 of 2 queried OpenShift clusters." in content
    assert "| OpenShift cluster | Kind | Namespace | Matching resource | Ready |" in content
    assert "| `Simplii Central DEV` | `Kafka` | `orders` | `orders-kafka` | Unknown |" in content
    assert "| `Simplii East DEV` | `Kafka` | `events` | `events-kafka` | Unknown |" in content
    assert "must not be interpreted as healthy or unhealthy" in content
    assert rendered["citations"] == ["central-kafka", "east-kafka"]


def test_field_search_renders_only_matching_multi_cluster_resources() -> None:
    evidence = [
        {
            "id": "central-routes", "cluster_id": "central",
            "cluster_name": "CMSP Central DEV", "tool": "search_resources",
            "data": {
                "kind": "Route", "scope": "cluster", "names": ["payments"],
                "objects": [{"namespace": "payments", "name": "payments"}],
                "searchComplete": True, "matchField": "spec.host",
                "matchOperator": "contains", "matchValue": ".az.cibc.com",
            },
        },
        {
            "id": "east-routes", "cluster_id": "east",
            "cluster_name": "CMSP East DEV", "tool": "search_resources",
            "data": {
                "kind": "Route", "scope": "cluster", "names": [], "objects": [],
                "searchComplete": True, "matchField": "spec.host",
                "matchOperator": "contains", "matchValue": ".az.cibc.com",
            },
        },
    ]
    rendered = _deterministic_inventory_answer(
        question='Are there Routes whose hostname contains ".az.cibc.com"?',
        preferred_kind="Route", inventory_only=True, evidence=evidence,
        activity=[
            {"tool": "search_resources", "status": "succeeded", "evidence_ids": [item["id"]]}
            for item in evidence
        ],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "Filtered multi-cluster inventory" in content
    assert "payments" in content
    assert "No matching resources" in content
    assert "1 matching resource on 1 of 2" in content


def test_incomplete_empty_field_search_is_inconclusive() -> None:
    evidence = [{
        "id": "route-search", "tool": "search_resources",
        "data": {
            "kind": "Route", "scope": "cluster", "names": [], "objects": [],
            "searchComplete": False, "truncated": True,
            "matchField": "spec.host", "matchOperator": "contains",
            "matchValue": ".az.cibc.com",
        },
    }]
    rendered = _deterministic_inventory_answer(
        question='Are there Routes whose hostname contains ".az.cibc.com"?',
        preferred_kind="Route", inventory_only=True, evidence=evidence,
        activity=[{
            "tool": "search_resources", "status": "succeeded",
            "evidence_ids": ["route-search"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "result is inconclusive" in content
    assert "No matching resources were returned" not in content
    assert "additional resources were not evaluated" in content


def test_resource_list_presentation_is_generic_and_evidence_derived() -> None:
    evidence = [
        {
            "id": "deployment-list", "cluster_id": "central",
            "cluster_name": "Central", "tool": "list_resources",
            "data": {
                "kind": "Deployment", "scope": "apps", "count": 1,
                "names": ["checkout"],
                "objects": [{"namespace": "apps", "name": "checkout"}],
                "items": [{
                    "apiVersion": "apps/v1", "kind": "Deployment",
                    "metadata": {"namespace": "apps", "name": "checkout"},
                    "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                }],
                "objectListComplete": True,
            },
        },
        {
            "id": "configmap-search", "cluster_id": "east",
            "cluster_name": "East", "tool": "search_resources",
            "data": {
                "kind": "ConfigMap", "scope": "cluster", "count": 1,
                "scannedCount": 87, "names": ["feature-flags"],
                "objects": [{"namespace": "platform", "name": "feature-flags"}],
                "items": [{
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"namespace": "platform", "name": "feature-flags"},
                    "data": {"environment": "production"},
                }],
                "matchField": "data.environment", "matchOperator": "exact",
                "matchValue": "production", "searchComplete": True,
            },
        },
        {
            "id": "uncited-pods", "cluster_id": "east", "tool": "list_resources",
            "data": {"kind": "Pod", "names": ["must-not-render"]},
        },
    ]
    activity = [
        {"tool": item["tool"], "status": "succeeded", "evidence_ids": [item["id"]]}
        for item in evidence
    ]

    presentation = _resource_list_presentation(
        evidence=evidence,
        activity=activity,
        citations=["deployment-list", "configmap-search"],
    )

    assert presentation is not None
    assert presentation["type"] == "grouped_resource_list"
    assert presentation["version"] == 1
    assert presentation["title"] == "Filtered resource results"
    assert presentation["total_count"] == 2
    assert presentation["show_kind"] is True
    assert len(presentation["groups"]) == 2
    assert presentation["groups"][0]["rows"] == [{
        "kind": "Deployment", "namespace": "apps", "name": "checkout",
        "matched_value": "—", "ready": "True",
    }]
    assert presentation["groups"][1]["match_field"] == "data.environment"
    assert presentation["groups"][1]["rows"][0]["matched_value"] == "production"
    assert "must-not-render" not in json.dumps(presentation)


def test_resource_list_presentation_preserves_incomplete_empty_group() -> None:
    presentation = _resource_list_presentation(
        evidence=[{
            "id": "jobs", "cluster_name": "Central", "tool": "search_resources",
            "data": {
                "kind": "Job", "scope": "cluster", "count": 0, "names": [],
                "scannedCount": 500, "searchComplete": False,
                "matchField": "status.failed", "matchOperator": "exact",
                "matchValue": "1",
            },
        }],
        activity=[{
            "tool": "search_resources", "status": "succeeded",
            "evidence_ids": ["jobs"],
        }],
        citations=["jobs"],
    )

    assert presentation is not None
    assert presentation["groups"][0]["complete"] is False
    assert presentation["groups"][0]["rows"] == []
    assert presentation["groups"][0]["scanned_count"] == 500


def test_resource_list_presentation_merges_repeated_cluster_kind_reads() -> None:
    evidence = [
        {
            "id": "central-first", "cluster_id": "central",
            "cluster_name": "CMSP Central DEV", "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder", "scope": "cluster", "count": 1,
                "names": ["instance"],
                "objects": [{"namespace": "openshift-logging", "name": "instance"}],
                "objectListComplete": True,
            },
        },
        {
            "id": "central-repeat", "cluster_id": "central",
            "cluster_name": "CMSP Central DEV", "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder", "scope": "cluster", "count": 2,
                "names": ["instance", "log-forwarder"],
                "objects": [
                    {"namespace": "openshift-logging", "name": "instance"},
                    {"namespace": "asgph-dit", "name": "log-forwarder"},
                ],
                "objectListComplete": True,
            },
        },
        {
            "id": "east-empty", "cluster_id": "east",
            "cluster_name": "CMSP East DEV", "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder", "scope": "cluster", "count": 0,
                "names": [], "objects": [], "objectListComplete": True,
            },
        },
        {
            "id": "east-result", "cluster_id": "east",
            "cluster_name": "CMSP East DEV", "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder", "scope": "cluster", "count": 1,
                "names": ["instance"],
                "objects": [{"namespace": "openshift-logging", "name": "instance"}],
                "objectListComplete": True,
            },
        },
    ]
    presentation = _resource_list_presentation(
        evidence=evidence,
        activity=[
            {"tool": "list_resources", "status": "succeeded", "evidence_ids": [item["id"]]}
            for item in evidence
        ],
        citations=[item["id"] for item in evidence],
    )

    assert presentation is not None
    assert presentation["total_count"] == 3
    assert presentation["displayed_count"] == 3
    assert len(presentation["groups"]) == 2
    central, east = presentation["groups"]
    assert central["cluster_name"] == "CMSP Central DEV"
    assert central["count"] == 2
    assert central["evidence_ids"] == ["central-first", "central-repeat"]
    assert [row["name"] for row in central["rows"]] == ["instance", "log-forwarder"]
    assert east["cluster_name"] == "CMSP East DEV"
    assert east["count"] == 1
    assert east["evidence_ids"] == ["east-empty", "east-result"]
    assert [row["name"] for row in east["rows"]] == ["instance"]


def test_resource_list_presentation_projects_match_values_through_lists() -> None:
    presentation = _resource_list_presentation(
        evidence=[{
            "id": "pods", "tool": "search_resources",
            "data": {
                "kind": "Pod", "scope": "apps", "count": 1, "names": ["api-1"],
                "items": [{
                    "metadata": {"namespace": "apps", "name": "api-1"},
                    "status": {"conditions": [
                        {"type": "Ready", "status": "False"},
                        {"type": "PodScheduled", "status": "True"},
                    ]},
                }],
                "matchField": "status.conditions.type", "matchOperator": "contains",
                "matchValue": "Ready", "searchComplete": True,
            },
        }],
        activity=[{
            "tool": "search_resources", "status": "succeeded", "evidence_ids": ["pods"],
        }],
        citations=["pods"],
    )

    assert presentation is not None
    assert presentation["groups"][0]["rows"][0]["matched_value"] == (
        '["Ready", "PodScheduled"]'
    )
    assert presentation["groups"][0]["rows"][0]["ready"] == "False"


def test_latest_resource_query_recovers_multi_cluster_field_search() -> None:
    evidence = [
        {
            "id": "central-routes", "tool": "search_resources",
            "cluster_id": "central", "cluster_name": "CMSP Central DEV",
            "collected_at": "2026-08-29T20:20:00+00:00",
            "data": {
                "resource": "routes.route.openshift.io",
                "apiVersion": "route.openshift.io/v1", "kind": "Route",
                "scope": "cluster", "names": ["central-route"], "limit": 100,
                "matchField": "spec.host", "matchOperator": "contains",
                "matchValue": ".az.cibc.com", "searchComplete": True,
            },
        },
        {
            "id": "east-routes", "tool": "search_resources",
            "cluster_id": "east", "cluster_name": "CMSP East DEV",
            "collected_at": "2026-08-29T20:20:01+00:00",
            "data": {
                "resource": "routes.route.openshift.io",
                "apiVersion": "route.openshift.io/v1", "kind": "Route",
                "scope": "cluster", "names": ["east-route"], "limit": 100,
                "matchField": "spec.host", "matchOperator": "contains",
                "matchValue": ".az.cibc.com", "searchComplete": True,
            },
        },
    ]

    prior = _latest_resource_query_semantics(evidence)

    assert prior is not None
    assert prior["kind"] == "Route"
    assert prior["resource_filter"] == {
        "field": "spec.host", "operator": "contains", "value": ".az.cibc.com",
    }
    assert prior["evidence_ids"] == ["central-routes", "east-routes"]
    assert prior["cluster_ids"] == ["central", "east"]


def test_resource_followup_inherits_query_but_freshness_requires_new_read() -> None:
    prior = {
        "kind": "Route", "namespace": None, "label_selector": None, "limit": 100,
        "resource_filter": {
            "field": "spec.host", "operator": "contains", "value": ".az.cibc.com",
        },
    }
    presentation_question = "show me the list of these routes from CMSP Central"
    fresh_question = "are these routes still present now in CMSP Central?"

    assert _resource_followup_reuses_snapshot(presentation_question, prior) is True
    assert _resource_followup_reuses_snapshot(fresh_question, prior) is False
    inherited = _resolve_resource_inquiry(
        question=fresh_question, inquiry=None, prior_resource_query=prior,
    )
    assert inherited is not None
    assert inherited.resource_query == "Route"
    assert inherited.resource_filter == ResourceFieldFilterSemantics(
        field="spec.host", operator="contains", value=".az.cibc.com",
    )
    assert inherited.continues_prior_resource_query is True


def test_question_cluster_ids_accepts_only_one_unique_selected_alias() -> None:
    clusters = [
        SimpleNamespace(id="central", name="CMSP Central DEV"),
        SimpleNamespace(id="east", name="CMSP East DEV"),
        SimpleNamespace(id="simplii", name="Simplii Central DEV"),
    ]

    assert _question_cluster_ids(
        "show these routes from the CMSP Central cluster", clusters,
    ) == {"central"}
    assert _question_cluster_ids("show these routes", clusters) == set()
    assert _question_cluster_ids("show these routes from Central", clusters) == set()


def test_reuse_prior_resource_evidence_narrows_to_named_cluster() -> None:
    evidence = [
        {"id": "central", "tool": "search_resources", "cluster_id": "cluster-central"},
        {"id": "east", "tool": "search_resources", "cluster_id": "cluster-east"},
    ]
    selected, activity = _reuse_prior_resource_evidence(
        evidence=evidence,
        prior_resource_query={"evidence_ids": ["central", "east"]},
        cluster_ids={"cluster-central"},
    )

    assert [item["id"] for item in selected] == ["central"]
    assert activity[0]["source"] == "prior_resource_snapshot"
    assert activity[0]["reused_snapshot"] is True


def test_plain_inventory_does_not_answer_field_predicate_question() -> None:
    rendered = _deterministic_inventory_answer(
        question='Are there Routes whose hostname contains ".az.cibc.com"?',
        inventory_only=True,
        evidence=[{
            "id": "route-list", "tool": "list_resources",
            "data": {
                "kind": "Route", "scope": "cluster", "names": ["unfiltered"],
                "objects": [{"namespace": "default", "name": "unfiltered"}],
                "objectListComplete": True,
            },
        }],
        activity=[{
            "tool": "list_resources", "status": "succeeded",
            "evidence_ids": ["route-list"],
        }],
    )

    assert rendered is None


def test_kafka_inventory_omits_unrelated_clusterrole_list_evidence() -> None:
    evidence = [
        {
            "id": "central-kafka", "cluster_id": "central",
            "cluster_name": "Simplii Central DEV", "tool": "list_resources",
            "data": {
                "kind": "Kafka", "scope": "cluster", "names": ["orders-kafka"],
                "objects": [{"namespace": "orders", "name": "orders-kafka"}],
            },
        },
        {
            "id": "east-roles", "cluster_id": "east",
            "cluster_name": "CM APP East DEV", "tool": "list_resources",
            "data": {
                "kind": "ClusterRole", "scope": "cluster",
                "names": ["admin", "aggregate-view"],
                "objects": [{"name": "admin"}, {"name": "aggregate-view"}],
            },
        },
    ]

    rendered = _deterministic_inventory_answer(
        question="List Kafka clusters on each OpenShift cluster.",
        preferred_kind="Kafka",
        inventory_only=True,
        evidence=evidence,
        activity=[
            {"tool": "list_resources", "status": "succeeded", "evidence_ids": [item["id"]]}
            for item in evidence
        ],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "**Found:** 1 matching resource on 1 of 2 queried OpenShift clusters." in content
    assert "orders-kafka" in content
    assert "No compatible requested-kind inventory evidence" in content
    assert "ClusterRole" not in content
    assert "aggregate-view" not in content


def test_kafka_inventory_candidates_do_not_offer_removed_list_helper() -> None:
    candidates = _grounded_read_candidates(
        question="List Kafka clusters on each OpenShift cluster.",
        evidence=[{
            "id": "roles-list", "tool": "list_resources",
            "data": {
                "resource": "clusterroles.rbac.authorization.k8s.io",
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "scope": "cluster", "objects": [{"name": "admin"}],
            },
        }],
        relationship_graph={"nodes": [], "frontier": [], "reverse_frontier": []},
        recovery_anchor_plan=None,
        seen_intents=set(),
        preferred_resource_query="Kafka",
        catalog_entries=[
            {
                "resource": "clusterroles.rbac.authorization.k8s.io",
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "namespaced": False, "verbs": ["get", "list"],
            },
            {
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "namespaced": True, "verbs": ["get", "list"],
            },
        ],
    )

    assert candidates == []


def test_model_authored_inventory_plan_cannot_change_requested_kind() -> None:
    plan = ReadPlan(
        goal_type="inventory",
        scope_summary="List a different catalog resource.",
        intents=[ReadIntent(
            tool="list_resources",
            resource="clusterroles.rbac.authorization.k8s.io",
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRole",
            limit=500,
        )],
    )
    inquiry = InquirySemantics(
        mode="inventory", resource_query="Kafka", needs_object_details=False,
        evidence_goal="List Kafka resources on the selected clusters.",
    )

    assert _inventory_plan_scope_errors(plan, inquiry) == [
        "Inventory read Kind 'ClusterRole' does not match the requested resource Kind 'Kafka'."
    ]


def test_inventory_plan_cannot_drop_or_change_field_predicate() -> None:
    inquiry = InquirySemantics(
        mode="inventory", resource_query="Route", cardinality="collection",
        resource_filter=ResourceFieldFilterSemantics(
            field="spec.host", operator="contains", value=".az.cibc.com",
        ),
        evidence_goal="Find Routes with the supplied hostname suffix.",
    )
    plain_list = ReadPlan(
        goal_type="inventory", scope_summary="List Routes.",
        intents=[ReadIntent(
            tool="list_resources", resource="routes.route.openshift.io",
            api_version="route.openshift.io/v1", kind="Route", limit=500,
        )],
    )
    changed_search = ReadPlan(
        goal_type="inventory", scope_summary="Search Routes.",
        intents=[ReadIntent(
            tool="search_resources", resource="routes.route.openshift.io",
            api_version="route.openshift.io/v1", kind="Route",
            match_field="metadata.name", match_operator="contains",
            match_value=".az.cibc.com", limit=100,
        )],
    )

    assert "dropped" in _inventory_plan_scope_errors(plain_list, inquiry)[0]
    assert "does not preserve" in _inventory_plan_scope_errors(changed_search, inquiry)[0]


def test_inventory_collection_does_not_turn_live_catalog_into_list_execution() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2",
                "kind": "Kafka",
                "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-kafka-list", tool="list_resources",
                summary="Read 1 Kafka resource in cluster.",
                source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Kafka", "scope": "cluster",
                    "names": ["orders-kafka"],
                    "objects": [{"namespace": "orders", "name": "orders-kafka"}],
                    "objectListComplete": True,
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="catalog-kafka-inventory",
        question="Which OpenShift clusters have Kafka instances running on them?",
        conversation=[], existing_evidence=[],
    ))

    assert explorer.calls == []
    assert result.activity == []
    assert result.evidence == []


def test_model_inventory_semantics_do_not_restore_removed_list_helper() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2",
                "kind": "Kafka",
                "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-kafka-list", tool="list_resources",
                summary="Read Kafka resources.",
                source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Kafka", "scope": "cluster", "names": ["orders"]},
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="semantic-kafka-inventory",
        question="Tell me where our streaming installations live.",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="inventory", resource_query="Kafka", needs_object_details=False,
            evidence_goal="Identify Kafka resources by cluster.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []
    rendered = _deterministic_inventory_answer(
        evidence=result.evidence,
        activity=result.activity,
        question="Tell me where our streaming installations live.",
        inventory_only=True,
    )
    assert rendered is None


def test_audit_semantics_execute_only_the_typed_audit_read() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls = []
            self.catalog_calls = 0

        def resource_catalog(self, **_kwargs):
            self.catalog_calls += 1
            raise AssertionError("Audit collection must not discover resource types.")

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="audit-current", tool="query_audit_events",
                summary="Read 1 completed audit event for user Druciare-Adm.",
                source="loki:audit/query/user_actions",
                collected_at=datetime.now(timezone.utc),
                data={"username": "Druciare-Adm", "events": [], "count": 0},
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[], adhoc_audit_default_limit=20,
            adhoc_audit_initial_range_seconds=3600,
        ),
        actor="ivy", workflow_id="semantic-audit",
        question="Show the last 5 successful actions by Druciare-Adm over 2 hours.",
        conversation=[], existing_evidence=[{
            "id": "old-node", "tool": "list_resources", "summary": "Read one Node."
        }],
        inquiry=InquirySemantics(
            mode="audit", needs_object_details=True,
            evidence_goal="List the supplied user's successful API actions.",
            result_limit=5, audit_username="Druciare-Adm",
            audit_operation_scope="all", audit_outcome="successful",
            audit_range_seconds=7200,
        ),
    ))

    assert explorer.catalog_calls == 0
    assert explorer.calls == [ReadIntent(
        tool="query_audit_events", audit_username="Druciare-Adm",
        audit_operation_scope="all", audit_outcome="successful",
        range_seconds=7200, limit=5,
    )]
    assert result.activity[0]["tool"] == "query_audit_events"


def test_semantic_exact_named_resource_compiles_get_through_live_catalog() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="exact_one",
            resource_query="Pod", object_name="api-123", namespace="payments",
            requested_fields=["spec.containers"], needs_object_details=True,
            evidence_goal="Read the configured container images.",
        ),
        resource_catalog=[{
            "resource": "pods", "apiVersion": "v1", "kind": "Pod",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show the image on pod api-123 in namespace payments.",
        conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="get_resource", resource="pods", api_version="v1", kind="Pod",
        namespace="payments", name="api-123",
    )]


def test_generic_named_pod_failure_compiles_exact_get_and_continues_diagnosis() -> None:
    question = (
        'find out why the pod "ids-simplii-66b77b9886-8bd6s" in the '
        '"cah-dev" namespace is NotReady?'
    )
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            capability="cluster_investigation", mode="investigate", operation=None,
            cardinality="exact_one", resource_query="Pod",
            object_name="ids-simplii-66b77b9886-8bd6s", namespace="cah-dev",
            needs_object_details=True,
            evidence_goal="Determine why the exact Pod is NotReady.",
        ),
        resource_catalog=[{
            "resource": "pods", "apiVersion": "v1", "kind": "Pod",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question=question, conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is False
    assert plan.intents == [ReadIntent(
        tool="get_resource", resource="pods", api_version="v1", kind="Pod",
        namespace="cah-dev", name="ids-simplii-66b77b9886-8bd6s",
    )]


def test_named_notready_pod_collects_only_exact_pod_logs_and_events() -> None:
    pod_name = "ids-simplii-66b77b9886-8bd6s"
    question = (
        f'find out why the pod "{pod_name}" in the "cah-dev" namespace is NotReady?'
    )

    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            event_candidate = next((
                item for item in context["read_candidates"]
                if item["capability"] == "cluster_events"
            ), None)
            if event_candidate is not None:
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Read Events involving only the exact NotReady Pod.",
                    candidate_ids=[event_candidate["id"]],
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                stop_reason="evidence_sufficient",
                scope_summary="The exact Pod, container logs, and related Events were read.",
                supporting_evidence_ids=[
                    evidence_id
                    for item in context["observations"]
                    for evidence_id in [item.get("id")]
                    if evidence_id
                ],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "pods", "apiVersion": "v1", "kind": "Pod",
                "namespaced": True, "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            if intent.tool == "get_resource":
                return ReadResult((AdHocObservation(
                    id="exact-pod", tool="get_resource", summary="Read the exact Pod.",
                    source=f"kubernetes:v1:Pod:cah-dev/{pod_name}",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"namespace": "cah-dev", "name": pod_name},
                        "spec": {"containers": [{"name": "ids-simplii"}]},
                        "status": {
                            "phase": "Running",
                            "conditions": [{
                                "type": "Ready", "status": "False",
                                "reason": "ContainersNotReady",
                            }],
                            "containerStatuses": [{
                                "name": "ids-simplii", "ready": False,
                                "restartCount": 0,
                            }],
                        },
                    },
                ),))
            if intent.tool == "pod_logs":
                return ReadResult((AdHocObservation(
                    id="exact-log", tool="pod_logs", summary="Read bounded Pod logs.",
                    source=f"kubernetes:v1:Pod/log:cah-dev/{pod_name}?current",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "container": "ids-simplii", "previous": False,
                        "tail": "Login failed for SQL datasource",
                    },
                ),))
            assert intent.tool == "search_resources"
            return ReadResult((AdHocObservation(
                id="exact-events", tool="search_resources",
                summary="Read Events involving the exact Pod.",
                source="kubernetes:v1:Event:cah-dev/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Event", "scope": "cah-dev", "names": [],
                    "matchField": "involvedObject.name", "matchValue": pod_name,
                    "objectListComplete": True,
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider, cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[], adhoc_inventory_max_objects=500,
        ),
        actor="ivy", workflow_id="named-notready-pod", question=question,
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            capability="cluster_investigation", mode="investigate", operation=None,
            cardinality="exact_one", resource_query="Pod", object_name=pod_name,
            namespace="cah-dev", needs_object_details=True,
            evidence_goal="Determine why the exact Pod is NotReady.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []
    assert provider.contexts[0]["read_candidates"]


def test_named_object_configuration_guidance_compiles_generic_exact_get() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="explain", operation="configuration_guidance", cardinality="exact_one",
            resource_query="Deployment", object_name="checkout", namespace="payments",
            requested_fields=["spec.template.spec.containers"], needs_object_details=True,
            evidence_goal="Explain how to configure the named Deployment.",
        ),
        resource_catalog=[{
            "resource": "deployments", "apiVersion": "apps/v1", "kind": "Deployment",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="How should I configure it?",
        conversation=[{
            "role": "assistant",
            "content": "The Deployment payments/checkout is currently available.",
        }],
        inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is False
    assert plan.goal_type == "explain"
    assert plan.intents == [ReadIntent(
        tool="get_resource", resource="deployments", api_version="apps/v1",
        kind="Deployment", namespace="payments", name="checkout",
    )]


def test_named_configmap_guidance_stops_after_exact_get() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="explain", operation="configuration_guidance", cardinality="exact_one",
            resource_query="ConfigMap", object_name="tm-streams-dev-metrics-config",
            namespace="tm-streams-dev", needs_object_details=True,
            evidence_goal="Show the referenced ConfigMap configuration.",
        ),
        resource_catalog=[{
            "resource": "configmaps", "apiVersion": "v1", "kind": "ConfigMap",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show me that configuration in the ConfigMap.",
        conversation=[{
            "role": "assistant",
            "content": "ConfigMap tm-streams-dev/tm-streams-dev-metrics-config is referenced.",
        }],
        inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.goal_type == "explain"
    assert plan.intents == [ReadIntent(
        tool="get_resource", resource="configmaps", api_version="v1", kind="ConfigMap",
        namespace="tm-streams-dev", name="tm-streams-dev-metrics-config",
    )]


def test_incomplete_inventory_cannot_support_named_object_absence_claim() -> None:
    evidence_id = "cluster-configmaps"
    validated = _validated_adhoc_answer(
        AdHocAnswer(
            answer_mode="evidence_based",
            answer=(
                "None of the returned ConfigMaps is named tm-streams-dev-metrics-config, "
                "so it is not present."
            ),
            cited_evidence_ids=[evidence_id],
        ),
        known_evidence_ids={evidence_id},
        observations=[{
            "id": evidence_id,
            "tool": "list_resources",
            "data": {
                "kind": "ConfigMap", "names": ["one", "two"],
                "objectListComplete": False, "truncated": True,
            },
        }],
    )

    assert validated["answer_mode"] == "evidence_based"
    assert validated["conclusion_status"] == "unresolved"
    assert validated["content"].endswith("so it is not present.")
    assert "incomplete or truncated inventory" in " ".join(validated["limitations"])


def test_configuration_guidance_follows_exact_nested_configmap_reference() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            referenced = next((
                item for item in context.get("read_candidates") or []
                if item.get("relation") == "configures_from"
            ), None)
            if referenced is not None:
                return ReadPlan(
                    goal_type="explain", scope_summary="Read the referenced exporter configuration.",
                    candidate_ids=[referenced["id"]],
                )
            config_id = next((
                item.get("id") for item in context.get("facts") or []
                if "exporter ConfigMap" in str(item.get("summary") or "")
            ), None)
            return ReadPlan(
                goal_type="explain", decision="answer_from_evidence",
                scope_summary="The exact exporter configuration is available.",
                supporting_evidence_ids=[config_id] if config_id else [],
                stop_reason="evidence_sufficient",
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "namespaced": True, "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            if intent.kind == "Kafka":
                return ReadResult((AdHocObservation(
                    id="cluster-kafka", tool="get_resource",
                    summary="Read the exact Kafka resource.",
                    source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:kafka-observability/kafka-observability-cluster",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                        "metadata": {
                            "namespace": "kafka-observability",
                            "name": "kafka-observability-cluster",
                        },
                        "spec": {"kafka": {"metricsConfig": {"valueFrom": {
                            "configMapKeyRef": {
                                "name": "kafka-observability-metrics-config",
                                "key": "metrics-config.yml",
                            },
                        }}}},
                    },
                ),))
            return ReadResult((AdHocObservation(
                id="cluster-exporter-config", tool="get_resource",
                summary="Read the exporter ConfigMap.",
                source="kubernetes:v1:ConfigMap:kafka-observability/kafka-observability-metrics-config",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {
                        "namespace": "kafka-observability",
                        "name": "kafka-observability-metrics-config",
                    },
                    "data": {"metrics-config.yml": "lowercaseOutputName: true"},
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider, cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="config-reference",
        question=(
            "Show the exporter configuration for kafka-observability-cluster "
            "in namespace kafka-observability."
        ),
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="explain", operation="configuration_guidance", cardinality="exact_one",
            resource_query="Kafka", object_name="kafka-observability-cluster",
            namespace="kafka-observability", needs_object_details=True,
            evidence_goal="Read the exact exporter configuration.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []
    assert provider.contexts[0]["read_candidates"]


def test_semantic_named_resource_without_namespace_compiles_grounded_search() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="exact_one",
            resource_query="Deployment", object_name="checkout",
            requested_fields=["status.conditions"], needs_object_details=True,
            evidence_goal="Locate the named Deployment before reading its status.",
        ),
        resource_catalog=[{
            "resource": "deployments", "apiVersion": "apps/v1", "kind": "Deployment",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show deployment checkout status.", conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is False
    assert plan.intents == [ReadIntent(
        tool="search_resources", resource="deployments", api_version="apps/v1",
        kind="Deployment", match_field="metadata.name", match_value="checkout",
        match_operator="exact", limit=5,
    )]


def test_semantic_collection_field_predicate_compiles_bounded_search() -> None:
    question = 'Are there Routes whose hostname field contains ".az.cibc.com"?'
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="inventory", operation="inventory", cardinality="collection",
            resource_query="Route",
            resource_filter=ResourceFieldFilterSemantics(
                field="spec.host", operator="contains", value=".az.cibc.com",
            ),
            evidence_goal="Find Routes with matching hostnames.",
        ),
        resource_catalog=[{
            "resource": "routes.route.openshift.io",
            "apiVersion": "route.openshift.io/v1", "kind": "Route",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question=question, conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="search_resources", resource="routes.route.openshift.io",
        api_version="route.openshift.io/v1", kind="Route",
        match_field="spec.host", match_value=".az.cibc.com",
        match_operator="contains", limit=100,
    )]


def test_uncompiled_field_predicate_cannot_make_plain_inventory_terminal() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="inventory", operation="inventory", cardinality="collection",
            resource_query="Route", evidence_goal="Find matching Route hostnames.",
        ),
        resource_catalog=[{
            "resource": "routes.route.openshift.io",
            "apiVersion": "route.openshift.io/v1", "kind": "Route",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question='Are there Routes whose hostname contains ".az.cibc.com"?',
        conversation=[], inventory_limit=500,
    )

    assert compiled is None


def test_semantic_coordinates_must_be_grounded_in_operator_context() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="exact_one",
            resource_query="Pod", object_name="model-invented-pod",
            requested_fields=["metadata.labels"], needs_object_details=True,
            evidence_goal="Read labels.",
        ),
        resource_catalog=[{
            "resource": "pods", "apiVersion": "v1", "kind": "Pod",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show that Pod's labels.", conversation=[], inventory_limit=500,
    )

    assert compiled is None


def test_semantic_service_account_does_not_resolve_as_service() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="exact_one",
            resource_query="ServiceAccount", object_name="builder", namespace="payments",
            requested_fields=["metadata.annotations"], needs_object_details=True,
            evidence_goal="Read the ServiceAccount metadata.",
        ),
        resource_catalog=[{
            "resource": "services", "apiVersion": "v1", "kind": "Service",
            "namespaced": True, "verbs": ["get", "list"],
        }, {
            "resource": "serviceaccounts", "apiVersion": "v1", "kind": "ServiceAccount",
            "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show annotations on service account builder in namespace payments.",
        conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    assert compiled[0].intents[0].kind == "ServiceAccount"
    assert compiled[0].intents[0].resource == "serviceaccounts"


def test_semantic_event_request_compiles_related_object_search() -> None:
    compiled = _semantic_resource_read_plan(
        InquirySemantics(
            mode="investigate", operation="events", cardinality="collection",
            resource_query="Event", object_name="api-123", namespace="payments",
            result_limit=30, needs_object_details=True,
            evidence_goal="Read recent Events related to the supplied Pod.",
        ),
        resource_catalog=[{
            "resource": "events.events.k8s.io", "apiVersion": "events.k8s.io/v1",
            "kind": "Event", "namespaced": True, "verbs": ["get", "list"],
        }],
        question="Show events for pod api-123 in namespace payments.",
        conversation=[], inventory_limit=500,
    )

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="search_resources", resource="events.events.k8s.io",
        api_version="events.k8s.io/v1", kind="Event", namespace="payments",
        match_field="regarding.name", match_value="api-123", match_operator="exact",
        limit=30,
    )]


def test_exact_node_label_capability_executes_grounded_get() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "nodes.core", "apiVersion": "v1", "kind": "Node",
                "namespaced": False, "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-node-detail", tool="get_resource",
                summary="Read the exact Node.",
                source=f"kubernetes:v1:Node:cluster/{intent.name}",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "v1", "kind": "Node",
                    "metadata": {"name": intent.name, "labels": {"role": "worker"}},
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="exact-node-labels",
        question=(
            'show the labels on the node '
            '"devocp4cmspc-wtlkr-worker-canadacentral1-vk96r"'
        ),
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="investigate", operation="object_fields", cardinality="exact_one",
            resource_query="Node",
            object_name="devocp4cmspc-wtlkr-worker-canadacentral1-vk96r",
            requested_fields=["metadata.labels"], needs_object_details=True,
            evidence_goal="Show the requested Node labels.",
        ),
    ))

    assert explorer.calls == [ReadIntent(
        tool="get_resource", resource="nodes.core", api_version="v1", kind="Node",
        name="devocp4cmspc-wtlkr-worker-canadacentral1-vk96r",
    )]
    assert result.activity[0]["tool"] == "get_resource"
    assert result.evidence[0]["data"]["metadata"]["labels"] == {"role": "worker"}


def test_inventory_details_do_not_offer_catalog_list_candidate() -> None:
    class Provider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            return ReadPlan(
                goal_type="inventory",
                decision="answer_from_evidence",
                scope_summary="The requested inventory has been collected.",
                supporting_evidence_ids=["cluster-kafka-list"],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2",
                "kind": "Kafka",
                "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-kafka-list", tool="list_resources",
                summary="Read Kafka resources.",
                source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Kafka", "scope": "cluster", "names": ["orders"]},
            ),))

    provider = Provider()
    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider, cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="semantic-kafka-detail-inventory",
        question="Show our streaming installations and inspect their details.",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="inventory", resource_query="Kafka", needs_object_details=True,
            evidence_goal="List Kafka resources, then inspect useful object details.",
        ),
    ))

    assert explorer.calls == []
    assert provider.contexts
    assert provider.contexts[0]["completed_reads"] == []
    assert provider.contexts[0]["read_candidates"] == []
    assert result.evidence == []


def test_collection_analysis_does_not_auto_list_or_fan_out_gets() -> None:
    class Provider:
        def plan_ad_hoc(self, _profile, _api_key, context):
            if not context["completed_reads"]:
                return ReadPlan(
                    goal_type="diagnose", decision="collect",
                    scope_summary="List the forwarders before analyzing them.",
                    intents=[ReadIntent(
                        tool="list_resources",
                        resource="clusterlogforwarders.observability.openshift.io",
                        api_version="observability.openshift.io/v1",
                        kind="ClusterLogForwarder", limit=20,
                    )],
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="Every discovered forwarder was inspected.",
                supporting_evidence_ids=[
                    str(item["id"]) for item in context["observations"]
                ],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "clusterlogforwarders.observability.openshift.io",
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder", "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            if intent.tool == "list_resources":
                return ReadResult((AdHocObservation(
                    id="forwarder-inventory", tool="list_resources",
                    summary="Listed ClusterLogForwarders.", source="cluster-api",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "apiVersion": "observability.openshift.io/v1",
                        "kind": "ClusterLogForwarder",
                        "resource": "clusterlogforwarders.observability.openshift.io",
                        "scope": "all-namespaces", "count": 2,
                        "objectListComplete": True,
                        "objects": [
                            {"namespace": "openshift-logging", "name": "instance"},
                            {"namespace": "team-a", "name": "application"},
                        ],
                    },
                ),))
            return ReadResult((AdHocObservation(
                id=f"forwarder-{intent.name}", tool="get_resource",
                summary=f"Read {intent.namespace}/{intent.name}.", source="cluster-api",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "observability.openshift.io/v1",
                    "kind": "ClusterLogForwarder",
                    "metadata": {"namespace": intent.namespace, "name": intent.name},
                    "spec": {"outputs": []}, "status": {"conditions": []},
                },
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[], adhoc_detail_fanout_max_objects=10,
        ),
        actor="ivy", workflow_id="forwarder-analysis",
        question="Analyze every cluster log forwarder and summarize its configuration.",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            mode="investigate", cardinality="collection",
            resource_query="ClusterLogForwarder", needs_object_details=True,
            evidence_goal="Analyze every ClusterLogForwarder configuration.",
        ),
    ))

    assert explorer.calls == []
    assert result.activity == []
    assert result.evidence == []


def test_hybrid_inventory_survives_final_provider_failure_for_novel_wording() -> None:
    collected_at = datetime.now(timezone.utc)
    evidence = [{
        "id": "cluster-kafka-list",
        "tool": "list_resources",
        "summary": "Read Kafka resources.",
        "source": "kubernetes:kafka.strimzi.io/v1beta2:Kafka:cluster/*",
        "collected_at": collected_at,
        "cluster_id": "cluster-a",
        "cluster_name": "Central DEV",
        "data": {
            "kind": "Kafka", "scope": "cluster", "names": ["orders"],
            "objects": [{"namespace": "streaming", "name": "orders"}],
        },
    }]
    activity = [{
        "round": 1, "tool": "list_resources", "status": "succeeded",
        "target": "Kafka inventory", "observations": 1,
        "evidence_ids": ["cluster-kafka-list"],
    }]

    rendered = _deterministic_provider_failure_answer(
        question="Tell me where our streaming installations live.",
        evidence=evidence,
        activity=activity,
        inventory_only=True,
    )

    assert "## Kafka inventory" in str(rendered["content"])
    assert "`streaming`" in str(rendered["content"])
    assert "`orders`" in str(rendered["content"])
    assert "cluster-kafka-list" in rendered["citations"]


def test_inventory_catalog_refresh_does_not_execute_removed_list_helper() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            return _agent_accepts_seeded_evidence(*_args, **_kwargs)

    class Explorer:
        def __init__(self):
            self.catalog_calls = []
            self.calls = []

        def resource_catalog(self, *, query="", limit=120, refresh=False):
            self.catalog_calls.append(refresh)
            if refresh:
                return [{
                    "resource": "widgets.example.io",
                    "apiVersion": "example.io/v1",
                    "kind": "Widget", "namespaced": True,
                    "verbs": ["get", "list"],
                }]
            return [{
                "resource": "namespaces", "apiVersion": "v1",
                "kind": "Namespace", "namespaced": False,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-widget-list", tool="list_resources",
                summary="Read Widget resources.",
                source="kubernetes:example.io/v1:Widget:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Widget", "scope": "cluster", "names": ["sample-widget"]},
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="catalog-widget-miss",
        question="Which Widget instances are running on the OpenShift clusters?",
        conversation=[], existing_evidence=[],
    ))

    assert explorer.catalog_calls == [False]
    assert explorer.calls == []
    assert result.activity == []
    assert result.evidence == []


def test_model_kafka_cluster_alias_is_canonicalized_to_live_kafka_kind() -> None:
    class Provider:
        def plan_ad_hoc(self, _profile, _api_key, context):
            if not context.get("observations"):
                return ReadPlan(
                    scope_summary="Collect the live Kafka resources.",
                    goal_type="inventory",
                    decision="collect",
                    intents=[ReadIntent(
                        tool="list_resources",
                        resource="kafkas.kafka.strimzi.io",
                        api_version="kafka.strimzi.io/v1beta2",
                        kind="Kafka",
                        limit=500,
                    )],
                )
            return _agent_accepts_seeded_evidence(_profile, _api_key, context)

    class Explorer:
        def __init__(self):
            self.calls = []

        def resource_catalog(self, **_kwargs):
            return [{
                "resource": "kafkas.kafka.strimzi.io",
                "apiVersion": "kafka.strimzi.io/v1beta2",
                "kind": "Kafka", "namespaced": True,
                "verbs": ["get", "list"],
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-kafka-list", tool="list_resources",
                summary="Read Kafka resources.",
                source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "Kafka", "scope": "cluster", "names": ["vc-cluster"]},
            ),))

    explorer = Explorer()
    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(), cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="canonical-kafka-inventory",
        question="show me the kafka clusters running on this openshift cluster",
        conversation=[], existing_evidence=[],
        inquiry=InquirySemantics(
            capability="cluster_investigation", mode="investigate", operation="explain",
            cardinality="unknown", resource_query="KafkaCluster",
            needs_object_details=True,
            evidence_goal="Find Kafka clusters.",
        ),
    ))

    assert explorer.calls == []
    assert result.evidence == []


def test_multi_cluster_inventory_distinguishes_catalog_miss_from_zero_objects() -> None:
    evidence = [
        {
            "id": "kafka-zero", "cluster_id": "east", "cluster_name": "East DEV",
            "tool": "list_resources",
            "data": {
                "kind": "Kafka", "scope": "cluster", "names": [],
                "objectListComplete": True,
            },
        },
        {
            "id": "kafka-api-missing", "cluster_id": "remote",
            "cluster_name": "Remote DEV", "tool": "discover_resources",
            "data": {"count": 0, "inventoryMatch": "none"},
        },
    ]
    rendered = _deterministic_inventory_answer(
        question="Which OpenShift clusters have Kafka instances running on them?",
        evidence=evidence,
        activity=[
            {"tool": item["tool"], "status": "succeeded", "evidence_ids": [item["id"]]}
            for item in evidence
        ],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "**Found:** 0 matching resources on 0 of 2 queried OpenShift clusters." in content
    assert "| `East DEV` | `Kafka` | — | _No matching resources_ | Not applicable |" in content
    assert "| `Remote DEV` | — | — | _No matching readable API resource type_ | Not applicable |" in content
    assert rendered["citations"] == ["kafka-zero", "kafka-api-missing"]


def test_configuration_question_does_not_fall_back_to_names_only_inventory() -> None:
    rendered = _deterministic_inventory_answer(
        question="How is the ClusterLogForwarder set up to forward logs?",
        evidence=[{
            "id": "cluster-clf-list", "tool": "list_resources",
            "data": {
                "kind": "ClusterLogForwarder", "scope": "openshift-logging",
                "names": ["instance"], "objectListComplete": True,
            },
        }],
        activity=[{
            "tool": "list_resources", "status": "succeeded",
            "evidence_ids": ["cluster-clf-list"],
        }],
    )

    assert rendered is None


def test_exact_resource_fallback_renders_material_configuration_fields() -> None:
    rendered = _deterministic_resource_detail_answer(
        question="Are the ClusterLogForwarders set up to forward logs to Kafka?",
        evidence=[{
            "id": "cluster-clf-detail",
            "cluster_id": "central",
            "cluster_name": "Central DEV",
            "tool": "get_resource",
            "data": {
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder",
                "metadata": {"namespace": "openshift-logging", "name": "instance"},
                "spec": {
                    "inputs": [{
                        "name": "audit", "type": "application",
                        "application": {"includes": [
                            {"namespace": "payments"}, {"namespace": "orders"},
                        ]},
                    }],
                    "outputs": [{
                        "name": "audit-kafka", "type": "kafka",
                        "kafka": {"url": "tcp://kafka.example.test:9092/audit"},
                    }],
                    "pipelines": [{
                        "name": "audit", "inputRefs": ["audit"],
                        "filterRefs": ["parse-json"], "outputRefs": ["audit-kafka"],
                    }],
                },
                "status": {"outputConditions": [{
                    "type": "ValidOutput-audit-kafka", "status": "True",
                    "message": "output audit-kafka is valid",
                }]},
            },
        }],
        activity=[{
            "tool": "get_resource", "status": "succeeded",
            "evidence_ids": ["cluster-clf-detail"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "Yes. Every inspected cluster has a Kafka output" in content
    assert "Central DEV · `openshift-logging/instance`" in content
    assert "Kafka output `audit-kafka`" in content
    assert "audit-kafka" in content
    assert "kafka.example.test:9092/audit" in content
    assert "Pipeline `audit`" in content
    assert "inputs `audit` → outputs `audit-kafka`" in content
    assert "2 namespace include rules (`payments`, `orders`)" in content
    assert "filters `parse-json`" in content
    assert "ValidOutput-audit-kafka=`True`" in content
    assert "status.outputConditions" not in content
    assert rendered["citations"] == ["cluster-clf-detail"]


def test_exact_configmap_fallback_renders_data_with_an_explicit_limit() -> None:
    rendered = _deterministic_resource_detail_answer(
        question="Show me the exporter ConfigMap.",
        evidence=[{
            "id": "cluster-configmap-detail",
            "cluster_id": "central",
            "cluster_name": "Central DEV",
            "tool": "get_resource",
            "data": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "namespace": "vc-streams",
                    "name": "kafka-metrics",
                },
                "data": {
                    "kafka-metrics-config.yml": (
                        "lowercaseOutputName: true\nrules:\n  - pattern: kafka.server<type=(.+)>"
                    ),
                },
            },
        }],
        activity=[{
            "tool": "get_resource", "status": "succeeded",
            "evidence_ids": ["cluster-configmap-detail"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert content.startswith("## ConfigMap configuration")
    assert "Central DEV · ConfigMap `vc-streams/kafka-metrics`" in content
    assert "#### `kafka-metrics-config.yml`" in content
    assert "lowercaseOutputName: true" in content
    assert "pattern: kafka.server" in content
    assert rendered["citations"] == ["cluster-configmap-detail"]


def test_primary_kafka_target_prevents_supporting_configmap_takeover() -> None:
    rendered = _deterministic_resource_detail_answer(
        question="Show me the Kafka CR configuration that references the ConfigMap.",
        preferred_kind="Kafka",
        evidence=[{
            "id": "cluster-kafka-detail", "tool": "get_resource",
            "data": {
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
                "spec": {"kafka": {"metricsConfig": {"valueFrom": {
                    "configMapKeyRef": {"name": "kafka-metrics", "key": "metrics.yml"},
                }}}},
            },
        }, {
            "id": "cluster-configmap-detail", "tool": "get_resource",
            "data": {
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"namespace": "vc-streams", "name": "kafka-metrics"},
                "data": {"metrics.yml": "rules: []"},
            },
        }],
        activity=[
            {"tool": "get_resource", "status": "succeeded", "evidence_ids": ["cluster-kafka-detail"]},
            {"tool": "get_resource", "status": "succeeded", "evidence_ids": ["cluster-configmap-detail"]},
        ],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert not content.startswith("## ConfigMap configuration")
    assert "Kafka `vc-streams/vc-cluster`" in content
    assert rendered["citations"] == ["cluster-kafka-detail"]


def test_exact_node_label_fallback_renders_metadata_labels() -> None:
    rendered = _deterministic_resource_detail_answer(
        question="Show the labels on the node worker-canadacentral1-vk96r.",
        evidence=[{
            "id": "cluster-node-detail",
            "cluster_id": "central",
            "cluster_name": "Central DEV",
            "tool": "get_resource",
            "data": {
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {
                    "name": "worker-canadacentral1-vk96r",
                    "labels": {
                        "kubernetes.io/hostname": "worker-canadacentral1-vk96r",
                        "node-role.kubernetes.io/worker": "",
                    },
                },
            },
        }],
        activity=[{
            "tool": "get_resource", "status": "succeeded",
            "evidence_ids": ["cluster-node-detail"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "## Exact resource metadata" in content
    assert "#### Labels" in content
    assert "kubernetes.io/hostname" in content
    assert "node-role.kubernetes.io/worker" in content
    assert rendered["citations"] == ["cluster-node-detail"]


def test_dns_resource_fallback_omits_unrelated_node_object_dumps() -> None:
    evidence = [{
        "id": "cluster-dns-detail",
        "cluster_id": "central",
        "cluster_name": "Central DEV",
        "tool": "get_resource",
        "data": {
            "apiVersion": "config.openshift.io/v1",
            "kind": "DNS",
            "metadata": {"name": "cluster"},
            "spec": {
                "baseDomain": "devocp4cmspc.azcanc.cloud.cibc.com",
                "privateZone": {
                    "id": "/subscriptions/example/privateDnsZones/devocp4cmspc.azcanc.cloud.cibc.com"
                },
            },
        },
    }]
    activity = [{
        "tool": "get_resource", "status": "succeeded",
        "evidence_ids": ["cluster-dns-detail"],
    }]
    for index in range(4):
        evidence_id = f"cluster-node-{index}"
        evidence.append({
            "id": evidence_id,
            "cluster_id": "central",
            "cluster_name": "Central DEV",
            "tool": "get_resource",
            "data": {
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {
                    "name": f"worker-{index}",
                    "labels": {"node-role.kubernetes.io/worker": ""},
                    "annotations": {"cloud.network.openshift.io/egress-ipconfig": "node data"},
                },
                "status": {
                    "nodeInfo": {"operatingSystem": "linux", "osImage": "RHCOS"},
                    "images": [{"names": ["registry.example.test/node-helper:latest"]}],
                },
            },
        })
        activity.append({
            "tool": "get_resource", "status": "succeeded", "evidence_ids": [evidence_id],
        })

    rendered = _deterministic_resource_detail_answer(
        question="How does pod and node DNS work on this cluster?",
        evidence=evidence,
        activity=activity,
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "spec.privateZone" in content
    assert "privateDnsZones" in content
    assert "· Node" not in content
    assert "metadata.labels" not in content
    assert "metadata.annotations" not in content
    assert "status.nodeInfo" not in content
    assert "status.images" not in content
    assert rendered["citations"] == ["cluster-dns-detail"]
    assert len(content) < 2_000


def test_kafka_namespace_followup_reuses_prior_evidence_and_honors_named_cluster() -> None:
    def clf_evidence(evidence_id: str, cluster_name: str, namespaces: list[str]) -> dict:
        return {
            "id": evidence_id,
            "cluster_id": cluster_name.casefold().replace(" ", "-"),
            "cluster_name": cluster_name,
            "tool": "get_resource",
            "data": {
                "apiVersion": "observability.openshift.io/v1",
                "kind": "ClusterLogForwarder",
                "metadata": {"namespace": "openshift-logging", "name": "instance"},
                "spec": {
                    "inputs": [{
                        "name": "apps", "type": "application",
                        "application": {
                            "includes": [{"namespace": item} for item in namespaces],
                            "excludes": [{"namespace": "excluded-namespace"}],
                        },
                    }],
                    "outputs": [{
                        "name": "logs-kafka", "type": "kafka",
                        "kafka": {"url": "tls://kafka.example.test:9093"},
                    }],
                    "pipelines": [{
                        "name": "apps-to-kafka", "inputRefs": ["apps"],
                        "outputRefs": ["logs-kafka"],
                    }],
                },
            },
        }

    rendered = _deterministic_resource_detail_answer(
        question="Which namespaces are sending their logs through Kafka on the Central cluster?",
        evidence=[
            clf_evidence("central-clf", "Simplii Central DEV", ["payments", "orders"]),
            clf_evidence("east-clf", "Simplii East DEV", ["shipping"]),
        ],
        # The Central read was cached from the previous turn; only East was read now.
        activity=[{
            "tool": "get_resource", "status": "succeeded", "evidence_ids": ["east-clf"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "Namespaces configured for Kafka forwarding" in content
    assert "Simplii Central DEV" in content
    assert "`payments`" in content
    assert "`orders`" in content
    assert "excluded-namespace" not in content
    assert "Simplii East DEV" not in content
    assert "`shipping`" not in content
    assert "does not prove" in content
    assert rendered["citations"] == ["central-clf"]


def test_inventory_fallback_enumerates_custom_resources_without_question_classification() -> None:
    rendered = _deterministic_inventory_answer(
        evidence=[{
            "id": "cluster-kafka-1",
            "tool": "list_resources",
            "data": {
                "kind": "Kafka",
                "scope": "cluster",
                "names": ["payments-kafka", "observability-kafka"],
                "items": [{
                    "metadata": {"name": "payments-kafka", "namespace": "payments"},
                    "status": {"conditions": [{"type": "Ready", "status": "False"}]},
                }, {
                    "metadata": {
                        "name": "observability-kafka", "namespace": "kafka-observability",
                    },
                    "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                }],
                "objectListComplete": True,
            },
        }],
        activity=[{
            "tool": "list_resources",
            "status": "succeeded",
            "evidence_ids": ["cluster-kafka-1"],
        }],
    )

    assert rendered is not None
    content = str(rendered["content"])
    assert "## Kafka inventory" in content
    assert "| `payments` | `payments-kafka` | False |" in content
    assert "| `kafka-observability` | `observability-kafka` | True |" in content
    assert "complete for this snapshot" in content
    assert rendered["citations"] == ["cluster-kafka-1"]


def test_free_form_diagnostic_cannot_restore_removed_list_helper() -> None:
    class FreeFormPlanner:
        def __init__(self) -> None:
            self.calls = 0

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.calls += 1
            if context["completed_reads"]:
                return ReadPlan(
                    goal_type="explain",
                    decision="answer_from_evidence",
                    scope_summary="The collected topic evidence answers the request.",
                    supporting_evidence_ids=["cluster-topics-1"],
                )
            return ReadPlan(
                goal_type="explain",
                scope_summary="Inspect the installed KafkaTopic resources.",
                intents=[ReadIntent(
                    tool="list_resources",
                    resource="kafkatopics",
                    api_version="kafka.strimzi.io/v1beta2",
                    kind="KafkaTopic",
                    namespace="kafka-observability",
                )],
            )

    class KafkaTopicExplorer:
        def __init__(self) -> None:
            self.calls = []

        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "kafkatopics",
                "apiVersion": "kafka.strimzi.io/v1beta2",
                "kind": "KafkaTopic",
                "namespaced": True,
            }]

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="cluster-topics-1",
                tool="list_resources",
                summary="Read KafkaTopic resources in kafka-observability.",
                source=(
                    "kubernetes:kafka.strimzi.io/v1beta2:KafkaTopic:"
                    "kafka-observability/*"
                ),
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "KafkaTopic",
                    "scope": "kafka-observability",
                    "names": ["audit-events"],
                    "objectListComplete": True,
                },
            ),))

    provider = FreeFormPlanner()
    explorer = KafkaTopicExplorer()
    settings = Settings(
        auth_mode="test",
        role_investigator_groups=[],
        role_approver_groups=[],
        role_breakglass_groups=[],
        adhoc_inventory_max_objects=500,
    )
    question = "Tell me what's going on with the messaging setup over there."

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test",
            base_url="https://models.example.test/v1",
            chat_model="test",
            embedding_model=None,
            timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=settings,
        actor="ivy",
        workflow_id="workflow-kafka-topics",
        question=question,
        conversation=[],
        existing_evidence=[],
    ))

    assert provider.calls == 1
    assert explorer.calls == []
    assert result.evidence == []
    assert any("removed list_resources helper" in item for item in result.limitations)


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
        ask_schemas: bool = True,
    ) -> None:
        self.fail_interpretation = fail_interpretation
        self.fail_chat = fail_chat
        self.chat_answer = chat_answer
        self.ask_schemas = ask_schemas
        self.interpret_calls: list[dict[str, object]] = []
        self.chat_calls: list[dict[str, object]] = []
        self.adhoc_plan_calls: list[dict[str, object]] = []
        self.adhoc_answer_calls: list[dict[str, object]] = []
        self.log_analysis_calls: list[dict[str, object]] = []

    def probe(self, profile, api_key: str) -> CapabilityReport:
        assert api_key == "test-api-token"
        return CapabilityReport(
            reachable=True,
            tls_valid=True,
            authenticated=True,
            model_available=True,
            streaming=True,
            tool_calls=True,
            structured_output=True,
            ask_schemas=self.ask_schemas,
            embeddings=True,
        )

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
        candidates = context.get("read_candidates") or []
        if candidates:
            return ReadPlan(
                scope_summary="Select the registered evidence reads relevant to this request.",
                candidate_ids=[item["id"] for item in candidates[:3]],
            )
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

    def analyze_logs(
        self, profile, api_key: str, context: dict[str, object]
    ) -> AdHocLogAnalysis:
        self.log_analysis_calls.append(context)
        return AdHocLogAnalysis(
            overview="No additional semantic log issue was identified.",
            issues=[],
            limitations=[],
        )


class FailingAdHocProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        raise ModelProviderError(
            "Provider response does not match ReadPlan. "
            "Provider returned content that failed schema validation "
            "(scope_summary: string_too_short)."
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="insufficient_evidence",
            answer="PodPilot could not collect cluster evidence because planning failed.",
            cited_evidence_ids=[],
            limitations=[],
        )


class EmptyFinalAnswerProvider(FakeModelProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        raise ModelProviderError("The provider returned no structured response content.")


class HeadingOnlyThenCompleteProvider(FakeModelProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        evidence_id = context["observations"][-1]["id"]
        if not context.get("answer_feedback"):
            return AdHocAnswer(
                answer_mode="evidence_based",
                answer="### Observed objects — what the cluster is actually doing",
                cited_evidence_ids=[evidence_id],
                limitations=[],
            )
        assert context["answer_feedback"]["reason"] == "heading_only_response"
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer=(
                "### Observed evidence\n\nThe exact Pod remains Pending because its selected "
                "node constraints do not match an available node in the collected Pod status."
            ),
            cited_evidence_ids=[evidence_id],
            limitations=[],
        )


class LateFailingPlanProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if context["investigation_round"] == 1:
            return ReadPlan(
                scope_summary="Inspect the operator-supplied Pod.",
                intents=[ReadIntent(
                    tool="get_resource", resource="pods", namespace="payments", name="api-7d9",
                )],
            )
        raise ModelProviderError(
            "Provider response does not match ReadPlan. Provider returned content that failed schema validation."
        )


class BlockingAdHocProvider(FakeModelProvider):
    def __init__(self) -> None:
        super().__init__()
        self.answer_started = threading.Event()
        self.release_answer = threading.Event()

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.answer_started.set()
        if not self.release_answer.wait(timeout=5):
            raise ModelProviderError("Synthetic background answer timed out.")
        return super().answer_ad_hoc(profile, api_key, context)


class ConcurrentBlockingAdHocProvider(FakeModelProvider):
    def __init__(self) -> None:
        super().__init__()
        self.release_answers = threading.Event()
        self.two_answers_started = threading.Event()
        self._lock = threading.Lock()
        self.active_answers = 0
        self.max_active_answers = 0

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        with self._lock:
            self.active_answers += 1
            self.max_active_answers = max(self.max_active_answers, self.active_answers)
            if self.active_answers >= 2:
                self.two_answers_started.set()
        try:
            if not self.release_answers.wait(timeout=5):
                raise ModelProviderError("Synthetic concurrent answers timed out.")
            return super().answer_ad_hoc(profile, api_key, context)
        finally:
            with self._lock:
                self.active_answers -= 1


class FakeReadExplorer:
    def __init__(self):
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        if intent.tool == "cluster_operator_health_summary":
            return ReadResult((AdHocObservation(
                id="cluster-operators-1",
                tool="cluster_operator_health_summary",
                summary="No ClusterOperator health anomalies detected.",
                source="kubernetes:config.openshift.io/v1:ClusterOperator/health:cluster",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "ClusterOperator", "scope": "cluster",
                    "resourceAvailable": True, "unavailableKinds": [],
                    "scannedCount": 2, "scanComplete": True,
                    "anomalyCount": 0, "returnedAnomalyCount": 0,
                    "anomaliesComplete": True, "anomalies": [], "objects": [],
                },
            ),))
        return ReadResult((AdHocObservation(
            id="cluster-pod-1", tool=intent.tool,
            summary="Read Pod payments/api-7d9.", source="kubernetes:v1:Pod:payments/api-7d9",
            collected_at=datetime.now(timezone.utc),
            data={"spec": {"nodeSelector": {"tier": "missing"}}, "status": {"phase": "Pending"}},
        ),))


class ForbiddenReadExplorer(FakeReadExplorer):
    def execute(self, intent):
        self.calls.append(intent)
        raise ReadOnlyExplorerError(
            "OpenShift RBAC denied the podpilot-investigator ServiceAccount permission "
            "to get pods/log in namespace openshift-kube-apiserver (HTTP 403)."
        )


class RbacAwareAdHocProvider(FakeModelProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="insufficient_evidence",
            answer="The requested API server logs could not be collected.",
            cited_evidence_ids=[],
            limitations=[],
        )


class DiscoveryThenLogsProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        round_number = context["investigation_round"]
        if round_number == 1:
            return ReadPlan(
                scope_summary="Discover kube-apiserver Pods.",
                limitations=["An exact Pod name is needed before logs can be read."],
                intents=[ReadIntent(
                    tool="search_resources", api_version="v1", kind="Pod",
                    namespace="openshift-kube-apiserver", limit=5,
                    match_field="metadata.name", match_value="kube-apiserver",
                    match_operator="contains",
                )],
            )
        if round_number == 2:
            candidates = context["tool_policy"]["pod_log_candidates"]
            assert candidates[0]["pod"] == "kube-apiserver-sno1"
            assert candidates[0]["container"] == "kube-apiserver"
            return ReadPlan(scope_summary="Inspect the discovered kube-apiserver logs.", intents=[ReadIntent(
                tool="pod_logs", candidate_id=candidates[0]["id"],
                namespace="invented", name="not-the-observed-pod", container="wrong-container",
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
        if intent.tool == "search_resources":
            return ReadResult((AdHocObservation(
                id="cluster-pod-search", tool="search_resources",
                summary="Discovered kube-apiserver-sno1.",
                source="kubernetes:v1:Pod:openshift-kube-apiserver/kube-apiserver-sno1",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Pod",
                    "namespace": "openshift-kube-apiserver",
                    "name": "kube-apiserver-sno1",
                    "containers": ["kube-apiserver"],
                    "logCandidates": [{
                        "namespace": "openshift-kube-apiserver",
                        "pod": "kube-apiserver-sno1",
                        "containers": ["kube-apiserver"],
                    }],
                },
            ),))
        return ReadResult((AdHocObservation(
            id="cluster-api-logs", tool="pod_logs", summary="Collected kube-apiserver logs.",
            source="kubernetes:v1:Pod/log:openshift-kube-apiserver/kube-apiserver-sno1",
            collected_at=datetime.now(timezone.utc), data={"tail": "request completed successfully"},
        ),))


class InvalidLogTargetsThenFallbackProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if len([
            item for item in context["observations"] if item["tool"] == "pod_logs"
        ]) >= 3:
            log_ids = [
                item["id"] for item in context["observations"] if item["tool"] == "pod_logs"
            ]
            return ReadPlan(
                goal_type="logs",
                decision="answer_from_evidence",
                scope_summary="The collected kube-apiserver logs answer the question.",
                supporting_evidence_ids=log_ids,
            )
        if context["completed_reads"]:
            return ReadPlan(
                goal_type="logs",
                scope_summary="Read synthesized kube-apiserver targets.",
                intents=[
                    ReadIntent(
                        tool="pod_logs",
                        namespace="openshift-kube-apiserver",
                        name=f"kube-apiserver/cluster-{index}",
                        container="kube-apiserver",
                    )
                    for index in range(3)
                ],
            )
        return ReadPlan(
            goal_type="logs",
            scope_summary="Discover kube-apiserver Pods before reading logs.",
            intents=[ReadIntent(
                tool="search_resources", api_version="v1", kind="Pod",
                namespace="openshift-kube-apiserver", limit=20,
                match_field="metadata.name", match_value="kube-apiserver",
                match_operator="contains",
            )],
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        logs = [item for item in context["observations"] if item["tool"] == "pod_logs"]
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer="PodPilot collected current logs from all three observed kube-apiserver containers.",
            cited_evidence_ids=[item["id"] for item in logs],
            limitations=[],
        )


class ExactCandidateFallbackExplorer:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        if intent.tool == "search_resources":
            return ReadResult((AdHocObservation(
                id="cluster-kube-api-pods",
                tool="search_resources",
                summary="Discovered kube-apiserver Pods.",
                source="kubernetes:v1:Pod:openshift-kube-apiserver/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "scope": "openshift-kube-apiserver",
                    "logCandidates": [
                        {
                            "namespace": "openshift-kube-apiserver",
                            "pod": f"kube-apiserver-master-{index}",
                            "containers": ["kube-apiserver"],
                            "phase": "Running",
                            "ready": True,
                            "restartCount": index,
                        }
                        for index in range(3)
                    ] + [{
                        "namespace": "openshift-kube-apiserver",
                        "pod": "installer-12-master-0",
                        "containers": ["installer"],
                        "phase": "Succeeded",
                        "ready": False,
                        "restartCount": 0,
                    }],
                },
            ),))
        assert intent.candidate_id
        assert intent.name in {
            "kube-apiserver-master-0",
            "kube-apiserver-master-1",
            "kube-apiserver-master-2",
        }
        assert intent.container == "kube-apiserver"
        return ReadResult((AdHocObservation(
            id=f"logs-{intent.name}",
            tool="pod_logs",
            summary=f"Collected logs for {intent.name}.",
            source=(
                "kubernetes:v1:Pod/log:openshift-kube-apiserver/"
                f"{intent.name}?current"
            ),
            collected_at=datetime.now(timezone.utc),
            data={"container": intent.container, "previous": False, "tail": "request completed"},
        ),))


class IncidentJobProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if not context["completed_reads"]:
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Inspect the exact alert-scoped Job.",
                intents=[ReadIntent(
                    tool="search_resources", resource="jobs", api_version="batch/v1",
                    kind="Job", namespace="operators", match_field="metadata.name",
                    match_value="status-check-abc", limit=1,
                )],
            )
        return ReadPlan(
            goal_type="diagnose", decision="answer_from_evidence",
            scope_summary="The alert-scoped Job evidence is available.",
            supporting_evidence_ids=["cluster-job-1"],
        )

    def chat(self, profile, api_key: str, context: dict[str, object]) -> InvestigationChatAnswer:
        self.chat_calls.append(context)
        observations = context["analysis"]["observations"]
        job = next(item for item in observations if item.get("id") == "cluster-job-1")
        assert job["data"]["status"]["failed"] == 1
        return InvestigationChatAnswer(
            answer_mode="evidence_based",
            answer="PodPilot inspected the alert-scoped Job; it has one failed execution.",
            cited_evidence_ids=["cluster-job-1"],
        )


class IncidentJobExplorer:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        return ReadResult((AdHocObservation(
            id="cluster-job-1",
            tool="get_resource",
            summary="Read Job operators/status-check-abc.",
            source="kubernetes:batch/v1:Job:operators/status-check-abc",
            collected_at=datetime.now(timezone.utc),
            data={
                "metadata": {"name": "status-check-abc", "namespace": "operators"},
                "status": {"failed": 1, "conditions": [{"type": "Failed", "reason": "BackoffLimitExceeded"}]},
            },
        ),))


class StorageClassProvider(FakeModelProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        storage = next((
            item for item in context["observations"] if item["id"] == "cluster-sc-1"
        ), None)
        if storage is None:
            return AdHocAnswer(
                answer_mode="insufficient_evidence",
                answer="No StorageClass inventory was collected because the LIST helper is unavailable.",
                cited_evidence_ids=[],
            )
        storage_name = storage["data"]["items"][0]["metadata"]["name"]
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer=f"The cluster exposes the {storage_name} StorageClass.",
            cited_evidence_ids=[storage["id"]],
            limitations=[],
        )


class StorageClassExplorer:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        return ReadResult((AdHocObservation(
            id="cluster-sc-1",
            tool="list_resources",
            summary="Read StorageClass cluster/managed-premium.",
            source="kubernetes:storage.k8s.io/v1:StorageClass:cluster/managed-premium",
            collected_at=datetime.now(timezone.utc),
            data={
                "kind": "StorageClass", "scope": "cluster",
                "names": ["managed-premium"],
                "objects": [{"name": "managed-premium"}],
                "items": [{
                    "metadata": {"name": "managed-premium"},
                    "provisioner": "disk.csi.azure.com",
                }],
                "objectListComplete": True,
            },
        ),))


class RouteBackendProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        completed = context["completed_reads"]
        if not completed:
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Find the Route named by the operator URL.",
                intents=[ReadIntent(
                    tool="search_resources", resource="routes.route.openshift.io",
                    api_version="route.openshift.io/v1", kind="Route",
                    match_field="spec.host", match_value="maas.apps.example.test", limit=5,
                )],
            )
        if not any(item.get("target", "").startswith("services ") for item in completed):
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Inspect the Service referenced by the matched Route.",
                intents=[ReadIntent(
                    tool="get_resource", resource="services", api_version="v1", kind="Service",
                    namespace="maas", name="model-server",
                )],
            )
        if not any(item.get("target", "").startswith("pods ") for item in completed):
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Discover Pods selected by the backend Service.",
                intents=[ReadIntent(
                    tool="list_resources", resource="pods", api_version="v1", kind="Pod",
                    namespace="maas", label_selector="app=model-server", limit=20,
                )],
            )
        if not any(item.get("tool") == "pod_logs" for item in completed):
            candidate = context["tool_policy"]["pod_log_candidates"][0]
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Inspect the selected backend Pod and its application logs.",
                intents=[
                    ReadIntent(tool="pod_logs", candidate_id=candidate["id"]),
                    ReadIntent(
                        tool="get_resource", resource="pods", api_version="v1", kind="Pod",
                        namespace="maas", name="model-server-abc",
                    ),
                    ReadIntent(
                        tool="search_resources", resource="events", api_version="v1", kind="Event",
                        namespace="maas", match_field="involvedObject.name",
                        match_value="model-server-abc", limit=20,
                    ),
                ],
            )
        return ReadPlan(
            goal_type="diagnose",
            decision="answer_from_evidence",
            scope_summary="The Route and Service configuration answer the protocol question.",
            supporting_evidence_ids=["cluster-route-1", "cluster-service-1"],
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="insufficient_evidence",
            answer="The model did not produce a usable evidence-backed interpretation.",
            cited_evidence_ids=[],
            limitations=[],
        )


class HeadingOnlyRouteProvider(RouteBackendProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer="### Observed objects — what the cluster is actually doing",
            cited_evidence_ids=[item["id"] for item in context["observations"]],
            limitations=[],
        )


class NoReadThenHeadingOnlyRouteProvider(HeadingOnlyRouteProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        if not context["completed_reads"]:
            self.adhoc_plan_calls.append(context)
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                scope_summary="Answer without collecting Route evidence.",
            )
        return super().plan_ad_hoc(profile, api_key, context)


class EarlyStoppingRouteProvider(RouteBackendProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        completed = context["completed_reads"]
        if completed and not context.get("planner_feedback"):
            self.adhoc_plan_calls.append(context)
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                scope_summary="Stop after the currently collected evidence.",
                supporting_evidence_ids=["cluster-route-1"],
            )
        return super().plan_ad_hoc(profile, api_key, context)


class StructuredGapRouteProvider(RouteBackendProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        completed = context["completed_reads"]
        observations = context["observations"]
        if not completed and not observations:
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Find the Route named by the URL.",
                intents=[ReadIntent(
                    tool="search_resources", resource="routes.route.openshift.io",
                    api_version="route.openshift.io/v1", kind="Route",
                    match_field="spec.host", match_value="maas.apps.example.test", limit=5,
                )],
            )
        has_service = any(
            item.get("data", {}).get("kind") == "Service" for item in observations
        )
        if context.get("investigation_gaps") and not has_service:
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Resolve the structured Service evidence gap.",
                intents=[ReadIntent(
                    tool="get_resource", resource="services", api_version="v1",
                    kind="Service", namespace="maas", name="model-server",
                )],
            )
        return ReadPlan(
            goal_type="diagnose",
            decision="answer_from_evidence",
            scope_summary="Answer from the evidence currently available.",
            supporting_evidence_ids=[str(item["id"]) for item in observations],
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        has_service = any(
            item.get("data", {}).get("kind") == "Service"
            for item in context["observations"]
        )
        if not has_service:
            return AdHocAnswer(
                answer_mode="evidence_based",
                conclusion_status="probable",
                answer=(
                    "The Route uses passthrough TLS, but the backend Service mapping is not "
                    "collected yet."
                ),
                cited_evidence_ids=["cluster-route-1"],
                investigation_gaps=[InvestigationGap(
                    question="Does the referenced Service expose the expected HTTPS target port?",
                    capability="service_spec",
                    priority="high",
                    supporting_evidence_ids=["cluster-route-1"],
                )],
            )
        return AdHocAnswer(
            answer_mode="evidence_based",
            conclusion_status="confirmed",
            answer=(
                "The Route uses passthrough TLS and the collected Service maps its `https` port "
                "to the backend Pods."
            ),
            cited_evidence_ids=["cluster-route-1", "cluster-service-1"],
        )


class EmbeddedGapRouteProvider(StructuredGapRouteProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        has_service = any(
            item.get("data", {}).get("kind") == "Service"
            for item in context["observations"]
        )
        if not has_service:
            return AdHocAnswer(
                answer_mode="evidence_based",
                conclusion_status="probable",
                answer=(
                    "## What the Route tells us\n\nThe Route uses TLS passthrough.\n\n"
                    "## Recommended next evidence collections | Priority | Evidence needed | "
                    "Why it matters | | High | service_spec | Verify the Service targetPort |\n\n"
                    "## Investigation gaps ```json [{\"investigation_gaps\": []}] ```"
                ),
                cited_evidence_ids=["cluster-route-1"],
                investigation_gaps=[],
                recommended_next_checks=[],
            )
        return AdHocAnswer(
            answer_mode="evidence_based",
            conclusion_status="confirmed",
            answer=(
                "The Route uses passthrough TLS and the collected Service maps its `https` "
                "port to the backend Pods."
            ),
            cited_evidence_ids=["cluster-route-1", "cluster-service-1"],
        )


class CandidateSelectingRouteProvider(RouteBackendProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        candidates = context["read_candidates"]
        completed = context["completed_reads"]
        if not completed:
            candidate = next(
                item for item in candidates if item["capability"] == "initial_discovery"
            )
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Select the exact Route discovery candidate.",
                candidate_ids=[candidate["id"]],
            )
        has_service = any(
            item.get("data", {}).get("kind") == "Service"
            for item in context["observations"]
        )
        if not has_service:
            candidate = next(
                item for item in candidates if item["capability"] == "service_spec"
            )
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Select the grounded backend Service candidate.",
                candidate_ids=[candidate["id"]],
            )
        return ReadPlan(
            goal_type="diagnose",
            decision="answer_from_evidence",
            stop_reason="evidence_sufficient",
            scope_summary="The Route and backend Service evidence answer the protocol question.",
            supporting_evidence_ids=["cluster-route-1", "cluster-service-1"],
        )


class UnknownCandidateRouteProvider(RouteBackendProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        return ReadPlan(
            goal_type="diagnose",
            scope_summary="Select a candidate that was not supplied.",
            candidate_ids=["read-ffffffffffffffffffff"],
        )


class GapStoppingCandidateProvider(StructuredGapRouteProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if not context["completed_reads"] and not context["observations"]:
            candidate = next(
                item for item in context["read_candidates"]
                if item["capability"] == "initial_discovery"
            )
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Select the exact Route discovery candidate.",
                candidate_ids=[candidate["id"]],
            )
        return ReadPlan(
            goal_type="diagnose",
            decision="answer_from_evidence",
            stop_reason="no_material_read",
            scope_summary="Stop despite the remaining grounded evidence gap.",
            supporting_evidence_ids=["cluster-route-1"],
        )


class EmptyInvestigateRouteProvider(CandidateSelectingRouteProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if not context["completed_reads"]:
            candidate = next(
                item for item in context["read_candidates"]
                if item["capability"] == "initial_discovery"
            )
            return ReadPlan(
                goal_type="diagnose",
                scope_summary="Select the exact Route discovery candidate.",
                candidate_ids=[candidate["id"]],
            )
        plan = ReadPlan(
            goal_type="diagnose",
            decision="collect",
            scope_summary="Continue investigating the supplied evidence actions.",
            intents=[],
        )
        plan._selection_incomplete = True
        return plan


class RouteOnlyAnswerProvider(RouteBackendProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer=(
                "The Route uses TLS passthrough, so the router forwards the client TLS stream "
                "to the backend without terminating it."
            ),
            cited_evidence_ids=["cluster-route-1"],
            limitations=[],
        )

    def analyze_logs(
        self, profile, api_key: str, context: dict[str, object]
    ) -> AdHocLogAnalysis:
        self.log_analysis_calls.append(context)
        return AdHocLogAnalysis(
            overview="The backend excerpt contains a certificate-loading failure.",
            issues=[LogAnalysisIssue(
                evidence_ids=["cluster-backend-logs"],
                severity="error",
                category="certificate loading",
                summary="The backend process could not load its configured PEM certificate.",
                potential_impact="The backend TLS listener may fail to initialize.",
                supporting_excerpt="FileNotFoundError: [Errno 2] No such file or directory",
                confidence="high",
            )],
            limitations=["Only a bounded log tail was analyzed."],
        )


class FailingTrafficPlanProvider(RouteBackendProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        raise ModelProviderError(
            "Provider response does not match ReadPlan. Provider returned content that failed "
            "schema validation (intents.0: value_error)."
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="insufficient_evidence",
            answer="The planner could not produce a safe typed read plan for this investigation.",
            cited_evidence_ids=[],
            limitations=["No cluster reads were attempted after the invalid plan."],
        )


class RouteBackendExplorer:
    def __init__(
        self,
        log_tail: str = "ERROR upstream model request returned HTTP 500",
        route_termination: str = "edge",
    ) -> None:
        self.calls = []
        self.log_tail = log_tail
        self.route_termination = route_termination

    def execute(self, intent):
        self.calls.append(intent)
        if intent.tool == "search_resources" and intent.kind == "Route":
            return ReadResult((AdHocObservation(
                id="cluster-route-1",
                tool="search_resources",
                summary="Found the matching OpenShift Route.",
                source="kubernetes:route.openshift.io/v1:Route:maas/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Route",
                    "scope": "cluster",
                    "items": [{
                        "kind": "Route",
                        "metadata": {"name": "maas", "namespace": "maas"},
                        "spec": {
                            "host": "maas.apps.example.test",
                            "to": {"kind": "Service", "name": "model-server"},
                            "port": {"targetPort": (
                                "https" if self.route_termination == "passthrough" else "http"
                            )},
                            "tls": {"termination": self.route_termination},
                        },
                    }],
                },
            ),))
        if intent.tool == "get_resource" and intent.kind == "Service":
            return ReadResult((AdHocObservation(
                id="cluster-service-1",
                tool="get_resource",
                summary="Read the Route backend Service.",
                source="kubernetes:v1:Service:maas/model-server",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Service",
                    "metadata": {"name": "model-server", "namespace": "maas"},
                    "spec": {
                        "selector": {"app": "model-server"},
                        "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
                    },
                },
            ),))
        if intent.tool == "list_resources" and intent.kind == "Pod":
            return ReadResult((AdHocObservation(
                id="cluster-backend-pods",
                tool="list_resources",
                summary="Read one backend Pod selected by the Service.",
                source="kubernetes:v1:Pod:maas/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Pod", "scope": "maas",
                    "logCandidates": [{
                        "namespace": "maas", "pod": "model-server-abc",
                        "containers": ["server"], "phase": "Running",
                        "ready": True, "restartCount": 0,
                    }],
                },
            ),))
        if intent.tool == "list_resources" and intent.kind == "EndpointSlice":
            return ReadResult((AdHocObservation(
                id="cluster-backend-slices", tool="list_resources",
                summary="Read one EndpointSlice for the backend Service.",
                source="kubernetes:discovery.k8s.io/v1:EndpointSlice:maas/*",
                collected_at=datetime.now(timezone.utc),
                data={"kind": "EndpointSlice", "items": []},
            ),))
        if intent.tool == "get_resource" and intent.kind == "Endpoints":
            return ReadResult((AdHocObservation(
                id="cluster-backend-endpoints", tool="get_resource",
                summary="Read the legacy Endpoints for the backend Service.",
                source="kubernetes:v1:Endpoints:maas/model-server",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Endpoints",
                    "metadata": {"name": "model-server", "namespace": "maas"},
                    "podTargets": [],
                },
            ),))
        if intent.tool == "get_resource" and intent.kind == "Pod":
            return ReadResult((AdHocObservation(
                id="cluster-backend-pod", tool="get_resource",
                summary="Read the exact backend Pod.",
                source="kubernetes:v1:Pod:maas/model-server-abc",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Pod",
                    "metadata": {"name": "model-server-abc", "namespace": "maas"},
                    "spec": {"containers": [{"name": "server"}]},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{
                            "name": "server", "ready": True, "restartCount": 0,
                        }],
                    },
                },
            ),))
        if intent.tool == "search_resources" and intent.kind == "Event":
            return ReadResult((AdHocObservation(
                id="cluster-backend-events", tool="search_resources",
                summary="No Events matched the backend Pod.",
                source="kubernetes:v1:Event:maas/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Event", "scope": "maas", "items": [],
                    "matchField": "involvedObject.name", "matchValue": "model-server-abc",
                },
            ),), ("No Event resources matched the bounded query.",))
        if intent.tool == "http_probe":
            return ReadResult((AdHocObservation(
                id="cluster-route-probe", tool="http_probe",
                summary="The Route endpoint completed TLS and returned HTTP 500.",
                source="http:https://maas.apps.example.test/v1/models",
                collected_at=datetime.now(timezone.utc),
                data={
                    "logicalHost": "maas.apps.example.test",
                    "statusCode": 500,
                    "tlsVerificationRequested": True,
                    "tls": {"verified": True, "version": "TLSv1.3"},
                },
            ),))
        assert intent.tool == "pod_logs"
        return ReadResult((AdHocObservation(
            id="cluster-backend-logs", tool="pod_logs",
            summary="Collected bounded logs from the backend application container.",
            source="kubernetes:v1:Pod/log:maas/model-server-abc?current",
            collected_at=datetime.now(timezone.utc),
            data={
                "container": "server", "previous": False,
                "tail": self.log_tail,
            },
        ),))


class NamespaceMetricProvider(FakeModelProvider):
    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        metric = next(item for item in context["observations"] if item["id"] == "metric-cpu-1")
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer="The collector Pod is the largest observed CPU consumer in the namespace.",
            cited_evidence_ids=[metric["id"]],
            limitations=[],
        )


class NamespaceMetricExplorer:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, intent):
        self.calls.append(intent)
        return ReadResult((AdHocObservation(
            id="metric-cpu-1",
            tool="query_metrics",
            summary="Ranked CPU consumers in namespace openshift-logging.",
            source="thanos:query_range/top_cpu_consumers",
            collected_at=datetime.now(timezone.utc),
            data={
                "metric": "top_cpu_consumers",
                "scope": "namespace",
                "namespace": "openshift-logging",
                "unit": "cores",
                "ranking": [{
                    "labels": {
                        "namespace": "openshift-logging",
                        "pod": "collector-1",
                        "container": "collector",
                    },
                    "current": 0.9,
                    "average": 0.7,
                    "maximum": 1.0,
                }],
                "complete": True,
            },
        ),))


class ImpliedHealthProvider(FakeModelProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        if context.get("completed_reads"):
            return ReadPlan(
                goal_type="health",
                decision="answer_from_evidence",
                scope_summary="The ClusterOperator evidence is sufficient.",
                supporting_evidence_ids=["cluster-operators-1"],
            )
        if context.get("planner_feedback"):
            return ReadPlan(
                goal_type="health",
                decision="collect",
                scope_summary="Read current ClusterOperator conditions.",
                intents=[ReadIntent(
                    tool="list_resources",
                    resource="clusteroperators",
                    limit=250,
                )],
            )
        return ReadPlan(
            goal_type="health",
            decision="answer_from_evidence",
            scope_summary="Assess ClusterOperator health.",
        )

    def answer_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> AdHocAnswer:
        self.adhoc_answer_calls.append(context)
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer="All observed ClusterOperators are Available and none are Degraded.",
            cited_evidence_ids=["cluster-operators-1"],
            limitations=[],
        )


class ClusterOperatorExplorer:
    def __init__(self) -> None:
        self.calls = []

    def resource_catalog(self, *, query: str = "", limit: int = 120):
        return [{
            "resource": "clusteroperators",
            "apiVersion": "config.openshift.io/v1",
            "kind": "ClusterOperator",
            "namespaced": False,
        }]

    def execute(self, intent):
        self.calls.append(intent)
        return ReadResult((AdHocObservation(
            id="cluster-operators-1",
            tool="list_resources",
            summary="Read current ClusterOperator conditions.",
            source="kubernetes:config.openshift.io/v1:ClusterOperator:cluster/*",
            collected_at=datetime.now(timezone.utc),
            data={
                "kind": "ClusterOperator",
                "scope": "cluster",
                "names": ["authentication", "console"],
                "objectListComplete": True,
                "detailsTruncated": False,
                "items": [{
                    "metadata": {"name": "authentication"},
                    "status": {"conditions": [
                        {"type": "Available", "status": "True"},
                        {"type": "Degraded", "status": "False"},
                    ]},
                }],
            },
        ),))


class RefusingCatalogProvider(ImpliedHealthProvider):
    def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
        self.adhoc_plan_calls.append(context)
        return ReadPlan(
            goal_type="health",
            decision="needs_clarification",
            scope_summary="Ask the operator for a specific resource name.",
            clarification="Provide a ClusterOperator name.",
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


def job_failed() -> AlertRecord:
    return AlertRecord(
        fingerprint="job-failed-1",
        state="active",
        labels={
            "alertname": "KubeJobFailed",
            "severity": "warning",
            "namespace": "operators",
            "job_name": "status-check-abc",
        },
        annotations={"summary": "A Kubernetes Job failed"},
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


class StaticCapabilityRoleResolver(StaticRoleResolver):
    def __init__(
        self,
        assignments: dict[str, Role],
        configuration_admins: set[str],
    ) -> None:
        super().__init__(assignments)
        self._configuration_admins = configuration_admins

    def can_manage(self, username: str) -> bool:
        return username in self._configuration_admins


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
    cluster_credential_store: MemoryCredentialStore | None = None,
    remote_read_explorer_factory=None,
    agent_runner=None,
    settings_overrides: dict[str, object] | None = None,
    configuration_admins: set[str] | None = None,
):
    test_settings = {"adhoc_job_worker_enabled": False}
    test_settings.update(settings_overrides or {})
    settings = Settings(
        environment="test",
        cluster_name="test-cluster",
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'podpilot.db'}",
        web_dir=ROOT / "apps" / "web",
        auth_mode="test",
        poc_mode=True,
        **test_settings,
    )
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    role_resolver = (
        StaticCapabilityRoleResolver(assignments, configuration_admins)
        if configuration_admins is not None
        else StaticRoleResolver(assignments)
    )
    return (
        create_app(
            settings,
            role_resolver,
            source,
            workload_source,
            credential_store or MemoryCredentialStore(),
            model_provider or FakeModelProvider(),
            remediation_executor or FakeRemediationExecutor(),
            diagnostic_executor or FakeDiagnosticExecutor(),
            read_explorer or FakeReadExplorer(),
            cluster_credential_store,
            remote_read_explorer_factory,
            agent_runner,
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
        assert "bounded, read-only cluster investigation" in response.text
        assert "PodPilot 0.12.0" in response.text
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
        assert "The agent cannot change the cluster selection" in page.text
        assert '<section class="notice"' not in page.text
        assert "Read-only cluster assistant" not in page.text
        assert 'class="panel-header ask-session-header"' in page.text
        assert 'class="boundary-pill caution-summary"' in page.text
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
        assert "Evidence used in this answer" in rendered.text
        assert rendered.text.index('class="boundary-pill caution-summary"') < rendered.text.index(
            "data-evidence-open"
        )
        assert "Inspected 1 cluster target" not in rendered.text
        assert "cluster-pod-1" in rendered.text
        assert '<details class="raw-model-response">' not in rendered.text

    assert len(explorer.calls) == 1
    assert explorer.calls[0].tool == "get_resource"
    assert provider.adhoc_plan_calls[0]["tool_policy"]["logs_and_configmaps_allowed"] is True
    assert provider.adhoc_answer_calls[0]["observations"][0]["id"] == "cluster-pod-1"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.scalar(select(func.count()).select_from(AdHocConversation)) == 1
        assert db_session.scalar(select(func.count()).select_from(AdHocMessage)) == 2
        run = db_session.scalar(select(AdHocRun))
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert run is not None and run.include_raw_response is False
        assert assistant is not None and json.loads(assistant.raw_responses_json) == []
        actions = list(db_session.scalars(select(AuditEvent.action)))
        assert "adhoc.message" in actions and "adhoc.answer" in actions
    engine.dispose()


def test_unrestricted_agent_executes_chat_completion_tool_calls_through_runner(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.agent_messages: list[list[dict[str, object]]] = []
            self.finalization_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, profile, api_key, messages):
            assert profile.api_type == "chat-completions"
            assert api_key == "test-api-token"
            self.agent_messages.append(list(messages))
            if len(self.agent_messages) == 1:
                return AgentStep(
                    assistant_message={
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "execute_shell",
                                "arguments": json.dumps({
                                    "command": "oc auth can-i patch deployments --all-namespaces"
                                }),
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="call-1",
                        name="execute_shell",
                        arguments=json.dumps({
                            "command": "oc auth can-i patch deployments --all-namespaces"
                        }),
                    ),),
                )
            if len(self.agent_messages) == 2:
                return AgentStep(
                    assistant_message={"role": "assistant", "content": None},
                    content=None,
                    tool_calls=(),
                )

        def finalize_agent_step(self, profile, api_key, messages):
            assert profile.api_type == "chat-completions"
            assert api_key == "test-api-token"
            self.finalization_messages.append(list(messages))
            return AgentStep(
                assistant_message={"role": "assistant", "content": "RBAC denied the mutation."},
                content="RBAC denied the mutation.",
                tool_calls=(),
            )

    class Runner:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def execute(self, command: str, connection=None, **_kwargs) -> AgentCommandResult:
            assert connection is None
            self.commands.append(command)
            return AgentCommandResult(
                command=command,
                exit_code=1,
                stdout="no\n",
                stderr="",
            )

    provider = Provider()
    runner = Runner()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        agent_runner=runner,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1,
            provider_label="OpenRouter",
            base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b",
            api_type="chat-completions",
            embedding_model=None,
            timeout_seconds=240,
            max_output_tokens=4096,
            status="ready",
            capabilities_json='{"tool_calls": true}',
            updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert 'class="boundary-pill caution-summary agent-mode-pill"' in page.text
        assert "Session cautions" in page.text
        assert "Unrestricted lab mode" in page.text
        assert "Delegated session ended" not in page.text
        assert 'data-starter-available="true"' in page.text
        composer = re.search(r'<textarea id="adhoc-message"[^>]*>', page.text)
        assert composer is not None
        assert "disabled" not in composer.group(0)
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Try to patch a deployment."},
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"}
        )
        assert "RBAC denied the mutation" in rendered.text

    assert runner.commands == ["oc auth can-i patch deployments --all-namespaces"]
    system_prompt = str(provider.agent_messages[0][0]["content"])
    assert "`oc logs` with `--tail=200 --timestamps`" in system_prompt
    assert "Never fetch unbounded Pod logs by default" in system_prompt
    assert "Use only the tools supplied in this request" in system_prompt
    assert "empty label-filtered workload query proves only" in system_prompt
    assert "inspect the exact discovered custom resource and its status" in system_prompt
    assert "Markdown table with a header row" in system_prompt
    tool_message = provider.agent_messages[1][-1]
    assert tool_message["role"] == "tool"
    assert '"exit_code": 1' in str(tool_message["content"])
    assert len(provider.agent_messages) == 2
    assert len(provider.finalization_messages) == 1
    retry_message = provider.finalization_messages[0][-1]
    assert retry_message["role"] == "user"
    assert "return a concise final answer now" in str(retry_message["content"])
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(AdHocMessage.role == "assistant"))
        assert assistant is not None
        activity = json.loads(assistant.tool_activity_json)
        assert activity["agent_mode"] == "unrestricted"
        assert activity["reads"][0]["status"] == "failed"
        audits = list(db_session.scalars(select(AuditEvent.action)))
        assert "agentic.command" in audits
    engine.dispose()


@pytest.mark.parametrize("second_finalization_is_valid", [True, False])
def test_unrestricted_agent_rejects_tool_arguments_returned_as_final_content(
    tmp_path: Path, second_finalization_is_valid: bool,
) -> None:
    raw_arguments = json.dumps({
        "cluster_id": SYSTEM_CLUSTER_ID,
        "command": "oc get pods -n openshift-logging -o name",
    })

    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.agent_calls = 0
            self.finalization_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, _profile, _api_key, _messages):
            self.agent_calls += 1
            if self.agent_calls == 1:
                return AgentStep(
                    assistant_message={
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "pods", "type": "function",
                            "function": {
                                "name": "execute_shell", "arguments": raw_arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="pods", name="execute_shell", arguments=raw_arguments,
                    ),),
                )
            return AgentStep(
                assistant_message={"role": "assistant", "content": None},
                content=None,
                tool_calls=(),
            )

        def finalize_agent_step(self, _profile, _api_key, messages):
            self.finalization_messages.append(list(messages))
            if len(self.finalization_messages) == 1 or not second_finalization_is_valid:
                return _agent_final_step(raw_arguments)
            return _agent_final_step(
                "No Loki Pods were returned from the openshift-logging namespace."
            )

    class Runner:
        def execute(self, command: str, connection=None, **_kwargs) -> AgentCommandResult:
            assert command == "oc get pods -n openshift-logging -o name"
            assert connection is None
            return AgentCommandResult(command=command, exit_code=0, stdout="", stderr="")

    provider = Provider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        agent_runner=Runner(),
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1,
            provider_label="OpenRouter",
            base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b",
            api_type="chat-completions",
            embedding_model=None,
            timeout_seconds=240,
            max_output_tokens=4096,
            status="ready",
            capabilities_json='{"tool_calls": true}',
            updated_by="ivy",
        ))
        db_session.commit()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Is the Loki stack healthy?"},
            follow_redirects=False,
        )
        client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert provider.agent_calls == 2
    assert len(provider.finalization_messages) == 2
    assert "Do not return JSON tool arguments" in str(
        provider.finalization_messages[1][-1]["content"]
    )
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert assistant is not None
        expected_content = (
            "No Loki Pods were returned from the openshift-logging namespace."
            if second_finalization_is_valid else
            "PodPilot completed the bounded cluster reads, but the model did not return "
            "a usable operator-facing conclusion. The rejected model output was not "
            "displayed, and no additional cluster operation was attempted."
        )
        assert assistant.content == expected_content
        assert raw_arguments not in assistant.content
        activity = json.loads(assistant.tool_activity_json)
        assert bool(activity["limitations"]) is (not second_finalization_is_valid)
    engine.dispose()


def test_agent_rejects_malformed_calls_with_retry_guidance_and_collapsed_diagnostics(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, _profile, _api_key, messages):
            self.agent_messages.append(list(messages))
            step = len(self.agent_messages)
            if step == 1:
                arguments = json.dumps({
                    "cluster_id": SYSTEM_CLUSTER_ID,
                    "resource": "clusterlogforwarders",
                    "api_version": "observability.openshift.io/v1",
                    "kind": "ClusterLogForwarder",
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "bad-search", "type": "function",
                            "function": {
                                "name": "search_resources", "arguments": arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="bad-search", name="search_resources", arguments=arguments,
                    ),),
                )
            if step == 2:
                arguments = json.dumps({
                    "cluster_id": f"{SYSTEM_CLUSTER_ID},another-cluster",
                    "command": "oc get clusterlogforwarders -A -o json",
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "bad-cluster", "type": "function",
                            "function": {
                                "name": "execute_shell", "arguments": arguments,
                            },
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="bad-cluster", name="execute_shell", arguments=arguments,
                    ),),
                )
            return _agent_final_step(
                "The malformed calls were rejected before any cluster request was executed."
            )

    class Runner:
        def execute(self, *_args, **_kwargs):
            raise AssertionError("Malformed shell arguments must not reach the runner.")

    provider = Provider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        agent_runner=Runner(),
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1,
            provider_label="OpenRouter",
            base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b",
            api_type="chat-completions",
            embedding_model=None,
            timeout_seconds=240,
            max_output_tokens=4096,
            status="ready",
            capabilities_json='{"tool_calls": true}',
            updated_by="ivy",
        ))
        db_session.commit()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Compare ClusterLogForwarders."},
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"}
        )

    assert '<details class="answer-diagnostics">' in rendered.text
    assert "2 rejected attempts" in rendered.text
    assert '<ul class="answer-limitations">' not in rendered.text
    assert "Cluster unknown" not in rendered.text
    search_feedback = json.loads(str(provider.agent_messages[1][-1]["content"]))
    assert "Correct the arguments using the tool schema" in search_feedback["retry_guidance"]
    command_feedback = json.loads(str(provider.agent_messages[2][-1]["content"]))
    assert "exactly one cluster_id" in command_feedback["retry_guidance"]
    assert SYSTEM_CLUSTER_ID in command_feedback["retry_guidance"]

    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert assistant is not None
        activity = json.loads(assistant.tool_activity_json)
        assert activity["limitations"] == []
        assert len(activity["diagnostics"]) == 2
        assert [item["status"] for item in activity["reads"]] == ["invalid", "invalid"]
    engine.dispose()


def test_unrestricted_agent_is_not_forced_through_registered_log_volume_enrichment(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, profile, api_key, messages):
            self.agent_messages.append(list(messages))
            return _agent_final_step("The collected evidence ranks payments first.")

    class LogVolumeExplorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id=f"log-volume-enrichment-{len(self.calls)}",
                tool="query_metrics",
                summary="Ranked namespaces by application-log payload volume.",
                source="loki:application/query/application_log_volume",
                collected_at=datetime.now(timezone.utc),
                data={
                    "metric": "application_log_volume",
                    "scope": "cluster",
                    "groupBy": ["namespace"],
                    "unit": "bytes",
                    "averageUnit": "bytes_per_second",
                    "rangeSeconds": intent.range_seconds,
                    "limit": intent.limit,
                    "complete": True,
                    "ranking": [{
                        "labels": {"namespace": "payments"},
                        "current": 4096,
                        "average": 13.6533333333,
                        "maximum": None,
                    }],
                },
            ),))

    provider = Provider()
    explorer = LogVolumeExplorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1,
            provider_label="OpenRouter",
            base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b",
            api_type="chat-completions",
            embedding_model=None,
            timeout_seconds=240,
            max_output_tokens=4096,
            status="ready",
            capabilities_json='{"tool_calls": true}',
            updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()


    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": "which namespaces produce the most amount of logs over the last week?"
            },
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"}
        )
        assert "Loki-backed namespace log-volume ranking" not in rendered.text
        assert "The collected evidence ranks payments first" in rendered.text
        assert "Kubernetes events" not in rendered.text
        assert rendered.text.count("<table") == 0
        conversation_id = created.headers["location"].rsplit("/", 1)[-1]
        continued = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Can you show me the log volume over a 3 day period?"},
            follow_redirects=False,
        )
        followup = client.get(
            continued.headers["location"], headers={"x-forwarded-user": "ivy"},
        )
        assert "The collected evidence ranks payments first" in followup.text
        assert "pods/exec" not in followup.text
        assert "logcli" not in followup.text

    assert explorer.calls == []
    assert len(provider.agent_messages) == 2
    engine = build_engine(settings)
    with Session(engine) as db_session:
        conversation = db_session.scalar(select(AdHocConversation))
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert conversation is not None
        evidence_items = json.loads(conversation.evidence_json)
        assert evidence_items == []
        assert assistant is not None
        assert assistant.answer_mode == "general_guidance"
        activity = json.loads(assistant.tool_activity_json)
        assert activity["reads"] == []
        assert activity["preferred_evidence_view"] is None
    engine.dispose()


def test_unrestricted_pending_pod_question_is_driven_by_agent_without_collector_seed(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.steps = 0

        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(
                mode="investigate", cardinality="exact_one", resource_query="Pod",
                object_name="logging-loki-ingester-1", namespace="openshift-logging",
                evidence_goal="Investigate why the exact Pod is Pending.",
            )

        def next_agent_step(self, *_args, **_kwargs):
            if self.steps == 0:
                self.steps += 1
                arguments = json.dumps({
                    "command": (
                        "oc get events -n openshift-logging "
                        "--field-selector involvedObject.name=logging-loki-ingester-1"
                    ),
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant", "content": None,
                        "tool_calls": [{
                            "id": "pending-events", "type": "function",
                            "function": {"name": "execute_shell", "arguments": arguments},
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id="pending-events", name="execute_shell", arguments=arguments,
                    ),),
                )
            return AgentStep(
                assistant_message={
                    "role": "assistant",
                    "content": "The scheduler event identifies an unbound PVC as the cause.",
                },
                content="The scheduler event identifies an unbound PVC as the cause.",
                tool_calls=(),
            )

    class PodExplorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "pods", "apiVersion": "v1", "kind": "Pod",
                "namespaced": True, "verbs": ["get", "list"],
            }]

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="pending-pod", tool="get_resource", summary="Read the Pending Pod.",
                source="kubernetes:v1:Pod:openshift-logging/logging-loki-ingester-1",
                collected_at=datetime.now(timezone.utc),
                data={
                    "apiVersion": "v1", "kind": "Pod", "resource": "pods",
                    "metadata": {
                        "namespace": "openshift-logging",
                        "name": "logging-loki-ingester-1",
                    },
                    "spec": {"volumes": [{"name": "storage"}]},
                    "status": {"phase": "Pending"},
                },
            ),))

    class Runner:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def execute(self, command, connection=None, **_kwargs):
            self.commands.append(command)
            return AgentCommandResult(
                command=command, exit_code=0,
                stdout="0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims\n",
                stderr="",
            )

    provider = Provider()
    explorer = PodExplorer()
    runner = Runner()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
        agent_runner=runner,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": (
                    "why is pod logging-loki-ingester-1 in namespace "
                    "openshift-logging Pending?"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert explorer.calls == []
    assert len(runner.commands) == 1
    assert "get events" in runner.commands[0]
    assert "unbound PVC" in rendered.text
    assert "Question-focused resource evidence" not in rendered.text


def test_unrestricted_typed_collectors_return_to_agent_without_terminating(
    tmp_path: Path,
) -> None:
    calls = [
        (
            "pod_health_summary",
            {
                "cluster_id": SYSTEM_CLUSTER_ID,
                "namespace": "openshift-logging",
                "label_selector": "app.kubernetes.io/name=loki",
                "limit": 100,
            },
        ),
        (
            "http_probe",
            {
                "cluster_id": SYSTEM_CLUSTER_ID,
                "url": "https://checkout.az.cibc.com/health",
                "connect_host": "10.0.0.10",
                "method": "GET",
                "tls_verify": True,
            },
        ),
        (
            "query_audit_events",
            {
                "cluster_id": SYSTEM_CLUSTER_ID,
                "namespace": "ai-ops",
                "audit_username": "druciare-adm",
                "audit_operation_scope": "delete",
                "audit_outcome": "any",
                "range_seconds": 3600,
                "limit": 5,
            },
        ),
        (
            "query_metrics",
            {
                "cluster_id": SYSTEM_CLUSTER_ID,
                "metric": "cpu_usage",
                "metric_scope": "namespace",
                "namespace": "ai-ops",
                "range_seconds": 900,
                "limit": 5,
            },
        ),
    ]

    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.index = 0
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, profile, api_key, messages):
            self.agent_messages.append(list(messages))
            if self.index >= len(calls):
                return _agent_final_step(
                    "I interpreted the filtered routes, audit activity, and metrics together."
                )
            name, arguments = calls[self.index]
            self.index += 1
            call_id = f"typed-{self.index}"
            encoded = json.dumps(arguments)
            return AgentStep(
                assistant_message={
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": call_id, "type": "function",
                        "function": {"name": name, "arguments": encoded},
                    }],
                },
                content=None,
                tool_calls=(AgentToolCall(
                    id=call_id, name=name, arguments=encoded,
                ),),
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            data: dict[str, object]
            if intent.tool == "pod_health_summary":
                data = {
                    "healthSummaryVersion": 1,
                    "scope": intent.namespace,
                    "labelSelector": intent.label_selector,
                    "scannedCount": 12,
                    "scanComplete": True,
                    "anomalyCount": 0,
                    "returnedAnomalyCount": 0,
                    "anomaliesComplete": True,
                    "byReason": {},
                    "bySeverity": {},
                    "anomalies": [],
                    "objects": [],
                }
            elif intent.tool == "http_probe":
                data = {
                    "url": intent.url, "connectHost": intent.connect_host,
                    "method": intent.method, "outcome": "succeeded",
                    "statusCode": 200, "tlsVerificationRequested": intent.tls_verify,
                    "tls": {"verified": True, "version": "TLSv1.3"},
                }
            elif intent.tool == "query_audit_events":
                data = {
                    "namespace": intent.namespace, "username": intent.audit_username,
                    "operationScope": intent.audit_operation_scope,
                    "outcome": intent.audit_outcome, "count": 1, "complete": True,
                    "events": [{
                        "timestamp": "2026-08-29T12:00:00Z",
                        "username": "druciare-adm", "verb": "delete",
                        "resource": "pods", "namespace": "ai-ops", "responseCode": 200,
                    }],
                }
            else:
                data = {
                    "metric": intent.metric, "scope": intent.metric_scope,
                    "namespace": intent.namespace, "unit": "cores", "complete": True,
                    "ranking": [{
                        "labels": {"namespace": "ai-ops"},
                        "current": 0.5, "average": 0.4, "maximum": 0.6,
                    }],
                }
            return ReadResult((AdHocObservation(
                id=f"typed-{intent.tool}", tool=intent.tool,
                summary=f"Collected {intent.tool} evidence.",
                source=f"test:{intent.tool}", collected_at=datetime.now(timezone.utc),
                data=data,
            ),))

    provider = Provider()
    explorer = Explorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider, read_explorer=explorer,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Investigate the filtered routes, audit activity, and metrics."},
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert [intent.tool for intent in explorer.calls] == [
        "pod_health_summary", "http_probe", "query_audit_events", "query_metrics",
    ]
    health_intent = next(
        intent for intent in explorer.calls if intent.tool == "pod_health_summary"
    )
    assert health_intent.namespace == "openshift-logging"
    assert health_intent.label_selector == "app.kubernetes.io/name=loki"
    audit_intent = next(
        intent for intent in explorer.calls if intent.tool == "query_audit_events"
    )
    assert audit_intent.audit_operation_scope == "deletes"
    assert audit_intent.audit_outcome == "all"
    metric_intent = next(
        intent for intent in explorer.calls if intent.tool == "query_metrics"
    )
    assert metric_intent.range_seconds == 300
    assert len(provider.agent_messages) == 5
    assert "app.kubernetes.io/name=loki" in json.dumps(provider.agent_messages[1])
    assert "TLSv1.3" in json.dumps(provider.agent_messages[2])
    assert "druciare-adm" in json.dumps(provider.agent_messages[3])
    assert "cpu_usage" in json.dumps(provider.agent_messages[4])
    assert "completion does not mean the investigation is complete" in json.dumps(
        provider.agent_messages[1]
    )
    assert "interpreted the filtered routes" in rendered.text
    engine = build_engine(settings)
    with Session(engine) as db_session:
        conversation = db_session.scalar(select(AdHocConversation))
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert conversation is not None
        assert len(json.loads(conversation.evidence_json)) == 4
        assert assistant is not None
        assert assistant.answer_mode == "evidence_based"
        assert len(json.loads(assistant.citations_json)) == 4
    engine.dispose()


def test_unrestricted_broad_pod_health_uses_complete_typed_scan_conclusion(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.steps = 0
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, profile, api_key, messages):
            self.agent_messages.append(list(messages))
            if self.steps:
                return _agent_final_step(
                    "All 75 Pods are healthy based on the inventory table."
                )
            self.steps += 1
            arguments = json.dumps({
                "cluster_id": SYSTEM_CLUSTER_ID,
                "namespace": "openshift-logging",
                "label_selector": "app.kubernetes.io/name=loki",
                "limit": 100,
            })
            return AgentStep(
                assistant_message={
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": "loki-health", "type": "function",
                        "function": {
                            "name": "pod_health_summary", "arguments": arguments,
                        },
                    }],
                },
                content=None,
                tool_calls=(AgentToolCall(
                    id="loki-health", name="pod_health_summary", arguments=arguments,
                ),),
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id="loki-health-complete", tool="pod_health_summary",
                summary="Detected no Pod health anomalies after evaluating 14 Loki Pods.",
                source="kubernetes:v1:Pod/health:openshift-logging",
                collected_at=datetime.now(timezone.utc),
                data={
                    "healthSummaryVersion": 1,
                    "scope": "openshift-logging matching label selector app.kubernetes.io/name=loki",
                    "labelSelector": "app.kubernetes.io/name=loki",
                    "scannedCount": 14,
                    "scanLimit": 500,
                    "scanComplete": True,
                    "anomalyCount": 0,
                    "returnedAnomalyCount": 0,
                    "anomaliesComplete": True,
                    "byReason": {}, "bySeverity": {}, "anomalies": [], "objects": [],
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider, read_explorer=explorer,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Are all the Loki Pods in openshift-logging running healthy?"},
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert len(explorer.calls) == 1
    assert explorer.calls[0].tool == "pod_health_summary"
    assert explorer.calls[0].label_selector == "app.kubernetes.io/name=loki"
    tool_payload = json.loads(str(provider.agent_messages[1][-1]["content"]))
    assert tool_payload["observations"][0]["data"]["scanComplete"] is True
    assert "No current Pod health anomalies were found across all 14 evaluated Pods" in rendered.text
    assert "All 75 Pods are healthy based on the inventory table" not in rendered.text
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        assert assistant is not None
        assert json.loads(assistant.citations_json) == ["loki-health-complete"]
        activity = json.loads(assistant.tool_activity_json)
        assert activity["conclusion_status"] == "confirmed"
    engine.dispose()


def test_unrestricted_input_limit_with_prior_evidence_is_reported_explicitly(
    tmp_path: Path, caplog,
) -> None:
    class Provider(FakeModelProvider):
        def next_agent_step(self, *_args, **_kwargs):
            raise ModelProviderError(
                "PodPilot stopped the model request before transmission because its conservative "
                "input-token upper bound (61668) exceeds the configured maximum (59904).",
                failure_type="input_limit",
                failure={
                    "failure_type": "input_limit",
                    "estimated_input_tokens_upper_bound": 61_668,
                    "configured_input_tokens": 59_904,
                },
            )

    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=Provider(),
        settings_overrides={"agent_mode": "unrestricted"},
    )
    conversation_id = "30600000-0000-0000-0000-000000000001"
    now = datetime.now(timezone.utc)
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Large investigation",
            status="active",
            evidence_json=json.dumps([{
                "id": "prior-evidence", "tool": "get_resource",
                "summary": "Previously read a Pod.", "source": "test:pod",
                "collected_at": now.isoformat(),
                "data": {"kind": "Pod", "metadata": {"name": "web", "namespace": "apps"}},
            }]),
        ))
        db_session.add(AdHocMessage(
            id="30600000-0000-0000-0000-000000000002",
            conversation_id=conversation_id, role="user", actor="ivy",
            content="Inspect the existing evidence.", created_at=now,
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        continued = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Continue the investigation."},
            follow_redirects=False,
        )
        rendered = client.get(
            continued.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert "configured input-token limit" in rendered.text
    assert "input-token upper bound (61668) exceeds the configured maximum (59904)" in rendered.text
    assert "UnboundLocalError" not in rendered.text
    assert "Internal job failure" not in rendered.text
    assert "podpilot.adhoc.provider_failed" in caplog.text


def test_unrestricted_audit_argument_normalization_is_broad_and_error_safe() -> None:
    aliases = _normalize_agent_collector_arguments("query_audit_events", {
        "audit_operation_scope": "delete",
        "audit_outcome": "any",
    })
    defaults = _normalize_agent_collector_arguments("query_audit_events", {})
    regex_wildcards = _normalize_agent_collector_arguments("query_audit_events", {
        "audit_operation_scope": ".*", "audit_outcome": ".*",
    })

    assert aliases == {
        "audit_operation_scope": "deletes",
        "audit_outcome": "all",
    }
    assert defaults == {
        "audit_operation_scope": "all",
        "audit_outcome": "all",
    }
    assert regex_wildcards == {
        "audit_operation_scope": "all",
        "audit_outcome": "all",
    }

    with pytest.raises(ValidationError) as captured:
        ReadIntent(
            tool="query_audit_events",
            audit_operation_scope="destroy",  # type: ignore[arg-type]
            audit_outcome="all",
        )
    detail = _agent_collector_error_detail(captured.value)
    assert "audit_operation_scope" in detail
    assert "errors.pydantic.dev" not in detail
    assert "input_value" not in detail


def test_unrestricted_metric_argument_normalization_repairs_log_ranking() -> None:
    normalized = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "log_entries_total",
            "metric_scope": "logs",
            "range_seconds": 3600,
        },
        question="Show me the namespaces that produce the most logs",
    )

    assert normalized["metric"] == "top_log_volume_by_namespace"
    assert normalized["metric_scope"] == "cluster"
    assert normalized["metric_operation"] == "rank"
    assert normalized["metric_group_by"] == ["namespace"]

    for guessed_metric in (
        "log_volume_bytes",
        "log_volume_bytes_total",
        "loki_log_entries_total",
        "container_log_bytes_total",
    ):
        repaired = _normalize_agent_collector_arguments(
            "query_metrics",
            {"metric": guessed_metric, "metric_scope": "cluster"},
            question="Show me the namespaces that produce the most amount of logs",
        )
        assert repaired["metric"] == "top_log_volume_by_namespace"
        assert repaired["metric_scope"] == "cluster"
        assert repaired["metric_operation"] == "rank"
        assert repaired["metric_group_by"] == ["namespace"]
    assert normalized["range_seconds"] == 300

    explicit_period = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "top-log-volume-by-namespace",
            "metric_scope": "namespaces",
        },
        question="Which namespaces generated the most logs in the last 2 hours?",
    )
    assert explicit_period["metric"] == "top_log_volume_by_namespace"
    assert explicit_period["metric_scope"] == "cluster"
    assert explicit_period["range_seconds"] == 7200

    generic_cluster_ranking = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "application_log_volume", "metric_scope": "cluster",
            "metric_operation": "rank", "metric_group_by": ["namespace"],
        },
        question="Rank namespaces by application log volume",
    )
    assert generic_cluster_ranking["metric"] == "top_log_volume_by_namespace"

    for kafka_alias in (
        "kafka_topic_disk_usage", "kafka_topic_disk_usage_bytes",
        "kafka_topic_disk_bytes", "kafka_topic_storage_bytes",
    ):
        kafka_storage = _normalize_agent_collector_arguments(
            "query_metrics",
            {
                "metric": kafka_alias, "metric_scope": "namespace",
                "namespace": "kafka-observability",
                "name": "kafka-observability-cluster",
            },
            question="Show Kafka topic disk usage grouped by topic",
        )
        assert kafka_storage["metric"] == "kafka_topic_disk_utilization"
        assert kafka_storage["metric_scope"] == "kafka_cluster"
        assert kafka_storage["metric_operation"] == "rank"
        assert kafka_storage["metric_group_by"] == ["topic"]

    exact_topic = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "kafka_topic_disk_usage_bytes",
            "metric_scope": "kafka_cluster",
            "kind": "Kafka",
            "namespace": "tm-streams-sit2",
            "name": "tm-streams-sit2-cluster",
            "topic": "ep.ticket.status.updated.events",
            "limit": 300,
        },
        question="Show disk usage for topic ep.ticket.status.updated.events",
    )
    assert exact_topic["topic"] == "ep.ticket.status.updated.events"
    assert exact_topic["limit"] == 1
    with pytest.raises(ValueError, match="not in the focused catalog"):
        _normalize_agent_collector_arguments(
            "query_metrics",
            {"metric": "log_entries_total", "metric_scope": "logging"},
            question="Show the total logs for this workload",
        )

    namespace_pods = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "top_log_volume_by_pod", "metric_scope": "namespaces",
            "namespace": "payments", "range_seconds": 3600,
        },
        question="Which pods in namespace payments produce the most logs?",
    )
    assert namespace_pods["metric"] == "application_log_volume"
    assert namespace_pods["metric_scope"] == "namespace"
    assert namespace_pods["metric_operation"] == "rank"
    assert namespace_pods["metric_group_by"] == ["pod"]
    assert namespace_pods["range_seconds"] == 300

    cluster_nodes = _normalize_agent_collector_arguments(
        "query_metrics",
        {"metric": "log_entries_total", "metric_scope": "logs"},
        question="Rank the nodes that generate the most logs",
    )
    assert cluster_nodes["metric"] == "application_log_volume"
    assert cluster_nodes["metric_scope"] == "cluster"
    assert cluster_nodes["metric_group_by"] == ["node"]

    exact_node = _normalize_agent_collector_arguments(
        "query_metrics",
        {
            "metric": "node_log_volume", "metric_scope": "node",
            "name": "worker-0",
        },
        question="Show application log volume for node worker-0",
    )
    assert exact_node["metric"] == "application_log_volume"
    assert exact_node["metric_scope"] == "node"
    assert exact_node["metric_operation"] == "show"
    assert exact_node.get("metric_group_by") is None


def test_kafka_metric_validation_retry_explains_cluster_and_topic_coordinates() -> None:
    guidance = _agent_tool_retry_guidance(
        tool_name="query_metrics",
        error=(
            "Invalid typed collector arguments: arguments: Value error, kafka_cluster "
            "metric scope requires kind Kafka and name must identify the owning Kafka custom resource"
        ),
        selected_cluster_ids=["cluster-1"],
    )

    assert "kind=Kafka" in guidance
    assert "owning Kafka CR name" in guidance
    assert "put the requested exact Kafka topic in topic" in guidance


def test_unrestricted_namespace_kafka_topic_storage_is_not_forced_by_heuristics(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(mode="investigate", evidence_goal="Investigate Kafka topic storage.")

        def next_agent_step(self, *_args, **_kwargs):
            return _agent_final_step("The agent interpreted the Kafka topic storage evidence.")

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            if intent.tool == "list_resources":
                return ReadResult((AdHocObservation(
                    id="kafka-discovery", tool="list_resources",
                    summary="Read two Kafka resources.",
                    source="kubernetes:kafka.strimzi.io:Kafka:kafka-observability/*",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "resource": "kafkas.kafka.strimzi.io", "kind": "Kafka",
                        "scope": "kafka-observability",
                        "names": ["logs-kafka", "unmonitored-kafka"],
                        "objects": [
                            {
                                "namespace": "kafka-observability", "name": "logs-kafka",
                            },
                            {
                                "namespace": "kafka-observability",
                                "name": "unmonitored-kafka",
                            },
                        ],
                        "objectListComplete": True,
                    },
                ),))
            assert intent.metric == "kafka_topic_storage"
            if intent.name == "unmonitored-kafka":
                raise ReadOnlyExplorerError(
                    "Thanos query failed (HTTP 403 Forbidden); grant cluster-monitoring-view."
                )
            return ReadResult((AdHocObservation(
                id="kafka-storage", tool="query_metrics",
                summary="Read topic storage for logs-kafka.",
                source="thanos:query_range/kafka_topic_storage",
                collected_at=datetime.now(timezone.utc),
                data={
                    "metric": "kafka_topic_storage", "scope": "kafka_cluster",
                    "namespace": intent.namespace, "name": intent.name,
                    "unit": "bytes", "limit": intent.limit, "complete": True,
                    "ranking": [{
                        "labels": {"topic": "logs-east-tm-system"},
                        "current": 6_442_450_944, "average": 6_400_000_000,
                        "maximum": 6_442_450_944,
                    }],
                },
            ),))

    explorer = Explorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=Provider(),
        read_explorer=explorer,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": (
                    "show me the disk usage of kafka topics in "
                    "kafka-observability namespace"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert explorer.calls == []
    assert "The agent interpreted the Kafka topic storage evidence" in rendered.text
    assert "model provider is currently unavailable" not in rendered.text.casefold()
    assert "execute_shell" not in rendered.text


def test_unrestricted_kafka_inventory_does_not_run_without_agent_selected_reads(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def classify_ad_hoc(self, *_args, **_kwargs):
            return InquirySemantics(
                mode="inventory", operation="inventory", cardinality="collection",
                resource_query="Kafka",
                evidence_goal="Inventory Kafka resources across clusters."
            )

        def next_agent_step(self, *_args, **_kwargs):
            return _agent_final_step("The agent compared Kafka evidence across the selected clusters.")

    class Explorer:
        def __init__(self, cluster_name: str) -> None:
            self.cluster_name = cluster_name
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            if self.cluster_name == "Legacy DEV":
                raise ReadOnlyExplorerError(
                    "The server does not expose the kafkas.kafka.strimzi.io resource type."
                )
            present = self.cluster_name == "Central DEV"
            names = ["orders-kafka"] if present else []
            objects = [{"namespace": "streams", "name": "orders-kafka"}] if present else []
            items = [{
                "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                "metadata": {"namespace": "streams", "name": "orders-kafka"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }] if present else []
            slug = self.cluster_name.casefold().replace(" ", "-")
            return ReadResult((AdHocObservation(
                id=f"kafka-{slug}", tool="list_resources",
                summary=f"Read Kafka resources from {self.cluster_name}.",
                source="kubernetes:kafka.strimzi.io:Kafka:cluster/*",
                collected_at=datetime.now(timezone.utc),
                data={
                    "resource": "kafkas.kafka.strimzi.io", "kind": "Kafka",
                    "scope": "cluster", "names": names, "objects": objects,
                    "items": items, "objectListComplete": True,
                },
            ),))

    cluster_credentials = MemoryCredentialStore()
    explorers: dict[str, Explorer] = {}

    def explorer_factory(cluster, _token):
        explorer = Explorer(cluster.name)
        explorers[cluster.name] = explorer
        return explorer

    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("model-token"),
        cluster_credential_store=cluster_credentials, model_provider=Provider(),
        remote_read_explorer_factory=explorer_factory,
        settings_overrides={"agent_mode": "unrestricted"},
    )
    cluster_ids = [
        "40000000-0000-0000-0000-000000000001",
        "40000000-0000-0000-0000-000000000002",
        "40000000-0000-0000-0000-000000000003",
    ]
    engine = build_engine(settings)
    with TestClient(app):
        pass
    with Session(engine) as db_session:
        now = datetime.now(timezone.utc)
        for cluster_id, name in zip(
            cluster_ids, ("Central DEV", "East DEV", "Legacy DEV"), strict=True,
        ):
            key = f"cluster_{cluster_id.replace('-', '')}"
            cluster_credentials.set(f"token-{name}", key)
            db_session.add(Cluster(
                id=cluster_id, name=name,
                api_url=f"https://api.{name.casefold().replace(' ', '-')}.example:6443",
                credential_key=key, tags_json="{}", tls_verify=True, is_enabled=True,
                is_system=False, status="ready", created_by="ada", updated_by="ada",
                created_at=now, updated_at=now,
            ))
        db_session.add(ModelProfile(
            id=1, provider_label="OpenRouter", base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b", api_type="chat-completions",
            embedding_model=None, timeout_seconds=240, max_output_tokens=4096,
            status="ready", capabilities_json='{"tool_calls": true}', updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": "Show me all the deployed Kafka clusters",
                "cluster_ids": json.dumps(cluster_ids),
            },
            follow_redirects=False,
        )
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"},
        )

    assert explorers == {}
    assert "agent compared Kafka evidence across the selected clusters" in rendered.text


def test_unrestricted_agent_brokers_each_selected_remote_cluster_and_surfaces_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="uvicorn.error")
    cluster_ids = [
        "30000000-0000-0000-0000-000000000001",
        "30000000-0000-0000-0000-000000000002",
    ]

    class Provider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.steps = 0
            self.agent_messages: list[list[dict[str, object]]] = []

        def next_agent_step(self, profile, api_key, messages):
            self.agent_messages.append(list(messages))
            if self.steps < 3:
                cluster_id = cluster_ids[min(self.steps, 1)]
                call_id = f"call-{self.steps + 1}"
                self.steps += 1
                arguments = json.dumps({
                    "command": "oc get kafkas.kafka.strimzi.io -A -o name",
                    "cluster_id": cluster_id,
                })
                return AgentStep(
                    assistant_message={
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": call_id,
                            "type": "function",
                            "function": {"name": "execute_shell", "arguments": arguments},
                        }],
                    },
                    content=None,
                    tool_calls=(AgentToolCall(
                        id=call_id,
                        name="execute_shell",
                        arguments=arguments,
                    ),),
                )
            finish_arguments = json.dumps({
                "stop_reason": "complete",
                "answer": "Checked both clusters.",
                "unresolved_safe_reads": [],
            })
            return AgentStep(
                assistant_message={
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "finish", "type": "function",
                        "function": {
                            "name": "finish_investigation",
                            "arguments": finish_arguments,
                        },
                    }],
                },
                content=None,
                tool_calls=(AgentToolCall(
                    id="finish",
                    name="finish_investigation",
                    arguments=finish_arguments,
                ),),
            )

    class Runner:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, command, connection=None, **_kwargs):
            self.calls.append((command, connection))
            if connection.cluster_id == cluster_ids[0]:
                time.sleep(2.1)
            failed = connection.cluster_id == cluster_ids[1]
            return AgentCommandResult(
                command=command,
                exit_code=1 if failed else 0,
                stdout="kafka.kafka.strimzi.io/vc-cluster\n" if not failed else "",
                stderr="Unable to connect to the server: synthetic failure" if failed else "",
                request_id="runner-east" if failed else "runner-central",
                duration_ms=416,
            )

    provider = Provider()
    runner = Runner()
    cluster_credentials = MemoryCredentialStore()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("model-token"),
        cluster_credential_store=cluster_credentials,
        model_provider=provider,
        agent_runner=runner,
        settings_overrides={
            "agent_mode": "unrestricted",
            "agent_heartbeat_seconds": 2,
        },
    )
    engine = build_engine(settings)
    with TestClient(app):
        pass
    with Session(engine) as db_session:
        now = datetime.now(timezone.utc)
        for cluster_id, name in zip(cluster_ids, ("Central DEV", "East DEV"), strict=True):
            key = f"cluster_{cluster_id.replace('-', '')}"
            cluster_credentials.set(f"token-{name}", key)
            db_session.add(Cluster(
                id=cluster_id,
                name=name,
                api_url=f"https://api.{name.casefold().replace(' ', '-')}.example:6443",
                credential_key=key,
                tags_json="{}",
                tls_verify=True,
                is_enabled=True,
                is_system=False,
                status="ready",
                created_by="ada",
                updated_by="ada",
                created_at=now,
                updated_at=now,
            ))
        db_session.add(ModelProfile(
            id=1,
            provider_label="OpenRouter",
            base_url="https://openrouter.ai/api/v1",
            chat_model="openai/gpt-oss-120b",
            api_type="chat-completions",
            embedding_model=None,
            timeout_seconds=240,
            max_output_tokens=4096,
            status="ready",
            capabilities_json='{"tool_calls": true}',
            updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": "Run the Kafka inventory command on both selected clusters.",
                "cluster_ids": json.dumps(cluster_ids),
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert [call[1].cluster_id for call in runner.calls] == cluster_ids
    assert all(call[1].tls_verify is True for call in runner.calls)
    assert "synthetic failure" not in rendered.text
    assert "Exploratory checks" in rendered.text
    assert "Command failed" in rendered.text
    assert "East DEV" in rendered.text
    assert "Cluster TLS exception" not in rendered.text
    assert "API TLS verification is disabled" not in rendered.text
    assert "credentials and evidence are vulnerable to interception" not in rendered.text
    assert all("token-" not in str(messages) for messages in provider.agent_messages)
    duplicate_payload = json.loads(str(provider.agent_messages[3][-1]["content"]))
    assert duplicate_payload["failure_category"] == "duplicate_command"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(AdHocMessage.role == "assistant"))
        run = db_session.scalar(select(AdHocRun))
        assert assistant is not None
        assert run is not None
        activity = json.loads(assistant.tool_activity_json)
        assert activity["stop_reason"] == "complete"
        command_reads = [item for item in activity["reads"] if item["tool"] == "execute_shell"]
        assert [item["cluster_id"] for item in command_reads] == [
            *cluster_ids, cluster_ids[1],
        ]
        duplicate_read = command_reads[-1]
        assert duplicate_read["status"] == "rejected"
        assert duplicate_read["failure_category"] == "duplicate_command"
        failed_read = next(item for item in command_reads if item["status"] == "failed")
        assert re.fullmatch(r"[0-9a-f]{12}", failed_read["diagnostic_ref"])
        assert activity["limitations"] == []
        assert all(
            "TLS verification is disabled" not in item
            for item in activity["limitations"]
        )
        assert any(
            "Still executing on Central DEV" in item["message"]
            for item in json.loads(run.progress_json)
        )
    engine.dispose()
    assert "runner_request_id=runner-east" in caplog.text
    assert "command='oc get kafkas.kafka.strimzi.io -A -o name'" in caplog.text
    assert "command_truncated=False" in caplog.text
    assert "stderr_tail='Unable to connect to the server: synthetic failure'" in caplog.text
    assert re.search(r"diagnostic_ref=[0-9a-f]{12}", caplog.text)


def test_safe_exception_diagnostics_redacts_chain_and_includes_frames() -> None:
    try:
        try:
            raise RuntimeError("request failed token=sensitive-token")
        except RuntimeError as exc:
            raise ReadOnlyExplorerError("collector failed") from exc
    except ReadOnlyExplorerError as exc:
        diagnostics = json.loads(_safe_exception_diagnostics(exc))

    assert [item["type"] for item in diagnostics] == [
        "ReadOnlyExplorerError", "RuntimeError",
    ]
    assert diagnostics[1]["detail"] == "request failed token=[REDACTED]"
    assert diagnostics[1]["frames"]


def test_agent_completion_gate_rejects_deferred_safe_reads() -> None:
    assert _agent_premature_deferral_issue(
        "I found one healthy pod. Let me know which component logs you'd like me to inspect.",
        stop_reason="complete",
        unresolved_safe_reads=[],
        action_budget_remaining=8,
    ) == "premature_operator_deferral"
    assert _agent_premature_deferral_issue(
        "The current evidence identifies the missing Service.",
        stop_reason="complete",
        unresolved_safe_reads=["Inspect the LokiStack custom resource status."],
        action_budget_remaining=8,
    ) == "declared_unresolved_safe_reads"
    assert _agent_premature_deferral_issue(
        "Further API discovery is unavailable to this identity.",
        stop_reason="blocked",
        unresolved_safe_reads=["Read the denied resource."],
        action_budget_remaining=8,
    ) is None


def test_agent_duplicate_command_requires_a_retry_reason() -> None:
    assert _agent_duplicate_command_issue(
        previous_executions=1, repeat_reason=None,
    ) is not None
    assert _agent_duplicate_command_issue(
        previous_executions=1, repeat_reason="time_comparison",
    ) is None
    assert _agent_duplicate_command_issue(
        previous_executions=0, repeat_reason=None,
    ) is None


def test_jq_preflight_extracts_inline_filters_without_cluster_input() -> None:
    command = (
        "oc get routes -n retail -o json | jq -r "
        "'.items[:5] | map({name: .metadata.name, "
        "destinationCA: (.spec.tls.destinationCACertificate // \"<none>\")})'"
    )

    assert _jq_filters_from_shell_command(command) == [
        '.items[:5] | map({name: .metadata.name, '
        'destinationCA: (.spec.tls.destinationCACertificate // "<none>")})'
    ]
    assert _jq_preflight_command(command) == (
        "jq -n '.items[:5] | map({name: .metadata.name, "
        "destinationCA: (.spec.tls.destinationCACertificate // \"<none>\")})' >/dev/null"
    )


def test_jq_failure_is_classified_as_a_filter_parse_error() -> None:
    stderr = (
        "jq: error: syntax error, unexpected //, expecting '}' "
        "at <top-level>, line 1:\njq: 1 compile error"
    )

    assert _command_failure_category(stderr) == "jq_filter_parse_error"


def test_agent_command_failures_are_grouped_without_response_bodies() -> None:
    failures = _summarize_agent_command_failures([
        {
            "tool": "execute_shell", "status": "failed",
            "cluster_name": "Central DEV", "failure_category": "forbidden",
        },
        {
            "tool": "execute_shell", "status": "failed",
            "cluster_name": "Central DEV", "failure_category": "forbidden",
        },
        {
            "tool": "execute_shell", "status": "failed",
            "cluster_name": "Central DEV", "failure_category": "not_found",
        },
    ])

    assert failures == [
        {
            "cluster": "Central DEV", "category": "forbidden",
            "label": "Access denied", "count": 2,
        },
        {
            "cluster": "Central DEV", "category": "not_found",
            "label": "Resource not found", "count": 1,
        },
    ]


def test_command_failure_classifies_proxy_html_without_exposing_it() -> None:
    stderr = (
        "Error from server (Forbidden): <!doctype html><html><head>"
        "<title>Access error - PodPilot</title></head></html>"
    )

    assert _command_failure_category(stderr) == "forbidden"


def test_agent_collector_failure_category_survives_wrapping() -> None:
    source = LogMetricsQueryError(
        "TLS certificate verification failed while connecting to Loki.",
        failure_category="tls_verification_failed",
    )
    try:
        try:
            raise source
        except LogMetricsQueryError as exc:
            raise ReadOnlyExplorerError(str(exc)) from exc
    except ReadOnlyExplorerError as exc:
        assert _agent_collector_failure_category(exc) == "tls_verification_failed"


def test_ask_raw_response_toggle_preserves_the_single_agent_answer_attempt(
    tmp_path: Path,
) -> None:
    provider = HeadingOnlyThenCompleteProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert "Show raw model response" in page.text
        assert "For this question only" not in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": "Why is pod api-7d9 pending in payments?",
                "include_raw_response": "on",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Raw model response" in rendered.text
        assert "Untrusted provider output" in rendered.text
        assert "1 attempt" in rendered.text
        assert "initial answer" in rendered.text
        assert "PodPilot correction" not in rendered.text
        assert "Observed objects" in rendered.text
        assert "Observed objects" in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.scalar(select(AdHocRun))
        assistant = db_session.scalar(select(AdHocMessage).where(
            AdHocMessage.role == "assistant"
        ))
        event = db_session.scalar(select(AuditEvent).where(
            AuditEvent.action == "adhoc.message"
        ))
        assert run is not None and run.include_raw_response is True
        assert assistant is not None
        attempts = json.loads(assistant.raw_responses_json)
        assert [item["stage"] for item in attempts] == ["initial answer"]
        assert event is not None
        assert json.loads(event.details_json)["raw_response_requested"] is True
    engine.dispose()


def test_ask_reasoning_choice_is_limited_by_model_and_persists_per_user(
    tmp_path: Path,
) -> None:
    class ReasoningCaptureProvider(FakeModelProvider):
        def __init__(self) -> None:
            super().__init__()
            self.reasoning_efforts: list[str | None] = []

        def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
            self.reasoning_efforts.append(profile.reasoning_effort)
            return super().plan_ad_hoc(profile, api_key, context)

    provider = ReasoningCaptureProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="GPT OSS", base_url="https://models.example.test/v1",
            chat_model="gpt-oss-120b", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}",
            reasoning_efforts_json=json.dumps(["low", "medium", "high"]),
            reasoning_effort=None, updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert '<option value="provider_default" selected>Provider default</option>' in page.text
        assert '<option value="low"' in page.text
        assert '<option value="medium"' in page.text
        assert '<option value="high"' in page.text
        assert '<option value="xhigh"' not in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        headers = {"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)}

        selected = client.post(
            "/api/v1/adhoc-conversations",
            headers=headers,
            data={
                "message": "Why is pod api-7d9 pending in payments?",
                "reasoning_effort": "high",
            },
            follow_redirects=False,
        )
        assert selected.status_code == 303
        persisted_page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert '<option value="high" selected>High</option>' in persisted_page.text

        inherited = client.post(
            "/api/v1/adhoc-conversations",
            headers=headers,
            data={"message": "Inspect pod api-7d9 again."},
            follow_redirects=False,
        )
        assert inherited.status_code == 303

        rejected = client.post(
            "/api/v1/adhoc-conversations",
            headers=headers,
            data={"message": "Inspect it once more.", "reasoning_effort": "xhigh"},
            follow_redirects=False,
        )
        assert rejected.status_code == 422

        provider_default = client.post(
            "/api/v1/adhoc-conversations",
            headers=headers,
            data={
                "message": "Inspect pod api-7d9 with the provider default.",
                "reasoning_effort": "provider_default",
            },
            follow_redirects=False,
        )
        assert provider_default.status_code == 303

    assert provider.reasoning_efforts[0] == "high"
    assert provider.reasoning_efforts[-1] is None
    engine = build_engine(settings)
    with Session(engine) as db_session:
        preference = db_session.scalar(select(UserModelPreference))
        assert preference is not None
        assert preference.username == "ivy"
        assert preference.model_profile_id == 1
        assert preference.reasoning_effort is None
        assert [run.reasoning_effort for run in db_session.scalars(
            select(AdHocRun).order_by(AdHocRun.created_at)
        )] == ["high", "high", None]
    engine.dispose()


def test_approver_manages_secret_backed_cluster_without_returning_token(tmp_path: Path) -> None:
    cluster_credentials = MemoryCredentialStore()

    class DiscoverableExplorer(FakeReadExplorer):
        def resource_catalog(self, *, query="", limit=120):
            return [{"resource": "pods", "kind": "Pod", "api_version": "v1"}]

    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER, "ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        cluster_credential_store=cluster_credentials,
        remote_read_explorer_factory=lambda cluster, token: DiscoverableExplorer(),
    )
    with TestClient(app) as client:
        page = client.get("/settings/clusters", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert page.status_code == 200 and csrf is not None
        assert "<h1>Cluster Management</h1>" in page.text
        assert re.search(
            r'href="/settings/clusters"[^>]*>[\s\S]*?Cluster Management\s*</a>',
            page.text,
        )
        denied = client.get("/settings/clusters", headers={"x-forwarded-user": "ivy"})
        assert denied.status_code == 403
        saved = client.post(
            "/api/v1/clusters",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "name": "azure-prod-1",
                "api_url": "https://api.azure-prod-1.example:6443",
                "token": "sha256~top-secret-cluster-token",
                "tags_json": '{"environment":"prod","platform":"azure","production":""}',
                "tls_verify": "false",
            },
        )
        assert saved.status_code == 200
        assert "top-secret" not in saved.text
        cluster_id = saved.json()["cluster_id"]
        tested = client.post(
            f"/api/v1/clusters/{cluster_id}/test",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )
        assert tested.json()["status"] == "ready"
        edited = client.get(
            f"/settings/clusters?edit={cluster_id}",
            headers={"x-forwarded-user": "ada"},
        )
        assert "Tags as JSON" not in edited.text
        assert "data-tag-editor" in edited.text
        assert "single word" in edited.text
        assert "production" in edited.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        cluster = db_session.get(Cluster, cluster_id)
        assert cluster is not None
        assert json.loads(cluster.tags_json) == {
            "environment": "prod",
            "platform": "azure",
            "production": "",
        }
        assert cluster.tls_verify is False
        assert "top-secret" not in json.dumps(cluster.__dict__, default=str)
        assert cluster_credentials.get(cluster.credential_key) == "sha256~top-secret-cluster-token"
    engine.dispose()


def test_default_remote_cluster_reader_includes_authenticated_metrics_adapter(
    tmp_path: Path, monkeypatch,
) -> None:
    cluster_credentials = MemoryCredentialStore()
    captured: dict[str, object] = {}

    class DiscoverableExplorer(FakeReadExplorer):
        def resource_catalog(self, *, query="", limit=120):
            return [{"resource": "pods", "kind": "Pod", "api_version": "v1"}]

    def fake_remote_cluster(cls, **kwargs):
        captured.update(kwargs)
        return DiscoverableExplorer()

    monkeypatch.setattr(
        KubernetesReadOnlyExplorer,
        "for_remote_cluster",
        classmethod(fake_remote_cluster),
    )
    app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        cluster_credential_store=cluster_credentials,
        settings_overrides={
            "adhoc_max_payload_bytes": 96_000,
            "adhoc_metrics_max_response_bytes": 2_097_152,
        },
    )

    with TestClient(app) as client:
        page = client.get("/settings/clusters", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        saved = client.post(
            "/api/v1/clusters",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "name": "remote-metrics",
                "api_url": "https://api.remote.example:6443",
                "token": "sha256~remote-monitoring-token",
                "tags_json": "{}",
                "tls_verify": "true",
            },
        )
        cluster_id = saved.json()["cluster_id"]
        tested = client.post(
            f"/api/v1/clusters/{cluster_id}/test",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
        )

    assert tested.status_code == 200
    assert isinstance(captured["metric_reader"], BoundedMetricTrendReader)
    assert captured["max_payload_bytes"] == 96_000
    assert captured["metric_reader"]._source._max_response_bytes == 2_097_152
    assert captured["api_url"] == "https://api.remote.example:6443"
    assert captured["token"] == "sha256~remote-monitoring-token"
    assert captured["tls_verify"] is True


def test_approver_updates_runtime_cluster_display_name_environment_and_tags(
    tmp_path: Path,
) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER, "ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
    )
    with TestClient(app) as client:
        page = client.get(
            f"/settings/clusters?edit={SYSTEM_CLUSTER_ID}",
            headers={"x-forwarded-user": "ada"},
        )
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert page.status_code == 200 and csrf is not None
        assert f'data-save-url="/api/v1/clusters/{SYSTEM_CLUSTER_ID}/metadata"' in page.text
        assert 'name="name"' in page.text
        assert 'name="environment"' in page.text
        assert 'name="environment" required maxlength="64" value="test"' in page.text
        assert 'name="tags_json"' in page.text
        assert "Tags scope cluster memory" in page.text
        assert "projected service-account connection remains managed by the deployment" in page.text

        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        renamed = client.post(
            f"/api/v1/clusters/{SYSTEM_CLUSTER_ID}/metadata",
            headers=headers,
            data={
                "name": "toronto-sno-lab",
                "environment": "hci",
                "tags_json": '{"azure":"","environment":"dev","region":"toronto"}',
            },
        )
        assert renamed.status_code == 200
        assert renamed.json() == {
            "status": "saved",
            "cluster_id": SYSTEM_CLUSTER_ID,
            "name": "toronto-sno-lab",
            "environment": "hci",
            "tags": {"azure": "", "environment": "dev", "region": "toronto"},
            "detail": "Runtime cluster metadata saved.",
        }

        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        ask = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        updated_page = client.get(
            f"/settings/clusters?edit={SYSTEM_CLUSTER_ID}",
            headers={"x-forwarded-user": "ada"},
        )
        assert "hci · toronto-sno-lab" in dashboard.text
        assert "toronto-sno-lab" in ask.text
        assert 'name="environment" required maxlength="64" value="hci"' in updated_page.text
        assert "<b>HCI</b>" in updated_page.text

        invalid_environment = client.post(
            f"/api/v1/clusters/{SYSTEM_CLUSTER_ID}/metadata",
            headers=headers,
            data={"name": "toronto-sno-lab", "environment": "not?valid"},
        )
        assert invalid_environment.status_code == 422

        denied = client.post(
            f"/api/v1/clusters/{SYSTEM_CLUSTER_ID}/metadata",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"name": "not-authorized"},
        )
        assert denied.status_code == 403

    restarted_app, _ = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
    )
    with TestClient(restarted_app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        assert "hci · toronto-sno-lab" in dashboard.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        cluster = db_session.get(Cluster, SYSTEM_CLUSTER_ID)
        assert cluster is not None
        assert cluster.name == "toronto-sno-lab"
        assert cluster.environment == "hci"
        assert json.loads(cluster.tags_json) == {
            "azure": "", "environment": "dev", "region": "toronto",
        }
        assert cluster.api_url == "in-cluster://service-account"
        assert cluster.credential_key is None
        event = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "cluster.metadata.update")
        )
        assert event is not None
        assert json.loads(event.details_json) == {
            "cluster_id": SYSTEM_CLUSTER_ID,
            "environment": "hci",
            "name": "toronto-sno-lab",
            "previous_environment": "test",
            "previous_name": "test-cluster",
            "previous_tag_keys": ["connection", "environment"],
            "tag_keys": ["azure", "environment", "region"],
        }
    engine.dispose()


def test_cluster_save_reports_and_logs_credential_store_failure(
    tmp_path: Path, caplog,
) -> None:
    class FailingCredentialStore(MemoryCredentialStore):
        def set(self, value: str, key: str | None = None) -> None:
            raise CredentialStoreError(
                "The credential Secret ai-ops/podpilot-cluster-credentials does not exist. "
                "Create the pre-provisioned Secret and try again."
            )

    app, _settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        cluster_credential_store=FailingCredentialStore(),
    )
    caplog.set_level("WARNING", logger="uvicorn.error")
    with TestClient(app) as client:
        page = client.get("/settings/clusters", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        response = client.post(
            "/api/v1/clusters",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "name": "missing-secret-cluster",
                "api_url": "https://api.missing-secret.example:6443",
                "token": "sha256~never-log-this-token",
                "tags_json": "{}",
                "tls_verify": "true",
            },
        )

    assert response.status_code == 503
    assert "does not exist" in response.json()["detail"]
    assert "Cluster credential save failed" in caplog.text
    assert "never-log-this-token" not in caplog.text


def test_cluster_test_does_not_return_raw_remote_client_exception(tmp_path: Path) -> None:
    cluster_credentials = MemoryCredentialStore()

    def failing_remote_reader(_cluster, _token):
        raise RuntimeError(
            "403 Forbidden HTTP response headers: Audit-Id=do-not-display "
            "Authorization=Bearer-do-not-display"
        )

    app, _settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        cluster_credential_store=cluster_credentials,
        remote_read_explorer_factory=failing_remote_reader,
    )
    with TestClient(app) as client:
        page = client.get("/settings/clusters", headers={"x-forwarded-user": "ada"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        saved = client.post(
            "/api/v1/clusters",
            headers=headers,
            data={
                "name": "forbidden-cluster",
                "api_url": "https://api.forbidden.example:6443",
                "token": "sha256~remote-cluster-token",
                "tags_json": "{}",
                "tls_verify": "false",
            },
        )
        tested = client.post(
            f"/api/v1/clusters/{saved.json()['cluster_id']}/test",
            headers=headers,
        )

    assert tested.status_code == 200
    assert tested.json()["status"] == "unavailable"
    assert "failed before read-only discovery" in tested.json()["detail"]
    assert "Audit-Id" not in tested.text
    assert "Authorization" not in tested.text


def test_ask_conversation_pins_and_reads_multiple_clusters(tmp_path: Path) -> None:
    cluster_credentials = MemoryCredentialStore()
    provider = FakeModelProvider()

    class PerClusterExplorer(FakeReadExplorer):
        def __init__(self, cluster_name: str):
            super().__init__()
            self.cluster_name = cluster_name

        def execute(self, intent):
            self.calls.append(intent)
            return ReadResult((AdHocObservation(
                id=f"cluster-{self.cluster_name}",
                tool=intent.tool,
                summary=f"Read Pod from {self.cluster_name}.",
                source=f"kubernetes:{self.cluster_name}:v1:Pod:payments/api-7d9",
                collected_at=datetime.now(timezone.utc),
                data={"status": {"phase": "Running"}},
            ),))

    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("model-token"),
        cluster_credential_store=cluster_credentials,
        model_provider=provider,
        remote_read_explorer_factory=lambda cluster, token: PerClusterExplorer(cluster.name),
    )
    first_id = "10000000-0000-0000-0000-000000000001"
    second_id = "10000000-0000-0000-0000-000000000002"
    engine = build_engine(settings)
    with TestClient(app):
        pass
    with Session(engine) as db_session:
        now = datetime.now(timezone.utc)
        for cluster_id, name, platform in (
            (first_id, "azure-one", "azure"),
            (second_id, "metal-one", "baremetal"),
        ):
            key = f"cluster_{cluster_id.replace('-', '')}"
            cluster_credentials.set(f"token-{name}", key)
            db_session.add(Cluster(
                id=cluster_id, name=name, api_url=f"https://api.{name}.example:6443",
                credential_key=key, tags_json=json.dumps({"platform": platform}),
                tls_verify=True, is_enabled=True, is_system=False, status="ready",
                created_by="ada", updated_by="ada", created_at=now, updated_at=now,
            ))
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
            data={
                "message": "Compare pod api-7d9 in namespace payments.",
                "cluster_ids": json.dumps([first_id, second_id]),
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "azure-one" in rendered.text and "metal-one" in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        conversation = db_session.scalar(select(AdHocConversation))
        assert json.loads(conversation.cluster_ids_json) == [first_id, second_id]
        evidence = json.loads(conversation.evidence_json)
        assert {item["cluster_name"] for item in evidence} == {"azure-one", "metal-one"}
    engine.dispose()
    assert {item["name"] for item in provider.adhoc_answer_calls[0]["clusters"]} == {
        "azure-one", "metal-one"
    }


def test_ask_top_cpu_runs_one_cluster_metric_query_and_renders_table(
    tmp_path: Path,
) -> None:
    cluster_credentials = MemoryCredentialStore()

    class Provider(FakeModelProvider):
        def classify_ad_hoc(self, _profile, _api_key, _context):
            return InquirySemantics(
                mode="metrics", resource_query="Pod", needs_object_details=True,
                evidence_goal="Rank CPU-consuming pods on each selected cluster.",
                metric_query="top_cpu_consumers", metric_scope="cluster", result_limit=5,
            )

    class Explorer:
        def __init__(self, cluster_name: str):
            self.cluster_name = cluster_name
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            slug = self.cluster_name.casefold().replace(" ", "-")
            return ReadResult((AdHocObservation(
                id=f"metric-{slug}", tool="query_metrics",
                summary=f"Ranked CPU consumers in {self.cluster_name}.",
                source="thanos:query_range/top_cpu_consumers",
                collected_at=datetime.now(timezone.utc),
                data={
                    "metric": "top_cpu_consumers", "scope": "cluster",
                    "unit": "cores", "limit": intent.limit, "complete": True,
                    "ranking": [{
                        "labels": {"namespace": "payments", "pod": f"api-{slug}"},
                        "current": 0.75, "average": 0.5, "maximum": 0.9,
                    }],
                },
            ),))

    provider = Provider()
    explorers: dict[str, Explorer] = {}

    def explorer_factory(cluster, _token):
        explorer = Explorer(cluster.name)
        explorers[cluster.name] = explorer
        return explorer

    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("model-token"),
        cluster_credential_store=cluster_credentials,
        model_provider=provider,
        remote_read_explorer_factory=explorer_factory,
    )
    cluster_ids = [
        "20000000-0000-0000-0000-000000000001",
        "20000000-0000-0000-0000-000000000002",
    ]
    engine = build_engine(settings)
    with TestClient(app):
        pass
    with Session(engine) as db_session:
        now = datetime.now(timezone.utc)
        for cluster_id, name in zip(cluster_ids, ("Central DEV", "East DEV"), strict=True):
            key = f"cluster_{cluster_id.replace('-', '')}"
            cluster_credentials.set(f"token-{name}", key)
            db_session.add(Cluster(
                id=cluster_id, name=name, api_url=f"https://api.{name}.example:6443",
                credential_key=key, tags_json="{}", tls_verify=True, is_enabled=True,
                is_system=False, status="ready", created_by="ada", updated_by="ada",
                created_at=now, updated_at=now,
            ))
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
            data={
                "message": "Show me the top 5 CPU-consuming pods on each cluster.",
                "cluster_ids": json.dumps(cluster_ids),
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "Top CPU Consumers" in rendered.text
    assert "top 5 CPU-consuming pods by cluster" not in rendered.text
    assert "api-central-dev" in rendered.text
    assert "api-east-dev" in rendered.text
    assert "Central DEV" in rendered.text and "East DEV" in rendered.text
    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1
    assert set(explorers) == {"Central DEV", "East DEV"}
    for explorer in explorers.values():
        assert len(explorer.calls) == 1
        assert explorer.calls[0].tool == "query_metrics"
        assert explorer.calls[0].metric_scope == "cluster"
        assert explorer.calls[0].limit == 5


def test_ask_multi_signal_pod_metrics_use_typed_plan_and_deterministic_table(
    tmp_path: Path,
) -> None:
    class Provider(FakeModelProvider):
        def classify_ad_hoc(self, _profile, _api_key, _context):
            return InquirySemantics(
                mode="metrics",
                evidence_goal="Compare CPU and memory for the exact Pod.",
                metric_request=MetricRequestSemantics(
                    signals=["cpu_usage", "memory_working_set"],
                    target=MetricTargetSemantics(
                        scope="pod", kind="Pod",
                        namespace="payments", name="api-7d9",
                    ),
                    operation="compare",
                    statistic="current",
                    range_seconds=900,
                ),
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            value = 0.75 if intent.metric == "cpu_usage" else 536_870_912.0
            unit = "cores" if intent.metric == "cpu_usage" else "bytes"
            return ReadResult((AdHocObservation(
                id=f"metric-{intent.metric}", tool="query_metrics",
                summary=f"Read {intent.metric} for payments/api-7d9.",
                source=f"thanos:query_range/{intent.metric}",
                collected_at=datetime.now(timezone.utc),
                data={
                    "metric": intent.metric, "scope": "pod",
                    "namespace": "payments", "name": "api-7d9",
                    "unit": unit, "complete": True,
                    "ranking": [{
                        "labels": {}, "current": value,
                        "average": value * 0.8, "maximum": value * 1.1,
                    }],
                },
            ),))

    provider = Provider()
    explorer = Explorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Compare current CPU and memory for pod api-7d9 in payments."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert [intent.metric for intent in explorer.calls] == [
        "cpu_usage", "memory_working_set",
    ]
    assert all(intent.metric_scope == "pod" for intent in explorer.calls)
    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1
    assert "Observed metric values" not in rendered.text
    assert "The Pod selector does not match an available node" in rendered.text
    assert "metric-cpu_usage" in rendered.text
    assert "metric-memory_working_set" in rendered.text


def test_ask_rbac_denial_reaches_terminal_answer_without_hanging(tmp_path: Path) -> None:
    provider = RbacAwareAdHocProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=ForbiddenReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check pod api-7d9 in namespace payments."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "requested API server logs could not be collected" in rendered.text
        assert "HTTP 403" in rendered.text
        assert "Working on your question" not in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.scalar(select(AdHocRun))
        assert run is not None and run.status == "succeeded"
        assert run.completed_at is not None
    engine.dispose()


def test_ask_preserves_heading_only_final_answer_without_style_retry(
    tmp_path: Path,
) -> None:
    provider = HeadingOnlyThenCompleteProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check pod api-7d9 in namespace payments."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "Observed objects" in rendered.text
    assert "The exact Pod remains Pending" not in rendered.text
    assert len(provider.adhoc_answer_calls) == 1
    assert "answer_feedback" not in provider.adhoc_answer_calls[0]


def test_ask_planner_failure_is_visible_and_does_not_block_answer(
    tmp_path: Path, caplog
) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=FailingAdHocProvider(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    secret_question = "Why is customer-secret-phrase workload unhealthy?"
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": secret_question},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "does not match ReadPlan" in rendered.text
        assert "scope_summary: string_too_short" in rendered.text

    log_text = caplog.text
    assert "podpilot.adhoc.provider_start" in log_text
    assert "podpilot.adhoc.provider_complete" in log_text
    assert "podpilot.adhoc.provider_failed" not in log_text
    assert "scope_summary: string_too_short" in log_text
    assert secret_question not in log_text


def test_final_provider_failure_preserves_collected_evidence_and_compact_context(
    tmp_path: Path, caplog,
) -> None:
    provider = EmptyFinalAnswerProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Check pod api-7d9 in namespace payments."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "Read Pod payments/api-7d9" in rendered.text
    assert "PodPilot could not complete this investigation" not in rendered.text
    assert "provider returned no structured response content" in rendered.text
    assert "podpilot.adhoc.provider_fallback" in caplog.text
    context = provider.adhoc_answer_calls[0]
    assert len(context["conversation"]) <= 4
    assert len(context["observations"]) <= 16
    assert len(context["curated_knowledge"]) <= 6
    assert "relationship_graph" not in context


def test_ask_continues_to_answer_when_later_plan_is_invalid(tmp_path: Path) -> None:
    provider = LateFailingPlanProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check pod api-7d9 in namespace payments."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert "selector does not match" in rendered.text
    assert "continued to the answer phase" in rendered.text
    assert len(provider.adhoc_answer_calls) == 1


def test_ask_storageclass_inventory_does_not_use_removed_list_helper(
    tmp_path: Path,
) -> None:
    provider = StorageClassProvider()
    explorer = StorageClassExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "What StorageClasses are available on the cluster?"},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "No StorageClass inventory was collected" in rendered.text
        assert "managed-premium" not in rendered.text
        assert "cluster-sc-1" not in rendered.text
        assert "Suggested next checks" not in rendered.text

    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1
    assert explorer.calls == []


def test_ask_route_protocol_grounds_backend_service_and_preserves_route_answer(
    tmp_path: Path,
) -> None:
    provider = RouteBackendProvider()
    explorer = RouteBackendExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    question = (
        "This Route reports an Internal Server Error over HTTPS, but is the backend HTTP? "
        "https://maas.apps.example.test/v1/models"
    )
    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": question},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "model did not produce a usable evidence-backed interpretation" in rendered.text
    assert "model planner did not select a safe evidence read" not in rendered.text
    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource",
    ]
    assert explorer.calls[1].name == "model-server"
    assert "removed list_resources helper" in rendered.text


def test_diagnostic_stop_is_respected_without_server_directed_reads(
    tmp_path: Path, caplog,
) -> None:
    provider = EarlyStoppingRouteProvider()
    explorer = RouteBackendExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": (
                    "This Route reports an Internal Server Error over HTTPS; validate the backend. "
                    "https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    review_calls = [
        context for context in provider.adhoc_plan_calls
        if context.get("planner_feedback", {}).get("code") == "review_evidence_sufficiency"
    ]
    assert review_calls == []
    assert "reason=evidence_sufficiency_review" not in caplog.text


def test_structured_answer_gap_remains_agent_authored_without_server_replanning(
    tmp_path: Path, caplog,
) -> None:
    provider = StructuredGapRouteProvider()
    explorer = RouteBackendExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": (
                    "Validate this Route backend: https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "backend Service mapping is not collected yet" in rendered.text
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    assert len(provider.adhoc_answer_calls) == 1
    assert "podpilot.adhoc.gap_followup_complete" not in caplog.text


def test_embedded_answer_gap_is_not_used_to_direct_server_side_collection(
    tmp_path: Path, caplog,
) -> None:
    provider = EmbeddedGapRouteProvider()
    explorer = RouteBackendExplorer(route_termination="passthrough")
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": (
                "Validate this Route backend: https://maas.apps.example.test/v1/models"
            )},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    assert "Route uses TLS passthrough" in rendered.text
    assert "investigation_gaps" in rendered.text
    assert "structured_fields_embedded_in_answer" not in caplog.text
    assert "podpilot.adhoc.gap_followup_complete" not in caplog.text
    assert len(provider.adhoc_answer_calls) == 1


def test_candidate_first_planner_selects_route_then_service_with_compact_context() -> None:
    provider = CandidateSelectingRouteProvider()
    explorer = RouteBackendExplorer()

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="candidate-first-route",
        question=(
            "Validate the backend protocol for Route "
            "https://maas.apps.example.test/v1/models"
        ),
        conversation=[
            {"role": "user", "content": f"historical context {index}"}
            for index in range(10)
        ],
        existing_evidence=[],
    ))

    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource",
    ]
    assert [item["id"] for item in result.evidence] == [
        "cluster-route-1", "cluster-service-1",
    ]
    first_context = provider.adhoc_plan_calls[0]
    assert first_context["tool_policy"]["mode"] == "candidate_selection"
    assert "resource_catalog" not in first_context["tool_policy"]
    assert len(first_context["conversation"]) == 4
    assert len(first_context["read_candidates"]) <= 12
    assert all(
        "read_hint" not in edge
        for edge in first_context["relationship_graph"]["edges"]
    )
    assert any(
        item["capability"] == "service_spec"
        for context in provider.adhoc_plan_calls
        for item in context["read_candidates"]
    )
    assert any(
        item["capability"] == "http_probe"
        and item["target"] == "GET https://maas.apps.example.test/v1/models"
        for context in provider.adhoc_plan_calls
        for item in context["read_candidates"]
    )


def test_unknown_candidate_id_executes_no_cluster_read() -> None:
    provider = UnknownCandidateRouteProvider()
    explorer = RouteBackendExplorer()

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="unknown-candidate",
        question="Validate https://maas.apps.example.test/v1/models",
        conversation=[], existing_evidence=[],
    ))

    assert explorer.calls == []
    assert result.evidence == []
    assert len(provider.adhoc_plan_calls) == 2


def test_structured_log_gap_offers_healthy_pod_log_candidate() -> None:
    class HealthyLogGapProvider:
        def __init__(self) -> None:
            self.contexts: list[dict[str, object]] = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if not context["completed_reads"]:
                candidate = next(
                    item for item in context["read_candidates"]
                    if item["capability"] == "pod_logs"
                )
                return ReadPlan(
                    goal_type="diagnose",
                    scope_summary="Read the exact healthy backend container logs for the 500.",
                    candidate_ids=[candidate["id"]],
                )
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                stop_reason="evidence_sufficient",
                scope_summary="The bounded backend logs were collected.",
                supporting_evidence_ids=["cluster-backend-logs"],
            )

    provider = HealthyLogGapProvider()
    explorer = RouteBackendExplorer()
    existing_pod = {
        "id": "cluster-healthy-pod",
        "tool": "get_resource",
        "summary": "Read the healthy backend Pod.",
        "data": {
            "kind": "Pod",
            "metadata": {"namespace": "maas", "name": "model-server-abc"},
            "spec": {"containers": [{"name": "server"}]},
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "name": "server", "ready": True, "restartCount": 0,
                }],
            },
        },
    }

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="healthy-log-gap",
        question="Why does this backend request return HTTP 500?",
        conversation=[], existing_evidence=[existing_pod],
        investigation_gaps=[InvestigationGap(
            question="What do the application logs show for the HTTP 500?",
            capability="pod_logs", priority="high",
            supporting_evidence_ids=["cluster-healthy-pod"],
        )],
    ))

    assert [call.tool for call in explorer.calls] == ["pod_logs"]
    assert any(item["id"] == "cluster-backend-logs" for item in result.evidence)
    first_context = provider.contexts[0]
    assert first_context["tool_policy"]["pod_log_candidates"][0][
        "investigation_priority"
    ] == "normal"
    assert any(
        item["capability"] == "pod_logs"
        for item in first_context["read_candidates"]
    )


def test_failure_question_offers_healthy_exact_pod_log_candidate() -> None:
    pod_evidence = [{
        "id": "cluster-healthy-pod",
        "tool": "get_resource",
        "summary": "Read the healthy backend Pod.",
        "data": {
            "kind": "Pod",
            "metadata": {"namespace": "maas", "name": "model-server-abc"},
            "spec": {"containers": [{"name": "server"}]},
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "name": "server", "ready": True, "restartCount": 0,
                }],
            },
        },
    }]

    failure_candidates = _grounded_read_candidates(
        question="Why is this endpoint returning an Internal Server Error?",
        evidence=pod_evidence,
        relationship_graph={"frontier": []},
        recovery_anchor_plan=None,
        seen_intents=set(),
    )
    neutral_candidates = _grounded_read_candidates(
        question="Describe the configuration of this Pod.",
        evidence=pod_evidence,
        relationship_graph={"frontier": []},
        recovery_anchor_plan=None,
        seen_intents=set(),
    )

    assert any(candidate.capability == "pod_logs" for candidate in failure_candidates)
    event_candidates = [
        candidate for candidate in failure_candidates
        if candidate.capability == "cluster_events"
    ]
    assert [candidate.intent for candidate in event_candidates] == [ReadIntent(
        tool="search_resources", resource="events", api_version="v1", kind="Event",
        namespace="maas", match_field="involvedObject.name",
        match_value="model-server-abc", match_operator="exact", limit=20,
    )]
    assert all(candidate.capability != "pod_logs" for candidate in neutral_candidates)
    assert all(candidate.capability != "cluster_events" for candidate in neutral_candidates)


def test_grounded_candidates_do_not_turn_catalog_matches_into_list_reads() -> None:
    candidates = _grounded_read_candidates(
        question="Is there Authorino configuration that defines the token format?",
        evidence=[],
        relationship_graph={
            "nodes": [{
                "kind": "Pod", "namespace": "kuadrant-system", "name": "authorino-abc",
                "observed": True,
            }],
            "frontier": [{
                "relation": "owned_by",
                "target": "ReplicaSet:kuadrant-system/authorino-54b888dfb9",
                "evidence_ids": ["cluster-pod"],
                "read_hint": {
                    "tool": "get_resource", "resource": "replicasets",
                    "api_version": "apps/v1", "kind": "ReplicaSet",
                    "namespace": "kuadrant-system", "name": "authorino-54b888dfb9",
                },
            }],
        },
        recovery_anchor_plan=None,
        seen_intents=set(),
        catalog_entries=[
            {
                "resource": "authconfigs.authorino.kuadrant.io",
                "apiVersion": "authorino.kuadrant.io/v1beta2", "kind": "AuthConfig",
                "namespaced": True, "verbs": ["get", "list"],
            },
            {
                "resource": "configmaps", "apiVersion": "v1", "kind": "ConfigMap",
                "namespaced": True, "verbs": ["get", "list"],
            },
            {
                "resource": "nodes", "apiVersion": "v1", "kind": "Node",
                "namespaced": False, "verbs": ["get", "list"],
            },
        ],
    )

    assert all(item.relation != "catalog_match" for item in candidates)
    assert [item.relation for item in candidates] == ["owned_by"]
    assert all(item.intent.kind != "Node" for item in candidates)


def test_exact_configmap_reference_outranks_generic_catalog_and_discovery_results() -> None:
    candidates = _grounded_read_candidates(
        question="Show the exporter configuration for the named cluster.",
        evidence=[{
            "id": "configmaps", "tool": "list_resources",
            "data": {
                "apiVersion": "v1", "kind": "ConfigMap", "resource": "configmaps",
                "scope": "kafka-observability",
                "objects": [{
                    "namespace": "kafka-observability", "name": "unrelated-config",
                }],
            },
        }],
        relationship_graph={
            "nodes": [],
            "frontier": [{
                "relation": "configures_from",
                "target": (
                    "ConfigMap:kafka-observability/"
                    "kafka-observability-metrics-config"
                ),
                "evidence_ids": ["kafka-1"],
                "read_hint": {
                    "tool": "get_resource", "resource": "configmaps",
                    "api_version": "v1", "kind": "ConfigMap",
                    "namespace": "kafka-observability",
                    "name": "kafka-observability-metrics-config",
                },
            }],
        },
        recovery_anchor_plan=None,
        seen_intents=set(),
        catalog_entries=[{
            "resource": "configs.operator.openshift.io",
            "apiVersion": "operator.openshift.io/v1", "kind": "Config",
            "namespaced": False, "verbs": ["get", "list"],
        }],
    )

    assert candidates[0].relation == "configures_from"
    assert candidates[0].intent.name == "kafka-observability-metrics-config"
    assert all(candidate.relation != "catalog_match" for candidate in candidates)


def test_bounded_discovery_results_become_exact_get_candidates() -> None:
    candidates = _grounded_read_candidates(
        question="Inspect the Authorino configuration.",
        evidence=[{
            "id": "cluster-authconfigs", "tool": "list_resources",
            "data": {
                "apiVersion": "authorino.kuadrant.io/v1beta2",
                "kind": "AuthConfig",
                "resource": "authconfigs.authorino.kuadrant.io",
                "scope": "kuadrant-system",
                "objects": [{"namespace": "kuadrant-system", "name": "authorino-protection"}],
                "items": [{
                    "kind": "AuthConfig",
                    "metadata": {"namespace": "kuadrant-system", "name": "authorino-protection"},
                }],
            },
        }],
        relationship_graph={"nodes": [], "frontier": []},
        recovery_anchor_plan=None,
        seen_intents=set(),
    )

    assert len(candidates) == 1
    assert candidates[0].relation == "discovery_result"
    assert candidates[0].intent == ReadIntent(
        tool="get_resource", resource="authconfigs.authorino.kuadrant.io",
        api_version="authorino.kuadrant.io/v1beta2", kind="AuthConfig",
        namespace="kuadrant-system", name="authorino-protection",
    )


def test_candidate_plan_combines_selected_and_model_authored_object_reads() -> None:
    candidates = _grounded_read_candidates(
        question="Inspect Authorino configuration.",
        evidence=[],
        relationship_graph={
            "nodes": [],
            "frontier": [{
                "relation": "owned_by", "target": "ReplicaSet:kuadrant-system/authorino-rs",
                "evidence_ids": ["cluster-pod"],
                "read_hint": {
                    "tool": "get_resource", "resource": "replicasets",
                    "api_version": "apps/v1", "kind": "ReplicaSet",
                    "namespace": "kuadrant-system", "name": "authorino-rs",
                },
            }],
        },
        recovery_anchor_plan=None,
        seen_intents=set(),
    )
    authored = ReadIntent(
        tool="list_resources", resource="authconfigs.authorino.kuadrant.io",
        kind="AuthConfig", namespace="kuadrant-system", limit=20,
    )
    compiled, errors = _compile_grounded_candidate_plan(
        ReadPlan(
            scope_summary="Inspect the owner and Authorino configuration.",
            candidate_ids=[candidates[0].id], intents=[authored],
        ),
        candidates,
    )

    assert errors == []
    assert compiled.candidate_ids == []
    assert compiled.intents == [candidates[0].intent, authored]


def test_failure_investigation_does_not_collect_logs_after_model_stops() -> None:
    class StopBeforeLogsProvider:
        def __init__(self) -> None:
            self.contexts: list[dict[str, object]] = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                stop_reason="no_material_read",
                scope_summary="Stop without selecting the available backend log action.",
                supporting_evidence_ids=["cluster-healthy-pod"],
            )

    provider = StopBeforeLogsProvider()
    explorer = RouteBackendExplorer()
    existing_pod = {
        "id": "cluster-healthy-pod",
        "tool": "get_resource",
        "summary": "Read the healthy backend Pod.",
        "data": {
            "kind": "Pod",
            "metadata": {"namespace": "maas", "name": "model-server-abc"},
            "spec": {"containers": [{"name": "server"}]},
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "name": "server", "ready": True, "restartCount": 0,
                }],
            },
        },
    }

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy",
        workflow_id="failure-log-recovery",
        question="Why is this backend returning HTTP 500 errors?",
        conversation=[],
        existing_evidence=[existing_pod],
    ))

    assert explorer.calls == []
    assert not any(item["id"] == "cluster-backend-logs" for item in result.evidence)


def test_grounded_candidates_prioritize_workload_evidence_after_tls_response() -> None:
    candidates = _grounded_read_candidates(
        question="Why does https://gateway.example.test/models return HTTP 500?",
        evidence=[
            {
                "id": "pod-1", "tool": "get_resource",
                "data": {
                    "kind": "Pod",
                    "metadata": {"namespace": "ingress", "name": "gateway-abc"},
                    "spec": {"containers": [{"name": "gateway"}]},
                    "status": {"phase": "Running", "containerStatuses": [{
                        "name": "gateway", "ready": True, "restartCount": 0,
                    }]},
                },
            },
            {
                "id": "probe-1", "tool": "http_probe",
                "data": {
                    "logicalHost": "gateway.example.test", "statusCode": 500,
                    "tlsVerificationRequested": False, "tls": {"verified": False},
                },
            },
        ],
        relationship_graph={"frontier": [{
            "relation": "has_endpoints", "target": "Service ingress/gateway endpoints",
            "evidence_ids": ["service-1"],
            "read_hint": {
                "tool": "list_resources", "resource": "endpointslices",
                "api_version": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                "namespace": "ingress", "label_selector": "kubernetes.io/service-name=gateway",
                "limit": 20,
            },
        }]},
        recovery_anchor_plan=None,
        seen_intents=set(),
        investigation_gaps=[
            InvestigationGap(question="Read application logs", capability="pod_logs", priority="high"),
            InvestigationGap(question="Read endpoints", capability="endpoints", priority="high"),
        ],
    )

    assert candidates[0].capability == "pod_logs"
    assert all(item.intent.tool != "list_resources" for item in candidates)


def test_agent_stop_is_not_overridden_by_structured_gap_candidate(
    tmp_path: Path, caplog,
) -> None:
    provider = GapStoppingCandidateProvider()
    explorer = RouteBackendExplorer(route_termination="passthrough")
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": (
                "Validate this Route backend: https://maas.apps.example.test/v1/models"
            )},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    assert "backend Service mapping is not collected yet" in rendered.text
    assert "podpilot.adhoc.gap_candidate_recovery" not in caplog.text


def test_empty_investigate_selection_does_not_invent_a_supplied_action(
    tmp_path: Path, caplog,
) -> None:
    provider = EmptyInvestigateRouteProvider()
    explorer = RouteBackendExplorer(route_termination="passthrough")
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": (
                "Validate this Route backend: https://maas.apps.example.test/v1/models"
            )},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    assert "podpilot.adhoc.action_candidate_recovery" not in caplog.text


def test_invalid_model_plan_does_not_trigger_a_preconceived_traffic_traversal(
    tmp_path: Path,
) -> None:
    provider = FailingTrafficPlanProvider()
    explorer = RouteBackendExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={
                "message": (
                    "This Route reports an Internal Server Error over HTTPS; inspect the backend. "
                    "https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "planner could not produce a safe typed read plan" in rendered.text
    assert "ReadPlan round 1 failed" in rendered.text
    assert explorer.calls == []
    assert provider.adhoc_answer_calls[0]["findings"] == []


def test_heading_only_route_answer_is_not_replaced_by_deterministic_prose(
    tmp_path: Path,
) -> None:
    provider = HeadingOnlyRouteProvider()
    explorer = RouteBackendExplorer(log_tail=(
        "ssl_context.load_cert_chain(\n"
        "    certfile='/etc/certs/server.pem',\n"
        "FileNotFoundError: [Errno 2] No such file or directory"
    ))
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={
                "message": (
                    "This Route reports an Internal Server Error over HTTPS; is the backend HTTP? "
                    "https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert len(provider.adhoc_answer_calls) == 1
    assert "Observed objects — what the cluster is actually doing" in rendered.text
    assert "Configured termination" not in rendered.text
    assert "Backend log findings" not in rendered.text


def test_repeated_no_read_plan_uses_operator_grounded_anchor_then_returns_to_model(
    tmp_path: Path, caplog,
) -> None:
    provider = NoReadThenHeadingOnlyRouteProvider()
    explorer = RouteBackendExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()
    caplog.set_level("INFO", logger="uvicorn.error")

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "message": (
                    "This Route reports an Internal Server Error over HTTPS; is the backend HTTP? "
                    "https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "Observed objects — what the cluster is actually doing" in rendered.text
    assert explorer.calls == []
    assert len(provider.adhoc_plan_calls) == 1
    assert provider.adhoc_plan_calls[0]["observations"] == []
    assert "podpilot.adhoc.operator_anchor_recovery" not in caplog.text


def test_natural_pod_log_request_discovers_exact_pod_then_analyzes_logs(
    tmp_path: Path,
) -> None:
    question = (
        "There is an authorino pod in kuadrant-system namespace, check its logs "
        "for errors that could generate 401 error code for the user"
    )

    class Provider(FakeModelProvider):
        def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
            self.adhoc_plan_calls.append(context)
            log_ids = [
                item["id"] for item in context["observations"]
                if item.get("tool") == "pod_logs"
            ]
            supporting_ids = log_ids or [item["id"] for item in context["observations"]]
            return ReadPlan(
                goal_type="logs",
                decision="answer_from_evidence",
                scope_summary="Stop so server recovery can prove the requested log path.",
                supporting_evidence_ids=supporting_ids,
            )

        def answer_ad_hoc(
            self, profile, api_key: str, context: dict[str, object]
        ) -> AdHocAnswer:
            self.adhoc_answer_calls.append(context)
            return AdHocAnswer(
                answer_mode="insufficient_evidence",
                conclusion_status="unresolved",
                answer="No Authorino Pod logs were collected, so the 401 cause is unresolved.",
                cited_evidence_ids=[],
            )

        def analyze_logs(
            self, profile, api_key: str, context: dict[str, object]
        ) -> AdHocLogAnalysis:
            self.log_analysis_calls.append(context)
            return AdHocLogAnalysis(
                overview="The Authorino log contains a user-facing authentication failure.",
                issues=[LogAnalysisIssue(
                    evidence_ids=["cluster-authorino-log"],
                    severity="error",
                    category="authentication",
                    summary="Authorino rejected a token because its audience was invalid.",
                    potential_impact="Affected requests receive HTTP 401 Unauthorized.",
                    supporting_excerpt="401 unauthorized: token audience invalid",
                    confidence="high",
                )],
                limitations=["Only the bounded current log tail was analyzed."],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls = []

        def execute(self, intent):
            self.calls.append(intent)
            if intent.tool == "search_resources":
                assert intent.kind == "Pod"
                assert intent.namespace == "kuadrant-system"
                assert intent.match_field == "metadata.name"
                assert intent.match_value == "authorino"
                assert intent.match_operator == "contains"
                return ReadResult((AdHocObservation(
                    id="cluster-authorino-pods",
                    tool="search_resources",
                    summary="Found one matching Authorino Pod.",
                    source="kubernetes:v1:Pod:kuadrant-system/*",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "kind": "Pod",
                        "scope": "kuadrant-system",
                        "logCandidates": [{
                            "namespace": "kuadrant-system",
                            "pod": "authorino-7fbbd96d8b-z2x9k",
                            "containers": ["authorino"],
                            "phase": "Running",
                            "ready": True,
                            "restartCount": 0,
                        }],
                    },
                ),))
            assert intent.tool == "pod_logs"
            assert intent.namespace == "kuadrant-system"
            assert intent.name == "authorino-7fbbd96d8b-z2x9k"
            assert intent.container == "authorino"
            return ReadResult((AdHocObservation(
                id="cluster-authorino-log",
                tool="pod_logs",
                summary="Collected bounded current Authorino logs.",
                source=(
                    "kubernetes:v1:Pod/log:kuadrant-system/"
                    "authorino-7fbbd96d8b-z2x9k?current"
                ),
                collected_at=datetime.now(timezone.utc),
                data={
                    "container": "authorino", "previous": False,
                    "tail": "401 unauthorized: token audience invalid",
                },
            ),))

    provider = Provider()
    explorer = Explorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}",
            updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": question},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert explorer.calls == []
    assert not provider.log_analysis_calls
    assert "No Authorino Pod logs were collected" in rendered.text
    assert "token audience invalid" not in rendered.text
    assert "Model-assisted log analysis" not in rendered.text


def test_invalid_correction_after_valid_no_read_uses_operator_grounded_anchor(
    caplog,
) -> None:
    class Provider(RouteBackendProvider):
        def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
            self.adhoc_plan_calls.append(context)
            if not context["completed_reads"]:
                if context.get("planner_feedback"):
                    raise ModelProviderError(
                        "Provider response does not match ReadPlan. Provider returned content "
                        "that failed schema validation (intents.0: value_error)."
                    )
                return ReadPlan(
                    goal_type="diagnose",
                    decision="answer_from_evidence",
                    scope_summary="Stop before collecting Route evidence.",
                )
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                scope_summary="The Route evidence is sufficient.",
                supporting_evidence_ids=["cluster-route-1"],
            )

    provider = Provider()
    explorer = RouteBackendExplorer()
    caplog.set_level("INFO", logger="uvicorn.error")

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="invalid-correction-anchor",
        question=(
            "Why does the Route https://maas.apps.example.test/v1/models return an "
            "Internal Server Error?"
        ),
        conversation=[], existing_evidence=[],
    ))

    assert explorer.calls == []
    assert result.evidence == []
    assert result.limitations == []
    assert "reason=invalid_correction" not in caplog.text


def test_removed_list_plan_stops_before_later_candidate_recovery(caplog) -> None:
    class Provider(FakeModelProvider):
        def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
            self.adhoc_plan_calls.append(context)
            completed = context["completed_reads"]
            if not completed:
                return ReadPlan(
                    goal_type="diagnose", decision="collect",
                    scope_summary="Discover Kafka resources before inspecting metrics configuration.",
                    intents=[ReadIntent(
                        tool="list_resources", resource="kafkas.kafka.strimzi.io",
                        api_version="kafka.strimzi.io/v1beta2", kind="Kafka",
                        namespace="vc-streams", limit=20,
                    )],
                )
            if len(completed) == 1:
                raise ModelProviderError(
                    "Provider response does not match ActionSelection. Provider returned content "
                    "that failed schema validation (object_reads.0: value_error).",
                    failure_type="schema_validation",
                )
            return ReadPlan(
                goal_type="diagnose", decision="answer_from_evidence",
                scope_summary="The exact Kafka configuration is available.",
                supporting_evidence_ids=["cluster-kafka-detail"],
            )

    class Explorer:
        def __init__(self) -> None:
            self.calls: list[ReadIntent] = []

        def execute(self, intent: ReadIntent) -> ReadResult:
            self.calls.append(intent)
            if intent.tool == "list_resources":
                return ReadResult((AdHocObservation(
                    id="cluster-kafka-list", tool=intent.tool,
                    summary="Read 1 Kafka resource.",
                    source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:vc-streams/*",
                    collected_at=datetime.now(timezone.utc),
                    data={
                        "resource": "kafkas.kafka.strimzi.io",
                        "apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka",
                        "scope": "vc-streams",
                        "objects": [{"namespace": "vc-streams", "name": "vc-cluster"}],
                    },
                ),))
            return ReadResult((AdHocObservation(
                id="cluster-kafka-detail", tool=intent.tool,
                summary="Read Kafka vc-streams/vc-cluster.",
                source="kubernetes:kafka.strimzi.io/v1beta2:Kafka:vc-streams/vc-cluster",
                collected_at=datetime.now(timezone.utc),
                data={
                    "kind": "Kafka", "metadata": {"namespace": "vc-streams", "name": "vc-cluster"},
                    "spec": {"kafka": {"metricsConfig": {"type": "jmxPrometheusExporter"}}},
                },
            ),))

    provider = Provider()
    explorer = Explorer()
    caplog.set_level("INFO", logger="uvicorn.error")

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=provider,
        cluster_reader=explorer,
        profile=ModelProfileConfig(
            provider_label="test", base_url="https://models.example.test/v1",
            chat_model="test", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200,
        ),
        api_key="test-api-token",
        settings=Settings(
            auth_mode="test", role_investigator_groups=[], role_approver_groups=[],
            role_breakglass_groups=[],
        ),
        actor="ivy", workflow_id="invalid-plan-candidate-recovery",
        question="Do the Kafka clusters have Prometheus metrics exporting set up?",
        conversation=[], existing_evidence=[],
    ))

    assert explorer.calls == []
    assert not any(item["id"] == "cluster-kafka-detail" for item in result.evidence)
    assert "removed list_resources helper" in " ".join(result.limitations)
    assert "podpilot.adhoc.invalid_plan_candidate_recovery" not in caplog.text
    assert "failed schema validation" not in caplog.text


def test_removed_list_helper_prevents_implicit_route_pod_log_expansion(
    tmp_path: Path,
) -> None:
    provider = RouteOnlyAnswerProvider()
    explorer = RouteBackendExplorer(
        route_termination="passthrough",
        log_tail=(
            "ssl_context.load_cert_chain(\n"
            "    certfile='/etc/certs/server.pem',\n"
            "FileNotFoundError: [Errno 2] No such file or directory"
        ),
    )
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={
                "message": (
                    "This Route reports an Internal Server Error over HTTPS; is the backend HTTP? "
                    "https://maas.apps.example.test/v1/models"
                )
            },
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    # The model-authored answer is retained without server-authored log prose.
    assert len(provider.adhoc_answer_calls) == 1
    assert provider.log_analysis_calls == []
    assert not any(
        item["tool"] == "pod_logs"
        for item in provider.adhoc_answer_calls[0]["observations"]
    )
    assert "router forwards the client TLS stream" in rendered.text
    assert "Model-assisted log analysis" not in rendered.text
    assert "backend process could not load its configured PEM certificate" not in rendered.text
    assert "passthrough" in rendered.text
    assert "Backend log findings" not in rendered.text
    assert "removed list_resources helper" in rendered.text


def test_ask_namespace_top_cpu_uses_deterministic_metric_read_without_model_plan(
    tmp_path: Path,
) -> None:
    provider = NamespaceMetricProvider()
    explorer = NamespaceMetricExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "What workloads are using the most CPU in openshift-logging?"},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert "Top CPU Consumers" in rendered.text
    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1
    assert len(explorer.calls) == 1
    assert explorer.calls[0].tool == "query_metrics"
    assert explorer.calls[0].metric == "top_cpu_consumers"
    assert explorer.calls[0].metric_scope == "namespace"
    assert explorer.calls[0].namespace == "openshift-logging"
    assert "Top CPU Consumers" in rendered.text
    assert "collector-1" in rendered.text
    assert "0.900 cores" in rendered.text
    assert "Download CSV" in rendered.text
    assert re.search(r'data-csv-table="metric-table-[^"]+-metric-cpu-1"', rendered.text)


def test_ask_cluster_operator_status_uses_typed_health_summary(
    tmp_path: Path,
) -> None:
    provider = ImpliedHealthProvider()
    explorer = ClusterOperatorExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check the status of the cluster operators"},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert rendered.status_code == 200
        assert "All observed ClusterOperators are Available" in rendered.text
        assert "cluster-operators-1" not in rendered.text

    assert explorer.calls == []
    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1


def test_ask_typed_cluster_operator_health_overrides_model_refusal(
    tmp_path: Path,
) -> None:
    provider = RefusingCatalogProvider()
    explorer = ClusterOperatorExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check the status of the cluster operators"},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "All observed ClusterOperators are Available" in rendered.text
        assert "cluster-operators-1" not in rendered.text

    assert provider.adhoc_plan_calls
    assert len(provider.adhoc_answer_calls) == 1
    assert explorer.calls == []


def test_ask_uses_safely_reduced_active_profile_without_chat_warning(
    tmp_path: Path,
) -> None:
    provider = FailingAdHocProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="reduced_capability",
            capabilities_json=json.dumps({
                "reachable": True, "tls_valid": True, "authenticated": True,
                "model_available": True, "structured_output": True,
                "ask_schemas": False,
            }),
            last_error="ReadPlan probe failed. Synthetic semantic mismatch.", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Show Pods in namespace ai-ops"},
            follow_redirects=False,
        )
        assert created.status_code == 303
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert rendered.status_code == 200
        assert "Model running with reduced capability" not in rendered.text
        assert "ReadPlan probe failed. Synthetic semantic mismatch." not in rendered.text
        assert "Model profile not ready" not in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assistant = db_session.scalar(select(AdHocMessage).where(AdHocMessage.role == "assistant"))
        assert assistant is not None
        assert assistant.provider_status == "reduced_capability"
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
        assert "Evidence used in this answer" in rendered.text
        assert "Inspected 2 cluster targets" not in rendered.text
        assert "cluster-api-logs" in rendered.text
        assert "exact Pod name is needed" not in rendered.text

    assert [call.tool for call in explorer.calls] == ["search_resources", "pod_logs"]
    assert provider.adhoc_plan_calls[1]["tool_policy"]["remaining_reads"] == (
        settings.adhoc_max_reads_per_turn - 1
    )
    assert provider.adhoc_plan_calls[1]["completed_reads"][0]["round"] == 1
    assert provider.adhoc_plan_calls[2]["observations"][-1]["tool"] == "pod_logs"


def test_ask_rejects_synthesized_log_targets_and_falls_back_to_exact_candidates(
    tmp_path: Path,
) -> None:
    provider = InvalidLogTargetsThenFallbackProvider()
    explorer = ExactCandidateFallbackExplorer()
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
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Check the latest kube API server logs for errors."},
            follow_redirects=False,
        )
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})

    assert rendered.status_code == 200
    assert "used exact discovered Pod/container targets" not in rendered.text
    assert [call.tool for call in explorer.calls] == ["search_resources"]
    repaired_contexts = [
        context for context in provider.adhoc_plan_calls
            if context.get("planner_feedback", {}).get("code") == "model_target_not_grounded"
    ]
    assert len(repaired_contexts) == 1
    fallback_candidates = repaired_contexts[0]["tool_policy"]["pod_log_candidates"]
    assert len(fallback_candidates) == 4
    assert [item["investigation_priority"] for item in fallback_candidates[:3]] == [
        "normal", "elevated", "elevated",
    ]
    assert fallback_candidates[3]["investigation_priority"] == "normal"


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


def test_new_ask_renders_real_read_only_starter_actions(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource()
    )
    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})

    assert page.status_code == 200
    assert 'data-starter-prompt="Find currently failing or unhealthy workloads' in page.text
    assert "Treat every Pod outside Running or Succeeded as unhealthy" in page.text
    assert 'data-starter-prompt="Review Kubernetes warning events from the last hour' not in page.text
    assert "Review recent warnings" not in page.text
    assert "data-workload-starter-open" in page.text
    assert "data-workload-starter-form" in page.text
    assert "Why is pod api-7d9 pending" not in page.text
    assert "Show my access" not in page.text
    assert "List my projects" not in page.text


def test_delegated_operator_connects_and_stamps_unrestricted_conversation(
    tmp_path: Path, monkeypatch,
) -> None:
    from podpilot_openshift.delegated import DelegatedIdentity

    revoked_tokens: list[str] = []

    class LoginClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def login(self, username: str, password: str) -> DelegatedIdentity:
            assert username == "dev-user"
            assert password == "one-time-password"
            assert self.kwargs["custom_ca_pem"] is None
            return DelegatedIdentity(
                username="dev-user", uid="remote-uid", token="sha256~delegated-token"
            )

        def revoke(self, _token: str) -> bool:
            revoked_tokens.append(_token)
            return True

    monkeypatch.setattr("podpilot_api.main.OpenShiftDelegatedLoginClient", LoginClient)
    app, settings = make_app(
        tmp_path,
        assignments={"dana": Role.DELEGATED_OPERATOR},
        source=FakeAlertSource(),
        settings_overrides={"delegated_access_enabled": True},
    )
    cluster_id = "50000000-0000-0000-0000-000000000001"
    engine = build_engine(settings)
    with TestClient(app) as client:
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            db_session.add(Cluster(
                id=cluster_id,
                name="East DEV",
                api_url="https://api.east-dev.example:6443",
                credential_key=None,
                tags_json='{"environment":"dev"}',
                tls_verify=True,
                is_enabled=True,
                is_system=False,
                status="ready",
                created_by="ada",
                updated_by="ada",
                created_at=now,
                updated_at=now,
            ))
            db_session.add(ModelProfile(
                id=1,
                provider_label="Test",
                base_url="https://models.example.test/v1",
                chat_model="test-model",
                embedding_model=None,
                timeout_seconds=30,
                max_output_tokens=1200,
                status="ready",
                capabilities_json='{"structured_output": true}',
                updated_by="dana",
            ))
            db_session.commit()

        redirected = client.get(
            "/ask", headers={"x-forwarded-user": "dana"}, follow_redirects=False
        )
        assert redirected.status_code == 303
        assert redirected.headers["location"] == "/delegated/connect"
        cluster_redirect = client.get(
            f"/clusters/{cluster_id}/ask",
            headers={"x-forwarded-user": "dana"},
            follow_redirects=False,
        )
        assert cluster_redirect.status_code == 303
        assert cluster_redirect.headers["location"].startswith(
            f"/delegated/connect?retry={cluster_id}&"
        )
        page = client.get("/delegated/connect", headers={"x-forwarded-user": "dana"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        assert settings.cluster_name in page.text
        assert "PodPilot system cluster" in page.text
        connected = client.post(
            "/api/v1/delegated-sessions/connect",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
            data={
                "cluster_ids": json.dumps([cluster_id]),
                "username": "dev-user",
                "password": "one-time-password",
                "consent": "on",
            },
        )
        assert connected.status_code == 200
        assert "podpilot_delegated_session" in connected.headers["set-cookie"]
        ask_page = client.get("/ask", headers={"x-forwarded-user": "dana"})
        assert "Investigate · read-only" in ask_page.text
        assert 'href="/delegated/connect">Cluster sign-ins</a>' not in ask_page.text
        assert "Find failing workloads" in ask_page.text
        assert "Review recent warnings" not in ask_page.text
        assert "Show my access" in ask_page.text
        assert "List my projects" in ask_page.text
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "List projects", "cluster_ids": json.dumps([cluster_id])},
            follow_redirects=False,
        )
        assert created.status_code == 303
        conversation_id = created.headers["location"].rsplit("/", 1)[-1]
        with Session(engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            assert conversation.execution_mode == "read_only"
            assert conversation.delegated_session_id
            assert json.loads(conversation.cluster_ids_json) == [cluster_id]
        conversation_page = client.get(
            created.headers["location"], headers={"x-forwarded-user": "dana"}
        )
        assert "execution-mode-read-only" in conversation_page.text
        assert "execution-mode-read-write" not in conversation_page.text
        assert "Delegated read-only mode" in conversation_page.text
        assert "broker blocks Kubernetes mutations" in conversation_page.text
        assert "This conversation remains read-only" in conversation_page.text
        assert "Delegated Action mode" not in conversation_page.text
        assert "agent-mode-pill" not in conversation_page.text
        client.cookies.delete("podpilot_delegated_session")
        ended_page = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "dana"}
        )
        assert "Cluster session needs reconnection" in ended_page.text
        assert f"retry={cluster_id}" in ended_page.text
        assert 'href="/ask?new=1">start a new conversation</a>' in ended_page.text
        ended_composer = re.search(
            r'<textarea id="adhoc-message"[^>]*>', ended_page.text
        )
        assert ended_composer is not None
        assert "disabled" in ended_composer.group(0)

        replacement_session_id = app.state.delegated_vault.new_session_id()
        app.state.delegated_vault.put(
            session_id=replacement_session_id,
            owner="dana",
            cluster_id=cluster_id,
            remote_username="dev-user",
            remote_uid="remote-uid",
            token="sha256~replacement-token",
        )
        client.cookies.set("podpilot_delegated_session", replacement_session_id)
        recovered_page = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "dana"}
        )
        recovered_composer = re.search(
            r'<textarea id="adhoc-message"[^>]*>', recovered_page.text
        )
        assert recovered_composer is not None
        assert "disabled" not in recovered_composer.group(0)
        continued = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Continue with my current cluster sign-in."},
            follow_redirects=False,
        )
        assert continued.status_code == 303
        with Session(engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            assert conversation.delegated_session_id == replacement_session_id

        connect_page = client.get(
            "/delegated/connect", headers={"x-forwarded-user": "dana"}
        )
        connected_checkbox = re.search(
            rf'<input[^>]+value="{cluster_id}"[^>]+>', connect_page.text
        )
        assert connected_checkbox is not None
        assert 'data-connected="true"' in connected_checkbox.group(0)
        assert "disabled" in connected_checkbox.group(0)
        assert "Start new conversation" not in connect_page.text
        assert "Remove all sign-ins" in connect_page.text
        disconnected = client.post(
            "/api/v1/delegated-sessions/disconnect",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
        )
        assert disconnected.status_code == 200
        assert disconnected.json()["disconnected"][0]["cluster_id"] == cluster_id
        assert app.state.delegated_vault.list_for(
            session_id=replacement_session_id, owner="dana"
        ) == []
        assert "sha256~replacement-token" in revoked_tokens
    engine.dispose()


def test_delegated_session_adds_and_removes_individual_cluster_sign_ins(
    tmp_path: Path, monkeypatch,
) -> None:
    from podpilot_openshift.delegated import DelegatedIdentity

    revoked_tokens: list[str] = []

    class LoginClient:
        def __init__(self, **kwargs) -> None:
            self.api_url = str(kwargs["api_url"])

        def login(self, username: str, password: str) -> DelegatedIdentity:
            assert (username, password) == ("dev-user", "one-time-password")
            suffix = "central" if "central" in self.api_url else "east"
            return DelegatedIdentity(
                username="dev-user",
                uid=f"uid-{suffix}",
                token=f"sha256~{suffix}-token",
            )

        def revoke(self, token: str) -> bool:
            revoked_tokens.append(token)
            return True

    monkeypatch.setattr("podpilot_api.main.OpenShiftDelegatedLoginClient", LoginClient)
    app, settings = make_app(
        tmp_path,
        assignments={"dana": Role.DELEGATED_OPERATOR},
        source=FakeAlertSource(),
        settings_overrides={"delegated_access_enabled": True},
    )
    central_id = "51000000-0000-0000-0000-000000000001"
    east_id = "51000000-0000-0000-0000-000000000002"
    engine = build_engine(settings)
    with TestClient(app) as client:
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            for cluster_id, name, slug in (
                (central_id, "Central DEV", "central-dev"),
                (east_id, "East DEV", "east-dev"),
            ):
                db_session.add(Cluster(
                    id=cluster_id,
                    name=name,
                    environment="dev",
                    api_url=f"https://api.{slug}.example:6443",
                    credential_key=None,
                    tags_json='{"environment":"dev"}',
                    tls_verify=True,
                    is_enabled=True,
                    is_system=False,
                    status="ready",
                    created_by="ada",
                    updated_by="ada",
                    created_at=now,
                    updated_at=now,
                ))
            db_session.commit()

        page = client.get("/delegated/connect", headers={"x-forwarded-user": "dana"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        headers = {"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)}
        credentials = {
            "username": "dev-user",
            "password": "one-time-password",
            "consent": "on",
        }
        first = client.post(
            "/api/v1/delegated-sessions/connect",
            headers=headers,
            data={**credentials, "cluster_ids": json.dumps([central_id])},
        )
        assert first.status_code == 200
        session_id = client.cookies.get("podpilot_delegated_session")
        assert session_id

        second = client.post(
            "/api/v1/delegated-sessions/connect",
            headers=headers,
            data={**credentials, "cluster_ids": json.dumps([east_id])},
        )
        assert second.status_code == 200
        assert client.cookies.get("podpilot_delegated_session") == session_id
        assert {
            item.cluster_id for item in app.state.delegated_vault.list_for(
                session_id=session_id, owner="dana"
            )
        } == {central_id, east_id}

        connect_page = client.get(
            "/delegated/connect", headers={"x-forwarded-user": "dana"}
        )
        assert "Add clusters from one environment" in connect_page.text
        assert "Existing sign-ins stay connected" in connect_page.text
        assert "Credentials are scoped by environment" not in connect_page.text
        assert "warning-notice" not in connect_page.text
        assert connect_page.text.count("data-delegated-remove-url=") == 2
        assert "Add selected clusters" in connect_page.text

        removed = client.post(
            f"/api/v1/delegated-sessions/connections/{central_id}/disconnect",
            headers=headers,
        )
        assert removed.status_code == 200
        assert removed.json()["disconnected"]["cluster_id"] == central_id
        assert [
            item.cluster_id for item in app.state.delegated_vault.list_for(
                session_id=session_id, owner="dana"
            )
        ] == [east_id]
        assert "sha256~central-token" in revoked_tokens
        assert "sha256~east-token" not in revoked_tokens

        ask_page = client.get("/ask?new=1", headers={"x-forwarded-user": "dana"})
        assert "East DEV" in ask_page.text
        assert "Central DEV" in ask_page.text
        assert 'class="cluster-session-status connected"' in ask_page.text
        assert 'class="cluster-session-status disconnected"' in ask_page.text
        assert 'aria-label="Available clusters"' in ask_page.text
        assert 'aria-label="Add a personal cluster"' in ask_page.text
        assert 'href="/clusters/personal?new=1"' in ask_page.text
        assert "Select cluster(s) first" in ask_page.text
        ask_checkboxes = re.findall(
            r'<input[^>]+data-cluster-checkbox[^>]+>', ask_page.text
        )
        assert ask_checkboxes
        assert all("checked" not in item for item in ask_checkboxes)

        east_start = client.get(
            f"/clusters/{east_id}/ask",
            headers={"x-forwarded-user": "dana"},
            follow_redirects=False,
        )
        assert east_start.status_code == 303
        assert east_start.headers["location"] == f"/ask?new=1&cluster_ids={east_id}"
        east_page = client.get(
            east_start.headers["location"], headers={"x-forwarded-user": "dana"}
        )
        east_checkbox = re.search(
            rf'<input[^>]+value="{east_id}"[^>]+>', east_page.text
        )
        central_checkbox = re.search(
            rf'<input[^>]+value="{central_id}"[^>]+>', east_page.text
        )
        assert east_checkbox is not None and "checked" in east_checkbox.group(0)
        assert central_checkbox is not None and "checked" not in central_checkbox.group(0)
        assert 'data-connected="false"' in central_checkbox.group(0)

        central_start = client.get(
            f"/clusters/{central_id}/ask",
            headers={"x-forwarded-user": "dana"},
            follow_redirects=False,
        )
        assert central_start.status_code == 303
        assert central_start.headers["location"].startswith(
            f"/delegated/connect?retry={central_id}&"
        )
        assert f"cluster_id%3D{central_id}" in central_start.headers["location"]

        expanded_start = client.get(
            f"/ask?new=1&cluster_ids={east_id},{central_id}",
            headers={"x-forwarded-user": "dana"},
            follow_redirects=False,
        )
        assert expanded_start.status_code == 303
        assert expanded_start.headers["location"].startswith(
            f"/delegated/connect?retry={central_id}&"
        )
        assert f"cluster_ids%3D{east_id}%2C{central_id}" in expanded_start.headers["location"]
    engine.dispose()


def test_delegated_operator_can_connect_the_system_cluster(
    tmp_path: Path, monkeypatch,
) -> None:
    from podpilot_openshift.delegated import DelegatedIdentity

    clients: list[dict[str, object]] = []

    class LoginClient:
        def __init__(self, **kwargs) -> None:
            clients.append(kwargs)

        def login(self, username: str, password: str) -> DelegatedIdentity:
            assert (username, password) == ("local-user", "one-time-password")
            return DelegatedIdentity(
                username="local-user", uid="local-uid", token="sha256~local-token"
            )

        def revoke(self, _token: str) -> bool:
            return True

    api_ca_path = tmp_path / "api-ca.crt"
    service_ca_path = tmp_path / "service-ca.crt"
    api_ca_path.write_text("api-ca", encoding="utf-8")
    service_ca_path.write_text("service-ca", encoding="utf-8")
    monkeypatch.setattr("podpilot_api.main.OpenShiftDelegatedLoginClient", LoginClient)
    app, _ = make_app(
        tmp_path,
        assignments={"dana": Role.DELEGATED_OPERATOR},
        source=FakeAlertSource(),
        settings_overrides={
            "delegated_access_enabled": True,
            "service_account_ca_path": api_ca_path,
            "service_ca_path": service_ca_path,
        },
    )

    with TestClient(app) as client:
        page = client.get("/delegated/connect", headers={"x-forwarded-user": "dana"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        connected = client.post(
            "/api/v1/delegated-sessions/connect",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
            data={
                "cluster_ids": json.dumps([SYSTEM_CLUSTER_ID]),
                "username": "local-user",
                "password": "one-time-password",
                "consent": "on",
            },
        )

    assert connected.status_code == 200
    assert connected.json()["connected"][0]["cluster_id"] == SYSTEM_CLUSTER_ID
    assert clients[0]["api_url"] == "https://kubernetes.default.svc"
    assert clients[0]["authorization_endpoint_override"] == (
        "https://oauth-openshift.openshift-authentication.svc/oauth/authorize"
    )
    assert clients[0]["custom_ca_pem"] == "api-ca\nservice-ca\n"


def test_partial_delegated_login_keeps_successes_and_preselects_retry(
    tmp_path: Path, monkeypatch,
) -> None:
    from podpilot_openshift.delegated import DelegatedIdentity, DelegatedLoginError

    class LoginClient:
        def __init__(self, **kwargs) -> None:
            self.api_url = kwargs["api_url"]

        def login(self, _username: str, _password: str) -> DelegatedIdentity:
            if "failed" in self.api_url:
                raise DelegatedLoginError("The credentials were rejected.")
            return DelegatedIdentity(
                username="dev-user", uid="remote-uid", token="sha256~working-token"
            )

        def revoke(self, _token: str) -> bool:
            return True

    monkeypatch.setattr("podpilot_api.main.OpenShiftDelegatedLoginClient", LoginClient)
    app, settings = make_app(
        tmp_path,
        assignments={"dana": Role.DELEGATED_OPERATOR},
        source=FakeAlertSource(),
        settings_overrides={"delegated_access_enabled": True},
    )
    working_id = "50500000-0000-0000-0000-000000000001"
    failed_id = "50500000-0000-0000-0000-000000000002"
    engine = build_engine(settings)
    with TestClient(app) as client:
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            for cluster_id, name, host in (
                (working_id, "Working DEV", "working"),
                (failed_id, "Failed DEV", "failed"),
            ):
                db_session.add(Cluster(
                    id=cluster_id,
                    name=name,
                    api_url=f"https://api.{host}.example:6443",
                    credential_key=None,
                    tags_json='{"environment":"dev"}',
                    environment="dev",
                    visibility="shared",
                    owner=None,
                    tls_verify=True,
                    is_enabled=True,
                    is_system=False,
                    status="ready",
                    created_by="ada",
                    updated_by="ada",
                    created_at=now,
                    updated_at=now,
                ))
            db_session.commit()
        page = client.get("/delegated/connect", headers={"x-forwarded-user": "dana"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        connected = client.post(
            "/api/v1/delegated-sessions/connect",
            headers={"x-forwarded-user": "dana", "x-podpilot-csrf": csrf.group(1)},
            data={
                "cluster_ids": json.dumps([working_id, failed_id]),
                "username": "dev-user",
                "password": "one-time-password",
                "consent": "on",
            },
        )
        assert connected.status_code == 200
        assert [item["cluster_id"] for item in connected.json()["connected"]] == [working_id]
        assert [item["cluster_id"] for item in connected.json()["failed"]] == [failed_id]

        retry_page = client.get(
            f"/delegated/connect?retry={failed_id}&next=/ask?new=1",
            headers={"x-forwarded-user": "dana"},
        )
        working_checkbox = re.search(
            rf'<input[^>]+value="{working_id}"[^>]+>', retry_page.text
        )
        failed_checkbox = re.search(
            rf'<input[^>]+value="{failed_id}"[^>]+>', retry_page.text
        )
        assert working_checkbox is not None and failed_checkbox is not None
        assert 'data-connected="true"' in working_checkbox.group(0)
        assert "disabled" in working_checkbox.group(0)
        assert "checked" in failed_checkbox.group(0)
        assert 'value="/ask?new=1"' in retry_page.text
    engine.dispose()


def test_read_write_user_selects_action_mode_while_investigator_is_read_only(
    tmp_path: Path,
) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "ada": Role.APPROVER},
        source=FakeAlertSource(),
        settings_overrides={"delegated_access_enabled": True},
    )
    cluster_id = "51000000-0000-0000-0000-000000000001"
    engine = build_engine(settings)
    with TestClient(app) as client:
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            db_session.add(Cluster(
                id=cluster_id,
                name="Shared DEV",
                api_url="https://api.shared-dev.example:6443",
                credential_key=None,
                tags_json="{}",
                environment="dev",
                visibility="shared",
                owner=None,
                tls_verify=True,
                is_enabled=True,
                is_system=False,
                status="ready",
                created_by="ada",
                updated_by="ada",
                created_at=now,
                updated_at=now,
            ))
            db_session.add(ModelProfile(
                id=1,
                provider_label="OpenRouter",
                base_url="https://openrouter.ai/api/v1",
                chat_model="test-agent",
                api_type="chat-completions",
                embedding_model=None,
                timeout_seconds=30,
                max_output_tokens=1200,
                status="ready",
                capabilities_json='{"tool_calls": true}',
                updated_by="ada",
            ))
            db_session.commit()

        for username, requested_mode, expected_status in (
            ("ivy", "action", 403),
            ("ada", "action", 303),
        ):
            session_id = app.state.delegated_vault.new_session_id()
            app.state.delegated_vault.put(
                session_id=session_id,
                owner=username,
                cluster_id=cluster_id,
                remote_username=username,
                remote_uid=f"uid-{username}",
                token=f"token-{username}",
            )
            client.cookies.set("podpilot_delegated_session", session_id)
            page = client.get("/ask", headers={"x-forwarded-user": username})
            csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
            assert csrf is not None
            response = client.post(
                "/api/v1/adhoc-conversations",
                headers={"x-forwarded-user": username, "x-podpilot-csrf": csrf.group(1)},
                data={
                    "message": "Check the selected cluster.",
                    "cluster_ids": json.dumps([cluster_id]),
                    "execution_mode": requested_mode,
                },
                follow_redirects=False,
            )
            assert response.status_code == expected_status

        conversation_id = response.headers["location"].rsplit("/", 1)[-1]
        with Session(engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            assert conversation.execution_mode == "action"
            assert conversation.delegated_session_id
        action_page = client.get(
            response.headers["location"], headers={"x-forwarded-user": "ada"}
        )
        assert 'class="ask-layout action-session"' in action_page.text
        assert "execution-mode-read-write" in action_page.text
        assert "execution-mode-read-only" not in action_page.text
        assert "Delegated Action mode" in action_page.text
        assert "may create, patch, apply, or delete objects directly" in action_page.text
        assert "There is no PodPilot preview or approval step" in action_page.text
        assert "change selected clusters using your OpenShift identity" not in action_page.text
        assert "agent-mode-pill" in action_page.text
    engine.dispose()


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


def test_active_ask_progress_renders_each_update_message_once(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        settings_overrides={"adhoc_job_worker_enabled": False},
    )
    conversation_id = "00000000-0000-0000-0000-000000000188"
    repeated = "Planning safe read-only checks."
    events = [
        {"seq": 0, "phase": "planning", "message": repeated},
        {"seq": 1, "phase": "planning", "message": repeated},
        {"seq": 2, "phase": "replanning", "message": repeated},
        {"seq": 3, "phase": "next_check", "message": "Collect selected evidence."},
    ]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Unique progress",
            status="active", evidence_json="[]",
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000187",
            conversation_id=conversation_id,
            role="user",
            actor="ivy",
            content="Investigate safely",
        ))
        db_session.add(AdHocRun(
            id="00000000-0000-0000-0000-000000000189",
            conversation_id=conversation_id,
            created_by="ivy",
            message_text="Investigate safely",
            status="queued",
            phase="next_check",
            progress_json=json.dumps(events),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})

    assert page.status_code == 200
    assert page.text.count(repeated) == 1
    assert 'data-progress-phase="replanning"' not in page.text


def test_owner_can_delete_queued_conversation_and_evidence_with_audit_record(
    tmp_path: Path,
) -> None:
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
        db_session.add(AdHocRun(
            id="00000000-0000-0000-0000-000000000091",
            conversation_id=conversation_id,
            created_by="ivy",
            message_text="Delete me",
            status="queued",
            phase="queued",
            progress_json="[]",
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
        assert db_session.scalar(
            select(func.count()).select_from(AdHocRun).where(
                AdHocRun.conversation_id == conversation_id
            )
        ) == 0
        event = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "adhoc.delete"))
        assert event is not None and event.actor == "ivy"
        assert json.loads(event.details_json)["cancelled_run_count"] == 1
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

    assert len(provider.adhoc_plan_calls[0]["conversation"]) == 4
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


def test_ask_job_returns_immediately_and_streams_private_progress(tmp_path: Path) -> None:
    provider = BlockingAdHocProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "ada": Role.APPROVER},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
        settings_overrides={
            "adhoc_job_worker_enabled": True,
            "adhoc_worker_concurrency": 1,
        },
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={
                "message": "Why is pod api-7d9 pending in payments?",
                "include_raw_response": "on",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert provider.answer_started.wait(timeout=2)
        conversation_id = created.headers["location"].rsplit("/", 1)[-1]

        pending_page = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Live investigation" in pending_page.text
        assert "thinking-spinner" in pending_page.text
        assert re.search(
            r'name="include_raw_response"\s+checked\s+disabled', pending_page.text
        )
        run_match = re.search(r'data-adhoc-run-id="([^"]+)"', pending_page.text)
        assert run_match is not None
        run_id = run_match.group(1)

        status_response = client.get(
            f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert status_response.status_code == 200
        assert status_response.json()["status"] == "running"
        assert any(
            event["phase"] in {"planning", "collecting", "answering"}
            for event in status_response.json()["events"]
        )
        hidden = client.get(
            f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ada"}
        )
        assert hidden.status_code == 404
        hidden_events = client.get(
            f"/api/v1/adhoc-runs/{run_id}/events", headers={"x-forwarded-user": "ada"}
        )
        assert hidden_events.status_code == 404
        second = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Investigate a separate session while the worker is busy."},
            follow_redirects=False,
        )
        assert second.status_code == 303
        queued_page = client.get(second.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Waiting to investigate" in queued_page.text
        assert (
            "Question queued. It will start automatically when the investigation worker is available."
            in queued_page.text
        )
        overlapping = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Run another check while this one is active."},
        )
        assert overlapping.status_code == 409
        delete_active = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/delete",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert delete_active.status_code == 303
        assert delete_active.headers["location"] == "/ask"

        provider.release_answer.set()
        assert client.get(
            f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
        ).status_code == 404
        assert client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"}
        ).status_code == 404

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.get(AdHocRun, run_id) is None
        event = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "adhoc.delete")
        )
        assert event is not None
        assert json.loads(event.details_json)["cancelled_run_count"] == 1
    engine.dispose()


def test_user_cancels_active_ask_run_and_correlated_runner_request(tmp_path: Path) -> None:
    provider = BlockingAdHocProvider()

    class Runner:
        def __init__(self) -> None:
            self.cancelled: list[str] = []

        def execute(self, *_args, **_kwargs):
            raise AssertionError("The synthetic provider should remain in its model call.")

        def cancel(self, request_id: str) -> bool:
            self.cancelled.append(request_id)
            return True

    runner = Runner()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
        agent_runner=runner,
        settings_overrides={
            "adhoc_job_worker_enabled": True,
            "adhoc_worker_concurrency": 1,
        },
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    runner_request_id = "00000000-0000-0000-0000-000000000104"
    with TestClient(app) as client:
        page = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/adhoc-conversations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Inspect the selected cluster."},
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert provider.answer_started.wait(timeout=2)
        conversation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            run_id = db_session.scalar(select(AdHocRun.id).where(
                AdHocRun.conversation_id == conversation_id
            ))
        engine.dispose()
        assert run_id is not None
        app.state.adhoc_runner_requests[run_id] = {runner_request_id}

        active = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert (
            f'data-run-cancel data-cancel-url="/api/v1/adhoc-runs/{run_id}/cancel"'
            in active.text
        )
        assert "Cancel request</button>" not in active.text
        textarea = re.search(r'<textarea id="adhoc-message"[^>]*>', active.text)
        assert textarea is not None and "disabled" not in textarea.group(0)

        cancelled = client.post(
            f"/api/v1/adhoc-runs/{run_id}/cancel",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["runner_cancellation_attempted"] is True
        assert cancelled.json()["runner_terminations"] == 1
        assert runner.cancelled == [runner_request_id]
        provider.release_answer.set()

        status = client.get(
            f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert status.status_code == 200
        assert status.json()["status"] == "cancelled"
        rendered = client.get(
            created.headers["location"], headers={"x-forwarded-user": "ivy"}
        )
        assert "Investigation cancelled at your request" in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        event = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "adhoc.cancel"))
        assert event is not None and event.outcome == "cancelled"
    engine.dispose()


def test_ask_worker_pool_runs_different_users_concurrently(tmp_path: Path) -> None:
    provider = ConcurrentBlockingAdHocProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "ada": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
        settings_overrides={
            "adhoc_job_worker_enabled": True,
            "adhoc_worker_concurrency": 3,
            "adhoc_max_concurrent_runs_per_user": 1,
        },
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        run_targets = []
        csrf_tokens = {}
        for username in ("ivy", "ada"):
            page = client.get("/ask", headers={"x-forwarded-user": username})
            csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
            assert csrf is not None
            csrf_tokens[username] = csrf.group(1)
            created = client.post(
                "/api/v1/adhoc-conversations",
                headers={
                    "x-forwarded-user": username,
                    "x-podpilot-csrf": csrf.group(1),
                },
                data={
                    "message": (
                        f"Investigate pod api-7d9 in namespace payments for {username}."
                    )
                },
                follow_redirects=False,
            )
            assert created.status_code == 303
            conversation_id = created.headers["location"].rsplit("/", 1)[-1]
            run_targets.append((username, conversation_id))

        assert provider.two_answers_started.wait(timeout=3)
        assert provider.max_active_answers == 2
        engine = build_engine(settings)
        with Session(engine) as db_session:
            assert db_session.scalar(
                select(func.count()).select_from(AdHocRun).where(AdHocRun.status == "running")
            ) == 2
        engine.dispose()

        same_user = client.post(
            "/api/v1/adhoc-conversations",
            headers={
                "x-forwarded-user": "ivy",
                "x-podpilot-csrf": csrf_tokens["ivy"],
            },
            data={"message": "Investigate pod api-7d9 in namespace payments again."},
            follow_redirects=False,
        )
        assert same_user.status_code == 303
        same_user_conversation_id = same_user.headers["location"].rsplit("/", 1)[-1]
        queued_page = client.get(
            same_user.headers["location"], headers={"x-forwarded-user": "ivy"}
        )
        assert "Waiting to investigate" in queued_page.text
        engine = build_engine(settings)
        with Session(engine) as db_session:
            assert db_session.scalar(
                select(func.count()).select_from(AdHocRun).where(AdHocRun.status == "queued")
            ) == 1
        engine.dispose()

        provider.release_answers.set()
        run_targets.append(("ivy", same_user_conversation_id))
        for username, conversation_id in run_targets:
            completed = False
            for _ in range(60):
                page = client.get(
                    f"/ask/{conversation_id}", headers={"x-forwarded-user": username}
                )
                if "selector does not match" in page.text:
                    completed = True
                    break
                time.sleep(0.05)
            assert completed


def test_ask_job_deadline_persists_terminal_failure_and_stops_spinner(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = BlockingAdHocProvider()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=FakeReadExplorer(),
        settings_overrides={
            "adhoc_job_worker_enabled": True,
            "adhoc_run_timeout_seconds": 1,
        },
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
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
            data={"message": "Why is pod api-7d9 pending in payments?"},
            follow_redirects=False,
        )
        assert provider.answer_started.wait(timeout=2)
        conversation_id = created.headers["location"].rsplit("/", 1)[-1]
        engine = build_engine(settings)
        with Session(engine) as db_session:
            run_id = db_session.scalar(select(AdHocRun.id).where(
                AdHocRun.conversation_id == conversation_id
            ))
        engine.dispose()
        terminal = None
        for _ in range(60):
            terminal = client.get(
                f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
            ).json()
            if terminal["status"] == "failed":
                break
            time.sleep(0.05)
        provider.release_answer.set()
        assert terminal is not None and terminal["status"] == "failed"
        assert terminal["phase"] == "failed"
        assert terminal["events"][-1]["phase"] == "failed"
        rendered = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "exceeded the execution deadline" in rendered.text
        assert "last recorded operation was:" in rendered.text
        assert "Working on your question" not in rendered.text
        assert "last_phase=" in caplog.text
        assert "last_progress=" in caplog.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.get(AdHocRun, run_id)
        assert run is not None and run.completed_at is not None
        assert run.error_detail == "Investigation exceeded the 1-second execution deadline."
        messages = list(db_session.scalars(select(AdHocMessage).where(
            AdHocMessage.conversation_id == conversation_id,
            AdHocMessage.role == "assistant",
        )))
        assert len(messages) == 1
    engine.dispose()


def test_ask_worker_requeues_interrupted_persisted_run_on_startup(tmp_path: Path) -> None:
    run_id = "00000000-0000-0000-0000-000000000094"
    conversation_id = "00000000-0000-0000-0000-000000000095"
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=FakeModelProvider(),
        read_explorer=FakeReadExplorer(),
        settings_overrides={"adhoc_job_worker_enabled": True},
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.add(AdHocConversation(
            id=conversation_id,
            created_by="ivy",
            title="Interrupted question",
            status="active",
            evidence_json="[]",
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000096",
            conversation_id=conversation_id,
            role="user",
            actor="ivy",
            content="Why is pod api-7d9 pending in payments?",
        ))
        db_session.add(AdHocRun(
            id=run_id,
            conversation_id=conversation_id,
            created_by="ivy",
            message_text="Why is pod api-7d9 pending in payments?",
            status="running",
            phase="answering",
            progress_json=json.dumps([{
                "seq": 0,
                "phase": "answering",
                "message": "Preparing an answer before restart.",
                "at": datetime.now(timezone.utc).isoformat(),
            }]),
            started_at=datetime.now(timezone.utc),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        terminal = None
        for _ in range(40):
            response = client.get(
                f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
            )
            terminal = response.json()
            if terminal["status"] == "succeeded":
                break
            time.sleep(0.05)
        assert terminal is not None and terminal["status"] == "succeeded"
        rendered = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"}
        )
        assert "selector does not match" in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.get(AdHocRun, run_id)
        assert run is not None
        assert run.started_at is not None
        assert run.completed_at is not None
        assert run.assistant_message_id is not None
    engine.dispose()


def test_ask_ui_documents_keyboard_and_unlimited_session_behavior() -> None:
    template = (ROOT / "apps" / "web" / "templates" / "ask.html").read_text()
    base_template = (ROOT / "apps" / "web" / "templates" / "base.html").read_text(
        encoding="utf-8"
    )
    script = (ROOT / "apps" / "web" / "static" / "app.js").read_text()
    styles = (ROOT / "apps" / "web" / "static" / "styles.css").read_text()
    assert "Conversation budget reached" not in template
    assert "Enter to send" not in template and "Shift+Enter for a new line" not in template
    assert 'event.key === "Enter" && !event.shiftKey' in script
    assert "adhocForm.requestSubmit()" in script
    assert "podpilot-composer-draft:" in script
    assert "focus({preventScroll: true})" in script
    assert "data-run-cancel" in template
    assert "/api/v1/adhoc-runs/{{ active_run.id }}/cancel" in template
    assert 'data-ask-submit data-run-cancel' in template
    assert '>Cancel</button>' in template
    assert 'pendingRun.querySelector("[data-run-cancel]")' not in script
    assert "appendOptimisticTurn" in script
    assert 'class="boundary-pill caution-summary' in template
    assert template.count('class="boundary-pill caution-summary') == 1
    assert template.count('class="boundary-pill execution-mode-badge ') == 1
    assert "Session cautions" in template
    assert "data-action-mode-notice" in template
    assert "ACTION MODE - Cluster WRITES Permitted" in template
    assert "data-action-tooltip" in template
    assert "data-read-only-tooltip" in template
    assert ".agent-mode-pill" in styles
    assert ".action-mode-notice[hidden]" in styles
    assert ".boundary-pill.caution-summary::after" in styles
    assert "Session cautions:&#10;&#10;" in template
    assert "execution-mode-read-write" in template
    assert "execution-mode-read-only" in template
    assert ".execution-mode-badge { min-height: 34px; padding: 0 11px; border-radius: 7px;" in styles
    assert ".execution-mode-badge.execution-mode-read-only" in styles
    assert ".execution-mode-badge.execution-mode-read-write" in styles
    assert ".ask-page .ask-session-header" in styles
    assert "padding-inline: 20px" in styles
    assert ".answer-table-result { margin: 10px 0 14px; }" in styles
    assert ".metric-ranking-table { width: 100%; min-width: 760px; border-collapse: collapse; font-size: 13px;" in styles
    assert ".metric-table-wrap { overflow-x: auto; border-radius: 8px; background: rgba(8, 15, 26, .42); }" in styles
    assert ".metric-ranking-table th { color: var(--subtle); font-size: 11px;" in styles
    assert ".metric-ranking-table td { color: #e8f3fb; }" in styles
    assert ".metric-ranking-table code { color: #e8f3fb; font-size: 13px;" in styles
    assert "cited.kafka_topic_storage" in template
    assert "Replicated disk usage" in template
    assert "Replica disk usage" in template
    assert ".kafka-topic-storage-group > summary" in styles
    assert ".kafka-partition-table" in styles
    assert "new URLSearchParams(new FormData(adhocForm))" in script
    assert 'requestBody.set("message", question)' in script
    assert "rawResponseToggle.disabled = true" in script
    assert "rawResponseToggle.disabled = false" in script
    assert "data-cluster-picker" in template
    assert "cluster-picker-selection" in template
    assert "data-cluster-selection-required" in template
    assert "Select cluster(s) first" in template
    assert 'Choose one or more clusters from "Send requests to"' not in template
    assert "cluster-picker-required-icon" in template
    assert ".cluster-picker-required-icon" in styles
    assert "updateAskSubmitAvailability" in script
    assert 'clusterPicker?.querySelector("[data-cluster-checkbox]:checked")' in script
    assert 'data-cluster-filter="connected">Signed-In</button>' in template
    assert 'data-cluster-filter="all">All</button>' in template
    assert 'let clusterFilter = filterTabs.find' in script
    assert 'const matchesStatus = clusterFilter === "all" || checkbox?.dataset.connected === "true"' in script
    assert 'document.addEventListener("pointerdown"' in script
    assert "clusterPicker.open && !clusterPicker.contains(event.target)" in script
    assert "clusterPicker.open = false" in script
    assert ".cluster-filter-tabs > button[aria-selected=\"true\"]" in styles
    assert "composer-toolbar" in template
    assert "composer-input-wrap" in template
    assert 'rows="2" data-min-rows="2" data-max-rows="10"' in template
    assert '>Submit</button>' in template
    assert 'askSubmit.textContent = "Submit"' in script
    assert "border: 1px solid #e7edf2" in styles
    assert ".composer-controls > [data-ask-submit]" in styles
    assert "min-height: 73px; max-height: 260px" in styles
    assert ".ask-composer .composer-input-wrap textarea" in styles
    assert "resizeComposerTextarea" in script
    assert 'composerTextarea.style.overflowY = contentHeight > maxHeight ? "auto" : "hidden"' in script
    assert ".ask-layout.action-session .composer-controls > [data-ask-submit]" in styles
    assert 'cautionSummary.dataset.tooltip = actionModeSelected' in script
    assert "actionModeNotice.hidden = !actionModeSelected" in script
    assert ".composer-input-wrap > [data-run-cancel]" not in styles
    assert "Each question: up to" not in template
    assert 'chip.className = "cluster-picker-chip"' in script
    assert 'pickerLabel.replaceChildren()' in script
    assert ".delegated-connect-panel .cluster-picker-menu { top: calc(100% + 7px); bottom: auto; }" in styles
    assert 'textarea.value = ""' in script
    assert "new EventSource" in script
    assert "thinking-spinner" in template
    assert "data-run-timeout-ms" in template
    assert "progressWatchdog" in script
    assert "reconcileStatus" in script
    assert "exceeded its progress deadline" in script
    assert "data-progress-current" in template
    assert "data-progress-title" in template
    assert 'event.phase === "queued" ? "Waiting to investigate" : "Live investigation"' in script
    assert "data-progress-phase" in template
    assert "event.message not in progress.seen_messages" in template
    assert "unique_phase.events[-3:]" in template
    assert "active_run.events[-6:]" not in template
    assert "progressItemsPerPhase = 3" in script
    assert "items.children.length > progressItemsPerPhase" in script
    assert "displayedProgressMessages.has(event.message)" in script
    assert '.progress-phase-updates li::before' not in styles
    assert 'phaseGroups.find((item) => item.dataset.progressPhase === phaseName)' in script
    assert 'document.querySelectorAll(\'.chat-citations a[href^="#evidence-"]\')' in script
    assert 'document.querySelectorAll(\'.answer-evidence a[href^="#evidence-"]\')' in script
    assert "target.scrollIntoView" in script
    assert "technicalDetails.open = true" in script
    assert 'aria-expanded", "true"' in script
    assert 'tabindex="-1"' in template
    assert "data-scroll-latest" in template
    assert "latestThread.scrollTop = latestThread.scrollHeight" in script
    assert "message.content | safe_markdown" in template
    assert '<h1>Ask PodPilot</h1>' not in template
    assert "Read-only cluster assistant" not in template
    assert 'class="panel-header ask-session-header"' in template
    assert template.index('class="panel-header ask-session-header"') < template.index(
        'class="chat-thread ask-thread"'
    )
    assert "ask-sidebar" not in template
    assert "data-evidence-dialog" in template and "data-evidence-open" in template
    assert "tool-activity" not in template
    assert "Inspected {{ message.activity.reads" not in template
    assert 'class="answer-status answer-status-limited"' in template
    assert 'class="answer-status answer-status-grounded"' in template
    assert 'data-tooltip="This reply contains' in template
    assert '<details class="answer-evidence">' in template
    assert 'class="answer-evidence-timeline"' in template
    assert "answer-confidence" not in template
    assert "recent_conversations" in base_template
    assert "nav-session-list" in base_template
    assert "nav-session-delete" in base_template
    assert "evidenceDialog.showModal()" in script
    assert 'name="include_raw_response"' in template
    assert "Show raw model response" in template
    assert 'class="raw-model-response"' in template


def test_recent_ask_sessions_remain_visible_outside_ask_routes(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource()
    )
    conversation_id = "00000000-0000-0000-0000-0000000000f1"
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id,
            created_by="ivy",
            title="Persistent sidebar session",
            status="active",
            evidence_json="[]",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})

    assert dashboard.status_code == 200
    assert 'class="nav-tree expanded"' in dashboard.text
    assert 'aria-label="Ask PodPilot conversations"' in dashboard.text
    assert f'href="/ask/{conversation_id}"' in dashboard.text
    assert "Persistent sidebar session" in dashboard.text
    assert 'href="/settings/clusters"' not in dashboard.text
    assert 'href="/settings/model"' not in dashboard.text
    assert 'href="/memory"' not in dashboard.text


def test_ask_evidence_ui_exposes_clickable_citations_and_technical_payload(
    tmp_path: Path,
) -> None:
    app, settings = make_app(
        tmp_path, assignments={"ivy": Role.INVESTIGATOR}, source=FakeAlertSource()
    )
    conversation_id = "00000000-0000-0000-0000-0000000000e1"
    evidence_id = "cluster-route-technical-1"
    evidence = [{
        "id": evidence_id,
        "tool": "search_resources",
        "summary": "Found the Route selected by host.",
        "source": "kubernetes:route.openshift.io/v1:Route:openshift-ingress/*",
        "collected_at": "2026-08-26T00:51:27+00:00",
        "data": {
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "scope": "cluster",
            "count": 1,
            "scannedCount": 1507,
            "matchField": "spec.host",
            "matchOperator": "exact",
            "matchValue": "maas.apps.example.test",
            "searchComplete": True,
            "items": [{
                "apiVersion": "route.openshift.io/v1",
                "kind": "Route",
                "metadata": {"name": "maas", "namespace": "openshift-ingress"},
                "spec": {
                    "host": "maas.apps.example.test",
                    "to": {"kind": "Service", "name": "maas-default-gateway"},
                    "port": {"targetPort": "https"},
                    "tls": {"termination": "passthrough"},
                },
            }],
        },
    }]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(AdHocConversation(
            id=conversation_id,
            created_by="ivy",
            title="Route TLS evidence",
            status="active",
            evidence_json=json.dumps(evidence),
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-0000000000e2",
            conversation_id=conversation_id,
            role="assistant",
            actor=None,
            content="The Route uses TLS passthrough.",
            answer_mode="evidence_based",
            citations_json=json.dumps([evidence_id]),
            tool_activity_json="{}",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        rendered = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"}
        )

    assert rendered.status_code == 200
    assert "Evidence used in this answer" in rendered.text
    assert '<details class="answer-evidence">' in rendered.text
    assert '<ol class="answer-evidence-timeline">' in rendered.text
    assert "1 source" in rendered.text
    assert "Evidence-backed" in rendered.text
    assert "Cluster-specific claims are backed by the cited observations" in rendered.text
    assert "20:51:27 EST (-4)" in rendered.text
    assert f'href="#evidence-{evidence_id}"' in rendered.text
    assert f">{evidence_id}</code>" in rendered.text
    assert "TLS termination" in rendered.text
    assert "passthrough" in rendered.text
    assert "Route target port" in rendered.text
    assert "View technical details" in rendered.text
    assert "Redacted collected payload" in rendered.text
    assert "Evidence links beneath replies open and focus the cited card" in rendered.text
    assert 'aria-controls="evidence-dialog"' in rendered.text


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
        assert "Evidence-first incident investigation" in detail.text

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
            data={"message": "x" * 4001},
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
        assert [event.action for event in events] == [
            "chat.message", "chat.investigate", "chat.answer"
        ]
        assert all("synthetic-secret" not in event.details_json for event in events)
    engine.dispose()


def test_incident_chat_collects_and_persists_alert_scoped_job_evidence(tmp_path: Path) -> None:
    provider = IncidentJobProvider()
    explorer = IncidentJobExplorer()
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource((job_failed(),)),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        dashboard = client.get("/", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
        created = client.post(
            "/api/v1/alerts/job-failed-1/investigations",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        investigation_id = created.headers["location"].rsplit("/", 1)[-1]
        asked = client.post(
            f"/api/v1/investigations/{investigation_id}/chat",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={"message": "Can you inspect the Job object and find clues?"},
            follow_redirects=False,
        )
        detail = client.get(asked.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "PodPilot inspected the alert-scoped Job" in detail.text
        assert 'href="#evidence-cluster-job-1"' in detail.text
        assert "Read Job operators/status-check-abc" in detail.text
        assert "chat may perform bounded" in detail.text

    assert len(explorer.calls) == 1
    assert explorer.calls[0].api_version == "batch/v1"
    assert explorer.calls[0].kind == "Job"
    assert explorer.calls[0].namespace == "operators"
    assert explorer.calls[0].match_field == "metadata.name"
    assert explorer.calls[0].match_value == "status-check-abc"
    assert provider.chat_calls[0]["policy"]["bounded_cluster_reads_enabled"] is True
    assert provider.chat_calls[0]["read_activity"][0]["status"] == "succeeded"

    engine = build_engine(settings)
    with Session(engine) as db_session:
        investigation = db_session.get(Investigation, investigation_id)
        analysis = json.loads(investigation.analysis_json)
        job = next(item for item in analysis["observations"] if item["id"] == "cluster-job-1")
        assert job["data"]["status"]["conditions"][0]["reason"] == "BackoffLimitExceeded"
        audit = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "chat.investigate")
        )
        assert json.loads(audit.details_json)["observations_added"] == 1
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
        assert "network policy definitely" in detail.text
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
        assert viewer_page.status_code == 403
        dashboard = client.get("/", headers={"x-forwarded-user": "vic"})
        viewer_csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', dashboard.text)
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
                "custom_ca_pem": "PRIVATE KEY MATERIAL MUST BE REJECTED",
            },
        )
        assert rejected_ca.status_code == 422
        assert "must not contain a private key" in rejected_ca.json()["detail"]
        rejected_reasoning = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "provider_label": "Invalid reasoning",
                "base_url": "https://models.example.test/v1",
                "chat_model": "test-model",
                "api_token": "test-api-token",
                "reasoning_effort": "extreme",
            },
        )
        assert rejected_reasoning.status_code == 422
        assert rejected_reasoning.json()["detail"] == "Reasoning effort is invalid."
        rejected_temperature = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "provider_label": "Invalid temperature",
                "base_url": "https://models.example.test/v1",
                "chat_model": "test-model",
                "api_token": "test-api-token",
                "temperature": "2.1",
            },
        )
        assert rejected_temperature.status_code == 422
        assert "temperature is outside" in rejected_temperature.json()["detail"]
        rejected_retries = client.post(
            "/api/v1/model-profile",
            headers={"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)},
            data={
                "provider_label": "Invalid retries",
                "base_url": "https://models.example.test/v1",
                "chat_model": "test-model",
                "api_token": "test-api-token",
                "max_retries": "11",
            },
        )
        assert rejected_retries.status_code == 422
        assert "retries" in rejected_retries.json()["detail"]
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
                "max_retries": "4",
                "max_output_tokens": "1200",
                "temperature": "0",
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
        assert probed.json()["diagnostic_call_count"] == 0
        engine = build_engine(settings)
        with Session(engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            assert profile is not None
            assert profile.temperature == 0
            assert profile.max_retries == 4
            captured_probe = json.loads(profile.last_probe_diagnostics_json)
            assert captured_probe["outcome"] == "ready"
            assert captured_probe["calls"] == []
            profile.last_probe_diagnostics_json = json.dumps({
                "call_count": 1,
                "usage_reported_calls": 1,
                "usage": {
                    "input_tokens": 42, "output_tokens": 9, "total_tokens": 51,
                    "cached_tokens": 0, "reasoning_tokens": 0,
                },
                "largest_input_tokens": 42,
                "outcome": "reduced_capability",
                "calls": [{
                    "operation": "workflow.ReadPlan.schema_retry",
                    "method": "POST", "endpoint": "/v1/chat/completions",
                    "http_status": 200, "duration_ms": 75, "failed": True,
                    "schema": "ReadPlan", "response_model": "test-model",
                    "response_id": "response-123", "request_id": "request-123",
                    "error": "The returned plan failed the capability check.",
                    "response_preview": '{"decision":"answer_from_evidence"}',
                    "usage": {"input_tokens": 42, "output_tokens": 9, "total_tokens": 51},
                }],
            }, sort_keys=True)
            db_session.commit()
        engine.dispose()
        diagnostics_page = client.get(
            "/settings/model?edit=1", headers={"x-forwarded-user": "ada"}
        )
        assert "Request diagnostics" in diagnostics_page.text
        assert "1 provider request" in diagnostics_page.text
        assert "probe.summary" not in diagnostics_page.text
        assert 'class="failed"' in diagnostics_page.text
        assert "response-123" in diagnostics_page.text
        assert "request-123" in diagnostics_page.text
        assert "Redacted response preview" in diagnostics_page.text
        assert "<details open>" in diagnostics_page.text
        assert "Authorization headers and request bodies are never stored" in diagnostics_page.text
        assert 'name="temperature"' in diagnostics_page.text
        assert 'value="0.0"' in diagnostics_page.text
        assert 'name="max_retries"' in diagnostics_page.text
        assert 'value="4"' in diagnostics_page.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        profile = db_session.get(ModelProfile, 1)
        assert profile is not None and profile.status == "ready"
        assert "test-api-token" not in profile.capabilities_json
        probe_diagnostics = json.loads(profile.last_probe_diagnostics_json)
        assert probe_diagnostics["call_count"] == 1
        assert probe_diagnostics["calls"][0]["operation"] == "workflow.ReadPlan.schema_retry"
        assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 2
    engine.dispose()


def test_model_registry_uses_distinct_secret_keys_and_one_active_profile(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore()
    provider = FakeModelProvider(ask_schemas=False)
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
                "reasoning_effort_low": "true",
                "reasoning_effort_medium": "true",
                "reasoning_effort_high": "true",
                "default_reasoning_effort": "high",
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
        assert probe.json()["capabilities"]["ask_schemas"] is False
        rendered = client.get(
            f"/settings/model?profile_id={second_id}", headers={"x-forwarded-user": "ada"}
        )
        assert "Ask PodPilot schemas" in rendered.text
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
        assert profiles[0].reasoning_effort == "high"
        assert json.loads(profiles[0].reasoning_efforts_json) == ["low", "medium", "high"]
        assert profiles[0].tool_calling_hint is True
        assert profiles[0].vision_hint is True
        assert profiles[0].credential_key in credentials.values
    assert len(credentials.values) == 1
    assert set(credentials.values) < credential_keys
    engine.dispose()


def test_model_registry_allows_plain_http_only_for_cluster_service_dns(
    tmp_path: Path,
) -> None:
    credentials = MemoryCredentialStore()
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        credential_store=credentials,
        model_provider=FakeModelProvider(),
    )
    with TestClient(app) as client:
        page = client.get("/settings/model", headers={"x-forwarded-user": "ada"})
        assert "Plain HTTP — in-cluster Service only" in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        common = {
            "provider_label": "Internal model",
            "chat_model": "gpt-oss-120b-rhoai",
            "api_type": "chat-completions",
            "api_token": "test-api-token",
            "timeout_seconds": "240",
            "max_input_tokens": "60000",
            "max_output_tokens": "4096",
        }
        external = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                **common,
                "base_url": "http://models.example.test/v1",
                "tls_mode": "plaintext",
            },
        )
        assert external.status_code == 422
        assert "only for service.namespace.svc" in external.json()["detail"]

        mismatched = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                **common,
                "base_url": "http://model.spt-llm.svc:8000/v1",
                "tls_mode": "system",
            },
        )
        assert mismatched.status_code == 422
        assert "requires Plain HTTP" in mismatched.json()["detail"]

        too_slow = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                **common,
                "base_url": "http://model.spt-llm.svc:8000/v1",
                "tls_mode": "plaintext",
                "timeout_seconds": "241",
            },
        )
        assert too_slow.status_code == 422
        assert "outside the allowed range" in too_slow.json()["detail"]

        saved = client.post(
            "/api/v1/model-profile",
            headers=headers,
            data={
                **common,
                "base_url": "http://model.spt-llm.svc:8000/v1",
                "tls_mode": "plaintext",
            },
        )
        assert saved.status_code == 200
        assert saved.json()["status"] == "saved"

    engine = build_engine(settings)
    with Session(engine) as db_session:
        profile = db_session.get(ModelProfile, saved.json()["profile_id"])
        assert profile is not None
        assert profile.base_url == "http://model.spt-llm.svc:8000/v1"
        assert profile.tls_mode == "plaintext"
        assert profile.timeout_seconds == 240
        assert profile.custom_ca_pem is None
    engine.dispose()


def test_active_model_can_be_deleted_with_ready_fallback_or_no_model(tmp_path: Path) -> None:
    credentials = MemoryCredentialStore()
    credentials.set("first-token", "model_first")
    credentials.set("second-token", "model_second")
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
        credential_store=credentials,
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add_all([
            ModelProfile(
                id=1, provider_label="First", base_url="https://first.example.test/v1",
                chat_model="first-model", credential_key="model_first",
                embedding_model=None, timeout_seconds=30, max_output_tokens=1200,
                status="ready", capabilities_json="{}", updated_by="ada", is_active=True,
                last_probe_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            ),
            ModelProfile(
                id=2, provider_label="Fallback", base_url="https://second.example.test/v1",
                chat_model="second-model", credential_key="model_second",
                embedding_model=None, timeout_seconds=30, max_output_tokens=1200,
                status="ready", capabilities_json="{}", updated_by="ada", is_active=False,
                last_probe_at=datetime.now(timezone.utc),
            ),
        ])
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get("/settings/model?edit=1", headers={"x-forwarded-user": "ada"})
        assert 'data-action-kind="delete"' in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        first_delete = client.post("/api/v1/model-profiles/1/delete", headers=headers, data={})
        assert first_delete.json() == {"status": "deleted", "activated_profile_id": 2}
        second_delete = client.post("/api/v1/model-profiles/2/delete", headers=headers, data={})
        assert second_delete.json() == {"status": "deleted", "activated_profile_id": None}

    engine = build_engine(settings)
    with Session(engine) as db_session:
        assert db_session.scalar(select(func.count()).select_from(ModelProfile)) == 0
        events = list(db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == "model_profile.delete")
        ))
        assert len(events) == 2
        assert json.loads(events[0].details_json)["activated_profile_id"] == 2
        assert json.loads(events[1].details_json)["activated_profile_id"] is None
    engine.dispose()
    assert credentials.values == {}


def test_management_sections_require_approver_or_breakglass(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={
            "ivy": Role.INVESTIGATOR,
            "ada": Role.APPROVER,
            "bea": Role.BREAKGLASS,
        },
        source=FakeAlertSource(),
    )

    with TestClient(app) as client:
        investigator_home = client.get("/", headers={"x-forwarded-user": "ivy"})
        for path in ("/settings/clusters", "/settings/model", "/memory"):
            assert client.get(path, headers={"x-forwarded-user": "ivy"}).status_code == 403
            assert client.get(path, headers={"x-forwarded-user": "ada"}).status_code == 200
            assert client.get(path, headers={"x-forwarded-user": "bea"}).status_code == 200

        for href in ('/settings/clusters', '/settings/model', '/memory'):
            assert f'href="{href}"' not in investigator_home.text

        for username in ("ada", "bea"):
            home = client.get("/", headers={"x-forwarded-user": username})
            assert home.text.count('<p class="nav-label section-gap">Manage</p>') == 1
            for href in ('/settings/clusters', '/settings/model', '/memory'):
                assert f'href="{href}"' in home.text


def test_investigator_configuration_admin_can_edit_management_forms(tmp_path: Path) -> None:
    app, _ = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        configuration_admins={"ivy"},
        source=FakeAlertSource(),
    )

    with TestClient(app) as client:
        headers = {"x-forwarded-user": "ivy"}
        home = client.get("/", headers=headers)
        assert home.status_code == 200
        for href in ('/settings/clusters', '/settings/model', '/memory'):
            assert f'href="{href}"' in home.text

        model_page = client.get("/settings/model?new=1", headers=headers)
        assert model_page.status_code == 200
        assert 'id="model-settings-form"' in model_page.text
        assert 'id="model-settings-form" class="settings-form" data-save-url="/api/v1/model-profile" aria-disabled="true"' not in model_page.text
        assert re.search(r'<input name="provider_label"[^>]* disabled', model_page.text) is None
        assert '<button class="button primary" type="submit">Save model</button>' in model_page.text
        assert "Configuration-administrator access is required" not in model_page.text

        memory_page = client.get("/memory", headers=headers)
        assert memory_page.status_code == 200
        assert 'id="knowledge-form"' in memory_page.text
        assert "Read-only access" not in memory_page.text


def test_users_manage_private_cluster_metadata_without_stored_tokens(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR, "grace": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        settings_overrides={"delegated_access_enabled": True},
    )
    with TestClient(app) as client:
        admin_page = client.get(
            "/settings/clusters", headers={"x-forwarded-user": "ivy"}
        )
        assert admin_page.status_code == 403
        page = client.get("/clusters/personal", headers={"x-forwarded-user": "ivy"})
        assert page.status_code == 200
        assert "<h1>My clusters</h1>" in page.text
        assert "Cluster Management" not in page.text
        assert 'data-redirect-base="/clusters/personal"' in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        created = client.post(
            "/api/v1/clusters",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            data={
                "name": "Ivy ad-hoc DEV",
                "environment": "dev",
                "visibility": "private",
                "api_url": "https://api.adhoc-dev.example:6443",
                "tls_verify": "false",
                "tags_json": '{"team":"payments"}',
            },
        )
        assert created.status_code == 200
        cluster_id = created.json()["cluster_id"]

        own_page = client.get("/clusters/personal", headers={"x-forwarded-user": "ivy"})
        other_page = client.get("/clusters/personal", headers={"x-forwarded-user": "grace"})
        assert "Ivy ad-hoc DEV" in own_page.text
        assert "Ivy ad-hoc DEV" not in other_page.text
        denied = client.post(
            f"/api/v1/clusters/{cluster_id}/disable",
            headers={"x-forwarded-user": "grace", "x-podpilot-csrf": csrf.group(1)},
        )
        assert denied.status_code == 403

        removed = client.post(
            f"/api/v1/clusters/{cluster_id}/delete",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
        )
        assert removed.status_code == 200
        assert removed.json()["status"] == "deleted"
        assert "Ivy ad-hoc DEV" not in client.get(
            "/clusters/personal", headers={"x-forwarded-user": "ivy"}
        ).text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        cluster = db_session.get(Cluster, cluster_id)
        assert cluster is None
        event = db_session.scalar(select(AuditEvent).where(
            AuditEvent.action == "cluster.delete"
        ))
        assert event is not None
        assert json.loads(event.details_json)["cluster_id"] == cluster_id
    engine.dispose()


def test_cluster_memory_is_versioned_scoped_and_authorized(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER, "grace": Role.INVESTIGATOR, "vic": Role.VIEWER},
        source=FakeAlertSource(),
    )
    with TestClient(app) as client:
        page = client.get("/memory", headers={"x-forwarded-user": "ada"})
        assert page.status_code == 200
        assert "retrieved for Ask PodPilot" in page.text
        csrf_match = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf_match is not None
        approver_headers = {
            "x-forwarded-user": "ada",
            "x-podpilot-csrf": csrf_match.group(1),
        }

        saved = client.post(
            "/api/v1/knowledge",
            headers=approver_headers,
            data={
                "title": "Payments registry mirror",
                "content": "# Image pulls\n\nPayments workloads pull through mirror.corp.example.",
                "source": "Platform team runbook",
                "source_type": "cluster_fact",
                "cluster_id": "test-cluster",
                "namespace": "payments",
                "owner": "platform-team",
                "verification_state": "reviewed",
                "sensitivity": "internal",
            },
        )
        assert saved.status_code == 200
        first = saved.json()
        assert first["version"] == 1

        out_of_scope = client.get(
            "/api/v1/knowledge/search?q=registry+mirror",
            headers={"x-forwarded-user": "grace"},
        )
        assert out_of_scope.json()["results"] == []
        in_scope = client.get(
            "/api/v1/knowledge/search?q=registry+mirror&namespace=payments",
            headers={"x-forwarded-user": "grace"},
        )
        assert len(in_scope.json()["results"]) == 1
        assert in_scope.json()["results"][0]["heading"] == "Image pulls"

        draft = client.post(
            "/api/v1/knowledge",
            headers=approver_headers,
            data={
                "title": "Unreviewed proxy note", "content": "Use tentative-proxy.example.",
                "source": "Operator note", "source_type": "cluster_fact",
                "cluster_id": "test-cluster", "owner": "ada",
                "verification_state": "draft", "sensitivity": "internal",
            },
        )
        assert draft.status_code == 200
        assert client.get(
            "/api/v1/knowledge/search?q=tentative-proxy",
            headers={"x-forwarded-user": "grace"},
        ).json()["results"] == []

        restricted = client.post(
            "/api/v1/knowledge",
            headers=approver_headers,
            data={
                "title": "Restricted escalation path", "content": "Escalate frobnicator faults.",
                "source": "SRE handbook", "source_type": "runbook",
                "cluster_id": "test-cluster", "owner": "sre",
                "verification_state": "reviewed", "sensitivity": "restricted",
            },
        )
        assert restricted.status_code == 200
        assert client.get(
            "/api/v1/knowledge/search?q=frobnicator",
            headers={"x-forwarded-user": "grace"},
        ).json()["results"] == []
        assert len(client.get(
            "/api/v1/knowledge/search?q=frobnicator",
            headers={"x-forwarded-user": "ada"},
        ).json()["results"]) == 1
        investigator_page = client.get("/memory", headers={"x-forwarded-user": "grace"})
        assert "Restricted escalation path" not in investigator_page.text
        assert "Unreviewed proxy note" not in investigator_page.text

        revised = client.post(
            "/api/v1/knowledge",
            headers=approver_headers,
            data={
                "logical_id": first["logical_id"],
                "title": "Payments registry mirror",
                "content": "# Image pulls\n\nPayments now uses quay-mirror.corp.example.",
                "source": "Platform team runbook", "source_type": "cluster_fact",
                "cluster_id": "test-cluster", "namespace": "payments",
                "owner": "platform-team", "verification_state": "reviewed",
                "sensitivity": "internal",
            },
        )
        assert revised.status_code == 200
        assert revised.json()["version"] == 2
        assert client.get(
            "/api/v1/knowledge/search?q=workloads&namespace=payments",
            headers={"x-forwarded-user": "grace"},
        ).json()["results"] == []
        assert len(client.get(
            "/api/v1/knowledge/search?q=quay-mirror&namespace=payments",
            headers={"x-forwarded-user": "grace"},
        ).json()["results"]) == 1

        disabled = client.post(
            f"/api/v1/knowledge/{revised.json()['document_id']}/status",
            headers=approver_headers,
            data={"enabled": "false"},
        )
        assert disabled.json()["status"] == "disabled"
        assert client.get(
            "/api/v1/knowledge/search?q=quay-mirror&namespace=payments",
            headers={"x-forwarded-user": "grace"},
        ).json()["results"] == []

        punctuation = client.get(
            '/api/v1/knowledge/search?q=%22+OR+NOT+%28registry%29',
            headers={"x-forwarded-user": "grace"},
        )
        assert punctuation.status_code == 200
        assert client.get("/memory", headers={"x-forwarded-user": "vic"}).status_code == 403
        forbidden_write = client.post(
            "/api/v1/knowledge", headers={
                "x-forwarded-user": "grace", "x-podpilot-csrf": csrf_match.group(1),
            }, data={},
        )
        assert forbidden_write.status_code == 403

    engine = build_engine(settings)
    with Session(engine) as db_session:
        versions = list(db_session.scalars(
            select(KnowledgeDocument)
            .where(KnowledgeDocument.logical_id == first["logical_id"])
            .order_by(KnowledgeDocument.version)
        ))
        assert [item.version for item in versions] == [1, 2]
        assert versions[0].is_current is False
        assert versions[1].is_current is True
        events = list(db_session.scalars(
            select(AuditEvent).where(AuditEvent.action.like("knowledge.%"))
        ))
        assert len(events) == 5
        assert all("mirror.corp.example" not in event.details_json for event in events)
    engine.dispose()


def test_cluster_memory_targets_global_explicit_and_tag_matched_clusters(tmp_path: Path) -> None:
    app, settings = make_app(
        tmp_path,
        assignments={"ada": Role.APPROVER},
        source=FakeAlertSource(),
    )
    azure_id = "20000000-0000-0000-0000-000000000001"
    metal_id = "20000000-0000-0000-0000-000000000002"
    with TestClient(app) as client:
        engine = build_engine(settings)
        with Session(engine) as db_session:
            now = datetime.now(timezone.utc)
            for cluster_id, name, platform in (
                (azure_id, "azure-prod", "azure"),
                (metal_id, "metal-prod", "baremetal"),
            ):
                db_session.add(Cluster(
                    id=cluster_id, name=name, api_url=f"https://api.{name}.example:6443",
                    credential_key=f"cluster_{cluster_id.replace('-', '')}",
                    tags_json=json.dumps({"platform": platform, "environment": "prod"}),
                    tls_verify=True, is_enabled=True, is_system=False, status="ready",
                    created_by="ada", updated_by="ada", created_at=now, updated_at=now,
                ))
            db_session.commit()
        engine.dispose()
        page = client.get("/memory", headers={"x-forwarded-user": "ada"})
        assert "data-knowledge-tag-matches" in page.text
        assert 'name="target_tags_json" data-tags-value' in page.text
        assert '<textarea name="target_tags_json"' not in page.text
        assert "platform:azure" in page.text
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text).group(1)
        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf}

        def save(title: str, targets: list[str], tags: dict[str, str]):
            response = client.post("/api/v1/knowledge", headers=headers, data={
                "title": title,
                "content": f"sharedneedle guidance for {title}",
                "source": "Platform handbook",
                "source_type": "runbook",
                "owner": "platform",
                "verification_state": "reviewed",
                "sensitivity": "internal",
                "target_cluster_ids_json": json.dumps(targets),
                "target_tags_json": json.dumps(tags),
            })
            assert response.status_code == 200
            return response.json()

        save("Global guidance", [], {})
        azure_saved = save("Azure guidance", [], {"platform": "azure"})
        save("Metal explicit guidance", [metal_id], {})
        edited = client.get(
            f"/memory?edit={azure_saved['document_id']}",
            headers={"x-forwarded-user": "ada"},
        )
        assert 'data-tags=\'{"platform": "azure"}\'' in edited.text
        azure = client.get(
            f"/api/v1/knowledge/search?q=sharedneedle&cluster_id={azure_id}",
            headers={"x-forwarded-user": "ada"},
        ).json()["results"]
        metal = client.get(
            f"/api/v1/knowledge/search?q=sharedneedle&cluster_id={metal_id}",
            headers={"x-forwarded-user": "ada"},
        ).json()["results"]
        assert {item["title"] for item in azure} == {"Global guidance", "Azure guidance"}
        assert {item["title"] for item in metal} == {"Global guidance", "Metal explicit guidance"}


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


def test_ask_message_hides_model_usage_under_author_column(tmp_path: Path) -> None:
    conversation_id = "00000000-0000-0000-0000-000000000190"
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
    )
    engine = build_engine(settings)
    with Session(engine) as db_session:
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}",
            updated_by="ivy",
        ))
        db_session.add(AdHocConversation(
            id=conversation_id, created_by="ivy", title="Token diagnostics",
            status="active", cluster_ids_json=json.dumps([SYSTEM_CLUSTER_ID]),
            evidence_json="[]",
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000191",
            conversation_id=conversation_id, role="assistant", actor=None,
            content="A bounded answer.", answer_mode="general_guidance",
            tool_activity_json=json.dumps({"reads": [
                {"tool": "execute_shell", "status": "completed"},
                {"tool": "execute_shell", "status": "failed"},
                {"tool": "query_metrics", "status": "denied_or_unavailable"},
            ]}),
            model_diagnostics_json=json.dumps({
                "call_count": 3,
                "usage_reported_calls": 2,
                "largest_input_tokens": 42000,
                "usage": {
                    "input_tokens": 50000,
                    "output_tokens": 1200,
                    "reasoning_tokens": 700,
                    "cached_tokens": 10000,
                    "total_tokens": 51200,
                },
                "calls": [{
                    "operation": "workflow.unrestricted_agent",
                    "http_status": 400,
                    "request_id": "provider-request-400",
                    "error_preview": (
                        "context_length_exceeded: request exceeds the model context window"
                    ),
                }],
                "failure_count": 1,
                "failures": [{
                    "operation": "workflow.ActionSelection.schema_retry",
                    "failure_type": "schema_validation",
                    "schema": "ActionSelection",
                    "attempt": 2,
                    "fields": [{
                        "path": "object_reads.0.resource",
                        "code": "value_error",
                        "message": "Value error, invalid Kubernetes resource identifier",
                    }],
                }],
            }),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        rendered = client.get(
            f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"}
        )

    assert rendered.status_code == 200
    assert '<details class="message-model-diagnostics">' in rendered.text
    assert "Model usage" in rendered.text
    assert "50,000" in rendered.text
    assert "Largest input" in rendered.text
    assert "3 model calls; usage reported for 2" in rendered.text
    assert "Tool activity" in rendered.text
    assert "execute_shell" in rendered.text
    assert "2 calls · 1 completed · 1 failed" in rendered.text
    assert "query_metrics" in rendered.text
    assert "1 call · 1 denied or unavailable" in rendered.text
    assert "Model request failures" in rendered.text
    assert "schema validation · ActionSelection · attempt 2" in rendered.text
    assert "object_reads.0.resource" in rendered.text
    assert "Provider HTTP error · 400" in rendered.text
    assert "provider-request-400" in rendered.text
    assert "context_length_exceeded" in rendered.text


def test_tool_activity_summary_groups_safe_names_and_statuses() -> None:
    summary = _summarize_tool_activity([
        {"tool": "execute_shell", "status": "completed"},
        {"tool": "execute_shell", "status": "invalid"},
        {"tool": "query_metrics", "status": "completed"},
        "not-an-activity-item",
        {"status": "completed"},
    ])

    assert summary == [
        {
            "name": "execute_shell",
            "count": 2,
            "statuses": [
                {"name": "completed", "count": 1},
                {"name": "invalid", "count": 1},
            ],
        },
        {
            "name": "query_metrics",
            "count": 1,
            "statuses": [{"name": "completed", "count": 1}],
        },
    ]
