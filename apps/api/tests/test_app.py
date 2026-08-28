import asyncio
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import (
    _append_deterministic_inventory,
    _adhoc_answer_quality_issue,
    _adhoc_answer_advisories,
    _adhoc_capability_wording_issue,
    _actionable_investigation_gaps,
    _adhoc_evidence_view,
    _bind_plan_log_intents,
    _classify_ad_hoc_inquiry,
    _collect_bounded_cluster_reads,
    _clean_adhoc_markdown,
    _compact_answer_evidence,
    _compile_grounded_candidate_plan,
    _compile_remaining_candidate_followups,
    _compile_suggested_followups,
    _current_reads_are_metric_rankings,
    _dedupe_limitations,
    _deterministic_evidence_fallback_answer,
    _deterministic_audit_answer,
    _deterministic_inventory_answer,
    _deterministic_metric_ranking_answer,
    _deterministic_log_findings_section,
    _deterministic_provider_failure_answer,
    _deterministic_resource_detail_answer,
    _deterministic_route_tls_answer,
    _format_est_time,
    _grounded_read_candidates,
    _investigation_capability_ledger,
    _investigation_unit_cost,
    _latest_audit_query_semantics,
    _merge_validated_recommendations,
    _model_log_analysis_section,
    _model_fact_cards,
    _parse_tags,
    _partition_investigation_gaps,
    _profile_is_usable,
    _reconcile_validated_answer_gaps,
    _semantic_metric_read_plan,
    _semantic_audit_read_plan,
    _semantic_resource_read_plan,
    _resolve_audit_inquiry,
    _validated_adhoc_answer,
    SYSTEM_CLUSTER_ID,
    create_app,
)
from podpilot_api.model_provider import (
    AdHocAnswer,
    AdHocLogAnalysis,
    LogAnalysisIssue,
    CapabilityReport,
    InvestigationChatAnswer,
    InquirySemantics,
    ModelProfileConfig,
    ModelInterpretation,
    ModelProviderError,
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
from podpilot_openshift.credentials import CredentialStoreError
from podpilot_openshift.explorer import KubernetesReadOnlyExplorer, ReadOnlyExplorerError
from podpilot_openshift.metric_trends import BoundedMetricTrendReader
from podpilot_openshift.workloads import WorkloadEvidenceError

ROOT = Path(__file__).resolve().parents[3]


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
                namespace="spt-llm", result_limit=5,
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


def test_final_gap_partition_uses_trusted_collected_states() -> None:
    gaps = [
        InvestigationGap(question="Read Service", capability="service_spec"),
        InvestigationGap(question="Read logs", capability="pod_logs"),
    ]
    resolved, remaining = _partition_investigation_gaps(
        gaps,
        capability_ledger={"checks": [
            {"capability": "service_spec", "state": "collected"},
            {"capability": "pod_logs", "state": "available_not_attempted"},
        ]},
    )

    assert [gap.capability for gap in resolved] == ["service_spec"]
    assert [gap.capability for gap in remaining] == ["pod_logs"]


def test_validated_answer_drops_structured_gaps_already_collected() -> None:
    validated = {
        "investigation_gaps": [
            InvestigationGap(question="Read Service", capability="service_spec"),
            InvestigationGap(question="Read logs", capability="pod_logs"),
        ]
    }

    _reconcile_validated_answer_gaps(
        validated,
        capability_ledger={"checks": [
            {"capability": "service_spec", "state": "collected"},
            {"capability": "pod_logs", "state": "available_not_attempted"},
        ]},
    )

    assert [
        gap.capability for gap in validated["investigation_gaps"]
    ] == ["pod_logs"]


def test_recommended_next_check_is_promoted_only_to_typed_planner_input() -> None:
    ledger = _investigation_capability_ledger(
        evidence=[{
            "id": "route-1", "tool": "get_resource",
            "data": {"kind": "Route", "metadata": {"name": "frontend"}},
        }],
        activity=[{
            "tool": "get_resource", "status": "succeeded",
            "evidence_ids": ["route-1"],
        }],
        remaining_units=6,
    )

    gaps = _actionable_investigation_gaps(
        validated_answer={
            "investigation_gaps": [],
            "recommended_next_checks": [
                "Read the backend Service spec to verify its targetPort mapping.",
                "Change the Deployment to expose port 443.",
            ],
        },
        capability_ledger=ledger,
    )

    assert len(gaps) == 1
    assert gaps[0].capability == "service_spec"
    assert gaps[0].question.startswith("Read the backend Service spec")
    assert "not executable" in gaps[0].reason


def test_suggested_followup_compiles_only_unread_grounded_read_actions() -> None:
    cluster = Cluster(id=SYSTEM_CLUSTER_ID, name="Runtime cluster")
    route_evidence = {
        "id": "cluster-route-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "tool": "search_resources",
        "data": {
            "kind": "Route",
            "items": [{
                "kind": "Route",
                "metadata": {"namespace": "maas", "name": "maas"},
                "spec": {"to": {"kind": "Service", "name": "model-server"}},
            }],
        },
    }
    validated = {
        "recommended_next_checks": [
            "Inspect the Service model-server port mapping.",
            "Change the Route TLS termination to edge.",
        ],
    }

    visible, actions = _compile_suggested_followups(
        validated_answer=validated,
        question="Why does the Route return HTTP 500?",
        evidence=[route_evidence],
        activity=[],
        cluster_runtimes=[{"cluster": cluster, "read_signatures": []}],
        remaining_units=5,
    )

    assert visible == validated["recommended_next_checks"]
    assert len(actions) == 1
    assert actions[0]["capability"] == "service_spec"
    assert actions[0]["target"] == "Service:maas/model-server"
    assert actions[0]["id"].startswith("read-")

    service_evidence = {
        "id": "cluster-service-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "tool": "get_resource",
        "data": {
            "kind": "Service",
            "metadata": {"namespace": "maas", "name": "model-server"},
            "spec": {"ports": [{"port": 443, "targetPort": 8443}]},
        },
    }
    visible, actions = _compile_suggested_followups(
        validated_answer=validated,
        question="Why does the Route return HTTP 500?",
        evidence=[route_evidence, service_evidence],
        activity=[],
        cluster_runtimes=[{"cluster": cluster, "read_signatures": []}],
        remaining_units=5,
    )

    assert visible == ["Change the Route TLS termination to edge."]
    assert actions == []


def test_remaining_candidates_become_clickable_actions_without_model_recommendations() -> None:
    cluster = Cluster(id=SYSTEM_CLUSTER_ID, name="Runtime cluster")
    route_evidence = {
        "id": "cluster-route-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "tool": "search_resources",
        "data": {
            "kind": "Route",
            "items": [{
                "kind": "Route",
                "metadata": {"namespace": "maas", "name": "maas"},
                "spec": {"to": {"kind": "Service", "name": "model-server"}},
            }],
        },
    }

    visible, actions = _compile_remaining_candidate_followups(
        question="Why does the Route return HTTP 500?",
        evidence=[route_evidence],
        activity=[],
        cluster_runtimes=[{"cluster": cluster, "read_signatures": []}],
        remaining_units=5,
    )

    assert visible
    assert actions
    assert actions[0]["id"].startswith("read-")
    assert actions[0]["cluster_id"] == SYSTEM_CLUSTER_ID
    assert actions[0]["label"] in visible
    assert actions[0]["capability"] == "service_spec"


def test_remaining_candidates_hide_capabilities_already_collected() -> None:
    cluster = Cluster(id=SYSTEM_CLUSTER_ID, name="Runtime cluster")
    pod_evidence = {
        "id": "cluster-pod-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "tool": "get_resource",
        "data": {
            "kind": "Pod",
            "metadata": {"namespace": "maas", "name": "gateway-abc"},
            "spec": {"containers": [{"name": "istio-proxy"}]},
        },
    }
    log_evidence = {
        "id": "cluster-log-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "tool": "pod_logs",
        "source": "kubernetes:v1:Pod/log:maas/gateway-abc?current",
        "data": {"container": "istio-proxy", "tail": "certificate load failed"},
    }

    _, actions = _compile_remaining_candidate_followups(
        question="Why is the gateway returning HTTP 500?",
        evidence=[pod_evidence, log_evidence],
        activity=[],
        cluster_runtimes=[{"cluster": cluster, "read_signatures": []}],
        remaining_units=5,
    )

    assert all(action["capability"] != "pod_logs" for action in actions)


def test_log_analysis_plural_failure_overview_is_not_reported_as_no_issue() -> None:
    section = _model_log_analysis_section({
        "overview": "The proxy shows repeated certificate failures and upstream errors.",
        "issues": [],
        "analyzed_evidence_ids": ["cluster-log-1"],
        "rejected_issue_count": 1,
    })

    assert "Treat the overview as a hypothesis" in section["content"]
    assert "No potential operational issue" not in section["content"]
    assert section["citations"] == ["cluster-log-1"]


def test_embedded_gap_prose_promotes_only_fixed_available_capabilities() -> None:
    ledger = _investigation_capability_ledger(
        evidence=[{
            "id": "route-1", "tool": "get_resource",
            "data": {"kind": "Route", "metadata": {"name": "frontend"}},
        }],
        activity=[{
            "tool": "get_resource", "status": "succeeded", "evidence_ids": ["route-1"],
        }],
        remaining_units=6,
    )

    gaps = _actionable_investigation_gaps(
        validated_answer={
            "investigation_gaps": [],
            "recommended_next_checks": [],
            "content": (
                "Recommended next evidence collections: service_spec for a named Service; "
                "endpoints; then delete the workload."
            ),
        },
        capability_ledger=ledger,
    )

    assert {gap.capability for gap in gaps} == {"service_spec", "endpoints"}
    assert all("not executable" in str(gap.reason) for gap in gaps)
    assert all("delete" not in gap.question for gap in gaps)


def test_duplicate_plan_is_repaired_to_novel_read_and_goal_stays_pinned() -> None:
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
    no_progress_context = next(
        context for context in provider.contexts
        if context.get("planner_feedback", {}).get("code") == "no_progress"
    )
    assert no_progress_context["pinned_goal_type"] == "diagnose"
    assert all(
        context.get("pinned_goal_type") in {None, "diagnose"}
        for context in provider.contexts
    )


def test_preflight_rejection_does_not_consume_cluster_read_budget() -> None:
    class RepairingProvider:
        def __init__(self) -> None:
            self.contexts = []

        def plan_ad_hoc(self, _profile, _api_key, context):
            self.contexts.append(context)
            if context["investigation_round"] == 1:
                return ReadPlan(
                    scope_summary="Try an ambiguous resource plural.",
                    intents=[ReadIntent(tool="list_resources", resource="routes")],
                )
            if context["investigation_round"] == 2:
                return ReadPlan(
                    scope_summary="Use an unambiguous safe resource.",
                    intents=[ReadIntent(
                        tool="list_resources", resource="pods", api_version="v1",
                        kind="Pod", namespace="payments", limit=5,
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
                tool="list_resources",
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


def test_collection_automatically_retries_tls_trust_failure_without_verification() -> None:
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

    assert [call.tls_verify for call in explorer.calls] == [True, False]
    assert result.activity[1]["automatic_followup"] == "tls_trust_retry"
    assert result.activity[1]["trigger_evidence_ids"] == ["network-trust-failed"]
    assert [item["id"] for item in result.evidence] == [
        "network-trust-failed", "network-insecure-500",
    ]
    assert provider.contexts[1]["observations"][-1]["data"]["statusCode"] == 500
    assert any("server identity was not verified" in item for item in result.limitations)


def test_collection_lets_model_plan_cross_namespace_network_policy_evidence() -> None:
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
        "Pod", "Pod", "Namespace", "Namespace", "NetworkPolicy", "NetworkPolicy",
    ]
    assert [call.namespace for call in explorer.calls[-2:]] == ["frontend", "data"]
    assert len(result.activity) == 6
    assert all(item["status"] == "succeeded" for item in result.activity)
    assert len(provider.contexts) == 3
    assert provider.contexts[-1]["planner_feedback"]["code"] == (
        "review_evidence_sufficiency"
    )
    assert provider.contexts[1]["investigation_round"] == 2
    assert len(provider.contexts[1]["observations"]) == 6


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


def test_adhoc_answer_surfaces_rbac_denial_and_removes_internal_evidence_paths() -> None:
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

    assert str(validated["content"]).startswith("**Access blocked by OpenShift RBAC.**")
    assert denial in str(validated["content"])
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
    assert len(provider.contexts) == 4
    assert provider.contexts[-1]["planner_feedback"]["code"] == (
        "review_evidence_sufficiency"
    )


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
    assert "did not cite collected evidence" in str(validated["content"])


def test_tls_claim_contradicted_by_certificate_failure_is_replaced_with_observed_facts() -> None:
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
    assert "presented TLS" in validated["content"]
    assert "does **not** show a plain-HTTP listener" in validated["content"]
    assert "sidecar container(s) `istio-proxy`" in validated["content"]
    assert "follow-up probe with certificate verification disabled returned HTTP `500`" in validated["content"]
    assert "serving only plain HTTP is not supported" in validated["content"]
    assert validated["citations"] == [
        "network-probe-1", "network-probe-insecure-1", "cluster-route-1",
        "cluster-sidecar-1",
    ]
    assert "rejected a model conclusion" in validated["limitations"][0]


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
    assert ranking["rows"][0] == {
        "rank": 1, "namespace": "logging", "pod": "collector-1",
        "container": "collector", "average": "0.700 cores",
        "current": "0.900 cores", "maximum": "1.000 cores", "progress": 0.9,
    }


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


def test_semantic_log_volume_plan_uses_registered_cluster_metric() -> None:
    compiled = _semantic_metric_read_plan(InquirySemantics(
        mode="metrics",
        resource_query="Namespace",
        needs_object_details=False,
        evidence_goal="Rank namespaces by application-log volume.",
        metric_query="top_log_volume_by_namespace",
        metric_scope="cluster",
        result_limit=10,
        metric_range_seconds=300,
    ))

    assert compiled is not None
    plan, terminal = compiled
    assert terminal is True
    assert plan.intents == [ReadIntent(
        tool="query_metrics",
        metric="top_log_volume_by_namespace",
        metric_scope="cluster",
        range_seconds=300,
        limit=10,
    )]


def test_log_volume_evidence_view_and_deterministic_answer() -> None:
    evidence = [{
        "id": "log-metric-central", "tool": "query_metrics",
        "cluster_id": "central", "cluster_name": "Central DEV",
        "source": "loki:application/query/top_log_volume_by_namespace",
        "data": {
            "metric": "top_log_volume_by_namespace", "scope": "cluster",
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

    assert view["metric_ranking"]["namespace_only"] is True
    assert view["metric_ranking"]["rows"][0]["average"] == "1.00 KiB/s"
    assert answer is not None
    assert "application-log volume by namespace and cluster" in answer["content"]
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


def test_ask_prefers_metric_card_and_keeps_markdown_as_render_fallback(
    tmp_path: Path,
) -> None:
    conversation_id = "00000000-0000-0000-0000-000000000181"
    evidence_id = "metric-log-volume-1"
    fallback_text = "Fallback metric ranking remains available."
    evidence = [{
        "id": evidence_id,
        "tool": "query_metrics",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "cluster_name": "Runtime cluster",
        "summary": "Ranked namespaces by application-log volume.",
        "source": "loki:application/query/top_log_volume_by_namespace",
        "data": {
            "metric": "top_log_volume_by_namespace",
            "scope": "cluster",
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
            content=fallback_text,
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
        assert "Top Application-Log Volume by Namespace" in rendered.text
        assert fallback_text not in rendered.text

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


def test_inventory_collection_uses_live_catalog_without_model_planning() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("Inventory collection must not call the model planner.")

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

    assert len(explorer.calls) == 1
    assert explorer.calls[0].resource == "kafkas.kafka.strimzi.io"
    assert result.activity[0]["status"] == "succeeded"
    assert result.evidence[0]["id"] == "cluster-kafka-list"


def test_model_semantics_can_route_novel_inventory_wording_through_live_catalog() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("Model-classified inventory must not enter open planning.")

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

    assert [call.resource for call in explorer.calls] == ["kafkas.kafka.strimzi.io"]
    assert result.evidence[0]["id"] == "cluster-kafka-list"
    rendered = _deterministic_inventory_answer(
        evidence=result.evidence,
        activity=result.activity,
        question="Tell me where our streaming installations live.",
        inventory_only=True,
    )
    assert rendered is not None
    assert "`orders`" in str(rendered["content"])


def test_audit_semantics_execute_only_the_typed_audit_read() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("Audit collection must not enter open model planning.")

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

    assert [(item.kind, item.name) for item in explorer.calls] == [
        ("Kafka", "kafka-observability-cluster"),
        ("ConfigMap", "kafka-observability-metrics-config"),
    ]
    assert any(item["id"] == "cluster-exporter-config" for item in result.evidence)
    assert provider.contexts[0]["read_candidates"][0]["relation"] == "configures_from"


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
            raise AssertionError("An exact Node label request must not enter open planning.")

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


def test_inventory_details_begin_with_catalog_list_before_optional_planning() -> None:
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

    assert [call.resource for call in explorer.calls] == ["kafkas.kafka.strimzi.io"]
    assert provider.contexts
    assert provider.contexts[0]["completed_reads"][0]["tool"] == "list_resources"
    assert result.evidence[0]["id"] == "cluster-kafka-list"


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


def test_inventory_catalog_miss_is_evidence_not_unrelated_model_traversal() -> None:
    class Provider:
        def plan_ad_hoc(self, *_args, **_kwargs):
            raise AssertionError("A catalog miss must not call the model planner.")

    class Explorer:
        def resource_catalog(self, *, query="", limit=120):
            return [{
                "resource": "namespaces", "apiVersion": "v1",
                "kind": "Namespace", "namespaced": False,
                "verbs": ["get", "list"],
            }]

        def execute(self, _intent):
            raise AssertionError("A catalog miss must not read an unrelated resource.")

    result = asyncio.run(_collect_bounded_cluster_reads(
        model_provider=Provider(),
        cluster_reader=Explorer(),
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
        actor="ivy", workflow_id="catalog-kafka-miss",
        question="Which OpenShift clusters have Kafka instances running on them?",
        conversation=[], existing_evidence=[],
    ))

    assert result.activity[0]["tool"] == "discover_resources"
    assert result.activity[0]["status"] == "succeeded"
    assert result.evidence[0]["data"]["inventoryMatch"] == "none"


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


def test_verified_inventory_augments_valid_concise_model_answer() -> None:
    validated: dict[str, object] = {
        "answer_mode": "evidence_based",
        "content": "Yes, Kafka resources exist on both selected clusters.",
        "citations": ["central-kafka"],
        "limitations": [],
    }
    inventory = {
        "answer_mode": "evidence_based",
        "content": "## Multi-cluster inventory\n\n| OpenShift cluster | Kind |",
        "citations": ["central-kafka", "east-kafka"],
    }

    result = _append_deterministic_inventory(validated, inventory)

    assert str(result["content"]).startswith("Yes, Kafka resources exist")
    assert "## Multi-cluster inventory" in str(result["content"])
    assert result["citations"] == ["central-kafka", "east-kafka"]


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


def test_free_form_model_planned_list_uses_configured_broker_ceiling() -> None:
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

    assert provider.calls == 3
    assert len(explorer.calls) == 1
    assert explorer.calls[0].resource == "kafkatopics"
    assert explorer.calls[0].namespace == "kafka-observability"
    assert explorer.calls[0].limit == 500
    assert result.evidence[-1]["data"]["names"] == ["audit-events"]


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
            ask_schemas=True,
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
                    tool="list_resources", api_version="v1", kind="Pod",
                    namespace="openshift-kube-apiserver", limit=5,
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
        if intent.tool == "list_resources":
            return ReadResult((AdHocObservation(
                id="cluster-pod-list", tool="list_resources",
                summary="Discovered kube-apiserver-sno1.",
                source="kubernetes:v1:Pod:openshift-kube-apiserver/kube-apiserver-sno1",
                collected_at=datetime.now(timezone.utc),
                data={
                    "namespace": "openshift-kube-apiserver",
                    "name": "kube-apiserver-sno1",
                    "containers": ["kube-apiserver"],
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
                tool="list_resources", api_version="v1", kind="Pod",
                namespace="openshift-kube-apiserver", limit=20,
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
        if intent.tool == "list_resources":
            return ReadResult((AdHocObservation(
                id="cluster-kube-api-pods",
                tool="list_resources",
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
        storage = next(item for item in context["observations"] if item["id"] == "cluster-sc-1")
        return AdHocAnswer(
            answer_mode="evidence_based",
            answer=f"The cluster exposes the {storage['data']['metadata']['name']} StorageClass.",
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
    settings_overrides: dict[str, object] | None = None,
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
            cluster_credential_store,
            remote_read_explorer_factory,
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
        assert "Investigation mode cannot change the cluster" in page.text
        assert '<section class="notice"' not in page.text
        assert "Read-only cluster assistant" not in page.text
        assert 'class="panel-header ask-session-header"' in page.text
        assert 'class="boundary-pill"' in page.text
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
        assert rendered.text.index('class="boundary-pill"') < rendered.text.index("data-evidence-open")
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


def test_ask_raw_response_toggle_persists_and_displays_both_answer_attempts(
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
        assert "2 attempts" in rendered.text
        assert "initial answer" in rendered.text
        assert "PodPilot correction" in rendered.text
        assert "Observed objects" in rendered.text
        assert "exact Pod remains Pending" in rendered.text

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
        assert [item["stage"] for item in attempts] == [
            "initial answer", "PodPilot correction",
        ]
        assert event is not None
        assert json.loads(event.details_json)["raw_response_requested"] is True
    engine.dispose()


def test_clicking_grounded_suggestion_runs_fresh_context_check_in_same_chat(
    tmp_path: Path,
) -> None:
    class FollowupProvider(FakeModelProvider):
        def plan_ad_hoc(self, profile, api_key: str, context: dict[str, object]) -> ReadPlan:
            self.adhoc_plan_calls.append(context)
            return ReadPlan(
                goal_type="diagnose",
                decision="answer_from_evidence",
                stop_reason="evidence_sufficient",
                scope_summary="The selected Service check is complete.",
                supporting_evidence_ids=["cluster-service-1"],
            )

        def answer_ad_hoc(
            self, profile, api_key: str, context: dict[str, object]
        ) -> AdHocAnswer:
            self.adhoc_answer_calls.append(context)
            return AdHocAnswer(
                answer_mode="evidence_based",
                conclusion_status="confirmed",
                answer=(
                    "## Selected check result\n\nThe backend Service port mapping was "
                    "collected in this linked evidence extension."
                ),
                cited_evidence_ids=["cluster-service-1"],
            )

    provider = FollowupProvider()
    explorer = RouteBackendExplorer(route_termination="passthrough")
    app, settings = make_app(
        tmp_path,
        assignments={"ivy": Role.INVESTIGATOR},
        source=FakeAlertSource(),
        credential_store=MemoryCredentialStore("test-api-token"),
        model_provider=provider,
        read_explorer=explorer,
    )
    conversation_id = "00000000-0000-0000-0000-000000000141"
    message_id = "00000000-0000-0000-0000-000000000142"
    route_evidence = {
        "id": "cluster-route-1",
        "cluster_id": SYSTEM_CLUSTER_ID,
        "cluster_name": "Runtime cluster",
        "tool": "search_resources",
        "summary": "Found the matching OpenShift Route.",
        "source": "kubernetes:route.openshift.io/v1:Route:maas/*",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "data": {
            "kind": "Route",
            "items": [{
                "kind": "Route",
                "metadata": {"namespace": "maas", "name": "maas"},
                "spec": {
                    "host": "maas.apps.example.test",
                    "to": {"kind": "Service", "name": "model-server"},
                },
            }],
        },
    }
    cluster = Cluster(id=SYSTEM_CLUSTER_ID, name="Runtime cluster")
    _, actions = _compile_suggested_followups(
        validated_answer={
            "recommended_next_checks": ["Inspect the backend Service port mapping."]
        },
        question="Why does the Route return HTTP 500?",
        evidence=[route_evidence],
        activity=[],
        cluster_runtimes=[{"cluster": cluster, "read_signatures": []}],
        remaining_units=5,
    )
    assert len(actions) == 1
    action = actions[0]

    engine = build_engine(settings)
    with Session(engine) as db_session:
        source_created_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.add(ModelProfile(
            id=1, provider_label="Internal", base_url="https://models.example.test/v1",
            chat_model="test-model", embedding_model=None, timeout_seconds=30,
            max_output_tokens=1200, status="ready", capabilities_json="{}", updated_by="ivy",
        ))
        db_session.add(AdHocConversation(
            id=conversation_id,
            created_by="ivy",
            title="Route failure",
            status="active",
            cluster_ids_json=json.dumps([SYSTEM_CLUSTER_ID]),
            evidence_json=json.dumps([route_evidence]),
        ))
        db_session.add(AdHocMessage(
            id="00000000-0000-0000-0000-000000000140",
            conversation_id=conversation_id,
            role="user",
            actor="ivy",
            content="Why does the Route return HTTP 500?",
            created_at=source_created_at,
        ))
        db_session.add(AdHocMessage(
            id=message_id,
            conversation_id=conversation_id,
            role="assistant",
            actor=None,
            content="The Route points to a backend Service.",
            answer_mode="evidence_based",
            citations_json=json.dumps(["cluster-route-1"]),
            tool_activity_json=json.dumps({
                "reads": [],
                "recommended_next_checks": [action["label"]],
                "suggested_followup_actions": actions,
            }),
            created_at=source_created_at + timedelta(milliseconds=500),
        ))
        db_session.commit()
    engine.dispose()

    with TestClient(app) as client:
        page = client.get(f"/ask/{conversation_id}", headers={"x-forwarded-user": "ivy"})
        csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text)
        assert csrf is not None
        assert "Run check" in page.text
        assert "Inspect the backend Service port mapping" in page.text
        unknown = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages/"
            f"{message_id}/followups/read-ffffffffffffffffffff",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
        )
        assert unknown.status_code == 404
        response = client.post(
            f"/api/v1/adhoc-conversations/{conversation_id}/messages/"
            f"{message_id}/followups/{action['id']}",
            headers={"x-forwarded-user": "ivy", "x-podpilot-csrf": csrf.group(1)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        rendered = client.get(response.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "Selected check result" in rendered.text

    assert [call.tool for call in explorer.calls] == ["get_resource"]
    assert explorer.calls[0].kind == "Service"
    assert provider.adhoc_plan_calls == []
    assert provider.adhoc_answer_calls
    assert "Original question:" in provider.adhoc_answer_calls[0]["question"]
    assert "Selected check:" in provider.adhoc_answer_calls[0]["question"]
    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.scalar(select(AdHocRun).where(
            AdHocRun.conversation_id == conversation_id
        ))
        assert run is not None
        stored_action = json.loads(run.followup_action_json)
        assert stored_action["id"] == action["id"]
        assert stored_action["source_message_id"] == message_id
        assert stored_action["source_question"] == "Why does the Route return HTTP 500?"
        assert "Run suggested check:" in run.message_text
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
    assert captured["api_url"] == "https://api.remote.example:6443"
    assert captured["token"] == "sha256~remote-monitoring-token"
    assert captured["tls_verify"] is True


def test_approver_renames_runtime_cluster_display_name(tmp_path: Path) -> None:
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
        assert 'data-save-url="/api/v1/clusters/' in page.text
        assert 'name="name"' in page.text
        assert "projected service-account connection remains managed by the deployment" in page.text

        headers = {"x-forwarded-user": "ada", "x-podpilot-csrf": csrf.group(1)}
        renamed = client.post(
            f"/api/v1/clusters/{SYSTEM_CLUSTER_ID}/rename",
            headers=headers,
            data={"name": "toronto-sno-lab"},
        )
        assert renamed.status_code == 200
        assert renamed.json() == {
            "status": "saved",
            "cluster_id": SYSTEM_CLUSTER_ID,
            "name": "toronto-sno-lab",
            "detail": "Runtime cluster renamed.",
        }

        dashboard = client.get("/", headers={"x-forwarded-user": "ada"})
        ask = client.get("/ask", headers={"x-forwarded-user": "ivy"})
        assert "test · toronto-sno-lab" in dashboard.text
        assert "toronto-sno-lab" in ask.text

        denied = client.post(
            f"/api/v1/clusters/{SYSTEM_CLUSTER_ID}/rename",
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
        assert "test · toronto-sno-lab" in dashboard.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        cluster = db_session.get(Cluster, SYSTEM_CLUSTER_ID)
        assert cluster is not None
        assert cluster.name == "toronto-sno-lab"
        assert cluster.api_url == "in-cluster://service-account"
        assert cluster.credential_key is None
        event = db_session.scalar(
            select(AuditEvent).where(AuditEvent.action == "cluster.rename")
        )
        assert event is not None
        assert json.loads(event.details_json) == {
            "cluster_id": SYSTEM_CLUSTER_ID,
            "name": "toronto-sno-lab",
            "previous_name": "test-cluster",
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
    assert provider.adhoc_plan_calls == []
    assert provider.adhoc_answer_calls == []
    assert set(explorers) == {"Central DEV", "East DEV"}
    for explorer in explorers.values():
        assert len(explorer.calls) == 1
        assert explorer.calls[0].tool == "query_metrics"
        assert explorer.calls[0].metric_scope == "cluster"
        assert explorer.calls[0].limit == 5


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
        assert "Access blocked by OpenShift RBAC" in rendered.text
        assert "HTTP 403" in rendered.text
        assert "Working on your question" not in rendered.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.scalar(select(AdHocRun))
        assert run is not None and run.status == "succeeded"
        assert run.completed_at is not None
    engine.dispose()


def test_ask_retries_heading_only_final_answer_once_with_bounded_feedback(
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
    assert "The exact Pod remains Pending" in rendered.text
    assert len(provider.adhoc_answer_calls) == 2
    feedback = provider.adhoc_answer_calls[1]["answer_feedback"]
    assert feedback["code"] == "incomplete_final_answer"
    assert feedback["reason"] == "heading_only_response"
    assert "Observed objects" not in json.dumps(feedback)


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


def test_ask_storageclass_inventory_uses_deterministic_read_without_model_plan(
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
        assert "StorageClass inventory" in rendered.text
        assert "managed-premium" in rendered.text
        assert "cluster-sc-1" in rendered.text
        assert "No observations were provided" not in rendered.text
        assert "Suggested next checks" not in rendered.text

    assert provider.adhoc_plan_calls == []
    assert provider.adhoc_answer_calls == []
    assert len(explorer.calls) == 1
    assert explorer.calls[0].api_version == "storage.k8s.io/v1"
    assert explorer.calls[0].kind == "StorageClass"
    assert explorer.calls[0].limit == 500


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
    assert "Configured termination" in rendered.text
    assert "forwards unencrypted HTTP" in rendered.text
    assert "maas/model-server" in rendered.text
    assert "model planner did not select a safe evidence read" not in rendered.text
    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource", "list_resources", "pod_logs",
        "get_resource", "search_resources",
    ]
    assert explorer.calls[1].name == "model-server"
    assert explorer.calls[2].kind == "Pod"
    assert explorer.calls[3].name == "model-server-abc"


def test_diagnostic_stop_is_reviewed_before_deferring_available_typed_reads(
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
    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource", "list_resources", "pod_logs",
        "get_resource", "search_resources",
    ]
    review_calls = [
        context for context in provider.adhoc_plan_calls
        if context.get("planner_feedback", {}).get("code") == "review_evidence_sufficiency"
    ]
    assert review_calls
    assert any(
        item["tool"] == "search_resources"
        for item in review_calls[0]["completed_reads"]
    )
    assert "reason=evidence_sufficiency_review" in caplog.text


def test_structured_answer_gap_is_replanned_into_typed_read_and_answer_regenerated(
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
    assert "collected Service maps its" in rendered.text
    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource",
    ]
    assert len(provider.adhoc_answer_calls) == 2
    gap_plan_context = next(
        context for context in provider.adhoc_plan_calls
        if context.get("investigation_gaps")
    )
    assert gap_plan_context["capability_ledger"]["checks"][0]["capability"] == (
        "service_spec"
    )
    assert any(
        edge["relation"] == "routes_to"
        for edge in gap_plan_context["relationship_graph"]["edges"]
    )
    assert "podpilot.adhoc.gap_followup_complete" in caplog.text


def test_embedded_answer_gap_is_recovered_without_rendering_serialized_fields(
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
    assert [call.tool for call in explorer.calls] == ["search_resources", "get_resource"]
    assert "collected Service maps its" in rendered.text
    assert "investigation_gaps" not in rendered.text
    assert "structured_fields_embedded_in_answer" in caplog.text
    assert "podpilot.adhoc.gap_followup_complete" in caplog.text
    final_context = provider.adhoc_answer_calls[-1]
    assert [
        gap["capability"] for gap in final_context["resolved_investigation_gaps"]
    ] == ["service_spec"]
    assert final_context["remaining_investigation_gaps"] == []


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
    first_context, second_context = provider.adhoc_plan_calls[:2]
    assert first_context["tool_policy"]["mode"] == "candidate_selection"
    assert "resource_catalog" not in first_context["tool_policy"]
    assert len(first_context["conversation"]) == 4
    assert len(first_context["read_candidates"]) <= 12
    assert all(
        "read_hint" not in edge
        for edge in second_context["relationship_graph"]["edges"]
    )
    assert any(
        item["capability"] == "service_spec"
        for item in second_context["read_candidates"]
    )
    assert any(
        item["capability"] == "http_probe"
        and item["target"] == "GET https://maas.apps.example.test/v1/models"
        for item in second_context["read_candidates"]
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
    assert all(candidate.capability != "pod_logs" for candidate in neutral_candidates)


def test_grounded_candidates_keep_query_relevant_catalog_reads_with_owner_edges() -> None:
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

    assert candidates[0].relation == "catalog_match"
    catalog_targets = [item for item in candidates if item.relation == "catalog_match"]
    assert {item.intent.kind for item in catalog_targets} == {"AuthConfig", "ConfigMap"}
    assert all(item.intent.namespace == "kuadrant-system" for item in catalog_targets)
    assert any(item.relation == "owned_by" for item in candidates)
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


def test_failure_investigation_collects_exact_logs_when_model_stops() -> None:
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

    assert [call.tool for call in explorer.calls] == ["pod_logs"]
    assert any(item["id"] == "cluster-backend-logs" for item in result.evidence)
    assert any(
        "exact workload log remained available" in limitation
        for limitation in result.limitations
    )


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
    assert any(item.capability == "endpoints" for item in candidates)


def test_structured_gap_recovery_executes_matching_grounded_candidate(
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
    assert [call.tool for call in explorer.calls] == ["search_resources", "get_resource"]
    assert "collected Service maps its" in rendered.text
    assert "podpilot.adhoc.gap_candidate_recovery" in caplog.text


def test_empty_investigate_selection_recovers_with_a_supplied_action(
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
    assert [call.tool for call in explorer.calls][:2] == ["search_resources", "http_probe"]
    assert any(call.tool == "get_resource" and call.kind == "Service" for call in explorer.calls)
    assert "podpilot.adhoc.action_candidate_recovery" in caplog.text


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


def test_heading_only_route_answer_retries_then_uses_deterministic_tls_answer(
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
    assert len(provider.adhoc_answer_calls) == 2
    assert "Configured termination" in rendered.text
    assert "forwards unencrypted HTTP" in rendered.text
    assert "Backend log findings" in rendered.text
    assert "tls or certificate" in rendered.text
    assert "/etc/certs/server.pem" in rendered.text
    assert "no such file or directory" in rendered.text.lower()
    assert "cluster-backend-logs" in rendered.text
    assert "Observed objects — what the cluster is actually doing" not in rendered.text
    assert "used grounded read candidates and deterministic evidence" in rendered.text


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
    assert "Configured termination" in rendered.text
    assert "forwards unencrypted HTTP" in rendered.text
    assert [call.tool for call in explorer.calls] == [
        "search_resources", "get_resource", "list_resources", "pod_logs",
        "get_resource", "search_resources",
    ]
    assert len(provider.adhoc_plan_calls) >= 3
    assert provider.adhoc_plan_calls[0]["observations"] == []
    assert provider.adhoc_plan_calls[1]["planner_feedback"]["code"] == (
        "actionable_goal_requires_evidence"
    )
    assert provider.adhoc_plan_calls[2]["completed_reads"][0]["tool"] == (
        "search_resources"
    )
    assert "podpilot.adhoc.operator_anchor_recovery" in caplog.text


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
                answer_mode="evidence_based",
                answer=(
                    "The discovered Authorino container log contains a 401 authentication "
                    "failure associated with an invalid token audience."
                ),
                cited_evidence_ids=["cluster-authorino-log"],
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
    assert [call.tool for call in explorer.calls] == ["search_resources", "pod_logs"]
    assert provider.log_analysis_calls
    assert "token audience invalid" in rendered.text
    assert "Model-assisted log analysis" in rendered.text


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

    assert [call.tool for call in explorer.calls] == ["search_resources"]
    assert [item["id"] for item in result.evidence] == ["cluster-route-1"]
    assert "correction was not schema-valid" in " ".join(result.limitations)
    assert "reason=invalid_correction" in caplog.text


def test_invalid_later_plan_continues_with_discovered_exact_candidate(caplog) -> None:
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

    assert [call.tool for call in explorer.calls] == ["list_resources", "get_resource"]
    assert explorer.calls[1].namespace == "vc-streams"
    assert explorer.calls[1].name == "vc-cluster"
    assert any(item["id"] == "cluster-kafka-detail" for item in result.evidence)
    assert "highest-priority unread candidate" in " ".join(result.limitations)
    assert "schema-invalid" in " ".join(result.limitations)
    assert "podpilot.adhoc.invalid_plan_candidate_recovery" in caplog.text
    assert "failure_type=schema_validation" in caplog.text


def test_passthrough_route_answer_cannot_hide_multiline_missing_pem_log(
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
    # A readable answer is retained even when the model omits a structured log
    # citation; the deterministic log section still exposes and cites that signal.
    assert len(provider.adhoc_answer_calls) == 1
    assert len(provider.log_analysis_calls) == 1
    assert provider.log_analysis_calls[0]["logs"][0]["evidence_id"] == "cluster-backend-logs"
    assert provider.log_analysis_calls[0]["investigation_context"] == (
        "This is a read-only OpenShift troubleshooting investigation. Analyze the bounded "
        "Pod logs for potential issues relevant to the operator request, including connectivity "
        "and TLS signals when present, without assuming they are causal."
    )
    assert "Internal Server Error over HTTPS" in provider.log_analysis_calls[0]["operator_request"]
    final_log = next(
        item for item in provider.adhoc_answer_calls[0]["observations"]
        if item["tool"] == "pod_logs"
    )
    assert "tail" not in final_log["data"]
    assert final_log["data"]["tailOmittedFromFinalContext"] is True
    assert "router forwards the client TLS stream" in rendered.text
    assert "Model-assisted log analysis" in rendered.text
    assert "backend process could not load its configured PEM certificate" in rendered.text
    assert "passthrough" in rendered.text
    assert "Backend log findings" in rendered.text
    assert "tls or certificate" in rendered.text
    assert "/etc/certs/server.pem" in rendered.text
    assert "no such file or directory" in rendered.text.lower()
    assert "cluster-backend-logs" in rendered.text


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
    assert provider.adhoc_plan_calls == []
    assert provider.adhoc_answer_calls == []
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


def test_ask_repairs_implied_health_intent_and_reads_live_catalog_target(
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
        assert "cluster-operators-1" in rendered.text

    assert len(explorer.calls) == 1
    assert explorer.calls[0].resource == "clusteroperators"
    assert explorer.calls[0].limit == 250
    assert len(provider.adhoc_plan_calls) == 3
    assert provider.adhoc_plan_calls[0]["read_candidates"][0]["target"] == (
        "List a bounded sample of ClusterOperator resources"
    )
    assert provider.adhoc_plan_calls[1]["planner_feedback"]["code"] == (
        "actionable_goal_requires_evidence"
    )
    assert provider.adhoc_plan_calls[2]["completed_reads"][0]["status"] == "succeeded"


def test_ask_does_not_override_model_direction_with_catalog_fallback(
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
        assert "could not provide a verified cluster-specific answer" in rendered.text
        assert "cluster-operators-1" not in rendered.text

    assert len(provider.adhoc_plan_calls) == 1
    assert provider.adhoc_plan_calls[0]["read_candidates"][0]["target"] == (
        "List a bounded sample of ClusterOperator resources"
    )
    assert explorer.calls == []


def test_ask_uses_safely_reduced_active_profile_and_shows_warning(
    tmp_path: Path,
) -> None:
    provider = FakeModelProvider()
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
        assert "Model running with reduced capability" in rendered.text
        assert "ReadPlan probe failed. Synthetic semantic mismatch." in rendered.text
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

    assert [call.tool for call in explorer.calls] == ["list_resources", "pod_logs"]
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
    assert "collected current logs from all three" in rendered.text
    assert "used exact discovered Pod/container targets" in rendered.text
    assert [call.tool for call in explorer.calls] == [
        "list_resources", "pod_logs", "pod_logs", "pod_logs",
    ]
    assert all("/" not in call.name for call in explorer.calls if call.tool == "pod_logs")
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
        )
        assert delete_active.status_code == 409

        provider.release_answer.set()
        terminal = None
        for _ in range(40):
            terminal = client.get(
                f"/api/v1/adhoc-runs/{run_id}", headers={"x-forwarded-user": "ivy"}
            ).json()
            if terminal["status"] == "succeeded":
                break
            time.sleep(0.05)
        assert terminal is not None and terminal["status"] == "succeeded"
        assert terminal["phase"] == "complete"

        event_stream = client.get(
            f"/api/v1/adhoc-runs/{run_id}/events",
            headers={"x-forwarded-user": "ivy"},
        )
        assert event_stream.status_code == 200
        assert "event: progress" in event_stream.text
        assert "event: complete" in event_stream.text
        assert "Preparing an evidence-backed answer" in event_stream.text

        completed = client.get(created.headers["location"], headers={"x-forwarded-user": "ivy"})
        assert "selector does not match" in completed.text
        assert "Live investigation" not in completed.text

    engine = build_engine(settings)
    with Session(engine) as db_session:
        run = db_session.get(AdHocRun, run_id)
        assert run is not None and run.status == "succeeded"
        assert run.assistant_message_id is not None
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


def test_ask_job_deadline_persists_terminal_failure_and_stops_spinner(tmp_path: Path) -> None:
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
        assert "Working on your question" not in rendered.text

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
    assert "Conversation budget reached" not in template
    assert "Enter to send" not in template and "Shift+Enter for a new line" not in template
    assert 'event.key === "Enter" && !event.shiftKey' in script
    assert "adhocForm.requestSubmit()" in script
    assert "appendOptimisticTurn" in script
    assert "new URLSearchParams(new FormData(adhocForm))" in script
    assert 'requestBody.set("message", question)' in script
    assert "rawResponseToggle.disabled = true" in script
    assert "rawResponseToggle.disabled = false" in script
    assert "data-cluster-picker" in template
    assert "cluster-picker-selection" in template
    assert "composer-meta-row" in template
    assert "composer-input-wrap" in template
    assert "Each question: up to" not in template
    assert 'chip.className = "cluster-picker-chip"' in script
    assert 'pickerLabel.replaceChildren()' in script
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
        memory = client.get("/memory", headers={"x-forwarded-user": "ivy"})

    for response in (dashboard, memory):
        assert response.status_code == 200
        assert 'class="nav-tree expanded"' in response.text
        assert 'aria-label="Ask PodPilot conversations"' in response.text
        assert f'href="/ask/{conversation_id}"' in response.text
        assert "Persistent sidebar session" in response.text


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
        assert probed.json()["diagnostic_call_count"] == 0
        engine = build_engine(settings)
        with Session(engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            assert profile is not None
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
                "reasoning_effort": "high",
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
        assert probe.json()["capabilities"]["ask_schemas"] is True
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
                "calls": [],
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
    assert "Model request failures" in rendered.text
    assert "schema validation · ActionSelection · attempt 2" in rendered.text
    assert "object_reads.0.resource" in rendered.text
