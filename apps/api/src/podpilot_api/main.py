from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from podpilot_api.auth import AuthContext, Role, RoleResolver, auth_dependency
from podpilot_api.database import build_engine, database_is_ready
from podpilot_api.markdown import render_safe_markdown
from podpilot_api.model_provider import (
    AdHocAnswer,
    InvestigationChatAnswer,
    ModelProfileConfig,
    ModelProvider,
    ModelProviderError,
    OpenAIResponsesProvider,
)
from podpilot_api.models import (
    AdHocConversation,
    AdHocMessage,
    AuditEvent,
    ChatMessage,
    DiagnosticCheck,
    Investigation,
    ModelProfile,
    RemediationAction,
)
from podpilot_api.settings import Settings, get_settings
from podpilot_diagnostics.alerts import AlertEvidence, analyze_alert
from podpilot_diagnostics.adhoc import ReadOnlyExplorer
from podpilot_diagnostics.checks import (
    DiagnosticCheckExecutor,
    DiagnosticCheckSpec,
    plan_diagnostic_checks,
)
from podpilot_diagnostics.redaction import redact_mapping, redact_text
from podpilot_diagnostics.remediation import (
    ActionProposal,
    RemediationExecutor,
    propose_actions,
)
from podpilot_openshift.alerts import (
    AlertRecord,
    AlertSnapshot,
    AlertSource,
    AlertSourceError,
    AlertmanagerClient,
)
from podpilot_openshift.credentials import (
    CredentialStore,
    CredentialStoreError,
    EnvironmentCredentialStore,
    KubernetesSecretCredentialStore,
)
from podpilot_openshift.explorer import KubernetesReadOnlyExplorer, ReadOnlyExplorerError
from podpilot_openshift.checks import KubernetesDiagnosticCheckExecutor
from podpilot_openshift.roles import LazyOpenShiftGroupRoleResolver
from podpilot_openshift.remediation import KubernetesRemediationExecutor, RemediationError
from podpilot_openshift.workloads import (
    KubernetesWorkloadClient,
    WorkloadEvidenceError,
    WorkloadEvidenceSource,
)

CSRF_COOKIE = "podpilot_csrf"


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _make_alert_source(settings: Settings) -> AlertSource:
    return AlertmanagerClient(
        base_url=settings.alertmanager_url,
        token_path=settings.service_account_token_path,
        ca_path=settings.service_ca_path,
        timeout_seconds=settings.alertmanager_timeout_seconds,
        max_alerts=settings.alertmanager_max_alerts,
    )


def _make_workload_source(settings: Settings) -> WorkloadEvidenceSource:
    return KubernetesWorkloadClient(
        max_events=settings.workload_max_events,
        log_tail_lines=settings.workload_log_tail_lines,
        max_log_bytes=settings.workload_max_log_bytes,
    )


def _make_credential_store(settings: Settings) -> CredentialStore:
    if settings.model_credential_store == "kubernetes":
        return KubernetesSecretCredentialStore(
            settings.model_secret_namespace,
            settings.model_secret_name,
            settings.model_secret_key,
        )
    return EnvironmentCredentialStore()


def _profile_config(profile: ModelProfile) -> ModelProfileConfig:
    return ModelProfileConfig(
        provider_label=profile.provider_label,
        base_url=profile.base_url,
        chat_model=profile.chat_model,
        embedding_model=profile.embedding_model,
        timeout_seconds=profile.timeout_seconds,
        max_output_tokens=profile.max_output_tokens,
    )


async def _urlencoded(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0]
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Form data must be URL encoded.")
    values = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    return {key: items[-1] for key, items in values.items()}


def _csrf_token(request: Request) -> tuple[str, bool]:
    existing = request.cookies.get(CSRF_COOKIE, "")
    if 32 <= len(existing) <= 128:
        return existing, False
    return secrets.token_urlsafe(32), True


def _verify_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("x-podpilot-csrf", "")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The request could not be verified. Refresh the page and try again.",
        )


def _to_evidence(alert: AlertRecord) -> AlertEvidence:
    return AlertEvidence(
        fingerprint=alert.fingerprint,
        name=alert.name,
        state=alert.state,
        severity=alert.severity,
        namespace=alert.namespace,
        starts_at=alert.starts_at,
        labels=redact_mapping(alert.labels),
        annotations=redact_mapping(alert.annotations),
    )


def _redact_alert(alert: AlertRecord) -> AlertRecord:
    return replace(
        alert,
        labels=redact_mapping(alert.labels),
        annotations=redact_mapping(alert.annotations),
    )


def _proposal_from_json(value: str) -> ActionProposal:
    payload = json.loads(value)
    payload["created_at"] = datetime.fromisoformat(payload["created_at"])
    payload["expires_at"] = datetime.fromisoformat(payload["expires_at"])
    return ActionProposal(**payload)


def _check_spec_from_row(check: DiagnosticCheck) -> DiagnosticCheckSpec:
    payload = json.loads(check.input_json)
    return DiagnosticCheckSpec(**payload)


def _validated_chat_answer(
    answer: InvestigationChatAnswer,
    *,
    known_evidence_ids: set[str],
    queued_checks: int,
) -> dict[str, object]:
    citations: list[str] = []
    for evidence_id in answer.cited_evidence_ids:
        bounded = str(evidence_id)[:128]
        if bounded in known_evidence_ids and bounded not in citations:
            citations.append(bounded)
    mode = answer.answer_mode
    content = redact_text(answer.answer)[:2400]
    if mode == "evidence_based" and not citations:
        mode = "insufficient_evidence"
        content = (
            "The model response did not cite evidence present in this investigation, "
            "so PodPilot withheld its factual answer. Run available checks or ask a narrower question."
        )
    intent = None
    if answer.proposed_tool_intent == "run_queued_checks" and queued_checks > 0:
        intent = {
            "name": "run_queued_checks",
            "reason": redact_text(answer.intent_reason or "Collect the queued registered evidence.")[:500],
        }
    return {
        "answer_mode": mode,
        "content": content,
        "citations": citations,
        "tool_intent": intent,
    }


def _validated_adhoc_answer(
    answer: AdHocAnswer, *, known_evidence_ids: set[str]
) -> dict[str, object]:
    citations: list[str] = []
    for evidence_id in answer.cited_evidence_ids:
        bounded = str(evidence_id)[:128]
        if bounded in known_evidence_ids and bounded not in citations:
            citations.append(bounded)
    mode = answer.answer_mode
    content = redact_text(answer.answer)[:4000]
    if mode == "evidence_based" and not citations:
        mode = "insufficient_evidence"
        content = (
            "The model response did not cite evidence collected for this conversation, "
            "so PodPilot withheld its cluster-specific answer. Add a namespace and resource name, "
            "or ask a narrower question."
        )
    return {
        "answer_mode": mode,
        "content": content,
        "citations": citations,
        "limitations": [redact_text(item)[:500] for item in answer.limitations[:6]],
    }


def _compact_adhoc_context(
    db_session: Session,
    *,
    conversation: AdHocConversation,
    recent_limit: int,
    summary_char_limit: int,
) -> list[dict[str, str]]:
    """Persist a bounded digest of older messages and return the recent context window."""
    total = db_session.scalar(
        select(func.count()).select_from(AdHocMessage).where(
            AdHocMessage.conversation_id == conversation.id
        )
    ) or 0
    older_count = max(0, total - recent_limit)
    if older_count > conversation.summarized_message_count:
        additions = list(db_session.scalars(
            select(AdHocMessage).where(AdHocMessage.conversation_id == conversation.id)
            .order_by(AdHocMessage.created_at, AdHocMessage.id)
            .offset(conversation.summarized_message_count)
            .limit(older_count - conversation.summarized_message_count)
        ))
        digest_lines = [conversation.context_summary] if conversation.context_summary else []
        digest_lines.extend(
            f"{row.role}: {redact_text(row.content)[:500]}" for row in additions
        )
        conversation.context_summary = "\n".join(digest_lines)[-summary_char_limit:]
        conversation.summarized_message_count = older_count
        db_session.flush()
    recent_rows = list(db_session.scalars(
        select(AdHocMessage).where(AdHocMessage.conversation_id == conversation.id)
        .order_by(AdHocMessage.created_at.desc(), AdHocMessage.id.desc())
        .limit(recent_limit)
    ))
    return [
        {"role": row.role, "content": row.content}
        for row in reversed(recent_rows)
    ]


def _enforce_adhoc_rate_limit(
    db_session: Session, *, username: str, now: datetime, limit: int
) -> None:
    recent = db_session.scalar(
        select(func.count()).select_from(AdHocMessage).where(
            AdHocMessage.actor == username,
            AdHocMessage.role == "user",
            AdHocMessage.created_at >= now - timedelta(minutes=1),
        )
    ) or 0
    if recent >= limit:
        raise HTTPException(
            status_code=429,
            detail="Ask PodPilot is receiving questions too quickly. Wait a minute and retry.",
        )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _closure_result(
    *, summary: str, actor: str, reason: str, detail: str, closed_at: datetime
) -> str:
    return json.dumps(
        {
            "summary": summary,
            "verification": {},
            "closure": {
                "actor": actor,
                "reason": reason,
                "detail": detail,
                "closed_at": closed_at.isoformat(),
            },
        },
        sort_keys=True,
    )


def _close_preview(
    db_session: Session,
    *,
    action: RemediationAction,
    investigation: Investigation,
    status_value: str,
    actor: str,
    audit_action: str,
    reason: str,
    summary: str,
    detail: str,
    now: datetime,
) -> bool:
    claimed = db_session.execute(
        update(RemediationAction)
        .where(
            RemediationAction.id == action.id,
            RemediationAction.status == "preview_ready",
        )
        .values(
            status=status_value,
            result_json=_closure_result(
                summary=summary,
                actor=actor,
                reason=reason,
                detail=detail,
                closed_at=now,
            ),
        )
    )
    if claimed.rowcount != 1:
        return False
    db_session.add(
        AuditEvent(
            actor=actor,
            action=audit_action,
            outcome=status_value,
            details_json=json.dumps(
                {
                    "action_id": action.id,
                    "investigation_id": investigation.id,
                    "reason": reason,
                    "detail": detail,
                },
                sort_keys=True,
            ),
        )
    )
    db_session.flush()
    remaining = db_session.scalar(
        select(func.count())
        .select_from(RemediationAction)
        .where(
            RemediationAction.investigation_id == investigation.id,
            RemediationAction.status == "preview_ready",
        )
    ) or 0
    if remaining == 0 and investigation.status == "awaiting_approval":
        investigation.status = "cancelled"
    return True


def _reconcile_alert_lifecycle(
    db_session: Session,
    *,
    now: datetime,
    active_fingerprints: set[str] | None,
) -> int:
    changed = 0
    rows = list(
        db_session.execute(
            select(RemediationAction, Investigation)
            .join(Investigation, RemediationAction.investigation_id == Investigation.id)
            .where(RemediationAction.status == "preview_ready")
        )
    )
    for action, investigation in rows:
        if now > _aware(action.expires_at):
            changed += int(
                _close_preview(
                    db_session,
                    action=action,
                    investigation=investigation,
                    status_value="expired",
                    actor="system:reconciler",
                    audit_action="remediation.expire",
                    reason="preview_expired",
                    summary="The approval window expired without execution.",
                    detail="Generate a fresh investigation before approving a remediation.",
                    now=now,
                )
            )
        elif (
            active_fingerprints is not None
            and investigation.alert_fingerprint not in active_fingerprints
        ):
            changed += int(
                _close_preview(
                    db_session,
                    action=action,
                    investigation=investigation,
                    status_value="cancelled",
                    actor="system:reconciler",
                    audit_action="remediation.reconcile",
                    reason="source_alert_not_active",
                    summary="The preview was cancelled because its source alert is no longer active.",
                    detail="Create a fresh investigation if the condition returns.",
                    now=now,
                )
            )
    if changed:
        db_session.commit()
    return changed


def create_app(
    settings: Settings | None = None,
    role_resolver: RoleResolver | None = None,
    alert_source: AlertSource | None = None,
    workload_source: WorkloadEvidenceSource | None = None,
    credential_store: CredentialStore | None = None,
    model_provider: ModelProvider | None = None,
    remediation_executor: RemediationExecutor | None = None,
    diagnostic_executor: DiagnosticCheckExecutor | None = None,
    read_explorer: ReadOnlyExplorer | None = None,
) -> FastAPI:
    app_settings = settings or get_settings()
    resolver = role_resolver or LazyOpenShiftGroupRoleResolver(
        cache_seconds=app_settings.role_cache_seconds
    )
    alerts = alert_source or _make_alert_source(app_settings)
    workloads = workload_source or _make_workload_source(app_settings)
    credentials = credential_store or _make_credential_store(app_settings)
    provider = model_provider or OpenAIResponsesProvider()
    executor = remediation_executor or KubernetesRemediationExecutor()
    check_executor = diagnostic_executor or KubernetesDiagnosticCheckExecutor(
        max_events=app_settings.workload_max_events,
        thanos_url=app_settings.thanos_url,
        token_path=app_settings.service_account_token_path,
        ca_path=app_settings.service_ca_path,
        monitoring_timeout_seconds=app_settings.thanos_timeout_seconds,
        monitoring_max_series=app_settings.thanos_max_series,
    )
    cluster_reader = read_explorer or KubernetesReadOnlyExplorer(
        log_tail_lines=app_settings.workload_log_tail_lines,
        max_log_bytes=app_settings.workload_max_log_bytes,
    )
    templates = Jinja2Templates(directory=app_settings.web_dir / "templates")
    templates.env.filters["safe_markdown"] = render_safe_markdown

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = app_settings
        application.state.engine = build_engine(app_settings)
        yield
        application.state.engine.dispose()

    app = FastAPI(
        title="PodPilot",
        version="0.10.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.mount(
        "/static",
        StaticFiles(directory=app_settings.web_dir / "static"),
        name="static",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    current_user = auth_dependency(app_settings, resolver)

    async def _run_adhoc_turn(
        *, request: Request, user: AuthContext, conversation_id: str, message_text: str
    ) -> None:
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None or conversation.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot conversation does not exist.")
            _enforce_adhoc_rate_limit(
                db_session, username=user.username, now=now,
                limit=app_settings.adhoc_rate_limit_per_minute,
            )
            db_session.add(AdHocMessage(
                id=str(uuid4()), conversation_id=conversation_id, role="user",
                actor=user.username, content=message_text,
            ))
            db_session.add(AuditEvent(
                actor=user.username, action="adhoc.message", outcome="accepted",
                details_json=json.dumps({"conversation_id": conversation_id}, sort_keys=True),
            ))
            conversation.updated_at = now
            db_session.commit()

        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            evidence = list(json.loads(conversation.evidence_json))
            history = _compact_adhoc_context(
                db_session,
                conversation=conversation,
                recent_limit=app_settings.adhoc_context_messages,
                summary_char_limit=app_settings.adhoc_context_summary_chars,
            )
            context_summary = conversation.context_summary
            profile = db_session.get(ModelProfile, 1)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
            db_session.commit()

        activity: list[dict[str, object]] = []
        limitations: list[str] = []
        provider_status = "ready"
        validated: dict[str, object] = {
            "answer_mode": "insufficient_evidence",
            "content": "Configure and successfully test a model profile before using Ask PodPilot.",
            "citations": [],
            "limitations": [],
        }
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                seen_intents: set[str] = set()
                reads_used = 0
                scope_summary = "Bounded read-only cluster investigation."
                plan_limitations: list[str] = []
                for round_number in range(1, app_settings.adhoc_max_rounds + 1):
                    remaining_reads = app_settings.adhoc_max_reads_per_turn - reads_used
                    if remaining_reads <= 0:
                        break
                    plan = await run_in_threadpool(
                        provider.plan_ad_hoc,
                        profile_snapshot,
                        api_key,
                        {
                            "cluster": app_settings.cluster_name,
                            "question": message_text,
                            "conversation": history,
                            "earlier_context_summary": context_summary,
                            "observations": evidence[-app_settings.adhoc_max_evidence :],
                            "completed_reads": activity,
                            "investigation_round": round_number,
                            "tool_policy": {
                                "available": ["get_resource", "list_resources", "pod_logs"],
                                "max_rounds": app_settings.adhoc_max_rounds,
                                "max_reads_total": app_settings.adhoc_max_reads_per_turn,
                                "remaining_reads": remaining_reads,
                                "logs_and_configmaps_allowed": True,
                                "secrets_and_mutations_allowed": False,
                            },
                        },
                    )
                    scope_summary = plan.scope_summary
                    plan_limitations = list(plan.limitations)
                    new_intents = []
                    for intent in plan.intents[:remaining_reads]:
                        signature = json.dumps(intent.model_dump(exclude_none=True), sort_keys=True)
                        if signature not in seen_intents:
                            seen_intents.add(signature)
                            new_intents.append(intent)
                    if not new_intents:
                        break
                    for intent in new_intents:
                        reads_used += 1
                        entry: dict[str, object] = {
                            "round": round_number,
                            "tool": intent.tool,
                            "target": f"{intent.api_version or 'v1'} {intent.kind or 'Pod'} "
                            f"{intent.namespace or 'cluster'}/{intent.name or '*'}"
                            + (f" container={intent.container}" if intent.container else "")
                            + (" previous=true" if intent.tool == "pod_logs" and intent.previous else ""),
                        }
                        try:
                            result = await run_in_threadpool(cluster_reader.execute, intent)
                            evidence.extend(item.to_dict() for item in result.observations)
                            limitations.extend(result.limitations)
                            entry["status"] = "succeeded"
                            entry["observations"] = len(result.observations)
                        except ReadOnlyExplorerError as exc:
                            limitations.append(str(exc))
                            entry["status"] = "denied_or_unavailable"
                            entry["detail"] = str(exc)
                        activity.append(entry)
                    evidence = evidence[-app_settings.adhoc_max_evidence :]
                limitations.extend(plan_limitations)
                answer = await run_in_threadpool(
                    provider.answer_ad_hoc,
                    profile_snapshot,
                    api_key,
                    {
                        "cluster": app_settings.cluster_name,
                        "question": message_text,
                        "conversation": history,
                        "earlier_context_summary": context_summary,
                        "scope_summary": scope_summary,
                        "observations": evidence,
                        "collection_limitations": limitations[:10],
                    },
                )
                validated = _validated_adhoc_answer(
                    answer, known_evidence_ids={str(item.get("id")) for item in evidence}
                )
                validated["limitations"] = list(dict.fromkeys(
                    [*limitations, *list(validated["limitations"])]
                ))[:8]
            except (CredentialStoreError, ModelProviderError) as exc:
                provider_status = "unavailable"
                validated = {
                    "answer_mode": "insufficient_evidence",
                    "content": "The model provider is currently unavailable. No cluster changes were attempted.",
                    "citations": [],
                    "limitations": [str(exc)],
                }
        elif profile is not None:
            provider_status = profile.status

        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            conversation.evidence_json = json.dumps(evidence, default=_json_default, sort_keys=True)
            conversation.updated_at = datetime.now(timezone.utc)
            db_session.add(AdHocMessage(
                id=str(uuid4()), conversation_id=conversation_id, role="assistant", actor=None,
                content=str(validated["content"]), answer_mode=str(validated["answer_mode"]),
                citations_json=json.dumps(validated["citations"], sort_keys=True),
                tool_activity_json=json.dumps(
                    {"reads": activity, "limitations": validated["limitations"]}, sort_keys=True
                ),
                provider_status=provider_status,
            ))
            db_session.add(AuditEvent(
                actor="system:podpilot", action="adhoc.answer", outcome=provider_status,
                details_json=json.dumps({
                    "conversation_id": conversation_id,
                    "read_count": len(activity),
                    "evidence_count": len(evidence),
                    "citation_count": len(validated["citations"]),
                }, sort_keys=True),
            ))
            db_session.commit()

    @app.get("/ask", response_class=HTMLResponse)
    async def ask_podpilot(
        request: Request, user: AuthContext = Depends(current_user)
    ):
        csrf_token, csrf_is_new = _csrf_token(request)
        with Session(request.app.state.engine) as db_session:
            recent = list(db_session.scalars(
                select(AdHocConversation).where(AdHocConversation.created_by == user.username)
                .order_by(AdHocConversation.updated_at.desc()).limit(20)
            ))
            profile = db_session.get(ModelProfile, 1)
        response = templates.TemplateResponse(
            request=request, name="ask.html", context={
                "user": user, "conversation": None, "messages": [], "evidence_by_id": {},
                "recent_conversations": recent, "csrf_token": csrf_token,
                "chat_max_chars": app_settings.chat_max_chars,
                "model_ready": bool(profile and profile.status == "ready"),
            },
        )
        if csrf_is_new:
            response.set_cookie(CSRF_COOKIE, csrf_token, secure=app_settings.auth_mode == "proxy",
                                httponly=True, samesite="strict", max_age=28_800)
        return response

    @app.get("/ask/{conversation_id}", response_class=HTMLResponse)
    async def ask_podpilot_conversation(
        conversation_id: str, request: Request, user: AuthContext = Depends(current_user)
    ):
        csrf_token, csrf_is_new = _csrf_token(request)
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None or conversation.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot conversation does not exist.")
            rows = list(db_session.scalars(
                select(AdHocMessage).where(AdHocMessage.conversation_id == conversation_id)
                .order_by(AdHocMessage.created_at.desc(), AdHocMessage.id.desc())
                .limit(app_settings.adhoc_display_messages)
            ))
            rows.reverse()
            evidence = json.loads(conversation.evidence_json)
            recent = list(db_session.scalars(
                select(AdHocConversation).where(AdHocConversation.created_by == user.username)
                .order_by(AdHocConversation.updated_at.desc()).limit(20)
            ))
            profile = db_session.get(ModelProfile, 1)
        messages = [{
            "role": row.role, "actor": row.actor, "content": row.content,
            "answer_mode": row.answer_mode, "citations": json.loads(row.citations_json),
            "activity": json.loads(row.tool_activity_json), "provider_status": row.provider_status,
            "created_at": row.created_at,
        } for row in rows]
        response = templates.TemplateResponse(
            request=request, name="ask.html", context={
                "user": user, "conversation": conversation, "messages": messages,
                "evidence_by_id": {item["id"]: item for item in evidence},
                "recent_conversations": recent, "csrf_token": csrf_token,
                "chat_max_chars": app_settings.chat_max_chars,
                "model_ready": bool(profile and profile.status == "ready"),
                "messages_truncated": conversation.summarized_message_count > 0,
            },
        )
        if csrf_is_new:
            response.set_cookie(CSRF_COOKIE, csrf_token, secure=app_settings.auth_mode == "proxy",
                                httponly=True, samesite="strict", max_age=28_800)
        return response

    @app.post("/api/v1/adhoc-conversations")
    async def create_adhoc_conversation(
        request: Request, user: AuthContext = Depends(current_user)
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(status_code=403, detail="Ask PodPilot requires the Investigator role or higher.")
        form = await _urlencoded(request)
        raw_message = form.get("message", "").strip()
        if not raw_message or len(raw_message) > app_settings.chat_max_chars:
            raise HTTPException(status_code=422, detail="Enter a bounded question for PodPilot.")
        message = redact_text(raw_message)[:app_settings.chat_max_chars]
        conversation_id = str(uuid4())
        with Session(request.app.state.engine) as db_session:
            _enforce_adhoc_rate_limit(
                db_session, username=user.username, now=datetime.now(timezone.utc),
                limit=app_settings.adhoc_rate_limit_per_minute,
            )
            db_session.add(AdHocConversation(
                id=conversation_id, created_by=user.username,
                title=message.replace("\n", " ")[:100], status="active", evidence_json="[]",
            ))
            db_session.commit()
        await _run_adhoc_turn(request=request, user=user, conversation_id=conversation_id, message_text=message)
        return RedirectResponse(f"/ask/{conversation_id}", status_code=303)

    @app.post("/api/v1/adhoc-conversations/{conversation_id}/messages")
    async def continue_adhoc_conversation(
        conversation_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(status_code=403, detail="Ask PodPilot requires the Investigator role or higher.")
        form = await _urlencoded(request)
        raw_message = form.get("message", "").strip()
        if not raw_message or len(raw_message) > app_settings.chat_max_chars:
            raise HTTPException(status_code=422, detail="Enter a bounded question for PodPilot.")
        await _run_adhoc_turn(
            request=request, user=user, conversation_id=conversation_id,
            message_text=redact_text(raw_message)[:app_settings.chat_max_chars],
        )
        return RedirectResponse(f"/ask/{conversation_id}", status_code=303)

    @app.post("/api/v1/adhoc-conversations/{conversation_id}/delete")
    async def delete_adhoc_conversation(
        conversation_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> RedirectResponse:
        _verify_csrf(request)
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None or conversation.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot conversation does not exist.")
            db_session.execute(
                delete(AdHocMessage).where(AdHocMessage.conversation_id == conversation_id)
            )
            db_session.delete(conversation)
            db_session.add(AuditEvent(
                actor=user.username,
                action="adhoc.delete",
                outcome="deleted",
                details_json=json.dumps({"conversation_id": conversation_id}, sort_keys=True),
            ))
            db_session.commit()
        return RedirectResponse("/ask", status_code=303)

    @app.get("/settings/model", response_class=HTMLResponse)
    async def model_settings(
        request: Request,
        user: AuthContext = Depends(current_user),
    ):
        csrf_token, csrf_is_new = _csrf_token(request)
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            profile_view = None
            if profile:
                profile_view = {
                    "provider_label": profile.provider_label,
                    "base_url": profile.base_url,
                    "chat_model": profile.chat_model,
                    "embedding_model": profile.embedding_model or "",
                    "timeout_seconds": profile.timeout_seconds,
                    "max_output_tokens": profile.max_output_tokens,
                    "status": profile.status,
                    "capabilities": json.loads(profile.capabilities_json),
                    "last_error": profile.last_error,
                    "last_probe_at": profile.last_probe_at,
                    "updated_by": profile.updated_by,
                    "updated_at": profile.updated_at,
                }
        credential_error = None
        try:
            token_configured = bool(credentials.get())
        except CredentialStoreError as exc:
            token_configured = False
            credential_error = str(exc)
        response = templates.TemplateResponse(
            request=request,
            name="model_settings.html",
            context={
                "user": user,
                "profile": profile_view,
                "token_configured": token_configured,
                "credential_error": credential_error,
                "csrf_token": csrf_token,
            },
        )
        if csrf_is_new:
            response.set_cookie(
                CSRF_COOKIE,
                csrf_token,
                secure=app_settings.auth_mode == "proxy",
                httponly=True,
                samesite="strict",
                max_age=28_800,
            )
        return response

    @app.post("/api/v1/model-profile")
    async def save_model_profile(
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Model settings require the Approver role or higher.")
        form = await _urlencoded(request)
        provider_label = form.get("provider_label", "").strip()
        base_url = form.get("base_url", "").strip().rstrip("/")
        chat_model = form.get("chat_model", "").strip()
        embedding_model = form.get("embedding_model", "").strip() or None
        token = form.get("api_token", "").strip()
        parsed_url = urlparse(base_url)
        if not provider_label or len(provider_label) > 100:
            raise HTTPException(status_code=422, detail="Provider label is required and must be at most 100 characters.")
        if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.username or parsed_url.password:
            raise HTTPException(status_code=422, detail="Base URL must be an HTTPS endpoint without embedded credentials.")
        if not chat_model or len(chat_model) > 253:
            raise HTTPException(status_code=422, detail="A valid chat model name is required.")
        try:
            timeout_seconds = float(form.get("timeout_seconds", "30"))
            max_output_tokens = int(form.get("max_output_tokens", "1200"))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Timeout and token budget must be numeric.") from exc
        if not 3 <= timeout_seconds <= 120 or not 128 <= max_output_tokens <= 16_384:
            raise HTTPException(status_code=422, detail="Timeout or token budget is outside the allowed range.")
        if token:
            if len(token) < 8 or len(token) > 8192:
                raise HTTPException(status_code=422, detail="The submitted token length is invalid.")
            try:
                await run_in_threadpool(credentials.set, token)
            except CredentialStoreError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        else:
            try:
                if not await run_in_threadpool(credentials.get):
                    raise HTTPException(status_code=422, detail="An API token is required for the first profile save.")
            except CredentialStoreError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc

        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, 1) or ModelProfile(id=1, updated_by=user.username)
            profile.provider_label = provider_label
            profile.base_url = base_url
            profile.chat_model = chat_model
            profile.embedding_model = embedding_model
            profile.timeout_seconds = timeout_seconds
            profile.max_output_tokens = max_output_tokens
            profile.status = "not_tested"
            profile.capabilities_json = "{}"
            profile.last_error = None
            profile.last_probe_at = None
            profile.updated_by = user.username
            profile.updated_at = now
            db_session.add(profile)
            db_session.add(AuditEvent(
                actor=user.username,
                action="model_profile.save",
                outcome="not_tested",
                details_json=json.dumps({"provider_label": provider_label, "base_url": base_url, "chat_model": chat_model}, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({"status": "saved", "token_configured": True})

    @app.post("/api/v1/model-profile/probe")
    async def probe_model_profile(
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Testing model settings requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            if profile is None:
                raise HTTPException(status_code=409, detail="Save a model profile before testing it.")
            config_snapshot = _profile_config(profile)
        try:
            api_key = await run_in_threadpool(credentials.get)
            if not api_key:
                raise ModelProviderError("No model API token is configured.")
            report = await run_in_threadpool(provider.probe, config_snapshot, api_key)
            outcome = "ready" if report.ready else "reduced_capability"
            capabilities = report.to_dict()
            error = None if report.ready else "The endpoint lacks one or more required capabilities."
        except (CredentialStoreError, ModelProviderError) as exc:
            outcome = "unavailable"
            capabilities = {}
            error = str(exc)
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            if profile is None:
                raise HTTPException(status_code=409, detail="The model profile changed during the probe.")
            profile.status = outcome
            profile.capabilities_json = json.dumps(capabilities, sort_keys=True)
            profile.last_error = error
            profile.last_probe_at = now
            db_session.add(AuditEvent(
                actor=user.username,
                action="model_profile.probe",
                outcome=outcome,
                details_json=json.dumps({"capabilities": capabilities}, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({"status": outcome, "capabilities": capabilities, "detail": error})

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/") or request.url.path.startswith("/health/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={"status_code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    async def ready(request: Request) -> JSONResponse:
        ready_now = database_is_ready(request.app.state.engine)
        return JSONResponse(
            {"status": "ready" if ready_now else "not-ready", "database": ready_now},
            status_code=200 if ready_now else 503,
        )

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(
        request: Request,
        user: AuthContext = Depends(current_user),
    ):
        snapshot: AlertSnapshot | None = None
        alert_error: str | None = None
        try:
            snapshot = await run_in_threadpool(alerts.fetch)
        except AlertSourceError as exc:
            alert_error = str(exc)

        active_alerts = [_redact_alert(alert) for alert in snapshot.alerts] if snapshot else []
        watchdogs = [alert for alert in active_alerts if alert.is_watchdog]
        queue_alerts = [alert for alert in active_alerts if not alert.is_watchdog]
        actionable = [
            alert
            for alert in queue_alerts
            if alert.state == "active" and not alert.is_silenced and not alert.is_inhibited
        ]
        csrf_token, csrf_is_new = _csrf_token(request)

        with Session(request.app.state.engine) as db_session:
            _reconcile_alert_lifecycle(
                db_session,
                now=datetime.now(timezone.utc),
                active_fingerprints=(
                    {alert.fingerprint for alert in active_alerts if alert.state == "active"}
                    if snapshot is not None and snapshot.is_complete
                    else None
                ),
            )
            recent = list(
                db_session.scalars(
                    select(Investigation)
                    .order_by(Investigation.created_at.desc())
                    .limit(5)
                )
            )
            awaiting_approval_count = db_session.scalar(
                select(func.count())
                .select_from(RemediationAction)
                .where(
                    RemediationAction.status == "preview_ready",
                    RemediationAction.expires_at > datetime.now(timezone.utc),
                )
            ) or 0

        response = templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "user": user,
                "cluster_name": app_settings.cluster_name,
                "environment": app_settings.environment,
                "poc_mode": app_settings.poc_mode,
                "now": datetime.now(timezone.utc),
                "snapshot": snapshot,
                "alert_error": alert_error,
                "actionable_alerts": actionable,
                "queue_alerts": queue_alerts,
                "watchdogs": watchdogs,
                "silenced_count": sum(alert.is_silenced for alert in active_alerts),
                "inhibited_count": sum(alert.is_inhibited for alert in active_alerts),
                "recent_investigations": recent,
                "awaiting_approval_count": awaiting_approval_count,
                "csrf_token": csrf_token,
            },
        )
        if csrf_is_new:
            response.set_cookie(
                CSRF_COOKIE,
                csrf_token,
                secure=app_settings.auth_mode == "proxy",
                httponly=True,
                samesite="strict",
                max_age=28_800,
            )
        return response

    @app.post("/api/v1/alerts/{fingerprint}/investigations")
    async def create_investigation(
        fingerprint: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Starting an investigation requires the Investigator role or higher.",
            )
        try:
            snapshot = await run_in_threadpool(alerts.fetch)
        except AlertSourceError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        alert = next(
            (candidate for candidate in snapshot.alerts if candidate.fingerprint == fingerprint),
            None,
        )
        if alert is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="That alert is no longer active. Refresh the alert queue.",
            )

        investigation_id = str(uuid4())
        evidence = _to_evidence(alert)
        workload = None
        workload_failure = None
        pod_name = evidence.labels.get("pod")
        if alert.name in {
            "KubePodCrashLooping",
            "KubeContainerWaiting",
            "KubePodNotScheduled",
        }:
            if not evidence.namespace or not pod_name:
                workload_failure = (
                    "The alert did not identify both a namespace and Pod, so live workload evidence was not collected."
                )
            else:
                try:
                    workload = await run_in_threadpool(
                        workloads.collect,
                        namespace=evidence.namespace,
                        pod_name=pod_name,
                        container_name=evidence.labels.get("container"),
                        include_logs=alert.name == "KubePodCrashLooping",
                        include_nodes=alert.name == "KubePodNotScheduled",
                    )
                except WorkloadEvidenceError as exc:
                    workload_failure = str(exc)
        analysis = analyze_alert(evidence, workload=workload)
        if workload_failure:
            analysis = replace(
                analysis,
                limitations=(*analysis.limitations, workload_failure),
            )
        alert_snapshot = {
            "fingerprint": evidence.fingerprint,
            "state": evidence.state,
            "labels": evidence.labels,
            "annotations": evidence.annotations,
            "starts_at": evidence.starts_at,
            "collected_at": snapshot.collected_at,
            "silenced": alert.is_silenced,
            "inhibited": alert.is_inhibited,
            "workload": workload.to_dict() if workload else None,
        }
        alert_json = json.dumps(alert_snapshot, default=_json_default, sort_keys=True)
        analysis_payload = analysis.to_dict()
        model_result: dict[str, object] = {"status": "not_configured"}
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, 1)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                interpretation = await run_in_threadpool(
                    provider.interpret,
                    profile_snapshot,
                    api_key,
                    {"alert": alert_snapshot, "deterministic_analysis": analysis_payload},
                )
                model_result = {"status": "ready", **interpretation.model_dump()}
            except (CredentialStoreError, ModelProviderError) as exc:
                model_result = {"status": "unavailable", "detail": str(exc)}
        elif profile is not None:
            model_result = {"status": profile.status}
            if profile.last_error:
                model_result["detail"] = profile.last_error
        analysis_payload["model"] = model_result
        analysis_json = json.dumps(analysis_payload, default=_json_default, sort_keys=True)
        proposals = (
            propose_actions(
                investigation_id=investigation_id,
                alert_name=alert.name,
                cluster=app_settings.cluster_name,
                workload=workload,
            )
            if workload
            else ()
        )
        action_records: list[RemediationAction] = []
        for proposal in proposals:
            try:
                preview = await run_in_threadpool(executor.preview, proposal)
                action_status = "preview_ready"
            except RemediationError as exc:
                preview = {"server_dry_run": "failed", "detail": str(exc)}
                action_status = "preview_failed"
            except Exception as exc:
                preview = {
                    "server_dry_run": "failed",
                    "detail": f"The server dry-run failed ({type(exc).__name__}).",
                }
                action_status = "preview_failed"
            action_records.append(
                RemediationAction(
                    id=proposal.id,
                    investigation_id=investigation_id,
                    created_at=proposal.created_at,
                    expires_at=proposal.expires_at,
                    created_by=user.username,
                    action_type=proposal.action_type,
                    status=action_status,
                    risk=proposal.risk,
                    target_namespace=proposal.namespace,
                    target_kind=proposal.target_kind,
                    target_name=proposal.target_name,
                    proposal_json=json.dumps(proposal.to_dict(), default=_json_default, sort_keys=True),
                    preview_json=json.dumps(preview, default=_json_default, sort_keys=True),
                )
            )
        check_plan = plan_diagnostic_checks(
            investigation_id=investigation_id,
            alert_name=alert.name,
            labels=evidence.labels,
        )
        check_records = [
            DiagnosticCheck(
                id=spec.id,
                investigation_id=investigation_id,
                position=spec.position,
                tool_name=spec.tool_name,
                title=spec.title,
                purpose=spec.purpose,
                status="queued",
                input_json=json.dumps(spec.to_dict(), sort_keys=True),
            )
            for spec in check_plan
        ]
        investigation_status = (
            "awaiting_approval"
            if any(item.status == "preview_ready" for item in action_records)
            else "recommendation_ready"
        )
        with Session(request.app.state.engine) as db_session:
            db_session.add(
                Investigation(
                    id=investigation_id,
                    created_by=user.username,
                    status=investigation_status,
                    alert_fingerprint=alert.fingerprint,
                    alert_name=alert.name,
                    alert_snapshot_json=alert_json,
                    analysis_json=analysis_json,
                )
            )
            db_session.add_all(action_records)
            db_session.add_all(check_records)
            db_session.add(
                AuditEvent(
                    actor=user.username,
                    action="investigation.create",
                    outcome=investigation_status,
                    details_json=json.dumps(
                        {
                            "investigation_id": investigation_id,
                            "alert_fingerprint": alert.fingerprint,
                            "alert_name": alert.name,
                        },
                        sort_keys=True,
                    ),
                )
            )
            for action in action_records:
                db_session.add(
                    AuditEvent(
                        actor=user.username,
                        action="remediation.preview",
                        outcome=action.status,
                        details_json=json.dumps(
                            {
                                "action_id": action.id,
                                "investigation_id": investigation_id,
                                "action_type": action.action_type,
                                "target": f"{action.target_kind}/{action.target_namespace}/{action.target_name}",
                            },
                            sort_keys=True,
                        ),
                    )
                )
            if check_records:
                db_session.add(
                    AuditEvent(
                        actor="system:planner",
                        action="diagnostic.plan",
                        outcome="queued",
                        details_json=json.dumps(
                            {
                                "investigation_id": investigation_id,
                                "tools": [item.tool_name for item in check_records],
                                "check_count": len(check_records),
                            },
                            sort_keys=True,
                        ),
                    )
                )
            db_session.commit()

        return RedirectResponse(
            url=f"/investigations/{investigation_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/investigations/{investigation_id}", response_class=HTMLResponse)
    async def investigation_detail(
        investigation_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ):
        csrf_token, csrf_is_new = _csrf_token(request)
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            if investigation is None:
                raise HTTPException(status_code=404, detail="Investigation not found.")
            existing_check_rows = list(
                db_session.scalars(
                    select(DiagnosticCheck).where(
                        DiagnosticCheck.investigation_id == investigation_id
                    )
                )
            )
            saved_alert = json.loads(investigation.alert_snapshot_json)
            desired_plan = plan_diagnostic_checks(
                investigation_id=investigation_id,
                alert_name=investigation.alert_name,
                labels=saved_alert.get("labels", {}),
            )
            existing_tools = {check.tool_name for check in existing_check_rows}
            missing_specs = [
                spec for spec in desired_plan if spec.tool_name not in existing_tools
            ]
            if missing_specs:
                next_position = max(
                    (check.position for check in existing_check_rows), default=0
                )
                new_checks = []
                for spec in missing_specs:
                    next_position += 1
                    payload = spec.to_dict()
                    payload["position"] = next_position
                    new_checks.append(
                        DiagnosticCheck(
                            id=spec.id,
                            investigation_id=investigation_id,
                            position=next_position,
                            tool_name=spec.tool_name,
                            title=spec.title,
                            purpose=spec.purpose,
                            status="queued",
                            input_json=json.dumps(payload, sort_keys=True),
                        )
                    )
                db_session.add_all(new_checks)
                if new_checks:
                    db_session.add(
                        AuditEvent(
                            actor="system:planner",
                            action="diagnostic.plan",
                            outcome="queued",
                            details_json=json.dumps(
                                {
                                    "investigation_id": investigation_id,
                                    "tools": [check.tool_name for check in new_checks],
                                    "check_count": len(new_checks),
                                    "reason": "milestone_9_backfill",
                                },
                                sort_keys=True,
                            ),
                        )
                    )
                db_session.commit()
            _reconcile_alert_lifecycle(
                db_session,
                now=now,
                active_fingerprints=None,
            )
            candidates = [
                (action.id, _proposal_from_json(action.proposal_json))
                for action in db_session.scalars(
                    select(RemediationAction).where(
                        RemediationAction.investigation_id == investigation_id,
                        RemediationAction.status == "preview_ready",
                    )
                )
            ]

        for action_id, proposal in candidates:
            validation = await run_in_threadpool(executor.validate, proposal)
            if validation.status not in {"stale", "missing"}:
                continue
            with Session(request.app.state.engine) as db_session:
                investigation = db_session.get(Investigation, investigation_id)
                action = db_session.get(RemediationAction, action_id)
                if investigation is None or action is None:
                    continue
                changed = _close_preview(
                    db_session,
                    action=action,
                    investigation=investigation,
                    status_value="cancelled",
                    actor="system:reconciler",
                    audit_action="remediation.reconcile",
                    reason=f"target_{validation.status}",
                    summary="The preview was cancelled because its exact target is no longer current.",
                    detail=validation.detail,
                    now=now,
                )
                if changed:
                    db_session.commit()

        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            if investigation is None:
                raise HTTPException(status_code=404, detail="Investigation not found.")
            view = {
                "id": investigation.id,
                "created_at": investigation.created_at,
                "created_by": investigation.created_by,
                "status": investigation.status,
                "alert_name": investigation.alert_name,
                "alert": json.loads(investigation.alert_snapshot_json),
                "analysis": json.loads(investigation.analysis_json),
            }
            actions = []
            for action in db_session.scalars(
                select(RemediationAction)
                .where(RemediationAction.investigation_id == investigation_id)
                .order_by(RemediationAction.created_at.asc())
            ):
                proposal = json.loads(action.proposal_json)
                actions.append(
                    {
                        "id": action.id,
                        "action_type": action.action_type,
                        "status": action.status,
                        "risk": action.risk,
                        "target_namespace": action.target_namespace,
                        "target_kind": action.target_kind,
                        "target_name": action.target_name,
                        "expires_at": action.expires_at,
                        "expired": now > _aware(action.expires_at),
                        "proposal": proposal,
                        "preview": json.loads(action.preview_json),
                        "approved_by": action.approved_by,
                        "approved_at": action.approved_at,
                        "result": json.loads(action.result_json) if action.result_json else None,
                    }
                )
            checks = [
                {
                    "id": check.id,
                    "position": check.position,
                    "title": check.title,
                    "purpose": check.purpose,
                    "tool_name": check.tool_name,
                    "status": check.status,
                    "requested_by": check.requested_by,
                    "started_at": check.started_at,
                    "completed_at": check.completed_at,
                    "result": json.loads(check.result_json) if check.result_json else None,
                }
                for check in db_session.scalars(
                    select(DiagnosticCheck)
                    .where(DiagnosticCheck.investigation_id == investigation_id)
                    .order_by(DiagnosticCheck.position.asc())
                )
            ]
            message_rows = list(
                db_session.scalars(
                    select(ChatMessage)
                    .where(ChatMessage.investigation_id == investigation_id)
                    .order_by(ChatMessage.created_at.desc())
                    .limit(app_settings.chat_max_messages)
                )
            )
            messages = [
                {
                    "id": message.id,
                    "role": message.role,
                    "actor": message.actor,
                    "content": message.content,
                    "answer_mode": message.answer_mode,
                    "citations": json.loads(message.citations_json),
                    "tool_intent": (
                        json.loads(message.tool_intent_json)
                        if message.tool_intent_json
                        else None
                    ),
                    "provider_status": message.provider_status,
                    "created_at": message.created_at,
                }
                for message in reversed(message_rows)
            ]
        response = templates.TemplateResponse(
            request=request,
            name="investigation.html",
            context={
                "user": user,
                "investigation": view,
                "actions": actions,
                "checks": checks,
                "messages": messages,
                "chat_max_chars": app_settings.chat_max_chars,
                "chat_budget_exhausted": len(messages) + 2 > app_settings.chat_max_messages,
                "csrf_token": csrf_token,
            },
        )
        if csrf_is_new:
            response.set_cookie(
                CSRF_COOKIE,
                csrf_token,
                secure=app_settings.auth_mode == "proxy",
                httponly=True,
                samesite="strict",
                max_age=28_800,
            )
        return response

    @app.post("/api/v1/investigations/{investigation_id}/chat")
    async def investigation_chat(
        investigation_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(
                status_code=403,
                detail="Investigation chat requires the Investigator role or higher.",
            )
        form = await _urlencoded(request)
        raw_message = form.get("message", "").strip()
        if not raw_message or len(raw_message) > app_settings.chat_max_chars:
            raise HTTPException(
                status_code=422,
                detail=f"Enter a message between 1 and {app_settings.chat_max_chars} characters.",
            )
        message_text = redact_text(raw_message)[: app_settings.chat_max_chars]
        user_message_id = str(uuid4())
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            if investigation is None:
                raise HTTPException(status_code=404, detail="Investigation not found.")
            message_count = db_session.scalar(
                select(func.count())
                .select_from(ChatMessage)
                .where(ChatMessage.investigation_id == investigation_id)
            ) or 0
            if message_count + 2 > app_settings.chat_max_messages:
                raise HTTPException(
                    status_code=409,
                    detail="This investigation reached its bounded chat-message budget.",
                )
            db_session.add(
                ChatMessage(
                    id=user_message_id,
                    investigation_id=investigation_id,
                    role="user",
                    actor=user.username,
                    content=message_text,
                    citations_json="[]",
                )
            )
            db_session.add(
                AuditEvent(
                    actor=user.username,
                    action="chat.message",
                    outcome="accepted",
                    details_json=json.dumps(
                        {
                            "investigation_id": investigation_id,
                            "message_id": user_message_id,
                            "character_count": len(message_text),
                        },
                        sort_keys=True,
                    ),
                )
            )
            db_session.commit()

        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            assert investigation is not None
            alert_snapshot = json.loads(investigation.alert_snapshot_json)
            analysis_payload = json.loads(investigation.analysis_json)
            known_evidence_ids = {
                str(item.get("id", ""))[:128]
                for item in analysis_payload.get("observations", [])
                if item.get("id")
            }
            queued_checks = db_session.scalar(
                select(func.count())
                .select_from(DiagnosticCheck)
                .where(
                    DiagnosticCheck.investigation_id == investigation_id,
                    DiagnosticCheck.status == "queued",
                )
            ) or 0
            history_rows = list(
                db_session.scalars(
                    select(ChatMessage)
                    .where(ChatMessage.investigation_id == investigation_id)
                    .order_by(ChatMessage.created_at.desc())
                    .limit(app_settings.chat_max_messages)
                )
            )
            conversation = [
                {"role": item.role, "content": item.content}
                for item in reversed(history_rows)
            ]
            profile = db_session.get(ModelProfile, 1)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
            alert_name = investigation.alert_name

        provider_status = "not_configured"
        validated = {
            "answer_mode": "insufficient_evidence",
            "content": "No ready model profile is configured. The persisted investigation evidence and safe diagnostic plan remain available.",
            "citations": [],
            "tool_intent": None,
        }
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                answer = await run_in_threadpool(
                    provider.chat,
                    profile_snapshot,
                    api_key,
                    {
                        "investigation": {
                            "id": investigation_id,
                            "alert_name": alert_name,
                        },
                        "alert": alert_snapshot,
                        "analysis": {
                            key: value for key, value in analysis_payload.items() if key != "model"
                        },
                        "conversation": conversation,
                        "policy": {
                            "available_tool_intents": (
                                ["run_queued_checks"] if queued_checks else []
                            ),
                            "tool_execution_requires_operator_click": True,
                            "chat_cannot_mutate_cluster": True,
                        },
                    },
                )
                validated = _validated_chat_answer(
                    answer,
                    known_evidence_ids=known_evidence_ids,
                    queued_checks=queued_checks,
                )
                provider_status = "ready"
            except (CredentialStoreError, ModelProviderError) as exc:
                provider_status = "unavailable"
                validated = {
                    "answer_mode": "insufficient_evidence",
                    "content": f"The model is temporarily unavailable. {str(exc)}",
                    "citations": [],
                    "tool_intent": None,
                }

        assistant_message_id = str(uuid4())
        with Session(request.app.state.engine) as db_session:
            db_session.add(
                ChatMessage(
                    id=assistant_message_id,
                    investigation_id=investigation_id,
                    role="assistant",
                    actor="podpilot",
                    content=str(validated["content"]),
                    answer_mode=str(validated["answer_mode"]),
                    citations_json=json.dumps(validated["citations"], sort_keys=True),
                    tool_intent_json=(
                        json.dumps(validated["tool_intent"], sort_keys=True)
                        if validated["tool_intent"]
                        else None
                    ),
                    provider_status=provider_status,
                )
            )
            db_session.add(
                AuditEvent(
                    actor="podpilot",
                    action="chat.answer",
                    outcome=provider_status,
                    details_json=json.dumps(
                        {
                            "investigation_id": investigation_id,
                            "message_id": assistant_message_id,
                            "answer_mode": validated["answer_mode"],
                            "citations": validated["citations"],
                            "proposed_tool_intent": (
                                validated["tool_intent"].get("name")
                                if isinstance(validated["tool_intent"], dict)
                                else None
                            ),
                        },
                        sort_keys=True,
                    ),
                )
            )
            db_session.commit()
        return RedirectResponse(
            url=f"/investigations/{investigation_id}#investigation-chat",
            status_code=303,
        )

    @app.post("/api/v1/investigations/{investigation_id}/checks/run")
    async def run_investigation_checks(
        investigation_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(
                status_code=403,
                detail="Running diagnostic checks requires the Investigator role or higher.",
            )
        now = datetime.now(timezone.utc)
        claimed: list[tuple[str, DiagnosticCheckSpec]] = []
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            if investigation is None:
                raise HTTPException(status_code=404, detail="Investigation not found.")
            queued = list(
                db_session.scalars(
                    select(DiagnosticCheck)
                    .where(
                        DiagnosticCheck.investigation_id == investigation_id,
                        DiagnosticCheck.status == "queued",
                    )
                    .order_by(DiagnosticCheck.position.asc())
                    .limit(app_settings.diagnostic_max_checks)
                )
            )
            for check in queued:
                result = db_session.execute(
                    update(DiagnosticCheck)
                    .where(
                        DiagnosticCheck.id == check.id,
                        DiagnosticCheck.status == "queued",
                    )
                    .values(status="running", started_at=now, requested_by=user.username)
                )
                if result.rowcount == 1:
                    claimed.append((check.id, _check_spec_from_row(check)))
            if not claimed:
                raise HTTPException(status_code=409, detail="No queued diagnostic checks remain.")
            db_session.commit()

        for check_id, spec in claimed:
            try:
                result = await run_in_threadpool(check_executor.run, spec)
                result_payload = result.to_dict()
                check_status = result.status
            except Exception as exc:
                result_payload = {
                    "status": "failed",
                    "summary": f"The registered diagnostic check failed ({type(exc).__name__}).",
                    "observations": [],
                    "limitations": ["No mutation was attempted. Retry after checking cluster API health."],
                }
                check_status = "failed"
            completed_at = datetime.now(timezone.utc)
            with Session(request.app.state.engine) as db_session:
                check = db_session.get(DiagnosticCheck, check_id)
                if check is None or check.status != "running":
                    continue
                check.status = check_status
                check.completed_at = completed_at
                check.result_json = json.dumps(
                    result_payload, default=_json_default, sort_keys=True
                )
                db_session.add(
                    AuditEvent(
                        actor=user.username,
                        action="diagnostic.execute",
                        outcome=check_status,
                        details_json=json.dumps(
                            {
                                "investigation_id": investigation_id,
                                "check_id": check.id,
                                "tool_name": check.tool_name,
                                "observation_count": len(result_payload.get("observations", [])),
                            },
                            sort_keys=True,
                        ),
                    )
                )
                db_session.commit()

        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            assert investigation is not None
            analysis_payload = json.loads(investigation.analysis_json)
            alert_snapshot = json.loads(investigation.alert_snapshot_json)
            diagnostic_results = [
                {
                    "tool_name": check.tool_name,
                    "title": check.title,
                    "status": check.status,
                    "result": json.loads(check.result_json) if check.result_json else None,
                }
                for check in db_session.scalars(
                    select(DiagnosticCheck)
                    .where(DiagnosticCheck.investigation_id == investigation_id)
                    .order_by(DiagnosticCheck.position.asc())
                )
            ]
            known_ids = {item["id"] for item in analysis_payload.get("observations", [])}
            limitations = list(analysis_payload.get("limitations", []))
            for item in diagnostic_results:
                result = item.get("result") or {}
                for observation in result.get("observations", []):
                    if observation.get("id") not in known_ids:
                        analysis_payload.setdefault("observations", []).append(observation)
                        known_ids.add(observation.get("id"))
                for limitation in result.get("limitations", []):
                    if limitation not in limitations:
                        limitations.append(limitation)
            analysis_payload["limitations"] = limitations
            analysis_payload["diagnostic_results"] = diagnostic_results
            profile = db_session.get(ModelProfile, 1)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None

        model_result: dict[str, object] = analysis_payload.get("model", {"status": "not_configured"})
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                interpretation = await run_in_threadpool(
                    provider.interpret,
                    profile_snapshot,
                    api_key,
                    {
                        "alert": alert_snapshot,
                        "deterministic_analysis": {
                            key: value for key, value in analysis_payload.items() if key != "model"
                        },
                        "diagnostic_results": diagnostic_results,
                    },
                )
                model_result = {
                    "status": "ready",
                    "updated_after_checks": True,
                    **interpretation.model_dump(),
                }
            except (CredentialStoreError, ModelProviderError) as exc:
                model_result = {"status": "unavailable", "detail": str(exc)}
        analysis_payload["model"] = model_result
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            if investigation is None:
                raise HTTPException(status_code=404, detail="Investigation not found.")
            investigation.analysis_json = json.dumps(
                analysis_payload, default=_json_default, sort_keys=True
            )
            db_session.add(
                AuditEvent(
                    actor=user.username,
                    action="investigation.reanalyze",
                    outcome=str(model_result.get("status", "not_configured")),
                    details_json=json.dumps(
                        {
                            "investigation_id": investigation_id,
                            "executed_checks": len(claimed),
                            "model_updated": model_result.get("status") == "ready",
                        },
                        sort_keys=True,
                    ),
                )
            )
            db_session.commit()
        return RedirectResponse(
            url=f"/investigations/{investigation_id}#investigation-plan",
            status_code=303,
        )

    @app.post("/api/v1/investigations/{investigation_id}/actions/{action_id}/approve")
    async def approve_action(
        investigation_id: str,
        action_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(
                status_code=403,
                detail="Executing a remediation requires the Approver role or higher.",
            )
        now = datetime.now(timezone.utc)
        try:
            approval_snapshot = await run_in_threadpool(alerts.fetch)
        except AlertSourceError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"PodPilot could not verify that the source alert is still active. {exc}",
            ) from exc
        active_fingerprints = {
            item.fingerprint for item in approval_snapshot.alerts if item.state == "active"
        }
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            action = db_session.get(RemediationAction, action_id)
            if investigation is None or action is None or action.investigation_id != investigation_id:
                raise HTTPException(status_code=404, detail="Remediation action not found.")
            if action.status != "preview_ready":
                raise HTTPException(status_code=409, detail="This remediation is no longer awaiting approval.")
            if (
                not approval_snapshot.is_complete
                and investigation.alert_fingerprint not in active_fingerprints
            ):
                raise HTTPException(
                    status_code=503,
                    detail="PodPilot could not prove that the source alert is still active because the Alertmanager snapshot was truncated.",
                )
            if investigation.alert_fingerprint not in active_fingerprints:
                _reconcile_alert_lifecycle(
                    db_session,
                    now=now,
                    active_fingerprints=active_fingerprints,
                )
                raise HTTPException(
                    status_code=409,
                    detail="The source alert is no longer active. This preview was cancelled.",
                )
            expires_at = _aware(action.expires_at)
            if now > expires_at:
                _close_preview(
                    db_session,
                    action=action,
                    investigation=investigation,
                    status_value="expired",
                    actor=user.username,
                    audit_action="remediation.expire",
                    reason="preview_expired",
                    summary="The approval window expired without execution.",
                    detail="Generate a fresh investigation before approving a remediation.",
                    now=now,
                )
                db_session.commit()
                raise HTTPException(status_code=409, detail="The preview expired. Generate a fresh investigation before approval.")
            proposal = _proposal_from_json(action.proposal_json)
            claimed = db_session.execute(
                update(RemediationAction)
                .where(
                    RemediationAction.id == action_id,
                    RemediationAction.status == "preview_ready",
                )
                .values(status="executing", approved_by=user.username, approved_at=now)
            )
            if claimed.rowcount != 1:
                db_session.rollback()
                raise HTTPException(status_code=409, detail="This remediation was already approved or changed.")
            investigation.status = "executing"
            db_session.add(AuditEvent(
                actor=user.username,
                action="remediation.approve",
                outcome="executing",
                details_json=json.dumps(
                    {
                        "action_id": action_id,
                        "investigation_id": investigation_id,
                        "action_type": action.action_type,
                        "target": f"{action.target_kind}/{action.target_namespace}/{action.target_name}",
                    },
                    sort_keys=True,
                ),
            ))
            db_session.commit()

        result = await run_in_threadpool(executor.execute, proposal)
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            action = db_session.get(RemediationAction, action_id)
            if investigation is None or action is None:
                raise HTTPException(status_code=500, detail="The remediation record could not be finalized.")
            action.status = result.outcome
            action.result_json = json.dumps(result.to_dict(), default=_json_default, sort_keys=True)
            investigation.status = result.outcome if result.outcome != "stale" else "unresolved"
            siblings = list(
                db_session.scalars(
                    select(RemediationAction).where(
                        RemediationAction.investigation_id == investigation_id,
                        RemediationAction.id != action_id,
                        RemediationAction.status == "preview_ready",
                    )
                )
            )
            for sibling in siblings:
                _close_preview(
                    db_session,
                    action=sibling,
                    investigation=investigation,
                    status_value="cancelled",
                    actor=user.username,
                    audit_action="remediation.cancel_siblings",
                    reason="sibling_action_executed",
                    summary="The preview was cancelled after another action executed.",
                    detail="A fresh investigation is required before another mutation.",
                    now=datetime.now(timezone.utc),
                )
            db_session.add(AuditEvent(
                actor=user.username,
                action="remediation.execute",
                outcome=result.outcome,
                details_json=json.dumps(
                    {
                        "action_id": action_id,
                        "investigation_id": investigation_id,
                        "summary": result.summary,
                        "verification": result.verification,
                    },
                    sort_keys=True,
                ),
            ))
            db_session.commit()
        return RedirectResponse(
            url=f"/investigations/{investigation_id}#action-{action_id}",
            status_code=303,
        )

    @app.post("/api/v1/investigations/{investigation_id}/actions/{action_id}/cancel")
    async def cancel_action(
        investigation_id: str,
        action_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            investigation = db_session.get(Investigation, investigation_id)
            action = db_session.get(RemediationAction, action_id)
            if investigation is None or action is None or action.investigation_id != investigation_id:
                raise HTTPException(status_code=404, detail="Remediation action not found.")
            if user.role < Role.APPROVER and investigation.created_by != user.username:
                raise HTTPException(
                    status_code=403,
                    detail="Only the investigation creator or an Approver can cancel this preview.",
                )
            if action.status != "preview_ready":
                raise HTTPException(status_code=409, detail="This preview is no longer active.")
            status_value = "expired" if now > _aware(action.expires_at) else "cancelled"
            changed = _close_preview(
                db_session,
                action=action,
                investigation=investigation,
                status_value=status_value,
                actor=user.username,
                audit_action=("remediation.expire" if status_value == "expired" else "remediation.cancel"),
                reason=("preview_expired" if status_value == "expired" else "user_cancelled"),
                summary=(
                    "The approval window expired without execution."
                    if status_value == "expired"
                    else "The remediation preview was cancelled without executing it."
                ),
                detail=(
                    "Generate a fresh investigation before approving a remediation."
                    if status_value == "expired"
                    else "No Kubernetes mutation was attempted."
                ),
                now=now,
            )
            if not changed:
                db_session.rollback()
                raise HTTPException(status_code=409, detail="This preview was already changed.")
            db_session.commit()
        return RedirectResponse(
            url=f"/investigations/{investigation_id}#action-{action_id}",
            status_code=303,
        )

    @app.get("/api/v1/session")
    async def session(user: AuthContext = Depends(current_user)) -> dict[str, str]:
        return {"username": user.username, "role": user.role.name.lower()}

    return app


app = create_app()
