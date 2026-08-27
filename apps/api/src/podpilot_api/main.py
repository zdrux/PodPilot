from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit, urlunsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session, aliased
from starlette.concurrency import run_in_threadpool

from podpilot_api.auth import AuthContext, Role, RoleResolver, auth_dependency
from podpilot_api.database import build_engine, database_is_ready
from podpilot_api.knowledge import (
    ensure_knowledge_fts,
    index_document,
    knowledge_applies_to,
    search_knowledge,
)
from podpilot_api.markdown import render_safe_markdown
from podpilot_api.model_provider import (
    AdHocAnswer,
    AdHocLogAnalysis,
    InquirySemantics,
    InvestigationChatAnswer,
    ModelProfileConfig,
    ModelProvider,
    ModelProviderError,
    OpenAIProviderRouter,
    capture_raw_model_responses,
    validate_model_endpoint,
)
from podpilot_api.models import (
    AdHocConversation,
    AdHocMessage,
    AdHocRun,
    AuditEvent,
    ChatMessage,
    Cluster,
    DiagnosticCheck,
    Investigation,
    KnowledgeDocument,
    ModelProfile,
    RemediationAction,
)
from podpilot_api.settings import Settings, get_settings
from podpilot_diagnostics.alerts import AlertEvidence, analyze_alert
from podpilot_diagnostics.adhoc import (
    InvestigationGap,
    PodLogCandidate,
    ReadIntent,
    ReadOnlyExplorer,
    ReadPlan,
    automatic_read_followups,
    derive_adhoc_findings,
    derive_evidence_relationship_graph,
    normalize_read_intent,
    plan_catalog_read,
    plan_known_read,
    plan_needs_evidence_repair,
    pod_log_candidates_from_evidence,
)
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
from podpilot_openshift.http_probe import BoundedHttpProbe
from podpilot_openshift.metric_trends import BoundedMetricTrendReader
from podpilot_openshift.metrics import ThanosQueryClient
from podpilot_openshift.checks import KubernetesDiagnosticCheckExecutor
from podpilot_openshift.roles import LazyOpenShiftGroupRoleResolver
from podpilot_openshift.remediation import KubernetesRemediationExecutor, RemediationError
from podpilot_openshift.workloads import (
    KubernetesWorkloadClient,
    WorkloadEvidenceError,
    WorkloadEvidenceSource,
)

CSRF_COOKIE = "podpilot_csrf"
LOGGER = logging.getLogger("uvicorn.error")
SYSTEM_CLUSTER_ID = "00000000-0000-0000-0000-000000000001"
_TAG_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_TAG_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,126}$")


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _bounded_raw_response_attempts(
    destination: list[dict[str, str]], captured: list[str], *, stage: str
) -> None:
    """Persist only bounded, redacted final-answer output requested by the operator."""

    for content in captured:
        if len(destination) >= 4:
            return
        destination.append({
            "stage": stage,
            "content": redact_text(str(content))[:16_000],
        })


def _format_est_time(value: object, pattern: str = "%H:%M") -> str:
    """Render persisted UTC timestamps in the operator-requested fixed UTC-4 display."""

    parsed: datetime
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    eastern = parsed.astimezone(timezone(timedelta(hours=-4)))
    return f"{eastern.strftime(pattern)} EST (-4)"


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


def _make_cluster_credential_store(settings: Settings) -> CredentialStore:
    if settings.cluster_credential_store == "kubernetes":
        return KubernetesSecretCredentialStore(
            settings.cluster_secret_namespace,
            settings.cluster_secret_name,
            "unused",
        )
    return EnvironmentCredentialStore("PODPILOT_CLUSTER_TOKEN")


def _validated_cluster_api_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
    ):
        raise HTTPException(
            status_code=422,
            detail="Cluster API URL must be an HTTPS origin without credentials, path, query, or fragment.",
        )
    return urlunsplit(("https", parsed.netloc, "", "", "")).rstrip("/")


def _parse_tags(value: str, *, field_name: str = "Tags") -> dict[str, str]:
    try:
        payload = json.loads(value or "{}")
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON object.") from exc
    if not isinstance(payload, dict) or len(payload) > 30:
        raise HTTPException(status_code=422, detail=f"{field_name} must contain at most 30 key/value pairs.")
    tags: dict[str, str] = {}
    for raw_key, raw_value in payload.items():
        if not isinstance(raw_value, str):
            raise HTTPException(status_code=422, detail=f"{field_name} values must be strings.")
        key, tag_value = str(raw_key).strip(), str(raw_value).strip()
        if not _TAG_KEY.fullmatch(key) or (tag_value and not _TAG_VALUE.fullmatch(tag_value)):
            raise HTTPException(status_code=422, detail=f"{field_name} contains an invalid key or value.")
        tags[key] = tag_value
    return dict(sorted(tags.items()))


def _cluster_summary(cluster: Cluster) -> dict[str, object]:
    return {
        "id": cluster.id,
        "name": cluster.name,
        "api_url": cluster.api_url,
        "tags": json.loads(cluster.tags_json or "{}"),
        "tls_verify": cluster.tls_verify,
        "is_enabled": cluster.is_enabled,
        "is_system": cluster.is_system,
        "status": cluster.status,
        "last_error": cluster.last_error,
        "last_tested_at": cluster.last_tested_at,
        "has_token": bool(cluster.credential_key),
    }


def _profile_config(profile: ModelProfile) -> ModelProfileConfig:
    return ModelProfileConfig(
        provider_label=profile.provider_label,
        base_url=profile.base_url,
        chat_model=profile.chat_model,
        embedding_model=profile.embedding_model,
        timeout_seconds=profile.timeout_seconds,
        max_output_tokens=profile.max_output_tokens,
        api_type=profile.api_type,
        tls_mode=profile.tls_mode,
        custom_ca_pem=profile.custom_ca_pem,
        max_input_tokens=profile.max_input_tokens,
    )


def _active_profile(db_session: Session) -> ModelProfile | None:
    return db_session.scalar(
        select(ModelProfile).where(ModelProfile.is_active.is_(True)).order_by(ModelProfile.id).limit(1)
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
    answer: AdHocAnswer,
    *,
    known_evidence_ids: set[str],
    collection_limitations: list[str] | None = None,
    observations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    citations: list[str] = []
    for evidence_id in answer.cited_evidence_ids:
        bounded = str(evidence_id)[:128]
        if bounded in known_evidence_ids and bounded not in citations:
            citations.append(bounded)
    # Some strict-JSON chat-completions models put an otherwise valid citation in
    # the prose while leaving the optional array empty. Normalize only exact IDs
    # from the allowlisted observations supplied to this answer request. Unknown,
    # partial, or invented IDs still cannot ground a response.
    for evidence_id in sorted(known_evidence_ids, key=len, reverse=True):
        if evidence_id in answer.answer and evidence_id not in citations:
            citations.append(evidence_id)
    original_mode = answer.answer_mode
    mode = original_mode
    content = _clean_adhoc_markdown(
        redact_text(answer.answer),
        known_evidence_ids=known_evidence_ids,
    )[:4000]
    rbac_limitation = next((
        item for item in (collection_limitations or [])
        if item.startswith("OpenShift RBAC denied ")
    ), None)
    if mode == "evidence_based" and not citations:
        mode = "insufficient_evidence"
        content = (
            "PodPilot could not provide a verified cluster-specific answer because the model did "
            "not cite collected evidence."
        )
    if original_mode == "insufficient_evidence" and citations:
        # Grounding and certainty are separate axes. A cited interpretation is
        # evidence-based even when its overall conclusion remains unresolved.
        mode = "evidence_based"
    mode, content, citations, claim_limitations = _guard_unsupported_tls_claim(
        mode=mode,
        content=content,
        citations=citations,
        observations=observations or [],
    )
    if rbac_limitation and rbac_limitation not in content:
        content = f"**Access blocked by OpenShift RBAC.** {rbac_limitation}\n\n{content}"
    investigation_gaps: list[InvestigationGap] = []
    for gap in answer.investigation_gaps[:5]:
        supporting_ids = [
            str(item)[:128] for item in gap.supporting_evidence_ids
            if str(item)[:128] in known_evidence_ids
        ]
        investigation_gaps.append(gap.model_copy(update={
            "question": redact_text(gap.question)[:500],
            "reason": redact_text(gap.reason)[:500] if gap.reason else None,
            "supporting_evidence_ids": list(dict.fromkeys(supporting_ids)),
        }))
    return {
        "answer_mode": mode,
        "conclusion_status": (
            answer.conclusion_status
            or ("unresolved" if original_mode == "insufficient_evidence" else "confirmed")
        ),
        "content": content,
        "citations": citations,
        "limitations": [
            redact_text(item)[:500]
            for item in [*claim_limitations, *answer.limitations][:6]
        ],
        "recommended_next_checks": [
            redact_text(item)[:500] for item in answer.recommended_next_checks[:5]
        ],
        "investigation_gaps": investigation_gaps,
    }


def _merge_validated_recommendations(
    earlier: dict[str, object],
    latest: dict[str, object],
) -> dict[str, object]:
    """Preserve structured checks when a later answer only rewrites prose."""

    merged: list[str] = []
    for source in (latest, earlier):
        for item in source.get("recommended_next_checks") or []:
            recommendation = redact_text(str(item))[:500]
            if recommendation.strip() and recommendation not in merged:
                merged.append(recommendation)
            if len(merged) >= 5:
                break
        if len(merged) >= 5:
            break
    latest["recommended_next_checks"] = merged
    return latest


_NO_TLS_CLAIM = re.compile(
    r"\b(?:not\s+(?:terminating|serving|speaking|using)\s+(?:https|tls)|"
    r"(?:serving|using|speaking)\s+(?:only\s+)?(?:plain[- ]?)?http(?:\s+only)?|"
    r"only\s+(?:plain[- ]?)?http\s+traffic)\b",
    re.IGNORECASE,
)


def _guard_unsupported_tls_claim(
    *,
    mode: str,
    content: str,
    citations: list[str],
    observations: list[dict[str, object]],
) -> tuple[str, str, list[str], list[str]]:
    """Replace a no-TLS claim contradicted by certificate-validation evidence."""

    if not _NO_TLS_CLAIM.search(content):
        return mode, content, citations, []
    certificate_failure: dict[str, object] | None = None
    insecure_probes: list[dict[str, object]] = []
    sidecar_logs: list[dict[str, object]] = []
    route_observation: dict[str, object] | None = None
    route_termination = ""
    for observation in observations:
        data = observation.get("data")
        if not isinstance(data, dict):
            continue
        if (
            observation.get("tool") == "http_probe"
            and data.get("stage") == "tls"
            and any(marker in str(data.get("error") or "").lower() for marker in (
                "certificate verify failed", "self-signed certificate", "unknown ca",
            ))
        ):
            certificate_failure = observation
        if observation.get("tool") == "http_probe" and (
            data.get("tlsVerificationRequested") is False
            or (
                isinstance(data.get("tls"), dict)
                and data["tls"].get("verified") is False
            )
        ):
            insecure_probes.append(observation)
        if (
            observation.get("tool") == "pod_logs"
            and str(data.get("container") or "").lower() in {"istio-proxy", "envoy"}
        ):
            sidecar_logs.append(observation)
        if data.get("kind") == "Route" and isinstance(data.get("items"), list):
            for item in data["items"]:
                if not isinstance(item, dict):
                    continue
                spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
                tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
                termination = str(tls.get("termination") or "").lower()
                if termination:
                    route_observation = observation
                    route_termination = termination
                    break
    if certificate_failure is None:
        return mode, content, citations, []

    probe_data = certificate_failure["data"]
    logical_host = str(probe_data.get("logicalHost") or "the selected endpoint")
    connect_host = str(probe_data.get("connectHost") or logical_host)
    port = probe_data.get("port")
    target = f"`{logical_host}` via `{connect_host}:{port}`" if port else f"`{logical_host}`"
    evidence_ids = [str(certificate_failure.get("id"))]
    observed_lines = [
        f"- The HTTPS probe to {target} reached TLS certificate validation and failed because "
        "the certificate chain was not trusted. The connected endpoint therefore presented TLS; "
        "this result does **not** show a plain-HTTP listener."
    ]
    insecure_probe = next((
        item for item in reversed(insecure_probes)
        if isinstance(item.get("data"), dict)
        and (
            not probe_data.get("logicalHost")
            or item["data"].get("logicalHost") == probe_data.get("logicalHost")
        )
    ), None)
    if insecure_probe is not None:
        insecure_data = insecure_probe["data"]
        evidence_ids.append(str(insecure_probe.get("id")))
        status = insecure_data.get("statusCode") or insecure_data.get("statusLine")
        outcome = (
            f"returned HTTP `{status}`" if status is not None
            else f"reported outcome `{insecure_data.get('outcome') or 'unknown'}`"
        )
        observed_lines.append(
            f"- The automatic follow-up probe with certificate verification disabled {outcome}. "
            "This separates endpoint behavior from certificate trust, but it does not authenticate "
            "the server identity."
        )
    if route_observation is not None:
        evidence_ids.append(str(route_observation.get("id")))
        observed_lines.append(
            f"- The matched OpenShift Route is configured with TLS termination "
            f"`{route_termination}`."
        )
    if sidecar_logs:
        evidence_ids.extend(str(item.get("id")) for item in sidecar_logs)
        containers = sorted({
            str(item["data"].get("container"))
            for item in sidecar_logs
            if isinstance(item.get("data"), dict)
        })
        observed_lines.append(
            f"- The bounded Pod logs came from sidecar container(s) "
            f"{', '.join(f'`{item}`' for item in containers)}. Sidecar logs do not establish "
            "the application container's listener protocol."
        )
    corrected = (
        "## Observed evidence\n\n"
        + "\n".join(observed_lines)
        + "\n\n## Conclusion\n\n"
        "The claim that the gateway application is serving only plain HTTP is not supported by "
        "the collected evidence. Its listener protocol remains unverified. PodPilot needs a direct, "
        "bounded probe of the selected workload endpoint or application-container configuration/logs "
        "before attributing the Route failure to an HTTP-versus-HTTPS mismatch."
    )
    merged_citations = list(dict.fromkeys([*evidence_ids, *citations]))
    return "evidence_based", corrected[:4000], merged_citations, [
        "PodPilot rejected a model conclusion that contradicted the TLS certificate-validation evidence."
    ]


_INTERNAL_EVIDENCE_PATH = re.compile(
    r"\s*\[?`?observations(?:\.[0-9]+|\[[0-9]+\])"
    r"(?:\.[A-Za-z0-9_-]+|\[[0-9]+\])*`?\]?",
    re.IGNORECASE,
)


_ADHOC_SECTION_LABEL = re.compile(
    r"(^|[.!?])\s*(?:\*\*)?"
    r"(summary|findings?|evidence|root cause|impact|remediation|recommended action|"
    r"next steps?|limitations?)"
    r"(?:\*\*)?\s*:\s*",
    re.IGNORECASE,
)
_ADHOC_INLINE_BOLD_SECTION = re.compile(
    r"(?:^|\s+)\*\*(observation|interpretation|summary|evidence|findings?|"
    r"remaining uncertainties|recommended next steps?|next steps?|limitations?)\*\*\s*:?\s*",
    re.IGNORECASE,
)
_ADHOC_SECTION_TITLES = {
    "observation": "Observed evidence",
    "interpretation": "Interpretation",
    "summary": "Summary",
    "finding": "Finding",
    "findings": "Findings",
    "evidence": "Evidence",
    "root cause": "Root cause",
    "impact": "Impact",
    "remediation": "Remediation",
    "recommended action": "Recommended action",
    "next step": "Next step",
    "next steps": "Next steps",
    "limitation": "Limitation",
    "limitations": "Limitations",
    "remaining uncertainties": "Remaining uncertainties",
    "recommended next step": "Recommended next steps",
    "recommended next steps": "Recommended next steps",
}
_ADHOC_INLINE_MARKDOWN_HEADING = re.compile(
    r"[ \t]+(?=#{2,4}[ \t]+(?:observed|runtime|interpretation|recommended|"
    r"next|uncertainty|limitations?|summary|findings?|evidence|root cause|impact|"
    r"remediation|conclusion|bottom line|what)\b)",
    re.IGNORECASE,
)


def _normalize_adhoc_heading_boundaries(value: str) -> str:
    """Put known operator-facing headings on their own lines outside code fences."""

    normalized: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in value.splitlines():
        stripped = line.lstrip()
        marker = stripped[:3]
        if marker in {"```", "~~~"}:
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            normalized.append(line)
            continue
        if not in_fence:
            line = _ADHOC_INLINE_MARKDOWN_HEADING.sub("\n\n", line)
            line = re.sub(
                r"(?m)^(#{1,4}[^\n]*?)\s+---+\s+",
                r"\1\n\n",
                line,
            )
            line = re.sub(
                r"\s+-\s+(?=(?:\*\*|`|[A-Z]))",
                "\n- ",
                line,
            )
        normalized.append(line)
    return "\n".join(normalized)


def _clean_adhoc_markdown(
    value: str,
    *,
    known_evidence_ids: set[str] | None = None,
) -> str:
    """Preserve readable Markdown while removing provider-facing citation syntax."""

    cleaned = _INTERNAL_EVIDENCE_PATH.sub("", value)
    # Suggested checks are composed independently from exact server candidates.
    # Remove provider attempts to serialize that separate contract into prose.
    cleaned = re.sub(
        r"(?is)\s*(?:---+\s*)?(?:#{1,6}\s+recommended actions?[^\n]*|"
        r"(?:\*\*)?[\"'`]?recommended_actions[\"'`]?(?:\*\*)?\s*:)\s*.*$",
        "",
        cleaned,
    )
    evidence_ids = sorted(known_evidence_ids or set(), key=len, reverse=True)
    if evidence_ids:
        inline_citations = re.compile(
            r"\s*\[(?:" + "|".join(re.escape(item) for item in evidence_ids) + r")\]"
        )
        cleaned = inline_citations.sub("", cleaned)
        parenthetical_citations = re.compile(
            r"\s*\((?:cited[_ ]evidence[_ ]ids?|evidence\s+ids?)\s*:\s*`?(?:"
            + "|".join(re.escape(item) for item in evidence_ids)
            + r")`?\s*\)",
            re.IGNORECASE,
        )
        cleaned = parenthetical_citations.sub("", cleaned)

    # Provider-facing citation fields are never operator prose. Remove the complete
    # bounded marker after exact allowlisted IDs have already been recovered above;
    # this also handles comma-separated IDs that smaller models place in headings.
    cleaned = re.sub(
        r"\s*\((?:cited[_ ]evidence[_ ]ids?|evidence\s+ids?)\s*:\s*[^)\n]{1,1000}\)",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = "\n".join(line.rstrip() for line in cleaned.splitlines())
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()

    # Some constrained providers flatten bold section labels and Unicode bullets
    # onto one line. Restore block structure without changing authored multiline
    # Markdown or the underlying wording.
    if "\n" not in cleaned and ("•" in cleaned or _ADHOC_INLINE_BOLD_SECTION.search(cleaned)):
        cleaned = _ADHOC_INLINE_BOLD_SECTION.sub(
            lambda match: (
                "\n\n### "
                + _ADHOC_SECTION_TITLES[match.group(1).lower()]
                + "\n\n"
            ),
            cleaned,
        ).strip()
        cleaned = re.sub(r"[ \t]*•[ \t]*", "\n- ", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()

    # Unicode-bullet recovery above can introduce the first newlines before we
    # encounter later inline headings. Normalize known section headings after
    # that pass as well, while leaving code fences and arbitrary prose intact.
    cleaned = _normalize_adhoc_heading_boundaries(cleaned)
    cleaned = re.sub(
        r"(?im)^(#{2,4}[ \t]+(?:observed|runtime|interpretation|recommended|next|"
        r"uncertainty|limitations?|summary|findings?|evidence|root cause|impact|"
        r"remediation|conclusion|bottom line|what)[^\n]*)\n(?=[-*+]\s)",
        r"\1\n\n",
        cleaned,
    )

    # Some chat-completions providers flatten an otherwise substantive Markdown
    # answer onto one physical line beginning with a heading. Without restoring
    # block boundaries, the quality check correctly recognizes the leading `###`
    # but then mistakes the entire answer for a heading. Normalize only this
    # compact shape; authored multi-line Markdown is left unchanged.
    if "\n" not in cleaned and re.match(r"^\s*#{1,4}\s+", cleaned):
        cleaned = re.sub(r"\s+---+\s+", "\n\n", cleaned)
        cleaned = re.sub(r"\s+(?=#{1,4}\s+)", "\n\n", cleaned)
        cleaned = re.sub(
            r"\s+-\s+(?=(?:\*\*|`|[A-Z]))",
            "\n- ",
            cleaned,
        )

    # Smaller chat-completions models sometimes return an otherwise useful answer as
    # one paragraph with inline labels. Convert only that unstructured shape; leave
    # authored Markdown headings, lists, tables, and paragraphs untouched.
    has_block_structure = "\n\n" in cleaned or bool(
        re.search(r"(?m)^\s*(?:#{1,4}\s|[-*+]\s|\d+[.)]\s|```|>)", cleaned)
    )
    if not has_block_structure:
        cleaned = _ADHOC_SECTION_LABEL.sub(
            lambda match: (
                match.group(1)
                + "\n\n### "
                + _ADHOC_SECTION_TITLES[match.group(2).lower()]
                + "\n\n"
            ),
            cleaned,
        ).strip()

    return cleaned


_MARKDOWN_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+", re.MULTILINE)
_MARKDOWN_DECORATION = re.compile(r"[`*_~>#|\[\]()-]+")


def _adhoc_answer_quality_issue(
    *, content: str, answer_mode: str | None = None, has_evidence: bool = False,
    has_citations: bool = False,
) -> str | None:
    """Retry only structurally empty answers; trust checks happen during validation."""

    # Citation allowlisting and unsupported-claim guards are enforced by
    # _validated_adhoc_answer. Log findings are appended deterministically, and
    # inventory-only evidence is an advisory rather than grounds to discard prose.
    if re.search(
        r"(?:#{1,6}\s*investigation gaps\s*```(?:json)?|"
        r"[\"']investigation_gaps[\"']\s*:)",
        content,
        re.IGNORECASE,
    ):
        return "structured_fields_embedded_in_answer"
    body_lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
        and not _MARKDOWN_HEADING.match(line)
        and not re.fullmatch(r"[-*_]{3,}", line.strip())
        and not line.strip().startswith("```")
    ]
    body = _MARKDOWN_DECORATION.sub(" ", " ".join(body_lines))
    body = re.sub(r"\s+", " ", body).strip()
    if not body_lines or not body:
        return "heading_only_response"
    # An evidence-backed answer may remain unresolved. Do not discard a useful,
    # cited interpretation merely because the provider honestly reports that the
    # available observations do not prove a root cause. Retry only an uncited
    # insufficient-evidence response when relevant evidence was available.
    if answer_mode == "insufficient_evidence" and has_evidence and not has_citations:
        return "insufficient_interpretation_with_available_evidence"
    return None


def _adhoc_capability_wording_issue(
    *, content: str, capability_ledger: dict[str, object] | None
) -> str | None:
    """Reject 'unavailable' wording when a typed check is merely uncollected."""

    if not capability_ledger:
        return None
    unavailable_patterns = {
        "service_spec": r"\b(?:service(?:\s+(?:spec|definition|object))?).{0,80}\b(?:unavailable|not available)\b",
        "endpoints": r"\bendpoints?(?:lices)?.{0,80}\b(?:unavailable|not available)\b",
        "pod_spec": r"\bpod(?:s|\s+(?:spec|definition|object))?.{0,80}\b(?:unavailable|not available)\b",
        "pod_logs": r"\b(?:pod\s+)?logs?.{0,80}\b(?:unavailable|not available)\b|\bno\s+logs?.{0,80}\bavailable\b",
        "metrics": r"\bmetrics?.{0,80}\b(?:unavailable|not available)\b|\bno\s+metrics?.{0,80}\bavailable\b",
        "http_probe": r"\bprobes?(?:\s+results?)?.{0,80}\b(?:unavailable|not available)\b|\bno\s+probes?.{0,80}\bavailable\b",
    }
    capability_mentions = {
        "service_spec": r"\bservice(?:_spec|\s+(?:spec|definition|object))\b",
        "endpoints": r"\bendpoint(?:s|slices?)?\b",
        "pod_spec": r"\bpod(?:_spec|s|\s+(?:spec|definition|object))\b",
        "pod_logs": r"\b(?:pod_logs|pod\s+logs?|logs?)\b",
        "metrics": r"\bmetrics?\b",
        "http_probe": r"\b(?:http_probe|https?\s+probe|probes?)\b",
    }
    for check in capability_ledger.get("checks") or []:
        if not isinstance(check, dict):
            continue
        capability = str(check.get("capability") or "")
        state = str(check.get("state") or "")
        pattern = unavailable_patterns.get(capability)
        if (
            state in {"available_not_attempted", "requires_target"}
            and pattern
            and re.search(pattern, content, re.IGNORECASE | re.DOTALL)
        ):
            return "available_check_described_as_unavailable"
        mention = capability_mentions.get(capability)
        if state == "collected" and mention:
            stale_gap_section = re.search(
                r"\binvestigation gaps?\b[^\n]{0,500}\b(?:still\s+)?not collected\b",
                content,
                re.IGNORECASE,
            )
            local_stale_claim = re.search(
                rf"{mention}.{{0,160}}\b(?:still\s+)?not collected\b",
                content,
                re.IGNORECASE | re.DOTALL,
            )
            if (
                local_stale_claim
                or (stale_gap_section and re.search(mention, stale_gap_section.group(0), re.IGNORECASE))
            ):
                return "collected_check_described_as_uncollected"
    return None


_RECOMMENDATION_CAPABILITY_PATTERNS = (
    ("resource_read", r"\b(?:mounts?|volumes?|configmaps?|certificate\s+configuration)\b"),
    ("service_spec", r"\bservice\b"),
    ("endpoints", r"\bendpoint(?:s|slice)?\b"),
    ("pod_logs", r"\b(?:pod\s+|application\s+)?logs?\b"),
    ("metrics", r"\bmetrics?\b"),
    ("http_probe", r"\b(?:probe|curl|https?\s+request|tls\s+handshake)\b"),
    ("pod_spec", r"\bpods?\b"),
)


def _recommendation_capability(
    text: str,
    check_states: dict[str, str] | None = None,
    allowed_states: set[str] | None = None,
) -> str | None:
    return next((
        name for name, pattern in _RECOMMENDATION_CAPABILITY_PATTERNS
        if re.search(pattern, text, re.IGNORECASE)
        and (
            check_states is None
            or allowed_states is None
            or check_states.get(name) in allowed_states
            or name not in check_states
        )
    ), None)


def _actionable_investigation_gaps(
    *,
    validated_answer: dict[str, object],
    capability_ledger: dict[str, object],
) -> list[InvestigationGap]:
    """Promote structured gaps, or safe capability-matched recommendation prose, to planner input."""

    available_states = {"available_not_attempted", "requires_target"}
    check_states = {
        str(item.get("capability")): str(item.get("state"))
        for item in capability_ledger.get("checks") or []
        if isinstance(item, dict)
    }
    result: list[InvestigationGap] = []
    seen: set[tuple[str, str]] = set()

    def add(gap: InvestigationGap) -> None:
        if gap.priority == "low":
            return
        if (
            gap.capability in check_states
            and check_states[gap.capability] not in available_states
        ):
            return
        key = (gap.capability, re.sub(r"\s+", " ", gap.question.lower()).strip())
        if key in seen or len(result) >= 5:
            return
        seen.add(key)
        result.append(gap)

    for gap in validated_answer.get("investigation_gaps") or []:
        if isinstance(gap, InvestigationGap):
            add(gap)

    for recommendation in validated_answer.get("recommended_next_checks") or []:
        text = redact_text(str(recommendation))[:500]
        capability = _recommendation_capability(text, check_states, available_states)
        if capability == "resource_read":
            # Broad configuration wording is useful for user-triggered exact actions,
            # but is intentionally too general for automatic recommendation follow-through.
            capability = None
        if capability:
            add(InvestigationGap(
                question=text,
                capability=capability,
                priority="medium",
                reason=(
                    "Promoted from operator-facing recommendation text for typed replanning; "
                    "the text itself is not executable."
                ),
            ))

    # Compatibility for constrained models that serialize structured fields into the
    # operator-facing answer. Promote only fixed capability categories that the trusted
    # ledger still marks actionable; never extract names, namespaces, URLs, or tool payloads.
    content = str(validated_answer.get("content") or "")
    if re.search(
        r"\b(?:recommended next (?:evidence|checks?|collections?)|investigation gaps?)\b",
        content,
        re.IGNORECASE,
    ):
        for capability, pattern in _RECOMMENDATION_CAPABILITY_PATTERNS:
            if capability == "resource_read":
                continue
            if (
                check_states.get(capability) in available_states
                and re.search(pattern, content, re.IGNORECASE)
            ):
                add(InvestigationGap(
                    question=f"Collect the unverified {capability.replace('_', ' ')} evidence.",
                    capability=capability,
                    priority="medium",
                    reason=(
                        "Promoted from a malformed operator-facing evidence recommendation; "
                        "only the fixed capability category is retained and the prose is not executable."
                    ),
                ))
    return result


def _partition_investigation_gaps(
    gaps: list[InvestigationGap],
    *,
    capability_ledger: dict[str, object],
) -> tuple[list[InvestigationGap], list[InvestigationGap]]:
    """Reconcile requested evidence gaps against the final trusted capability ledger."""

    states = {
        str(item.get("capability")): str(item.get("state"))
        for item in capability_ledger.get("checks") or []
        if isinstance(item, dict)
    }
    resolved: list[InvestigationGap] = []
    unresolved: list[InvestigationGap] = []
    for gap in gaps:
        (resolved if states.get(gap.capability) == "collected" else unresolved).append(gap)
    return resolved, unresolved


def _reconcile_validated_answer_gaps(
    validated_answer: dict[str, object],
    *,
    capability_ledger: dict[str, object],
) -> dict[str, object]:
    """Remove model-authored gaps that trusted collection state already resolved."""

    gaps = [
        gap for gap in (validated_answer.get("investigation_gaps") or [])
        if isinstance(gap, InvestigationGap)
    ]
    _, unresolved = _partition_investigation_gaps(
        gaps, capability_ledger=capability_ledger
    )
    validated_answer["investigation_gaps"] = unresolved
    return validated_answer


def _adhoc_answer_advisories(
    *, citations: list[str], question: str,
    observations: list[dict[str, object]],
) -> list[str]:
    """Describe weak evidence shape without vetoing a readable provider answer."""

    if not (_question_requires_object_details(question) and citations):
        return []
    cited_tools = {
        str(item.get("tool") or "")
        for item in observations
        if str(item.get("id") or "") in citations
    }
    if (
        cited_tools
        and cited_tools <= {"list_resources", "search_resources"}
        and not _inventory_citations_have_material_details(
            citations=citations,
            observations=observations,
            question=question,
        )
    ):
        return [
            "This answer relies on inventory-level evidence; exact-object spec/status "
            "evidence would be needed for a detailed configuration or health conclusion."
        ]
    return []


def _question_requires_object_details(question: str) -> bool:
    """Treat only explicit enumeration/count requests as inventory-only."""

    if not question.strip():
        return False
    explanatory_signal = bool(re.search(
        r"(?i)\b(?:why|health|healthy|unhealthy|status|state|ready|readiness|degraded|"
        r"configur(?:e|ed|ation)|set\s*up|setup|details?|forward(?:ed|ing)?|routing?|"
        r"pipeline|destinations?|connect(?:ed|ion)?|integrat(?:e|ed|ion)|"
        r"how(?!\s+many\b))\b",
        question,
    ))
    if explanatory_signal:
        return True
    explicit_inventory = bool(re.search(
        r"(?i)\b(?:list|show|display|enumerate|inventory|count|how\s+many)\b",
        question,
    )) or bool(re.search(
        r"(?i)\b(?:what|which)\b.{0,80}\b(?:available|exist|present|installed|"
        r"have|deployed|running)\b",
        question,
    )) or bool(re.search(
        r"(?i)\b(?:do|does|are|is)\b.{0,80}\b(?:have|exist|present|installed|"
        r"deployed|running)\b",
        question,
    ))
    return not explicit_inventory


def _inventory_citations_have_material_details(
    *, citations: list[str], observations: list[dict[str, object]], question: str,
) -> bool:
    configuration_signal = bool(re.search(
        r"(?i)\b(?:configur(?:e|ed|ation)|set\s*up|setup|forward(?:ed|ing)?|routing?|"
        r"pipeline|outputs?|inputs?|destinations?|connect(?:ed|ion)?|integrat(?:e|ed|ion))\b",
        question,
    ))
    for observation in observations:
        if (
            str(observation.get("id") or "") not in citations
            or observation.get("tool") not in {"list_resources", "search_resources"}
        ):
            continue
        data = observation.get("data") if isinstance(observation.get("data"), dict) else {}
        if data.get("detailsTruncated"):
            continue
        items = data.get("items") if isinstance(data.get("items"), list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
            status = item.get("status") if isinstance(item.get("status"), dict) else {}
            if spec or (status and not configuration_signal):
                return True
            if not configuration_signal and any(
                key not in {"apiVersion", "kind", "metadata", "spec", "status"}
                for key in item
            ):
                return True
    return False


def _compact_provider_value(
    value: object, *, string_limit: int = 2_000, list_limit: int = 24, depth: int = 0
) -> object:
    """Bound provider-facing evidence while preserving the persisted redacted observation."""

    if depth >= 6:
        return _evidence_value(value, limit=min(string_limit, 500))
    if isinstance(value, str):
        return value if len(value) <= string_limit else value[:string_limit] + "…"
    if isinstance(value, dict):
        return {
            str(key)[:128]: _compact_provider_value(
                item, string_limit=string_limit, list_limit=list_limit, depth=depth + 1
            )
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple)):
        return [
            _compact_provider_value(
                item, string_limit=string_limit, list_limit=list_limit, depth=depth + 1
            )
            for item in list(value)[:list_limit]
        ]
    return value


def _compact_answer_evidence(
    evidence: list[dict[str, object]],
    *,
    activity: list[dict[str, object]],
    total_byte_limit: int = 96_000,
    per_observation_byte_limit: int = 14_000,
    max_observations: int | None = None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Prioritize current-turn evidence and enforce a total final-answer context budget."""

    current_ids = {
        str(evidence_id)
        for entry in activity
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    prioritized = [item for item in evidence if str(item.get("id")) in current_ids]
    prioritized.extend(
        reversed([item for item in evidence if str(item.get("id")) not in current_ids])
    )
    compacted: list[dict[str, object]] = []
    used_bytes = 0
    for item in prioritized:
        if max_observations is not None and len(compacted) >= max_observations:
            break
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        compact_data = _compact_provider_value(data)
        if item.get("tool") == "pod_logs" and isinstance(compact_data, dict):
            tail = str(data.get("tail") or "")
            compact_data["tail"] = tail[-6_000:]
            if len(tail) > 6_000:
                compact_data["tailTruncatedForModel"] = True
        candidate = {
            "id": item.get("id"),
            "cluster_id": item.get("cluster_id"),
            "cluster_name": item.get("cluster_name"),
            "tool": item.get("tool"),
            "summary": item.get("summary"),
            "source": item.get("source"),
            "collected_at": item.get("collected_at"),
            "data": compact_data,
        }
        encoded = json.dumps(candidate, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > per_observation_byte_limit:
            candidate["data"] = _compact_provider_value(
                data, string_limit=700, list_limit=10
            )
            if item.get("tool") == "pod_logs" and isinstance(candidate["data"], dict):
                tail = str(data.get("tail") or "")
                candidate["data"]["tail"] = tail[-3_000:]
                candidate["data"]["tailTruncatedForModel"] = len(tail) > 3_000
            encoded = json.dumps(candidate, sort_keys=True, default=str).encode("utf-8")
        if compacted and used_bytes + len(encoded) > total_byte_limit:
            continue
        compacted.append(candidate)
        used_bytes += len(encoded)
    metadata = {
        "observations_available": len(evidence),
        "observations_sent": len(compacted),
        "observations_omitted": len(evidence) - len(compacted),
        "current_turn_observations": len(current_ids),
        "encoded_bytes": used_bytes,
        "per_observation_byte_limit": per_observation_byte_limit,
        "total_byte_limit": total_byte_limit,
    }
    return compacted, metadata


def _compact_answer_findings(
    findings: list[dict[str, object]], *, total_byte_limit: int = 28_000
) -> list[dict[str, object]]:
    compacted: list[dict[str, object]] = []
    used_bytes = 0
    for finding in findings[:12]:
        candidate = _compact_provider_value(
            finding, string_limit=700, list_limit=8
        )
        encoded = json.dumps(candidate, sort_keys=True, default=str).encode("utf-8")
        if compacted and used_bytes + len(encoded) > total_byte_limit:
            break
        assert isinstance(candidate, dict)
        compacted.append(candidate)
        used_bytes += len(encoded)
    return compacted


def _limitation_signature(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    if any(marker in normalized for marker in (
        "model planner", "model twice stopped", "model returned an incomplete final answer",
        "model provider could not correct", "model planner repeated only reads",
        "podpilot selected the highest priority grounded read candidate",
        "podpilot requested a novel evidence step",
    )):
        return "model_orchestration_recovery"
    if "tls" in normalized and any(
        marker in normalized for marker in ("bypass", "disabled", "without verification")
    ):
        return "tls_verification_bypassed"
    if "certificate" in normalized and any(
        marker in normalized for marker in ("verify", "trust", "self signed")
    ):
        return "certificate_trust_failure"
    if "event" in normalized and any(
        marker in normalized for marker in ("no event", "none matched", "not found")
    ):
        return "no_matching_events"
    return normalized[:240]


def _dedupe_limitations(values: list[str], *, limit: int = 8) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        bounded = redact_text(str(value))[:500]
        signature = _limitation_signature(bounded)
        if not bounded or signature in seen:
            continue
        seen.add(signature)
        result.append(
            "The model stopped early or repeated reads; PodPilot used grounded read "
            "candidates and deterministic evidence where needed."
            if signature == "model_orchestration_recovery" else bounded
        )
        if len(result) >= limit:
            break
    return result


def _deterministic_evidence_fallback_answer(
    *, evidence: list[dict[str, object]], activity: list[dict[str, object]]
) -> dict[str, object]:
    current_ids = [
        str(evidence_id)
        for entry in activity
        for evidence_id in (entry.get("evidence_ids") or [])
    ]
    by_id = {str(item.get("id")): item for item in evidence if item.get("id")}
    selected_ids = list(dict.fromkeys(
        [item for item in current_ids if item in by_id]
        or [str(item.get("id")) for item in evidence[-6:] if item.get("id")]
    ))[:8]
    if not selected_ids:
        return {
            "answer_mode": "insufficient_evidence",
            "content": (
                "PodPilot could not produce a complete technical answer and no successful "
                "cluster observations were available for a deterministic summary."
            ),
            "citations": [],
        }
    lines = []
    for evidence_id in selected_ids:
        item = by_id[evidence_id]
        lines.append(
            f"- **{str(item.get('tool') or 'read').replace('_', ' ')}:** "
            f"{str(item.get('summary') or evidence_id)[:500]}"
        )
    return {
        "answer_mode": "evidence_based",
        "content": (
            "## Investigation result\n\n"
            "The model provider did not return a complete technical explanation, so PodPilot "
            "preserved the verified observations below instead of displaying an empty response.\n\n"
            "## Observed evidence\n\n" + "\n".join(lines) + "\n\n"
            "## Still unverified\n\n"
            "These observations require a complete evidence-backed interpretation before a root cause "
            "can be confirmed."
        ),
        "citations": selected_ids,
    }


def _deterministic_provider_failure_answer(
    *,
    question: str,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
    inventory_only: bool | None = None,
) -> dict[str, object]:
    """Preserve successful reads when the final provider call has no usable content."""

    evidence_summary = _deterministic_evidence_fallback_answer(
        evidence=evidence, activity=activity
    )
    specialized = (
        _deterministic_route_tls_answer(
            question=question, evidence=evidence, activity=activity
        )
        or _deterministic_resource_detail_answer(
            question=question, evidence=evidence, activity=activity
        )
        or _deterministic_inventory_answer(
            question=question,
            evidence=evidence,
            activity=activity,
            inventory_only=inventory_only,
        )
    )
    if specialized is None:
        return evidence_summary
    specialized_content = str(specialized["content"]).rstrip()
    evidence_content = str(evidence_summary["content"])
    observed_marker = "## Observed evidence\n\n"
    observed_section = (
        evidence_content.split(observed_marker, 1)[1].split("\n\n## Still unverified", 1)[0]
        if observed_marker in evidence_content else ""
    )
    if observed_section:
        specialized["content"] = (
            f"{specialized_content}\n\n## Other collected evidence\n\n{observed_section.strip()}"
        )
    specialized["citations"] = list(dict.fromkeys([
        *[str(item) for item in specialized.get("citations", [])],
        *[str(item) for item in evidence_summary.get("citations", [])],
    ]))
    return specialized


def _deterministic_resource_detail_answer(
    *, evidence: list[dict[str, object]], activity: list[dict[str, object]],
    question: str = "",
) -> dict[str, object] | None:
    """Render a bounded question-focused answer from exact-object evidence."""

    current_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded" and entry.get("tool") == "get_resource"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    observations = [
        item for item in evidence
        if str(item.get("id") or "") in current_ids
        and item.get("tool") == "get_resource"
        and isinstance(item.get("data"), dict)
    ][:6]
    # Follow-up turns commonly reuse an exact object collected on an earlier turn.
    # Keep the default fallback scoped to current reads, but make prior CLF evidence
    # available for Kafka questions so a cached target is not displaced by a newly
    # read object from another selected cluster.
    if "kafka" in question.casefold():
        by_id = {str(item.get("id") or ""): item for item in observations}
        for item in reversed(evidence):
            data = item.get("data")
            if (
                item.get("tool") == "get_resource"
                and isinstance(data, dict)
                and str(data.get("kind") or "").casefold() == "clusterlogforwarder"
                and item.get("id")
            ):
                by_id.setdefault(str(item["id"]), item)
        observations = list(by_id.values())[:10]
    if not observations:
        return None

    def bounded_value(value: object, *, limit: int = 450) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        safe = redact_text(encoded).replace("|", "\\|").replace("`", "'")
        return safe if len(safe) <= limit else safe[:limit] + "…"

    def string_list(value: object) -> list[str]:
        return [str(item) for item in value] if isinstance(value, list) else []

    def matching_items(value: object, terms: set[str]) -> list[dict[str, object]]:
        return [
            item for item in value if isinstance(item, dict)
            and any(term in json.dumps(item, sort_keys=True, default=str).casefold() for term in terms)
        ] if isinstance(value, list) else []

    def endpoint_summary(output: dict[str, object]) -> str:
        candidates: list[str] = []
        def visit(value: object, *, depth: int = 0) -> None:
            if depth > 4:
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    if str(key).casefold() in {
                        "url", "urls", "brokers", "bootstrapservers", "bootstrap_servers",
                    }:
                        candidates.extend(string_list(item) or ([str(item)] if item else []))
                    else:
                        visit(item, depth=depth + 1)
            elif isinstance(value, list):
                for item in value[:12]:
                    visit(item, depth=depth + 1)
        visit(output)
        return ", ".join(dict.fromkeys(redact_text(item)[:253] for item in candidates)) or "not exposed"

    def input_summary(item: dict[str, object]) -> str:
        name = str(item.get("name") or "unnamed")
        input_type = str(item.get("type") or "unspecified type")
        includes = 0
        namespaces: list[str] = []
        def visit(value: object) -> None:
            nonlocal includes
            if isinstance(value, dict):
                if value.get("namespace"):
                    includes += 1
                    namespaces.append(str(value["namespace"]))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(item)
        sample = ", ".join(f"`{value}`" for value in namespaces[:4])
        scope = (
            f"; {includes} namespace include rule{'s' if includes != 1 else ''}"
            + (f" ({sample}{', …' if includes > 4 else ''})" if sample else "")
            if includes else ""
        )
        return f"`{name}` ({input_type}{scope})"

    kafka_observations = [
        item for item in observations
        if str(item["data"].get("kind") or "").casefold() == "clusterlogforwarder"
        and "kafka" in question.casefold()
    ]
    if kafka_observations:
        question_tokens = set(re.findall(r"[a-z0-9]+", question.casefold()))
        ignored_cluster_tokens = {
            "cluster", "clusters", "dev", "development", "prod", "production",
            "test", "testing", "stage", "staging", "the",
        }
        cluster_match_scores = [
            (
                len((set(re.findall(
                    r"[a-z0-9]+",
                    str(item.get("cluster_name") or "").casefold(),
                )) - ignored_cluster_tokens) & question_tokens),
                item,
            )
            for item in kafka_observations
        ]
        highest_cluster_match = max((score for score, _ in cluster_match_scores), default=0)
        if highest_cluster_match:
            kafka_observations = [
                item for score, item in cluster_match_scores if score == highest_cluster_match
            ]

        cluster_sections: list[str] = []
        configured_clusters: list[str] = []
        citations: list[str] = []
        namespace_question = bool(re.search(
            r"(?i)\b(?:which|what|list|show)\s+namespaces?\b|\bnamespaces?\s+(?:are|is)\b",
            question,
        ))
        for observation in kafka_observations:
            data = observation["data"]
            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
            status = data.get("status") if isinstance(data.get("status"), dict) else {}
            cluster = str(
                observation.get("cluster_name") or observation.get("cluster_id") or "cluster"
            )[:253]
            namespace = str(metadata.get("namespace") or "cluster")[:253]
            name = str(metadata.get("name") or "unnamed")[:253]
            outputs = matching_items(spec.get("outputs"), {"kafka"})
            output_names = {str(item.get("name")) for item in outputs if item.get("name")}
            pipelines = [
                item for item in (spec.get("pipelines") or []) if isinstance(item, dict)
                and (
                    output_names.intersection(string_list(
                        item.get("outputRefs") or item.get("output_refs")
                    ))
                    or "kafka" in json.dumps(item, sort_keys=True, default=str).casefold()
                )
            ]
            if outputs and pipelines:
                configured_clusters.append(cluster)
            input_names = {
                value for pipeline in pipelines
                for value in string_list(pipeline.get("inputRefs") or pipeline.get("input_refs"))
            }
            inputs = [
                item for item in (spec.get("inputs") or [])
                if isinstance(item, dict) and str(item.get("name") or "") in input_names
            ]
            conditions = [
                condition
                for key, value in status.items()
                if str(key).casefold().endswith("conditions") and isinstance(value, list)
                for condition in value
                if isinstance(condition, dict) and (
                    "kafka" in json.dumps(condition, sort_keys=True, default=str).casefold()
                    or any(name.casefold() in json.dumps(condition, default=str).casefold()
                           for name in output_names)
                    or any(str(pipeline.get("name") or "").casefold()
                           in json.dumps(condition, default=str).casefold()
                           for pipeline in pipelines if pipeline.get("name"))
                )
            ][:6]
            cluster_sections.extend([
                "",
                f"### {cluster} · `{namespace}/{name}`",
                "",
            ])
            if not outputs:
                cluster_sections.append("- **Kafka output:** No Kafka output was found in the exact CLF read.")
            else:
                cluster_sections.extend(
                    f"- **Kafka output `{str(output.get('name') or 'unnamed')}`:** "
                    f"type `{str(output.get('type') or 'kafka')}`; destination `{endpoint_summary(output)}`."
                    for output in outputs[:4]
                )
            if pipelines:
                for pipeline in pipelines[:6]:
                    pipeline_name = str(pipeline.get("name") or "unnamed")
                    input_refs = string_list(pipeline.get("inputRefs") or pipeline.get("input_refs"))
                    output_refs = string_list(pipeline.get("outputRefs") or pipeline.get("output_refs"))
                    pipeline_filters = string_list(pipeline.get("filterRefs") or pipeline.get("filter_refs"))
                    cluster_sections.append(
                        f"- **Pipeline `{pipeline_name}`:** inputs "
                        f"{', '.join(f'`{item}`' for item in input_refs) or 'none'} → "
                        f"outputs {', '.join(f'`{item}`' for item in output_refs) or 'none'}"
                        + (f"; filters {', '.join(f'`{item}`' for item in pipeline_filters)}." if pipeline_filters else ".")
                    )
            elif outputs:
                cluster_sections.append("- **Pipeline linkage:** No pipeline referencing the Kafka output was found.")
            if inputs:
                cluster_sections.append(
                    "- **Referenced inputs:** " + "; ".join(input_summary(item) for item in inputs[:6]) + "."
                )
            if conditions:
                cluster_sections.append("- **Validation:** " + "; ".join(
                    f"{str(item.get('type') or 'condition')}=`{str(item.get('status') or 'Unknown')}`"
                    + (f" ({str(item.get('message'))[:180]})" if item.get("message") else "")
                    for item in conditions
                ) + ".")
            citations.append(str(observation["id"]))
        if namespace_question:
            namespace_sections: list[str] = []
            namespace_citations: list[str] = []
            for observation in kafka_observations:
                data = observation["data"]
                metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
                spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
                cluster = str(
                    observation.get("cluster_name") or observation.get("cluster_id") or "cluster"
                )[:253]
                outputs = matching_items(spec.get("outputs"), {"kafka"})
                output_names = {str(item.get("name")) for item in outputs if item.get("name")}
                pipelines = [
                    item for item in (spec.get("pipelines") or []) if isinstance(item, dict)
                    and output_names.intersection(string_list(
                        item.get("outputRefs") or item.get("output_refs")
                    ))
                ]
                input_names = {
                    value for pipeline in pipelines
                    for value in string_list(pipeline.get("inputRefs") or pipeline.get("input_refs"))
                }
                inputs = [
                    item for item in (spec.get("inputs") or [])
                    if isinstance(item, dict) and str(item.get("name") or "") in input_names
                ]
                namespaces: list[str] = []

                def collect_include_namespaces(value: object) -> None:
                    if isinstance(value, dict):
                        for key, child in value.items():
                            if str(key).casefold() == "includes" and isinstance(child, list):
                                for rule in child:
                                    if isinstance(rule, dict) and rule.get("namespace"):
                                        namespaces.append(str(rule["namespace"]))
                            else:
                                collect_include_namespaces(child)
                    elif isinstance(value, list):
                        for child in value:
                            collect_include_namespaces(child)

                for item in inputs:
                    collect_include_namespaces(item)
                namespaces = list(dict.fromkeys(namespaces))
                namespace_sections.extend([
                    "",
                    f"### {cluster} · `{str(metadata.get('namespace') or 'cluster')[:253]}/"
                    f"{str(metadata.get('name') or 'unnamed')[:253]}`",
                    "",
                ])
                if namespaces:
                    namespace_sections.extend(f"- `{namespace}`" for namespace in namespaces[:100])
                    if len(namespaces) > 100:
                        namespace_sections.append(
                            f"- …and {len(namespaces) - 100} additional configured namespace rules."
                        )
                else:
                    namespace_sections.append(
                        "- No explicit namespace include rules were found on the inputs linked to Kafka."
                    )
                namespace_citations.append(str(observation["id"]))
            return {
                "answer_mode": "evidence_based",
                "content": "\n".join([
                    "## Namespaces configured for Kafka forwarding",
                    *namespace_sections,
                    "",
                    "## Verification boundary",
                    "",
                    (
                        "These are the explicit namespace include rules on CLF inputs linked to a "
                        "Kafka output. This configuration does not prove that every namespace is "
                        "currently producing logs or that Kafka received them."
                    ),
                ]),
                "citations": namespace_citations,
            }
        all_configured = len(configured_clusters) == len(kafka_observations)
        summary = (
            "Yes. Every inspected cluster has a Kafka output referenced by at least one CLF pipeline."
            if all_configured else
            f"Kafka forwarding is fully linked on {len(configured_clusters)} of "
            f"{len(kafka_observations)} inspected clusters."
        )
        return {
            "answer_mode": "evidence_based",
            "content": "\n".join([
                "## Kafka forwarding answer", "", summary,
                *cluster_sections,
                "", "## Verification boundary", "",
                (
                    "This proves the observed CLF configuration and validation state. It does not "
                    "prove that Kafka received logs; that requires destination-side or delivery evidence."
                ),
            ]),
            "citations": citations,
        }

    stopwords = {
        "about", "cluster", "configuration", "details", "each", "from", "have", "show",
        "that", "their", "these", "this", "what", "which", "with", "your",
    }
    terms = {
        token.casefold() for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", question)
        if token.casefold() not in stopwords
    }
    sections = [
        "## Question-focused resource evidence",
        "",
        (
            "The model did not return an evidence-backed interpretation, so PodPilot rendered "
            "the successfully collected exact-object fields most relevant to the question."
        ),
    ]
    citations: list[str] = []
    for observation in observations:
        data = observation["data"]
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        kind = str(data.get("kind") or "Resource")[:128]
        namespace = str(metadata.get("namespace") or "cluster")[:253]
        name = str(metadata.get("name") or "unnamed")[:253]
        cluster = str(
            observation.get("cluster_name") or observation.get("cluster_id") or "cluster"
        )[:253]
        sections.extend([
            "",
            f"### {cluster} · {kind} `{namespace}/{name}`",
            "",
            "| Field | Observed value |",
            "|---|---|",
        ])
        fields: list[tuple[str, object]] = []
        for section_name in ("spec", "status"):
            section = data.get(section_name)
            if isinstance(section, dict):
                candidates = [
                    (f"{section_name}.{key}", value)
                    for key, value in section.items()
                    if not terms or any(
                        term in f"{key} {json.dumps(value, default=str)}".casefold()
                        for term in terms
                    )
                ]
                fields.extend(candidates[:6])
        if not fields and data.get("truncated_json"):
            fields.append(("object", data["truncated_json"]))
        if not fields:
            fields.append(("result", "No exact-object fields matched the question terms."))
        sections.extend(
            f"| `{field}` | `{bounded_value(value)}` |" for field, value in fields
        )
        citations.append(str(observation["id"]))
    sections.extend([
        "",
        "## Interpretation boundary",
        "",
        (
            "These are question-matched observed fields, not a complete object dump. Configuration "
            "shows intended state and does not by itself prove external behavior."
        ),
    ])
    return {
        "answer_mode": "evidence_based",
        "content": "\n".join(sections),
        "citations": citations,
    }


def _deterministic_inventory_answer(
    *,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
    question: str = "",
    inventory_only: bool | None = None,
) -> dict[str, object] | None:
    """Render validated list evidence when the model cannot produce a useful answer."""

    if inventory_only is False or (
        inventory_only is None and _question_requires_object_details(question)
    ):
        return None

    current_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded" and entry.get("tool") == "list_resources"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    observations = [
        item for item in reversed(evidence)
        if str(item.get("id")) in current_ids
        and item.get("tool") == "list_resources"
        and isinstance(item.get("data"), dict)
        and isinstance(item["data"].get("names"), list)
    ]
    discovery_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded"
        and entry.get("tool") == "discover_resources"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    discovery_misses = [
        item for item in reversed(evidence)
        if str(item.get("id")) in discovery_ids
        and item.get("tool") == "discover_resources"
        and isinstance(item.get("data"), dict)
        and item["data"].get("inventoryMatch") == "none"
    ]
    if not observations and not discovery_misses:
        return None

    def inventory_rows(data: dict[str, object]) -> list[tuple[str, str, str]]:
        names = [str(name)[:253] for name in data.get("names", [])]
        refs = data.get("objects") if isinstance(data.get("objects"), list) else []
        items = data.get("items") if isinstance(data.get("items"), list) else []
        scope = str(data.get("scope") or "cluster")
        rows: list[tuple[str, str, str]] = []
        for index, name in enumerate(names):
            ref = refs[index] if index < len(refs) and isinstance(refs[index], dict) else {}
            item = items[index] if index < len(items) and isinstance(items[index], dict) else {}
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            namespace = str(
                ref.get("namespace")
                or metadata.get("namespace")
                or (scope if scope != "cluster" else "—")
            )
            status = item.get("status") if isinstance(item.get("status"), dict) else {}
            conditions = (
                status.get("conditions")
                if isinstance(status.get("conditions"), list) else []
            )
            ready = "—"
            for condition in conditions:
                if (
                    isinstance(condition, dict)
                    and str(condition.get("type") or "").casefold() == "ready"
                ):
                    ready = str(condition.get("status") or "Unknown")[:32]
                    break
            rows.append((namespace[:253], name, ready))
        return rows

    inventory_sources = [*observations, *discovery_misses]
    source_cluster_ids = {
        str(item.get("cluster_id") or item.get("cluster_name") or "cluster")
        for item in inventory_sources
    }
    if len(source_cluster_ids) > 1:
        rows: list[str] = []
        citations: list[str] = []
        total_matches = 0
        for observation in reversed(observations):
            data = observation["data"]
            cluster_name = str(observation.get("cluster_name") or observation.get("cluster_id") or "cluster")
            kind = str(data.get("kind") or "Resource")
            objects = inventory_rows(data)
            citations.append(str(observation["id"]))
            if objects:
                total_matches += len(objects)
                rows.extend(
                    f"| `{cluster_name}` | `{kind}` | `{namespace}` | `{name}` | {ready} |"
                    for namespace, name, ready in objects
                )
            else:
                rows.append(
                    f"| `{cluster_name}` | `{kind}` | — | _No matching resources_ | — |"
                )
        for observation in reversed(discovery_misses):
            cluster_name = str(
                observation.get("cluster_name")
                or observation.get("cluster_id")
                or "cluster"
            )
            citations.append(str(observation["id"]))
            rows.append(
                f"| `{cluster_name}` | — | — | "
                "_No matching readable API resource type_ | Unknown |"
            )
        return {
            "answer_mode": "evidence_based",
            "content": (
                "## Multi-cluster inventory\n\n"
                f"**Collected:** {total_matches} matching resource"
                f"{'s' if total_matches != 1 else ''} across {len(source_cluster_ids)} "
                "OpenShift clusters.\n\n"
                "| OpenShift cluster | Kind | Namespace | Matching resource | Ready |\n"
                "|---|---|---|---|---|\n" + "\n".join(rows) +
                "\n\nEach row comes from an independently bounded read against the named cluster."
            ),
            "citations": citations,
        }
    if discovery_misses:
        observation = discovery_misses[0]
        cluster_name = str(
            observation.get("cluster_name")
            or observation.get("cluster_id")
            or "cluster"
        )
        return {
            "answer_mode": "evidence_based",
            "content": (
                "## Inventory result\n\n"
                f"No matching readable API resource type was discovered on `{cluster_name}`. "
                "The API may not be installed, or the configured identity may not be allowed to read it."
            ),
            "citations": [str(observation["id"])],
        }
    observation = observations[0]
    data = observation["data"]
    objects = inventory_rows(data)
    kind = str(data.get("kind") or "Resource")
    scope = str(data.get("scope") or "cluster")
    complete = bool(data.get("objectListComplete", not data.get("truncated")))
    lines = [
        f"## {kind} inventory",
        "",
        f"**Scope:** `{scope}`  ",
        f"**Collected:** {len(objects)}",
        "",
    ]
    if objects:
        lines.extend(["| # | Namespace | Name | Ready |", "|---:|---|---|---|"])
        lines.extend(
            f"| {index} | `{namespace}` | `{name}` | {ready} |"
            for index, (namespace, name, ready) in enumerate(objects, 1)
        )
    else:
        lines.append("No matching resources were returned.")
    lines.extend(["", (
        "The collected object list is complete for this snapshot."
        if complete else
        "The configured inventory ceiling was reached; additional matching resources exist."
    )])
    if data.get("detailsTruncated"):
        lines.append(
            "Verbose status details were compacted, but every collected resource name is shown above."
        )
    return {
        "answer_mode": "evidence_based",
        "content": "\n".join(lines),
        "citations": [str(observation["id"])],
    }


def _append_deterministic_inventory(
    validated: dict[str, object], inventory_answer: dict[str, object] | None,
) -> dict[str, object]:
    """Augment a concise model conclusion with verified object identities."""

    if inventory_answer is None:
        return validated
    inventory_content = str(inventory_answer.get("content") or "").strip()
    if not inventory_content or inventory_content in str(validated.get("content") or ""):
        return validated
    validated["content"] = (
        f"{str(validated.get('content') or '').rstrip()}\n\n{inventory_content}"
    ).strip()
    validated["citations"] = list(dict.fromkeys([
        *[str(item) for item in (validated.get("citations") or [])],
        *[str(item) for item in (inventory_answer.get("citations") or [])],
    ]))
    return validated


def _deterministic_route_tls_answer(
    *,
    question: str,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
) -> dict[str, object] | None:
    """Explain configured Route TLS behavior from a host-matched OpenShift Route."""

    if not (
        re.search(r"\broute\b", question, re.IGNORECASE)
        and re.search(r"\b(?:https?|tls|backend|endpoint)\b", question, re.IGNORECASE)
    ):
        return None
    current_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded" and entry.get("tool") == "search_resources"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    current_probe_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("tool") == "http_probe"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    current_success_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    for observation in reversed(evidence):
        if str(observation.get("id")) not in current_ids:
            continue
        data = observation.get("data")
        if not isinstance(data, dict) or data.get("kind") != "Route":
            continue
        items = data.get("items")
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            continue
        route = items[0]
        metadata = route.get("metadata") if isinstance(route.get("metadata"), dict) else {}
        spec = route.get("spec") if isinstance(route.get("spec"), dict) else {}
        tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
        termination = str(tls.get("termination") or "").lower()
        destination = spec.get("to") if isinstance(spec.get("to"), dict) else {}
        service = str(destination.get("name") or "")
        namespace = str(metadata.get("namespace") or data.get("scope") or "")
        target = f"`{namespace}/{service}`" if namespace and service else "the backend Service"
        port = spec.get("port") if isinstance(spec.get("port"), dict) else {}
        target_port = port.get("targetPort")
        port_text = f" on target port `{target_port}`" if target_port is not None else ""
        behavior = {
            "edge": (
                f"The router terminates client TLS and forwards unencrypted HTTP to {target}{port_text}. "
                "An HTTP-speaking backend is therefore the expected configuration."
            ),
            "reencrypt": (
                f"The router terminates client TLS, then creates a new TLS connection to {target}{port_text}. "
                "The backend must speak HTTPS/TLS."
            ),
            "passthrough": (
                f"The router does not terminate TLS; it passes the client TLS stream through to "
                f"{target}{port_text}. The backend must terminate HTTPS/TLS itself."
            ),
            "": (
                f"The Route has no TLS termination configured and routes unsecured HTTP to "
                f"{target}{port_text}."
            ),
        }.get(termination)
        if behavior is None:
            continue
        configured = f"`{termination}`" if termination else "none (unsecured)"
        route_host = str(spec.get("host") or "")
        probe_observations = [
            item for item in evidence
            if str(item.get("id")) in current_probe_ids
            and item.get("tool") == "http_probe"
            and isinstance(item.get("data"), dict)
            and (
                not route_host or item["data"].get("logicalHost") == route_host
            )
        ]
        probe_lines: list[str] = []
        probe_citations: list[str] = []
        application_response_observed = False
        for probe in probe_observations:
            probe_data = probe["data"]
            probe_id = str(probe.get("id"))
            if (
                probe_data.get("stage") == "tls"
                and "certificate" in str(probe_data.get("error") or "").lower()
            ):
                probe_lines.append(
                    "- The verified HTTPS probe reached TLS certificate validation but could not "
                    "trust the presented certificate chain."
                )
                probe_citations.append(probe_id)
            elif (
                probe_data.get("tlsVerificationRequested") is False
                or (
                    isinstance(probe_data.get("tls"), dict)
                    and probe_data["tls"].get("verified") is False
                )
            ):
                status = probe_data.get("statusCode") or probe_data.get("statusLine")
                result = (
                    f"returned HTTP `{status}`" if status is not None
                    else f"reported outcome `{probe_data.get('outcome') or 'unknown'}`"
                )
                probe_lines.append(
                    f"- The automatic retry without certificate verification {result}. This "
                    "tests endpoint behavior but does not authenticate server identity."
                )
                probe_citations.append(probe_id)
                application_response_observed = (
                    application_response_observed
                    or probe_data.get("statusCode") is not None
                )
        backend_lines: list[str] = []
        backend_citations: list[str] = []
        route_cluster_id = str(observation.get("cluster_id") or "")
        service_selector: dict[str, object] = {}
        endpoint_target_names: set[str] = set()
        for related in evidence:
            if (
                str(related.get("id") or "") not in current_success_ids
                or not isinstance(related.get("data"), dict)
                or (
                    route_cluster_id
                    and str(related.get("cluster_id") or "") != route_cluster_id
                )
            ):
                continue
            related_data = related["data"]
            related_metadata = (
                related_data.get("metadata")
                if isinstance(related_data.get("metadata"), dict) else {}
            )
            if (
                related_data.get("kind") == "Service"
                and related_metadata.get("name") == service
                and isinstance(related_data.get("spec"), dict)
                and isinstance(related_data["spec"].get("selector"), dict)
            ):
                service_selector = related_data["spec"]["selector"]
            if related_data.get("kind") not in {"EndpointSlice", "Endpoints"}:
                continue
            for endpoint_object in related_data.get("items") or [related_data]:
                if not isinstance(endpoint_object, dict):
                    continue
                related_endpoint_metadata = (
                    endpoint_object.get("metadata")
                    if isinstance(endpoint_object.get("metadata"), dict) else {}
                )
                related_endpoint_labels = (
                    related_endpoint_metadata.get("labels")
                    if isinstance(related_endpoint_metadata.get("labels"), dict) else {}
                )
                related_endpoint_service = str(
                    related_endpoint_labels.get("kubernetes.io/service-name")
                    or related_endpoint_metadata.get("name")
                    or related_metadata.get("name")
                )
                if service and related_endpoint_service and not (
                    related_endpoint_service == service
                    or related_endpoint_service.startswith(f"{service}-")
                ):
                    continue
                for endpoint in endpoint_object.get("endpoints") or []:
                    if not isinstance(endpoint, dict):
                        continue
                    target_ref = endpoint.get("targetRef")
                    if isinstance(target_ref, dict) and target_ref.get("name"):
                        endpoint_target_names.add(str(target_ref["name"]))
        for backend in evidence:
            backend_id = str(backend.get("id") or "")
            if (
                backend_id not in current_success_ids
                or not isinstance(backend.get("data"), dict)
                or (
                    route_cluster_id
                    and str(backend.get("cluster_id") or "") != route_cluster_id
                )
            ):
                continue
            backend_data = backend["data"]
            kind = str(backend_data.get("kind") or "")
            metadata = (
                backend_data.get("metadata")
                if isinstance(backend_data.get("metadata"), dict) else {}
            )
            backend_namespace = str(metadata.get("namespace") or backend_data.get("scope") or "")
            backend_name = str(metadata.get("name") or "")
            if kind == "Service" and backend_name == service and (
                not namespace or not backend_namespace or backend_namespace == namespace
            ):
                service_spec = (
                    backend_data.get("spec")
                    if isinstance(backend_data.get("spec"), dict) else {}
                )
                mappings = []
                for item in service_spec.get("ports") or []:
                    if not isinstance(item, dict):
                        continue
                    label = item.get("name") or item.get("port") or "unnamed"
                    mappings.append(
                        f"`{label}:{item.get('port')} -> {item.get('targetPort', item.get('port'))}`"
                    )
                if mappings:
                    backend_lines.append(
                        f"- The collected Service `{backend_namespace}/{backend_name}` exposes "
                        f"{', '.join(mappings)}."
                    )
                    backend_citations.append(backend_id)
            elif kind in {"EndpointSlice", "Endpoints"}:
                ports: list[str] = []
                targets: list[str] = []
                objects = backend_data.get("items") or [backend_data]
                for endpoint_object in objects:
                    if not isinstance(endpoint_object, dict):
                        continue
                    endpoint_metadata = (
                        endpoint_object.get("metadata")
                        if isinstance(endpoint_object.get("metadata"), dict) else {}
                    )
                    endpoint_labels = (
                        endpoint_metadata.get("labels")
                        if isinstance(endpoint_metadata.get("labels"), dict) else {}
                    )
                    endpoint_service = str(
                        endpoint_labels.get("kubernetes.io/service-name")
                        or endpoint_metadata.get("name") or backend_name
                    )
                    if service and endpoint_service and not (
                        endpoint_service == service or endpoint_service.startswith(f"{service}-")
                    ):
                        continue
                    for endpoint_port in endpoint_object.get("ports") or []:
                        if isinstance(endpoint_port, dict):
                            ports.append(str(
                                endpoint_port.get("name") or endpoint_port.get("port") or "unknown"
                            ) + f":{endpoint_port.get('port', 'unknown')}")
                    for endpoint in endpoint_object.get("endpoints") or []:
                        if not isinstance(endpoint, dict):
                            continue
                        target_ref = endpoint.get("targetRef")
                        if isinstance(target_ref, dict) and target_ref.get("name"):
                            targets.append(str(target_ref["name"]))
                if ports or targets or backend_data.get("podTargets"):
                    target_text = sorted(set(targets)) or [
                        str(item) for item in backend_data.get("podTargets") or []
                    ]
                    details = []
                    if ports:
                        details.append("ports " + ", ".join(f"`{item}`" for item in sorted(set(ports))))
                    if target_text:
                        details.append("targets " + ", ".join(f"`{item}`" for item in target_text[:6]))
                    backend_lines.append(
                        f"- The collected {kind} " + " and ".join(details) + "."
                    )
                    backend_citations.append(backend_id)
            elif kind == "Pod":
                pod_labels = (
                    metadata.get("labels")
                    if isinstance(metadata.get("labels"), dict) else {}
                )
                selector_matches = bool(service_selector) and all(
                    pod_labels.get(key) == value
                    for key, value in service_selector.items()
                )
                if not (
                    backend_name in endpoint_target_names
                    or selector_matches
                ):
                    continue
                pod_spec = (
                    backend_data.get("spec")
                    if isinstance(backend_data.get("spec"), dict) else {}
                )
                containers = []
                for container in pod_spec.get("containers") or []:
                    if not isinstance(container, dict):
                        continue
                    ports = [
                        str(item.get("containerPort"))
                        for item in container.get("ports") or []
                        if isinstance(item, dict) and item.get("containerPort") is not None
                    ]
                    containers.append(
                        f"`{container.get('name') or 'unnamed'}`"
                        + (f" (declared ports {', '.join(ports)})" if ports else "")
                    )
                if containers:
                    pod_name = backend_name or "observed backend Pod"
                    backend_lines.append(
                        f"- Pod `{pod_name}` contains {', '.join(containers)}. "
                        "Declared container ports describe configuration, not proof of TLS termination."
                    )
                    backend_citations.append(backend_id)
        content = (
            "## Route TLS behavior\n\n"
            f"**Configured termination:** {configured}\n\n"
            f"{behavior}\n\n"
            "This validates the Route configuration, not live backend reachability. An HTTP 500 can "
            "still originate from the router, backend application, or an upstream dependency."
        )
        if probe_lines:
            content += "\n\n## Live probe results\n\n" + "\n".join(probe_lines)
        if backend_lines:
            content += "\n\n## Backend topology observed\n\n" + "\n".join(backend_lines)
        if application_response_observed and termination in {"passthrough", "reencrypt"}:
            content += (
                "\n\nThe HTTPS probe completed TLS and received an HTTP response from the tested "
                "Route path. That rules out a failure caused solely by sending passthrough TLS to a "
                "backend path with no TLS-capable termination point; "
                "the returned status must be investigated at the gateway, application, authentication, "
                "or an upstream dependency."
            )
        return {
            "answer_mode": "evidence_based",
            "content": content,
            "citations": list(dict.fromkeys([
                str(observation["id"]), *probe_citations,
                *backend_citations,
            ])),
        }
    return None


def _deterministic_log_findings_section(
    *,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
) -> dict[str, object] | None:
    """Render current-turn structured log signals so model fallback cannot hide them."""

    current_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    evidence_by_id = {
        str(item.get("id")): item
        for item in evidence
        if item.get("id") and str(item.get("id")) in current_ids
    }
    selected: list[tuple[dict[str, object], list[str], list[str]]] = []
    for finding in derive_adhoc_findings(list(evidence_by_id.values())):
        finding_ids = [
            str(item) for item in (finding.get("evidence_ids") or [])
            if str(item) in current_ids and str(item) in evidence_by_id
        ]
        log_ids = [
            item for item in finding_ids
            if evidence_by_id[item].get("tool") == "pod_logs"
        ]
        if log_ids:
            selected.append((finding, finding_ids, log_ids))
    if not selected:
        return None

    def inline_code(value: object, *, limit: int = 500) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()[:limit]
        return f"`{text.replace('`', "'")}`"

    lines = [
        "## Backend log findings",
        "",
        "PodPilot detected these structured signals in the bounded backend log excerpts:",
    ]
    citations: list[str] = []
    required_log_citations: list[str] = []
    for finding, finding_ids, log_ids in selected[:5]:
        namespace = str(finding.get("namespace") or "unknown-namespace")
        pod = str(finding.get("pod") or "unknown-pod")
        container = str(finding.get("container") or "default")
        category = str(finding.get("category") or "operational signal").replace("_", " ")
        severity = str(finding.get("severity") or "unknown")
        occurrences = int(finding.get("occurrences_in_excerpt") or 0)
        lines.extend((
            "",
            f"### `{namespace}/{pod}` · `{container}`",
            "",
            f"- **Signal:** {severity} · {category}",
            f"- **Observed:** {occurrences} occurrence{'s' if occurrences != 1 else ''} "
            "in the bounded log excerpt",
        ))
        paths = finding.get("paths")
        if isinstance(paths, list) and paths:
            lines.append("- **Referenced paths:** " + ", ".join(
                inline_code(item, limit=240) for item in paths[:6]
            ))
        endpoints = finding.get("endpoints")
        if isinstance(endpoints, list) and endpoints:
            lines.append("- **Referenced endpoints:** " + ", ".join(
                inline_code(item, limit=240) for item in endpoints[:6]
            ))
        samples = finding.get("error_samples")
        if isinstance(samples, list) and samples:
            lines.append("- **Log sample:** " + inline_code(samples[0]))
        completed = finding.get("completed_checks")
        if isinstance(completed, list) and completed:
            lines.append(
                "- **Correlated checks:** "
                + ", ".join(str(item).replace("_", " ") for item in completed[:5])
            )
        citations.extend(finding_ids)
        required_log_citations.extend(log_ids)
    lines.extend((
        "",
        "These log matches are operational signals, not proof of root cause. Their relevance "
        "depends on the Route, Service, Pod, Event, and probe evidence collected in this turn.",
    ))
    return {
        "content": "\n".join(lines),
        "citations": list(dict.fromkeys(citations)),
        "required_log_citations": list(dict.fromkeys(required_log_citations)),
    }


def _current_log_analysis_payload(
    *, evidence: list[dict[str, object]], activity: list[dict[str, object]], question: str,
) -> tuple[dict[str, object] | None, dict[str, str]]:
    """Build a fresh, bounded provider payload containing every current log read."""

    current_ids = {
        str(evidence_id)
        for entry in activity
        if entry.get("status") == "succeeded" and entry.get("tool") == "pod_logs"
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    logs = [
        item for item in evidence
        if item.get("tool") == "pod_logs"
        and str(item.get("id") or "") in current_ids
        and isinstance(item.get("data"), dict)
        and str(item["data"].get("tail") or "").strip()
    ]
    if not logs:
        return None, {}
    per_log_limit = max(1_500, 30_000 // len(logs))
    excerpts: list[dict[str, object]] = []
    text_by_id: dict[str, str] = {}
    for item in logs:
        evidence_id = str(item["id"])
        data = item["data"]
        tail = redact_text(str(data.get("tail") or ""))[-per_log_limit:]
        text_by_id[evidence_id] = tail
        excerpts.append({
            "evidence_id": evidence_id,
            "cluster": str(item.get("cluster_name") or item.get("cluster_id") or "cluster")[:253],
            "source": str(item.get("source") or "")[:500],
            "container": str(data.get("container") or "default")[:253],
            "previous": bool(data.get("previous")),
            "excerpt": tail,
            "excerpt_limit": "bounded tail; earlier log lines may be absent",
        })
    return {
        "investigation_context": (
            "This is a read-only OpenShift troubleshooting investigation. Analyze the bounded "
            "Pod logs for potential issues relevant to the operator request, including connectivity "
            "and TLS signals when present, without assuming they are causal."
        ),
        "operator_request": redact_text(question)[:1_000],
        "logs": excerpts,
        "analysis_boundary": (
            "Identify potential issues in these excerpts only. They may be incomplete and do not prove causality."
        ),
    }, text_by_id


def _validated_model_log_analysis(
    analysis: AdHocLogAnalysis, *, text_by_id: dict[str, str],
) -> dict[str, object]:
    """Allow only cited issues whose quoted excerpt exists in the supplied logs."""

    issues: list[dict[str, object]] = []
    rejected_issue_count = 0
    for issue in analysis.issues:
        evidence_ids = list(dict.fromkeys(
            item for item in issue.evidence_ids if item in text_by_id
        ))
        excerpt = redact_text(issue.supporting_excerpt)[:500]
        normalized_excerpt = re.sub(r"\s+", " ", excerpt).strip().casefold()
        if not evidence_ids or not normalized_excerpt:
            rejected_issue_count += 1
            continue
        if not any(
            normalized_excerpt in re.sub(r"\s+", " ", text_by_id[item]).casefold()
            for item in evidence_ids
        ):
            rejected_issue_count += 1
            continue
        issues.append({
            "evidence_ids": evidence_ids,
            "severity": issue.severity,
            "category": redact_text(issue.category)[:100],
            "summary": redact_text(issue.summary)[:500],
            "potential_impact": redact_text(issue.potential_impact)[:700],
            "supporting_excerpt": excerpt,
            "confidence": issue.confidence,
        })
    return {
        "overview": redact_text(analysis.overview)[:700],
        "issues": issues[:10],
        "limitations": [redact_text(item)[:500] for item in analysis.limitations[:4]],
        "analyzed_evidence_ids": list(text_by_id),
        "rejected_issue_count": rejected_issue_count,
    }


def _model_log_analysis_section(analysis: dict[str, object]) -> dict[str, object]:
    """Render separately analyzed logs as hypotheses with evidence provenance."""

    issues = analysis.get("issues") if isinstance(analysis.get("issues"), list) else []
    lines = [
        "## Model-assisted log analysis",
        "",
        str(analysis.get("overview") or "The bounded Pod log excerpts were analyzed for potential issues."),
    ]
    citations: list[str] = []
    overview = str(analysis.get("overview") or "")
    overview_has_signal = bool(re.search(
        r"(?i)\b(?:denied|unauthorized|forbidden|errors?|fail(?:ed|ures?)?|401|403|permission)\b",
        overview,
    ))
    if not issues and overview_has_signal:
        lines.extend((
            "",
            "The overview noted a possible operational signal, but no structured issue could be "
            "verified against an exact cited log excerpt. Treat the overview as a hypothesis and "
            "continue correlating it with resource, event, metric, or probe evidence.",
        ))
        citations.extend(str(item) for item in analysis.get("analyzed_evidence_ids", []))
    elif not issues:
        lines.extend((
            "",
            "No potential operational issue was identified in the supplied bounded excerpts.",
        ))
        citations.extend(str(item) for item in analysis.get("analyzed_evidence_ids", []))
    for issue in issues[:10]:
        if not isinstance(issue, dict):
            continue
        lines.extend((
            "",
            f"### {str(issue.get('severity') or 'info').title()} · "
            f"{str(issue.get('category') or 'potential issue')}",
            "",
            f"- **Potential issue:** {str(issue.get('summary') or '')}",
            f"- **Potential impact:** {str(issue.get('potential_impact') or '')}",
            f"- **Confidence:** {str(issue.get('confidence') or 'low')}",
            "- **Supporting log excerpt:** `"
            + str(issue.get("supporting_excerpt") or "").replace("`", "'")
            + "`",
        ))
        citations.extend(str(item) for item in issue.get("evidence_ids", []))
    lines.extend((
        "",
        "This is semantic analysis of bounded log excerpts, not proof of root cause. "
        "Corroborating resource, event, metric, or probe evidence is still required.",
    ))
    return {"content": "\n".join(lines), "citations": list(dict.fromkeys(citations))}


def _evidence_value(value: object, *, limit: int = 1200) -> str:
    if isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(value, sort_keys=True, default=str)
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    elif value is None:
        rendered = "not reported"
    else:
        rendered = str(value)
    return rendered[:limit]


def _format_metric_value(value: object, unit: str) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    numeric = float(value)
    if unit == "bytes":
        labels = ("B", "KiB", "MiB", "GiB", "TiB")
        magnitude = abs(numeric)
        index = 0
        while magnitude >= 1024 and index < len(labels) - 1:
            numeric /= 1024
            magnitude /= 1024
            index += 1
        return f"{numeric:.2f} {labels[index]}"
    if unit == "bytes_per_second":
        return f"{_format_metric_value(numeric, 'bytes')}/s"
    if unit == "percent":
        return f"{numeric:.2f}%"
    if unit == "cores":
        return f"{numeric:.3f} cores"
    if unit == "ratio":
        return f"{numeric:.3f}"
    return f"{numeric:.3f} {unit}".strip()


def _metric_ranking_view(data: dict[str, object]) -> dict[str, object] | None:
    ranking = data.get("ranking")
    if not isinstance(ranking, list) or not ranking:
        return None
    unit = str(data.get("unit") or "")
    rows: list[dict[str, object]] = []
    current_values = [
        float(item["current"])
        for item in ranking
        if isinstance(item, dict)
        and isinstance(item.get("current"), (int, float))
        and not isinstance(item.get("current"), bool)
    ]
    scale_max = max(current_values, default=0.0)
    if scale_max <= 0:
        scale_max = 1.0
    for index, item in enumerate(ranking[:10], start=1):
        if not isinstance(item, dict):
            continue
        labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
        current = item.get("current")
        progress = (
            max(0.0, float(current))
            if isinstance(current, (int, float)) and not isinstance(current, bool)
            else 0.0
        )
        rows.append({
            "rank": index,
            "namespace": str(labels.get("namespace") or "—"),
            "pod": str(labels.get("pod") or "—"),
            "container": str(labels.get("container") or "—"),
            "average": _format_metric_value(item.get("average"), unit),
            "current": _format_metric_value(current, unit),
            "maximum": _format_metric_value(item.get("maximum"), unit),
            "progress": progress,
        })
    if not rows:
        return None
    metric_name = str(data.get("metric") or "metric")
    metric_title = {
        "top_cpu_consumers": "Top CPU Consumers",
        "top_memory_consumers": "Top Memory Consumers",
    }.get(metric_name, metric_name.replace("_", " ").title())
    return {
        "title": metric_title,
        "unit": unit,
        "scale_max": scale_max,
        "rows": rows,
        "complete": data.get("complete") is True,
    }


def _adhoc_evidence_view(item: dict[str, object]) -> dict[str, object]:
    """Build redacted, operator-facing facts from one persisted evidence observation."""

    view = dict(item)
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    facts: list[dict[str, str]] = []

    def add(label: str, value: object) -> None:
        if value in (None, "", [], {}):
            return
        facts.append({"label": label, "value": _evidence_value(value)})

    tool = str(item.get("tool") or "")
    if tool == "http_probe":
        add("Outcome", data.get("outcome"))
        add("Failure stage", data.get("stage"))
        add("Logical host / SNI", data.get("logicalHost"))
        add("Connected to", (
            f"{data.get('connectHost')}:{data.get('port')}"
            if data.get("connectHost") and data.get("port") else data.get("connectHost")
        ))
        add("Resolved addresses", data.get("resolvedAddresses"))
        add("TLS verification requested", data.get("tlsVerificationRequested"))
        tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
        add("TLS version", tls.get("version"))
        add("TLS cipher", tls.get("cipher"))
        add("HTTP status", data.get("statusLine") or data.get("statusCode"))
        add("Probe error", data.get("error"))
        add("Elapsed", f"{data.get('elapsedMs')} ms" if data.get("elapsedMs") is not None else None)
    elif tool == "pod_logs":
        add("Container", data.get("container") or "default container")
        add("Previous container", data.get("previous"))
        view["excerpt"] = str(data.get("tail") or "")
    elif tool == "query_metrics":
        add("Metric", data.get("metric"))
        add("Scope", data.get("scope"))
        add("Target", (
            f"{data.get('namespace')}/{data.get('name')}"
            if data.get("namespace") and data.get("name")
            else data.get("namespace") or data.get("name")
        ))
        add("Period", f"{data.get('rangeSeconds')} seconds" if data.get("rangeSeconds") else None)
        add("Resolution", f"{data.get('stepSeconds')} seconds" if data.get("stepSeconds") else None)
        add("Unit", data.get("unit"))
        add("Statistics", data.get("statistics"))
        add("Complete", data.get("complete"))
        view["metric_ranking"] = _metric_ranking_view(data)
    else:
        add("API version", data.get("apiVersion"))
        add("Kind", data.get("kind"))
        add("Scope", data.get("scope"))
        add("Objects returned", data.get("count"))
        add("Objects scanned", data.get("scannedCount"))
        if data.get("matchField"):
            add("Search predicate", f"{data.get('matchField')} {data.get('matchOperator')} {data.get('matchValue')}")
        add("Search complete", data.get("searchComplete"))
        add("Object list complete", data.get("objectListComplete"))
        objects = data.get("items") if isinstance(data.get("items"), list) else []
        projected = objects[0] if len(objects) == 1 and isinstance(objects[0], dict) else data
        metadata = projected.get("metadata") if isinstance(projected.get("metadata"), dict) else {}
        api_version = projected.get("apiVersion") or data.get("apiVersion")
        kind = projected.get("kind") or data.get("kind")
        namespace = metadata.get("namespace") or data.get("scope")
        name = metadata.get("name")
        add("Object", (
            f"{api_version} {kind} {namespace}/{name}"
            if kind and name else None
        ))
        spec = projected.get("spec") if isinstance(projected.get("spec"), dict) else {}
        if kind == "Route":
            tls = spec.get("tls") if isinstance(spec.get("tls"), dict) else {}
            destination = spec.get("to") if isinstance(spec.get("to"), dict) else {}
            port = spec.get("port") if isinstance(spec.get("port"), dict) else {}
            add("Route host", spec.get("host"))
            add("TLS termination", tls.get("termination") or "none (unsecured)")
            add("Backend Service", destination.get("name"))
            add("Route target port", port.get("targetPort"))
        elif kind == "Service":
            add("Service type", spec.get("type"))
            add("Cluster IP", spec.get("clusterIP"))
            add("Selector", spec.get("selector"))
            add("Ports", spec.get("ports"))
        elif kind == "Pod":
            status = projected.get("status") if isinstance(projected.get("status"), dict) else {}
            add("Phase", status.get("phase"))
            add("Pod IP", status.get("podIP"))
            add("Containers", [
                container.get("name")
                for container in spec.get("containers", [])
                if isinstance(container, dict) and container.get("name")
            ])
    view["facts"] = facts
    view["data_json"] = json.dumps(data, indent=2, sort_keys=True, default=str)
    return view


def _model_fact_cards(
    evidence: list[dict[str, object]],
    *,
    activity: list[dict[str, object]],
    max_cards: int = 8,
    total_byte_limit: int = 8_000,
) -> list[dict[str, object]]:
    """Normalize observations into small, resource-agnostic model evidence cards."""

    current_ids = {
        str(evidence_id)
        for entry in activity
        for evidence_id in (entry.get("evidence_ids") or [])
    }
    ordered = [item for item in evidence if str(item.get("id")) in current_ids]
    ordered.extend(
        reversed([item for item in evidence if str(item.get("id")) not in current_ids])
    )
    cards: list[dict[str, object]] = []
    used_bytes = 0
    for item in ordered:
        if len(cards) >= max_cards or not item.get("id"):
            break
        view = _adhoc_evidence_view(item)
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        card: dict[str, object] = {
            "id": str(item["id"]),
            "cluster": str(item.get("cluster_name") or item.get("cluster_id") or "cluster")[:253],
            "summary": redact_text(str(item.get("summary") or "Observed cluster evidence."))[:500],
            "facts": list(view.get("facts") or [])[:12],
        }
        if item.get("tool") == "pod_logs":
            card["log_excerpt"] = redact_text(str(data.get("tail") or ""))[-1_500:]
        else:
            objects = data.get("items") if isinstance(data.get("items"), list) else []
            projected = objects[:4] if objects else [data]
            material: list[dict[str, object]] = []
            for resource in projected:
                if not isinstance(resource, dict):
                    continue
                metadata = (
                    resource.get("metadata")
                    if isinstance(resource.get("metadata"), dict) else {}
                )
                detail: dict[str, object] = {
                    "kind": resource.get("kind") or data.get("kind"),
                    "namespace": metadata.get("namespace"),
                    "name": metadata.get("name"),
                }
                if isinstance(resource.get("spec"), dict):
                    detail["spec"] = _compact_provider_value(
                        resource["spec"], string_limit=300, list_limit=6
                    )
                if isinstance(resource.get("status"), dict):
                    detail["status"] = _compact_provider_value(
                        resource["status"], string_limit=300, list_limit=6
                    )
                if isinstance(resource.get("ports"), list):
                    detail["ports"] = _compact_provider_value(
                        resource["ports"], string_limit=200, list_limit=8
                    )
                if isinstance(resource.get("endpoints"), list):
                    detail["endpoints"] = _compact_provider_value(
                        resource["endpoints"], string_limit=200, list_limit=8
                    )
                material.append(detail)
            if material and any(
                any(value not in (None, "", [], {}) for value in detail.values())
                for detail in material
            ):
                card["material_details"] = material
            if isinstance(data.get("names"), list):
                card["names"] = [str(value)[:253] for value in data["names"][:20]]
        encoded = json.dumps(card, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > 3_000:
            card.pop("material_details", None)
            card["names"] = list(card.get("names") or [])[:8]
            card["facts"] = [
                {
                    "label": redact_text(str(fact.get("label") or "Fact"))[:100],
                    "value": redact_text(str(fact.get("value") or ""))[:300],
                }
                for fact in card.get("facts") or []
                if isinstance(fact, dict)
            ][:6]
            if "log_excerpt" in card:
                card["log_excerpt"] = str(card["log_excerpt"])[-750:]
            encoded = json.dumps(card, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > 3_000:
            card = {
                "id": card["id"],
                "cluster": card["cluster"],
                "summary": str(card["summary"])[:300],
                "facts": list(card.get("facts") or [])[:4],
            }
            encoded = json.dumps(card, sort_keys=True, default=str).encode("utf-8")
        if used_bytes + len(encoded) > total_byte_limit:
            continue
        cards.append(card)
        used_bytes += len(encoded)
    return cards


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


@dataclass
class _BoundedReadCollection:
    evidence: list[dict[str, object]]
    activity: list[dict[str, object]]
    limitations: list[str]
    scope_summary: str
    units_used: int = 0
    read_signatures: list[str] | None = None


ProgressReporter = Callable[[str, str], Awaitable[None]]


def _read_intent_signature(intent: ReadIntent) -> str:
    """Deduplicate exact reads even when equivalent Pod candidates have different IDs."""

    payload = intent.model_dump(exclude_none=True)
    if intent.tool == "pod_logs":
        payload.pop("candidate_id", None)
    return json.dumps(payload, sort_keys=True)


@dataclass(frozen=True)
class _GroundedReadCandidate:
    id: str
    capability: str
    target: str
    reason: str
    intent: ReadIntent
    supporting_evidence_ids: tuple[str, ...] = ()
    relation: str | None = None

    def planner_view(self) -> dict[str, object]:
        return {
            "id": self.id,
            "capability": self.capability,
            "target": self.target,
            "reason": self.reason,
            "relation": self.relation,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "investigation_units": _investigation_unit_cost(self.intent),
        }


_FAILURE_DIAGNOSTIC_PATTERN = re.compile(
    r"\b(?:internal server error|5xx|5\d\d|errors?|fail(?:ed|ing|ure)?|"
    r"crash(?:ed|ing|loop)?|timeout|unavailable)\b",
    re.IGNORECASE,
)


def _resource_query_terms(value: object) -> set[str]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(value or ""))
    terms: set[str] = set()
    for raw in re.findall(r"[a-z0-9]+", expanded.lower()):
        if len(raw) < 3:
            continue
        if raw.startswith("config"):
            terms.add("config")
        elif raw.startswith("auth"):
            terms.add("auth")
        else:
            terms.add(raw[:-1] if raw.endswith("s") and len(raw) > 4 else raw)
    return terms


def _catalog_relevance(question: str, entry: dict[str, object]) -> int:
    """Score only explicit lexical matches; unrelated catalog APIs stay out of context."""

    question_terms = _resource_query_terms(question)
    resource_terms = _resource_query_terms(
        f"{entry.get('resource') or ''} {entry.get('kind') or ''}"
    )
    overlap = question_terms.intersection(resource_terms)
    if not overlap:
        return 0
    normalized_question = re.sub(r"[^a-z0-9]", "", question.lower())
    normalized_kind = re.sub(r"[^a-z0-9]", "", str(entry.get("kind") or "").lower())
    exact_kind = bool(normalized_kind and normalized_kind in normalized_question)
    return len(overlap) * 10 + (20 if exact_kind else 0)


def _failure_logs_are_relevant(question: str) -> bool:
    return bool(_FAILURE_DIAGNOSTIC_PATTERN.search(question))


def _grounded_read_candidates(
    *,
    question: str,
    evidence: list[dict[str, object]],
    relationship_graph: dict[str, object],
    recovery_anchor_plan: ReadPlan | None,
    seen_intents: set[str],
    investigation_gaps: list[InvestigationGap] | None = None,
    catalog_entries: list[dict[str, object]] | None = None,
    limit: int = 12,
) -> list[_GroundedReadCandidate]:
    """Build compact non-executable choices backed only by trusted server state."""

    candidates: list[_GroundedReadCandidate] = []
    signatures: set[str] = set()
    gap_capabilities = {
        gap.capability for gap in (investigation_gaps or [])
        if gap.priority in {"high", "medium"}
    }
    failure_logs_relevant = _failure_logs_are_relevant(question)

    def add(
        intent: ReadIntent,
        *,
        capability: str,
        target: str,
        reason: str,
        evidence_ids: list[str] | tuple[str, ...] = (),
        relation: str | None = None,
    ) -> None:
        prepared = normalize_read_intent(intent)
        signature = _read_intent_signature(prepared)
        if (
            signature in seen_intents
            or signature in signatures
            or len(candidates) >= max(40, limit * 4)
        ):
            return
        signatures.add(signature)
        digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:20]
        candidates.append(_GroundedReadCandidate(
            id=f"read-{digest}", capability=capability,
            target=redact_text(target)[:500], reason=redact_text(reason)[:500],
            intent=prepared,
            supporting_evidence_ids=tuple(str(item)[:128] for item in evidence_ids),
            relation=relation,
        ))

    relation_capabilities = {
        "routes_to": "service_spec",
        "has_endpoints": "endpoints",
        "selects": "pod_spec",
        "targets": "pod_spec",
        "owned_by": "resource_read",
        "mounts_from": "resource_read",
        "configures_from": "resource_read",
    }
    for edge in relationship_graph.get("frontier") or []:
        if not isinstance(edge, dict) or not isinstance(edge.get("read_hint"), dict):
            continue
        try:
            intent = ReadIntent.model_validate(edge["read_hint"])
        except (TypeError, ValueError):
            continue
        relation = str(edge.get("relation") or "related_to")[:64]
        capability = relation_capabilities.get(relation, "resource_read")
        add(
            intent,
            capability=capability,
            target=str(edge.get("target") or "related resource"),
            reason=f"Observed evidence relation {relation} points to an unread target.",
            evidence_ids=[str(item) for item in edge.get("evidence_ids") or []],
            relation=relation,
        )

    for log_candidate in pod_log_candidates_from_evidence(evidence):
        if (
            log_candidate.investigation_priority not in {"high", "elevated"}
            and "pod_logs" not in gap_capabilities
            and not failure_logs_relevant
        ):
            continue
        add(
            ReadIntent(tool="pod_logs", candidate_id=log_candidate.id),
            capability="pod_logs",
            target=(
                f"Pod {log_candidate.namespace}/{log_candidate.pod}"
                + (f" container {log_candidate.container}" if log_candidate.container else "")
            ),
            reason=(
                ", ".join(log_candidate.trigger_reasons)
                or (
                    "The operator is diagnosing a failure and this exact workload container "
                    "may contain the corresponding error evidence."
                    if failure_logs_relevant else ""
                )
                or "A structured diagnostic gap makes this exact healthy-Pod log read relevant."
            ),
            evidence_ids=[log_candidate.evidence_id],
            relation="has_logs",
        )

    # A bounded list/search is discovery. Its server-normalized object references
    # authorize exact GET candidates on the next round without trusting model prose.
    for observation in evidence:
        if observation.get("tool") not in {"list_resources", "search_resources"}:
            continue
        data = observation.get("data")
        if not isinstance(data, dict):
            continue
        kind = str(data.get("kind") or "")
        if not kind or kind == "Secret":
            continue
        api_version = str(data.get("apiVersion") or "") or None
        resource = str(data.get("resource") or "") or None
        evidence_id = str(observation.get("id") or "")
        for ref in (data.get("objects") or [])[:8]:
            if not isinstance(ref, dict) or not ref.get("name"):
                continue
            namespace = ref.get("namespace")
            if not namespace and data.get("scope") not in {None, "cluster"}:
                namespace = data.get("scope")
            add(
                ReadIntent(
                    tool="get_resource", resource=resource, api_version=api_version,
                    kind=kind, namespace=str(namespace) if namespace else None,
                    name=str(ref["name"]),
                ),
                capability="resource_read",
                target=f"{kind}:{namespace or 'cluster'}/{ref['name']}",
                reason="A bounded discovery read returned this exact object coordinate.",
                evidence_ids=[evidence_id] if evidence_id else [],
                relation="discovery_result",
            )

    route_evidence_ids = [
        str(item.get("id"))
        for item in evidence
        if item.get("id") and isinstance(item.get("data"), dict)
        and (
            item["data"].get("kind") == "Route"
            or any(
                isinstance(candidate, dict) and candidate.get("kind") == "Route"
                for candidate in (item["data"].get("items") or [])
            )
        )
    ]
    if route_evidence_ids or "http_probe" in gap_capabilities:
        for match in re.finditer(r"https?://[^\s\"'<>]+", question, re.IGNORECASE):
            url = match.group(0).rstrip(".,;:!?)]}")
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                continue
            try:
                probe_intent = ReadIntent(tool="http_probe", url=url, method="GET")
            except ValueError:
                continue
            add(
                probe_intent,
                capability="http_probe",
                target=f"GET {url}",
                reason="Exact operator-supplied URL can directly test the observed Route behavior.",
                evidence_ids=route_evidence_ids,
                relation="probes",
            )

    if recovery_anchor_plan is not None:
        for intent in recovery_anchor_plan.intents:
            add(
                intent,
                capability="initial_discovery",
                target=_read_progress_message(intent),
                reason="Exact coordinate compiled from the operator request.",
                relation="operator_anchor",
            )

    # Keep a small query-relevant API frontier even when graph candidates exist.
    # This prevents a generic owner edge from hiding a configuration CRD or ConfigMap
    # that the operator explicitly asked about.
    ranked_catalog = sorted(
        (
            (_catalog_relevance(question, entry), entry)
            for entry in (catalog_entries or [])
            if isinstance(entry, dict)
        ),
        key=lambda item: (-item[0], str(item[1].get("resource") or "")),
    )
    selected_catalog = [entry for score, entry in ranked_catalog if score > 0][:4]
    if not selected_catalog and not candidates:
        selected_catalog = [entry for _score, entry in ranked_catalog[:6]]
    observed_namespaces = {
        str(node.get("namespace"))
        for node in relationship_graph.get("nodes") or []
        if isinstance(node, dict)
        and node.get("observed")
        and node.get("namespace") not in {None, "cluster"}
    }
    namespace_hint = next(iter(observed_namespaces)) if len(observed_namespaces) == 1 else None
    for entry in selected_catalog:
        if not isinstance(entry, dict):
            continue
        verbs = entry.get("verbs")
        if isinstance(verbs, list) and "list" not in verbs:
            continue
        resource = str(entry.get("resource") or "")
        kind = str(entry.get("kind") or "")
        if not resource or not kind:
            continue
        try:
            intent = ReadIntent(
                tool="list_resources",
                resource=resource,
                api_version=str(entry.get("apiVersion") or "") or None,
                kind=kind,
                namespace=(namespace_hint if entry.get("namespaced") else None),
                limit=20,
            )
        except ValueError:
            continue
        add(
            intent,
            capability="resource_read",
            target=(
                f"List a bounded sample of {kind} resources"
                + (f" in {namespace_hint}" if namespace_hint and entry.get("namespaced") else "")
            ),
            reason="The readable API catalog lexically matches the operator's current question.",
            relation="catalog_match",
        )

    protocol_proven = any(
        item.get("tool") == "http_probe"
        and isinstance(item.get("data"), dict)
        and item["data"].get("statusCode") is not None
        and (
            str(item["data"].get("logicalHost") or "").lower().startswith("http")
            or item["data"].get("tlsVerificationRequested") is False
            or isinstance(item["data"].get("tls"), dict)
        )
        for item in evidence
    )
    post_protocol_priority = {
        "pod_logs": 0,
        "pod_spec": 1,
        "service_spec": 2,
        "endpoints": 3,
        "resource_read": 4,
        "http_probe": 5,
    }
    candidates.sort(key=lambda item: (
        0 if item.capability in gap_capabilities else 1,
        0 if item.capability == "initial_discovery" and not evidence else 1,
        post_protocol_priority.get(item.capability, 10) if protocol_proven else 0,
        {
            "discovery_result": 0,
            "catalog_match": 1,
            "mounts_from": 2,
            "configures_from": 2,
            "owned_by": 3,
        }.get(item.relation or "", 4),
        item.capability,
        item.id,
    ))
    return candidates[:limit]


_MUTATING_RECOMMENDATION = re.compile(
    r"\b(?:apply|change|create|delete|edit|install|patch|replace|restart|rollout|rotate|scale|update)\b",
    re.IGNORECASE,
)


def _compile_suggested_followups(
    *,
    validated_answer: dict[str, object],
    question: str,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
    cluster_runtimes: list[dict[str, object]],
    remaining_units: int,
) -> tuple[list[str], list[dict[str, object]]]:
    """Compile recommendation prose into optional exact read-only action buttons."""

    recommendations = [
        redact_text(str(item))[:500]
        for item in validated_answer.get("recommended_next_checks") or []
        if str(item).strip()
    ]
    visible: list[str] = []
    actions: list[dict[str, object]] = []
    used_candidates: set[tuple[str, str]] = set()
    runtime_states: list[tuple[dict[str, object], dict[str, str]]] = []
    for runtime in cluster_runtimes:
        cluster = runtime["cluster"]
        cluster_id = str(cluster.id)
        cluster_evidence = [
            dict(item) for item in evidence
            if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == cluster_id
        ]
        cluster_activity = [
            dict(item) for item in activity
            if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == cluster_id
        ]
        ledger = _investigation_capability_ledger(
            evidence=cluster_evidence,
            activity=cluster_activity,
            remaining_units=remaining_units,
        )
        states = {
            str(item.get("capability")): str(item.get("state"))
            for item in ledger.get("checks") or []
            if isinstance(item, dict)
        }
        runtime_states.append((runtime, states))

    for recommendation in recommendations:
        capability = _recommendation_capability(recommendation)
        mutation = bool(_MUTATING_RECOMMENDATION.search(recommendation))
        recommendation_actions: list[dict[str, object]] = []
        collected_everywhere = bool(runtime_states) and capability is not None
        for runtime, states in runtime_states:
            state = states.get(capability or "")
            collected_everywhere = collected_everywhere and state == "collected"
            if (
                mutation
                or capability is None
                or remaining_units <= 0
                or (state is not None and state not in {"available_not_attempted", "requires_target"})
            ):
                continue
            cluster = runtime["cluster"]
            cluster_id = str(cluster.id)
            cluster_evidence = [
                dict(item) for item in evidence
                if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == cluster_id
            ]
            gap = InvestigationGap(
                question=recommendation,
                capability=capability,
                priority="medium",
            )
            candidates = _grounded_read_candidates(
                question=question,
                evidence=cluster_evidence,
                relationship_graph=derive_evidence_relationship_graph(cluster_evidence),
                recovery_anchor_plan=None,
                seen_intents=set(runtime.get("read_signatures") or []),
                investigation_gaps=[gap],
            )
            for candidate in candidates:
                if candidate.capability != capability:
                    continue
                key = (cluster_id, candidate.id)
                if key in used_candidates:
                    continue
                used_candidates.add(key)
                recommendation_actions.append({
                    "id": candidate.id,
                    "cluster_id": cluster_id,
                    "cluster_name": str(cluster.name),
                    "capability": capability,
                    "label": recommendation,
                    "target": candidate.target,
                    "supporting_evidence_ids": list(candidate.supporting_evidence_ids),
                })
                break
        if collected_everywhere:
            continue
        visible.append(recommendation)
        actions.extend(recommendation_actions[:1])
        if len(actions) >= 4:
            break
    return visible[:5], actions[:4]


def _compile_remaining_candidate_followups(
    *,
    question: str,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
    cluster_runtimes: list[dict[str, object]],
    remaining_units: int,
    limit: int = 3,
) -> tuple[list[str], list[dict[str, object]]]:
    """Expose remaining exact server candidates without asking the answer model for prose."""

    if remaining_units <= 0 or limit <= 0:
        return [], []
    labels = {
        "pod_logs": "Read logs for",
        "pod_spec": "Inspect",
        "service_spec": "Inspect",
        "endpoints": "Inspect",
        "http_probe": "Probe",
        "metrics": "Read metrics for",
        "resource_read": "Inspect",
        "initial_discovery": "Inspect",
    }
    visible: list[str] = []
    actions: list[dict[str, object]] = []
    used_ids: set[str] = set()
    for runtime in cluster_runtimes:
        cluster = runtime["cluster"]
        cluster_id = str(cluster.id)
        cluster_evidence = [
            dict(item) for item in evidence
            if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == cluster_id
        ]
        cluster_activity = [
            dict(item) for item in activity
            if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == cluster_id
        ]
        capability_states = {
            str(item.get("capability")): str(item.get("state"))
            for item in _investigation_capability_ledger(
                evidence=cluster_evidence,
                activity=cluster_activity,
                remaining_units=remaining_units,
            ).get("checks", [])
            if isinstance(item, dict)
        }
        candidates = _grounded_read_candidates(
            question=question,
            evidence=cluster_evidence,
            relationship_graph=derive_evidence_relationship_graph(cluster_evidence),
            recovery_anchor_plan=None,
            seen_intents=set(runtime.get("read_signatures") or []),
            investigation_gaps=None,
            limit=max(8, limit * 2),
        )
        for candidate in candidates:
            if capability_states.get(candidate.capability) == "collected":
                continue
            if candidate.id in used_ids:
                continue
            used_ids.add(candidate.id)
            prefix = labels.get(candidate.capability, "Inspect")
            label = f"{prefix} {candidate.target}"[:500]
            visible.append(label)
            actions.append({
                "id": candidate.id,
                "cluster_id": cluster_id,
                "cluster_name": str(cluster.name),
                "capability": candidate.capability,
                "label": label,
                "target": candidate.target,
                "supporting_evidence_ids": list(candidate.supporting_evidence_ids),
            })
            if len(actions) >= limit:
                return visible, actions
    return visible, actions


def _compile_grounded_candidate_plan(
    plan: ReadPlan,
    candidates: list[_GroundedReadCandidate],
) -> tuple[ReadPlan, list[str]]:
    """Compile model-selected opaque IDs; never derive coordinates from model prose."""

    if not plan.candidate_ids:
        # Model-authored object discovery and reads are allowed, but still pass through
        # normalization, API discovery, deny policy, scope/RBAC preflight, and budgets.
        return plan, []

    by_id = {candidate.id: candidate for candidate in candidates}
    unknown = [candidate_id for candidate_id in plan.candidate_ids if candidate_id not in by_id]
    if unknown:
        return plan.model_copy(update={"candidate_ids": [], "intents": []}), [
            "One or more selected read candidate IDs were not present in the supplied candidate list."
        ]
    intents = [by_id[candidate_id].intent for candidate_id in plan.candidate_ids]
    intents.extend(plan.intents)
    return plan.model_copy(update={"candidate_ids": [], "intents": intents}), []


def _read_progress_message(intent) -> str:
    if intent.tool == "discover_resources":
        return f"Looking for readable OpenShift APIs related to {intent.discovery_query}."
    if intent.tool == "http_probe":
        verification = " without certificate verification" if not intent.tls_verify else ""
        return f"Testing {intent.method} connectivity to {_display_probe_url(intent.url)}{verification}."
    if intent.tool == "query_metrics":
        target = (
            intent.namespace if intent.metric_scope == "namespace" else
            intent.name if intent.metric_scope == "node" else
            f"{intent.namespace}/{intent.name}"
        )
        return f"Reading {intent.metric} trend for {intent.metric_scope} {target}."
    resource = intent.kind or intent.resource or "cluster resource"
    scope = f" in {intent.namespace}" if intent.namespace else " across the cluster"
    if intent.tool == "pod_logs":
        container = f" container {intent.container}" if intent.container else ""
        return f"Checking logs for Pod {intent.namespace}/{intent.name}{container}."
    if intent.tool == "get_resource":
        return f"Inspecting {resource} {intent.namespace or 'cluster'}/{intent.name}."
    if intent.tool == "search_resources":
        return f"Searching {resource}{scope} by {intent.match_field}."
    if intent.tool == "watch_resources":
        target = f" {intent.namespace}/{intent.name}" if intent.name else scope
        return f"Watching {resource}{target} for up to {intent.watch_seconds} seconds."
    return f"Getting a list of {resource}{scope}."


def _investigation_unit_cost(intent: ReadIntent) -> int:
    """Weight slower or higher-volume evidence operations inside one bounded turn."""

    if intent.tool == "watch_resources":
        return 3
    if intent.tool in {"pod_logs", "http_probe", "query_metrics"}:
        return 2
    return 1


def _investigation_capability_ledger(
    *,
    evidence: list[dict[str, object]],
    activity: list[dict[str, object]],
    remaining_units: int,
) -> dict[str, object]:
    """Distinguish available-but-uncollected checks from blocked or completed checks."""

    attempts_by_tool: dict[str, list[dict[str, object]]] = {}
    for entry in activity:
        attempts_by_tool.setdefault(str(entry.get("tool") or "unknown"), []).append(entry)
    evidence_tools = {str(item.get("tool") or "") for item in evidence}
    observed_kinds: set[str] = set()
    for item in evidence:
        data = item.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("kind"):
            observed_kinds.add(str(data["kind"]))
        if isinstance(data.get("metadata"), dict) and data.get("kind"):
            observed_kinds.add(str(data["kind"]))
        for obj in data.get("items") or []:
            if isinstance(obj, dict) and obj.get("kind"):
                observed_kinds.add(str(obj["kind"]))

    log_candidates = pod_log_candidates_from_evidence(evidence)

    def tool_state(tool: str, *, prerequisite: str | None = None) -> dict[str, object]:
        attempts = attempts_by_tool.get(tool, [])
        succeeded = sum(1 for item in attempts if item.get("status") == "succeeded")
        failed = len(attempts) - succeeded
        if succeeded or tool in evidence_tools:
            state = "collected"
            reason = "At least one observation was collected."
        elif attempts:
            state = "attempted_failed"
            reason = "The check was attempted but did not produce a successful observation."
        elif remaining_units <= 0:
            state = "budget_exhausted"
            reason = "No investigation units remain."
        elif prerequisite:
            state = "requires_target"
            reason = prerequisite
        else:
            state = "available_not_attempted"
            reason = "The typed read is available but has not been attempted."
        return {
            "tool": tool,
            "state": state,
            "attempts": len(attempts),
            "succeeded": succeeded,
            "failed": failed,
            "reason": reason,
        }

    tools = [
        tool_state("discover_resources"),
        tool_state("get_resource"),
        tool_state("list_resources"),
        tool_state("search_resources"),
        tool_state("watch_resources"),
        tool_state(
            "pod_logs",
            prerequisite=(
                None if log_candidates else
                "Collect an exact Pod/container candidate before requesting logs."
            ),
        ),
        tool_state("http_probe"),
        tool_state("query_metrics"),
    ]

    def check_state(
        name: str,
        tool: str,
        collected: bool,
        prerequisite: str | None = None,
        target_patterns: tuple[str, ...] = (),
    ) -> dict[str, object]:
        relevant_attempts = [
            item for item in attempts_by_tool.get(tool, [])
            if not target_patterns or any(
                pattern in str(item.get("target") or "").lower()
                for pattern in target_patterns
            )
        ]
        if collected:
            state = "collected"
            reason = "Relevant evidence was collected."
        elif relevant_attempts:
            state = "attempted_failed"
            reason = "The targeted check was attempted but produced no relevant evidence."
        elif remaining_units <= 0:
            state = "budget_exhausted"
            reason = "No investigation units remain."
        elif prerequisite:
            state = "requires_target"
            reason = prerequisite
        else:
            state = "available_not_attempted"
            reason = "The typed read is available but has not been attempted."
        return {"capability": name, "tool": tool, "state": state, "reason": reason}

    checks = [
        check_state(
            "service_spec", "get_resource", "Service" in observed_kinds,
            target_patterns=(" service ", " services "),
        ),
        check_state(
            "endpoints", "list_resources",
            bool({"EndpointSlice", "Endpoints"}.intersection(observed_kinds)),
            target_patterns=("endpoint",),
        ),
        check_state(
            "pod_spec", "get_resource", "Pod" in observed_kinds,
            target_patterns=(" pod ", " pods "),
        ),
        check_state(
            "pod_logs", "pod_logs", "pod_logs" in evidence_tools,
            None if log_candidates else "Pod discovery is required before logs can be selected.",
        ),
        check_state("metrics", "query_metrics", "query_metrics" in evidence_tools),
        check_state("http_probe", "http_probe", "http_probe" in evidence_tools),
    ]
    return {
        "remaining_investigation_units": max(0, remaining_units),
        "tools": tools,
        "checks": checks,
        "language_rule": (
            "Say 'not collected' for available_not_attempted or requires_target. Reserve "
            "'unavailable' for an explicit denied, failed, unsupported, or budget-exhausted state."
        ),
    }


def _display_probe_url(value: str | None) -> str:
    parsed = urlsplit(value or "")
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "[REDACTED]" if parsed.query else "",
        "",
    ))


def _bind_pod_log_intent(
    intent: ReadIntent,
    candidates: list[PodLogCandidate],
) -> tuple[ReadIntent | None, str | None]:
    """Resolve a model-selected log candidate to exact server-observed coordinates."""

    if intent.tool != "pod_logs":
        return intent, None
    if not candidates:
        return None, (
            "Pod logs require an exact candidate from previously collected Pod evidence."
        )
    candidate = None
    if intent.candidate_id:
        candidate = next((item for item in candidates if item.id == intent.candidate_id), None)
        if candidate is None:
            return None, "The requested Pod log candidate ID was not present in collected evidence."
    else:
        matches = [
            item for item in candidates
            if item.namespace == intent.namespace
            and item.pod == intent.name
            and (intent.container is None or item.container == intent.container)
        ]
        if len(matches) == 1:
            candidate = matches[0]
        elif not matches:
            return None, "The requested Pod/container was not present in collected evidence."
        else:
            return None, "The discovered Pod has multiple containers; select an exact log candidate ID."
    return intent.model_copy(update={
        "candidate_id": candidate.id,
        "namespace": candidate.namespace,
        "name": candidate.pod,
        "container": candidate.container,
        "previous": bool(intent.previous and candidate.restart_count > 0),
    }), None


def _bind_plan_log_intents(
    plan: ReadPlan,
    candidates: list[PodLogCandidate],
    *,
    question: str,
    evidence: list[dict[str, object]],
) -> tuple[ReadPlan, list[str], list[ReadIntent]]:
    bound: list[ReadIntent] = []
    errors: list[str] = []
    rejected: list[ReadIntent] = []
    observed_names: set[str] = set()
    observed_scopes: dict[str, set[str]] = {}

    def add_target(name: object, namespace: object = None) -> None:
        if not name:
            return
        bounded_name = str(name).lower()
        observed_names.add(bounded_name)
        if namespace:
            observed_scopes.setdefault(bounded_name, set()).add(str(namespace))

    def add_object_targets(value: object, inherited_namespace: object = None) -> None:
        """Collect explicit Kubernetes references without trusting arbitrary strings as targets."""

        if not isinstance(value, dict):
            return
        metadata = value.get("metadata")
        namespace = inherited_namespace
        if isinstance(metadata, dict):
            namespace = metadata.get("namespace") or metadata.get("namespace_") or namespace
            add_target(metadata.get("name"), namespace)
            owners = metadata.get("ownerReferences") or metadata.get("owner_references")
            if isinstance(owners, list):
                for owner in owners:
                    if isinstance(owner, dict):
                        add_target(owner.get("name"), namespace)

        mounts = value.get("podpilotMounts")
        if isinstance(mounts, list):
            for mount in mounts:
                if isinstance(mount, dict):
                    add_target(mount.get("sourceName"), namespace)

        for target_key in ("targetRef", "target_ref"):
            target_ref = value.get(target_key)
            if isinstance(target_ref, dict):
                add_target(
                    target_ref.get("name"),
                    target_ref.get("namespace") or namespace,
                )
        pod_targets = value.get("podTargets") or value.get("pod_targets")
        if isinstance(pod_targets, list):
            for target in pod_targets:
                if isinstance(target, dict):
                    add_target(
                        target.get("name") or target.get("pod"),
                        target.get("namespace") or namespace,
                    )
                else:
                    add_target(target, namespace)
        endpoints = value.get("endpoints")
        if isinstance(endpoints, list):
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                add_object_targets(endpoint, namespace)
                addresses = endpoint.get("addresses")
                if isinstance(addresses, list):
                    for address in addresses:
                        if isinstance(address, dict):
                            add_object_targets(address, namespace)

        spec = value.get("spec")
        if not isinstance(spec, dict):
            return
        volumes = spec.get("volumes")
        if isinstance(volumes, list):
            for volume in volumes:
                if not isinstance(volume, dict):
                    continue
                for source_key in (
                    "configMap", "config_map", "persistentVolumeClaim",
                    "persistent_volume_claim", "secret",
                ):
                    source = volume.get(source_key)
                    if not isinstance(source, dict):
                        continue
                    add_target(
                        source.get("name")
                        or source.get("secretName")
                        or source.get("secret_name")
                        or source.get("claimName")
                        or source.get("claim_name"),
                        namespace,
                    )
        template = spec.get("template")
        if isinstance(template, dict):
            add_object_targets(template, namespace)

    for candidate in candidates:
        add_target(candidate.pod, candidate.namespace)
    for observation in evidence:
        data = observation.get("data")
        if not isinstance(data, dict):
            continue
        names = data.get("names")
        if isinstance(names, list):
            observed_names.update(str(name).lower() for name in names if name)
        refs = data.get("objects")
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict) or not ref.get("name") or not ref.get("namespace"):
                    continue
                observed_scopes.setdefault(str(ref["name"]).lower(), set()).add(
                    str(ref["namespace"])
                )
        add_object_targets(data)
        items = data.get("items")
        if isinstance(items, list):
            for item in items:
                add_object_targets(item)
                item_kind = (
                    str(item.get("kind") or data.get("kind") or "")
                    if isinstance(item, dict) else ""
                )
                item_spec = item.get("spec") if isinstance(item, dict) else None
                if item_kind == "Route" and isinstance(item_spec, dict):
                    destination = item_spec.get("to")
                    if isinstance(destination, dict) and destination.get("name"):
                        add_target(destination["name"], (
                            item.get("metadata", {}).get("namespace")
                            if isinstance(item.get("metadata"), dict) else None
                        ))
                    alternate_backends = item_spec.get("alternateBackends")
                    if isinstance(alternate_backends, list):
                        for backend in alternate_backends:
                            if isinstance(backend, dict):
                                add_target(backend.get("name"), (
                                    item.get("metadata", {}).get("namespace")
                                    if isinstance(item.get("metadata"), dict) else None
                                ))
    for intent in plan.intents:
        normalized = normalize_read_intent(intent)
        resolved, error = _bind_pod_log_intent(normalized, candidates)
        if (
            error is None
            and resolved is not None
            and resolved.tool in {"get_resource", "watch_resources"}
            and resolved.name
            and not resolved.namespace
        ):
            namespaces = observed_scopes.get(resolved.name.lower(), set())
            if len(namespaces) == 1:
                resolved = resolved.model_copy(update={"namespace": next(iter(namespaces))})
        if (
            error is None
            and resolved is not None
            and resolved.tool in {"get_resource", "watch_resources"}
            and resolved.name
            and resolved.name.lower() not in observed_names
            and not re.search(
                rf"(?<![-A-Za-z0-9_.]){re.escape(resolved.name)}(?![-A-Za-z0-9_.])",
                question,
                re.IGNORECASE,
            )
        ):
            error = (
                "The named resource target was neither supplied by the operator nor present "
                "in collected evidence; discover it with a bounded list first."
            )
        if error:
            errors.append(error)
            rejected.append(normalized)
        elif resolved is not None:
            bound.append(resolved)
    if errors:
        return plan, list(dict.fromkeys(errors)), rejected
    return plan.model_copy(update={"intents": bound}), [], []


def _fallback_pod_log_plan(
    *,
    question: str,
    candidates: list[PodLogCandidate],
    rejected: list[ReadIntent],
    limit: int,
) -> ReadPlan | None:
    if (
        limit <= 0
        or not candidates
        or (not rejected and not re.search(r"\blogs?\b", question, re.IGNORECASE))
    ):
        return None
    normalized_question = re.sub(r"[^a-z0-9]", "", question.lower())
    hints = [normalized_question]
    hints.extend(
        re.sub(r"[^a-z0-9]", "", str(value).lower())
        for intent in rejected
        for value in (intent.name, intent.container)
        if value
    )

    def relevance(candidate: PodLogCandidate) -> int:
        pod = re.sub(r"[^a-z0-9]", "", candidate.pod.lower())
        container = re.sub(r"[^a-z0-9]", "", (candidate.container or "").lower())
        return max((
            100 if container and container in hint else
            80 if pod and pod in hint else
            60 if container and hint and hint in container else
            0
            for hint in hints
        ), default=0)

    relevant = [candidate for candidate in candidates if relevance(candidate) > 0]
    pool = relevant or candidates
    selected = sorted(pool, key=lambda candidate: (
        -relevance(candidate), -candidate.restart_count,
        candidate.pod, candidate.container or "",
    ))[: min(3, limit)]
    previous_requested = bool(re.search(
        r"\b(?:previous|restart(?:ed|s|ing)?|crash(?:ed|es|ing)?|terminated)\b",
        question,
        re.IGNORECASE,
    ))
    return ReadPlan(
        goal_type="logs",
        decision="collect",
        scope_summary="Collect bounded logs from exact Pods discovered in cluster evidence.",
        intents=[ReadIntent(
            tool="pod_logs",
            candidate_id=item.id,
            previous=bool(previous_requested and item.restart_count > 0),
        ) for item in selected],
    )


async def _classify_ad_hoc_inquiry(
    *,
    model_provider: ModelProvider,
    profile: ModelProfileConfig,
    api_key: str,
    question: str,
    conversation: list[dict[str, str]],
    cluster_names: list[str],
) -> InquirySemantics | None:
    """Ask the model for coarse semantics once; deterministic routing is the fallback."""

    classify = getattr(model_provider, "classify_ad_hoc", None)
    if not callable(classify):
        return None
    context = {
        "question": redact_text(question)[:1000],
        "recent_context": [
            {
                "role": str(item.get("role") or "")[:16],
                "content": redact_text(str(item.get("content") or ""))[:500],
            }
            for item in conversation[-2:]
        ],
        "selected_clusters": [str(name)[:120] for name in cluster_names[:10]],
    }
    try:
        return await run_in_threadpool(classify, profile, api_key, context)
    except ModelProviderError as exc:
        LOGGER.warning("podpilot.adhoc.classification_failed error=%s", str(exc))
        return None


async def _collect_bounded_cluster_reads(
    *,
    model_provider: ModelProvider,
    cluster_reader: ReadOnlyExplorer,
    profile: ModelProfileConfig,
    api_key: str,
    settings: Settings,
    actor: str,
    workflow_id: str,
    question: str,
    conversation: list[dict[str, str]],
    existing_evidence: list[dict[str, object]],
    earlier_context_summary: str = "",
    knowledge: list[dict[str, object]] | None = None,
    investigation_gaps: list[InvestigationGap] | None = None,
    existing_read_signatures: list[str] | None = None,
    requested_candidate_id: str | None = None,
    alert_name: str | None = None,
    alert_labels: dict[str, object] | None = None,
    progress: ProgressReporter | None = None,
    inquiry: InquirySemantics | None = None,
) -> _BoundedReadCollection:
    evidence = list(existing_evidence)
    activity: list[dict[str, object]] = []
    limitations: list[str] = []
    seen_intents: set[str] = set(existing_read_signatures or [])
    units_used = 0
    automatic_tls_retries = 0
    pinned_goal: str | None = (
        "diagnose" if investigation_gaps else inquiry.planner_goal if inquiry else None
    )
    scope_summary = "Bounded read-only cluster investigation."
    known_plan = plan_known_read(
        question,
        inventory_limit=settings.adhoc_inventory_max_objects,
        alert_name=alert_name,
        alert_labels=alert_labels,
    )
    # Keep deterministic compilation only for terminal, unambiguous inventory or
    # metric requests. Troubleshooting and object traversal remain model-directed.
    deterministic_plan = (
        (
            known_plan[0],
            False
            if inquiry is not None
            and inquiry.mode == "inventory"
            and inquiry.needs_object_details
            else known_plan[1],
        )
        if known_plan is not None
        and known_plan[1]
        and (
            inquiry is None
            or inquiry.mode == "inventory"
            or known_plan[0].goal_type != "inventory"
        )
        else None
    )
    # A single non-terminal read compiled from an exact operator coordinate (for
    # example, searching Route.spec.host for a supplied URL) is retained only as
    # a recovery anchor. It is never the initial troubleshooting plan and it does
    # not prescribe any traversal after the first observation.
    recovery_anchor_plan = (
        known_plan[0]
        if known_plan is not None
        and not known_plan[1]
        and len(known_plan[0].intents) == 1
        else None
    )
    catalog_entries: list[dict[str, object]] = []
    catalog_available = False
    catalog_reader = getattr(cluster_reader, "resource_catalog", None)
    if callable(catalog_reader):
        if progress:
            await progress("discovering", "Discovering available cluster resources.")
        try:
            catalog_entries = await run_in_threadpool(
                catalog_reader, query=question, limit=120
            )
            catalog_available = True
        except ReadOnlyExplorerError as exc:
            LOGGER.warning(
                "podpilot.resource_catalog.unavailable actor=%s workflow_id=%s error=%s",
                actor,
                workflow_id,
                str(exc),
            )

    # Once live discovery resolves an explicit inventory question, normal code owns
    # the same bounded LIST on every selected cluster. This avoids asking the model
    # to independently rediscover identical syntax and semantics per cluster. An
    # available catalog with no matching readable type is itself useful negative
    # evidence; do not replace it with an unrelated catalog traversal.
    inventory_request = (
        inquiry.mode == "inventory"
        if inquiry is not None
        else not _question_requires_object_details(question)
    )
    if deterministic_plan is None and inventory_request:
        catalog_question = (
            f"list {inquiry.resource_query}"
            if inquiry is not None and inquiry.resource_query
            else question
        )
        catalog_plan = plan_catalog_read(
            catalog_question,
            catalog_entries,
            inventory_limit=settings.adhoc_inventory_max_objects,
        )
        if catalog_plan is not None and catalog_plan[1]:
            deterministic_plan = (
                catalog_plan[0],
                not (
                    inquiry is not None
                    and inquiry.mode == "inventory"
                    and inquiry.needs_object_details
                ),
            )
        elif catalog_available:
            evidence_id = f"cluster-discovery-{uuid4()}"
            collected_at = datetime.now(timezone.utc)
            evidence.append({
                "id": evidence_id,
                "tool": "discover_resources",
                "summary": (
                    "No readable API resource type matched the operator's inventory question."
                ),
                "source": "kubernetes:api-discovery",
                "collected_at": collected_at,
                "data": {
                    "query": redact_text(question)[:253],
                    "count": 0,
                    "inventoryMatch": "none",
                    "policy": (
                        "live API discovery with sensitive resource types excluded"
                    ),
                },
            })
            activity.append({
                "round": 0,
                "tool": "discover_resources",
                "status": "succeeded",
                "target": "readable API catalog inventory match",
                "observations": 1,
                "evidence_ids": [evidence_id],
                "investigation_units": 0,
            })
            return _BoundedReadCollection(
                evidence=evidence[-settings.adhoc_max_evidence :],
                activity=activity,
                limitations=limitations,
                scope_summary=(
                    "The readable API catalog had no resource type matching this inventory question."
                ),
                units_used=units_used,
                read_signatures=sorted(seen_intents),
            )
    def plan_requires_repair(plan: ReadPlan, *, round_number: int) -> bool:
        known_evidence_ids = {str(item.get("id")) for item in evidence}
        return plan_needs_evidence_repair(
            plan,
            known_evidence_ids=known_evidence_ids,
            has_completed_reads=bool(activity),
        )

    def plan_needs_sufficiency_review(plan: ReadPlan) -> bool:
        """Challenge one early diagnostic stop without prescribing its next read."""

        known_evidence_ids = {str(item.get("id")) for item in evidence}
        has_valid_support = bool(
            known_evidence_ids.intersection(plan.supporting_evidence_ids)
        )
        has_successful_read = any(
            item.get("status") == "succeeded" for item in activity
        ) or bool(investigation_gaps and evidence)
        return (
            plan.goal_type in {"diagnose", "logs", "explain"}
            and plan.decision == "answer_from_evidence"
            and has_valid_support
            and has_successful_read
        )

    def planner_context(
        *,
        round_number: int,
        remaining_reads: int,
        read_candidates: list[_GroundedReadCandidate],
        feedback: dict[str, object] | None = None,
    ) -> dict[str, object]:
        relationship_graph = derive_evidence_relationship_graph(evidence)
        capability_ledger = _investigation_capability_ledger(
            evidence=evidence,
            activity=activity,
            remaining_units=remaining_reads,
        )
        compact_observations, _metadata = _compact_answer_evidence(
            evidence, activity=activity
        )
        compact_graph = {
            "nodes": [
                {
                    key: node.get(key)
                    for key in ("id", "kind", "namespace", "name", "selector", "observed")
                }
                for node in (relationship_graph.get("nodes") or [])[-60:]
                if isinstance(node, dict)
            ],
            "edges": [
                {
                    key: edge.get(key)
                    for key in (
                        "source", "target", "relation", "target_observed", "evidence_ids"
                    )
                }
                for edge in (relationship_graph.get("edges") or [])[-80:]
                if isinstance(edge, dict)
            ],
            "truncated": bool(relationship_graph.get("truncated")),
        }
        candidate_mode = True
        context: dict[str, object] = {
            "cluster": settings.cluster_name,
            "question": question,
            "inquiry": inquiry.model_dump() if inquiry else None,
            "conversation": [
                {
                    "role": str(item.get("role") or "")[:16],
                    "content": redact_text(str(item.get("content") or ""))[:1000],
                }
                for item in conversation[-4:]
            ],
            "earlier_context_summary": redact_text(earlier_context_summary)[-1500:],
            "alert_scope": (
                {"alert_name": alert_name, "labels": alert_labels or {}}
                if alert_name else None
            ),
            "observations": compact_observations[-16:],
            "facts": _model_fact_cards(evidence, activity=activity),
            "findings": _compact_answer_findings(derive_adhoc_findings(evidence))[-8:],
            "relationship_graph": compact_graph,
            "capability_ledger": {
                "remaining_investigation_units": capability_ledger.get(
                    "remaining_investigation_units"
                ),
                "checks": capability_ledger.get("checks") or [],
            },
            "pinned_goal_type": pinned_goal,
            "investigation_gaps": [
                gap.model_dump() for gap in (investigation_gaps or [])
            ],
            "read_candidates": [candidate.planner_view() for candidate in read_candidates],
            "resource_catalog": catalog_entries[:12],
            "completed_reads": [
                {
                    key: item.get(key)
                    for key in ("round", "tool", "status", "target", "evidence_ids")
                }
                for item in activity[-12:]
            ],
            "investigation_round": round_number,
            "tool_policy": {
                "mode": "candidate_selection",
                "direct_intents_allowed": True,
                "direct_intent_tools": [
                    "discover_resources", "get_resource", "list_resources", "search_resources",
                ],
                "remaining_reads": remaining_reads,
                "remaining_investigation_units": remaining_reads,
                "logs_and_configmaps_allowed": True,
                "secrets_and_mutations_allowed": False,
                "pod_log_candidates": [
                    candidate.model_dump()
                    for candidate in pod_log_candidates_from_evidence(evidence)[:12]
                ],
            },
        }
        if feedback:
            context["planner_feedback"] = feedback
        return context

    for round_number in range(1, settings.adhoc_max_rounds + 1):
        remaining_reads = settings.adhoc_max_reads_per_turn - units_used
        if remaining_reads <= 0:
            break
        regular_unit_ceiling = max(
            1,
            settings.adhoc_max_reads_per_turn - settings.adhoc_followup_reserve_units,
        )
        if units_used >= regular_unit_ceiling:
            break
        terminal_plan = False
        if round_number == 1 and requested_candidate_id:
            requested_candidates = _grounded_read_candidates(
                question=question,
                evidence=evidence,
                relationship_graph=derive_evidence_relationship_graph(evidence),
                recovery_anchor_plan=None,
                seen_intents=seen_intents,
                investigation_gaps=investigation_gaps,
                catalog_entries=catalog_entries,
            )
            requested_candidate = next((
                candidate for candidate in requested_candidates
                if candidate.id == requested_candidate_id
            ), None)
            if requested_candidate is None:
                limitations.append(
                    "The selected suggested check no longer maps to an exact unread target. "
                    "PodPilot did not substitute a different action."
                )
                break
            plan = ReadPlan(
                goal_type="diagnose",
                scope_summary="Run the operator-selected grounded read-only follow-up check.",
                intents=[requested_candidate.intent],
            )
            # A user-selected suggestion is one exact broker-validated read. Do
            # not re-enter open-ended planning after it completes.
            terminal_plan = True
            if progress:
                await progress("planning", "Validated the selected read-only follow-up check.")
        elif round_number == 1 and deterministic_plan:
            plan, terminal_plan = deterministic_plan
        else:
            plan = None
            planner_error: ModelProviderError | None = None
            feedback: dict[str, object] | None = None
            target_errors: list[str] = []
            rejected_log_intents: list[ReadIntent] = []
            no_progress_plan = False
            had_actionable_no_read_plan = False
            read_candidates: list[_GroundedReadCandidate] = []
            candidate_errors: list[str] = []
            binding_errors: list[str] = []
            candidate_stop_requires_repair = False
            actionable_gap_candidates: list[_GroundedReadCandidate] = []
            diagnostic_log_candidates: list[_GroundedReadCandidate] = []
            for planning_attempt in range(1, 3):
                relationship_graph = derive_evidence_relationship_graph(evidence)
                read_candidates = _grounded_read_candidates(
                    question=question,
                    evidence=evidence,
                    relationship_graph=relationship_graph,
                    recovery_anchor_plan=recovery_anchor_plan,
                    seen_intents=seen_intents,
                    investigation_gaps=investigation_gaps,
                    catalog_entries=catalog_entries,
                )
                gap_capabilities = {
                    gap.capability for gap in (investigation_gaps or [])
                    if gap.priority in {"high", "medium"}
                }
                actionable_gap_candidates = [
                    candidate for candidate in read_candidates
                    if candidate.capability in gap_capabilities
                    or "resource_read" in gap_capabilities
                    or "other" in gap_capabilities
                ]
                diagnostic_log_candidates = [
                    candidate for candidate in read_candidates
                    if candidate.capability == "pod_logs"
                    and _failure_logs_are_relevant(question)
                ]
                if progress:
                    await progress("planning", "Planning safe read-only checks.")
                try:
                    plan = await run_in_threadpool(
                        model_provider.plan_ad_hoc,
                        profile,
                        api_key,
                        planner_context(
                            round_number=round_number,
                            remaining_reads=remaining_reads,
                            read_candidates=read_candidates,
                            feedback=feedback,
                        ),
                    )
                    if (
                        plan.decision == "answer_from_evidence"
                        and not plan.supporting_evidence_ids
                        and evidence
                    ):
                        plan = plan.model_copy(update={
                            "supporting_evidence_ids": [
                                str(item.get("id"))
                                for item in evidence[-12:]
                                if item.get("id")
                            ]
                        })
                except ModelProviderError as exc:
                    planner_error = exc
                    break
                if pinned_goal is None:
                    pinned_goal = plan.goal_type
                elif plan.goal_type != pinned_goal:
                    LOGGER.info(
                        "podpilot.adhoc.goal_pinned actor=%s workflow_id=%s proposed=%s pinned=%s",
                        actor,
                        workflow_id,
                        plan.goal_type,
                        pinned_goal,
                    )
                    plan = plan.model_copy(update={"goal_type": pinned_goal})
                plan, candidate_errors = _compile_grounded_candidate_plan(
                    plan, read_candidates
                )
                log_candidates = pod_log_candidates_from_evidence(evidence)
                bound_plan, binding_errors, rejected = _bind_plan_log_intents(
                    plan, log_candidates,
                    question=question,
                    evidence=evidence,
                )
                target_errors = [*candidate_errors, *binding_errors]
                rejected_log_intents.extend(rejected)
                prepared_signatures: list[str] = []
                for proposed_intent in bound_plan.intents:
                    prepared = normalize_read_intent(proposed_intent)
                    if (
                        prepared.tool == "list_resources"
                        and prepared.limit == ReadIntent.model_fields["limit"].default
                    ):
                        prepared = prepared.model_copy(
                            update={"limit": settings.adhoc_inventory_max_objects}
                        )
                    prepared_signatures.append(_read_intent_signature(prepared))
                novel_intents = sum(
                    1 for signature in prepared_signatures if signature not in seen_intents
                )
                no_progress_plan = bool(bound_plan.intents) and novel_intents == 0
                candidate_stop_requires_repair = bool(
                    (actionable_gap_candidates or diagnostic_log_candidates)
                    and bound_plan.decision == "answer_from_evidence"
                ) or bool(getattr(bound_plan, "_selection_incomplete", False))
                evidence_repair_needed = plan_requires_repair(
                    plan, round_number=round_number
                ) or candidate_stop_requires_repair
                had_actionable_no_read_plan = (
                    had_actionable_no_read_plan or evidence_repair_needed
                )
                sufficiency_review_needed = (
                    planning_attempt == 1
                    and not evidence_repair_needed
                    and not target_errors
                    and plan_needs_sufficiency_review(plan)
                )
                if (
                    not evidence_repair_needed
                    and not sufficiency_review_needed
                    and not no_progress_plan
                    and not target_errors
                ):
                    plan = bound_plan
                    LOGGER.info(
                        "podpilot.adhoc.plan_decision actor=%s workflow_id=%s round=%s "
                        "attempt=%s goal=%s decision=%s intents=%s novel=%s",
                        actor, workflow_id, round_number, planning_attempt,
                        plan.goal_type, plan.decision, len(plan.intents), novel_intents,
                    )
                    break
                repair_reason = (
                    "candidate_selection" if candidate_errors else
                    "ungrounded_target" if target_errors else
                    "unsupported_answer" if evidence_repair_needed else
                    "no_progress" if no_progress_plan else
                    "evidence_sufficiency_review"
                )
                LOGGER.warning(
                    "podpilot.adhoc.plan_repair actor=%s workflow_id=%s round=%s attempt=%s "
                    "goal=%s decision=%s reason=%s",
                    actor,
                    workflow_id,
                    round_number,
                    planning_attempt,
                    plan.goal_type,
                    plan.decision,
                    repair_reason,
                )
                feedback = ({
                    "code": "select_grounded_candidate",
                    "message": (
                        "Grounded read candidates are available. Return one or more exact IDs from "
                        "read_candidates in candidate_ids and leave intents empty. Candidate text is "
                        "descriptive only; the server compiles the selected IDs."
                    ),
                    "errors": candidate_errors,
                } if candidate_errors else {
                    "code": "model_target_not_grounded",
                    "message": (
                        "One or more named targets were not grounded in the operator question or "
                        "collected evidence. Discover names first. Pod logs must select candidate_id "
                        "values from tool_policy.pod_log_candidates; never construct names or use "
                        "placeholders for results that do not exist yet."
                    ),
                    "errors": target_errors,
                } if target_errors else {
                    "code": "actionable_goal_requires_evidence",
                    "message": (
                        "The operational question still has an actionable grounded read candidate. "
                        "Select one or more exact IDs from read_candidates in candidate_ids and leave "
                        "intents empty."
                        if read_candidates else
                        "The operational question has no valid supporting evidence. Use the compact "
                        "resource catalog to return one safe discovery intent. Only request "
                        "clarification if no catalog target can answer the question."
                    ),
                } if evidence_repair_needed else {
                    "code": "no_progress",
                    "message": (
                        "Every proposed intent repeats a read already completed in this turn. "
                        "Use the supplied relationship_graph frontier, capability_ledger, findings, "
                        "and investigation_gaps to choose a novel typed read that materially advances "
                        "the pinned goal. If no novel allowed read would improve the answer, return "
                        "answer_from_evidence with exact supporting IDs and a stop reason rather than "
                        "repeating an intent."
                    ),
                    "duplicate_intent_count": len(prepared_signatures),
                } if no_progress_plan else {
                    "code": "review_evidence_sufficiency",
                    "message": (
                        "Before ending this diagnostic investigation, review the supplied "
                        "observations, findings, explicit object relationships, and remaining "
                        "typed read budget. If one allowed read can materially verify an "
                        "uninspected next hop, distinguish a live hypothesis, or resolve a "
                        "limitation you would otherwise recommend as a next check, return "
                        "decision=collect with that typed intent now. Do not merely defer an "
                        "available read to the final answer. If no available read would "
                        "materially improve the answer, repeat decision=answer_from_evidence "
                        "with exact supporting_evidence_ids."
                    ),
                })
            needs_fallback = plan is None or plan_requires_repair(
                plan, round_number=round_number
            ) or candidate_stop_requires_repair or bool(target_errors)
            log_fallback = _fallback_pod_log_plan(
                question=question,
                candidates=pod_log_candidates_from_evidence(evidence),
                rejected=rejected_log_intents,
                limit=remaining_reads,
            ) if target_errors else None
            if (
                needs_fallback
                and investigation_gaps
                and actionable_gap_candidates
                and planner_error is None
                and not binding_errors
            ):
                selected_candidate = actionable_gap_candidates[0]
                plan = ReadPlan(
                    goal_type=pinned_goal or "diagnose",
                    scope_summary=(
                        "Collect the highest-priority grounded read candidate for an unresolved "
                        "structured evidence gap."
                    ),
                    intents=[selected_candidate.intent],
                )
                target_errors = []
                candidate_errors = []
                limitations.append(
                    "The model twice stopped despite an actionable structured evidence gap; "
                    "PodPilot selected the highest-priority grounded read candidate identified "
                    "from that gap and current evidence."
                )
                LOGGER.warning(
                    "podpilot.adhoc.gap_candidate_recovery actor=%s workflow_id=%s "
                    "candidate_id=%s capability=%s",
                    actor, workflow_id, selected_candidate.id, selected_candidate.capability,
                )
            elif (
                needs_fallback
                and diagnostic_log_candidates
                and planner_error is None
                and not binding_errors
            ):
                selected_candidate = diagnostic_log_candidates[0]
                plan = ReadPlan(
                    goal_type=pinned_goal or "diagnose",
                    scope_summary=(
                        "Collect one exact workload log after the model twice stopped during "
                        "an operator-requested failure investigation."
                    ),
                    intents=[selected_candidate.intent],
                )
                target_errors = []
                candidate_errors = []
                limitations.append(
                    "The model twice stopped while an exact workload log remained available for "
                    "the reported failure; PodPilot collected that bounded read-only log evidence."
                )
                LOGGER.warning(
                    "podpilot.adhoc.diagnostic_log_candidate_recovery actor=%s workflow_id=%s "
                    "candidate_id=%s reason=failure_question",
                    actor, workflow_id, selected_candidate.id,
                )
            elif (
                needs_fallback
                and plan is not None
                and getattr(plan, "_selection_incomplete", False)
                and read_candidates
                and not target_errors
            ):
                selected_candidate = read_candidates[0]
                plan = ReadPlan(
                    goal_type=pinned_goal or "diagnose",
                    scope_summary=(
                        "Continue the model-requested investigation with the highest-priority "
                        "supplied evidence action after its empty selection."
                    ),
                    intents=[selected_candidate.intent],
                )
                candidate_errors = []
                limitations.append(
                    "The model requested more investigation but twice omitted an action ID; "
                    "PodPilot used the highest-priority supplied read-only evidence action."
                )
                LOGGER.warning(
                    "podpilot.adhoc.action_candidate_recovery actor=%s workflow_id=%s "
                    "candidate_id=%s capability=%s reason=empty_selection",
                    actor, workflow_id, selected_candidate.id, selected_candidate.capability,
                )
            elif needs_fallback and log_fallback is not None:
                plan = log_fallback
                target_errors = []
                limitations.append(
                    "PodPilot rejected model-authored log targets that were not present in collected "
                    "evidence and used exact discovered Pod/container targets instead."
                )
                if progress:
                    await progress(
                        "planning",
                        f"Using {len(plan.intents)} exact Pod/container target"
                        f"{'s' if len(plan.intents) != 1 else ''} from collected evidence.",
                    )
                LOGGER.info(
                    "podpilot.adhoc.log_target_fallback actor=%s workflow_id=%s candidates=%s",
                    actor,
                    workflow_id,
                    len(plan.intents),
                )
            elif (
                needs_fallback
                and not target_errors
                and not activity
                and recovery_anchor_plan is not None
                and (planner_error is None or had_actionable_no_read_plan)
            ):
                plan = recovery_anchor_plan
                limitations.append(
                    (
                        "The model planner's correction was not schema-valid after it first stopped "
                        "without evidence; PodPilot used one read grounded directly in the operator's "
                        "request, then returned diagnostic direction to the model."
                        if planner_error is not None else
                        "The model planner twice stopped before collecting evidence; PodPilot used one "
                        "read grounded directly in the operator's request, then returned diagnostic "
                        "direction to the model."
                    )
                )
                if progress:
                    await progress(
                        "planning",
                        "Using the exact target in your question as the first discovery anchor.",
                    )
                LOGGER.warning(
                    "podpilot.adhoc.operator_anchor_recovery actor=%s workflow_id=%s tool=%s "
                    "reason=%s",
                    actor,
                    workflow_id,
                    plan.intents[0].tool,
                    "invalid_correction" if planner_error is not None else "repeated_stop",
                )
            elif needs_fallback and planner_error is not None:
                LOGGER.warning(
                    "podpilot.adhoc.plan_failed actor=%s workflow_id=%s round=%s error=%s",
                    actor,
                    workflow_id,
                    round_number,
                    str(planner_error),
                )
                limitations.append(
                    f"ReadPlan round {round_number} failed; PodPilot continued to the answer phase "
                    f"with the evidence available. {planner_error}"
                )
                break
            elif needs_fallback:
                limitations.append(
                    "The model planner did not select a safe evidence read for its actionable goal."
                )
                break
            assert plan is not None
        if progress and plan.working_hypothesis:
            await progress(
                "hypothesis",
                f"Working hypothesis: {plan.working_hypothesis}",
            )
        if progress and plan.next_step_summary:
            await progress("next_check", plan.next_step_summary)
        scope_summary = plan.scope_summary
        new_intents = []
        current_log_candidates = pod_log_candidates_from_evidence(evidence)
        for proposed_intent in plan.intents[:remaining_reads]:
            intent = normalize_read_intent(proposed_intent)
            if (
                intent.tool == "list_resources"
                and intent.limit == ReadIntent.model_fields["limit"].default
            ):
                # The read broker, not a wording classifier, owns the bounded LIST policy.
                # Replace the schema's implicit 20-object default so free-form questions
                # receive the configured inventory window. Preserve a deliberate planner
                # limit used by purpose-built diagnostic reads.
                intent = intent.model_copy(
                    update={"limit": settings.adhoc_inventory_max_objects}
                )
            intent, binding_error = _bind_pod_log_intent(intent, current_log_candidates)
            if binding_error:
                limitations.append(
                    f"A model-authored Pod log target was rejected before collection: {binding_error}"
                )
                continue
            assert intent is not None
            signature = _read_intent_signature(intent)
            if signature not in seen_intents:
                seen_intents.add(signature)
                new_intents.append(intent)
        if not new_intents:
            if plan.intents:
                limitations.append(
                    "The model planner repeated only reads already completed in this turn; "
                    "PodPilot requested a novel evidence step before stopping."
                )
            break
        intent_queue: list[tuple[ReadIntent, str | None, str | None, tuple[str, ...]]] = [
            (intent, None, None, ()) for intent in new_intents
        ]
        queue_index = 0
        while (
            queue_index < len(intent_queue)
            and units_used < settings.adhoc_max_reads_per_turn
        ):
            intent, automatic_code, automatic_reason, trigger_evidence_ids = intent_queue[queue_index]
            queue_index += 1
            unit_cost = _investigation_unit_cost(intent)
            unit_ceiling = (
                settings.adhoc_max_reads_per_turn if automatic_code else regular_unit_ceiling
            )
            if units_used + unit_cost > unit_ceiling:
                continue
            if progress:
                message = _read_progress_message(intent)
                if automatic_code == "tls_trust_retry":
                    message = "Retrying the bounded HTTPS probe without certificate verification."
                elif automatic_code == "pod_log_investigation":
                    message = "Inspecting bounded logs for a relevant backend container."
                elif automatic_code == "traffic_path_investigation":
                    message = "Following the observed Route traffic path to its backend workloads."
                elif automatic_code == "log_signal_investigation":
                    message = "Correlating a notable bounded log signal with exact Pod evidence."
                elif automatic_code == "configuration_detail":
                    message = "Reading exact discovered objects to explain their configuration."
                await progress("collecting", message)
            entry: dict[str, object] = {
                "round": round_number,
                "tool": intent.tool,
                "investigation_units": unit_cost,
                "target": (
                    f"{_display_probe_url(intent.url)} via {intent.connect_host or 'DNS'}"
                    if intent.tool == "http_probe" else
                    f"{intent.metric} {intent.metric_scope} "
                    f"{intent.namespace + '/' if intent.namespace else ''}{intent.name or '*'} "
                    f"range={intent.range_seconds}s"
                    if intent.tool == "query_metrics" else
                    f"discovery query={intent.discovery_query}"
                    if intent.tool == "discover_resources" else
                    f"{intent.resource or intent.api_version or 'v1'} {intent.kind or 'resource'} "
                    f"{intent.namespace or 'cluster'}/{intent.name or '*'}"
                    + (f" container={intent.container}" if intent.container else "")
                    + (" previous=true" if intent.tool == "pod_logs" and intent.previous else "")
                ),
            }
            if automatic_code:
                entry["automatic_followup"] = automatic_code
                entry["trigger_evidence_ids"] = list(trigger_evidence_ids)
            read_started = False
            try:
                preflight = getattr(cluster_reader, "preflight", None)
                if callable(preflight):
                    await run_in_threadpool(preflight, intent)
                units_used += unit_cost
                read_started = True
                result = await run_in_threadpool(cluster_reader.execute, intent)
                evidence.extend(item.to_dict() for item in result.observations)
                limitations.extend(result.limitations)
                for followup in automatic_read_followups(
                    intent, result.observations, question=question, goal_type=plan.goal_type
                ):
                    # Mechanical trust-only retry is not a diagnostic direction.
                    # All object traversal, logs, events, and configuration reads
                    # must be explicitly selected by the model on the next round.
                    if followup.code != "tls_trust_retry" or automatic_tls_retries >= 2:
                        continue
                    followup_intent = normalize_read_intent(followup.intent)
                    signature = _read_intent_signature(followup_intent)
                    if signature in seen_intents:
                        continue
                    automatic_tls_retries += 1
                    seen_intents.add(signature)
                    intent_queue.append((
                        followup_intent,
                        followup.code,
                        followup.reason,
                        followup.evidence_ids,
                    ))
                    LOGGER.info(
                        "podpilot.adhoc.automatic_followup actor=%s workflow_id=%s code=%s "
                        "tool=%s trigger_evidence_ids=%s",
                        actor,
                        workflow_id,
                        followup.code,
                        followup_intent.tool,
                        ",".join(followup.evidence_ids),
                    )
                probe_failed = intent.tool == "http_probe" and any(
                    item.data.get("outcome") == "failed" for item in result.observations
                )
                entry["status"] = "failed" if probe_failed else "succeeded"
                entry["observations"] = len(result.observations)
                entry["evidence_ids"] = [item.id for item in result.observations]
                if automatic_reason:
                    entry["reason"] = automatic_reason
                if progress:
                    summaries = [
                        str(item.summary).strip() for item in result.observations
                        if str(item.summary).strip()
                    ]
                    await progress(
                        "finding",
                        f"Found: {summaries[0]}" if summaries else
                        f"Collected {len(result.observations)} evidence item"
                        f"{'s' if len(result.observations) != 1 else ''}.",
                    )
            except ReadOnlyExplorerError as exc:
                event = (
                    "podpilot.cluster_read.failed"
                    if read_started else "podpilot.cluster_read.rejected"
                )
                LOGGER.warning(
                    "%s actor=%s workflow_id=%s tool=%s target=%s error=%s",
                    event,
                    actor,
                    workflow_id,
                    intent.tool,
                    entry["target"],
                    str(exc),
                )
                limitations.append(str(exc))
                entry["status"] = (
                    "denied_or_unavailable" if read_started else "rejected_before_collection"
                )
                entry["detail"] = str(exc)
            activity.append(entry)
        evidence = evidence[-settings.adhoc_max_evidence :]
        if terminal_plan:
            break
    return _BoundedReadCollection(
        evidence=evidence,
        activity=activity,
        limitations=list(dict.fromkeys(limitations))[:10],
        scope_summary=scope_summary,
        units_used=units_used,
        read_signatures=sorted(seen_intents),
    )


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
    cluster_credential_store: CredentialStore | None = None,
    remote_read_explorer_factory: Callable[[Cluster, str], ReadOnlyExplorer] | None = None,
) -> FastAPI:
    app_settings = settings or get_settings()
    resolver = role_resolver or LazyOpenShiftGroupRoleResolver(
        cache_seconds=app_settings.role_cache_seconds,
        role_groups=(
            (Role.BREAKGLASS, tuple(app_settings.role_breakglass_groups)),
            (Role.APPROVER, tuple(app_settings.role_approver_groups)),
            (Role.INVESTIGATOR, tuple(app_settings.role_investigator_groups)),
        ),
    )
    alerts = alert_source or _make_alert_source(app_settings)
    workloads = workload_source or _make_workload_source(app_settings)
    credentials = credential_store or _make_credential_store(app_settings)
    cluster_credentials = cluster_credential_store or _make_cluster_credential_store(app_settings)
    provider = model_provider or OpenAIProviderRouter()
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
        max_search_scan_objects=app_settings.adhoc_search_max_scan_objects,
        http_probe=BoundedHttpProbe(
            timeout_seconds=app_settings.adhoc_http_probe_timeout_seconds,
            max_response_bytes=app_settings.adhoc_http_probe_max_bytes,
            additional_ca_path=app_settings.service_ca_path,
        ),
        metric_reader=BoundedMetricTrendReader(
            ThanosQueryClient(
                base_url=app_settings.thanos_url,
                token_path=app_settings.service_account_token_path,
                ca_path=app_settings.service_ca_path,
                timeout_seconds=app_settings.thanos_timeout_seconds,
                max_series=app_settings.thanos_max_series,
                max_points_per_series=app_settings.adhoc_metrics_max_points_per_series,
            ),
            max_range_seconds=app_settings.adhoc_metrics_max_range_seconds,
            max_points_per_series=app_settings.adhoc_metrics_max_points_per_series,
        ),
    )
    templates = Jinja2Templates(directory=app_settings.web_dir / "templates")
    templates.env.filters["safe_markdown"] = render_safe_markdown
    templates.env.filters["est_time"] = _format_est_time

    def remote_cluster_reader(cluster: Cluster, token: str) -> ReadOnlyExplorer:
        if remote_read_explorer_factory is not None:
            return remote_read_explorer_factory(cluster, token)
        return KubernetesReadOnlyExplorer.for_remote_cluster(
            api_url=cluster.api_url,
            token=token,
            tls_verify=cluster.tls_verify,
            log_tail_lines=app_settings.workload_log_tail_lines,
            max_log_bytes=app_settings.workload_max_log_bytes,
            max_search_scan_objects=app_settings.adhoc_search_max_scan_objects,
            http_probe=BoundedHttpProbe(
                timeout_seconds=app_settings.adhoc_http_probe_timeout_seconds,
                max_response_bytes=app_settings.adhoc_http_probe_max_bytes,
            ),
        )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = app_settings
        application.state.engine = build_engine(app_settings)
        ensure_knowledge_fts(application.state.engine)
        with Session(application.state.engine) as db_session:
            system_cluster = db_session.get(Cluster, SYSTEM_CLUSTER_ID)
            if system_cluster is None:
                now = datetime.now(timezone.utc)
                db_session.add(Cluster(
                    id=SYSTEM_CLUSTER_ID,
                    name=app_settings.cluster_name,
                    api_url="in-cluster://service-account",
                    credential_key=None,
                    tags_json=json.dumps({
                        "connection": "in-cluster",
                        "environment": app_settings.environment,
                    }, sort_keys=True),
                    tls_verify=True,
                    is_enabled=True,
                    is_system=True,
                    status="ready",
                    created_by="system:bootstrap",
                    updated_by="system:bootstrap",
                    created_at=now,
                    updated_at=now,
                ))
            db_session.execute(
                update(AdHocConversation)
                .where(AdHocConversation.cluster_ids_json == "[]")
                .values(cluster_ids_json=json.dumps([SYSTEM_CLUSTER_ID]))
            )
            for document in db_session.scalars(
                select(KnowledgeDocument).where(
                    KnowledgeDocument.target_cluster_ids_json.contains(app_settings.cluster_name)
                )
            ):
                try:
                    legacy_targets = list(json.loads(document.target_cluster_ids_json or "[]"))
                except (TypeError, ValueError):
                    continue
                migrated_targets = [
                    SYSTEM_CLUSTER_ID if item == app_settings.cluster_name else item
                    for item in legacy_targets
                ]
                if migrated_targets != legacy_targets:
                    document.target_cluster_ids_json = json.dumps(migrated_targets, sort_keys=True)
            db_session.commit()
        worker_tasks: list[asyncio.Task[None]] = []
        if app_settings.adhoc_job_worker_enabled:
            with Session(application.state.engine) as db_session:
                db_session.execute(
                    update(AdHocRun)
                    .where(AdHocRun.status == "running")
                    .values(status="queued", phase="queued", started_at=None)
                )
                db_session.commit()
            application.state.adhoc_wake = asyncio.Event()
            worker_tasks = [
                asyncio.create_task(
                    _adhoc_worker(application, worker_number),
                    name=f"podpilot-adhoc-worker-{worker_number}",
                )
                for worker_number in range(1, app_settings.adhoc_worker_concurrency + 1)
            ]
            LOGGER.info(
                "podpilot.adhoc.worker_pool_started workers=%s per_user_limit=%s",
                app_settings.adhoc_worker_concurrency,
                app_settings.adhoc_max_concurrent_runs_per_user,
            )
        try:
            yield
        finally:
            for worker_task in worker_tasks:
                worker_task.cancel()
            if worker_tasks:
                await asyncio.gather(*worker_tasks, return_exceptions=True)
            application.state.engine.dispose()

    app = FastAPI(
        title="PodPilot",
        version="0.12.0",
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

    async def _execute_adhoc_turn(
        *, engine, username: str, conversation_id: str, message_text: str,
        run_id: str, include_raw_response: bool = False,
        followup_action: dict[str, object] | None = None,
        progress: ProgressReporter | None = None,
    ) -> str:
        source_question = redact_text(str(
            (followup_action or {}).get("source_question") or message_text
        ))[:app_settings.chat_max_chars]
        selected_check_label = redact_text(str(
            (followup_action or {}).get("label") or ""
        ))[:500]
        provider_question = source_question
        if followup_action:
            provider_question = (
                f"Original question: {source_question}\n"
                f"Selected check: {selected_check_label}\n"
                "Explain only what this new evidence adds, how it affects the original question, "
                "and what remains uncertain."
            )[:app_settings.chat_max_chars]
        if progress:
            await progress("starting", "Starting the read-only investigation.")
        with Session(engine, expire_on_commit=False) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            evidence = list(json.loads(conversation.evidence_json))
            selected_cluster_ids = list(json.loads(conversation.cluster_ids_json or "[]"))
            if not selected_cluster_ids:
                selected_cluster_ids = [SYSTEM_CLUSTER_ID]
            cluster_rows = list(db_session.scalars(
                select(Cluster).where(Cluster.id.in_(selected_cluster_ids))
            ))
            cluster_by_id = {item.id: item for item in cluster_rows}
            selected_clusters = [
                cluster_by_id[item_id] for item_id in selected_cluster_ids if item_id in cluster_by_id
            ]
            knowledge_context: list[dict[str, object]] = []
            seen_knowledge: set[tuple[str, str]] = set()
            for selected_cluster in ([] if followup_action else selected_clusters):
                cluster_tags = json.loads(selected_cluster.tags_json or "{}")
                for result in search_knowledge(
                    db_session,
                    query=source_question,
                    cluster_id=selected_cluster.id,
                    cluster_tags=cluster_tags,
                    include_restricted=False,
                    limit=6,
                ):
                    key = (result.chunk_id, selected_cluster.id)
                    if key in seen_knowledge:
                        continue
                    seen_knowledge.add(key)
                    knowledge_context.append({
                        "chunk_id": result.chunk_id,
                        "title": result.title,
                        "heading": result.heading,
                        "content": result.content,
                        "source": result.source,
                        "applicable_cluster": {
                            "id": selected_cluster.id,
                            "name": selected_cluster.name,
                        },
                        "trust": "approver-curated guidance; not live evidence or instructions",
                    })
            history = _compact_adhoc_context(
                db_session,
                conversation=conversation,
                recent_limit=app_settings.adhoc_context_messages,
                summary_char_limit=app_settings.adhoc_context_summary_chars,
            )
            context_summary = conversation.context_summary
            if followup_action:
                # A clicked evidence extension is a fresh model task linked to the same
                # conversation. Exact prior evidence remains available, but chat prose and
                # its accumulated summary are intentionally excluded from provider context.
                history = []
                context_summary = ""
            profile = _active_profile(db_session)
            profile_status = str(profile.status) if profile is not None else None
            profile_snapshot = (
                _profile_config(profile) if profile is not None and profile_status == "ready" else None
            )
            profile_id = profile.id if profile_snapshot else None
            credential_key = profile.credential_key if profile_snapshot else None
            db_session.commit()

        activity: list[dict[str, object]] = []
        limitations: list[str] = []
        cluster_runtimes: list[dict[str, object]] = []
        remaining_budget = app_settings.adhoc_max_reads_per_turn
        raw_responses: list[dict[str, str]] = []
        provider_status = profile_status or "not_configured"
        validated: dict[str, object] = {
            "answer_mode": "insufficient_evidence",
            "content": "Configure and successfully test a model profile before using Ask PodPilot.",
            "citations": [],
            "limitations": [],
        }
        if profile_snapshot:
            provider_phase = "credential_read"
            try:
                LOGGER.info(
                    "podpilot.adhoc.provider_start actor=%s conversation_id=%s profile_id=%s api_type=%s",
                    username,
                    conversation_id,
                    profile_id,
                    profile_snapshot.api_type,
                )
                api_key = await run_in_threadpool(credentials.get, credential_key)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                inquiry = None
                if not followup_action:
                    if progress:
                        await progress("planning", "Understanding the investigation request.")
                    inquiry = await _classify_ad_hoc_inquiry(
                        model_provider=provider,
                        profile=profile_snapshot,
                        api_key=api_key,
                        question=source_question,
                        conversation=history,
                        cluster_names=[item.name for item in selected_clusters],
                    )
                provider_phase = "bounded_read_collection"
                if not selected_clusters:
                    limitations.append("The conversation's selected clusters no longer exist.")
                evidence_by_id = {
                    str(item.get("id")): dict(item)
                    for item in evidence if isinstance(item, dict) and item.get("id")
                }
                scope_summaries: list[str] = []
                requested_cluster_id = str(followup_action.get("cluster_id") or "") if followup_action else ""
                for cluster_index, selected_cluster in enumerate(selected_clusters):
                    if requested_cluster_id and selected_cluster.id != requested_cluster_id:
                        continue
                    cluster_label = selected_cluster.name
                    if not selected_cluster.is_enabled:
                        limitations.append(
                            f"Cluster {cluster_label} is disabled; PodPilot retained the session but did not connect."
                        )
                        continue
                    clusters_remaining = len(selected_clusters) - cluster_index
                    cluster_budget = max(1, remaining_budget // max(1, clusters_remaining))
                    cluster_budget = min(cluster_budget, remaining_budget)
                    if cluster_budget <= 0:
                        limitations.append(
                            f"Cluster {cluster_label} was not read because the shared {app_settings.adhoc_max_reads_per_turn}-read budget was exhausted."
                        )
                        continue
                    reader: ReadOnlyExplorer = cluster_reader
                    if not selected_cluster.is_system:
                        try:
                            cluster_token = await run_in_threadpool(
                                cluster_credentials.get, selected_cluster.credential_key
                            )
                        except CredentialStoreError as exc:
                            limitations.append(f"Cluster {cluster_label}: {exc}")
                            continue
                        if not cluster_token:
                            limitations.append(
                                f"Cluster {cluster_label} has no usable API token; an Approver must rotate it."
                            )
                            continue
                        try:
                            reader = remote_cluster_reader(selected_cluster, cluster_token)
                        except Exception as exc:
                            limitations.append(
                                f"Cluster {cluster_label}: the Kubernetes API client could not be initialized ({type(exc).__name__})."
                            )
                            continue
                        if not selected_cluster.tls_verify:
                            limitations.append(
                                f"Cluster {cluster_label} API TLS verification is disabled; the bearer token and evidence are vulnerable to interception."
                            )
                    if progress:
                        await progress("selecting_cluster", f"Investigating cluster {cluster_label}.")
                    prior_cluster_evidence = [
                        dict(item) for item in evidence_by_id.values()
                        if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID) == selected_cluster.id
                    ]
                    cluster_settings = app_settings.model_copy(update={
                        "cluster_name": cluster_label,
                        "adhoc_max_reads_per_turn": cluster_budget,
                        "adhoc_followup_reserve_units": min(
                            app_settings.adhoc_followup_reserve_units,
                            max(0, cluster_budget // 5),
                        ),
                    })
                    cluster_knowledge = [
                        item for item in knowledge_context
                        if item["applicable_cluster"]["id"] == selected_cluster.id
                    ]
                    cluster_runtime: dict[str, object] = {
                        "cluster": selected_cluster,
                        "reader": reader,
                        "knowledge": cluster_knowledge,
                        "read_signatures": [],
                    }
                    cluster_runtimes.append(cluster_runtime)
                    collected = await _collect_bounded_cluster_reads(
                        model_provider=provider,
                        cluster_reader=reader,
                        profile=profile_snapshot,
                        api_key=api_key,
                        settings=cluster_settings,
                        actor=username,
                        workflow_id=f"{conversation_id}:{selected_cluster.id}",
                        question=source_question,
                        conversation=history,
                        earlier_context_summary=context_summary,
                        existing_evidence=prior_cluster_evidence,
                        knowledge=[] if followup_action else cluster_knowledge,
                        investigation_gaps=([
                            InvestigationGap(
                                question=str(followup_action.get("label") or source_question)[:500],
                                capability=str(followup_action.get("capability") or "resource_read"),
                                priority="high",
                                supporting_evidence_ids=[
                                    str(item)[:128] for item in
                                    followup_action.get("supporting_evidence_ids", [])
                                ],
                            )
                        ] if followup_action else None),
                        requested_candidate_id=(
                            str(followup_action.get("id")) if followup_action else None
                        ),
                        progress=progress,
                        inquiry=inquiry,
                    )
                    cluster_runtime["read_signatures"] = (
                        collected.read_signatures or []
                    )
                    remaining_budget = max(0, remaining_budget - collected.units_used)
                    for item in collected.evidence:
                        attributed = dict(item)
                        attributed["cluster_id"] = selected_cluster.id
                        attributed["cluster_name"] = cluster_label
                        evidence_by_id[str(attributed.get("id"))] = attributed
                    for item in collected.activity:
                        attributed_activity = dict(item)
                        attributed_activity["cluster_id"] = selected_cluster.id
                        attributed_activity["cluster_name"] = cluster_label
                        activity.append(attributed_activity)
                    limitations.extend(
                        collected.limitations if len(selected_clusters) == 1 else
                        [f"Cluster {cluster_label}: {item}" for item in collected.limitations]
                    )
                    scope_summaries.append(f"{cluster_label}: {collected.scope_summary}")
                evidence = list(evidence_by_id.values())[-app_settings.adhoc_max_evidence :]
                collected_scope_summary = "; ".join(scope_summaries) or "No selected cluster was readable."
                provider_phase = "final_answer"
                if progress:
                    await progress(
                        "answering",
                        f"Preparing an evidence-backed answer from {len(evidence)} observation"
                        f"{'s' if len(evidence) != 1 else ''}.",
                    )
                answer_observations, answer_context_metadata = _compact_answer_evidence(
                    evidence, activity=activity, total_byte_limit=48_000,
                    per_observation_byte_limit=8_000, max_observations=16,
                )
                answer_findings = _compact_answer_findings(
                    derive_adhoc_findings(evidence), total_byte_limit=12_000
                )[:8]
                deterministic_log_section = _deterministic_log_findings_section(
                    evidence=evidence, activity=activity
                )
                model_log_analysis: dict[str, object] | None = None
                log_payload, log_text_by_id = _current_log_analysis_payload(
                    evidence=evidence, activity=activity, question=provider_question,
                )
                analyze_logs = getattr(provider, "analyze_logs", None)
                if log_payload is not None and callable(analyze_logs):
                    provider_phase = "log_analysis"
                    if progress:
                        await progress(
                            "analyzing_logs",
                            f"Analyzing {len(log_text_by_id)} bounded Pod log excerpt"
                            f"{'s' if len(log_text_by_id) != 1 else ''} for potential issues.",
                        )
                    try:
                        raw_log_analysis = await run_in_threadpool(
                            analyze_logs, profile_snapshot, api_key, log_payload,
                        )
                        model_log_analysis = _validated_model_log_analysis(
                            raw_log_analysis, text_by_id=log_text_by_id,
                        )
                        limitations.extend(
                            str(item) for item in model_log_analysis.get("limitations", [])
                        )
                        LOGGER.info(
                            "podpilot.adhoc.log_analysis_complete actor=%s conversation_id=%s "
                            "logs=%s issues=%s",
                            username,
                            conversation_id,
                            len(log_text_by_id),
                            len(model_log_analysis.get("issues", [])),
                        )
                    except ModelProviderError as exc:
                        LOGGER.warning(
                            "podpilot.adhoc.log_analysis_failed actor=%s conversation_id=%s error=%s",
                            username,
                            conversation_id,
                            exc,
                        )
                        limitations.append(
                            "The dedicated model-assisted Pod log analysis was unavailable; "
                            "the bounded log evidence remains available for inspection."
                        )
                    finally:
                        provider_phase = "final_answer"
                if model_log_analysis is not None:
                    compact_without_log_tails: list[dict[str, object]] = []
                    for observation in answer_observations:
                        candidate = dict(observation)
                        if candidate.get("tool") == "pod_logs" and isinstance(
                            candidate.get("data"), dict
                        ):
                            data = dict(candidate["data"])
                            data.pop("tail", None)
                            data["tailOmittedFromFinalContext"] = True
                            data["tailAnalysis"] = (
                                "See model_log_analysis; the complete bounded excerpt remains in evidence."
                            )
                            candidate["data"] = data
                        compact_without_log_tails.append(candidate)
                    answer_observations = compact_without_log_tails
                answer_context: dict[str, object] = {
                    "clusters": [_cluster_summary(item) for item in selected_clusters],
                    "question": provider_question,
                    "conversation": [
                        {
                            "role": str(item.get("role") or "")[:16],
                            "content": redact_text(str(item.get("content") or ""))[:1000],
                        }
                        for item in history[-4:]
                    ],
                    "earlier_context_summary": redact_text(context_summary)[-1500:],
                    "scope_summary": collected_scope_summary,
                    "observations": answer_observations,
                    "facts": _model_fact_cards(evidence, activity=activity),
                    "curated_knowledge": knowledge_context[:6],
                    "evidence_context": answer_context_metadata,
                    "findings": answer_findings,
                    "capability_ledger": _investigation_capability_ledger(
                        evidence=evidence,
                        activity=activity,
                        remaining_units=remaining_budget,
                    ),
                    "model_log_analysis": model_log_analysis,
                    "collection_limitations": _dedupe_limitations(limitations, limit=10),
                }
                with capture_raw_model_responses(include_raw_response) as captured:
                    try:
                        answer = await run_in_threadpool(
                            provider.answer_ad_hoc,
                            profile_snapshot,
                            api_key,
                            answer_context,
                        )
                    finally:
                        _bounded_raw_response_attempts(
                            raw_responses, captured, stage="initial answer"
                        )
                if include_raw_response and not captured:
                    _bounded_raw_response_attempts(
                        raw_responses,
                        [answer.model_dump_json() if hasattr(answer, "model_dump_json") else str(answer)],
                        stage="initial answer",
                    )
                validated = _validated_adhoc_answer(
                    answer,
                    known_evidence_ids={str(item.get("id")) for item in evidence},
                    collection_limitations=limitations,
                    observations=evidence,
                )
                _reconcile_validated_answer_gaps(
                    validated,
                    capability_ledger=answer_context["capability_ledger"],
                )
                answer_quality_issue = _adhoc_answer_quality_issue(
                    content=str(validated["content"]),
                    answer_mode=str(validated["answer_mode"]),
                    has_evidence=bool(evidence),
                    has_citations=bool(validated["citations"]),
                )
                if answer_quality_issue:
                    LOGGER.warning(
                        "podpilot.adhoc.answer_quality_rejected actor=%s conversation_id=%s "
                        "attempt=1 reason=%s",
                        username,
                        conversation_id,
                        answer_quality_issue,
                    )
                    if progress:
                        await progress(
                            "answering",
                            "The first answer was incomplete; requesting one bounded correction.",
                        )
                    retry_context = dict(answer_context)
                    feedback_message = (
                        "Return only a short operator-facing answer. Do not embed JSON or schema fields."
                        if answer_quality_issue == "structured_fields_embedded_in_answer"
                        else
                        "Briefly interpret the supplied evidence and state what remains uncertain."
                        if answer_quality_issue == "insufficient_interpretation_with_available_evidence"
                        else
                        "Return a short answer with substantive prose, not a heading alone."
                    )
                    retry_context["answer_feedback"] = {
                        "code": "incomplete_final_answer",
                        "reason": answer_quality_issue,
                        "message": feedback_message,
                    }
                    try:
                        with capture_raw_model_responses(include_raw_response) as captured:
                            try:
                                retry_answer = await run_in_threadpool(
                                    provider.answer_ad_hoc,
                                    profile_snapshot,
                                    api_key,
                                    retry_context,
                                )
                            finally:
                                _bounded_raw_response_attempts(
                                    raw_responses, captured, stage="PodPilot correction"
                                )
                        if include_raw_response and not captured:
                            _bounded_raw_response_attempts(
                                raw_responses,
                                [
                                    retry_answer.model_dump_json()
                                    if hasattr(retry_answer, "model_dump_json")
                                    else str(retry_answer)
                                ],
                                stage="PodPilot correction",
                            )
                        retry_validated = _validated_adhoc_answer(
                            retry_answer,
                            known_evidence_ids={str(item.get("id")) for item in evidence},
                            collection_limitations=limitations,
                            observations=evidence,
                        )
                        retry_validated = _merge_validated_recommendations(
                            validated, retry_validated
                        )
                        _reconcile_validated_answer_gaps(
                            retry_validated,
                            capability_ledger=retry_context["capability_ledger"],
                        )
                        retry_issue = _adhoc_answer_quality_issue(
                            content=str(retry_validated["content"]),
                            answer_mode=str(retry_validated["answer_mode"]),
                            has_evidence=bool(evidence),
                            has_citations=bool(retry_validated["citations"]),
                        )
                        validated = retry_validated
                        answer_quality_issue = retry_issue
                        if retry_issue:
                            LOGGER.warning(
                                "podpilot.adhoc.answer_quality_rejected actor=%s "
                                "conversation_id=%s attempt=2 reason=%s",
                                username,
                                conversation_id,
                                retry_issue,
                            )
                    except ModelProviderError as exc:
                        LOGGER.warning(
                            "podpilot.adhoc.answer_retry_failed actor=%s conversation_id=%s "
                            "error=%s",
                            username,
                            conversation_id,
                            exc,
                        )
                        limitations.append(
                            "The model provider could not correct its incomplete final answer; "
                            "PodPilot used deterministic evidence instead."
                        )
                structured_gaps = _actionable_investigation_gaps(
                    validated_answer=validated,
                    capability_ledger=answer_context["capability_ledger"],
                )
                if (
                    not followup_action
                    and structured_gaps
                    and remaining_budget > 0
                    and cluster_runtimes
                ):
                    if progress:
                        await progress(
                            "planning",
                            "Turning unresolved evidence questions into safe typed follow-up reads.",
                        )
                    activity_before_gaps = len(activity)
                    runtimes_remaining = len(cluster_runtimes)
                    for runtime in cluster_runtimes:
                        if remaining_budget <= 0:
                            break
                        selected_cluster = runtime["cluster"]
                        reader = runtime["reader"]
                        cluster_knowledge = runtime["knowledge"]
                        cluster_budget = max(
                            1, remaining_budget // max(1, runtimes_remaining)
                        )
                        cluster_budget = min(cluster_budget, remaining_budget)
                        runtimes_remaining -= 1
                        prior_cluster_evidence = [
                            dict(item) for item in evidence_by_id.values()
                            if str(item.get("cluster_id") or SYSTEM_CLUSTER_ID)
                            == selected_cluster.id
                        ]
                        cluster_settings = app_settings.model_copy(update={
                            "cluster_name": selected_cluster.name,
                            "adhoc_max_reads_per_turn": cluster_budget,
                            "adhoc_followup_reserve_units": 0,
                        })
                        gap_collection = await _collect_bounded_cluster_reads(
                            model_provider=provider,
                            cluster_reader=reader,
                            profile=profile_snapshot,
                            api_key=api_key,
                            settings=cluster_settings,
                            actor=username,
                            workflow_id=(
                                f"{conversation_id}:{selected_cluster.id}:answer-gaps"
                            ),
                            question=message_text,
                            conversation=history,
                            earlier_context_summary=context_summary,
                            existing_evidence=prior_cluster_evidence,
                            knowledge=cluster_knowledge,
                            investigation_gaps=structured_gaps,
                            existing_read_signatures=list(
                                runtime.get("read_signatures") or []
                            ),
                            progress=progress,
                            inquiry=inquiry,
                        )
                        runtime["read_signatures"] = (
                            gap_collection.read_signatures or []
                        )
                        remaining_budget = max(
                            0, remaining_budget - gap_collection.units_used
                        )
                        for item in gap_collection.evidence:
                            attributed = dict(item)
                            attributed["cluster_id"] = selected_cluster.id
                            attributed["cluster_name"] = selected_cluster.name
                            evidence_by_id[str(attributed.get("id"))] = attributed
                        for item in gap_collection.activity:
                            attributed_activity = dict(item)
                            attributed_activity["cluster_id"] = selected_cluster.id
                            attributed_activity["cluster_name"] = selected_cluster.name
                            activity.append(attributed_activity)
                        limitations.extend(
                            gap_collection.limitations
                            if len(selected_clusters) == 1 else
                            [
                                f"Cluster {selected_cluster.name}: {item}"
                                for item in gap_collection.limitations
                            ]
                        )
                    if len(activity) > activity_before_gaps:
                        evidence = list(evidence_by_id.values())[
                            -app_settings.adhoc_max_evidence:
                        ]
                        answer_observations, answer_context_metadata = (
                            _compact_answer_evidence(
                                evidence, activity=activity, total_byte_limit=48_000,
                                per_observation_byte_limit=8_000, max_observations=16,
                            )
                        )
                        answer_findings = _compact_answer_findings(
                            derive_adhoc_findings(evidence), total_byte_limit=12_000
                        )[:8]
                        deterministic_log_section = _deterministic_log_findings_section(
                            evidence=evidence, activity=activity
                        )
                        model_log_analysis = None
                        log_payload, log_text_by_id = _current_log_analysis_payload(
                            evidence=evidence, activity=activity, question=message_text,
                        )
                        if log_payload is not None and callable(analyze_logs):
                            try:
                                raw_log_analysis = await run_in_threadpool(
                                    analyze_logs, profile_snapshot, api_key, log_payload,
                                )
                                model_log_analysis = _validated_model_log_analysis(
                                    raw_log_analysis, text_by_id=log_text_by_id,
                                )
                            except ModelProviderError as exc:
                                LOGGER.warning(
                                    "podpilot.adhoc.gap_log_analysis_failed actor=%s "
                                    "conversation_id=%s error=%s",
                                    username, conversation_id, exc,
                                )
                        if model_log_analysis is not None:
                            without_log_tails: list[dict[str, object]] = []
                            for observation in answer_observations:
                                candidate = dict(observation)
                                if candidate.get("tool") == "pod_logs" and isinstance(
                                    candidate.get("data"), dict
                                ):
                                    data = dict(candidate["data"])
                                    data.pop("tail", None)
                                    data["tailOmittedFromFinalContext"] = True
                                    data["tailAnalysis"] = (
                                        "See model_log_analysis; the complete bounded excerpt "
                                        "remains in evidence."
                                    )
                                    candidate["data"] = data
                                without_log_tails.append(candidate)
                            answer_observations = without_log_tails
                        final_capability_ledger = _investigation_capability_ledger(
                            evidence=evidence,
                            activity=activity,
                            remaining_units=remaining_budget,
                        )
                        resolved_gaps, remaining_gaps = _partition_investigation_gaps(
                            structured_gaps,
                            capability_ledger=final_capability_ledger,
                        )
                        answer_context = {
                            "clusters": [
                                _cluster_summary(item) for item in selected_clusters
                            ],
                            "question": message_text,
                            "conversation": [
                                {
                                    "role": str(item.get("role") or "")[:16],
                                    "content": redact_text(str(item.get("content") or ""))[:1000],
                                }
                                for item in history[-4:]
                            ],
                            "earlier_context_summary": redact_text(context_summary)[-1500:],
                            "scope_summary": collected_scope_summary,
                            "observations": answer_observations,
                            "facts": _model_fact_cards(evidence, activity=activity),
                            "curated_knowledge": knowledge_context[:6],
                            "evidence_context": answer_context_metadata,
                            "findings": answer_findings,
                            "capability_ledger": final_capability_ledger,
                            "model_log_analysis": model_log_analysis,
                            "collection_limitations": _dedupe_limitations(
                                limitations, limit=10
                            ),
                            "resolved_investigation_gaps": [
                                gap.model_dump() for gap in resolved_gaps
                            ],
                            "remaining_investigation_gaps": [
                                gap.model_dump() for gap in remaining_gaps
                            ],
                        }
                        with capture_raw_model_responses(
                            include_raw_response
                        ) as captured:
                            try:
                                answer = await run_in_threadpool(
                                    provider.answer_ad_hoc,
                                    profile_snapshot,
                                    api_key,
                                    answer_context,
                                )
                            finally:
                                _bounded_raw_response_attempts(
                                    raw_responses,
                                    captured,
                                    stage="evidence follow-up answer",
                                )
                        if include_raw_response and not captured:
                            _bounded_raw_response_attempts(
                                raw_responses,
                                [
                                    answer.model_dump_json()
                                    if hasattr(answer, "model_dump_json") else str(answer)
                                ],
                                stage="evidence follow-up answer",
                            )
                        followup_validated = _validated_adhoc_answer(
                            answer,
                            known_evidence_ids={
                                str(item.get("id")) for item in evidence
                            },
                            collection_limitations=limitations,
                            observations=evidence,
                        )
                        validated = _merge_validated_recommendations(
                            validated, followup_validated
                        )
                        _reconcile_validated_answer_gaps(
                            validated,
                            capability_ledger=final_capability_ledger,
                        )
                        answer_quality_issue = _adhoc_answer_quality_issue(
                            content=str(validated["content"]),
                            answer_mode=str(validated["answer_mode"]),
                            has_evidence=bool(evidence),
                            has_citations=bool(validated["citations"]),
                        )
                        LOGGER.info(
                            "podpilot.adhoc.gap_followup_complete actor=%s "
                            "conversation_id=%s gaps=%s new_reads=%s remaining_units=%s",
                            username,
                            conversation_id,
                            len(structured_gaps),
                            len(activity) - activity_before_gaps,
                            remaining_budget,
                        )
                inventory_answer = _deterministic_inventory_answer(
                    evidence=evidence,
                    activity=activity,
                    question=message_text,
                    inventory_only=(
                        inquiry.mode == "inventory" if inquiry is not None else None
                    ),
                )
                resource_detail_answer = _deterministic_resource_detail_answer(
                    evidence=evidence,
                    activity=activity,
                    question=message_text,
                )
                route_tls_answer = _deterministic_route_tls_answer(
                    question=message_text,
                    evidence=evidence,
                    activity=activity,
                )
                route_fallback_needed = (
                    validated.get("answer_mode") != "evidence_based"
                    or not validated.get("citations")
                    or answer_quality_issue is not None
                )
                deterministic_answer = (
                    route_tls_answer if route_fallback_needed else None
                ) or (
                    resource_detail_answer if route_fallback_needed else None
                ) or (
                    inventory_answer if route_fallback_needed else None
                ) or (
                    _deterministic_evidence_fallback_answer(
                        evidence=evidence, activity=activity
                    ) if answer_quality_issue is not None else None
                )
                if deterministic_answer is not None:
                    validated.update(deterministic_answer)
                    if answer_quality_issue is not None:
                        limitations.append(
                            "The model returned an incomplete final answer after one correction attempt; "
                            "PodPilot used a deterministic evidence summary."
                        )
                    validated["limitations"] = _dedupe_limitations(limitations)
                else:
                    validated["limitations"] = _dedupe_limitations(
                        [*limitations, *list(validated["limitations"])]
                    )
                if deterministic_answer is not inventory_answer:
                    _append_deterministic_inventory(validated, inventory_answer)
                if deterministic_log_section is not None:
                    content = str(validated["content"]).rstrip()
                    log_content = str(deterministic_log_section["content"])
                    if "## Backend log findings" not in content:
                        validated["content"] = f"{content}\n\n{log_content}".strip()
                    validated["citations"] = list(dict.fromkeys([
                        *[str(item) for item in validated["citations"]],
                        *[str(item) for item in deterministic_log_section["citations"]],
                    ]))
                if model_log_analysis is not None:
                    model_log_section = _model_log_analysis_section(model_log_analysis)
                    content = str(validated["content"]).rstrip()
                    validated["content"] = (
                        f"{content}\n\n{model_log_section['content']}"
                    ).strip()
                    validated["citations"] = list(dict.fromkeys([
                        *[str(item) for item in validated["citations"]],
                        *[str(item) for item in model_log_section["citations"]],
                    ]))
                validated["limitations"] = _dedupe_limitations([
                    *[str(item) for item in validated.get("limitations", [])],
                    *_adhoc_answer_advisories(
                        citations=[str(item) for item in validated["citations"]],
                        question=source_question,
                        observations=evidence,
                    ),
                ])
                _reconcile_validated_answer_gaps(
                    validated,
                    capability_ledger=_investigation_capability_ledger(
                        evidence=evidence,
                        activity=activity,
                        remaining_units=remaining_budget,
                    ),
                )
                LOGGER.info(
                    "podpilot.adhoc.provider_complete actor=%s conversation_id=%s "
                    "profile_id=%s reads=%s evidence=%s",
                    username,
                    conversation_id,
                    profile_id,
                    len(activity),
                    len(evidence),
                )
            except (CredentialStoreError, ModelProviderError) as exc:
                LOGGER.warning(
                    "podpilot.adhoc.provider_failed actor=%s conversation_id=%s "
                    "profile_id=%s phase=%s error=%s",
                    username,
                    conversation_id,
                    profile_id,
                    provider_phase,
                    str(exc),
                )
                contract_failure = isinstance(exc, ModelProviderError) and any(
                    marker in str(exc).lower()
                    for marker in ("schema", "does not match", "structured response")
                )
                provider_status = "invalid_response" if contract_failure else "unavailable"
                if evidence:
                    validated = _deterministic_provider_failure_answer(
                        question=message_text,
                        evidence=evidence,
                        activity=activity,
                        inventory_only=(
                            inquiry.mode == "inventory" if inquiry is not None else None
                        ),
                    )
                    failure_kind = (
                        "invalid structured response" if contract_failure
                        else "provider failure"
                    )
                    limitations.append(
                        f"The final model answer had an {failure_kind}; PodPilot preserved the "
                        "successfully collected evidence in a deterministic cited answer."
                    )
                    limitations.append(str(exc))
                    validated["limitations"] = _dedupe_limitations(limitations)
                    validated["conclusion_status"] = "probable"
                    log_section = _deterministic_log_findings_section(
                        evidence=evidence, activity=activity
                    )
                    if log_section is not None:
                        content = str(validated["content"]).rstrip()
                        log_content = str(log_section["content"])
                        if "## Backend log findings" not in content:
                            validated["content"] = f"{content}\n\n{log_content}".strip()
                        validated["citations"] = list(dict.fromkeys([
                            *[str(item) for item in validated["citations"]],
                            *[str(item) for item in log_section["citations"]],
                        ]))
                    LOGGER.warning(
                        "podpilot.adhoc.provider_fallback actor=%s conversation_id=%s "
                        "evidence=%s citations=%s",
                        username, conversation_id, len(evidence),
                        len(validated["citations"]),
                    )
                else:
                    validated = {
                        "answer_mode": "insufficient_evidence",
                        "content": (
                            "The model returned an invalid structured response, so PodPilot could not "
                            "complete this investigation. No cluster changes were attempted."
                            if contract_failure else
                            "The model provider is currently unavailable. No cluster changes were attempted."
                        ),
                        "citations": [],
                        "limitations": [str(exc)],
                    }
        suggested_checks, suggested_followup_actions = _compile_remaining_candidate_followups(
            question=source_question,
            evidence=evidence,
            activity=activity,
            cluster_runtimes=cluster_runtimes,
            remaining_units=remaining_budget,
            limit=3,
        )
        validated["recommended_next_checks"] = suggested_checks
        validated["suggested_followup_actions"] = suggested_followup_actions
        actionable_labels = {
            str(item.get("label")) for item in suggested_followup_actions
        }
        validated["guidance_next_checks"] = [
            item for item in suggested_checks if item not in actionable_labels
        ]
        if followup_action:
            content = str(validated.get("content") or "").strip()
            if not content.startswith("## Suggested check result"):
                validated["content"] = (
                    "## Suggested check result\n\n"
                    f"**Check performed:** {selected_check_label}\n\n"
                    f"{content}"
                ).strip()
        assistant_message_id = str(uuid4())
        with Session(engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            assert conversation is not None
            run = db_session.get(AdHocRun, run_id)
            assert run is not None
            if run.status != "running":
                return run.assistant_message_id or ""
            conversation.evidence_json = json.dumps(evidence, default=_json_default, sort_keys=True)
            conversation.updated_at = datetime.now(timezone.utc)
            db_session.add(AdHocMessage(
                id=assistant_message_id, conversation_id=conversation_id, role="assistant", actor=None,
                content=str(validated["content"]), answer_mode=str(validated["answer_mode"]),
                citations_json=json.dumps(validated["citations"], sort_keys=True),
                tool_activity_json=json.dumps(
                    {
                        "reads": activity,
                        "limitations": validated["limitations"],
                        "recommended_next_checks": validated.get("recommended_next_checks", []),
                        "suggested_followup_actions": validated.get(
                            "suggested_followup_actions", []
                        ),
                        "guidance_next_checks": validated.get("guidance_next_checks", []),
                        "investigation_gaps": [
                            gap.model_dump()
                            for gap in validated.get("investigation_gaps", [])
                            if isinstance(gap, InvestigationGap)
                        ],
                        "conclusion_status": validated.get("conclusion_status", "confirmed"),
                    }, sort_keys=True
                ),
                provider_status=provider_status,
                raw_responses_json=json.dumps(raw_responses, sort_keys=True),
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
            progress_events = list(json.loads(run.progress_json))
            progress_events.append({
                "seq": (int(progress_events[-1]["seq"]) + 1) if progress_events else 0,
                "phase": "complete",
                "message": "Investigation complete.",
                "at": datetime.now(timezone.utc).isoformat(),
            })
            run.status = "succeeded"
            run.phase = "complete"
            run.progress_json = json.dumps(progress_events[-40:], sort_keys=True)
            run.assistant_message_id = assistant_message_id
            run.completed_at = datetime.now(timezone.utc)
            db_session.commit()
        return assistant_message_id

    async def _record_run_progress(
        engine, run_id: str, phase: str, message: str
    ) -> None:
        with Session(engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.status not in {"queued", "running"}:
                return
            events = list(json.loads(run.progress_json))
            if events and events[-1].get("phase") == phase and events[-1].get("message") == message:
                return
            events.append({
                "seq": (int(events[-1]["seq"]) + 1) if events else 0,
                "phase": phase,
                "message": redact_text(message)[:500],
                "at": datetime.now(timezone.utc).isoformat(),
            })
            run.phase = phase
            run.progress_json = json.dumps(events[-40:], sort_keys=True)
            db_session.commit()

    def _fail_adhoc_run(
        engine,
        run_id: str,
        *,
        error_type: str,
        error_detail: str,
        progress_message: str,
        answer: str,
    ) -> bool:
        """Persist one terminal failure; callers may safely race or retry."""
        now = datetime.now(timezone.utc)
        with Session(engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.status not in {"queued", "running"}:
                return False
            conversation_id = run.conversation_id
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None:
                return False
            events = list(json.loads(run.progress_json))
            events.append({
                "seq": (int(events[-1]["seq"]) + 1) if events else 0,
                "phase": "failed",
                "message": progress_message,
                "at": now.isoformat(),
            })
            assistant_message_id = str(uuid4())
            claimed = db_session.execute(
                update(AdHocRun)
                .where(
                    AdHocRun.id == run_id,
                    AdHocRun.status.in_(("queued", "running")),
                )
                .values(
                    status="failed",
                    phase="failed",
                    progress_json=json.dumps(events[-40:], sort_keys=True),
                    error_detail=error_detail,
                    assistant_message_id=assistant_message_id,
                    completed_at=now,
                )
            )
            if claimed.rowcount != 1:
                db_session.rollback()
                return False
            conversation.updated_at = now
            db_session.add(AdHocMessage(
                id=assistant_message_id,
                conversation_id=conversation_id,
                role="assistant",
                actor=None,
                content=answer,
                answer_mode="insufficient_evidence",
                citations_json="[]",
                tool_activity_json=json.dumps({
                    "reads": [],
                    "limitations": [error_detail],
                }, sort_keys=True),
                provider_status="unavailable",
            ))
            db_session.add(AuditEvent(
                actor="system:podpilot",
                action="adhoc.run",
                outcome="failed",
                details_json=json.dumps({
                    "conversation_id": conversation_id,
                    "run_id": run_id,
                    "error_type": error_type,
                }, sort_keys=True),
            ))
            db_session.commit()
            return True

    def _expire_stale_adhoc_run(engine, run_id: str) -> bool:
        with Session(engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.status != "running" or run.started_at is None:
                return False
            elapsed = (datetime.now(timezone.utc) - _aware(run.started_at)).total_seconds()
        if elapsed < app_settings.adhoc_run_timeout_seconds:
            return False
        seconds = int(app_settings.adhoc_run_timeout_seconds)
        return _fail_adhoc_run(
            engine,
            run_id,
            error_type="RunTimeout",
            error_detail=f"Investigation exceeded the {seconds}-second execution deadline.",
            progress_message="The investigation reached its execution deadline.",
            answer=(
                "PodPilot stopped this investigation because it exceeded the execution deadline. "
                "No cluster changes were attempted. Retry the question or review the application logs."
            ),
        )

    def _claim_adhoc_run(engine, run_id: str | None = None) -> str | None:
        with Session(engine) as db_session:
            queued_run = aliased(AdHocRun)
            running_run = aliased(AdHocRun)
            running_for_user = (
                select(func.count(running_run.id))
                .where(
                    running_run.status == "running",
                    running_run.created_by == queued_run.created_by,
                )
                .correlate(queued_run)
                .scalar_subquery()
            )
            query = select(queued_run.id).where(
                queued_run.status == "queued",
                running_for_user < app_settings.adhoc_max_concurrent_runs_per_user,
            )
            if run_id:
                query = query.where(queued_run.id == run_id)
            selected = db_session.scalar(query.order_by(queued_run.created_at).limit(1))
            if selected is None:
                return None
            claimed = db_session.execute(
                update(AdHocRun)
                .where(AdHocRun.id == selected, AdHocRun.status == "queued")
                .values(
                    status="running",
                    phase="starting",
                    started_at=datetime.now(timezone.utc),
                    error_detail=None,
                )
            )
            db_session.commit()
            return selected if claimed.rowcount == 1 else None

    async def _run_persisted_adhoc_job(application: FastAPI, run_id: str) -> None:
        engine = application.state.engine
        with Session(engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.status != "running":
                return
            username = run.created_by
            conversation_id = run.conversation_id
            message_text = run.message_text
            include_raw_response = run.include_raw_response
            followup_action = json.loads(run.followup_action_json or "{}")

        async def report(phase: str, message: str) -> None:
            await _record_run_progress(engine, run_id, phase, message)

        try:
            await asyncio.wait_for(
                _execute_adhoc_turn(
                    engine=engine,
                    username=username,
                    conversation_id=conversation_id,
                    message_text=message_text,
                    run_id=run_id,
                    include_raw_response=include_raw_response,
                    followup_action=followup_action or None,
                    progress=report,
                ),
                timeout=app_settings.adhoc_run_timeout_seconds,
            )
        except TimeoutError:
            LOGGER.warning(
                "podpilot.adhoc.run_timed_out actor=%s conversation_id=%s run_id=%s timeout=%s",
                username,
                conversation_id,
                run_id,
                app_settings.adhoc_run_timeout_seconds,
            )
            seconds = int(app_settings.adhoc_run_timeout_seconds)
            _fail_adhoc_run(
                engine,
                run_id,
                error_type="RunTimeout",
                error_detail=f"Investigation exceeded the {seconds}-second execution deadline.",
                progress_message="The investigation reached its execution deadline.",
                answer=(
                    "PodPilot stopped this investigation because it exceeded the execution deadline. "
                    "No cluster changes were attempted. Retry the question or review the application logs."
                ),
            )
        except Exception as exc:
            LOGGER.error(
                "podpilot.adhoc.run_failed actor=%s conversation_id=%s run_id=%s error_type=%s",
                username,
                conversation_id,
                run_id,
                type(exc).__name__,
            )
            _fail_adhoc_run(
                engine,
                run_id,
                error_type=type(exc).__name__,
                error_detail=f"Internal job failure ({type(exc).__name__}).",
                progress_message="The investigation could not be completed.",
                answer=(
                    "PodPilot could not complete this investigation. No cluster changes were "
                    "attempted. Retry the question or review the application logs."
                ),
            )

    async def _adhoc_worker(application: FastAPI, worker_number: int) -> None:
        wake = application.state.adhoc_wake
        while True:
            wake.clear()
            run_id = _claim_adhoc_run(application.state.engine)
            if run_id is not None:
                LOGGER.info(
                    "podpilot.adhoc.worker_claimed worker=%s run_id=%s",
                    worker_number,
                    run_id,
                )
                await _run_persisted_adhoc_job(application, run_id)
                continue
            try:
                await asyncio.wait_for(wake.wait(), timeout=1.0)
            except TimeoutError:
                pass

    def _queue_adhoc_run(
        db_session: Session,
        *,
        conversation: AdHocConversation,
        username: str,
        message_text: str,
        include_raw_response: bool = False,
        followup_action: dict[str, object] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        _enforce_adhoc_rate_limit(
            db_session,
            username=username,
            now=now,
            limit=app_settings.adhoc_rate_limit_per_minute,
        )
        active = db_session.scalar(
            select(func.count()).select_from(AdHocRun).where(
                AdHocRun.conversation_id == conversation.id,
                AdHocRun.status.in_(("queued", "running")),
            )
        ) or 0
        if active:
            raise HTTPException(
                status_code=409,
                detail="Wait for the current PodPilot investigation to finish.",
            )
        run_id = str(uuid4())
        events = [{
            "seq": 0,
            "phase": "queued",
            "message": (
                "Question queued. It will start automatically when the investigation "
                "worker is available."
            ),
            "at": now.isoformat(),
        }]
        db_session.add(AdHocMessage(
            id=str(uuid4()),
            conversation_id=conversation.id,
            role="user",
            actor=username,
            content=message_text,
        ))
        db_session.add(AdHocRun(
            id=run_id,
            conversation_id=conversation.id,
            created_by=username,
            message_text=message_text,
            include_raw_response=include_raw_response,
            followup_action_json=json.dumps(followup_action or {}, sort_keys=True),
            status="queued",
            phase="queued",
            progress_json=json.dumps(events, sort_keys=True),
        ))
        db_session.add(AuditEvent(
            actor=username,
            action="adhoc.message",
            outcome="accepted",
            details_json=json.dumps({
                "conversation_id": conversation.id,
                "run_id": run_id,
                "cluster_ids": json.loads(conversation.cluster_ids_json or "[]"),
                "raw_response_requested": include_raw_response,
                "followup_action_id": (
                    str(followup_action.get("id")) if followup_action else None
                ),
            }, sort_keys=True),
        ))
        conversation.updated_at = now
        return run_id

    async def _start_queued_run(request: Request, run_id: str) -> None:
        if app_settings.adhoc_job_worker_enabled:
            request.app.state.adhoc_wake.set()
            return
        claimed = _claim_adhoc_run(request.app.state.engine, run_id)
        if claimed:
            await _run_persisted_adhoc_job(request.app, claimed)

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
            profile = _active_profile(db_session)
            available_clusters = list(db_session.scalars(
                select(Cluster).where(Cluster.is_enabled.is_(True)).order_by(Cluster.name)
            ))
        response = templates.TemplateResponse(
            request=request, name="ask.html", context={
                "user": user, "conversation": None, "messages": [], "evidence_by_id": {},
                "recent_conversations": recent, "csrf_token": csrf_token,
                "chat_max_chars": app_settings.chat_max_chars,
                "chat_read_budget": app_settings.adhoc_max_reads_per_turn,
                "model_ready": bool(profile and profile.status == "ready"),
                "active_run": None,
                "clusters": [_cluster_summary(item) for item in available_clusters],
                "selected_cluster_ids": [SYSTEM_CLUSTER_ID],
                "max_selected_clusters": app_settings.adhoc_max_clusters_per_conversation,
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
            evidence_by_id = {
                str(item["id"]): _adhoc_evidence_view(item)
                for item in evidence
                if isinstance(item, dict) and item.get("id")
            }
            recent = list(db_session.scalars(
                select(AdHocConversation).where(AdHocConversation.created_by == user.username)
                .order_by(AdHocConversation.updated_at.desc()).limit(20)
            ))
            profile = _active_profile(db_session)
            active_run_row = db_session.scalar(
                select(AdHocRun).where(
                    AdHocRun.conversation_id == conversation_id,
                    AdHocRun.status.in_(("queued", "running")),
                ).order_by(AdHocRun.created_at.desc()).limit(1)
            )
            conversation_cluster_ids = list(json.loads(conversation.cluster_ids_json or "[]"))
            available_clusters = list(db_session.scalars(
                select(Cluster).where(
                    (Cluster.is_enabled.is_(True)) | (Cluster.id.in_(conversation_cluster_ids))
                ).order_by(Cluster.name)
            ))
        messages = [{
            "id": row.id, "role": row.role, "actor": row.actor, "content": row.content,
            "answer_mode": row.answer_mode, "citations": json.loads(row.citations_json),
            "activity": json.loads(row.tool_activity_json), "provider_status": row.provider_status,
            "raw_responses": json.loads(row.raw_responses_json or "[]"),
            "created_at": row.created_at,
        } for row in rows]
        response = templates.TemplateResponse(
            request=request, name="ask.html", context={
                "user": user, "conversation": conversation, "messages": messages,
                "evidence_by_id": evidence_by_id,
                "recent_conversations": recent, "csrf_token": csrf_token,
                "chat_max_chars": app_settings.chat_max_chars,
                "chat_read_budget": app_settings.adhoc_max_reads_per_turn,
                "model_ready": bool(profile and profile.status == "ready"),
                "messages_truncated": conversation.summarized_message_count > 0,
                "adhoc_run_timeout_seconds": app_settings.adhoc_run_timeout_seconds,
                "active_run": ({
                    "id": active_run_row.id,
                    "status": active_run_row.status,
                    "phase": active_run_row.phase,
                    "include_raw_response": active_run_row.include_raw_response,
                    "events": json.loads(active_run_row.progress_json),
                } if active_run_row else None),
                "clusters": [_cluster_summary(item) for item in available_clusters],
                "selected_cluster_ids": conversation_cluster_ids,
                "max_selected_clusters": app_settings.adhoc_max_clusters_per_conversation,
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
        include_raw_response = form.get("include_raw_response", "").lower() in {
            "1", "true", "on", "yes"
        }
        try:
            requested_cluster_ids = [
                str(item) for item in json.loads(
                    form.get("cluster_ids", json.dumps([SYSTEM_CLUSTER_ID]))
                )
            ]
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Select one or more valid clusters.") from exc
        requested_cluster_ids = list(dict.fromkeys(requested_cluster_ids))
        if not requested_cluster_ids or len(requested_cluster_ids) > app_settings.adhoc_max_clusters_per_conversation:
            raise HTTPException(
                status_code=422,
                detail=f"Select between 1 and {app_settings.adhoc_max_clusters_per_conversation} clusters.",
            )
        conversation_id = str(uuid4())
        with Session(request.app.state.engine) as db_session:
            valid_cluster_count = db_session.scalar(
                select(func.count()).select_from(Cluster).where(
                    Cluster.id.in_(requested_cluster_ids), Cluster.is_enabled.is_(True)
                )
            ) or 0
            if valid_cluster_count != len(requested_cluster_ids):
                raise HTTPException(status_code=422, detail="One or more selected clusters are unavailable.")
            conversation = AdHocConversation(
                id=conversation_id, created_by=user.username,
                title=message.replace("\n", " ")[:100], status="active", evidence_json="[]",
                cluster_ids_json=json.dumps(requested_cluster_ids),
            )
            db_session.add(conversation)
            run_id = _queue_adhoc_run(
                db_session,
                conversation=conversation,
                username=user.username,
                message_text=message,
                include_raw_response=include_raw_response,
            )
            db_session.commit()
        await _start_queued_run(request, run_id)
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
        message = redact_text(raw_message)[:app_settings.chat_max_chars]
        include_raw_response = form.get("include_raw_response", "").lower() in {
            "1", "true", "on", "yes"
        }
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None or conversation.created_by != user.username:
                raise HTTPException(
                    status_code=404,
                    detail="That PodPilot conversation does not exist.",
                )
            run_id = _queue_adhoc_run(
                db_session,
                conversation=conversation,
                username=user.username,
                message_text=message,
                include_raw_response=include_raw_response,
            )
            db_session.commit()
        await _start_queued_run(request, run_id)
        return RedirectResponse(f"/ask/{conversation_id}", status_code=303)

    @app.post(
        "/api/v1/adhoc-conversations/{conversation_id}/messages/"
        "{message_id}/followups/{action_id}"
    )
    async def run_adhoc_suggested_followup(
        conversation_id: str,
        message_id: str,
        action_id: str,
        request: Request,
        user: AuthContext = Depends(current_user),
    ) -> RedirectResponse:
        _verify_csrf(request)
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(
                status_code=403,
                detail="Suggested checks require the Investigator role or higher.",
            )
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            message = db_session.get(AdHocMessage, message_id)
            if (
                conversation is None
                or conversation.created_by != user.username
                or message is None
                or message.conversation_id != conversation_id
                or message.role != "assistant"
            ):
                raise HTTPException(
                    status_code=404,
                    detail="That suggested check does not exist.",
                )
            activity = json.loads(message.tool_activity_json or "{}")
            actions = activity.get("suggested_followup_actions") or []
            action = next((
                item for item in actions
                if isinstance(item, dict) and str(item.get("id")) == action_id
            ), None)
            if action is None:
                raise HTTPException(
                    status_code=404,
                    detail="That suggested check is no longer available.",
                )
            cluster_ids = set(json.loads(conversation.cluster_ids_json or "[]"))
            if not cluster_ids:
                cluster_ids = {SYSTEM_CLUSTER_ID}
            capability = str(action.get("capability") or "")
            label = redact_text(str(action.get("label") or ""))[:500]
            if (
                str(action.get("cluster_id") or "") not in cluster_ids
                or capability not in {
                    "resource_read", "service_spec", "endpoints", "pod_spec",
                    "pod_logs", "metrics", "http_probe",
                }
                or not label
                or _MUTATING_RECOMMENDATION.search(label)
            ):
                raise HTTPException(
                    status_code=409,
                    detail="The suggested check is not an eligible read-only action.",
                )
            raw_supporting_ids = action.get("supporting_evidence_ids")
            supporting_ids = raw_supporting_ids if isinstance(raw_supporting_ids, list) else []
            source_user_message = db_session.scalar(
                select(AdHocMessage).where(
                    AdHocMessage.conversation_id == conversation_id,
                    AdHocMessage.role == "user",
                    AdHocMessage.created_at <= message.created_at,
                ).order_by(
                    AdHocMessage.created_at.desc(), AdHocMessage.id.desc()
                ).limit(1)
            )
            source_question = redact_text(
                source_user_message.content if source_user_message is not None else label
            )[:app_settings.chat_max_chars]
            objective = f"Run suggested check: {label}"[:app_settings.chat_max_chars]
            run_id = _queue_adhoc_run(
                db_session,
                conversation=conversation,
                username=user.username,
                message_text=objective,
                followup_action={
                    "id": str(action["id"]),
                    "cluster_id": str(action["cluster_id"]),
                    "cluster_name": redact_text(str(action.get("cluster_name") or ""))[:253],
                    "capability": capability,
                    "label": label,
                    "target": redact_text(str(action.get("target") or ""))[:500],
                    "supporting_evidence_ids": [
                        str(item)[:128]
                        for item in supporting_ids[:8]
                    ],
                    "source_message_id": message_id,
                    "source_question": source_question,
                },
            )
            db_session.commit()
        await _start_queued_run(request, run_id)
        return RedirectResponse(f"/ask/{conversation_id}", status_code=303)

    @app.get("/api/v1/adhoc-runs/{run_id}")
    async def adhoc_run_status(
        run_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> JSONResponse:
        with Session(request.app.state.engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot run does not exist.")
        _expire_stale_adhoc_run(request.app.state.engine, run_id)
        with Session(request.app.state.engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            assert run is not None
            return JSONResponse({
                "id": run.id,
                "conversation_id": run.conversation_id,
                "status": run.status,
                "phase": run.phase,
                "events": json.loads(run.progress_json),
                "location": f"/ask/{run.conversation_id}",
            })

    @app.get("/api/v1/adhoc-runs/{run_id}/events")
    async def adhoc_run_events(
        run_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> StreamingResponse:
        with Session(request.app.state.engine) as db_session:
            run = db_session.get(AdHocRun, run_id)
            if run is None or run.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot run does not exist.")

        try:
            last_event_id = int(request.headers.get("last-event-id", "-1"))
        except ValueError:
            last_event_id = -1

        async def stream() -> AsyncIterator[str]:
            last_seen = last_event_id
            heartbeat_at = datetime.now(timezone.utc)
            while True:
                if await request.is_disconnected():
                    return
                _expire_stale_adhoc_run(request.app.state.engine, run_id)
                with Session(request.app.state.engine) as db_session:
                    current = db_session.get(AdHocRun, run_id)
                    if current is None or current.created_by != user.username:
                        return
                    events = list(json.loads(current.progress_json))
                    status_value = current.status
                    location = f"/ask/{current.conversation_id}"
                for event in events:
                    seq = int(event.get("seq", -1))
                    if seq <= last_seen:
                        continue
                    last_seen = seq
                    yield (
                        f"id: {seq}\n"
                        "event: progress\n"
                        f"data: {json.dumps(event, sort_keys=True)}\n\n"
                    )
                if status_value in {"succeeded", "failed"}:
                    yield (
                        "event: complete\n"
                        f"data: {json.dumps({'status': status_value, 'location': location})}\n\n"
                    )
                    return
                now = datetime.now(timezone.utc)
                if (now - heartbeat_at).total_seconds() >= 10:
                    yield ": heartbeat\n\n"
                    heartbeat_at = now
                await asyncio.sleep(0.5)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/v1/adhoc-conversations/{conversation_id}/delete")
    async def delete_adhoc_conversation(
        conversation_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> RedirectResponse:
        _verify_csrf(request)
        with Session(request.app.state.engine) as db_session:
            conversation = db_session.get(AdHocConversation, conversation_id)
            if conversation is None or conversation.created_by != user.username:
                raise HTTPException(status_code=404, detail="That PodPilot conversation does not exist.")
            active_runs = db_session.scalar(
                select(func.count()).select_from(AdHocRun).where(
                    AdHocRun.conversation_id == conversation_id,
                    AdHocRun.status.in_(("queued", "running")),
                )
            ) or 0
            if active_runs:
                raise HTTPException(
                    status_code=409,
                    detail="Wait for the current investigation before deleting this conversation.",
                )
            db_session.execute(
                delete(AdHocRun).where(AdHocRun.conversation_id == conversation_id)
            )
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

    @app.get("/settings/clusters", response_class=HTMLResponse)
    async def cluster_settings(
        request: Request, user: AuthContext = Depends(current_user)
    ):
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Cluster management requires the Approver role or higher.")
        csrf_token, csrf_is_new = _csrf_token(request)
        edit_id = request.query_params.get("edit", "").strip()
        with Session(request.app.state.engine) as db_session:
            rows = list(db_session.scalars(select(Cluster).order_by(Cluster.name)))
        clusters_view = [_cluster_summary(item) for item in rows]
        selected = next((item for item in clusters_view if item["id"] == edit_id), None)
        response = templates.TemplateResponse(
            request=request,
            name="cluster_settings.html",
            context={
                "user": user,
                "clusters": clusters_view,
                "selected": selected,
                "csrf_token": csrf_token,
            },
        )
        if csrf_is_new:
            response.set_cookie(
                CSRF_COOKIE, csrf_token, secure=app_settings.auth_mode == "proxy",
                httponly=True, samesite="strict", max_age=28_800,
            )
        return response

    @app.post("/api/v1/clusters")
    async def save_cluster(
        request: Request, user: AuthContext = Depends(current_user)
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Cluster management requires the Approver role or higher.")
        form = await _urlencoded(request)
        cluster_id = form.get("cluster_id", "").strip()
        name = redact_text(form.get("name", "").strip())[:253]
        api_url = _validated_cluster_api_url(form.get("api_url", ""))
        token = form.get("token", "").strip()
        tags = _parse_tags(form.get("tags_json", "{}"), field_name="Cluster tags")
        tls_verify = form.get("tls_verify", "true").strip().lower() == "true"
        if not name:
            raise HTTPException(status_code=422, detail="Cluster name is required.")
        if token and not (8 <= len(token) <= 16_384):
            raise HTTPException(status_code=422, detail="Cluster token length is invalid.")
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id) if cluster_id else None
            if cluster_id and cluster is None:
                raise HTTPException(status_code=404, detail="Cluster entry not found.")
            if cluster is not None and cluster.is_system:
                raise HTTPException(status_code=409, detail="The runtime system cluster cannot be modified here.")
            if cluster is not None and not cluster.is_enabled and not token:
                raise HTTPException(
                    status_code=422,
                    detail="A new bearer token is required when re-enabling a disabled cluster.",
                )
            duplicate = db_session.scalar(select(Cluster).where(Cluster.name == name))
            if duplicate is not None and (cluster is None or duplicate.id != cluster.id):
                raise HTTPException(status_code=409, detail="A cluster with that name already exists.")
            if cluster is None:
                if not token:
                    raise HTTPException(status_code=422, detail="A bearer token is required for a new cluster.")
                cluster_id = str(uuid4())
                credential_key = f"cluster_{cluster_id.replace('-', '')}"
                cluster = Cluster(
                    id=cluster_id,
                    name=name,
                    api_url=api_url,
                    credential_key=credential_key,
                    tags_json=json.dumps(tags, sort_keys=True),
                    tls_verify=tls_verify,
                    is_enabled=True,
                    is_system=False,
                    status="not_tested",
                    created_by=user.username,
                    updated_by=user.username,
                    created_at=now,
                    updated_at=now,
                )
                action = "cluster.create"
                db_session.add(cluster)
            else:
                credential_key = cluster.credential_key
                cluster.name = name
                cluster.api_url = api_url
                cluster.tags_json = json.dumps(tags, sort_keys=True)
                cluster.tls_verify = tls_verify
                cluster.is_enabled = True
                cluster.status = "not_tested"
                cluster.last_error = None
                cluster.updated_by = user.username
                cluster.updated_at = now
                action = "cluster.update"
            assert credential_key
            if token:
                try:
                    await run_in_threadpool(cluster_credentials.set, token, credential_key)
                except CredentialStoreError as exc:
                    LOGGER.warning(
                        "Cluster credential save failed for cluster=%r actor=%r: %s",
                        name,
                        user.username,
                        exc,
                        exc_info=True,
                    )
                    raise HTTPException(status_code=503, detail=str(exc)) from exc
            db_session.add(AuditEvent(
                actor=user.username,
                action=action,
                outcome="saved",
                details_json=json.dumps({
                    "cluster_id": cluster.id,
                    "name": name,
                    "tag_keys": sorted(tags),
                    "tls_verify": tls_verify,
                    "token_rotated": bool(token),
                }, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({"status": "saved", "cluster_id": cluster_id})

    @app.post("/api/v1/clusters/{cluster_id}/rename")
    async def rename_runtime_cluster(
        cluster_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Cluster management requires the Approver role or higher.")
        form = await _urlencoded(request)
        name = redact_text(form.get("name", "").strip())[:253]
        if not name:
            raise HTTPException(status_code=422, detail="Cluster name is required.")
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id)
            if cluster is None:
                raise HTTPException(status_code=404, detail="Cluster entry not found.")
            if not cluster.is_system:
                raise HTTPException(
                    status_code=409,
                    detail="Only the runtime system cluster can be renamed through this endpoint.",
                )
            duplicate = db_session.scalar(select(Cluster).where(Cluster.name == name))
            if duplicate is not None and duplicate.id != cluster.id:
                raise HTTPException(status_code=409, detail="A cluster with that name already exists.")
            previous_name = cluster.name
            cluster.name = name
            cluster.updated_by = user.username
            cluster.updated_at = now
            db_session.add(AuditEvent(
                actor=user.username,
                action="cluster.rename",
                outcome="saved",
                details_json=json.dumps({
                    "cluster_id": cluster.id,
                    "previous_name": previous_name,
                    "name": name,
                }, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({
            "status": "saved",
            "cluster_id": cluster_id,
            "name": name,
            "detail": "Runtime cluster renamed.",
        })

    @app.post("/api/v1/clusters/{cluster_id}/test")
    async def test_cluster_connection(
        cluster_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Cluster management requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id)
            if cluster is None:
                raise HTTPException(status_code=404, detail="Cluster entry not found.")
            if not cluster.is_enabled:
                raise HTTPException(status_code=409, detail="Enable and save the cluster before testing it.")
            cluster_snapshot = _cluster_summary(cluster)
            credential_key = cluster.credential_key
            is_system = cluster.is_system
        status_value = "ready"
        error_detail = None
        try:
            reader: ReadOnlyExplorer = cluster_reader
            if not is_system:
                token = await run_in_threadpool(cluster_credentials.get, credential_key)
                if not token:
                    raise ReadOnlyExplorerError("The cluster token is unavailable.")
                reader = remote_cluster_reader(cluster, token)
            await run_in_threadpool(reader.resource_catalog, query="namespaces", limit=1)
        except Exception as exc:
            status_value = "unavailable"
            if isinstance(exc, (ReadOnlyExplorerError, CredentialStoreError)):
                error_detail = redact_text(str(exc))[:500] or type(exc).__name__
            else:
                error_detail = (
                    "The cluster connection test failed before read-only discovery completed. "
                    "Check the API pod logs for the failure category."
                )
            LOGGER.warning(
                "Cluster connection test failed for cluster=%r actor=%r error_type=%s detail=%s",
                cluster_snapshot["name"],
                user.username,
                type(exc).__name__,
                error_detail,
            )
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id)
            assert cluster is not None
            cluster.status = status_value
            cluster.last_error = error_detail
            cluster.last_tested_at = now
            cluster.updated_by = user.username
            cluster.updated_at = now
            db_session.add(AuditEvent(
                actor=user.username,
                action="cluster.test",
                outcome=status_value,
                details_json=json.dumps({
                    "cluster_id": cluster_id,
                    "tls_verify": cluster_snapshot["tls_verify"],
                }, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({
            "status": status_value,
            "detail": error_detail or "Authenticated Kubernetes API discovery succeeded.",
        })

    @app.post("/api/v1/clusters/{cluster_id}/disable")
    async def disable_cluster(
        cluster_id: str, request: Request, user: AuthContext = Depends(current_user)
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Cluster management requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id)
            if cluster is None:
                raise HTTPException(status_code=404, detail="Cluster entry not found.")
            if cluster.is_system:
                raise HTTPException(status_code=409, detail="The runtime system cluster cannot be disabled.")
            credential_key = cluster.credential_key
            if credential_key:
                try:
                    await run_in_threadpool(cluster_credentials.delete, credential_key)
                except CredentialStoreError as exc:
                    raise HTTPException(status_code=503, detail=str(exc)) from exc
            cluster.is_enabled = False
            cluster.status = "disabled"
            cluster.last_error = None
            cluster.updated_by = user.username
            cluster.updated_at = datetime.now(timezone.utc)
            db_session.add(AuditEvent(
                actor=user.username,
                action="cluster.disable",
                outcome="disabled",
                details_json=json.dumps({"cluster_id": cluster_id}, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({"status": "disabled", "cluster_id": cluster_id})

    @app.get("/settings/model", response_class=HTMLResponse)
    async def model_settings(
        request: Request,
        user: AuthContext = Depends(current_user),
    ):
        csrf_token, csrf_is_new = _csrf_token(request)
        with Session(request.app.state.engine) as db_session:
            rows = list(db_session.scalars(select(ModelProfile).order_by(ModelProfile.id)))
            requested_id = request.query_params.get("edit")
            profile = next((row for row in rows if str(row.id) == requested_id), None)
            if profile is None and request.query_params.get("new") != "1":
                profile = next((row for row in rows if row.is_active), None)
            def view(row: ModelProfile) -> dict[str, object]:
                return {
                    "id": row.id,
                    "provider_label": row.provider_label,
                    "base_url": row.base_url, "chat_model": row.chat_model,
                    "embedding_model": row.embedding_model or "", "api_type": row.api_type,
                    "tls_mode": row.tls_mode, "custom_ca_pem": row.custom_ca_pem or "",
                    "max_input_tokens": row.max_input_tokens,
                    "max_output_tokens": row.max_output_tokens,
                    "timeout_seconds": row.timeout_seconds, "status": row.status,
                    "capabilities": json.loads(row.capabilities_json),
                    "tool_calling_hint": row.tool_calling_hint, "vision_hint": row.vision_hint,
                    "is_active": row.is_active, "last_error": row.last_error,
                    "last_probe_at": row.last_probe_at, "updated_by": row.updated_by,
                    "updated_at": row.updated_at,
                }
            profile_view = view(profile) if profile else None
            profile_views = [view(row) for row in rows]
        credential_error = None
        try:
            token_configured = bool(credentials.get(profile.credential_key)) if profile else False
        except CredentialStoreError as exc:
            token_configured = False
            credential_error = str(exc)
        response = templates.TemplateResponse(
            request=request,
            name="model_settings.html",
            context={
                "user": user,
                "profile": profile_view,
                "profiles": profile_views,
                "token_configured": token_configured,
                "credential_error": credential_error,
                "model_timeout_max_seconds": app_settings.model_timeout_max_seconds,
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
        profile_id_text = form.get("profile_id", "").strip()
        provider_label = form.get("provider_label", "").strip()
        base_url = form.get("base_url", "").strip().rstrip("/")
        chat_model = form.get("chat_model", "").strip()
        embedding_model = form.get("embedding_model", "").strip() or None
        token = form.get("api_token", "").strip()
        api_type = form.get("api_type", "responses").strip()
        tls_mode = form.get("tls_mode", "system").strip()
        custom_ca_pem = form.get("custom_ca_pem", "").strip() or None
        if not provider_label or len(provider_label) > 100:
            raise HTTPException(status_code=422, detail="Provider label is required and must be at most 100 characters.")
        try:
            validate_model_endpoint(base_url, tls_mode)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not chat_model or len(chat_model) > 253:
            raise HTTPException(status_code=422, detail="A valid chat model name is required.")
        if api_type not in {"responses", "chat-completions"}:
            raise HTTPException(status_code=422, detail="API type must be Responses or Chat Completions.")
        if tls_mode not in {"system", "custom_ca", "insecure", "plaintext"}:
            raise HTTPException(status_code=422, detail="TLS mode is invalid.")
        if tls_mode == "custom_ca" and not custom_ca_pem:
            raise HTTPException(status_code=422, detail="Custom-CA mode requires a PEM CA bundle.")
        if custom_ca_pem and len(custom_ca_pem) > 65_536:
            raise HTTPException(status_code=422, detail="The custom CA bundle is too large.")
        if custom_ca_pem and "PRIVATE KEY" in custom_ca_pem.upper():
            raise HTTPException(status_code=422, detail="Custom CA input must not contain a private key.")
        try:
            timeout_seconds = float(form.get("timeout_seconds", "30"))
            max_input_tokens = int(form.get("max_input_tokens", "128000"))
            max_output_tokens = int(form.get("max_output_tokens", "1200"))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Timeout and token budget must be numeric.") from exc
        if (not 3 <= timeout_seconds <= app_settings.model_timeout_max_seconds
                or not 1_024 <= max_input_tokens <= 2_000_000
                or not 128 <= max_output_tokens <= 131_072):
            raise HTTPException(status_code=422, detail="Timeout or token budget is outside the allowed range.")
        try:
            profile_id = int(profile_id_text) if profile_id_text else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Model profile ID is invalid.") from exc
        with Session(request.app.state.engine) as db_session:
            existing_profile = db_session.get(ModelProfile, profile_id) if profile_id else None
            if profile_id and existing_profile is None:
                raise HTTPException(status_code=404, detail="Model profile not found.")
            credential_key = (
                existing_profile.credential_key if existing_profile else f"model_{uuid4().hex}"
            )
        if token:
            if len(token) < 8 or len(token) > 8192:
                raise HTTPException(status_code=422, detail="The submitted token length is invalid.")
            try:
                await run_in_threadpool(credentials.set, token, credential_key)
            except CredentialStoreError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        else:
            try:
                if not await run_in_threadpool(credentials.get, credential_key):
                    raise HTTPException(status_code=422, detail="An API token is required for the first profile save.")
            except CredentialStoreError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc

        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id) if profile_id else None
            if profile is None:
                profile = ModelProfile(
                    updated_by=user.username, credential_key=credential_key,
                    is_active=db_session.scalar(select(func.count(ModelProfile.id))) == 0,
                )
            profile.provider_label = provider_label
            profile.base_url = base_url
            profile.chat_model = chat_model
            profile.embedding_model = embedding_model
            profile.api_type = api_type
            profile.tls_mode = tls_mode
            profile.custom_ca_pem = custom_ca_pem if tls_mode == "custom_ca" else None
            profile.max_input_tokens = max_input_tokens
            profile.tool_calling_hint = form.get("tool_calling_hint") == "true"
            profile.vision_hint = form.get("vision_hint") == "true"
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
            saved_profile_id = profile.id
        return JSONResponse({"status": "saved", "token_configured": True, "profile_id": saved_profile_id})

    @app.post("/api/v1/model-profiles/{profile_id}/probe")
    @app.post("/api/v1/model-profile/probe")
    async def probe_model_profile(
        request: Request,
        profile_id: int | None = None,
        user: AuthContext = Depends(current_user),
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Testing model settings requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id) if profile_id else _active_profile(db_session)
            if profile is None:
                raise HTTPException(status_code=409, detail="Save a model profile before testing it.")
            config_snapshot = _profile_config(profile)
            credential_key = profile.credential_key
            provider_label = profile.provider_label
        LOGGER.info(
            "podpilot.model_probe.start actor=%s profile_id=%s provider=%s api_type=%s model=%s",
            user.username,
            profile_id,
            provider_label,
            config_snapshot.api_type,
            config_snapshot.chat_model,
        )
        try:
            api_key = await run_in_threadpool(credentials.get, credential_key)
            if not api_key:
                raise ModelProviderError("No model API token is configured.")
            report = await run_in_threadpool(provider.probe, config_snapshot, api_key)
            outcome = "ready" if report.ready else "reduced_capability"
            capabilities = report.to_dict()
            error = None if report.ready else (
                report.ask_schema_error
                or "The endpoint lacks one or more required capabilities."
            )
            log_method = LOGGER.info if report.ready else LOGGER.warning
            log_method(
                "podpilot.model_probe.complete actor=%s profile_id=%s outcome=%s "
                "structured_output=%s ask_schemas=%s streaming=%s tool_calls=%s error=%s",
                user.username,
                profile_id,
                outcome,
                report.structured_output,
                report.ask_schemas,
                report.streaming,
                report.tool_calls,
                error,
            )
        except (CredentialStoreError, ModelProviderError) as exc:
            outcome = "unavailable"
            capabilities = {}
            error = str(exc)
            LOGGER.warning(
                "podpilot.model_probe.failed actor=%s profile_id=%s error=%s",
                user.username,
                profile_id,
                error,
            )
        now = datetime.now(timezone.utc)
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id) if profile_id else _active_profile(db_session)
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

    @app.post("/api/v1/model-profiles/{profile_id}/activate")
    async def activate_model_profile(request: Request, profile_id: int, user: AuthContext = Depends(current_user)):
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Activating models requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id)
            if profile is None:
                raise HTTPException(status_code=404, detail="Model profile not found.")
            if profile.status != "ready":
                raise HTTPException(status_code=409, detail="Test the model successfully before activation.")
            db_session.execute(update(ModelProfile).values(is_active=False))
            profile.is_active = True
            db_session.add(AuditEvent(actor=user.username, action="model_profile.activate", outcome="ready", details_json=json.dumps({"profile_id": profile.id})))
            db_session.commit()
        return JSONResponse({"status": "active", "profile_id": profile_id})

    @app.post("/api/v1/model-profiles/{profile_id}/delete")
    async def delete_model_profile(request: Request, profile_id: int, user: AuthContext = Depends(current_user)):
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Deleting models requires the Approver role or higher.")
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id)
            if profile is None:
                raise HTTPException(status_code=404, detail="Model profile not found.")
            credential_key = profile.credential_key
        try:
            await run_in_threadpool(credentials.delete, credential_key)
        except CredentialStoreError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        with Session(request.app.state.engine) as db_session:
            profile = db_session.get(ModelProfile, profile_id)
            if profile is None:
                raise HTTPException(status_code=409, detail="The model profile changed before deletion.")
            was_active = profile.is_active
            db_session.delete(profile)
            replacement = None
            if was_active:
                replacement = db_session.scalar(
                    select(ModelProfile)
                    .where(ModelProfile.id != profile_id, ModelProfile.status == "ready")
                    .order_by(ModelProfile.last_probe_at.desc(), ModelProfile.updated_at.desc())
                    .limit(1)
                )
                if replacement:
                    replacement.is_active = True
            replacement_id = replacement.id if replacement else None
            db_session.add(AuditEvent(
                actor=user.username,
                action="model_profile.delete",
                outcome="deleted",
                details_json=json.dumps({
                    "profile_id": profile_id,
                    "was_active": was_active,
                    "activated_profile_id": replacement_id,
                }),
            ))
            db_session.commit()
        response = {"status": "deleted"}
        if was_active:
            response["activated_profile_id"] = replacement_id
        return JSONResponse(response)

    @app.get("/memory", response_class=HTMLResponse)
    async def cluster_memory(request: Request, user: AuthContext = Depends(current_user)):
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(status_code=403, detail="Cluster memory requires the Investigator role or higher.")
        csrf_token, csrf_is_new = _csrf_token(request)
        query = request.query_params.get("q", "").strip()[:500]
        namespace = request.query_params.get("namespace", "").strip()[:253] or None
        edit_id = request.query_params.get("edit", "").strip()
        preview_cluster_id = request.query_params.get("cluster_id", SYSTEM_CLUSTER_ID).strip()
        with Session(request.app.state.engine) as db_session:
            clusters = list(db_session.scalars(select(Cluster).order_by(Cluster.name)))
            preview_cluster = next((item for item in clusters if item.id == preview_cluster_id), None)
            if preview_cluster is None:
                preview_cluster = next((item for item in clusters if item.id == SYSTEM_CLUSTER_ID), None)
            assert preview_cluster is not None
            document_query = select(KnowledgeDocument).where(KnowledgeDocument.is_current.is_(True))
            if user.role < Role.APPROVER:
                document_query = document_query.where(
                    KnowledgeDocument.sensitivity != "restricted",
                    KnowledgeDocument.is_enabled.is_(True),
                    KnowledgeDocument.verification_state == "reviewed",
                    (KnowledgeDocument.expires_at.is_(None))
                    | (KnowledgeDocument.expires_at > datetime.now(timezone.utc)),
                )
                if namespace:
                    document_query = document_query.where(
                        (KnowledgeDocument.namespace.is_(None))
                        | (KnowledgeDocument.namespace == namespace)
                    )
                else:
                    document_query = document_query.where(KnowledgeDocument.namespace.is_(None))
            documents = list(db_session.scalars(
                document_query
                .order_by(KnowledgeDocument.title, KnowledgeDocument.created_at.desc())
            ))
            if user.role < Role.APPROVER:
                preview_tags = json.loads(preview_cluster.tags_json or "{}")
                documents = [item for item in documents if knowledge_applies_to(
                    target_cluster_ids_json=item.target_cluster_ids_json,
                    target_tags_json=item.target_tags_json,
                    cluster_id=preview_cluster.id,
                    cluster_tags=preview_tags,
                )]
            selected = next((item for item in documents if item.id == edit_id), None)
            results = search_knowledge(
                db_session, query=query, cluster_id=preview_cluster.id,
                cluster_tags=json.loads(preview_cluster.tags_json or "{}"),
                namespace=namespace, include_restricted=user.role >= Role.APPROVER,
            ) if query else []
        response = templates.TemplateResponse(
            request=request,
            name="cluster_memory.html",
            context={
                "user": user, "documents": documents, "selected": selected,
                "results": results, "query": query, "namespace": namespace or "",
                "cluster_id": preview_cluster.id, "cluster_name": preview_cluster.name,
                "clusters": [_cluster_summary(item) for item in clusters],
                "selected_target_ids": (
                    json.loads(selected.target_cluster_ids_json or "[]") if selected else []
                ),
                "selected_target_tags": (
                    json.loads(selected.target_tags_json or "{}") if selected else {}
                ),
                "csrf_token": csrf_token,
            },
        )
        if csrf_is_new:
            response.set_cookie(
                CSRF_COOKIE, csrf_token, secure=app_settings.auth_mode == "proxy",
                httponly=True, samesite="strict", max_age=28_800,
            )
        return response

    @app.get("/api/v1/knowledge/search")
    async def knowledge_search(
        request: Request, q: str, namespace: str | None = None,
        cluster_id: str = SYSTEM_CLUSTER_ID,
        user: AuthContext = Depends(current_user),
    ) -> JSONResponse:
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(status_code=403, detail="Knowledge search requires the Investigator role or higher.")
        query = q.strip()
        if not query or len(query) > 500:
            raise HTTPException(status_code=422, detail="Search text must be between 1 and 500 characters.")
        bounded_namespace = namespace.strip()[:253] if namespace else None
        with Session(request.app.state.engine) as db_session:
            cluster = db_session.get(Cluster, cluster_id)
            if cluster is None:
                raise HTTPException(status_code=404, detail="Cluster entry not found.")
            results = search_knowledge(
                db_session, query=query, cluster_id=cluster.id,
                cluster_tags=json.loads(cluster.tags_json or "{}"),
                namespace=bounded_namespace, include_restricted=user.role >= Role.APPROVER,
            )
        return JSONResponse({
            "query": query, "cluster_id": cluster.id,
            "namespace": bounded_namespace,
            "results": [result.__dict__ for result in results],
        })

    @app.post("/api/v1/knowledge")
    async def save_knowledge(request: Request, user: AuthContext = Depends(current_user)) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Managing cluster memory requires the Approver role or higher.")
        form = await _urlencoded(request)
        logical_id = form.get("logical_id", "").strip()
        title = redact_text(form.get("title", "").strip())[:253]
        content = redact_text(form.get("content", "").strip())
        source = redact_text(form.get("source", "").strip())[:512]
        source_type = form.get("source_type", "cluster_fact").strip()
        try:
            target_cluster_ids = list(dict.fromkeys(
                str(item) for item in json.loads(form.get("target_cluster_ids_json", "[]"))
            ))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Knowledge cluster targets are invalid.") from exc
        target_tags = _parse_tags(
            form.get("target_tags_json", "{}"), field_name="Knowledge target tags"
        )
        legacy_cluster_target = form.get("cluster_id", "").strip()
        if "target_cluster_ids_json" not in form and legacy_cluster_target not in {"", "*"}:
            target_cluster_ids = [
                SYSTEM_CLUSTER_ID if legacy_cluster_target == app_settings.cluster_name
                else legacy_cluster_target
            ]
        cluster_id = target_cluster_ids[0] if target_cluster_ids else "*"
        namespace = form.get("namespace", "").strip()[:253] or None
        resource_kind = form.get("resource_kind", "").strip()[:128] or None
        resource_name = form.get("resource_name", "").strip()[:253] or None
        owner = form.get("owner", user.username).strip()[:253]
        verification_state = form.get("verification_state", "draft").strip()
        sensitivity = form.get("sensitivity", "internal").strip()
        expires_text = form.get("expires_at", "").strip()
        if not title or not source or not owner:
            raise HTTPException(status_code=422, detail="Title, source, and owner are required.")
        if not content or len(content) > 100_000:
            raise HTTPException(status_code=422, detail="Content must be between 1 and 100,000 characters.")
        if source_type not in {"runbook", "cluster_fact", "incident_summary", "product_knowledge"}:
            raise HTTPException(status_code=422, detail="Knowledge source type is invalid.")
        if verification_state not in {"draft", "reviewed"}:
            raise HTTPException(status_code=422, detail="Verification state must be draft or reviewed.")
        if sensitivity not in {"internal", "restricted"}:
            raise HTTPException(status_code=422, detail="Sensitivity must be internal or restricted.")
        try:
            expires_at = (
                datetime.fromisoformat(expires_text).replace(tzinfo=timezone.utc)
                if expires_text else None
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Expiry must be an ISO date.") from exc
        now = datetime.now(timezone.utc)
        if expires_at is not None and expires_at <= now:
            raise HTTPException(status_code=422, detail="Expiry must be in the future.")
        with Session(request.app.state.engine) as db_session:
            if target_cluster_ids:
                target_count = db_session.scalar(
                    select(func.count()).select_from(Cluster).where(Cluster.id.in_(target_cluster_ids))
                ) or 0
                if target_count != len(target_cluster_ids):
                    raise HTTPException(status_code=422, detail="One or more knowledge cluster targets do not exist.")
            previous = None
            if logical_id:
                previous = db_session.scalar(select(KnowledgeDocument).where(
                    KnowledgeDocument.logical_id == logical_id,
                    KnowledgeDocument.is_current.is_(True),
                ))
                if previous is None:
                    raise HTTPException(status_code=404, detail="Knowledge entry not found.")
                previous.is_current = False
                version = previous.version + 1
            else:
                logical_id = str(uuid4())
                version = 1
            document = KnowledgeDocument(
                id=str(uuid4()), logical_id=logical_id, version=version,
                created_at=now, created_by=user.username, title=title, content=content,
                source=source, source_type=source_type, cluster_id=cluster_id,
                target_cluster_ids_json=json.dumps(target_cluster_ids, sort_keys=True),
                target_tags_json=json.dumps(target_tags, sort_keys=True),
                namespace=namespace, resource_kind=resource_kind, resource_name=resource_name,
                owner=owner, verification_state=verification_state, sensitivity=sensitivity,
                review_at=now if verification_state == "reviewed" else None,
                expires_at=expires_at, is_enabled=True, is_current=True,
                content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
            db_session.add(document)
            db_session.flush()
            index_document(db_session, document)
            db_session.add(AuditEvent(
                actor=user.username,
                action="knowledge.create" if version == 1 else "knowledge.revise",
                outcome="saved",
                details_json=json.dumps({
                    "document_id": document.id, "logical_id": logical_id,
                    "version": version, "source_type": source_type,
                    "target_cluster_ids": target_cluster_ids,
                    "target_tag_keys": sorted(target_tags), "namespace": namespace,
                    "verification_state": verification_state, "sensitivity": sensitivity,
                }, sort_keys=True),
            ))
            document_id = document.id
            db_session.commit()
        return JSONResponse({
            "status": "saved", "document_id": document_id,
            "logical_id": logical_id, "version": version,
        })

    @app.post("/api/v1/knowledge/{document_id}/status")
    async def set_knowledge_status(
        document_id: str, request: Request, user: AuthContext = Depends(current_user),
    ) -> JSONResponse:
        _verify_csrf(request)
        if user.role < Role.APPROVER:
            raise HTTPException(status_code=403, detail="Managing cluster memory requires the Approver role or higher.")
        form = await _urlencoded(request)
        enabled_text = form.get("enabled", "").strip().lower()
        if enabled_text not in {"true", "false"}:
            raise HTTPException(status_code=422, detail="Enabled must be true or false.")
        enabled = enabled_text == "true"
        with Session(request.app.state.engine) as db_session:
            document = db_session.get(KnowledgeDocument, document_id)
            if document is None or not document.is_current:
                raise HTTPException(status_code=404, detail="Knowledge entry not found.")
            document.is_enabled = enabled
            db_session.add(AuditEvent(
                actor=user.username, action="knowledge.status",
                outcome="enabled" if enabled else "disabled",
                details_json=json.dumps({
                    "document_id": document.id, "logical_id": document.logical_id,
                    "version": document.version,
                }, sort_keys=True),
            ))
            db_session.commit()
        return JSONResponse({"status": "enabled" if enabled else "disabled", "document_id": document_id})

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
            runtime_cluster = db_session.get(Cluster, SYSTEM_CLUSTER_ID)
            runtime_cluster_name = (
                runtime_cluster.name if runtime_cluster is not None else app_settings.cluster_name
            )

        response = templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "user": user,
                "cluster_name": runtime_cluster_name,
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
            profile = _active_profile(db_session)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
            credential_key = profile.credential_key if profile_snapshot else None
            runtime_cluster = db_session.get(Cluster, SYSTEM_CLUSTER_ID)
            runtime_cluster_name = (
                runtime_cluster.name if runtime_cluster is not None else app_settings.cluster_name
            )
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get, credential_key)
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
                cluster=runtime_cluster_name,
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
                "chat_read_budget": app_settings.adhoc_max_reads_per_turn,
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
            profile = _active_profile(db_session)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
            credential_key = profile.credential_key if profile_snapshot else None
            alert_name = investigation.alert_name

        provider_status = "not_configured"
        validated = {
            "answer_mode": "insufficient_evidence",
            "content": "No ready model profile is configured. The persisted investigation evidence and safe diagnostic plan remain available.",
            "citations": [],
            "tool_intent": None,
        }
        read_activity: list[dict[str, object]] = []
        read_limitations: list[str] = []
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get, credential_key)
                if not api_key:
                    raise ModelProviderError("The configured model token is unavailable.")
                inquiry = await _classify_ad_hoc_inquiry(
                    model_provider=provider,
                    profile=profile_snapshot,
                    api_key=api_key,
                    question=message_text,
                    conversation=conversation,
                    cluster_names=[app_settings.cluster_name],
                )
                original_evidence_ids = {
                    str(item.get("id")) for item in analysis_payload.get("observations", [])
                    if item.get("id")
                }
                try:
                    collected = await _collect_bounded_cluster_reads(
                        model_provider=provider,
                        cluster_reader=cluster_reader,
                        profile=profile_snapshot,
                        api_key=api_key,
                        settings=app_settings,
                        actor=user.username,
                        workflow_id=investigation_id,
                        question=message_text,
                        conversation=conversation,
                        existing_evidence=list(analysis_payload.get("observations", [])),
                        alert_name=alert_name,
                        alert_labels=dict(alert_snapshot.get("labels") or {}),
                        inquiry=inquiry,
                    )
                    read_activity = collected.activity
                    read_limitations = collected.limitations
                    new_observations = [
                        item for item in collected.evidence
                        if str(item.get("id")) not in original_evidence_ids
                    ]
                    for item in new_observations:
                        analysis_payload.setdefault("observations", []).append({
                            "id": item.get("id"),
                            "title": item.get("summary", "Collected cluster evidence."),
                            "detail": item.get("summary", "Collected bounded read-only cluster evidence."),
                            "source": item.get("source", "kubernetes"),
                            "observed_at": item.get("collected_at"),
                            "tool": item.get("tool"),
                            "data": item.get("data", {}),
                        })
                    known_evidence_ids.update(
                        str(item.get("id"))[:128] for item in new_observations if item.get("id")
                    )
                    if new_observations or read_activity or read_limitations:
                        with Session(request.app.state.engine) as db_session:
                            current = db_session.get(Investigation, investigation_id)
                            if current is None:
                                raise HTTPException(status_code=404, detail="Investigation not found.")
                            current.analysis_json = json.dumps(
                                analysis_payload, default=_json_default, sort_keys=True
                            )
                            db_session.add(AuditEvent(
                                actor=user.username,
                                action="chat.investigate",
                                outcome="completed",
                                details_json=json.dumps({
                                    "investigation_id": investigation_id,
                                    "reads": read_activity,
                                    "limitations": read_limitations,
                                    "observations_added": len(new_observations),
                                }, sort_keys=True),
                            ))
                            db_session.commit()
                except ModelProviderError as exc:
                    read_limitations = [str(exc)]
                    LOGGER.warning(
                        "podpilot.chat.read_plan_failed actor=%s investigation_id=%s error=%s",
                        user.username,
                        investigation_id,
                        str(exc),
                    )
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
                        "read_activity": read_activity,
                        "read_limitations": read_limitations,
                        "policy": {
                            "available_tool_intents": (
                                ["run_queued_checks"] if queued_checks else []
                            ),
                            "tool_execution_requires_operator_click": True,
                            "chat_cannot_mutate_cluster": True,
                            "bounded_cluster_reads_enabled": True,
                            "chat_must_not_delegate_reads_to_operator": True,
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
                            "read_count": len(read_activity),
                            "read_limitations": read_limitations,
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
            profile = _active_profile(db_session)
            profile_snapshot = _profile_config(profile) if profile and profile.status == "ready" else None
            credential_key = profile.credential_key if profile_snapshot else None

        model_result: dict[str, object] = analysis_payload.get("model", {"status": "not_configured"})
        if profile_snapshot:
            try:
                api_key = await run_in_threadpool(credentials.get, credential_key)
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
