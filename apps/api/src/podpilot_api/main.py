from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from podpilot_api.auth import AuthContext, Role, RoleResolver, auth_dependency
from podpilot_api.database import build_engine, database_is_ready
from podpilot_api.model_provider import (
    ModelProfileConfig,
    ModelProvider,
    ModelProviderError,
    OpenAIResponsesProvider,
)
from podpilot_api.models import AuditEvent, Investigation, ModelProfile
from podpilot_api.settings import Settings, get_settings
from podpilot_diagnostics.alerts import AlertEvidence, analyze_alert
from podpilot_diagnostics.redaction import redact_mapping
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
from podpilot_openshift.roles import LazyOpenShiftGroupRoleResolver
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


def create_app(
    settings: Settings | None = None,
    role_resolver: RoleResolver | None = None,
    alert_source: AlertSource | None = None,
    workload_source: WorkloadEvidenceSource | None = None,
    credential_store: CredentialStore | None = None,
    model_provider: ModelProvider | None = None,
) -> FastAPI:
    app_settings = settings or get_settings()
    resolver = role_resolver or LazyOpenShiftGroupRoleResolver(
        cache_seconds=app_settings.role_cache_seconds
    )
    alerts = alert_source or _make_alert_source(app_settings)
    workloads = workload_source or _make_workload_source(app_settings)
    credentials = credential_store or _make_credential_store(app_settings)
    provider = model_provider or OpenAIResponsesProvider()
    templates = Jinja2Templates(directory=app_settings.web_dir / "templates")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = app_settings
        application.state.engine = build_engine(app_settings)
        yield
        application.state.engine.dispose()

    app = FastAPI(
        title="PodPilot",
        version="0.4.0",
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
            recent = list(
                db_session.scalars(
                    select(Investigation)
                    .order_by(Investigation.created_at.desc())
                    .limit(5)
                )
            )

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
        analysis_payload["model"] = model_result
        analysis_json = json.dumps(analysis_payload, default=_json_default, sort_keys=True)
        with Session(request.app.state.engine) as db_session:
            db_session.add(
                Investigation(
                    id=investigation_id,
                    created_by=user.username,
                    status="recommendation_ready",
                    alert_fingerprint=alert.fingerprint,
                    alert_name=alert.name,
                    alert_snapshot_json=alert_json,
                    analysis_json=analysis_json,
                )
            )
            db_session.add(
                AuditEvent(
                    actor=user.username,
                    action="investigation.create",
                    outcome="recommendation_ready",
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
        return templates.TemplateResponse(
            request=request,
            name="investigation.html",
            context={"user": user, "investigation": view},
        )

    @app.get("/api/v1/session")
    async def session(user: AuthContext = Depends(current_user)) -> dict[str, str]:
        return {"username": user.username, "role": user.role.name.lower()}

    return app


app = create_app()
