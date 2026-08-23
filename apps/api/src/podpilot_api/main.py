from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
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
from podpilot_api.models import AuditEvent, Investigation
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
from podpilot_openshift.roles import LazyOpenShiftGroupRoleResolver

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
) -> FastAPI:
    app_settings = settings or get_settings()
    resolver = role_resolver or LazyOpenShiftGroupRoleResolver(
        cache_seconds=app_settings.role_cache_seconds
    )
    alerts = alert_source or _make_alert_source(app_settings)
    templates = Jinja2Templates(directory=app_settings.web_dir / "templates")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = app_settings
        application.state.engine = build_engine(app_settings)
        yield
        application.state.engine.dispose()

    app = FastAPI(
        title="PodPilot",
        version="0.2.0",
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
        analysis = analyze_alert(evidence)
        alert_snapshot = {
            "fingerprint": evidence.fingerprint,
            "state": evidence.state,
            "labels": evidence.labels,
            "annotations": evidence.annotations,
            "starts_at": evidence.starts_at,
            "collected_at": snapshot.collected_at,
            "silenced": alert.is_silenced,
            "inhibited": alert.is_inhibited,
        }
        alert_json = json.dumps(alert_snapshot, default=_json_default, sort_keys=True)
        analysis_json = json.dumps(analysis.to_dict(), default=_json_default, sort_keys=True)
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
