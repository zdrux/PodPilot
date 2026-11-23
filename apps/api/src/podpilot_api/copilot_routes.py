"""Account linking is an extra authorization, never a replacement for proxy identity."""
import json

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from podpilot_api.copilot import STATE_COOKIE
from podpilot_api.model_provider import ModelProviderError
from podpilot_api.models import AuditEvent


def install_copilot(app, service, current_user, templates, csrf_token, verify_csrf, recent_conversations):
    def require(user):
        if not user.can_manage_configuration:
            raise HTTPException(403, "GitHub Copilot requires configuration-administrator access.")

    def audit(request, user, action, outcome):
        with Session(request.app.state.engine) as db:
            db.add(AuditEvent(actor=user.username, action="copilot." + action, outcome=outcome,
                              details_json=json.dumps({"personal": True})))
            db.commit()

    @app.get("/settings/copilot")
    async def page(request: Request, user=Depends(current_user)):
        require(user)
        csrf, new = csrf_token(request)
        with Session(request.app.state.engine) as db:
            recent = recent_conversations(db, user.username)
        response = templates.TemplateResponse(request=request, name="copilot_settings.html", context={
            "user": user, "csrf_token": csrf, "recent_conversations": recent,
            "copilot_enabled": service.enabled,
            "connection": await run_in_threadpool(service.view, service.owner_key(user.username), user.username),
            "connection_lifetime_days": service.settings.copilot_connection_lifetime_seconds / 86400,
            "persistent_credentials": service.settings.copilot_credential_store == "kubernetes",
        })
        response.headers["Cache-Control"] = "no-store"
        if new:
            response.set_cookie("podpilot_csrf", csrf, secure=service.settings.auth_mode == "proxy",
                                httponly=True, samesite="strict", max_age=28800)
        return response

    @app.post("/api/v1/copilot/connect")
    async def connect(request: Request, user=Depends(current_user)):
        verify_csrf(request)
        require(user)
        try:
            url, binding = await run_in_threadpool(service.begin, user.username)
        except ModelProviderError as exc:
            raise HTTPException(409, str(exc)) from None
        audit(request, user, "connect", "started")
        # Return the URL to same-origin JS; it performs a top-level OAuth navigation.
        from fastapi.responses import JSONResponse
        response = JSONResponse({"url": url})
        response.headers["Cache-Control"] = "no-store"
        response.set_cookie(STATE_COOKIE, binding, secure=service.settings.auth_mode == "proxy",
                            httponly=True, samesite="lax", max_age=600, path="/api/v1/copilot")
        return response

    @app.get("/api/v1/copilot/callback")
    async def callback(request: Request, user=Depends(current_user)):
        require(user)
        try:
            await run_in_threadpool(service.complete, user.username,
                request.query_params.get("state", ""), request.cookies.get(STATE_COOKIE, ""),
                request.query_params.get("code", ""))
        except ModelProviderError as exc:
            audit(request, user, "connect", "failed")
            raise HTTPException(400, str(exc)) from None
        audit(request, user, "connect", "connected")
        response = RedirectResponse("/settings/copilot", status_code=303)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        response.delete_cookie(STATE_COOKIE, path="/api/v1/copilot")
        return response

    @app.post("/api/v1/copilot/models/refresh")
    async def refresh(request: Request, user=Depends(current_user)):
        verify_csrf(request)
        require(user)
        try:
            await run_in_threadpool(service.refresh, service.owner_key(user.username), user.username)
        except ModelProviderError as exc:
            audit(request, user, "models", "failed")
            raise HTTPException(409, str(exc)) from None
        audit(request, user, "models", "refreshed")
        return {"url": "/settings/copilot"}

    @app.post("/api/v1/copilot/disconnect")
    async def disconnect(request: Request, user=Depends(current_user)):
        verify_csrf(request)
        require(user)
        try:
            await run_in_threadpool(service.disconnect, service.owner_key(user.username), user.username)
        except ModelProviderError as exc:
            raise HTTPException(503, str(exc)) from None
        audit(request, user, "disconnect", "disconnected")
        from fastapi.responses import JSONResponse
        response = JSONResponse({"url": "/settings/copilot"})
        return response
