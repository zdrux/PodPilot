"""One-request self-approval at the delegated Kubernetes broker boundary."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from podpilot_api.secret_policy import redact_secret_output
from podpilot_api.models import AdHocConversation, AdHocRun, AuditEvent, Cluster, WriteApproval
from podpilot_diagnostics.redaction import redact_text


def now():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@dataclass(frozen=True)
class CommandScope:
    base_capability: str
    run_id: str
    owner: str
    cluster_id: str
    cluster_name: str
    command: str


class WriteApprovalGate:
    def __init__(self):
        self.scopes: dict[str, CommandScope] = {}

    def register(self, **values):
        capability = secrets.token_urlsafe(32)
        self.scopes[capability] = CommandScope(**values)
        return capability

    def release(self, capability):
        self.scopes.pop(capability, None)

    def scope(self, capability):
        return self.scopes.get(capability)

    @staticmethod
    def audit(db, approval, outcome):
        db.add(AuditEvent(actor=approval.owner, action="write.self_approval", outcome=outcome,
            details_json=json.dumps({"approval_id": approval.id, "run_id": approval.run_id,
                "cluster_id": approval.cluster_id, "request_hash": approval.request_hash})))

    def valid(self, db, scope, vault):
        grant = vault.grant_by_capability(scope.base_capability)
        run = db.get(AdHocRun, scope.run_id)
        conversation = db.get(AdHocConversation, run.conversation_id) if run else None
        cluster = db.get(Cluster, scope.cluster_id)
        return bool(grant and grant[1] == "action" and grant[0].owner == scope.owner
            and cluster and cluster.is_enabled
            and grant[0].cluster_id == scope.cluster_id and run and run.status == "running"
            and run.created_by == scope.owner and conversation and conversation.execution_mode == "action"
            and conversation.created_by == scope.owner
            and conversation.delegated_session_id == grant[0].session_id
            and scope.cluster_id in json.loads(conversation.cluster_ids_json))

    async def wait(self, *, request, capability, connection, body, remote_path, api_url):
        scope = self.scope(capability)
        if scope is None:
            raise HTTPException(403, "A write requires a live command and requester approval.")
        engine, vault = request.app.state.engine, request.app.state.delegated_vault
        # The full bytes are held only in this in-flight request. Approval never
        # authorizes a later retry, different body, request, command or cluster.
        if len(body) > 65536:
            raise HTTPException(413, "This write is too large for an exact approval preview. Split it into smaller changes.")
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "Binary request bodies cannot be reviewed for self-approval.")
        secret_resource = "secrets" in remote_path.lower().split("/")
        try:
            document = json.loads(body_text) if body_text else None
        except ValueError:
            document = None
        if secret_resource and document is not None:
            if isinstance(document, dict):
                document = {k: ("[REDACTED]" if k in {"data", "stringData"} else v)
                            for k, v in document.items()}
            else:
                document = "[REDACTED Secret patch]"
        preview_body = json.dumps(document, indent=2) if document is not None else body_text
        if secret_resource and document is None and body:
            preview_body = "[REDACTED Secret content]"
        preview_body = redact_secret_output(preview_body)
        safe_command = "[Secret operation: review the resource and redacted request below]" if secret_resource or re.search(r"(?i)(kind:\s*Secret|create\s+secret|--from-literal)", scope.command) else redact_secret_output(scope.command)
        request_hash = hashlib.sha256(b"\0".join([
            request.method.encode(), remote_path.encode(), request.url.query.encode(),
            request.headers.get("content-type", "").encode(), body])).hexdigest()
        created = now()
        approval_id = str(uuid4())
        preview = {"command": safe_command, "cluster": scope.cluster_name, "api_url": api_url,
            "cluster_id": scope.cluster_id, "requester": scope.owner,
            "cluster_identity": connection.remote_username, "method": request.method,
            "path": "/" + remote_path.lstrip("/"), "query": redact_text(request.url.query),
            "content_type": request.headers.get("content-type", ""), "body": preview_body,
            "request_hash": request_hash,
            "notice": "Approve only this API request. Other writes need separate approval. Kubernetes RBAC and admission still apply. Values marked REDACTED are withheld. This is not a dry run or a guarantee of success. Changes may not be reversible.",
            "risk": "Deletion may remove dependent resources and data." if request.method == "DELETE" else
                    "This request can change cluster state or start a privileged operation. Review the command and exact request."}
        with Session(engine) as db:
            if not self.valid(db, scope, vault):
                raise HTTPException(403, "The requesting Action session is no longer active.")
            existing = list(db.scalars(select(WriteApproval.id).where(
                WriteApproval.run_id == scope.run_id).limit(64)))
            if len(existing) >= 64:
                raise HTTPException(429, "This turn reached its write-review budget. Start a new user request.")
            rejected = db.scalar(select(WriteApproval.id).where(WriteApproval.run_id == scope.run_id,
                WriteApproval.status.in_(("rejected", "expired", "cancelled"))).limit(1))
            if rejected:
                raise HTTPException(403, "A write was rejected or expired in this turn. Do not retry; wait for a new user request.")
            row = WriteApproval(id=approval_id, run_id=scope.run_id, owner=scope.owner,
                cluster_id=scope.cluster_id, request_hash=request_hash, preview_json=json.dumps(preview),
                status="pending", created_at=created, expires_at=created+timedelta(seconds=120))
            db.add(row)
            self.audit(db, row, "pending")
            db.commit()
        try:
            while True:
                disconnected = await request.is_disconnected()
                with Session(engine) as db:
                    row = db.get(WriteApproval, approval_id)
                    if not row:
                        raise HTTPException(409, "The approval no longer exists.")
                    if disconnected or self.scope(capability) != scope or not self.valid(db, scope, vault):
                        row.status = "cancelled"
                    elif aware(row.expires_at) <= now():
                        row.status = "expired"
                    if row.status in {"cancelled", "expired", "rejected"}:
                        self.audit(db, row, row.status)
                        db.commit()
                        raise HTTPException(403, "Write " + row.status + "; nothing was sent to Kubernetes. Do not retry without a new user request.")
                    if row.status == "approved":
                        claimed = db.execute(update(WriteApproval).where(WriteApproval.id == approval_id,
                            WriteApproval.status == "approved").values(status="executing"))
                        if claimed.rowcount != 1:
                            raise HTTPException(409, "Approval already consumed.")
                        self.audit(db, row, "executing")
                        db.commit()
                        return approval_id
                await asyncio.sleep(0.25)
        finally:
            with Session(engine) as db:
                row = db.get(WriteApproval, approval_id)
                if row and row.status in {"pending", "approved"}:
                    row.status = "cancelled"
                    self.audit(db, row, "cancelled")
                    db.commit()

    def finish(self, engine, approval_id, outcome):
        if not approval_id:
            return
        with Session(engine) as db:
            row = db.get(WriteApproval, approval_id)
            if row and row.status == "executing":
                row.status = outcome
                self.audit(db, row, outcome)
                db.commit()

    def list_pending(self, engine, run_id):
        with Session(engine) as db:
            return [{"id": row.id, "expires_at": aware(row.expires_at).isoformat(),
                     **json.loads(row.preview_json)} for row in db.scalars(select(WriteApproval).where(
                WriteApproval.run_id == run_id, WriteApproval.status == "pending",
                WriteApproval.expires_at > now()).order_by(WriteApproval.created_at))]

    def decide(self, engine, vault, approval_id, owner, session_id, decision):
        with Session(engine) as db:
            row = db.get(WriteApproval, approval_id)
            if row is None or row.owner != owner:
                raise HTTPException(404, "Approval not found.")
            scope = next((scope for scope in self.scopes.values() if scope.run_id == row.run_id
                          and scope.cluster_id == row.cluster_id and scope.owner == owner), None)
            if not scope or not self.valid(db, scope, vault):
                raise HTTPException(409, "The command or session is no longer active.")
            grant = vault.grant_by_capability(scope.base_capability)
            if not grant or grant[0].session_id != session_id:
                raise HTTPException(403, "Use the requesting browser session to approve this change.")
            if row.status != "pending" or aware(row.expires_at) <= now():
                raise HTTPException(409, "This approval is expired or already decided.")
            status = "approved" if decision == "approve" else "rejected"
            result = db.execute(update(WriteApproval).where(WriteApproval.id == row.id,
                WriteApproval.status == "pending", WriteApproval.expires_at > now()).values(
                    status=status, decided_at=now()).execution_options(synchronize_session=False))
            if result.rowcount != 1:
                raise HTTPException(409, "This approval was already decided.")
            self.audit(db, row, status)
            db.commit()
