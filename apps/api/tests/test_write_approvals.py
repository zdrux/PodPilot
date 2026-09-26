import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app, CSRF_COOKIE, DELEGATED_SESSION_COOKIE
from podpilot_api.models import Base, Cluster, AdHocConversation, AdHocMessage, AdHocRun, WriteApproval, AuditEvent
from podpilot_api.settings import Settings


@pytest.fixture
def approval_app(tmp_path, monkeypatch):
    settings = Settings(environment="test", auth_mode="test", database_url=f"sqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path, web_dir=Path(__file__).resolve().parents[2] / "web",
        adhoc_job_worker_enabled=False, incident_worker_enabled=False, secret_access_enabled=True)
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    app = create_app(settings, role_resolver=StaticRoleResolver({"requester": Role.READ_WRITE, "other": Role.BREAKGLASS}))
    forwarded = []
    def upstream(request):
        forwarded.append(request)
        return httpx.Response(201, json={"kind": "Namespace", "metadata": {"name": "mike"}})
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(upstream), **kw))
    with TestClient(app) as client:
        with Session(app.state.engine) as db:
            cluster = db.scalar(select(Cluster))
            cluster_id = cluster.id
            cluster.is_system = False
            cluster.api_url = "https://api.example"
            db.add(AdHocConversation(id="conversation", created_by="requester", title="Create mike", execution_mode="action",
                cluster_ids_json=json.dumps([cluster_id]), delegated_session_id="s"*40))
            db.add(AdHocMessage(id="message", conversation_id="conversation", role="user", actor="requester", content="Create mike"))
            db.add(AdHocRun(id="run", conversation_id="conversation", created_by="requester", message_text="Create mike",
                           status="running", started_at=datetime.now(timezone.utc)))
            db.commit()
        connection = app.state.delegated_vault.put(session_id="s"*40, owner="requester", cluster_id=cluster_id,
            remote_username="cluster-requester", remote_uid="uid", token="never-disclose-token")
        capability = app.state.write_approval_gate.register(base_capability=connection.action_proxy_capability,
            run_id="run", owner="requester", cluster_id=cluster_id, cluster_name="Test cluster", command="oc create namespace mike")
        client.cookies.set(CSRF_COOKIE, "csrf-test")
        client.cookies.set(DELEGATED_SESSION_COOKIE, "s"*40)
        headers = {"x-forwarded-user": "requester", "x-podpilot-csrf": "csrf-test"}
        yield client, app, capability, connection, headers, forwarded
        app.state.write_approval_gate.release(capability)
        app.state.delegated_vault.pop_all()
    engine.dispose()


@contextmanager
def approval_pool(app, cap):
    pool = ThreadPoolExecutor()
    try:
        yield pool
    finally:
        app.state.write_approval_gate.release(cap)
        pool.shutdown(wait=True)


def pending(app):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = app.state.write_approval_gate.list_pending(app.state.engine, "run")
        if rows:
            return rows[0]
        time.sleep(.025)
    raise AssertionError("No pending approval")


def submit(client, capability, path="api/v1/namespaces", payload=None):
    return client.post(f"/internal/delegated-proxy/{capability}/{path}", json=payload or {
        "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "mike"}})


def test_write_waits_for_requester_and_forwards_exact_bytes_once(approval_app):
    client, app, cap, conn, headers, forwarded = approval_app
    with approval_pool(app, cap) as pool:
        task = pool.submit(submit, client, cap)
        proposal = pending(app)
        assert not forwarded and not task.done()
        assert proposal["cluster_identity"] == "cluster-requester"
        assert json.loads(proposal["body"])["metadata"]["name"] == "mike"
        url = f"/api/v1/write-approvals/{proposal['id']}/approve"
        assert client.post(url, headers={**headers, "x-forwarded-user": "other"}).status_code == 404
        assert client.post(url, headers={"x-forwarded-user": "requester"}).status_code == 403
        assert client.post(url, headers=headers).status_code == 200
        assert task.result(timeout=5).status_code == 201
        assert len(forwarded) == 1
        assert forwarded[0].headers["authorization"] == "Bearer never-disclose-token"
        assert json.loads(forwarded[0].content)["metadata"]["name"] == "mike"
        assert client.post(url, headers=headers).status_code == 409
    with Session(app.state.engine) as db:
        approval = db.get(WriteApproval, proposal["id"])
        assert approval.status == "succeeded"
        assert "never-disclose-token" not in approval.preview_json
        outcomes = [row.outcome for row in db.scalars(select(AuditEvent).where(AuditEvent.action == "write.self_approval"))]
        assert outcomes == ["pending", "approved", "executing", "succeeded"]


@pytest.mark.parametrize("ending", ["reject", "expire", "cancel", "logout", "release"])
def test_rejection_expiry_cancellation_and_session_loss_never_forward(approval_app, ending):
    client, app, cap, conn, headers, forwarded = approval_app
    with approval_pool(app, cap) as pool:
        task = pool.submit(submit, client, cap)
        proposal = pending(app)
        if ending == "reject":
            assert client.post(f"/api/v1/write-approvals/{proposal['id']}/reject", headers=headers).status_code == 200
        elif ending == "logout":
            app.state.delegated_vault.pop_all()
        elif ending == "release":
            app.state.write_approval_gate.release(cap)
        else:
            with Session(app.state.engine) as db:
                if ending == "expire":
                    db.get(WriteApproval, proposal["id"]).expires_at = datetime.now(timezone.utc)-timedelta(seconds=1)
                else:
                    db.get(AdHocRun, "run").status = "cancelled"
                db.commit()
        assert task.result(timeout=5).status_code == 403
    assert not forwarded
    if ending == "reject":
        retry_cap = app.state.write_approval_gate.register(base_capability=conn.action_proxy_capability,
            run_id="run", owner="requester", cluster_id=conn.cluster_id, cluster_name="Test", command="retry")
        assert submit(client, retry_cap).status_code == 403
        assert not app.state.write_approval_gate.list_pending(app.state.engine, "run")


def test_approval_is_not_a_blanket_command_grant(approval_app):
    client, app, cap, conn, headers, forwarded = approval_app
    with approval_pool(app, cap) as pool:
        first = pool.submit(submit, client, cap)
        proposal = pending(app)
        assert client.post(f"/api/v1/write-approvals/{proposal['id']}/approve", headers=headers).status_code == 200
        assert first.result(timeout=5).status_code == 201
        second = pool.submit(submit, client, cap, "api/v1/namespaces", {"kind": "Namespace", "metadata": {"name": "other"}})
        next_proposal = pending(app)
        assert next_proposal["id"] != proposal["id"]
        assert next_proposal["request_hash"] != proposal["request_hash"]
        assert len(forwarded) == 1 and not second.done()
        client.post(f"/api/v1/write-approvals/{next_proposal['id']}/reject", headers=headers)
        assert second.result(timeout=5).status_code == 403


def test_read_only_and_unscoped_action_writes_fail_closed(approval_app):
    client, app, cap, conn, headers, forwarded = approval_app
    assert submit(client, conn.read_only_proxy_capability).status_code == 403
    assert submit(client, conn.action_proxy_capability).status_code == 403
    assert client.get(f"/internal/delegated-proxy/{cap}/api/v1/namespaces/mike").status_code == 201
    assert len(forwarded) == 1
    for endpoint in ("approve", "execute", "cancel"):
        assert client.post(f"/api/v1/investigations/old/actions/old/{endpoint}", headers=headers).status_code == 404


def test_secret_preview_is_redacted_but_original_request_is_bound(approval_app):
    client, app, cap, conn, headers, forwarded = approval_app
    with approval_pool(app, cap) as pool:
        task = pool.submit(submit, client, cap, "api/v1/namespaces/test/secrets", {
            "kind": "Secret", "metadata": {"name": "credential"}, "data": {"credential": "private-value"}})
        proposal = pending(app)
        assert "private-value" not in json.dumps(proposal)
        client.post(f"/api/v1/write-approvals/{proposal['id']}/reject", headers=headers)
        assert task.result(timeout=5).status_code == 403
    assert not forwarded


def test_requester_modal_in_browser(approval_app, tmp_path):
    import os
    import subprocess
    if os.environ.get("PODPILOT_BROWSER_TESTS") != "1":
        pytest.skip("Enable browser tests with Playwright on NODE_PATH")
    client, app, cap, conn, headers, forwarded = approval_app
    response = client.get("/ask/conversation", headers=headers)
    assert response.status_code == 200
    fixture = tmp_path / "approval.html"
    fixture.write_text(response.text, encoding="utf-8")
    result = subprocess.run(["node", "apps/web/tests/write-approval.cjs", str(fixture),
        str(tmp_path / "approval-modal.png")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    print(str(tmp_path / "approval-modal.png"))
    scroll_result = subprocess.run(["node", "apps/web/tests/chat-scroll.cjs", str(fixture)],
        capture_output=True, text=True, timeout=60)
    assert scroll_result.returncode == 0, scroll_result.stdout + scroll_result.stderr



@pytest.mark.parametrize("content,read_only,has_approval,expected", [
    ("Requested approval: I will now submit a patch request. Please approve the exact change.", False, False, True),
    ("Once approved, I will execute the patches under your RBAC.", False, False, True),
    ("Please approve the change.", True, False, False),
    ("Please approve the change.", False, True, False),
    ("The request was rejected. No changes were made.", False, False, False),
    ("The target namespace is missing; which namespace should I use?", False, False, False),
    ("All pods are healthy. No changes are needed.", False, False, False),
])
def test_missing_approval_handoff(content, read_only, has_approval, expected):
    from podpilot_api.main import _missing_action_approval
    assert _missing_action_approval(content, read_only=read_only, has_approval=has_approval) is expected
