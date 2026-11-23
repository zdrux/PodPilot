import json
import re
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from podpilot_api.auth import Role
from podpilot_api.main import DELEGATED_SESSION_COOKIE, SYSTEM_CLUSTER_ID
from podpilot_api.models import AdHocConversation, AdHocMessage, AuditEvent
from podpilot_openshift.agent_runner import AgentCommandResult

from .test_app import FakeAlertSource, make_app
from .test_copilot import SDKFactory, seed


@pytest.fixture(autouse=True)
def fake_cluster_logout(monkeypatch):
    monkeypatch.setattr("podpilot_api.main.OpenShiftDelegatedLoginClient",
        lambda **_: SimpleNamespace(revoke=lambda _: None))


def app_fixture(tmp_path, runner=None):
    ca_path = tmp_path / "fake-ca.crt"
    ca_path.write_text("test trust bundle", encoding="utf-8")
    return make_app(tmp_path, assignments={"ada": Role.INVESTIGATOR, "writer": Role.READ_WRITE},
        configuration_admins={"ada"}, source=FakeAlertSource(), agent_runner=runner,
        settings_overrides={"delegated_access_enabled": True, "service_account_ca_path": ca_path,
            "service_ca_path": ca_path, "copilot_client_id": "test-client",
            "copilot_client_secret": "test-secret",
            "copilot_redirect_uri": "https://podpilot.test/api/v1/copilot/callback"})[0]


def headers(client, owner="ada"):
    page = client.get("/settings/copilot", headers={"x-forwarded-user": "ada"})
    assert page.status_code == 200
    csrf = re.search(r'name="podpilot-csrf" content="([^"]+)"', page.text).group(1)
    return {"x-forwarded-user": owner, "X-PodPilot-CSRF": csrf}


def connect_cluster(app, client):
    session_id = app.state.delegated_vault.new_session_id()
    client.cookies.set(DELEGATED_SESSION_COOKIE, session_id)
    return app.state.delegated_vault.put(session_id=session_id, owner="ada", cluster_id=SYSTEM_CLUSTER_ID,
        remote_username="ada", remote_uid="uid-ada", token="private-cluster-token")


def test_routes_keep_proxy_auth_csrf_and_configuration_admin_gate(tmp_path):
    app = app_fixture(tmp_path)
    with TestClient(app) as client:
        assert client.get("/settings/copilot").status_code == 401
        auth = headers(client, "writer")
        assert client.get("/settings/copilot", headers=auth).status_code == 403
        for path in ["connect", "models/refresh", "disconnect"]:
            assert client.post("/api/v1/copilot/" + path, headers=auth).status_code == 403
        assert client.get("/api/v1/copilot/callback?state=bogus&code=bogus", headers=auth).status_code == 403
        assert client.post("/api/v1/copilot/connect", headers={"x-forwarded-user": "ada"}).status_code == 403
        assert client.post("/api/v1/adhoc-conversations", headers=auth,
            data={"message": "show pods", "copilot_model": "model-a"}).status_code == 403
        connect_cluster(app, client)
        normal_page = client.get("/ask", headers=auth)
        assert "Personal Copilot" not in normal_page.text
        assert "data-copilot-model" not in normal_page.text


def test_oauth_http_flow_model_refresh_and_disconnect_are_owner_scoped(tmp_path):
    app = app_fixture(tmp_path)
    with TestClient(app) as client:
        app.state.copilot.transport = httpx.MockTransport(lambda request: httpx.Response(200,
            json={"access_token": "gho_private-token"} if request.url.path.endswith("access_token") else {"login": "github-ada"}))
        app.state.copilot.client_factory = SDKFactory()
        auth = headers(client)
        started = client.post("/api/v1/copilot/connect", headers=auth)
        state = parse_qs(urlparse(started.json()["url"]).query)["state"][0]
        linked = client.get("/api/v1/copilot/callback", headers=auth,
            params={"state": state, "code": "private-code"}, follow_redirects=False)
        assert linked.status_code == 303
        assert client.post("/api/v1/copilot/models/refresh", headers=auth).status_code == 200
        page = client.get("/settings/copilot", headers=auth)
        assert "github-ada" in page.text and "allowed" in page.text and "denied" not in page.text
        assert "gho_private-token" not in page.text and "test-secret" not in page.text
        assert client.post("/api/v1/copilot/disconnect", headers=auth).status_code == 200
        assert app.state.copilot.view(None, "ada") is None
        with Session(app.state.engine) as db:
            audits = list(db.scalars(select(AuditEvent).where(AuditEvent.action.like("copilot.%"))))
            assert {a.action for a in audits} >= {"copilot.connect", "copilot.models", "copilot.disconnect"}
            assert "gho_private-token" not in str([a.details_json for a in audits])


def test_personal_copilot_uses_existing_delegated_read_only_runner_and_persists_selection(tmp_path):
    commands = []
    class Runner:
        def execute(self, command, connection=None, **kwargs):
            commands.append((command, connection))
            return AgentCommandResult(command=command, exit_code=0,
                stdout='{"items":[]}', stderr="")
    app = app_fixture(tmp_path, Runner())
    sdk = SDKFactory([
        {"content": None, "tool_calls": [{"name": "execute_shell", "arguments": {
            "command": "oc get pods -A -o json", "cluster_id": SYSTEM_CLUSTER_ID}}]},
        {"content": "The selected cluster returned an empty Pod list. This check found no Pods; it does not establish overall cluster health.", "tool_calls": []},
    ])
    with TestClient(app) as client:
        auth = headers(client)
        key = seed(app.state.copilot)
        app.state.copilot.client_factory = sdk
        grant = connect_cluster(app, client)
        page = client.get("/ask?copilot_model=model-a", headers=auth)
        assert page.status_code == 200 and 'value="model-a" selected' in page.text
        created = client.post("/api/v1/adhoc-conversations", headers=auth, follow_redirects=False,
            data={"message": "Show Pods", "copilot_model": "model-a", "execution_mode": "read_only"})
        assert created.status_code == 303, created.text
        assert len(commands) == 1
        command, connection = commands[0]
        assert command == "oc get pods -A -o json"
        assert connection.token is None
        assert connection.proxy_url.endswith(grant.read_only_proxy_capability)
        assert not connection.proxy_url.endswith(grant.action_proxy_capability)
        with Session(app.state.engine) as db:
            conversation = db.scalar(select(AdHocConversation))
            assert conversation.copilot_model == "model-a" and conversation.copilot_connection_id == key
            answer = db.scalar(select(AdHocMessage).where(AdHocMessage.role == "assistant"))
            assert answer.provider_status == "ready", answer.content
            assert "gho_test-token" not in answer.content
        rendered = client.get(created.headers["location"], headers=auth)
        assert rendered.status_code == 200 and "Personal GitHub Copilot" in rendered.text
        assert "private-cluster-token" not in json.dumps(sdk.prompts)
        # Removing app configuration access blocks follow-ups even for a previously linked user.
        app.state.copilot.can_manage = lambda _: False
        followup = client.post(created.headers["location"].replace("/ask/", "/api/v1/adhoc-conversations/") + "/messages",
            headers=auth, data={"message": "Check again"})
        assert followup.status_code == 409
        assert len(commands) == 1


def test_copilot_rejects_action_mode_and_unknown_models_without_queueing(tmp_path):
    app = app_fixture(tmp_path)
    with TestClient(app) as client:
        auth = headers(client)
        seed(app.state.copilot)
        connect_cluster(app, client)
        assert client.post("/api/v1/adhoc-conversations", headers=auth,
            data={"message": "change it", "copilot_model": "model-a", "execution_mode": "action"}).status_code == 403
        assert client.post("/api/v1/adhoc-conversations", headers=auth,
            data={"message": "show pods", "copilot_model": "not-available"}).status_code == 409
        with Session(app.state.engine) as db:
            assert db.scalar(select(AdHocConversation)) is None
