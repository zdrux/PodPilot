import asyncio
import json
import time
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from podpilot_api.copilot import CopilotProvider, CopilotService, Connection, MemoryCopilotCredentials
from podpilot_api.model_provider import ModelProviderError
from podpilot_api.settings import Settings


def service(**kwargs):
    return CopilotService(Settings(copilot_client_id="test-client", copilot_client_secret="test-secret",
        copilot_redirect_uri="https://podpilot.test/api/v1/copilot/callback"), lambda owner: owner == "ada", **kwargs)


def seed(s, *, owner="ada", **kwargs):
    now = time.time()
    connection = Connection(owner, "gho_test-token", "github-ada", now + 2592000, now,
        models={"model-a": {"id": "model-a", "name": "Model A", "context": 64000, "input": 64000, "output": 4096}})
    connection = replace(connection, **kwargs)
    key = s.owner_key(owner)
    s._save(key, connection)
    return key


def test_oauth_state_is_bound_to_owner_browser_pkce_and_single_use():
    requests = []
    def respond(request):
        requests.append(request)
        if request.url.path == "/login/oauth/access_token":
            fields = parse_qs(request.content.decode())
            assert fields["code_verifier"] and fields["client_secret"] == ["test-secret"]
            return httpx.Response(200, json={"access_token": "gho_test-token"})
        assert request.headers["Authorization"] == "Bearer gho_test-token"
        return httpx.Response(200, json={"login": "github-ada"})
    s = service(transport=httpx.MockTransport(respond))
    url, binding = s.begin("ada")
    params = parse_qs(urlparse(url).query)
    assert params["code_challenge_method"] == ["S256"]
    state = params["state"][0]
    for owner, browser in [("other", binding), ("ada", "wrong")]:
        with pytest.raises(ModelProviderError):
            s.complete(owner, state, browser, "code")
    assert not requests
    key = s.complete("ada", state, binding, "code")
    assert s.connection(key, "ada").token == "gho_test-token"
    with pytest.raises(ModelProviderError):
        s.complete("ada", state, binding, "code")


def test_persistence_refresh_rotation_and_absolute_configured_expiry():
    store = MemoryCopilotCredentials()
    calls = []
    def respond(request):
        calls.append(request)
        assert parse_qs(request.content.decode())["refresh_token"] == ["ghr_old"]
        return httpx.Response(200, json={"access_token": "ghu_new", "refresh_token": "ghr_new",
            "expires_in": 28800, "refresh_token_expires_in": 15552000})
    first = service(credential_store=store)
    key = seed(first, token_expires=time.time() - 1, refresh_token="ghr_old", refresh_expires=time.time() + 10000)
    original_expiry = first.connection(key, "ada", refresh=False).expires
    restarted = service(credential_store=store, transport=httpx.MockTransport(respond))
    refreshed = restarted.connection(key, "ada")
    assert refreshed.token == "ghu_new" and refreshed.refresh_token == "ghr_new"
    assert refreshed.expires == original_expiry
    assert len(calls) == 1
    assert restarted.connection(key, "ada").token == "ghu_new"
    restarted._save(key, replace(refreshed, created=time.time() - 4000))
    restarted.settings.copilot_connection_lifetime_seconds = 3600
    with pytest.raises(ModelProviderError, match="stored Copilot connection expired"):
        restarted.connection(key, "ada")
    assert store.get(key) is None


def test_owner_isolation_group_revocation_disconnect_and_missing_refresh():
    s = service()
    key = seed(s)
    with pytest.raises(ModelProviderError):
        s.profile(key, "mallory", "model-a")
    s.can_manage = lambda _: False
    with pytest.raises(ModelProviderError, match="configuration-administrator"):
        s.connection(key, "ada")
    s.can_manage = lambda _: True
    s.disconnect(key, "mallory")
    assert s.connection(key, "ada")
    s.disconnect(key, "ada")
    with pytest.raises(ModelProviderError):
        s.connection(key, "ada")
    key = seed(s, token_expires=time.time() - 10)
    with pytest.raises(ModelProviderError, match="token expired"):
        s.connection(key, "ada")


def test_no_user_tokens_in_oauth_errors():
    s = service(transport=httpx.MockTransport(lambda _: httpx.Response(500, text="gho_private test-secret")))
    url, binding = s.begin("ada")
    with pytest.raises(ModelProviderError) as error:
        s.complete("ada", parse_qs(urlparse(url).query)["state"][0], binding, "code")
    assert "gho_private" not in str(error.value) and "test-secret" not in str(error.value)


class SDKFactory:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.options, self.sessions, self.prompts, self.stopped = [], [], [], 0

    def __call__(self, **options):
        self.options.append(options)
        factory = self
        class Client:
            async def start(self): pass
            async def stop(self): factory.stopped += 1
            async def list_models(self):
                def model(name, state):
                    return SimpleNamespace(id=name, name=name, policy=SimpleNamespace(state=state),
                        capabilities=SimpleNamespace(limits=SimpleNamespace(max_context_window_tokens=64000,
                            max_prompt_tokens=32000, max_output_tokens=4096)))
                return [model("allowed", "enabled"), model("denied", "disabled")]
            async def create_session(self, **kwargs):
                factory.sessions.append(kwargs)
                class Session:
                    async def send_and_wait(self, prompt, **kwargs):
                        factory.prompts.append((prompt, kwargs))
                        response = factory.responses.pop(0)
                        if isinstance(response, Exception): raise response
                        return SimpleNamespace(data=SimpleNamespace(content=json.dumps(response)))
                return Session()
        return Client()


def test_sdk_has_no_execution_tools_no_shared_environment_and_validated_proposals():
    sdk = SDKFactory([{"content": None, "tool_calls": [{"name": "execute_shell",
        "arguments": {"command": "oc get pods -A", "cluster_id": "cluster"}}]}])
    s = service(client_factory=sdk)
    key = seed(s)
    step = CopilotProvider(s).next_agent_step(s.profile(key, "ada", "model-a"), key,
        [{"role": "user", "content": "Show Pods"}])
    assert step.tool_calls[0].name == "execute_shell"
    assert json.loads(step.tool_calls[0].arguments)["command"] == "oc get pods -A"
    assert sdk.options[0]["mode"] == "empty" and sdk.options[0]["use_logged_in_user"] is False
    assert "KUBECONFIG" not in sdk.options[0]["env"]
    session = sdk.sessions[0]
    assert session["available_tools"] == [] and session["tools"] == [] and session["mcp_servers"] == {}
    assert session["enable_config_discovery"] is False and session["enable_session_store"] is False
    assert session["on_permission_request"](None, None).kind == "reject"
    assert sdk.stopped == 1
    assert "gho_test-token" not in sdk.prompts[0][0]
    sdk.responses = [{"content": None, "tool_calls": [{"name": "bash", "arguments": {}}]}]
    with pytest.raises(ModelProviderError, match="valid bounded"):
        CopilotProvider(s).next_agent_step(s.profile(key, "ada", "model-a"), key, [])
    assert sdk.stopped == 2


def test_model_discovery_filters_disabled_models_and_survives_restart():
    store = MemoryCopilotCredentials()
    s = service(client_factory=SDKFactory(), credential_store=store)
    key = seed(s)
    assert set(s.refresh(key, "ada")) == {"allowed"}
    restarted = service(credential_store=store)
    assert restarted.profile(key, "ada", "allowed").max_input_tokens == 32000
    with pytest.raises(ModelProviderError):
        restarted.profile(key, "ada", "denied")


def test_output_and_input_fail_closed_and_cleanup():
    sdk = SDKFactory([RuntimeError("gho_private")])
    s = service(client_factory=sdk)
    key = seed(s)
    profile = s.profile(key, "ada", "model-a")
    with pytest.raises(ModelProviderError) as error:
        CopilotProvider(s).next_agent_step(profile, key, [])
    assert "gho_private" not in str(error.value) and sdk.stopped == 1
    with pytest.raises(ModelProviderError, match="input budget"):
        s.completion(replace(profile, max_input_tokens=100), key, {"messages": ["x" * 10000]})
    assert sdk.stopped == 1
