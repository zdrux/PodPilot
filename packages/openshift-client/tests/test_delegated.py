from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from podpilot_openshift.delegated import (
    DelegatedLoginError,
    OpenShiftDelegatedLoginClient,
    validate_custom_ca,
)


def test_challenging_login_only_sends_password_after_same_origin_basic_challenge() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json={
                "authorization_endpoint": "https://oauth.dev.example/oauth/authorize",
            })
        if request.url.path == "/oauth/authorize" and "authorization" not in request.headers:
            return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=openshift"})
        if request.url.path == "/oauth/authorize":
            expected = "Basic " + base64.b64encode(b"alice:password").decode()
            assert request.headers["authorization"] == expected
            return httpx.Response(302, headers={
                "Location": "https://oauth.dev.example/#access_token=sha256~user-token",
            })
        if request.url.path == "/apis/user.openshift.io/v1/users/~":
            assert request.headers["authorization"] == "Bearer sha256~user-token"
            return httpx.Response(200, json={
                "metadata": {"name": "alice", "uid": "uid-alice"},
            })
        raise AssertionError(f"Unexpected request: {request.url}")

    identity = OpenShiftDelegatedLoginClient(
        api_url="https://api.dev.example:6443",
        transport=httpx.MockTransport(handler),
    ).login("alice", "password")

    assert identity.username == "alice"
    assert identity.token == "sha256~user-token"
    assert "authorization" not in requests[0].headers
    assert "authorization" not in requests[1].headers


def test_challenging_login_refuses_cross_origin_redirect_before_credentials() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json={
                "authorization_endpoint": "https://oauth.dev.example/oauth/authorize",
            })
        return httpx.Response(302, headers={
            "Location": "https://identity.evil.example/login",
        })

    client = OpenShiftDelegatedLoginClient(
        api_url="https://api.dev.example:6443",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(DelegatedLoginError, match="unregistered origin"):
        client.login("alice", "password")


def test_challenging_login_can_use_a_trusted_internal_oauth_endpoint() -> None:
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json={
                "authorization_endpoint": "https://oauth.apps.example/oauth/authorize",
            })
        if request.url.path == "/oauth/authorize" and "authorization" not in request.headers:
            assert request.url.host == "oauth-openshift.openshift-authentication.svc"
            return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=openshift"})
        if request.url.path == "/oauth/authorize":
            assert request.url.host == "oauth-openshift.openshift-authentication.svc"
            return httpx.Response(302, headers={
                "Location": (
                    "https://oauth-openshift.openshift-authentication.svc/"
                    "#access_token=sha256~system-user-token"
                ),
            })
        if request.url.path == "/apis/user.openshift.io/v1/users/~":
            return httpx.Response(200, json={
                "metadata": {"name": "alice", "uid": "uid-alice"},
            })
        raise AssertionError(f"Unexpected request: {request.url}")

    identity = OpenShiftDelegatedLoginClient(
        api_url="https://kubernetes.default.svc",
        authorization_endpoint_override=(
            "https://oauth-openshift.openshift-authentication.svc/oauth/authorize"
        ),
        transport=httpx.MockTransport(handler),
    ).login("alice", "password")

    assert identity.token == "sha256~system-user-token"
    assert "oauth.apps.example" not in requested_hosts


def test_custom_ca_rejects_private_key_material() -> None:
    with pytest.raises(DelegatedLoginError, match="private key"):
        validate_custom_ca("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")


def test_revoke_uses_openshift_sha256_token_resource_name() -> None:
    token = "sha256~user-token"
    expected = "sha256~" + base64.urlsafe_b64encode(
        hashlib.sha256(token.encode()).digest()
    ).rstrip(b"=").decode()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path.endswith(f"/useroauthaccesstokens/{expected}")
        assert request.headers["authorization"] == f"Bearer {token}"
        return httpx.Response(200)

    client = OpenShiftDelegatedLoginClient(
        api_url="https://api.dev.example:6443",
        transport=httpx.MockTransport(handler),
    )
    assert client.revoke(token) is True
