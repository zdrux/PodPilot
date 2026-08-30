from __future__ import annotations

import base64
import hashlib
import ssl
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

import httpx


class DelegatedLoginError(RuntimeError):
    pass


@dataclass(frozen=True)
class DelegatedIdentity:
    username: str
    uid: str
    token: str


def tls_context(custom_ca_pem: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if custom_ca_pem and custom_ca_pem.strip():
        try:
            context.load_verify_locations(cadata=custom_ca_pem.strip())
        except ssl.SSLError as exc:
            raise DelegatedLoginError("The configured cluster CA is not a valid PEM certificate bundle.") from exc
    return context


def validate_custom_ca(custom_ca_pem: str | None) -> str | None:
    normalized = (custom_ca_pem or "").strip()
    if not normalized:
        return None
    if len(normalized.encode("utf-8")) > 65_536:
        raise DelegatedLoginError("The configured cluster CA bundle exceeds 64 KiB.")
    if "PRIVATE KEY" in normalized.upper():
        raise DelegatedLoginError("The configured cluster CA bundle must not contain a private key.")
    tls_context(normalized)
    return normalized + "\n"


class OpenShiftDelegatedLoginClient:
    """Exchange one username/password challenge for a user-owned OpenShift token."""

    def __init__(
        self,
        *,
        api_url: str,
        custom_ca_pem: str | None = None,
        timeout_seconds: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(api_url.strip())
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise DelegatedLoginError("Delegated login requires a registered HTTPS Kubernetes API origin.")
        self.api_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.verify = tls_context(custom_ca_pem)
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    def probe(self) -> str:
        """Verify the registered API trust chain and its advertised OAuth endpoint."""
        try:
            with httpx.Client(
                verify=self.verify,
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = client.get(f"{self.api_url}/.well-known/oauth-authorization-server")
                response.raise_for_status()
                endpoint = urlsplit(str(response.json().get("authorization_endpoint") or ""))
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise DelegatedLoginError(
                f"The remote OpenShift OAuth discovery probe failed ({type(exc).__name__})."
            ) from exc
        if endpoint.scheme != "https" or not endpoint.hostname:
            raise DelegatedLoginError("The cluster advertised an invalid OAuth authorization endpoint.")
        return urlunsplit((endpoint.scheme, endpoint.netloc, endpoint.path, "", ""))

    def login(self, username: str, password: str) -> DelegatedIdentity:
        username = username.strip()
        if not username or not password:
            raise DelegatedLoginError("A username and password are required.")
        try:
            with httpx.Client(
                verify=self.verify,
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                metadata = client.get(f"{self.api_url}/.well-known/oauth-authorization-server")
                metadata.raise_for_status()
                authorization_endpoint = str(metadata.json().get("authorization_endpoint") or "")
                token = self._challenge_for_token(
                    client, authorization_endpoint=authorization_endpoint,
                    username=username, password=password,
                )
                identity = client.get(
                    f"{self.api_url}/apis/user.openshift.io/v1/users/~",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
                identity.raise_for_status()
                payload = identity.json()
        except DelegatedLoginError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise DelegatedLoginError(
                f"The remote OpenShift login failed ({type(exc).__name__})."
            ) from exc
        remote_username = str(payload.get("metadata", {}).get("name") or "").strip()
        remote_uid = str(payload.get("metadata", {}).get("uid") or "").strip()
        if not remote_username:
            raise DelegatedLoginError("The remote API did not return a usable user identity.")
        return DelegatedIdentity(username=remote_username, uid=remote_uid, token=token)

    def revoke(self, token: str) -> bool:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        token_name = "sha256~" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        try:
            with httpx.Client(
                verify=self.verify,
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
                response = client.delete(
                    f"{self.api_url}/apis/oauth.openshift.io/v1/useroauthaccesstokens/{token_name}",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
            return response.status_code in {200, 202, 404}
        except httpx.HTTPError:
            return False

    def _challenge_for_token(
        self,
        client: httpx.Client,
        *,
        authorization_endpoint: str,
        username: str,
        password: str,
    ) -> str:
        endpoint = urlsplit(authorization_endpoint)
        if endpoint.scheme != "https" or not endpoint.hostname:
            raise DelegatedLoginError("The cluster advertised an invalid OAuth authorization endpoint.")
        allowed_origin = (endpoint.scheme, endpoint.hostname.casefold(), endpoint.port or 443)
        query = urlencode({
            "client_id": "openshift-challenging-client",
            "response_type": "token",
        })
        current_url = authorization_endpoint + ("&" if endpoint.query else "?") + query
        supplied_basic = False
        for _ in range(8):
            headers = {"X-CSRF-Token": "podpilot", "Accept": "text/html,application/json"}
            auth: httpx.BasicAuth | None = None
            if supplied_basic:
                auth = httpx.BasicAuth(username, password)
            response = client.get(current_url, headers=headers, auth=auth)
            if response.status_code == 401:
                challenge = response.headers.get("WWW-Authenticate", "")
                current = urlsplit(current_url)
                current_origin = (current.scheme, current.hostname.casefold() if current.hostname else "", current.port or 443)
                if "basic" not in challenge.casefold() or current_origin != allowed_origin:
                    raise DelegatedLoginError(
                        "This cluster identity provider does not support username/password challenge login."
                    )
                supplied_basic = True
                continue
            if response.status_code not in {301, 302, 303, 307, 308}:
                raise DelegatedLoginError(f"The remote OAuth server returned HTTP {response.status_code}.")
            location = response.headers.get("Location", "")
            target = urlsplit(urljoin(current_url, location))
            fragment = parse_qs(target.fragment)
            access_tokens = fragment.get("access_token") or []
            if access_tokens and access_tokens[0]:
                return access_tokens[0]
            errors = parse_qs(target.query).get("error") or []
            if errors:
                raise DelegatedLoginError(f"The remote OAuth server rejected the login ({errors[0]}).")
            target_origin = (
                target.scheme,
                target.hostname.casefold() if target.hostname else "",
                target.port or 443,
            )
            if target_origin != allowed_origin:
                raise DelegatedLoginError("The remote OAuth flow redirected to an unregistered origin.")
            current_url = urlunsplit((target.scheme, target.netloc, target.path, target.query, ""))
            supplied_basic = False
        raise DelegatedLoginError("The remote OAuth flow exceeded its redirect limit.")
