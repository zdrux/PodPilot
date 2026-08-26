from __future__ import annotations

import base64
import os
from typing import Protocol

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


class CredentialStoreError(RuntimeError):
    pass


class CredentialStore(Protocol):
    def get(self, key: str | None = None) -> str | None: ...
    def set(self, value: str, key: str | None = None) -> None: ...
    def delete(self, key: str | None = None) -> None: ...


class EnvironmentCredentialStore:
    """Read-only local-development store; it never persists submitted values."""

    def __init__(self, variable: str = "OPENAI_API_KEY") -> None:
        self.variable = variable

    def get(self, key: str | None = None) -> str | None:
        return os.environ.get(self.variable) or None

    def set(self, value: str, key: str | None = None) -> None:
        raise CredentialStoreError(
            "This runtime reads its model token from the process environment and cannot update it."
        )

    def delete(self, key: str | None = None) -> None:
        raise CredentialStoreError("Environment-backed model credentials cannot be deleted here.")


class KubernetesSecretCredentialStore:
    """Store opaque tokens as keys in one pre-created, resourceName-restricted Secret."""

    def __init__(self, namespace: str, secret_name: str, key: str = "api_key") -> None:
        config.load_incluster_config()
        self._api = client.CoreV1Api()
        self.namespace = namespace
        self.secret_name = secret_name
        self.key = key

    def get(self, key: str | None = None) -> str | None:
        try:
            secret = self._api.read_namespaced_secret(self.secret_name, self.namespace)
        except ApiException as exc:
            raise CredentialStoreError("The credential Secret could not be read.") from exc
        encoded = (secret.data or {}).get(key or self.key)
        if not encoded:
            return None
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CredentialStoreError("The credential Secret contains invalid data.") from exc

    def set(self, value: str, key: str | None = None) -> None:
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        try:
            self._api.patch_namespaced_secret(
                self.secret_name,
                self.namespace,
                {"data": {key or self.key: encoded}},
            )
        except ApiException as exc:
            raise CredentialStoreError("The credential Secret could not be updated.") from exc

    def delete(self, key: str | None = None) -> None:
        try:
            self._api.patch_namespaced_secret(
                self.secret_name, self.namespace, {"data": {key or self.key: None}}
            )
        except ApiException as exc:
            raise CredentialStoreError("The credential could not be removed.") from exc
