from __future__ import annotations

import base64
import os
from typing import Protocol

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


class CredentialStoreError(RuntimeError):
    pass


class CredentialStore(Protocol):
    def get(self) -> str | None: ...
    def set(self, value: str) -> None: ...


class EnvironmentCredentialStore:
    """Read-only local-development store; it never persists submitted values."""

    def __init__(self, variable: str = "OPENAI_API_KEY") -> None:
        self.variable = variable

    def get(self) -> str | None:
        return os.environ.get(self.variable) or None

    def set(self, value: str) -> None:
        raise CredentialStoreError(
            "This runtime reads its model token from the process environment and cannot update it."
        )


class KubernetesSecretCredentialStore:
    """Store one token in one pre-created, resourceName-restricted Secret."""

    def __init__(self, namespace: str, secret_name: str, key: str = "api_key") -> None:
        config.load_incluster_config()
        self._api = client.CoreV1Api()
        self.namespace = namespace
        self.secret_name = secret_name
        self.key = key

    def get(self) -> str | None:
        try:
            secret = self._api.read_namespaced_secret(self.secret_name, self.namespace)
        except ApiException as exc:
            raise CredentialStoreError("The model credential Secret could not be read.") from exc
        encoded = (secret.data or {}).get(self.key)
        if not encoded:
            return None
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CredentialStoreError("The model credential Secret contains invalid data.") from exc

    def set(self, value: str) -> None:
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        try:
            self._api.patch_namespaced_secret(
                self.secret_name,
                self.namespace,
                {"data": {self.key: encoded}},
            )
        except ApiException as exc:
            raise CredentialStoreError("The model credential Secret could not be updated.") from exc
