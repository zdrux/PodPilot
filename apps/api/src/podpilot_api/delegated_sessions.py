from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class DelegatedConnection:
    session_id: str
    owner: str
    cluster_id: str
    remote_username: str
    remote_uid: str
    token: str = field(repr=False)
    proxy_capability: str
    created_at: datetime
    expires_at: datetime


class DelegatedSessionVault:
    """Process-local delegated credentials, bounded by a PodPilot browser session."""

    def __init__(self, *, lifetime_seconds: int = 7200) -> None:
        self.lifetime_seconds = lifetime_seconds
        self._lock = threading.RLock()
        self._connections: dict[tuple[str, str], DelegatedConnection] = {}
        self._capabilities: dict[str, tuple[str, str]] = {}
        self._expired: list[DelegatedConnection] = []
        self._login_attempts: dict[str, list[datetime]] = {}

    @staticmethod
    def new_session_id() -> str:
        return secrets.token_urlsafe(32)

    def allow_login(self, *, owner: str, attempts_per_minute: int) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=1)
        with self._lock:
            attempts = [item for item in self._login_attempts.get(owner, []) if item > cutoff]
            if len(attempts) >= attempts_per_minute:
                self._login_attempts[owner] = attempts
                return False
            attempts.append(now)
            self._login_attempts[owner] = attempts
            return True

    def put(
        self,
        *,
        session_id: str,
        owner: str,
        cluster_id: str,
        remote_username: str,
        remote_uid: str,
        token: str,
    ) -> DelegatedConnection:
        now = datetime.now(timezone.utc)
        connection = DelegatedConnection(
            session_id=session_id,
            owner=owner,
            cluster_id=cluster_id,
            remote_username=remote_username,
            remote_uid=remote_uid,
            token=token,
            proxy_capability=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + timedelta(seconds=self.lifetime_seconds),
        )
        with self._lock:
            prior = self._connections.pop((session_id, cluster_id), None)
            if prior is not None:
                self._capabilities.pop(prior.proxy_capability, None)
            self._connections[(session_id, cluster_id)] = connection
            self._capabilities[connection.proxy_capability] = (session_id, cluster_id)
        return connection

    def get(self, *, session_id: str, owner: str, cluster_id: str) -> DelegatedConnection | None:
        with self._lock:
            connection = self._connections.get((session_id, cluster_id))
            if connection is None or connection.owner != owner:
                return None
            if connection.expires_at <= datetime.now(timezone.utc):
                self._expired.append(connection)
                self._remove_locked(connection)
                return None
            return connection

    def by_capability(self, capability: str) -> DelegatedConnection | None:
        with self._lock:
            key = self._capabilities.get(capability)
            connection = self._connections.get(key) if key else None
            if connection is None:
                return None
            if connection.expires_at <= datetime.now(timezone.utc):
                self._expired.append(connection)
                self._remove_locked(connection)
                return None
            return connection

    def list_for(self, *, session_id: str, owner: str) -> list[DelegatedConnection]:
        with self._lock:
            result: list[DelegatedConnection] = []
            for connection in list(self._connections.values()):
                if connection.expires_at <= datetime.now(timezone.utc):
                    self._expired.append(connection)
                    self._remove_locked(connection)
                elif connection.session_id == session_id and connection.owner == owner:
                    result.append(connection)
            return sorted(result, key=lambda item: item.cluster_id)

    def pop_session(self, *, session_id: str, owner: str) -> list[DelegatedConnection]:
        with self._lock:
            result = [
                item for item in self._connections.values()
                if item.session_id == session_id and item.owner == owner
            ]
            for connection in result:
                self._remove_locked(connection)
            return result

    def pop_connection(
        self, *, session_id: str, owner: str, cluster_id: str
    ) -> DelegatedConnection | None:
        with self._lock:
            connection = self._connections.get((session_id, cluster_id))
            if connection is None or connection.owner != owner:
                return None
            self._remove_locked(connection)
            return connection

    def pop_expired(self) -> list[DelegatedConnection]:
        with self._lock:
            now = datetime.now(timezone.utc)
            for connection in list(self._connections.values()):
                if connection.expires_at <= now:
                    self._expired.append(connection)
                    self._remove_locked(connection)
            expired, self._expired = self._expired, []
            return expired

    def pop_all(self) -> list[DelegatedConnection]:
        with self._lock:
            result = list(self._connections.values()) + self._expired
            for connection in list(self._connections.values()):
                self._remove_locked(connection)
            self._expired = []
            return result

    def pop_cluster(self, cluster_id: str) -> list[DelegatedConnection]:
        with self._lock:
            result = [
                item for item in self._connections.values()
                if item.cluster_id == cluster_id
            ]
            for connection in result:
                self._remove_locked(connection)
            return result

    def _remove_locked(self, connection: DelegatedConnection) -> None:
        self._connections.pop((connection.session_id, connection.cluster_id), None)
        self._capabilities.pop(connection.proxy_capability, None)
