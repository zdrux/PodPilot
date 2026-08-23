from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Protocol

from kubernetes import client, config
from kubernetes.dynamic import DynamicClient

from podpilot_api.auth import Role

ROLE_GROUPS: tuple[tuple[Role, str], ...] = (
    (Role.BREAKGLASS, "podpilot-breakglass"),
    (Role.APPROVER, "podpilot-approvers"),
    (Role.INVESTIGATOR, "podpilot-investigators"),
    (Role.VIEWER, "podpilot-viewers"),
)


class GroupReader(Protocol):
    def users(self, group_name: str) -> set[str]: ...


class DynamicGroupReader:
    def __init__(self, dynamic_client: DynamicClient) -> None:
        self._groups = dynamic_client.resources.get(
            api_version="user.openshift.io/v1",
            kind="Group",
        )

    def users(self, group_name: str) -> set[str]:
        group = self._groups.get(name=group_name)
        return set(getattr(group, "users", []) or [])


@dataclass
class OpenShiftGroupRoleResolver:
    reader: GroupReader
    cache_seconds: int = 30
    _cache: dict[str, tuple[float, Role | None]] = field(default_factory=dict)

    @classmethod
    def from_environment(cls, cache_seconds: int = 30) -> "OpenShiftGroupRoleResolver":
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        return cls(DynamicGroupReader(DynamicClient(api_client)), cache_seconds)

    def resolve(self, username: str) -> Role | None:
        now = monotonic()
        cached = self._cache.get(username)
        if cached is not None and cached[0] >= now:
            return cached[1]

        resolved: Role | None = None
        for role, group_name in ROLE_GROUPS:
            if username in self.reader.users(group_name):
                resolved = role
                break

        self._cache[username] = (now + self.cache_seconds, resolved)
        return resolved


@dataclass
class LazyOpenShiftGroupRoleResolver:
    cache_seconds: int = 30
    _resolver: OpenShiftGroupRoleResolver | None = None

    def resolve(self, username: str) -> Role | None:
        if self._resolver is None:
            self._resolver = OpenShiftGroupRoleResolver.from_environment(
                cache_seconds=self.cache_seconds
            )
        return self._resolver.resolve(username)
