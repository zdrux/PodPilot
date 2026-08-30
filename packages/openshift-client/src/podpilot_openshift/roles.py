from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Protocol

from kubernetes import client, config
from kubernetes.dynamic import DynamicClient

from podpilot_api.auth import Role

RoleGroups = tuple[tuple[Role, tuple[str, ...]], ...]

DEFAULT_ROLE_GROUPS: RoleGroups = (
    (Role.BREAKGLASS, ("podpilot-breakglass",)),
    (Role.APPROVER, ("podpilot-approvers",)),
    (Role.INVESTIGATOR, ("podpilot-investigators",)),
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
    role_groups: RoleGroups = DEFAULT_ROLE_GROUPS
    default_role: Role | None = Role.VIEWER
    _cache: dict[str, tuple[float, Role | None]] = field(default_factory=dict)

    @classmethod
    def from_environment(
        cls,
        cache_seconds: int = 30,
        role_groups: RoleGroups = DEFAULT_ROLE_GROUPS,
        default_role: Role | None = Role.VIEWER,
    ) -> "OpenShiftGroupRoleResolver":
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        return cls(
            DynamicGroupReader(DynamicClient(api_client)),
            cache_seconds=cache_seconds,
            role_groups=role_groups,
            default_role=default_role,
        )

    def resolve(self, username: str) -> Role | None:
        now = monotonic()
        cached = self._cache.get(username)
        if cached is not None and cached[0] >= now:
            return cached[1]

        resolved = self.default_role
        matched = False
        for role, group_names in self.role_groups:
            for group_name in group_names:
                if username in self.reader.users(group_name):
                    resolved = role
                    matched = True
                    break
            if matched:
                break

        self._cache[username] = (now + self.cache_seconds, resolved)
        return resolved


@dataclass
class LazyOpenShiftGroupRoleResolver:
    cache_seconds: int = 30
    role_groups: RoleGroups = DEFAULT_ROLE_GROUPS
    default_role: Role | None = Role.VIEWER
    _resolver: OpenShiftGroupRoleResolver | None = None

    def resolve(self, username: str) -> Role | None:
        if self._resolver is None:
            self._resolver = OpenShiftGroupRoleResolver.from_environment(
                cache_seconds=self.cache_seconds,
                role_groups=self.role_groups,
                default_role=self.default_role,
            )
        return self._resolver.resolve(username)
