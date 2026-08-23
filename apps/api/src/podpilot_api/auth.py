import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol

from fastapi import HTTPException, Request, status
from starlette.concurrency import run_in_threadpool

from podpilot_api.settings import Settings

# OpenShift virtual users and service-account identities commonly contain colons
# (for example, kube:admin and system:serviceaccount:namespace:name). Keep the
# header bounded and reject whitespace/control characters without treating valid
# OpenShift identity syntax as an authentication failure.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,252}$")


class Role(IntEnum):
    VIEWER = 10
    INVESTIGATOR = 20
    APPROVER = 30
    BREAKGLASS = 40

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").title()


@dataclass(frozen=True)
class AuthContext:
    username: str
    role: Role


class RoleResolver(Protocol):
    def resolve(self, username: str) -> Role | None: ...


class StaticRoleResolver:
    def __init__(self, assignments: dict[str, Role]) -> None:
        self._assignments = assignments

    def resolve(self, username: str) -> Role | None:
        return self._assignments.get(username)


def auth_dependency(settings: Settings, resolver: RoleResolver):
    async def current_user(request: Request) -> AuthContext:
        username = request.headers.get(settings.proxy_user_header, "").strip()
        if not username or not USERNAME_PATTERN.fullmatch(username):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid identity from the OpenShift OAuth proxy is required.",
            )

        try:
            role = await run_in_threadpool(resolver.resolve, username)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OpenShift role resolution is temporarily unavailable.",
            ) from exc

        if role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This OpenShift user has no PodPilot application role.",
            )
        return AuthContext(username=username, role=role)

    return current_user
