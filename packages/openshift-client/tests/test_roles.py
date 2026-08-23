from podpilot_api.auth import Role
from podpilot_openshift.roles import OpenShiftGroupRoleResolver


class FakeGroupReader:
    def __init__(self, memberships: dict[str, set[str]]) -> None:
        self.memberships = memberships
        self.calls = 0

    def users(self, group_name: str) -> set[str]:
        self.calls += 1
        return self.memberships.get(group_name, set())


def test_resolver_selects_highest_role_and_caches() -> None:
    reader = FakeGroupReader(
        {
            "podpilot-viewers": {"grace"},
            "podpilot-investigators": {"grace"},
            "podpilot-approvers": {"grace"},
        }
    )
    resolver = OpenShiftGroupRoleResolver(reader, cache_seconds=60)

    assert resolver.resolve("grace") is Role.APPROVER
    first_call_count = reader.calls
    assert resolver.resolve("grace") is Role.APPROVER
    assert reader.calls == first_call_count


def test_resolver_returns_none_for_unassigned_user() -> None:
    resolver = OpenShiftGroupRoleResolver(FakeGroupReader({}), cache_seconds=0)
    assert resolver.resolve("outsider") is None
