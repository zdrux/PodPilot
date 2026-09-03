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
            "podpilot-investigators": {"grace"},
            "podpilot-approvers": {"grace"},
        }
    )
    resolver = OpenShiftGroupRoleResolver(reader, cache_seconds=60)

    assert resolver.resolve("grace") is Role.APPROVER
    first_call_count = reader.calls
    assert resolver.resolve("grace") is Role.APPROVER
    assert reader.calls == first_call_count


def test_resolver_returns_viewer_for_authenticated_unassigned_user() -> None:
    resolver = OpenShiftGroupRoleResolver(FakeGroupReader({}), cache_seconds=0)
    assert resolver.resolve("outsider") is Role.VIEWER


def test_resolver_can_explicitly_classify_unassigned_user_as_delegated() -> None:
    resolver = OpenShiftGroupRoleResolver(
        FakeGroupReader({}), cache_seconds=0, default_role=Role.DELEGATED_OPERATOR
    )
    assert resolver.resolve("outsider") is Role.DELEGATED_OPERATOR


def test_resolver_needs_no_group_reads_when_all_elevated_mappings_are_empty() -> None:
    reader = FakeGroupReader({})
    resolver = OpenShiftGroupRoleResolver(
        reader,
        cache_seconds=0,
        role_groups=(),
    )

    assert resolver.resolve("authenticated-user") is Role.VIEWER
    assert reader.calls == 0


def test_resolver_can_still_fail_closed_when_no_default_role_is_requested() -> None:
    resolver = OpenShiftGroupRoleResolver(
        FakeGroupReader({}),
        cache_seconds=0,
        default_role=None,
    )
    assert resolver.resolve("outsider") is None


def test_resolver_supports_multiple_existing_groups_per_role() -> None:
    reader = FakeGroupReader({"corp-sre-secondary": {"lin"}})
    resolver = OpenShiftGroupRoleResolver(
        reader,
        cache_seconds=0,
        role_groups=(
            (Role.APPROVER, ("corp-platform-admins",)),
            (Role.INVESTIGATOR, ("corp-sre-primary", "corp-sre-secondary")),
        ),
    )

    assert resolver.resolve("lin") is Role.INVESTIGATOR


def test_resolver_uses_configured_precedence_and_skips_empty_roles() -> None:
    reader = FakeGroupReader({
        "corp-platform-admins": {"sam"},
    })
    resolver = OpenShiftGroupRoleResolver(
        reader,
        cache_seconds=0,
        role_groups=(
            (Role.BREAKGLASS, ()),
            (Role.APPROVER, ("corp-platform-admins",)),
            (Role.INVESTIGATOR, ()),
        ),
    )

    assert resolver.resolve("sam") is Role.APPROVER
