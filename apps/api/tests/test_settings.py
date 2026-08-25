import pytest
from pydantic import ValidationError

from podpilot_api.settings import Settings


def test_role_groups_are_loaded_from_json_environment_lists(monkeypatch) -> None:
    monkeypatch.setenv(
        "PODPILOT_ROLE_INVESTIGATOR_GROUPS",
        '["corp-sre-primary", "corp-sre-secondary"]',
    )
    monkeypatch.setenv("PODPILOT_ROLE_BREAKGLASS_GROUPS", "[]")

    settings = Settings(_env_file=None)

    assert settings.role_investigator_groups == ["corp-sre-primary", "corp-sre-secondary"]
    assert settings.role_breakglass_groups == []


def test_role_group_names_are_trimmed_and_deduplicated() -> None:
    settings = Settings(
        role_investigator_groups=[" corp-operations ", "corp-operations"],
    )
    assert settings.role_investigator_groups == ["corp-operations"]


def test_same_group_cannot_map_to_multiple_application_roles() -> None:
    with pytest.raises(ValidationError, match="only one PodPilot role"):
        Settings(
            role_investigator_groups=["corp-operations"],
            role_approver_groups=["corp-operations"],
        )


def test_all_elevated_role_groups_may_be_empty() -> None:
    settings = Settings(
        role_investigator_groups=[],
        role_approver_groups=[],
        role_breakglass_groups=[],
    )

    assert settings.role_investigator_groups == []
    assert settings.role_approver_groups == []
    assert settings.role_breakglass_groups == []
