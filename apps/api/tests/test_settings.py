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


def test_inventory_object_ceiling_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_INVENTORY_MAX_OBJECTS", "1000")

    settings = Settings(_env_file=None)

    assert settings.adhoc_inventory_max_objects == 1000
    with pytest.raises(ValidationError):
        Settings(adhoc_inventory_max_objects=1001)


def test_resource_search_scan_ceiling_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS", "3000")

    settings = Settings(_env_file=None)

    assert settings.adhoc_search_max_scan_objects == 3000


def test_metric_trend_bounds_are_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_METRICS_MAX_RANGE_SECONDS", "604800")
    monkeypatch.setenv("PODPILOT_ADHOC_METRICS_MAX_POINTS_PER_SERIES", "500")

    settings = Settings(_env_file=None)

    assert settings.adhoc_metrics_max_range_seconds == 604800
    assert settings.adhoc_metrics_max_points_per_series == 500


def test_loki_timeout_defaults_to_scan_safe_value_and_is_bounded() -> None:
    assert Settings(_env_file=None).loki_timeout_seconds == 30
    assert Settings(loki_timeout_seconds=60).loki_timeout_seconds == 60
    with pytest.raises(ValidationError):
        Settings(loki_timeout_seconds=61)


def test_adhoc_run_deadline_is_bounded() -> None:
    assert Settings(adhoc_run_timeout_seconds=45).adhoc_run_timeout_seconds == 45
    with pytest.raises(ValidationError):
        Settings(adhoc_run_timeout_seconds=0)
    with pytest.raises(ValidationError):
        Settings(adhoc_run_timeout_seconds=901)


def test_model_timeout_ceiling_is_bounded() -> None:
    assert Settings(model_timeout_max_seconds=240).model_timeout_max_seconds == 240
    with pytest.raises(ValidationError):
        Settings(model_timeout_max_seconds=29)
    with pytest.raises(ValidationError):
        Settings(model_timeout_max_seconds=301)
