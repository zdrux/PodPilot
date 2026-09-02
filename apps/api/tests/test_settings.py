import pytest
from pydantic import ValidationError

from podpilot_api.settings import Settings


def test_chat_message_limit_defaults_to_supported_maximum() -> None:
    assert Settings(_env_file=None).chat_max_chars == 4000


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


def test_detail_fanout_ceiling_is_small_and_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_DETAIL_FANOUT_MAX_OBJECTS", "12")

    settings = Settings(_env_file=None)

    assert settings.adhoc_detail_fanout_max_objects == 12
    with pytest.raises(ValidationError):
        Settings(adhoc_detail_fanout_max_objects=0)
    with pytest.raises(ValidationError):
        Settings(adhoc_detail_fanout_max_objects=26)


def test_evidence_payload_ceiling_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_MAX_PAYLOAD_BYTES", "96000")

    settings = Settings(_env_file=None)

    assert settings.adhoc_max_payload_bytes == 96_000
    with pytest.raises(ValidationError):
        Settings(adhoc_max_payload_bytes=16_383)
    with pytest.raises(ValidationError):
        Settings(adhoc_max_payload_bytes=1_048_577)


def test_resource_search_scan_ceiling_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS", "3000")

    settings = Settings(_env_file=None)

    assert settings.adhoc_search_max_scan_objects == 3000


def test_metric_trend_bounds_are_configurable(monkeypatch) -> None:
    monkeypatch.setenv("PODPILOT_ADHOC_METRICS_MAX_RANGE_SECONDS", "604800")
    monkeypatch.setenv("PODPILOT_ADHOC_METRICS_MAX_POINTS_PER_SERIES", "500")
    monkeypatch.setenv("PODPILOT_ADHOC_METRICS_MAX_RESPONSE_BYTES", "2097152")

    settings = Settings(_env_file=None)

    assert settings.adhoc_metrics_max_range_seconds == 604800
    assert settings.adhoc_metrics_max_points_per_series == 500
    assert settings.adhoc_metrics_max_response_bytes == 2_097_152
    with pytest.raises(ValidationError):
        Settings(adhoc_metrics_max_response_bytes=65_535)
    with pytest.raises(ValidationError):
        Settings(adhoc_metrics_max_response_bytes=4_194_305)


def test_loki_timeout_defaults_to_scan_safe_value_and_is_bounded() -> None:
    assert Settings(_env_file=None).loki_timeout_seconds == 90
    assert Settings(loki_timeout_seconds=120).loki_timeout_seconds == 120
    with pytest.raises(ValidationError):
        Settings(loki_timeout_seconds=121)


def test_audit_query_defaults_and_bounds_are_configurable() -> None:
    settings = Settings(
        adhoc_audit_initial_range_seconds=7200,
        adhoc_audit_max_range_seconds=172800,
        adhoc_audit_default_limit=5,
        adhoc_audit_max_response_bytes=2_097_152,
    )

    assert settings.adhoc_audit_initial_range_seconds == 7200
    assert settings.adhoc_audit_max_range_seconds == 172800
    assert settings.adhoc_audit_default_limit == 5
    assert settings.adhoc_audit_max_response_bytes == 2_097_152
    with pytest.raises(ValidationError):
        Settings(adhoc_audit_default_limit=101)
    with pytest.raises(ValidationError):
        Settings(adhoc_audit_max_response_bytes=65_535)
    with pytest.raises(ValidationError, match="initial audit search range"):
        Settings(
            adhoc_audit_initial_range_seconds=7200,
            adhoc_audit_max_range_seconds=3600,
        )


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


def test_app_wide_action_budget_defaults_to_fifty_and_is_configurable() -> None:
    assert Settings(_env_file=None).adhoc_max_reads_per_turn == 50
    assert Settings(adhoc_max_reads_per_turn=75).adhoc_max_reads_per_turn == 75
    with pytest.raises(ValidationError):
        Settings(adhoc_max_reads_per_turn=101)
    with pytest.raises(ValidationError):
        Settings(model_timeout_max_seconds=301)


def test_agent_mode_defaults_guarded_and_rejects_unknown_values() -> None:
    assert Settings(_env_file=None).agent_mode == "guarded"
    assert Settings(agent_mode="unrestricted").agent_mode == "unrestricted"
    with pytest.raises(ValidationError):
        Settings(agent_mode="unbounded")


def test_agent_command_timeout_and_heartbeat_are_bounded() -> None:
    assert Settings(_env_file=None).agent_command_timeout_seconds == 240
    settings = Settings(agent_command_timeout_seconds=120, agent_heartbeat_seconds=5)
    assert settings.agent_command_timeout_seconds == 120
    assert settings.agent_heartbeat_seconds == 5
    with pytest.raises(ValidationError):
        Settings(agent_command_timeout_seconds=4)
    with pytest.raises(ValidationError):
        Settings(agent_command_timeout_seconds=601)
    with pytest.raises(ValidationError):
        Settings(agent_heartbeat_seconds=1)
