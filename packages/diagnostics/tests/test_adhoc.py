from podpilot_diagnostics.adhoc import ReadIntent, normalize_read_intent


def test_known_resource_coordinates_are_canonicalized() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        api_version="core/v1/invalid",
        kind="pods",
        namespace="ai-ops",
        limit=3,
    )

    normalized = normalize_read_intent(proposed)

    assert normalized.api_version == "v1"
    assert normalized.kind == "Pod"
    assert normalized.namespace == "ai-ops"
    assert normalized.limit == 3


def test_custom_resource_coordinates_remain_model_proposed_for_broker_validation() -> None:
    proposed = ReadIntent(
        tool="list_resources",
        api_version="example.io/v1",
        kind="Widget",
    )

    assert normalize_read_intent(proposed) == proposed


def test_pod_log_coordinates_are_not_rewritten() -> None:
    proposed = ReadIntent(
        tool="pod_logs", kind="pods", namespace="ai-ops", name="podpilot-1"
    )

    assert normalize_read_intent(proposed) == proposed
