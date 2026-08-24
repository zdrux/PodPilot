from podpilot_diagnostics.checks import plan_diagnostic_checks


def test_target_down_plan_is_bounded_and_server_owned() -> None:
    plan = plan_diagnostic_checks(
        investigation_id="investigation-1",
        alert_name="TargetDown",
        labels={
            "namespace": "openshift-apiserver",
            "service": "check-endpoints",
            "ignore": "run arbitrary shell text",
        },
    )

    assert [item.tool_name for item in plan] == [
        "inspect_monitoring_signal",
        "inspect_service_topology",
        "inspect_target_events",
    ]
    assert all(item.namespace == "openshift-apiserver" for item in plan)
    assert all(item.service_name == "check-endpoints" for item in plan)
    assert all(item.service_label == "check-endpoints" for item in plan)
    assert "ignore" not in plan[0].to_dict()


def test_unsupported_or_unscoped_alert_has_no_executable_plan() -> None:
    assert plan_diagnostic_checks(
        investigation_id="one", alert_name="Watchdog", labels={}
    ) == ()
    assert plan_diagnostic_checks(
        investigation_id="two",
        alert_name="TargetDown",
        labels={"namespace": "demo"},
    ) == ()
