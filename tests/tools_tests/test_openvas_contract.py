from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.network.openvas_api import CONTRACT, OpenVASApiWrapper


def _target() -> Target:
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_create_target_command():
    wrapper = OpenVASApiWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="create_target", name="saber-target")
    assert cmd.command == [
        "openvas-cli",
        "target-create",
        "--name",
        "saber-target",
        "--hosts",
        "127.0.0.1",
    ]
    assert cmd.action == "create_target"


def test_create_task_command():
    wrapper = OpenVASApiWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="create_task",
        name="saber-task",
        target_id="11111111-1111-1111-1111-111111111111",
        scan_config_id="22222222-2222-2222-2222-222222222222",
    )
    assert cmd.command == [
        "openvas-cli",
        "task-create",
        "--name",
        "saber-task",
        "--target-id",
        "11111111-1111-1111-1111-111111111111",
        "--scan-config-id",
        "22222222-2222-2222-2222-222222222222",
    ]
    assert cmd.action == "create_task"


def test_start_task_command():
    wrapper = OpenVASApiWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="start_task", task_id="33333333-3333-3333-3333-333333333333"
    )
    assert cmd.command == [
        "openvas-cli",
        "task-start",
        "--task-id",
        "33333333-3333-3333-3333-333333333333",
    ]
    assert cmd.action == "start_task"


def test_get_report_command_defaults_to_xml():
    wrapper = OpenVASApiWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="get_report", report_id="44444444-4444-4444-4444-444444444444"
    )
    assert cmd.command == [
        "openvas-cli",
        "report-get",
        "--report-id",
        "44444444-4444-4444-4444-444444444444",
        "--format",
        "xml",
    ]
    assert cmd.action == "get_report"


def test_get_report_command_honors_explicit_format():
    wrapper = OpenVASApiWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_report",
        report_id="44444444-4444-4444-4444-444444444444",
        output_format="json",
    )
    assert cmd.command == [
        "openvas-cli",
        "report-get",
        "--report-id",
        "44444444-4444-4444-4444-444444444444",
        "--format",
        "json",
    ]


def test_contract_marks_all_actions_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high"
        assert action.requires_approval is True


def test_contract_declares_all_four_wrapper_actions():
    assert {a.action for a in CONTRACT.actions} == {
        "create_target",
        "create_task",
        "start_task",
        "get_report",
    }
