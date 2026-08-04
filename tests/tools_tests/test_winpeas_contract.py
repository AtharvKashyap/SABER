from saber.models.target import Target, TargetType
from saber.tools.post_exploit.winpeas import CONTRACT, WinpeasWrapper


def _target():
    return Target(type=TargetType.IP, value="10.0.0.22")


def test_run_exe_command_uses_the_default_binary():
    wrapper = WinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_exe")
    assert cmd.command == ["winPEASx64.exe"]
    assert cmd.requires_explicit_authorization is True


def test_run_exe_appends_arguments():
    wrapper = WinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_exe", arguments=["quiet", "systeminfo"])
    assert cmd.command == ["winPEASx64.exe", "quiet", "systeminfo"]


def test_run_cmd_capture_redirects_to_the_default_output_file():
    wrapper = WinpeasWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="run_cmd_capture")
    assert cmd.command == ["cmd.exe", "/c", "winPEASx64.exe > winpeas.out 2>&1"]


def test_declared_defaults_are_actually_applied_not_raised():
    """A contract that advertises a default while the wrapper raises is drift."""

    wrapper = WinpeasWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action)
        assert cmd.command, action.action
        assert "winPEASx64.exe" in " ".join(cmd.command)


def test_contract_matches_wrapper_category_and_phase():
    wrapper = WinpeasWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_every_action_is_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high", action.action
        assert action.requires_approval is True, action.action
