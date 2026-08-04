from saber.models.target import Target, TargetType
from saber.tools.post_exploit.mimikatz import CONTRACT, MimikatzWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def _wrapper():
    return MimikatzWrapper(sandbox=None)


def test_logonpasswords_command():
    cmd = _wrapper().build_command(_target(), action="logonpasswords", exe_path="mimikatz.exe")
    assert cmd.command == [
        "mimikatz.exe",
        '"privilege::debug"',
        '"sekurlsa::logonpasswords"',
        '"exit"',
    ]
    assert cmd.action == "logonpasswords"
    assert cmd.requires_explicit_authorization is True


def test_dump_tickets_command():
    cmd = _wrapper().build_command(_target(), action="dump_tickets", exe_path="mimikatz.exe")
    assert cmd.command == ["mimikatz.exe", '"privilege::debug"', '"sekurlsa::tickets"', '"exit"']
    assert cmd.action == "dump_tickets"
    assert cmd.requires_explicit_authorization is True


def test_lsadump_sam_command():
    cmd = _wrapper().build_command(_target(), action="lsadump_sam", exe_path="mimikatz.exe")
    assert cmd.command == [
        "mimikatz.exe",
        '"privilege::debug"',
        '"token::elevate"',
        '"lsadump::sam"',
        '"exit"',
    ]
    assert cmd.action == "lsadump_sam"
    assert cmd.requires_explicit_authorization is True


def test_custom_script_command_appends_exit():
    cmd = _wrapper().build_command(
        _target(),
        action="custom_script",
        exe_path="mimikatz.exe",
        commands=["privilege::debug", "sekurlsa::logonpasswords"],
    )
    assert cmd.command == [
        "mimikatz.exe",
        '"privilege::debug"',
        '"sekurlsa::logonpasswords"',
        '"exit"',
    ]
    assert cmd.action == "custom_script"
    assert cmd.requires_explicit_authorization is True


def test_exe_path_defaults_when_omitted():
    """CONTRACT declares exe_path optional with a default; the wrapper must apply it."""

    cmd = _wrapper().build_command(_target(), action="logonpasswords")
    assert cmd.command[0] == "mimikatz.exe"


def test_unsupported_action_raises():
    try:
        _wrapper().build_command(_target(), action="bogus", exe_path="mimikatz.exe")
    except ValueError as exc:
        assert "Unsupported Mimikatz action" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported action")


def test_contract_declares_all_four_dispatch_branches():
    assert {a.action for a in CONTRACT.actions} == {
        "logonpasswords",
        "dump_tickets",
        "lsadump_sam",
        "custom_script",
    }


def test_contract_marks_every_action_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high"
        assert action.requires_approval is True


def test_contract_actions_are_buildable_from_their_own_example_args():
    wrapper = _wrapper()
    for action in CONTRACT.actions:
        command = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert command.command


def test_contract_declares_no_reserved_args():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        assert not ({spec.name for spec in action.args} & reserved)
        assert not (set(action.example_args) & reserved)
