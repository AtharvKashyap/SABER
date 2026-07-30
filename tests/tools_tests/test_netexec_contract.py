from saber.models.target import Target, TargetType
from saber.tools.active_directory.netexec import CONTRACT, NetExecWrapper


def _target():
    return Target(type=TargetType.IP, value="10.0.0.5")


def _wrapper():
    return NetExecWrapper(sandbox=None)


def test_smb_auth_check_command():
    cmd = _wrapper().build_command(
        _target(), action="smb_auth_check", domain="LAB", username="jdoe"
    )
    assert cmd.command == [
        "nxc",
        "smb",
        "10.0.0.5",
        "-d",
        "LAB",
        "-u",
        "jdoe",
        "-p",
        "$AD_PASSWORD",
    ]
    assert cmd.action == "netexec_smb_auth_check"


def test_smb_shares_command_appends_shares_flag():
    cmd = _wrapper().build_command(
        _target(), action="smb_shares", domain="LAB", username="jdoe"
    )
    assert cmd.command == [
        "nxc",
        "smb",
        "10.0.0.5",
        "-d",
        "LAB",
        "-u",
        "jdoe",
        "-p",
        "$AD_PASSWORD",
        "--shares",
    ]
    assert cmd.action == "netexec_smb_shares"


def test_ldap_users_command_uses_ldap_protocol_and_users_flag():
    cmd = _wrapper().build_command(
        _target(), action="ldap_users", domain="LAB", username="jdoe"
    )
    assert cmd.command == [
        "nxc",
        "ldap",
        "10.0.0.5",
        "-d",
        "LAB",
        "-u",
        "jdoe",
        "-p",
        "$AD_PASSWORD",
        "--users",
    ]
    assert cmd.action == "netexec_ldap_users"


def test_local_admin_check_command_appends_local_auth_and_requires_authorization():
    cmd = _wrapper().build_command(
        _target(), action="local_admin_check", domain="LAB", username="jdoe"
    )
    assert cmd.command == [
        "nxc",
        "smb",
        "10.0.0.5",
        "-d",
        "LAB",
        "-u",
        "jdoe",
        "-p",
        "$AD_PASSWORD",
        "--local-auth",
    ]
    assert cmd.action == "netexec_local_admin_check"
    assert cmd.requires_explicit_authorization is True


def test_custom_password_env_var_is_applied():
    cmd = _wrapper().build_command(
        _target(),
        action="smb_auth_check",
        domain="LAB",
        username="jdoe",
        password_env_var="LAB_SECRET",
    )
    assert cmd.command[-1] == "$LAB_SECRET"
    assert cmd.environment == {"LAB_SECRET": ""}


def test_unsupported_action_raises():
    try:
        _wrapper().build_command(_target(), action="bogus", domain="LAB", username="jdoe")
    except ValueError as exc:
        assert "Unsupported NetExec action" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported action")


def test_contract_declares_all_four_dispatch_branches():
    assert {a.action for a in CONTRACT.actions} == {
        "smb_auth_check",
        "smb_shares",
        "ldap_users",
        "local_admin_check",
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
