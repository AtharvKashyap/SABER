from saber.models.target import Target, TargetType
from saber.tools.active_directory.impacket_tools import CONTRACT, ImpacketToolsWrapper


def _target():
    return Target(type=TargetType.IP, value="10.0.0.5")


def test_get_ad_users_command():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_ad_users",
        domain="corp.local",
        username="svc-recon",
        password_env_var="AD_PASSWORD",
    )
    assert cmd.command == [
        "impacket-GetADUsers",
        "corp.local/svc-recon:$AD_PASSWORD",
        "-all",
    ]
    assert cmd.action == "impacket_get_ad_users"


def test_get_ad_users_command_includes_dc_ip():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_ad_users",
        domain="corp.local",
        username="svc-recon",
        dc_ip="10.0.0.1",
    )
    assert cmd.command == [
        "impacket-GetADUsers",
        "corp.local/svc-recon:$AD_PASSWORD",
        "-all",
        "-dc-ip",
        "10.0.0.1",
    ]


def test_get_spns_command_without_request_tickets():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_spns",
        domain="corp.local",
        username="svc-recon",
        request_tickets=False,
    )
    assert cmd.command == ["impacket-GetUserSPNs", "corp.local/svc-recon:$AD_PASSWORD"]
    assert cmd.requires_explicit_authorization is False


def test_get_spns_command_with_request_tickets_requires_authorization():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_spns",
        domain="corp.local",
        username="svc-recon",
        request_tickets=True,
        dc_ip="10.0.0.1",
    )
    assert cmd.command == [
        "impacket-GetUserSPNs",
        "corp.local/svc-recon:$AD_PASSWORD",
        "-request",
        "-dc-ip",
        "10.0.0.1",
    ]
    assert cmd.requires_explicit_authorization is True


def test_get_asrep_candidates_command():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="get_asrep_candidates",
        domain="corp.local",
        username_file="/evidence/usernames.txt",
    )
    assert cmd.command == [
        "impacket-GetNPUsers",
        "corp.local",
        "-usersfile",
        "/evidence/usernames.txt",
        "-no-pass",
    ]
    assert cmd.action == "impacket_get_asrep_candidates"
    assert cmd.requires_explicit_authorization is True


def test_smb_exec_check_command():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="smb_exec_check",
        domain="corp.local",
        username="administrator",
    )
    assert cmd.command == [
        "impacket-psexec",
        "corp.local/administrator:$AD_PASSWORD",
        "@10.0.0.5",
        "whoami",
    ]
    assert cmd.action == "impacket_smb_exec_check"
    assert cmd.requires_explicit_authorization is True


def test_contract_declares_all_four_real_dispatch_actions():
    assert {a.action for a in CONTRACT.actions} == {
        "get_ad_users",
        "get_spns",
        "get_asrep_candidates",
        "smb_exec_check",
    }


def test_contract_marks_every_action_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high"
        assert action.requires_approval is True


def test_contract_actions_are_buildable_from_example_args():
    wrapper = ImpacketToolsWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command


def test_contract_declares_no_reserved_args():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        arg_names = {spec.name for spec in action.args}
        assert not (arg_names & reserved)
        assert not (set(action.example_args) & reserved)
