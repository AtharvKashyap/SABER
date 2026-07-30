from saber.models.target import Target, TargetType
from saber.tools.post_exploit.chisel import CONTRACT, ChiselWrapper


def _target():
    return Target(type=TargetType.IP, value="10.0.0.5")


def test_server_command_defaults_to_reverse_without_socks5():
    wrapper = ChiselWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="server", listen_port=8000, reverse=True)
    assert cmd.command == ["chisel", "server", "-p", "8000", "--reverse"]
    assert cmd.requires_explicit_authorization is True


def test_server_command_can_enable_socks5():
    wrapper = ChiselWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="server", listen_port=9001, socks5=True)
    assert cmd.command == ["chisel", "server", "-p", "9001", "--reverse", "--socks5"]


def test_client_command_forwards_the_remote_spec():
    wrapper = ChiselWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="client", server="http://10.0.0.1:8000", remote="R:3389:10.0.0.5:3389"
    )
    assert cmd.command == ["chisel", "client", "http://10.0.0.1:8000", "R:3389:10.0.0.5:3389"]


def test_reverse_socks_builds_the_socks_remote_spec():
    wrapper = ChiselWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="reverse_socks", server="http://10.0.0.1:8000", socks_port=1080
    )
    assert cmd.command == ["chisel", "client", "http://10.0.0.1:8000", "R:socks:1080"]
    assert cmd.metadata["socks_port"] == 1080


def test_every_action_is_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high", action.action
        assert action.requires_approval is True, action.action


def test_contract_does_not_claim_to_create_sessions():
    """A tunnel grants reachability, not an interactive foothold."""

    for action in CONTRACT.actions:
        assert "session" not in action.emits_kinds
        assert action.emits_kinds == ("note",)
