from saber.models.target import Target, TargetType
from saber.tools.network.bettercap import CONTRACT, BettercapWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_net_probe_command():
    wrapper = BettercapWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="net_probe", interface="eth0")
    assert cmd.command == [
        "bettercap",
        "-iface",
        "eth0",
        "-eval",
        "net.probe on; sleep 10; net.show; quit",
    ]
    assert cmd.action == "net_probe"
    assert cmd.requires_explicit_authorization is False


def test_net_recon_command():
    wrapper = BettercapWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="net_recon", interface="eth0")
    assert cmd.command == [
        "bettercap",
        "-iface",
        "eth0",
        "-eval",
        "net.recon on; sleep 10; net.show; quit",
    ]
    assert cmd.action == "net_recon"
    assert cmd.requires_explicit_authorization is False


def test_caplet_command_requires_authorization():
    wrapper = BettercapWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="caplet", interface="eth0", caplet_path="/root/caplets/probe.cap"
    )
    assert cmd.command == ["bettercap", "-iface", "eth0", "-caplet", "/root/caplets/probe.cap"]
    assert cmd.action == "caplet"
    assert cmd.requires_explicit_authorization is True


def test_contract_declares_every_real_dispatch_branch():
    assert {a.action for a in CONTRACT.actions} == {"net_probe", "net_recon", "caplet"}


def test_contract_marks_caplet_high_risk_and_approval_gated():
    caplet = next(a for a in CONTRACT.actions if a.action == "caplet")
    assert caplet.risk == "high"
    assert caplet.requires_approval is True


def test_contract_marks_passive_discovery_actions_medium_and_no_approval():
    for action_name in ("net_probe", "net_recon"):
        action = next(a for a in CONTRACT.actions if a.action == action_name)
        assert action.risk == "medium"
        assert action.requires_approval is False


def test_every_declared_action_builds_from_its_own_example_args():
    wrapper = BettercapWrapper(sandbox=None)
    for action in CONTRACT.actions:
        command = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert command.command
