from saber.models.target import Target, TargetType
from saber.tools.network.responder import CONTRACT, ResponderWrapper


def _target():
    return Target(type=TargetType.CIDR, value="192.168.56.0/24")


def test_listen_analyze_only_command_uses_dash_a():
    wrapper = ResponderWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="listen", interface="eth0", analyze_only=True)
    assert cmd.command == ["responder", "-I", "eth0", "-A"]
    assert cmd.action == "listen"


def test_listen_active_poisoning_drops_dash_a_and_needs_authorization():
    wrapper = ResponderWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="listen", interface="eth0", analyze_only=False)
    assert cmd.command == ["responder", "-I", "eth0"]
    assert cmd.requires_explicit_authorization is True


def test_contract_marks_responder_high_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "high"
        assert action.requires_approval is True


def test_contract_declares_the_wrappers_real_action_name():
    # The wrapper implements "listen"; the plan text called it "capture".
    assert {a.action for a in CONTRACT.actions} == {"listen"}
