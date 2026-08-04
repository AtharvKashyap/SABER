from saber.models.target import Target, TargetType
from saber.tools.network.enum4linux import CONTRACT, Enum4LinuxWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_full_enum_command():
    wrapper = Enum4LinuxWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="full_enum")
    assert cmd.command == ["enum4linux", "-o", "-a", "127.0.0.1"]
    assert cmd.action == "full_enum"


def test_users_command():
    wrapper = Enum4LinuxWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="users")
    assert cmd.command == ["enum4linux", "-o", "-U", "127.0.0.1"]
    assert cmd.action == "users"


def test_shares_command():
    wrapper = Enum4LinuxWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="shares")
    assert cmd.command == ["enum4linux", "-o", "-S", "127.0.0.1"]
    assert cmd.action == "shares"


def test_shares_command_with_credentials():
    wrapper = Enum4LinuxWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="shares", username="alice", password="secret")
    assert cmd.command == ["enum4linux", "-o", "-S", "-u", "alice", "-p", "secret", "127.0.0.1"]


def test_contract_declares_the_wrappers_three_real_actions():
    assert {a.action for a in CONTRACT.actions} == {"full_enum", "users", "shares"}


def test_contract_marks_enum4linux_medium_risk_and_approval_gated():
    for action in CONTRACT.actions:
        assert action.risk == "medium"
        assert action.requires_approval is True
