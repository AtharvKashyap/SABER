from saber.models.target import Target, TargetType
from saber.tools.network.snmpwalk import SnmpwalkWrapper


def test_enumerate_command_uses_defaults():
    wrapper = SnmpwalkWrapper(sandbox=None)  # build_command does not touch sandbox
    cmd = wrapper.build_command(
        Target(type=TargetType.IP, value="127.0.0.1"),
        action="enumerate",
        community="public",
    )
    assert cmd.command == [
        "snmpwalk",
        "-v",
        "2c",
        "-c",
        "public",
        "127.0.0.1",
        "1.3.6.1.2.1",
    ]
    assert cmd.action == "enumerate"


def test_enumerate_command_respects_overrides():
    wrapper = SnmpwalkWrapper(sandbox=None)
    cmd = wrapper.build_command(
        Target(type=TargetType.IP, value="10.0.0.5"),
        action="enumerate",
        community="private",
        oid="1.3.6.1.2.1.25",
        version="1",
    )
    assert cmd.command == [
        "snmpwalk",
        "-v",
        "1",
        "-c",
        "private",
        "10.0.0.5",
        "1.3.6.1.2.1.25",
    ]


def test_unsupported_action_raises():
    wrapper = SnmpwalkWrapper(sandbox=None)
    try:
        wrapper.build_command(
            Target(type=TargetType.IP, value="127.0.0.1"), action="bogus"
        )
    except ValueError as exc:
        assert "Unsupported SNMPWalk action" in str(exc)
    else:
        raise AssertionError("expected ValueError for unsupported action")
