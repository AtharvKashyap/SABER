from saber.models.target import Target, TargetType
from saber.tools.reverse_engineering.radare2 import CONTRACT, Radare2Wrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_analyze_command_defaults_to_aaa():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="analyze", binary_path="/tmp/challenge.bin")
    assert cmd.command == ["r2", "-q", "-c", "aaa", "-c", "q", "/tmp/challenge.bin"]
    assert cmd.action == "analyze"


def test_analyze_command_honors_explicit_level():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="analyze", binary_path="/tmp/challenge.bin", analysis_level="aaaa"
    )
    assert cmd.command == ["r2", "-q", "-c", "aaaa", "-c", "q", "/tmp/challenge.bin"]


def test_info_command_uses_ij_by_default():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="info", binary_path="/tmp/challenge.bin")
    assert cmd.command == ["r2", "-q", "-c", "ij", "-c", "q", "/tmp/challenge.bin"]


def test_info_command_uses_i_when_json_output_is_false():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="info", binary_path="/tmp/challenge.bin", json_output=False
    )
    assert cmd.command == ["r2", "-q", "-c", "i", "-c", "q", "/tmp/challenge.bin"]


def test_functions_command_uses_aflj_by_default():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="functions", binary_path="/tmp/challenge.bin")
    assert cmd.command == [
        "r2",
        "-q",
        "-c",
        "aaa",
        "-c",
        "aflj",
        "-c",
        "q",
        "/tmp/challenge.bin",
    ]


def test_functions_command_uses_afl_when_json_output_is_false():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="functions", binary_path="/tmp/challenge.bin", json_output=False
    )
    assert cmd.command == ["r2", "-q", "-c", "aaa", "-c", "afl", "-c", "q", "/tmp/challenge.bin"]


def test_custom_commands_builds_a_c_flag_per_command():
    wrapper = Radare2Wrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="custom_commands",
        binary_path="/tmp/challenge.bin",
        commands=["aaa", "afl", "pdf @main"],
    )
    assert cmd.command == [
        "r2",
        "-q",
        "-c",
        "aaa",
        "-c",
        "afl",
        "-c",
        "pdf @main",
        "-c",
        "q",
        "/tmp/challenge.bin",
    ]
    assert cmd.action == "custom_commands"


def test_custom_commands_requires_at_least_one_command():
    import pytest

    wrapper = Radare2Wrapper(sandbox=None)
    with pytest.raises(ValueError):
        wrapper.build_command(_target(), action="custom_commands", binary_path="/tmp/challenge.bin")


def test_contract_matches_wrapper_category_and_phase():
    wrapper = Radare2Wrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_declared_defaults_are_actually_applied_not_raised():
    """A contract that advertises a default while the wrapper raises is drift."""

    wrapper = Radare2Wrapper(sandbox=None)
    for action in CONTRACT.actions:
        if action.action == "custom_commands":
            # commands has no sensible default; it is genuinely required.
            continue
        cmd = wrapper.build_command(
            _target(), action=action.action, binary_path="/tmp/challenge.bin"
        )
        assert cmd.command, action.action


def test_custom_commands_and_only_custom_commands_are_approval_gated():
    gated = {a.action for a in CONTRACT.actions if a.requires_approval}
    assert gated == {"custom_commands"}
    for action in CONTRACT.actions:
        if action.action == "custom_commands":
            assert action.risk == "medium"
        else:
            assert action.risk == "low"
            assert action.requires_approval is False
