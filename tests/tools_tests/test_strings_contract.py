from saber.models.target import Target, TargetType
from saber.tools.reverse_engineering.strings import CONTRACT, StringsWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_extract_command_uses_the_default_min_length():
    wrapper = StringsWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="extract", file_path="/opt/lab/vulnbin")
    assert cmd.command == ["strings", "-n", "4", "/opt/lab/vulnbin"]


def test_extract_command_honours_min_length_and_encoding():
    wrapper = StringsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="extract", file_path="/opt/lab/vulnbin", min_length=8, encoding="l"
    )
    assert cmd.command == ["strings", "-n", "8", "-e", "l", "/opt/lab/vulnbin"]


def test_unicode_command_forces_16bit_little_endian():
    wrapper = StringsWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="unicode", file_path="/opt/lab/agent.exe")
    assert cmd.command == ["strings", "-n", "4", "-e", "l", "/opt/lab/agent.exe"]


def test_grep_command_pipes_through_grep():
    wrapper = StringsWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="grep", file_path="/opt/lab/vulnbin", pattern="password"
    )
    assert cmd.command == [
        "bash",
        "-lc",
        "strings -n 4 /opt/lab/vulnbin | grep -i -- password",
    ]


def test_every_declared_action_builds_from_its_example_args():
    wrapper = StringsWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command, action.action


def test_contract_matches_wrapper_category_and_phase():
    wrapper = StringsWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_reading_a_local_file_is_low_risk_and_autonomous():
    for action in CONTRACT.actions:
        assert action.risk == "low", action.action
        assert action.requires_approval is False, action.action


def test_every_action_can_yield_a_flag():
    """A flag can appear in any strings output, so all three declare it."""

    for action in CONTRACT.actions:
        assert "flag" in action.emits_kinds, action.action
