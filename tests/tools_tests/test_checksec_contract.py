from saber.models.target import Target, TargetType
from saber.tools.reverse_engineering.checksec import CONTRACT, ChecksecWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_binary_command_applies_the_declared_json_default():
    """The contract declares output_format="json"; the wrapper must apply it.

    Without it checksec emits its cli table, which is far harder to parse — and a
    contract advertising a default the wrapper ignores is the drift this
    workstream removes.
    """

    wrapper = ChecksecWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="binary", binary_path="/opt/lab/vulnbin")
    assert cmd.command == ["checksec", "--file", "/opt/lab/vulnbin", "--output=json"]


def test_binary_command_honours_an_explicit_format():
    wrapper = ChecksecWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="binary", binary_path="/opt/lab/vulnbin", output_format="csv"
    )
    assert cmd.command == ["checksec", "--file", "/opt/lab/vulnbin", "--output=csv"]


def test_directory_command():
    wrapper = ChecksecWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="directory", directory_path="/usr/local/bin")
    assert cmd.command == ["checksec", "--dir", "/usr/local/bin", "--output=json"]


def test_kernel_command_takes_no_args():
    wrapper = ChecksecWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="kernel")
    assert cmd.command == ["checksec", "--kernel"]


def test_every_declared_action_builds_from_its_example_args():
    wrapper = ChecksecWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command, action.action


def test_contract_matches_wrapper_category_and_phase():
    wrapper = ChecksecWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_reading_a_local_binary_is_low_risk_and_autonomous():
    for action in CONTRACT.actions:
        assert action.risk == "low", action.action
        assert action.requires_approval is False, action.action
