from saber.models.target import Target, TargetType
from saber.tools.reverse_engineering.file import CONTRACT, FileWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_identify_command():
    wrapper = FileWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="identify", file_path="/opt/lab/vulnbin")
    assert cmd.command == ["file", "/opt/lab/vulnbin"]


def test_identify_brief_inserts_dash_b_before_the_path():
    wrapper = FileWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="identify", file_path="/opt/lab/vulnbin", brief=True
    )
    assert cmd.command == ["file", "-b", "/opt/lab/vulnbin"]


def test_mime_command():
    wrapper = FileWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="mime", file_path="/opt/lab/vulnbin")
    assert cmd.command == ["file", "--mime", "/opt/lab/vulnbin"]


def test_directory_command_is_depth_limited_by_default():
    wrapper = FileWrapper(sandbox=None)
    cmd = wrapper.build_command(_target(), action="directory", directory_path="/opt/lab")
    assert cmd.command == [
        "find",
        "/opt/lab",
        "-type",
        "f",
        "-maxdepth",
        "1",
        "-exec",
        "file",
        "{}",
        ";",
    ]


def test_directory_recursive_drops_the_depth_limit():
    wrapper = FileWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="directory", directory_path="/opt/lab", recursive=True
    )
    assert "-maxdepth" not in cmd.command


def test_every_declared_action_builds_from_its_example_args():
    wrapper = FileWrapper(sandbox=None)
    for action in CONTRACT.actions:
        cmd = wrapper.build_command(_target(), action=action.action, **action.example_args)
        assert cmd.command, action.action


def test_contract_matches_wrapper_category_and_phase():
    wrapper = FileWrapper(sandbox=None)
    assert CONTRACT.category == wrapper.config.category.value
    assert CONTRACT.phase == wrapper.config.phase.value


def test_identifying_a_local_file_is_low_risk_and_autonomous():
    for action in CONTRACT.actions:
        assert action.risk == "low", action.action
        assert action.requires_approval is False, action.action
