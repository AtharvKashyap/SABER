from saber.models.target import Target, TargetType
from saber.tools.lateral_movement.path_validation import CONTRACT, PathValidationWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_validate_step_command_includes_source_target_and_technique():
    wrapper = PathValidationWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="validate_step", source="WKSTN01", technique="psexec"
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.path_validation",
        "validate-step",
        "--source",
        "WKSTN01",
        "--target",
        "127.0.0.1",
        "--technique",
        "psexec",
    ]
    assert cmd.requires_explicit_authorization is False


def test_validate_step_command_includes_credential_ref_when_given():
    wrapper = PathValidationWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="validate_step",
        source="WKSTN01",
        technique="psexec",
        credential_ref="cred-42",
    )
    assert cmd.command[-2:] == ["--credential-ref", "cred-42"]


def test_validate_path_command_reads_a_path_file():
    wrapper = PathValidationWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="validate_path",
        path_file="lateral_movement/plan/paths/candidates.json",
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.path_validation",
        "validate-path",
        "--input",
        "lateral_movement/plan/paths/candidates.json",
    ]
    assert cmd.requires_explicit_authorization is False


def test_dry_run_path_command_requires_authorization():
    wrapper = PathValidationWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="dry_run_path",
        path_file="lateral_movement/plan/paths/candidates.json",
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.path_validation",
        "dry-run-path",
        "--input",
        "lateral_movement/plan/paths/candidates.json",
    ]
    assert cmd.requires_explicit_authorization is True


def test_dry_run_path_is_the_only_medium_risk_action():
    for action in CONTRACT.actions:
        if action.action == "dry_run_path":
            assert action.risk == "medium"
            assert action.requires_approval is True
        else:
            assert action.risk == "low"
            assert action.requires_approval is False


def test_no_action_declares_a_reserved_arg_name():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        names = {spec.name for spec in action.args}
        assert not (names & reserved), (action.action, names)
        assert not (set(action.example_args) & reserved), action.action
