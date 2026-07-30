from saber.models.target import Target, TargetType
from saber.tools.lateral_movement.session_checks import CONTRACT, SessionChecksWrapper


def _target():
    return Target(type=TargetType.IP, value="127.0.0.1")


def test_validate_session_command_includes_target_and_protocol():
    wrapper = SessionChecksWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(), action="validate_session", session_id="sess-1001", protocol="ssh"
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.session_checks",
        "validate-session",
        "--session-id",
        "sess-1001",
        "--target",
        "127.0.0.1",
        "--protocol",
        "ssh",
    ]
    assert cmd.requires_explicit_authorization is False


def test_validate_session_command_includes_expected_user_when_given():
    wrapper = SessionChecksWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="validate_session",
        session_id="sess-1001",
        expected_user="svc-backup",
    )
    assert cmd.command[-2:] == ["--expected-user", "svc-backup"]


def test_summarize_sessions_command_reads_a_sessions_file():
    wrapper = SessionChecksWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="summarize_sessions",
        sessions_file="lateral_movement/session_checks/sessions.json",
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.session_checks",
        "summarize-sessions",
        "--input",
        "lateral_movement/session_checks/sessions.json",
    ]
    assert cmd.requires_explicit_authorization is False


def test_authenticated_reachability_command_requires_authorization():
    wrapper = SessionChecksWrapper(sandbox=None)
    cmd = wrapper.build_command(
        _target(),
        action="authenticated_reachability",
        source="WKSTN01",
        protocol="smb",
        credential_ref="cred-42",
    )
    assert cmd.command == [
        "python",
        "-m",
        "saber.tools.lateral_movement.session_checks",
        "authenticated-reachability",
        "--source",
        "WKSTN01",
        "--target",
        "127.0.0.1",
        "--protocol",
        "smb",
        "--credential-ref",
        "cred-42",
    ]
    assert cmd.requires_explicit_authorization is True


def test_authenticated_reachability_is_the_only_medium_risk_action():
    for action in CONTRACT.actions:
        if action.action == "authenticated_reachability":
            assert action.risk == "medium"
            assert action.requires_approval is True
        else:
            assert action.risk == "low"
            assert action.requires_approval is False


def test_validate_session_may_emit_a_session_but_reachability_never_does():
    for action in CONTRACT.actions:
        if action.action == "validate_session":
            assert "session" in action.emits_kinds
        else:
            assert "session" not in action.emits_kinds


def test_no_action_declares_a_reserved_arg_name():
    reserved = {"target", "session", "action", "metadata"}
    for action in CONTRACT.actions:
        names = {spec.name for spec in action.args}
        assert not (names & reserved), (action.action, names)
        assert not (set(action.example_args) & reserved), action.action
