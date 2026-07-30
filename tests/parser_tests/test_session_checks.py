import json
from pathlib import Path

from saber.parsers.session_checks import SessionChecksParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_session_checks_output.json")


def _observations():
    result = SessionChecksParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_validate_session_valid_emits_a_note_and_a_session():
    _, obs = _observations()
    kinds = [o["kind"] for o in obs]
    assert kinds == ["note", "session"]
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "Session sess-1001 validated as live", "severity": "info"},
    )
    assert_observation(
        obs[1],
        kind="session",
        data_subset={"host": "10.0.0.5", "kind": "ssh", "user": "svc-backup", "ref": "sess-1001"},
    )


def test_validate_session_grows_mission_state_notes_and_sessions():
    _, obs = _observations()
    state = merge_observations(obs, tool="session_checks", action="validate_session")
    assert len(state.notes) == 1
    assert len(state.sessions) == 1
    assert state.sessions[0].host == "10.0.0.5"


def test_validate_session_invalid_never_fabricates_a_session():
    payload = {
        "action": "validate_session",
        "session_id": "sess-1002",
        "host": "10.0.0.6",
        "protocol": "winrm",
        "valid": False,
    }
    result = SessionChecksParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert {o["kind"] for o in obs} == {"note"}
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "Session sess-1002 is no longer valid", "severity": "medium"},
    )
    state = merge_observations(obs, tool="session_checks", action="validate_session")
    assert state.sessions == []


def test_validate_session_without_host_never_fabricates_a_session():
    """KnownSession.host is required; a valid record without a host stays note-only."""

    payload = {"action": "validate_session", "session_id": "sess-1003", "valid": True}
    result = SessionChecksParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert {o["kind"] for o in obs} == {"note"}


def test_summarize_sessions_emits_notes_only():
    payload = {
        "action": "summarize_sessions",
        "sessions": [
            {"session_id": "sess-1001", "host": "10.0.0.5", "protocol": "ssh", "status": "active"},
            {"session_id": "sess-1002", "host": "10.0.0.6", "protocol": "winrm", "status": "stale"},
        ],
    }
    result = SessionChecksParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert {o["kind"] for o in obs} == {"note"}
    assert len(obs) == 2
    state = merge_observations(obs, tool="session_checks", action="summarize_sessions")
    assert len(state.notes) == 2
    assert state.sessions == []


def test_authenticated_reachability_never_emits_a_session():
    payload = {
        "action": "authenticated_reachability",
        "source": "WKSTN01",
        "target": "10.0.0.5",
        "protocol": "smb",
        "credential_ref": "cred-42",
        "reachable": True,
        "detail": "Authenticated SMB connection succeeded using cred-42.",
    }
    result = SessionChecksParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert {o["kind"] for o in obs} == {"note"}
    assert_observation(
        obs[0],
        kind="note",
        data_subset={
            "title": "Authenticated reachability confirmed: WKSTN01 -> 10.0.0.5 (smb)",
            "severity": "medium",
        },
    )
    state = merge_observations(obs, tool="session_checks", action="authenticated_reachability")
    assert state.sessions == []
    assert len(state.notes) == 1


def test_session_checks_parser_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not json at all", "{}", json.dumps({"unrelated": True})):
        result = SessionChecksParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
