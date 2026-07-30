import json
from pathlib import Path

from saber.parsers.path_validation import PathValidationParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_path_validation_output.json")


def _observations():
    result = PathValidationParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_dry_run_blocked_emits_a_single_high_severity_note():
    _, obs = _observations()
    assert len(obs) == 1
    assert_observation(
        obs[0],
        kind="note",
        data_subset={
            "title": "Path path-1 dry run blocked at DC01",
            "severity": "high",
        },
    )
    assert obs[0]["data"]["metadata"]["reachable_hops"] == ["WKSTN01", "SRV-FILE01"]


def test_dry_run_grows_mission_state_notes():
    _, obs = _observations()
    state = merge_observations(obs, tool="path_validation", action="dry_run_path")
    assert len(state.notes) == 1


def test_dry_run_fully_reachable_is_info_severity():
    payload = {
        "action": "dry_run_path",
        "path_id": "path-2",
        "hops": ["WKSTN01", "DC01"],
        "reachable_hops": ["WKSTN01", "DC01"],
        "blocked_at": None,
    }
    result = PathValidationParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(
        obs[0], kind="note", data_subset={"title": "Path path-2 dry run succeeded",
                                           "severity": "info"}
    )


def test_validate_step_valid_and_invalid():
    valid_payload = {
        "action": "validate_step",
        "source": "WKSTN01",
        "target": "10.0.0.5",
        "technique": "psexec",
        "valid": True,
        "reason": "SMB reachable and admin share writable.",
    }
    result = PathValidationParser().parse_json(valid_payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "Path step validated: WKSTN01 -> 10.0.0.5 via psexec"},
    )

    invalid_payload = {**valid_payload, "valid": False, "reason": "No known credential."}
    result = PathValidationParser().parse_json(invalid_payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(
        obs[0],
        kind="note",
        data_subset={
            "title": "Path step invalid: WKSTN01 -> 10.0.0.5 via psexec",
            "severity": "medium",
        },
    )


def test_validate_path_valid_and_invalid():
    valid_payload = {
        "action": "validate_path",
        "path_id": "path-1",
        "hops": ["WKSTN01", "DC01"],
        "valid": True,
        "invalid_hops": [],
    }
    result = PathValidationParser().parse_json(valid_payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(obs[0], kind="note", data_subset={"title": "Path path-1 validated"})
    state = merge_observations(obs, tool="path_validation", action="validate_path")
    assert len(state.notes) == 1

    invalid_payload = {
        **valid_payload,
        "valid": False,
        "invalid_hops": ["DC01"],
    }
    result = PathValidationParser().parse_json(invalid_payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(
        obs[0], kind="note", data_subset={"title": "Path path-1 failed validation"}
    )


def test_path_validation_parser_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not json at all", "{}", json.dumps({"unrelated": True})):
        result = PathValidationParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
