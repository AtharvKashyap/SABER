import json
from pathlib import Path

from saber.parsers.plan import PlanParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_plan_output.json")


def _observations():
    result = PlanParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_plan_paths_emits_only_notes():
    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} == {"note"}


def test_plan_paths_notes_have_distinct_titles_per_path():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs}
    assert len(titles) == len(obs) == 2
    assert "Lateral movement path planned: path-1 (WKSTN01 -> SRV-FILE01 -> DC01)" in titles
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"metadata": {"path_id": "path-1", "hops": ["WKSTN01", "SRV-FILE01", "DC01"],
                                   "technique": "psexec", "risk": "medium"}},
    )


def test_plan_paths_grows_mission_state_notes():
    _, obs = _observations()
    state = merge_observations(obs, tool="plan", action="plan_paths")
    assert len(state.notes) == 2


def test_rank_paths_output_emits_a_note_per_ranked_entry():
    payload = {
        "action": "rank_paths",
        "criteria": "lowest_risk",
        "ranked": [
            {"path_id": "path-2", "rank": 1, "score": 0.92, "technique": "wmiexec"},
            {"path_id": "path-1", "rank": 2, "score": 0.61, "technique": "psexec"},
        ],
    }
    result = PlanParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert {o["kind"] for o in obs} == {"note"}
    titles = {o["data"]["title"] for o in obs}
    assert "Path path-2 ranked #1 by lowest_risk" in titles
    state = merge_observations(obs, tool="plan", action="rank_paths")
    assert len(state.notes) == 2


def test_export_plan_output_emits_a_single_note():
    payload = {
        "action": "export_plan",
        "plan_id": "plan-001",
        "format": "json",
        "exported_path": "/evidence/lateral_movement/plan-001.json",
        "path_count": 2,
    }
    result = PlanParser().parse_json(payload)
    obs = [o.to_dict() for o in result.observations]
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "Lateral movement plan exported: plan-001"},
    )
    state = merge_observations(obs, tool="plan", action="export_plan")
    assert len(state.notes) == 1


def test_plan_parser_accepts_json_via_parse_text():
    text = json.dumps({"action": "export_plan", "plan_id": "plan-xyz", "format": "md"})
    result = PlanParser().parse_text(text)
    assert result.success is True
    assert result.observations[0].data["title"] == "Lateral movement plan exported: plan-xyz"


def test_plan_parser_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not json at all", "{}", json.dumps({"unrelated": True})):
        result = PlanParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
