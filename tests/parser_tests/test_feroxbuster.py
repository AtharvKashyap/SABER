from pathlib import Path

from saber.parsers.feroxbuster import FeroxbusterParser

from tests.conftest import assert_observation, merge_observations

_JSON_FIXTURE = Path("tests/fixtures/sample_feroxbuster_output.json")


def test_feroxbuster_json_lines_emit_notes_and_grow_state():
    result = FeroxbusterParser().parse_text(_JSON_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    notes = [o for o in obs if o["kind"] == "note"]
    # 301 /admin, 403 /backup, 200 /index.php, 401 /secret.txt -> 4 individual notes,
    # plus one folded summary note for the 500 /old and 404 /gone responses.
    assert len(notes) == 5

    assert_observation(
        notes[0],
        kind="note",
        data_subset={"title": "/admin", "detail": "HTTP 301"},
    )
    assert_observation(
        notes[2],
        kind="note",
        data_subset={"title": "/index.php", "detail": "HTTP 200"},
    )

    titles = {n["data"]["title"] for n in notes}
    assert "/admin" in titles
    assert "/backup" in titles
    assert "/index.php" in titles
    assert "/secret.txt" in titles
    assert "Feroxbuster: additional non-interesting responses" in titles

    summary = next(n for n in notes if n["data"]["title"].startswith("Feroxbuster:"))
    assert summary["data"]["metadata"]["count"] == 2
    assert summary["data"]["metadata"]["statuses"] == [404, 500]

    state = merge_observations(obs, tool="feroxbuster", action="directory_bruteforce")
    assert len(state.notes) == 5


def test_feroxbuster_ignores_non_response_record_types():
    text = (
        '{"type":"heartbeat","done":1,"total":10}\n'
        '{"type":"statistics","total_scans":1}\n'
        '{"type":"response","url":"http://x/y","path":"/y","status":200}\n'
    )
    result = FeroxbusterParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    assert len(obs) == 1
    assert obs[0]["data"]["title"] == "/y"


def test_feroxbuster_deduplicates_repeated_paths():
    text = (
        '{"type":"response","url":"http://x/y","path":"/y","status":200}\n'
        '{"type":"response","url":"http://x/y","path":"/y","status":200}\n'
    )
    result = FeroxbusterParser().parse_text(text)
    assert len(result.observations) == 1


def test_feroxbuster_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not json at all", "{", "[{bad json"):
        result = FeroxbusterParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
