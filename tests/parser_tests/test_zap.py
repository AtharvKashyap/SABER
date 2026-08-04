from pathlib import Path

from saber.parsers.zap import ZapParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_zap_output.json")


def test_zap_json_emits_vuln_and_note_and_grows_state():
    result = ZapParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    vulns = [o for o in obs if o["kind"] == "vuln"]
    notes = [o for o in obs if o["kind"] == "note"]
    assert len(vulns) == 2
    assert len(notes) == 1

    assert_observation(
        vulns[0],
        kind="vuln",
        data_subset={
            "title": "Cross Site Scripting (Reflected)",
            "host": "192.168.56.101",
            "port": 8080,
            "severity": "high",
            "identifier": "79",
            "confirmed": True,
        },
    )
    assert_observation(
        vulns[1],
        kind="vuln",
        data_subset={
            "title": "Content Security Policy (CSP) Header Not Set",
            "host": "192.168.56.101",
            "port": 8080,
            "severity": "low",
            "identifier": "693",
            "confirmed": True,
        },
    )
    assert_observation(
        notes[0],
        kind="note",
        data_subset={"title": "ZAP scan summary: http://192.168.56.101:8080"},
    )

    state = merge_observations(obs, tool="zap_api", action="active_scan")
    assert len(state.vulns) == 2
    assert len(state.notes) == 1


def test_zap_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not json at all", "{", '{"no_site_key": true}', "[1, 2, 3]"):
        result = ZapParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
