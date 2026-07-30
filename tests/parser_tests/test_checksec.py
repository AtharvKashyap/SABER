from pathlib import Path

from saber.parsers.checksec import ChecksecParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_checksec_output.json")


def _observations():
    result = ChecksecParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_one_note_per_binary():
    result, obs = _observations()
    assert len(obs) == 3
    assert {o["kind"] for o in obs} == {"note"}
    assert result.metadata["format"] == "json"


def test_flags_dict_keys_are_the_contract_with_the_exploit_loop():
    """These key names are read by binary-exploitation work; pin them."""

    _, obs = _observations()
    flags = next(o for o in obs if "vulnbin" in o["data"]["title"])["data"]["metadata"]

    assert set(flags) >= {"nx", "pie", "relro", "canary", "fortify", "stripped", "path"}
    assert flags["nx"] is False
    assert flags["pie"] is False
    assert flags["canary"] is False
    assert flags["relro"] == "none"


def test_hardened_binary_flags_are_all_true():
    _, obs = _observations()
    flags = next(o for o in obs if "hardened-app" in o["data"]["title"])["data"]["metadata"]

    assert flags["nx"] is True
    assert flags["pie"] is True
    assert flags["canary"] is True
    assert flags["fortify"] is True
    assert flags["relro"] == "full"


def test_relro_is_normalised_to_three_values():
    _, obs = _observations()
    values = {o["data"]["metadata"]["relro"] for o in obs}
    assert values == {"none", "full", "partial"}


def test_severity_tracks_how_soft_the_binary_is():
    _, obs = _observations()
    by_title = {o["data"]["title"]: o for o in obs}

    # nx+pie+canary all missing -> directly exploitable.
    assert by_title["Binary hardening: /opt/lab/vulnbin"]["data"]["severity"] == "high"
    # everything on -> nothing to report.
    assert by_title["Binary hardening: /usr/bin/hardened-app"]["data"]["severity"] == "info"
    # only PIE missing.
    assert by_title["Binary hardening: /usr/bin/partly-hardened"]["data"]["severity"] == "low"


def test_detail_lists_missing_mitigations():
    _, obs = _observations()
    vulnbin = next(o for o in obs if "vulnbin" in o["data"]["title"])
    assert_observation(vulnbin, kind="note", data_subset={"severity": "high"})
    assert "missing: nx, pie, canary, fortify" in vulnbin["data"]["detail"]


def test_checksec_grows_state_notes():
    _, obs = _observations()
    state = merge_observations(obs, tool="checksec", action="directory")
    assert len(state.notes) == 3


def test_cli_table_form_is_parsed():
    text = (
        "RELRO           STACK CANARY      NX            PIE\n"
        "No RELRO        No canary found   NX disabled   No PIE\n"
    )
    result = ChecksecParser().parse_text(text, metadata={"binary_path": "/opt/lab/vulnbin"})
    assert result.metadata["format"] == "cli"
    flags = result.observations[0].data["metadata"]
    assert flags["nx"] is False
    assert flags["relro"] == "none"
    assert flags["path"] == "/opt/lab/vulnbin"


def test_checksec_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "{not json", "unrelated text"):
        result = ChecksecParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
