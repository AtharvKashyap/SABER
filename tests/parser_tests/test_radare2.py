from pathlib import Path

from saber.parsers.radare2 import Radare2Parser

from tests.conftest import assert_observation, merge_observations

_INFO_FIXTURE = Path("tests/fixtures/sample_radare2_info_output.json")
_FUNCTIONS_FIXTURE = Path("tests/fixtures/sample_radare2_functions_output.json")
_CUSTOM_FIXTURE = Path("tests/fixtures/sample_radare2_custom_output.txt")


def _observations(fixture: Path, action: str, binary_path: str = "/tmp/challenge.bin"):
    result = Radare2Parser().parse_text(
        fixture.read_text(), metadata={"action": action, "binary_path": binary_path}
    )
    return result, [o.to_dict() for o in result.observations]


def test_info_emits_a_single_arch_bits_protections_note():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations(_INFO_FIXTURE, "info")
    assert len(obs) == 1
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "radare2 binary info: /tmp/challenge.bin", "severity": "high"},
    )
    assert obs[0]["data"]["metadata"]["arch"] == "x86"
    assert obs[0]["data"]["metadata"]["bits"] == 64
    assert obs[0]["data"]["metadata"]["canary"] is False
    assert obs[0]["data"]["metadata"]["nx"] is False


def test_info_grows_state_notes_by_one():
    _, obs = _observations(_INFO_FIXTURE, "info")
    state = merge_observations(obs, tool="radare2", action="info")
    assert len(state.notes) == 1


def test_functions_surfaces_only_dangerous_sinks_plus_summary():
    _, obs = _observations(_FUNCTIONS_FIXTURE, "functions")
    notes = [o for o in obs if o["kind"] == "note"]
    titles = {n["data"]["title"] for n in notes}

    assert "Dangerous function referenced: sym.imp.strcpy" in titles
    assert "Dangerous function referenced: sym.imp.gets" in titles
    assert "Dangerous function referenced: sym.imp.system" in titles
    assert "Dangerous function referenced: sym.imp.memcpy" in titles
    # Benign symbols (main, entry0, puts, __libc_start_main) are not surfaced.
    assert not any("main" in t and "Dangerous" in t for t in titles)
    assert any("summary" in t for t in titles)
    # 4 dangerous sinks + 1 summary note; the full 10-entry symbol table is not dumped.
    assert len(notes) == 5


def test_functions_grows_state_notes_by_expected_count():
    _, obs = _observations(_FUNCTIONS_FIXTURE, "functions")
    state = merge_observations(obs, tool="radare2", action="functions")
    assert len(state.notes) == 5


def test_functions_dangerous_sink_severity():
    _, obs = _observations(_FUNCTIONS_FIXTURE, "functions")
    notes = [o for o in obs if o["kind"] == "note"]
    gets_note = next(
        n for n in notes if "gets" in n["data"]["title"] and "Dangerous" in n["data"]["title"]
    )
    memcpy_note = next(
        n for n in notes if "memcpy" in n["data"]["title"] and "Dangerous" in n["data"]["title"]
    )
    assert gets_note["data"]["severity"] == "high"
    assert memcpy_note["data"]["severity"] == "medium"


def test_custom_commands_raw_output_becomes_one_note():
    _, obs = _observations(_CUSTOM_FIXTURE, "custom_commands")
    assert len(obs) == 1
    assert_observation(
        obs[0],
        kind="note",
        data_subset={"title": "radare2 custom_commands output: /tmp/challenge.bin"},
    )


def test_analyze_with_no_output_degrades_to_zero_observations():
    result = Radare2Parser().parse_text("", metadata={"action": "analyze"})
    assert result.observations == []
    assert result.success is False
    assert result.errors


def test_info_malformed_json_degrades_to_zero_observations():
    result = Radare2Parser().parse_text("not json at all", metadata={"action": "info"})
    assert result.observations == []
    assert result.success is False
    assert result.errors


def test_functions_malformed_json_degrades_to_zero_observations():
    result = Radare2Parser().parse_text("{}", metadata={"action": "functions"})
    assert result.observations == []
    assert result.success is False
    assert result.errors


def test_empty_input_degrades_to_zero_observations_regardless_of_action():
    for text in ("", "   "):
        result = Radare2Parser().parse_text(text, metadata={"action": "info"})
        assert result.observations == []
        assert result.success is False
        assert result.errors
