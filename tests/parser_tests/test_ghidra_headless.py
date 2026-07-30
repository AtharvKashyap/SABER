from pathlib import Path

from saber.parsers.ghidra_headless import GhidraHeadlessParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_ghidra_output.txt")


def _observations(binary_path: str = "/tmp/challenge.bin"):
    result = GhidraHeadlessParser().parse_text(
        _FIXTURE.read_text(), metadata={"binary_path": binary_path}
    )
    return result, [o.to_dict() for o in result.observations]


def test_ghidra_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert {o["kind"] for o in obs} == {"note"}


def test_decompiled_summary_highlights_are_surfaced():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs}

    assert "Ghidra decompiled summary: main (/tmp/challenge.bin)" in titles
    assert "Ghidra decompiled summary: read_input (/tmp/challenge.bin)" in titles
    assert "Ghidra decompiled summary: print_banner (/tmp/challenge.bin)" in titles


def test_system_call_highlight_is_high_severity():
    _, obs = _observations()
    main_note = next(o for o in obs if "main (" in o["data"]["title"])
    assert_observation(main_note, kind="note", data_subset={"severity": "high"})
    assert main_note["data"]["metadata"]["function"] == "main"
    assert main_note["data"]["metadata"]["address"] == "0x00401136"


def test_overflow_highlight_is_high_severity():
    _, obs = _observations()
    read_note = next(o for o in obs if "read_input" in o["data"]["title"])
    assert read_note["data"]["severity"] == "high"


def test_benign_highlight_is_medium_severity():
    _, obs = _observations()
    banner_note = next(o for o in obs if "print_banner" in o["data"]["title"])
    assert banner_note["data"]["severity"] == "medium"


def test_error_lines_are_surfaced_as_notes():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs}
    assert any(t.startswith("Ghidra analysis error:") for t in titles)


def test_summary_note_is_present_and_counts_lines():
    _, obs = _observations()
    summary = next(
        o for o in obs if o["data"]["title"].startswith("Ghidra headless analysis summary")
    )
    assert summary["data"]["metadata"]["lines_reviewed"] > 0
    assert summary["data"]["metadata"]["summary_count"] == 3
    assert summary["data"]["metadata"]["error_count"] == 1


def test_ghidra_grows_state_notes_by_expected_count():
    _, obs = _observations()
    state = merge_observations(obs, tool="ghidra_headless", action="export_analysis")
    # 3 decompiled-summary highlights + 1 error + 1 overall summary note.
    assert len(state.notes) == 5


def test_ghidra_does_not_emit_one_note_per_log_line():
    _, obs = _observations()
    total_lines = len(_FIXTURE.read_text().splitlines())
    assert len(obs) < total_lines


def test_ghidra_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "nothing of interest here at all"):
        result = GhidraHeadlessParser().parse_text(text)
        if text.strip():
            # Plain noise with no summary/error markers surfaces no observations.
            assert result.observations == []
            assert result.success is False
        else:
            assert result.observations == []
            assert result.success is False
        assert result.errors
