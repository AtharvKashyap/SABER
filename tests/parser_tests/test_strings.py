from pathlib import Path

from saber.parsers.strings import StringsParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_strings_output.txt")
_META = {"file_path": "/opt/lab/vulnbin", "target": "10.0.0.7"}


def _observations(metadata=_META):
    result = StringsParser().parse_text(_FIXTURE.read_text(), metadata=metadata)
    return result, [o.to_dict() for o in result.observations]


def test_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert {o["kind"] for o in obs} == {"flag", "loot", "note"}


def test_flag_becomes_a_canonical_flag_observation():
    _, obs = _observations()
    flags = [o for o in obs if o["kind"] == "flag"]
    assert len(flags) == 1
    assert_observation(
        flags[0],
        kind="flag",
        data_subset={
            "value": "flag{f4ke_l4b_fl4g_for_tests}",
            "host": "10.0.0.7",
            "location": "/opt/lab/vulnbin",
        },
    )


def test_credential_material_becomes_loot():
    _, obs = _observations()
    descriptions = " ".join(o["data"]["description"] for o in obs if o["kind"] == "loot")

    assert "postgres://labuser:" in descriptions
    assert "AKIAFAKELABKEY1234XZ" in descriptions
    assert "private key" in descriptions.lower()
    assert "api_key=" in descriptions


def test_private_key_loot_is_kind_key_not_file():
    _, obs = _observations()
    key = next(o for o in obs if o["kind"] == "loot" and "private key" in o["data"]["description"])
    assert key["data"]["kind"] == "key"


def test_urls_paths_and_shell_primitives_become_notes():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs if o["kind"] == "note"}

    assert "Embedded URL: http://updates.lab.example.com/manifest.json" in titles
    assert "Referenced system path: /etc/passwd" in titles
    assert any("Shell execution primitive" in t and "/bin/sh" in t for t in titles)


def test_library_symbols_are_not_reported():
    _, obs = _observations()
    blob = " ".join(o["data"].get("title", "") for o in obs)
    for noise in ("__cxa_finalize", "GLIBC_2.2.5", ".shstrtab", "__gmon_start__"):
        assert noise not in blob


def test_does_not_emit_one_observation_per_string():
    _, obs = _observations()
    total_lines = len(_FIXTURE.read_text().splitlines())
    assert len(obs) < total_lines / 2


def test_grows_flags_loot_and_notes_in_state():
    _, obs = _observations()
    state = merge_observations(obs, tool="strings", action="extract")

    assert len(state.flags) == 1
    assert state.flags[0].value == "flag{f4ke_l4b_fl4g_for_tests}"
    assert len(state.loot) == 4
    assert state.notes


def test_summary_note_records_what_was_reviewed():
    _, obs = _observations()
    summary = next(o for o in obs if o["data"].get("title", "").startswith("strings summary"))
    assert summary["data"]["metadata"]["flags"] == 1
    assert summary["data"]["metadata"]["strings_reviewed"] > 0


def test_repeated_flag_is_deduped():
    text = "flag{dup_flag_here}\nflag{dup_flag_here}\n"
    result = StringsParser().parse_text(text)
    assert len([o for o in result.observations if o.kind == "flag"]) == 1


def test_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "__cxa_finalize\nlibc.so.6\n"):
        result = StringsParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
