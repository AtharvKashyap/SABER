from pathlib import Path

from saber.parsers.winpeas import WinpeasParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_winpeas_output.txt")


def _observations(metadata=None):
    result = WinpeasParser().parse_text(_FIXTURE.read_text(), metadata=metadata)
    return result, [o.to_dict() for o in result.observations]


def test_winpeas_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert {o["kind"] for o in obs} == {"note", "loot"}


def test_always_install_elevated_is_critical():
    _, obs = _observations()
    note = next(o for o in obs if o["data"].get("title", "").startswith("AlwaysInstallElevated"))
    assert_observation(note, kind="note", data_subset={"severity": "critical"})


def test_impersonate_privilege_is_critical_but_change_notify_is_not():
    _, obs = _observations()
    by_title = {o["data"]["title"]: o for o in obs if o["kind"] == "note"}

    assert by_title["Token privilege enabled: SeImpersonatePrivilege"]["data"]["severity"] == (
        "critical"
    )
    assert by_title["Token privilege enabled: SeChangeNotifyPrivilege"]["data"]["severity"] == (
        "medium"
    )


def test_unquoted_service_path_and_writable_binary_are_surfaced():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs if o["kind"] == "note"}

    assert any("Unquoted service path" in t and "backup service.exe" in t for t in titles)
    assert any("Writable privileged path" in t and "Lab Vuln" in t for t in titles)


def test_credential_material_becomes_loot():
    _, obs = _observations()
    loot = [o for o in obs if o["kind"] == "loot"]
    descriptions = " ".join(o["data"]["description"] for o in loot)

    assert "unattend.xml" in descriptions
    assert "web.config" in descriptions
    assert "Autologon" in descriptions
    # An installed-application line is not loot.
    assert "Notepad++" not in descriptions


def test_host_is_taken_from_metadata():
    _, obs = _observations(metadata={"target": "10.0.0.22"})
    loot = next(o for o in obs if o["kind"] == "loot")
    assert loot["data"]["host"] == "10.0.0.22"


def test_winpeas_grows_state_and_emits_a_summary_note():
    _, obs = _observations()
    state = merge_observations(obs, tool="winpeas", action="run_exe")

    assert len(state.loot) >= 3
    summary = next(n for n in state.notes if n.title == "winPEAS enumeration summary")
    assert summary.metadata["lines_reviewed"] > 0


def test_winpeas_does_not_emit_one_note_per_line():
    _, obs = _observations()
    total_lines = len(_FIXTURE.read_text().splitlines())
    assert len(obs) < total_lines / 2


def test_winpeas_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "nothing of interest here at all"):
        result = WinpeasParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
