from pathlib import Path

from saber.parsers.linpeas import LinpeasParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_linpeas_output.txt")


def _observations(metadata=None):
    result = LinpeasParser().parse_text(_FIXTURE.read_text(), metadata=metadata)
    return result, [o.to_dict() for o in result.observations]


def test_linpeas_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert {o["kind"] for o in obs} == {"note", "loot"}


def test_high_probability_vector_is_critical_severity():
    _, obs = _observations()
    notes = [o for o in obs if o["kind"] == "note"]
    pwnkit = next(o for o in notes if "pwnkit" in o["data"]["title"])

    assert_observation(pwnkit, kind="note", data_subset={"severity": "critical"})
    assert pwnkit["data"]["metadata"]["probability"] == 99


def test_lower_probability_vector_is_high_not_critical():
    _, obs = _observations()
    notes = [o for o in obs if o["kind"] == "note"]
    lower = next(o for o in notes if "CVE-2021-3560" in o["data"]["title"])
    assert lower["data"]["severity"] == "high"


def test_sudo_suid_and_writable_service_are_surfaced():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs if o["kind"] == "note"}

    assert "Passwordless sudo: /usr/bin/find" in titles
    assert "Notable SUID binary: /usr/bin/pkexec" in titles
    assert "Writable service unit: /etc/systemd/system/backup.service" in titles


def test_sensitive_files_become_loot():
    _, obs = _observations()
    loot = [o for o in obs if o["kind"] == "loot"]
    paths = {o["data"]["path"] for o in loot}

    assert "/home/svcuser/.ssh/id_rsa" in paths
    assert "/opt/app/config/credentials.yml" in paths
    assert "/etc/shadow" in paths
    # A boring log file is not loot.
    assert "/var/log/syslog" not in paths


def test_host_is_taken_from_metadata():
    _, obs = _observations(metadata={"target": "10.0.0.9"})
    loot = next(o for o in obs if o["kind"] == "loot")
    assert loot["data"]["host"] == "10.0.0.9"


def test_linpeas_grows_state_and_emits_a_summary_note():
    _, obs = _observations()
    state = merge_observations(obs, tool="linpeas", action="run_local")

    assert len(state.loot) == 3
    assert len(state.notes) == len({o["data"]["title"] for o in obs if o["kind"] == "note"})
    summary = next(n for n in state.notes if n.title == "LinPEAS enumeration summary")
    assert summary.metadata["lines_reviewed"] > 0


def test_linpeas_does_not_emit_one_note_per_line():
    """The whole point: a huge report must not flood MissionState."""

    _, obs = _observations()
    total_lines = len(_FIXTURE.read_text().splitlines())
    assert len(obs) < total_lines / 2


def test_linpeas_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "nothing of interest here at all"):
        result = LinpeasParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
