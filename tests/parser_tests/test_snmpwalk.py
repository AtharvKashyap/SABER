from pathlib import Path

from saber.parsers.snmpwalk import SnmpwalkParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_snmpwalk_output.txt")


def test_snmpwalk_emits_summary_notes_and_accounts():
    text = _FIXTURE.read_text()
    result = SnmpwalkParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]

    notes = [o for o in obs if o["kind"] == "note"]
    accounts = [o for o in obs if o["kind"] == "account"]

    # 4 sys* fields + running-processes summary + installed-software summary.
    assert len(notes) == 6
    assert len(accounts) == 3

    titles = {n["data"]["title"] for n in notes}
    assert titles == {
        "SNMP sysDescr",
        "SNMP sysName",
        "SNMP sysContact",
        "SNMP sysLocation",
        "SNMP running processes summary",
        "SNMP installed software summary",
    }

    assert_observation(
        [n for n in notes if n["data"]["title"] == "SNMP sysName"][0],
        kind="note",
        data_subset={"detail": "dc01.example.com"},
    )

    process_note = [n for n in notes if n["data"]["title"] == "SNMP running processes summary"][0]
    assert process_note["data"]["metadata"]["count"] == 3
    assert "sshd" in process_note["data"]["metadata"]["processes"]

    software_note = [
        n for n in notes if n["data"]["title"] == "SNMP installed software summary"
    ][0]
    assert software_note["data"]["metadata"]["count"] == 2

    usernames = {a["data"]["username"] for a in accounts}
    assert usernames == {"Administrator", "Guest", "svc_backup"}
    assert_observation(
        accounts[0],
        kind="account",
        data_subset={"source": "snmpwalk"},
    )


def test_snmpwalk_does_not_emit_one_note_per_oid_line():
    text = _FIXTURE.read_text()
    result = SnmpwalkParser().parse_text(text)
    # 14 raw OID lines in the fixture, but only 9 distilled observations.
    assert len(text.strip().splitlines()) == 14
    assert len(result.observations) == 9


def test_snmpwalk_grows_state_notes_and_accounts():
    text = _FIXTURE.read_text()
    result = SnmpwalkParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]

    state = merge_observations(obs, tool="snmpwalk", action="enumerate")

    assert len(state.notes) == 6
    assert len(state.accounts) == 3
    usernames = {account.username for account in state.accounts}
    assert usernames == {"Administrator", "Guest", "svc_backup"}


def test_snmpwalk_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not snmp output at all", "===\n---\n"):
        result = SnmpwalkParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
