"""BloodHound output must land in MissionState.

Before F3 this parser emitted ad_entity/ad_relationship/ad_path — none of which
StateMerger knows — so every collection was silently discarded and MissionState
never grew. These tests pin the canonical mapping.
"""

from pathlib import Path

from saber.parsers.bloodhound import BloodHoundParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_bloodhound_output.json")


def _observations():
    result = BloodHoundParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_no_observation_uses_a_non_canonical_kind():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs, "fixture produced no observations"
    offenders = {o["kind"] for o in obs} - CANONICAL_KINDS
    assert not offenders, f"non-canonical kinds would be silently dropped: {offenders}"


def test_ad_users_become_accounts():
    _, obs = _observations()
    accounts = [o for o in obs if o["kind"] == "account"]
    assert len(accounts) == 3

    by_user = {o["data"]["username"]: o for o in accounts}
    assert_observation(
        by_user["jdoe"],
        kind="account",
        data_subset={"username": "jdoe", "domain": "LAB.LOCAL", "source": "bloodhound"},
    )
    # A disabled account is still worth knowing about, but flagged as disabled.
    assert by_user["oldsvc"]["data"]["enabled"] is False
    assert by_user["svc_backup"]["data"]["enabled"] is True


def test_ad_computers_become_hosts_with_os():
    _, obs = _observations()
    hosts = [o for o in obs if o["kind"] == "host"]
    assert len(hosts) == 2

    by_address = {o["data"]["address"]: o for o in hosts}
    assert_observation(
        by_address["dc01.lab.local"],
        kind="host",
        data_subset={"address": "dc01.lab.local", "os": "Windows Server 2019 Standard"},
    )


def test_relationships_and_paths_become_notes():
    _, obs = _observations()
    notes = [o for o in obs if o["kind"] == "note"]
    titles = {o["data"]["title"] for o in notes}

    assert "AD relationship: SVC_BACKUP@LAB.LOCAL -GenericAll-> DOMAIN ADMINS@LAB.LOCAL" in titles
    assert "AD attack path: JDOE@LAB.LOCAL -> DOMAIN ADMINS@LAB.LOCAL" in titles
    assert "AD group: DOMAIN ADMINS@LAB.LOCAL" in titles

    # A path to Domain Admins is high severity, not buried at info.
    path_note = next(o for o in notes if o["data"]["title"].startswith("AD attack path"))
    assert path_note["data"]["severity"] == "high"


def test_bloodhound_grows_mission_state():
    _, obs = _observations()
    state = merge_observations(obs, tool="bloodhound", action="collect")

    assert len(state.accounts) == 3
    assert len(state.hosts) == 2
    assert state.notes, "relationships/paths/groups should reach state.notes"


def test_high_value_path_still_produces_a_finding():
    result, _ = _observations()
    titles = [f.title for f in result.findings]
    assert any("high-value AD target" in t for t in titles)


def test_bloodhound_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "{not json", "[]"):
        result = BloodHoundParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
