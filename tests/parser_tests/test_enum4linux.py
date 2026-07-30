from pathlib import Path

from saber.parsers.enum4linux import Enum4LinuxParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_enum4linux_output.txt")


def _parse():
    return Enum4LinuxParser().parse_text(
        _FIXTURE.read_text(), metadata={"target": "192.168.56.10"}
    )


def test_enum4linux_emits_shares_and_grows_state():
    result = _parse()
    obs = [o.to_dict() for o in result.observations]

    shares = [o for o in obs if o["kind"] == "share"]
    assert len(shares) == 6

    netlogon = next(o for o in shares if o["data"]["name"] == "NETLOGON")
    assert_observation(
        netlogon,
        kind="share",
        data_subset={
            "host": "192.168.56.10",
            "name": "NETLOGON",
            "type": "disk",
            "access": "read",
        },
    )

    users_share = next(o for o in shares if o["data"]["name"] == "Users")
    assert users_share["data"]["access"] == "none"

    admin_share = next(o for o in shares if o["data"]["name"] == "ADMIN$")
    assert admin_share["data"]["access"] == "none"

    state = merge_observations(obs, tool="enum4linux", action="shares")
    assert len(state.shares) == 6


def test_enum4linux_emits_accounts_and_grows_state():
    result = _parse()
    obs = [o.to_dict() for o in result.observations]

    accounts = [o for o in obs if o["kind"] == "account"]
    assert len(accounts) == 2

    jdoe = next(o for o in accounts if o["data"]["username"] == "jdoe")
    assert_observation(
        jdoe,
        kind="account",
        data_subset={"username": "jdoe", "host": "192.168.56.10", "source": "enum4linux"},
    )

    state = merge_observations(obs, tool="enum4linux", action="users")
    assert len(state.accounts) == 2


def test_enum4linux_emits_domain_and_sid_notes_and_grows_state():
    result = _parse()
    obs = [o.to_dict() for o in result.observations]

    notes = [o for o in obs if o["kind"] == "note"]
    titles = {o["data"]["title"] for o in notes}
    assert "SMB domain/workgroup: CORP" in titles
    assert "SMB domain SID" in titles
    assert len(notes) == 2

    state = merge_observations(obs, tool="enum4linux", action="full_enum")
    assert len(state.notes) == 2


def test_enum4linux_full_enum_grows_shares_accounts_and_notes_together():
    result = _parse()
    obs = [o.to_dict() for o in result.observations]

    state = merge_observations(obs, tool="enum4linux", action="full_enum")
    assert len(state.shares) == 6
    assert len(state.accounts) == 2
    assert len(state.notes) == 2


def test_enum4linux_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "banner only, nothing useful"):
        result = Enum4LinuxParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors


def test_enum4linux_no_metadata_falls_back_to_host_from_mapping_line():
    result = Enum4LinuxParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]
    shares = [o for o in obs if o["kind"] == "share"]
    assert all(o["data"]["host"] == "192.168.56.10" for o in shares)
