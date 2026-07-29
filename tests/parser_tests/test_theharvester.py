from pathlib import Path

from saber.parsers.theharvester import TheHarvesterParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_theharvester_output.json")


def test_theharvester_json_emits_accounts_hosts_and_summary_note():
    result = TheHarvesterParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    accounts = [o for o in obs if o["kind"] == "account"]
    hosts = [o for o in obs if o["kind"] == "host"]
    notes = [o for o in obs if o["kind"] == "note"]

    assert len(accounts) == 3
    assert len(hosts) == 3
    assert len(notes) == 1

    assert_observation(
        accounts[0],
        kind="account",
        data_subset={
            "username": "admin",
            "domain": "example.com",
            "source": "theharvester",
        },
    )
    assert accounts[0]["data"]["metadata"]["email"] == "admin@example.com"


def test_theharvester_host_with_ip_uses_ip_as_address():
    result = TheHarvesterParser().parse_text(_FIXTURE.read_text())
    hosts = [o.to_dict() for o in result.observations if o.kind == "host"]
    by_address = {o["data"]["address"]: o for o in hosts}

    assert_observation(
        by_address["93.184.216.34"],
        kind="host",
        data_subset={"address": "93.184.216.34", "hostnames": ["www.example.com"]},
    )
    # An unresolved host falls back to its own name as the address.
    assert by_address["dev.example.com"]["data"]["hostnames"] == ["dev.example.com"]


def test_theharvester_grows_state():
    result = TheHarvesterParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]
    state = merge_observations(obs, tool="theharvester", action="search")

    assert len(state.accounts) == 3
    assert len(state.hosts) == 3
    assert len(state.notes) == 1
    assert state.notes[0].metadata["email_count"] == 3


def test_theharvester_stdout_form_is_parsed():
    text = "\n".join(
        [
            "[*] Emails found: 2",
            "---------------------",
            "admin@example.com",
            "info@example.com",
            "",
            "[*] Hosts found: 2",
            "---------------------",
            "www.example.com:93.184.216.34",
            "mail.example.com",
            "",
        ]
    )
    result = TheHarvesterParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]

    assert result.metadata["format"] == "text"
    assert len([o for o in obs if o["kind"] == "account"]) == 2
    assert len([o for o in obs if o["kind"] == "host"]) == 2


def test_theharvester_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "{not json", "nothing useful"):
        result = TheHarvesterParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
