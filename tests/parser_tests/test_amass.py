from pathlib import Path

from saber.parsers.amass import AmassParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_amass_output.txt")


def test_amass_resolved_relation_uses_ip_as_address():
    result = AmassParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    assert all(o["kind"] == "host" for o in obs)
    by_address = {o["data"]["address"]: o for o in obs}

    assert_observation(
        by_address["93.184.216.34"],
        kind="host",
        data_subset={"address": "93.184.216.34", "hostnames": ["www.example.com"]},
    )
    assert "2606:2800:220:1:248:1893:25c8:1946" in by_address


def test_amass_bare_name_is_its_own_address():
    result = AmassParser().parse_text(_FIXTURE.read_text())
    by_address = {o.data["address"]: o for o in result.observations}
    assert by_address["dev.example.com"].data["hostnames"] == ["dev.example.com"]
    assert by_address["staging.example.com"].data["hostnames"] == ["staging.example.com"]


def test_amass_non_address_relation_records_both_names():
    result = AmassParser().parse_text(
        "example.com (FQDN) --> mx_record --> mail.example.com (FQDN)\n"
    )
    addresses = {o.data["address"] for o in result.observations}
    assert addresses == {"example.com", "mail.example.com"}


def test_amass_grows_state():
    result = AmassParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]
    state = merge_observations(obs, tool="amass", action="passive_enum")
    # 3 resolved IPs + example.com + mail.example.com + dev + staging
    assert len(state.hosts) == len({o["data"]["address"] for o in obs})
    assert len(state.hosts) == 7


def test_amass_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "==== nothing parseable ===="):
        result = AmassParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
