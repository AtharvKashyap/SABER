from pathlib import Path

from saber.parsers.masscan import MasscanParser

from tests.conftest import assert_observation, merge_observations

_STDOUT_FIXTURE = Path("tests/fixtures/sample_masscan_output.txt")
_JSON_FIXTURE = Path("tests/fixtures/sample_masscan_output.json")


def test_masscan_stdout_emits_host_and_service_and_grows_state():
    result = MasscanParser().parse_text(_STDOUT_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    hosts = [o for o in obs if o["kind"] == "host"]
    services = [o for o in obs if o["kind"] == "service"]
    assert len(hosts) == 2
    assert len(services) == 4

    assert_observation(hosts[0], kind="host", data_subset={"address": "192.168.56.101"})
    assert_observation(
        services[0],
        kind="service",
        data_subset={
            "host": "192.168.56.101",
            "port": 80,
            "protocol": "tcp",
            "state": "open",
        },
    )

    state = merge_observations(obs, tool="masscan", action="scan_ports")
    assert len(state.hosts) == 2
    assert len(state.services) == 4


def test_masscan_parses_udp_protocol():
    result = MasscanParser().parse_text(_STDOUT_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]
    udp = [o for o in obs if o["kind"] == "service" and o["data"]["protocol"] == "udp"]
    assert len(udp) == 1
    assert udp[0]["data"]["port"] == 161


def test_masscan_json_output_with_trailing_comma_is_parsed():
    result = MasscanParser().parse_text(_JSON_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    assert result.metadata["format"] == "json"
    services = [o for o in obs if o["kind"] == "service"]
    assert len(services) == 3

    state = merge_observations(obs, tool="masscan", action="scan_ports")
    assert len(state.hosts) == 2
    assert len(state.services) == 3


def test_masscan_oL_list_format_is_parsed():
    text = "open tcp 8080 10.0.0.5 1785326404\nopen tcp 8443 10.0.0.5 1785326404\n"
    result = MasscanParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    services = [o for o in obs if o["kind"] == "service"]
    assert len(services) == 2
    assert services[0]["data"]["port"] == 8080


def test_masscan_skips_closed_ports_in_json():
    text = '[{"ip": "10.0.0.9", "ports": [{"port": 22, "proto": "tcp", "status": "closed"}]}]'
    result = MasscanParser().parse_text(text)
    assert result.observations == []
    assert result.success is False


def test_masscan_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not masscan output at all", "{", "[{bad json"):
        result = MasscanParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
