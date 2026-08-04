from pathlib import Path

from saber.parsers.subfinder import SubfinderParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_subfinder_output.txt")


def test_subfinder_emits_host_per_subdomain_and_grows_state():
    result = SubfinderParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    # Fixture has 5 lines, one a duplicate of www.example.com.
    assert len(obs) == 4
    assert all(o["kind"] == "host" for o in obs)
    assert_observation(
        obs[0],
        kind="host",
        data_subset={"address": "www.example.com", "hostnames": ["www.example.com"]},
    )

    state = merge_observations(obs, tool="subfinder", action="passive")
    assert len(state.hosts) == 4


def test_subfinder_skips_banner_noise():
    text = "\n".join(
        [
            "               __    _____           __",
            "[INF] Enumerating subdomains for example.com",
            "www.example.com",
            "notahostname",
            "",
        ]
    )
    result = SubfinderParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    assert len(obs) == 1
    assert obs[0]["data"]["address"] == "www.example.com"


def test_subfinder_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "no-hostnames-here"):
        result = SubfinderParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
