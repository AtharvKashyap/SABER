from pathlib import Path

from saber.parsers.chisel import ChiselParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_chisel_output.txt")


def _observations():
    result = ChiselParser().parse_text(_FIXTURE.read_text())
    return result, [o.to_dict() for o in result.observations]


def test_chisel_emits_only_notes():
    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} == {"note"}


def test_chisel_records_listener_and_tunnels():
    _, obs = _observations()
    titles = {o["data"]["title"] for o in obs}

    assert "Chisel listener on http://0.0.0.0:8000" in titles
    assert "Chisel tunnel established: R:127.0.0.1:1080=>socks" in titles
    assert "Chisel tunnel established: R:3389:10.0.0.5:3389" in titles
    assert "Chisel client connected to server" in titles
    assert "Chisel reverse tunnelling enabled" in titles


def test_established_tunnel_is_high_severity():
    _, obs = _observations()
    tunnel = next(o for o in obs if o["data"]["title"].startswith("Chisel tunnel established"))
    assert_observation(tunnel, kind="note", data_subset={"severity": "high"})
    assert tunnel["data"]["metadata"]["chisel_session"] == "1"


def test_chisel_grows_mission_state_notes():
    _, obs = _observations()
    state = merge_observations(obs, tool="chisel", action="reverse_socks")
    # Note merger dedupes on title, so every event must have a distinct title.
    assert len(state.notes) == len({o["data"]["title"] for o in obs})
    assert len(state.notes) >= 5


def test_chisel_does_not_fabricate_a_session():
    """A tunnel is reachability, not an interactive foothold."""

    _, obs = _observations()
    state = merge_observations(obs, tool="chisel", action="reverse_socks")
    assert state.sessions == []


def test_chisel_repeated_lines_are_deduped():
    text = "server: Listening on http://0.0.0.0:8000\n" * 3
    result = ChiselParser().parse_text(text)
    assert len(result.observations) == 1


def test_chisel_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "totally unrelated output"):
        result = ChiselParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
