from pathlib import Path

from saber.parsers.bettercap import BettercapParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_bettercap_output.txt")


def test_bettercap_emits_host_per_table_row_and_grows_state():
    result = BettercapParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    hosts = [o for o in obs if o["kind"] == "host"]
    assert len(hosts) == 3

    router = next(o for o in hosts if o["data"]["address"] == "192.168.1.1")
    assert_observation(
        router,
        kind="host",
        data_subset={
            "address": "192.168.1.1",
            "hostnames": ["router.local"],
        },
    )
    assert router["data"]["metadata"]["mac"] == "aa:bb:cc:dd:ee:01"
    assert router["data"]["metadata"]["vendor"] == "TP-Link"

    # A host with no Name cell still parses, just without a hostname.
    nameless = next(o for o in hosts if o["data"]["address"] == "192.168.1.105")
    assert nameless["data"]["hostnames"] == []
    assert nameless["data"]["metadata"]["mac"] == "11:22:33:44:55:66"

    state = merge_observations(obs, tool="bettercap", action="net_probe")
    assert len(state.hosts) == 3


def test_bettercap_emits_summary_note_from_banner():
    result = BettercapParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    notes = [o for o in obs if o["kind"] == "note"]
    assert len(notes) == 1
    assert_observation(
        notes[0],
        kind="note",
        data_subset={"title": "Bettercap net table on eth0"},
    )

    state = merge_observations(obs, tool="bettercap", action="net_probe")
    assert len(state.notes) == 1


def test_bettercap_strips_ansi_escapes():
    text = (
        "│ \x1b[97m10.0.0.9\x1b[0m │ \x1b[97maa:bb:cc:dd:ee:ff\x1b[0m │ "
        "\x1b[97mbox\x1b[0m │ \x1b[97mVendor\x1b[0m │\n"
    )
    result = BettercapParser().parse_text(text)
    hosts = [o for o in result.observations if o.kind == "host"]
    assert len(hosts) == 1
    assert hosts[0].data["address"] == "10.0.0.9"
    assert hosts[0].data["metadata"]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_bettercap_duplicate_rows_deduped_by_address():
    text = (
        "┌────┬────┬────┬────┐\n"
        "│ 10.0.0.5 │ aa:aa:aa:aa:aa:aa │ host │ Vendor │\n"
        "│ 10.0.0.5 │ aa:aa:aa:aa:aa:aa │ host │ Vendor │\n"
        "└────┴────┴────┴────┘\n"
    )
    result = BettercapParser().parse_text(text)
    hosts = [o for o in result.observations if o.kind == "host"]
    assert len(hosts) == 1


def test_bettercap_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "banner only, no table"):
        result = BettercapParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
