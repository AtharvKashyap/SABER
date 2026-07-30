"""Passive capture must turn packets into state, not into a packet dump.

The payoff of sniffing is finding hosts that never answer a scan and credentials
sent in the clear — so those are the things this asserts.
"""

from pathlib import Path

from saber.parsers.tshark import TsharkParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_tshark_output.json")
_META = {"pcap_path": "/workspace/output/capture.pcap"}


def _observations(metadata=_META):
    result = TsharkParser().parse_text(_FIXTURE.read_text(), metadata=metadata)
    return result, [o.to_dict() for o in result.observations]


def test_emits_only_canonical_kinds():
    from saber.core.canonical_kinds import CANONICAL_KINDS

    _, obs = _observations()
    assert obs
    assert {o["kind"] for o in obs} <= CANONICAL_KINDS
    assert {o["kind"] for o in obs} == {"host", "note", "credential", "loot"}


def test_every_ip_on_the_wire_becomes_a_host():
    """A host that never answers a probe still shows up in traffic."""

    _, obs = _observations()
    addresses = {o["data"]["address"] for o in obs if o["kind"] == "host"}

    assert addresses == {"10.0.0.5", "10.0.0.9", "10.0.0.7", "10.0.0.20", "10.0.0.1"}


def test_host_records_how_often_it_was_seen():
    _, obs = _observations()
    host = next(o for o in obs if o["kind"] == "host" and o["data"]["address"] == "10.0.0.5")
    assert host["data"]["metadata"]["packets_seen"] == 3
    assert host["data"]["metadata"]["discovered_by"] == "tshark"


def test_cleartext_protocols_are_flagged_higher_than_encrypted_ones():
    _, obs = _observations()
    by_title = {o["data"]["title"]: o["data"] for o in obs if o["kind"] == "note"}

    assert by_title["Protocol observed: ftp"]["severity"] == "medium"
    assert "credentials in the clear" in by_title["Protocol observed: ftp"]["detail"]
    assert by_title["Protocol observed: dns"]["severity"] == "info"


def test_http_basic_auth_is_decoded_into_a_credential():
    _, obs = _observations()
    credentials = [o for o in obs if o["kind"] == "credential"]
    http = next(o for o in credentials if o["data"]["service"] == "http")

    assert_observation(
        http,
        kind="credential",
        data_subset={
            "username": "admin",
            "secret": "FakeLabPassw0rd",
            "service": "http",
            "validated": False,
        },
    )


def test_ftp_login_is_captured():
    _, obs = _observations()
    ftp = [o for o in obs if o["kind"] == "credential" and o["data"]["service"] == "ftp"]
    usernames = {o["data"]["username"] for o in ftp}
    assert "labuser" in usernames


def test_sniffed_credentials_are_never_marked_validated():
    """Seeing a password proves it was sent, not that it still works."""

    _, obs = _observations()
    for credential in (o for o in obs if o["kind"] == "credential"):
        assert credential["data"]["validated"] is False


def test_the_pcap_itself_is_recorded_as_loot():
    _, obs = _observations()
    loot = next(o for o in obs if o["kind"] == "loot")
    assert loot["data"]["path"] == "/workspace/output/capture.pcap"
    assert loot["data"]["kind"] == "file"


def test_no_loot_when_no_pcap_path_is_known():
    _, obs = _observations(metadata={})
    assert not [o for o in obs if o["kind"] == "loot"]


def test_capture_grows_hosts_credentials_notes_and_loot():
    _, obs = _observations()
    state = merge_observations(obs, tool="tshark", action="capture")

    assert len(state.hosts) == 5
    assert len(state.credentials) >= 2
    assert state.notes
    assert len(state.loot) == 1


def test_does_not_emit_one_observation_per_packet():
    _, obs = _observations()
    # 6 packets in the fixture; aggregation must not scale 1:1 with packets.
    assert len([o for o in obs if o["kind"] == "note"]) <= 5


def test_summary_text_form_is_parsed():
    text = (
        "    1   0.000000 10.0.0.5 -> 10.0.0.9  TCP 74 44210 > 21 [SYN]\n"
        "    2   0.000221 10.0.0.9 -> 10.0.0.5  TCP 74 21 > 44210 [SYN, ACK]\n"
    )
    result = TsharkParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]

    assert result.metadata["format"] == "summary"
    assert {o["data"]["address"] for o in obs if o["kind"] == "host"} == {"10.0.0.5", "10.0.0.9"}


def test_malformed_basic_auth_is_ignored_not_crashed_on():
    text = "Authorization: Basic !!!!notbase64!!!!\n"
    result = TsharkParser().parse_text(text)
    assert not [o for o in result.observations if o.kind == "credential"]


def test_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "[", "no packets here"):
        result = TsharkParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
