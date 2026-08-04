from pathlib import Path

from saber.parsers.dnsrecon import DNSReconParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_dnsrecon_output.json")


def test_dnsrecon_json_emits_hosts_and_notes_and_grows_state():
    result = DNSReconParser().parse_text(_FIXTURE.read_text())
    obs = [o.to_dict() for o in result.observations]

    hosts = [o for o in obs if o["kind"] == "host"]
    notes = [o for o in obs if o["kind"] == "note"]

    # A records for example.com and www.example.com share one address.
    assert len(hosts) == 2
    # CNAME, MX and NS become notes.
    assert len(notes) == 3

    by_address = {o["data"]["address"]: o for o in hosts}
    assert sorted(by_address["93.184.216.34"]["data"]["hostnames"]) == [
        "example.com",
        "www.example.com",
    ]
    assert "2606:2800:220:1:248:1893:25c8:1946" in by_address

    state = merge_observations(obs, tool="dnsrecon", action="standard")
    assert len(state.hosts) == 2
    assert len(state.notes) == 3


def test_dnsrecon_scaninfo_header_is_ignored():
    result = DNSReconParser().parse_text(_FIXTURE.read_text())
    titles = [o.data.get("title") for o in result.observations if o.kind == "note"]
    assert not any("ScanInfo" in str(title) for title in titles)


def test_dnsrecon_cname_note_carries_target_detail():
    result = DNSReconParser().parse_text(_FIXTURE.read_text())
    notes = [o.to_dict() for o in result.observations if o.kind == "note"]
    cname = next(o for o in notes if "CNAME" in o["data"]["title"])
    assert_observation(
        cname,
        kind="note",
        data_subset={
            "title": "DNS CNAME shop.example.com",
            "severity": "info",
        },
    )
    assert "storefront.cdn.example.net" in cname["data"]["detail"]


def test_dnsrecon_stdout_form_is_parsed():
    text = "\n".join(
        [
            "[*] std: Performing General Enumeration against: example.com...",
            "[-] DNSSEC is not configured for example.com",
            "[*]      A www.example.com 93.184.216.34",
            "[*]      MX example.com mail.example.com",
            "",
        ]
    )
    result = DNSReconParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    assert result.metadata["format"] == "text"
    assert [o["kind"] for o in obs].count("host") == 1
    assert [o["kind"] for o in obs].count("note") == 1


def test_dnsrecon_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "{not json", "totally unrelated text"):
        result = DNSReconParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors
