from __future__ import annotations

from pathlib import Path

from saber.parsers.openvas import OpenVASParser

from tests.conftest import assert_observation, merge_observations

_FIXTURE = Path("tests/fixtures/sample_openvas_output.xml")


def test_openvas_emits_vuln_per_result_and_grows_state():
    text = _FIXTURE.read_text()
    result = OpenVASParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]

    vulns = [o for o in obs if o["kind"] == "vuln"]
    assert len(vulns) == 2

    heartbleed = next(o for o in vulns if "Heartbleed" in o["data"]["title"])
    assert_observation(
        heartbleed,
        kind="vuln",
        data_subset={
            "title": "OpenSSL Heartbleed Vulnerability",
            "host": "10.0.0.5",
            "port": 443,
            "severity": "high",
            "identifier": "CVE-2014-0160",
            "confirmed": True,
        },
    )

    weak_kex = next(o for o in vulns if "Weak SSH" in o["data"]["title"])
    assert_observation(
        weak_kex,
        kind="vuln",
        data_subset={
            "host": "10.0.0.5",
            "port": 22,
            "severity": "medium",
            "identifier": None,
        },
    )

    state = merge_observations(obs, tool="openvas", action="get_report")
    assert len(state.vulns) == 2


def test_openvas_skips_log_threat_entries():
    text = _FIXTURE.read_text()
    result = OpenVASParser().parse_text(text)
    titles = {o.data["title"] for o in result.observations}
    assert "NVT: Ping Host" not in titles


def test_openvas_malformed_input_degrades_to_zero_observations():
    for text in ("", "   ", "not xml at all", "<unclosed"):
        result = OpenVASParser().parse_text(text)
        assert result.observations == []
        assert result.success is False
        assert result.errors


def test_openvas_xml_with_no_results_degrades_to_zero_observations():
    result = OpenVASParser().parse_text("<get_reports_response><report/></get_reports_response>")
    assert result.observations == []
    assert result.success is False
    assert result.errors
