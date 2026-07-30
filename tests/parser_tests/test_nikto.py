"""Tests for NiktoParser."""

from __future__ import annotations

from pathlib import Path

from saber.parsers.nikto import NiktoParser

from tests.conftest import assert_observation, merge_observations


class TestNiktoParser:
    """Validate Nikto parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = NiktoParser().parse_text("")

        assert result.success is False
        assert result.errors == ["Nikto output is empty."]

    def test_no_findings_fails(self) -> None:
        """Output with no OSVDB findings should fail."""

        text = "- Nikto v2.5.0\n+ Target IP: 10.0.0.5\n+ Server: Apache\n"

        result = NiktoParser().parse_text(text)

        assert result.success is False
        assert result.errors == ["No Nikto findings could be parsed."]

    def test_parse_finding_uses_metadata_host(self) -> None:
        """A finding line becomes a vuln observation using the metadata host."""

        text = "+ OSVDB-3092: /admin/: This might be interesting."

        result = NiktoParser().parse_text(text, metadata={"target": "10.0.0.9"})

        assert result.success is True
        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.kind == "vuln"
        assert observation.data["title"] == "OSVDB-3092: /admin/: This might be interesting."
        assert observation.data["host"] == "10.0.0.9"
        assert observation.data["severity"] == "info"
        assert observation.data["identifier"] == "OSVDB-3092"
        assert observation.data["confirmed"] is True

    def test_parse_finding_falls_back_to_target_ip_line(self) -> None:
        """When no metadata host is given, the report's Target IP line is used."""

        text = "+ Target IP: 10.0.0.5\n+ OSVDB-877: HTTP TRACE method is active.\n"

        result = NiktoParser().parse_text(text)

        assert result.success is True
        assert result.observations[0].data["host"] == "10.0.0.5"


def test_nikto_fixture_emits_vuln_and_grows_state() -> None:
    """Fixture Nikto output yields canonical vuln observations that grow state."""

    text = Path("tests/fixtures/sample_nikto_output.txt").read_text()
    result = NiktoParser().parse_text(text, metadata={"target": "10.0.0.5"})
    obs = [o.to_dict() for o in result.observations]
    vulns = [o for o in obs if o["kind"] == "vuln"]
    # 4, not 3: three OSVDB findings PLUS the X-Content-Type-Options finding, which
    # has no identifier. Requiring OSVDB discarded identifier-less findings — and
    # since Nikto 2.5 dropped OSVDB entirely (retired 2016), a real modern scan
    # produced zero observations and read as a clean target.
    assert len(vulns) == 4
    header_finding = next(v for v in vulns if "X-Content-Type-Options" in v["data"]["title"])
    assert header_finding["data"]["identifier"] is None
    admin_finding = next(v for v in vulns if v["data"]["identifier"] == "OSVDB-3092")
    assert_observation(
        admin_finding,
        kind="vuln",
        data_subset={
            "host": "10.0.0.5",
            "severity": "info",
            "identifier": "OSVDB-3092",
            "confirmed": True,
        },
    )
    state = merge_observations(obs, tool="nikto", action="web_scan")
    assert len(state.vulns) == 4
