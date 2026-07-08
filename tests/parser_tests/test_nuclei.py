"""Tests for NucleiParser."""

from __future__ import annotations

from saber.parsers.base import ParserSeverity
from saber.parsers.nuclei import NucleiParser


class TestNucleiParser:
    """Validate Nuclei parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = NucleiParser().parse_text("")

        assert result.success is False
        assert result.errors == ["Nuclei output is empty."]

    def test_parse_json_record(self) -> None:
        """Nuclei JSON should produce finding and observation."""

        data = {
            "template-id": "cve-2024-0001",
            "info": {
                "name": "Example CVE",
                "severity": "high",
                "description": "Example vulnerability.",
                "reference": ["https://example.com/advisory"],
                "tags": "cve,rce",
            },
            "matched-at": "https://example.com",
            "host": "example.com",
            "ip": "10.0.0.5",
            "port": 443,
        }

        result = NucleiParser().parse_json(data)

        assert result.success is True
        assert len(result.findings) == 1
        assert len(result.observations) == 1

        finding = result.findings[0]
        assert finding.title == "Example CVE"
        assert finding.severity == ParserSeverity.HIGH
        assert finding.description == "Example vulnerability."
        assert finding.evidence["template_id"] == "cve-2024-0001"
        assert finding.evidence["matched_at"] == "https://example.com"
        assert finding.references == ["https://example.com/advisory"]

        observation = result.observations[0]
        assert observation.kind == "vulnerability"
        assert observation.metadata["severity"] == "high"

    def test_parse_json_text(self) -> None:
        """JSON text should route to parse_json."""

        text = '{"template-id":"exposure","info":{"name":"Exposure","severity":"medium"},"matched-at":"https://example.com"}'

        result = NucleiParser().parse_text(text)

        assert result.success is True
        assert result.findings[0].severity == ParserSeverity.MEDIUM
        assert result.findings[0].title == "Exposure"

    def test_parse_jsonl_text(self) -> None:
        """JSONL text should parse multiple records."""

        text = """
{"template-id":"one","info":{"name":"One","severity":"low"},"matched-at":"https://a.example"}
{"template-id":"two","info":{"name":"Two","severity":"critical"},"matched-at":"https://b.example"}
"""

        result = NucleiParser().parse_text(text)

        assert result.success is True
        assert result.metadata["format"] == "jsonl"
        assert len(result.findings) == 2
        assert result.findings[0].severity == ParserSeverity.LOW
        assert result.findings[1].severity == ParserSeverity.CRITICAL

    def test_parse_jsonl_with_bad_line_keeps_error(self) -> None:
        """Bad JSONL lines should be preserved as errors when some lines parse."""

        text = """
{"template-id":"one","info":{"name":"One","severity":"low"},"matched-at":"https://a.example"}
bad-json
"""

        result = NucleiParser().parse_text(text)

        assert result.success is True
        assert len(result.findings) == 1
        assert len(result.errors) == 1
        assert "line 2" in result.errors[0]

    def test_parse_stdout(self) -> None:
        """Stdout should produce finding."""

        text = "[cve-2024-0001] [http] [high] https://example.com"

        result = NucleiParser().parse_text(text)

        assert result.success is True
        assert result.metadata["format"] == "stdout"
        assert result.findings[0].title == "cve-2024-0001"
        assert result.findings[0].severity == ParserSeverity.HIGH
        assert result.findings[0].evidence["matched_at"] == "https://example.com"

    def test_parse_unrecognized_stdout_fails(self) -> None:
        """Unrecognized stdout should fail."""

        result = NucleiParser().parse_text("nothing useful")

        assert result.success is False
        assert result.errors

    def test_parse_json_without_findings_fails(self) -> None:
        """JSON without usable finding should fail."""

        result = NucleiParser().parse_json({"info": {}})

        assert result.success is False
        assert result.errors == ["No Nuclei findings could be parsed."]
