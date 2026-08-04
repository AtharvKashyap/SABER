"""Tests for parser base models."""

from __future__ import annotations
import json
import pytest

from saber.parsers.base import (
    BaseParser,
    ParsedFinding,
    ParsedObservation,
    ParserResult,
    ParserSeverity,
)

class DummyParser(BaseParser):
    """Concrete test parser."""
    
    source_tool = "dummy"

    def parse_text(self, text: str, metadata: dict | None = None) -> ParserResult:
        """Parse text."""

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=[
                ParsedObservation(
                    kind="generic",
                    summary=text,
                    source_tool=self.source_tool,
                )
            ],
        )

    def parse_json(self, data: dict | list, metadata: dict | None = None) -> ParserResult:
        """Parse JSON."""

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            metadata={"data": data},
        )

class TestParsedObservation:
    """Validate ParsedObservation."""

    def test_validates_kind(self) -> None:
        """Empty kind should raise."""

        with pytest.raises(ValueError, match="ParsedObservation.kind cannot be empty"):
            ParsedObservation(kind="", summary="summary", source_tool="tool")

    def test_validates_summary(self) -> None:
        """Empty summary should raise."""

        with pytest.raises(ValueError, match="ParsedObservation.summary cannot be empty"):
            ParsedObservation(kind="generic", summary="", source_tool="tool")

    def test_validates_source_tool(self) -> None:
        """Empty source tool should raise."""

        with pytest.raises(ValueError, match="ParsedObservation.source_tool cannot be empty"):
            ParsedObservation(kind="generic", summary="summary", source_tool="")

    def test_to_dict(self) -> None:
        """Observation should serialize."""

        observation = ParsedObservation(
            kind="service",
            summary="Port open.",
            source_tool="nmap",
            data={"port": 80},
            metadata={"format": "xml"},
        )

        assert observation.to_dict() == {
            "kind": "service",
            "summary": "Port open.",
            "source_tool": "nmap",
            "data": {"port": 80},
            "metadata": {"format": "xml"},
        }

class TestParsedFinding:
    """Validate ParsedFinding."""

    def test_validates_title(self) -> None:
        """Empty title should raise."""

        with pytest.raises(ValueError, match="ParsedFinding.title cannot be empty"):
            ParsedFinding(
                title="",
                severity=ParserSeverity.HIGH,
                description="desc",
                source_tool="nuclei",
            )

    def test_validates_description(self) -> None:
        """Empty description should raise."""

        with pytest.raises(ValueError, match="ParsedFinding.description cannot be empty"):

            ParsedFinding(
                title="Finding",
                severity=ParserSeverity.HIGH,
                description="",
                source_tool="nuclei",
            )

    def test_validates_source_tool(self) -> None:
        """Empty source tool should raise."""

        with pytest.raises(ValueError, match="ParsedFinding.source_tool cannot be empty"):

            ParsedFinding(
                title="Finding",
                severity=ParserSeverity.HIGH,
                description="desc",
                source_tool="",
            )

    def test_to_dict(self) -> None:
        """Finding should serialize."""

        finding = ParsedFinding(
            title="Critical issue",
            severity=ParserSeverity.CRITICAL,
            description="Description.",
            source_tool="nuclei",
            evidence={"template_id": "cve"},
            references=["https://example.com"],
            metadata={"tag": "test"},
        )

        assert finding.to_dict() == {
            "title": "Critical issue",
            "severity": "critical",
            "description": "Description.",
            "source_tool": "nuclei",
            "evidence": {"template_id": "cve"},
            "references": ["https://example.com"],
            "metadata": {"tag": "test"},
        }

class TestParserResult:
    """Validate ParserResult."""

    def test_validates_source_tool(self) -> None:
        """Empty source tool should raise."""

        with pytest.raises(ValueError, match="ParserResult.source_tool cannot be empty"):
            ParserResult(source_tool="", success=True)

    def test_has_data(self) -> None:
        """has_data should reflect observations/findings."""
        
        empty = ParserResult(source_tool="tool", success=True)

        with_observation = ParserResult(
            source_tool="tool",
            success=True,
            observations=[ParsedObservation(kind="generic", summary="Observed.", source_tool="tool")],
        )

        with_finding = ParserResult(
            source_tool="tool",
            success=True,
            findings=[
                ParsedFinding(
                    title="Finding",
                    severity=ParserSeverity.INFO,
                    description="desc",
                    source_tool="tool",
                )
            ],
        )

        assert empty.has_data() is False
        assert with_observation.has_data() is True
        assert with_finding.has_data() is True

    def test_to_dict(self) -> None:
        """ParserResult should serialize."""

        result = ParserResult(
            source_tool="tool",
            success=True,
            observations=[ParsedObservation(kind="generic", summary="Observed.", source_tool="tool")],

            findings=[
                ParsedFinding(
                    title="Finding",
                    severity=ParserSeverity.INFO,
                    description="desc",
                    source_tool="tool",
                )
            ],
            errors=["warning"],
            metadata={"count": 1},
        )
        data = result.to_dict()

        assert data["source_tool"] == "tool"
        assert data["success"] is True
        assert data["observations"][0]["summary"] == "Observed."
        assert data["findings"][0]["severity"] == "info"
        assert data["errors"] == ["warning"]
        assert data["metadata"] == {"count": 1}

class TestBaseParser:
    """Validate BaseParser helpers."""

    def test_base_parse_text_not_implemented(self) -> None:
        """Base parser should raise for parse_text."""

        parser = BaseParser()

        with pytest.raises(NotImplementedError, match="parse_text is not implemented"):
            parser.parse_text("x")

    def test_base_parse_json_not_implemented(self) -> None:
        """Base parser should raise for parse_json."""

        parser = BaseParser()

        with pytest.raises(NotImplementedError, match="parse_json is not implemented"):
            parser.parse_json({})

    @pytest.mark.parametrize(
        
        ("raw", "expected"),
        [
            ("info", ParserSeverity.INFO),
            ("informational", ParserSeverity.INFO),
            ("low", ParserSeverity.LOW),
            ("med", ParserSeverity.MEDIUM),
            ("medium", ParserSeverity.MEDIUM),
            ("high", ParserSeverity.HIGH),
            ("crit", ParserSeverity.CRITICAL),
            ("critical", ParserSeverity.CRITICAL),
            ("bad", ParserSeverity.UNKNOWN),
            (None, ParserSeverity.UNKNOWN),
        ],
    )

    def test_severity_from_string(self, raw: str | None, expected: ParserSeverity) -> None:
        """Severity should normalize."""
        
        assert BaseParser.severity_from_string(raw) == expected

    def test_safe_json_loads(self) -> None:
        """safe_json_loads should parse valid JSON and return None for invalid."""

        assert BaseParser.safe_json_loads('{"a": 1}') == {"a": 1}
        assert BaseParser.safe_json_loads("{bad") is None

    def test_parse_json_lines(self) -> None:
        """parse_json_lines should parse valid JSONL and collect errors."""
        
        objects, errors = BaseParser.parse_json_lines('{"a": 1}\nnot-json\n{"b": 2}')

        assert objects == [{"a": 1}, {"b": 2}]
        assert len(errors) == 1
        assert "line 2" in errors[0]

    def test_parse_file_missing(self, tmp_path) -> None:
        """Missing input file should return parser error."""

        parser = DummyParser()
        result = parser.parse_file(tmp_path / "missing.txt")

        assert result.success is False
        assert "does not exist" in result.errors[0]

    def test_parse_file_text(self, tmp_path) -> None:
        """Text file should route to parse_text."""

        path = tmp_path / "out.txt"
        path.write_text("hello")
        parser = DummyParser()
        result = parser.parse_file(path)

        assert result.success is True
        assert result.observations[0].summary == "hello"

    def test_parse_file_json(self, tmp_path) -> None:
        """JSON file should route to parse_json."""

        path = tmp_path / "out.json"
        path.write_text(json.dumps({"a": 1}))
        parser = DummyParser()
        result = parser.parse_file(path)

        assert result.success is True
        assert result.metadata["data"] == {"a": 1}

    def test_parse_file_jsonl(self, tmp_path) -> None:
        """JSONL file should route to parse_json."""

        path = tmp_path / "out.jsonl"
        path.write_text('{"a": 1}\n{"b": 2}\n')
        parser = DummyParser()
        result = parser.parse_file(path)

        assert result.success is True
        assert result.metadata["data"] == [{"a": 1}, {"b": 2}]

class _P(BaseParser):
    source_tool = "x"

    def parse_text(self, text, metadata=None):
        return ParserResult(source_tool="x", success=True)


def test_parse_text_accepts_metadata_kwarg():
    """A subclass overriding parse_text with metadata should accept the kwarg."""

    assert _P().parse_text("hi", metadata={"target": "127.0.0.1"}).success


def test_existing_parsers_accept_metadata_kwarg():
    """The registry always passes metadata=..., so real parsers must accept it."""

    from saber.parsers.nmap import NmapParser

    result = NmapParser().parse_text("", metadata={"target": "127.0.0.1"})
    assert isinstance(result, ParserResult)
