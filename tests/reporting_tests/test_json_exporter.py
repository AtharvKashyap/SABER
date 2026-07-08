"""Tests for JSON report exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentObservation
from saber.parsers.base import ParsedFinding, ParsedObservation, ParserSeverity
from saber.reporting.json_exporter import (
    JsonExporter,
    ReportDocument,
    ReportFinding,
    ReportObservation,
    ReportSeverity,
)


def make_generated_at() -> datetime:
    """Return deterministic timestamp."""

    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_observation() -> ReportObservation:
    """Create report observation."""

    return ReportObservation(
        kind="service",
        summary="10.0.0.5:443/tcp is open running https.",
        source_tool="nmap",
        data={"host": "10.0.0.5", "port": 443},
        metadata={"format": "xml"},
    )


def make_finding(severity: ReportSeverity = ReportSeverity.HIGH) -> ReportFinding:
    """Create report finding."""

    return ReportFinding(
        title="Example Vulnerability",
        severity=severity,
        description="Example vulnerability description.",
        source_tool="nuclei",
        evidence={"template_id": "cve-2026-0001", "matched_at": "https://example.com"},
        references=["https://example.com/advisory"],
        metadata={"tag": "test"},
    )


def make_document(findings: list[ReportFinding] | None = None) -> ReportDocument:
    """Create report document."""

    return ReportDocument(
        report_id="report_test",
        mission_name="Unit Test Mission",
        target="example.com",
        generated_at=make_generated_at(),
        executive_summary="Unit test summary.",
        observations=[make_observation()],
        findings=findings if findings is not None else [make_finding()],
        metadata={"owner": "unit-test"},
    )


class TestReportObservation:
    """Validate ReportObservation."""

    def test_validates_kind(self) -> None:
        """Empty kind should raise."""

        with pytest.raises(ValueError, match="ReportObservation.kind cannot be empty"):
            ReportObservation(kind="", summary="summary")

    def test_validates_summary(self) -> None:
        """Empty summary should raise."""

        with pytest.raises(ValueError, match="ReportObservation.summary cannot be empty"):
            ReportObservation(kind="generic", summary="")

    def test_to_dict(self) -> None:
        """Observation should serialize."""

        observation = make_observation()

        assert observation.to_dict() == {
            "kind": "service",
            "summary": "10.0.0.5:443/tcp is open running https.",
            "source_tool": "nmap",
            "data": {"host": "10.0.0.5", "port": 443},
            "metadata": {"format": "xml"},
        }


class TestReportFinding:
    """Validate ReportFinding."""

    def test_validates_title(self) -> None:
        """Empty title should raise."""

        with pytest.raises(ValueError, match="ReportFinding.title cannot be empty"):
            ReportFinding(
                title="",
                severity=ReportSeverity.HIGH,
                description="description",
            )

    def test_validates_description(self) -> None:
        """Empty description should raise."""

        with pytest.raises(ValueError, match="ReportFinding.description cannot be empty"):
            ReportFinding(
                title="Finding",
                severity=ReportSeverity.HIGH,
                description="",
            )

    def test_to_dict(self) -> None:
        """Finding should serialize."""

        finding = make_finding()

        assert finding.to_dict() == {
            "title": "Example Vulnerability",
            "severity": "high",
            "description": "Example vulnerability description.",
            "source_tool": "nuclei",
            "evidence": {"template_id": "cve-2026-0001", "matched_at": "https://example.com"},
            "references": ["https://example.com/advisory"],
            "metadata": {"tag": "test"},
        }


class TestReportDocument:
    """Validate ReportDocument."""

    def test_validates_report_id(self) -> None:
        """Empty report ID should raise."""

        with pytest.raises(ValueError, match="ReportDocument.report_id cannot be empty"):
            ReportDocument(
                report_id="",
                mission_name="Mission",
                target="example.com",
                generated_at=make_generated_at(),
                executive_summary="Summary.",
            )

    def test_validates_mission_name(self) -> None:
        """Empty mission name should raise."""

        with pytest.raises(ValueError, match="ReportDocument.mission_name cannot be empty"):
            ReportDocument(
                report_id="report",
                mission_name="",
                target="example.com",
                generated_at=make_generated_at(),
                executive_summary="Summary.",
            )

    def test_validates_target(self) -> None:
        """Empty target should raise."""

        with pytest.raises(ValueError, match="ReportDocument.target cannot be empty"):
            ReportDocument(
                report_id="report",
                mission_name="Mission",
                target="",
                generated_at=make_generated_at(),
                executive_summary="Summary.",
            )

    def test_validates_executive_summary(self) -> None:
        """Empty executive summary should raise."""

        with pytest.raises(ValueError, match="ReportDocument.executive_summary cannot be empty"):
            ReportDocument(
                report_id="report",
                mission_name="Mission",
                target="example.com",
                generated_at=make_generated_at(),
                executive_summary="",
            )

    def test_severity_counts(self) -> None:
        """Severity counts should include all severities."""

        document = make_document(
            [
                make_finding(ReportSeverity.CRITICAL),
                make_finding(ReportSeverity.HIGH),
                make_finding(ReportSeverity.HIGH),
                make_finding(ReportSeverity.MEDIUM),
            ]
        )

        counts = document.severity_counts()

        assert counts == {
            "info": 0,
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 1,
            "unknown": 0,
        }

    def test_highest_severity(self) -> None:
        """Highest severity should return most severe finding."""

        document = make_document(
            [
                make_finding(ReportSeverity.LOW),
                make_finding(ReportSeverity.CRITICAL),
                make_finding(ReportSeverity.HIGH),
            ]
        )

        assert document.highest_severity() == ReportSeverity.CRITICAL

    def test_highest_severity_no_findings_defaults_info(self) -> None:
        """No findings should default highest severity to info."""

        document = make_document([])

        assert document.highest_severity() == ReportSeverity.INFO

    def test_sorted_findings(self) -> None:
        """Findings should sort by severity."""

        low = make_finding(ReportSeverity.LOW)
        critical = make_finding(ReportSeverity.CRITICAL)
        medium = make_finding(ReportSeverity.MEDIUM)
        document = make_document([low, critical, medium])

        assert [finding.severity for finding in document.sorted_findings()] == [
            ReportSeverity.CRITICAL,
            ReportSeverity.MEDIUM,
            ReportSeverity.LOW,
        ]

    def test_priority_findings_limit(self) -> None:
        """Priority findings should respect limit."""

        document = make_document(
            [
                make_finding(ReportSeverity.CRITICAL),
                make_finding(ReportSeverity.HIGH),
                make_finding(ReportSeverity.MEDIUM),
            ]
        )

        assert len(document.priority_findings(limit=2)) == 2

    def test_to_dict_and_json(self) -> None:
        """Document should serialize to dict and JSON."""

        document = make_document()
        data = document.to_dict()

        assert data["report_id"] == "report_test"
        assert data["mission_name"] == "Unit Test Mission"
        assert data["target"] == "example.com"
        assert data["generated_at"] == "2026-01-01T12:00:00+00:00"
        assert data["highest_severity"] == "high"
        assert data["finding_count"] == 1
        assert data["observation_count"] == 1
        assert data["findings"][0]["title"] == "Example Vulnerability"

        parsed = json.loads(document.to_json())
        assert parsed["report_id"] == "report_test"


class TestJsonExporter:
    """Validate JsonExporter."""

    def test_build_document_from_report_objects(self) -> None:
        """Exporter should build document from report objects."""

        exporter = JsonExporter()
        document = exporter.build_document(
            mission_name="Mission",
            target="example.com",
            observations=[make_observation()],
            findings=[make_finding()],
            metadata={"scope": "approved"},
            report_id="report_fixed",
            generated_at=make_generated_at(),
        )

        assert document.report_id == "report_fixed"
        assert document.mission_name == "Mission"
        assert document.target == "example.com"
        assert document.generated_at == make_generated_at()
        assert document.metadata == {"scope": "approved"}
        assert document.findings[0].severity == ReportSeverity.HIGH

    def test_build_document_generates_summary_without_findings(self) -> None:
        """Exporter should generate deterministic summary when no findings exist."""

        exporter = JsonExporter()
        document = exporter.build_document(
            mission_name="Mission",
            target="example.com",
            observations=[make_observation()],
            findings=[],
            report_id="report_fixed",
            generated_at=make_generated_at(),
        )

        assert "No reportable findings" in document.executive_summary

    def test_build_document_generates_summary_with_findings(self) -> None:
        """Exporter should generate deterministic finding summary."""

        exporter = JsonExporter()
        document = exporter.build_document(
            mission_name="Mission",
            target="example.com",
            observations=[make_observation()],
            findings=[make_finding(ReportSeverity.CRITICAL), make_finding(ReportSeverity.LOW)],
            report_id="report_fixed",
            generated_at=make_generated_at(),
        )

        assert "SABER identified 2 findings" in document.executive_summary
        assert "highest finding severity is critical" in document.executive_summary

    def test_normalize_parsed_observation(self) -> None:
        """ParsedObservation should normalize."""

        exporter = JsonExporter()
        parsed = ParsedObservation(
            kind="web_technology",
            summary="Uses nginx.",
            source_tool="whatweb",
            data={"server": "nginx"},
            metadata={"format": "json"},
        )

        observation = exporter.normalize_observation(parsed)

        assert observation.kind == "web_technology"
        assert observation.summary == "Uses nginx."
        assert observation.source_tool == "whatweb"
        assert observation.data == {"server": "nginx"}

    def test_normalize_agent_observation(self) -> None:
        """AgentObservation should normalize."""

        exporter = JsonExporter()
        agent_observation = AgentObservation(
            summary="Agent saw web surface.",
            tool_name="whatweb",
            action="fingerprint",
            success=True,
            metadata={"agent": "web_agent"},
        )

        observation = exporter.normalize_observation(agent_observation)

        assert observation.kind == "generic"
        assert observation.summary == "Agent saw web surface."
        assert observation.source_tool == "whatweb"
        assert observation.data == {}
        assert observation.metadata == {"agent": "web_agent"}

    def test_normalize_observation_dict(self) -> None:
        """Observation dict should normalize."""

        exporter = JsonExporter()
        observation = exporter.normalize_observation(
            {
                "kind": "service",
                "summary": "Port open.",
                "tool_name": "nmap",
                "data": {"port": 80},
                "metadata": {"x": 1},
            }
        )

        assert observation.kind == "service"
        assert observation.source_tool == "nmap"
        assert observation.data == {"port": 80}

    def test_normalize_parsed_finding(self) -> None:
        """ParsedFinding should normalize."""

        exporter = JsonExporter()
        parsed = ParsedFinding(
            title="Nuclei Finding",
            severity=ParserSeverity.CRITICAL,
            description="Critical issue.",
            source_tool="nuclei",
            evidence={"template_id": "x"},
            references=["https://example.com"],
            metadata={"tag": "cve"},
        )

        finding = exporter.normalize_finding(parsed)

        assert finding.title == "Nuclei Finding"
        assert finding.severity == ReportSeverity.CRITICAL
        assert finding.source_tool == "nuclei"
        assert finding.evidence == {"template_id": "x"}
        assert finding.references == ["https://example.com"]

    def test_normalize_finding_dict(self) -> None:
        """Finding dict should normalize."""

        exporter = JsonExporter()
        finding = exporter.normalize_finding(
            {
                "title": "Dict Finding",
                "severity": "med",
                "description": "Description.",
                "source_tool": "nuclei",
                "evidence": {"k": "v"},
                "references": "https://example.com",
            }
        )

        assert finding.title == "Dict Finding"
        assert finding.severity == ReportSeverity.MEDIUM
        assert finding.references == ["https://example.com"]

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("info", ReportSeverity.INFO),
            ("informational", ReportSeverity.INFO),
            ("low", ReportSeverity.LOW),
            ("med", ReportSeverity.MEDIUM),
            ("medium", ReportSeverity.MEDIUM),
            ("high", ReportSeverity.HIGH),
            ("crit", ReportSeverity.CRITICAL),
            ("critical", ReportSeverity.CRITICAL),
            ("bad", ReportSeverity.UNKNOWN),
            (None, ReportSeverity.UNKNOWN),
            (ReportSeverity.HIGH, ReportSeverity.HIGH),
            (ParserSeverity.LOW, ReportSeverity.LOW),
        ],
    )
    def test_severity_from_value(self, raw: object, expected: ReportSeverity) -> None:
        """Severity should normalize from multiple value types."""

        assert JsonExporter.severity_from_value(raw) == expected

    def test_export_and_export_dict(self, tmp_path) -> None:
        """Exporter should write JSON file and return dict."""

        exporter = JsonExporter()
        document = make_document()
        output_path = tmp_path / "report.json"

        returned = exporter.export(document, output_path)

        assert returned == output_path
        assert output_path.exists()

        loaded = json.loads(output_path.read_text())
        assert loaded["report_id"] == "report_test"

        exported = exporter.export_dict(document)
        assert exported["report_id"] == "report_test"
