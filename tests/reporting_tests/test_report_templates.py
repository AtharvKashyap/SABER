"""Tests for report templates."""

from __future__ import annotations

from pathlib import Path

from saber.reporting.json_exporter import ReportDocument, ReportFinding, ReportObservation, ReportSeverity
from saber.reporting.pdf_exporter import PdfExporter


TEMPLATE_DIR = Path("saber/reporting/templates")


def make_document(with_data: bool = True) -> ReportDocument:
    """Create report document."""

    findings = []
    observations = []

    if with_data:
        findings = [
            ReportFinding(
                title="High Risk Finding",
                severity=ReportSeverity.HIGH,
                description="High risk description.",
                source_tool="nuclei",
                evidence={"template_id": "high-template"},
                references=["https://example.com/high"],
                metadata={"tag": "high"},
            )
        ]
        observations = [
            ReportObservation(
                kind="web_technology",
                summary="Target uses nginx.",
                source_tool="whatweb",
                data={"server": "nginx"},
                metadata={"format": "json"},
            )
        ]

    return ReportDocument(
        report_id="report_template_test",
        mission_name="Template Mission",
        target="example.com",
        generated_at=__import__("datetime").datetime(2026, 1, 1, 12, 0, 0, tzinfo=__import__("datetime").UTC),
        executive_summary="Template summary.",
        observations=observations,
        findings=findings,
        metadata={"scope": "approved"},
    )


class TestReportTemplates:
    """Validate report template files."""

    def test_templates_exist(self) -> None:
        """Expected templates should exist."""

        assert (TEMPLATE_DIR / "executive_summary.md.j2").exists()
        assert (TEMPLATE_DIR / "technical_report.md.j2").exists()

    def test_executive_summary_template_has_expected_sections(self) -> None:
        """Executive summary template should contain required sections."""

        text = (TEMPLATE_DIR / "executive_summary.md.j2").read_text()

        assert "# Executive Summary" in text
        assert "## Overall Risk" in text
        assert "## Finding Summary" in text
        assert "## Highest Priority Findings" in text
        assert "## Recommended Next Steps" in text

    def test_technical_report_template_has_expected_sections(self) -> None:
        """Technical template should contain required sections."""

        text = (TEMPLATE_DIR / "technical_report.md.j2").read_text()

        assert "# SABER Technical Report" in text
        assert "## Executive Summary" in text
        assert "## Severity Summary" in text
        assert "## Findings" in text
        assert "## Observations" in text
        assert "## Report Metadata" in text

    def test_executive_summary_template_renders_with_findings(self) -> None:
        """Executive template should render with data."""

        markdown = PdfExporter().render_markdown(make_document(), template_name="executive_summary.md.j2")

        assert "# Executive Summary" in markdown
        assert "**Mission:** Template Mission" in markdown
        assert "**Target:** example.com" in markdown
        assert "| High | 1 |" in markdown
        assert "High Risk Finding" in markdown
        assert "https://example.com/high" in markdown

    def test_executive_summary_template_renders_without_findings(self) -> None:
        """Executive template should render no-finding message."""

        markdown = PdfExporter().render_markdown(make_document(with_data=False), template_name="executive_summary.md.j2")

        assert "No high-priority findings were included in this report." in markdown
        assert "| High | 0 |" in markdown

    def test_technical_report_template_renders_with_data(self) -> None:
        """Technical template should render findings and observations."""

        markdown = PdfExporter().render_markdown(make_document(), template_name="technical_report.md.j2")

        assert "# SABER Technical Report" in markdown
        assert "High Risk Finding" in markdown
        assert "High risk description." in markdown
        assert "high-template" in markdown
        assert "Target uses nginx." in markdown
        assert '"server": "nginx"' in markdown
        assert '"scope": "approved"' in markdown

    def test_technical_report_template_renders_without_data(self) -> None:
        """Technical template should render empty-state messages."""

        markdown = PdfExporter().render_markdown(make_document(with_data=False), template_name="technical_report.md.j2")

        assert "No findings were included in this report." in markdown
        assert "No observations were included in this report." in markdown
        assert '"scope": "approved"' in markdown

    def test_templates_do_not_contain_broken_shell_fence_markers(self) -> None:
        """Templates should not contain accidental shell heredoc artifacts."""

        for template in TEMPLATE_DIR.glob("*.md.j2"):
            text = template.read_text()
            assert "``` id=" not in text
            assert "cat >" not in text
            assert "<<'J2'" not in text
