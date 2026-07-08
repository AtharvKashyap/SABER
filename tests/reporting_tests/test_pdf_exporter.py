"""Tests for PDF and Markdown exporter."""

from __future__ import annotations

import pytest

from saber.reporting.json_exporter import (
    ReportDocument,
    ReportFinding,
    ReportObservation,
    ReportSeverity,
)
from saber.reporting.pdf_exporter import PdfExporter


def make_document() -> ReportDocument:
    """Create report document."""

    return ReportDocument(
        report_id="report_pdf_test",
        mission_name="PDF Mission",
        target="example.com",
        generated_at=__import__("datetime").datetime(2026, 1, 1, 12, 0, 0, tzinfo=__import__("datetime").UTC),
        executive_summary="PDF summary.",
        observations=[
            ReportObservation(
                kind="service",
                summary="Port 443 is open.",
                source_tool="nmap",
                data={"host": "10.0.0.5", "port": 443},
                metadata={"format": "xml"},
            )
        ],
        findings=[
            ReportFinding(
                title="Critical Finding",
                severity=ReportSeverity.CRITICAL,
                description="Critical description.",
                source_tool="nuclei",
                evidence={"template_id": "critical-template"},
                references=["https://example.com/critical"],
                metadata={"tag": "critical"},
            ),
            ReportFinding(
                title="Low Finding",
                severity=ReportSeverity.LOW,
                description="Low description.",
                source_tool="nuclei",
                evidence={"template_id": "low-template"},
                references=[],
                metadata={},
            ),
        ],
        metadata={"owner": "unit-test"},
    )


class TestPdfExporter:
    """Validate PdfExporter."""

    def test_render_markdown_technical_report(self) -> None:
        """Technical report template should render markdown."""

        exporter = PdfExporter()
        markdown = exporter.render_markdown(make_document())

        assert "# SABER Technical Report" in markdown
        assert "**Mission:** PDF Mission" in markdown
        assert "**Target:** example.com" in markdown
        assert "**Report ID:** report_pdf_test" in markdown
        assert "## Findings" in markdown
        assert "Critical Finding" in markdown
        assert "Low Finding" in markdown
        assert "critical-template" in markdown
        assert "## Observations" in markdown
        assert "Port 443 is open." in markdown
        assert "## Report Metadata" in markdown
        assert '"owner": "unit-test"' in markdown

    def test_render_markdown_executive_summary(self) -> None:
        """Executive summary template should render markdown."""

        exporter = PdfExporter()
        markdown = exporter.render_markdown(make_document(), template_name="executive_summary.md.j2")

        assert "# Executive Summary" in markdown
        assert "**Mission:** PDF Mission" in markdown
        assert "## Finding Summary" in markdown
        assert "| Critical | 1 |" in markdown
        assert "## Highest Priority Findings" in markdown
        assert "Critical Finding" in markdown

    def test_findings_sorted_by_severity_in_render(self) -> None:
        """Findings should be sorted by severity in technical report."""

        exporter = PdfExporter()
        markdown = exporter.render_markdown(make_document())

        critical_index = markdown.index("Critical Finding")
        low_index = markdown.index("Low Finding")

        assert critical_index < low_index

    def test_export_markdown(self, tmp_path) -> None:
        """Markdown export should write file."""

        exporter = PdfExporter()
        output_path = tmp_path / "report.md"

        returned = exporter.export_markdown(make_document(), output_path)

        assert returned == output_path
        assert output_path.exists()
        assert "# SABER Technical Report" in output_path.read_text()

    def test_export_pdf(self, tmp_path) -> None:
        """PDF export should write non-empty PDF when reportlab is available."""

        pytest.importorskip("reportlab")

        exporter = PdfExporter()
        output_path = tmp_path / "report.pdf"

        returned = exporter.export_pdf(make_document(), output_path)

        assert returned == output_path
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_missing_template_raises(self) -> None:
        """Missing template should raise."""

        exporter = PdfExporter()

        with pytest.raises(Exception):
            exporter.render_markdown(make_document(), template_name="missing.md.j2")

    def test_custom_template_dir(self, tmp_path) -> None:
        """Exporter should support custom template directory."""

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "custom.md.j2").write_text("Mission={{ document.mission_name }}")

        exporter = PdfExporter(template_dir=template_dir)
        markdown = exporter.render_markdown(make_document(), template_name="custom.md.j2")

        assert markdown == "Mission=PDF Mission\n"

    def test_tojson_pretty_filter(self) -> None:
        """JSON filter should pretty print."""

        rendered = PdfExporter._tojson_pretty({"b": 2, "a": 1})

        assert rendered.splitlines()[0] == "{"
        assert '  "a": 1' in rendered
        assert '  "b": 2' in rendered

    def test_escape_xml(self) -> None:
        """XML escaping should escape unsafe characters."""

        assert PdfExporter._escape_xml("<a&b>") == "&lt;a&amp;b&gt;"
