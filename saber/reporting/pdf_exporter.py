"""PDF and Markdown report exporter for SABER."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from saber.reporting.json_exporter import ReportDocument, ReportFinding, SEVERITY_ORDER


class PdfExporter:
    """Render SABER report documents to Markdown and PDF."""

    def __init__(self, template_dir: str | Path | None = None) -> None:
        """Initialize exporter."""

        self.template_dir = Path(template_dir) if template_dir else Path(__file__).parent / "templates"
        self.environment = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(default_for_string=False, default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.environment.filters["tojson_pretty"] = self._tojson_pretty

    def render_markdown(
        self,
        document: ReportDocument,
        template_name: str = "technical_report.md.j2",
    ) -> str:
        """Render report document to Markdown."""

        template = self.environment.get_template(template_name)
        findings = sorted(document.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
        priority_findings = self._priority_findings(document)

        # Pass the MissionState context through. Without it the human-readable report
        # rendered only findings + a raw tool-call timeline, so a mission that had
        # discovered hosts, services and technologies still printed "No reportable
        # findings" with an all-zero severity table — while the methodology, attack
        # chain and recon inventory sat unused in document.metadata. The report is the
        # deliverable a client reads; it has to show what the mission actually learned.
        mission_state = (document.metadata or {}).get("mission_state") or {}

        return template.render(
            document=document,
            severity_counts=document.severity_counts(),
            findings=findings,
            observations=document.observations,
            priority_findings=priority_findings,
            mission_state=mission_state,
            methodology=mission_state.get("methodology") or [],
            attack_chain=mission_state.get("attack_chain") or [],
            hosts=mission_state.get("hosts") or [],
            services=mission_state.get("services") or [],
            technologies=mission_state.get("technologies") or [],
            access=mission_state.get("access") or {},
            collected=mission_state.get("collected") or {},
        ).strip() + "\n"

    def export_markdown(
        self,
        document: ReportDocument,
        output_path: str | Path,
        template_name: str = "technical_report.md.j2",
    ) -> Path:
        """Write rendered Markdown report."""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render_markdown(document, template_name), encoding="utf-8")
        return path

    def export_pdf(
        self,
        document: ReportDocument,
        output_path: str | Path,
        template_name: str = "technical_report.md.j2",
    ) -> Path:
        """Write rendered PDF report.

        This uses ReportLab when installed. Markdown export is always supported.
        """

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
        except ImportError as exc:
            raise RuntimeError(
                "PDF export requires reportlab. Install it or use export_markdown() instead."
            ) from exc

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        markdown = self.render_markdown(document, template_name)
        styles = getSampleStyleSheet()
        story = []

        for line in markdown.splitlines():
            stripped = line.strip()

            if not stripped:
                story.append(Spacer(1, 8))
                continue

            if stripped.startswith("# "):
                story.append(Paragraph(self._escape_xml(stripped[2:]), styles["Title"]))
            elif stripped.startswith("## "):
                story.append(Paragraph(self._escape_xml(stripped[3:]), styles["Heading2"]))
            elif stripped.startswith("### "):
                story.append(Paragraph(self._escape_xml(stripped[4:]), styles["Heading3"]))
            elif stripped.startswith("#### "):
                story.append(Paragraph(self._escape_xml(stripped[5:]), styles["Heading4"]))
            elif stripped.startswith("- "):
                story.append(Paragraph("• " + self._escape_xml(stripped[2:]), styles["BodyText"]))
            elif stripped.startswith("|"):
                story.append(Paragraph(self._escape_xml(stripped), styles["Code"]))
            else:
                story.append(Paragraph(self._inline_markdown_to_reportlab(stripped), styles["BodyText"]))

        pdf = SimpleDocTemplate(str(path), pagesize=letter)
        pdf.build(story)
        return path

    @staticmethod
    def _priority_findings(document: ReportDocument, limit: int = 5) -> list[ReportFinding]:
        """Return high-priority findings for executive summary."""

        return sorted(document.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])[:limit]

    @staticmethod
    def _tojson_pretty(value: Any) -> str:
        """Jinja filter for pretty JSON."""

        return json.dumps(value, indent=2, sort_keys=True, default=str)

    @classmethod
    def _inline_markdown_to_reportlab(cls, text: str) -> str:
        """Convert very small subset of inline Markdown to ReportLab-safe text."""

        escaped = cls._escape_xml(text)
        escaped = escaped.replace("**", "<b>", 1).replace("**", "</b>", 1)
        return escaped

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape text for ReportLab Paragraph."""

        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
