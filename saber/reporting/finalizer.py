"""Mission report finalization for SABER.

ReportFinalizer bridges persisted mission evidence/findings to the existing
JSON/XLSX/PDF exporters. It is intentionally small and deterministic so the
orchestrator can call it automatically when a mission completes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from saber.models.mission_state import MissionState
from saber.models.session import MissionSession
from saber.reporting.json_exporter import JsonExporter, ReportDocument
from saber.reporting.pdf_exporter import PdfExporter
from saber.reporting.state_report_adapter import MissionStateReportAdapter
from saber.reporting.xlsx_exporter import XlsxExporter


@dataclass(frozen=True)
class ReportArtifact:
    """One exported report artifact."""

    path: str
    report_type: str
    size_bytes: int
    sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "report_type": self.report_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ReportFinalizationResult:
    """Result of final report generation."""

    report_id: str
    artifacts: list[ReportArtifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "errors": self.errors,
        }


class ReportFinalizer:
    """Build and export final reports from persisted findings/observations."""

    def __init__(
        self,
        finding_store: Any,
        output_dir: str | Path = "runs/reports",
        connection: Any | None = None,
        export_pdf: bool = True,
        export_markdown: bool = True,
    ) -> None:
        self.finding_store = finding_store
        self.output_dir = Path(output_dir)
        self.connection = connection or getattr(finding_store, "connection", None)
        self.export_pdf = export_pdf
        self.export_markdown = export_markdown
        self.json_exporter = JsonExporter()
        self.xlsx_exporter = XlsxExporter()
        self.pdf_exporter = PdfExporter()

    def finalize(
        self,
        *,
        session_id: str,
        mission_name: str,
        target: str,
        metadata: dict[str, Any] | None = None,
    ) -> ReportFinalizationResult:
        """Export JSON, XLSX, Markdown, and PDF reports for one mission."""

        report_id = f"report_{uuid4().hex[:12]}"
        session_dir = self.output_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        errors: list[str] = []
        artifacts: list[ReportArtifact] = []

        findings = self.finding_store.list_findings(session_id)
        observations = self.finding_store.list_observations(session_id)

        document = self.json_exporter.build_document(
            report_id=report_id,
            mission_name=mission_name,
            target=target,
            findings=findings,
            observations=observations,
            metadata={
                "session_id": session_id,
                **(metadata or {}),
            },
        )

        export_jobs = self._build_export_jobs(document, session_dir)

        for report_type, path, exporter in export_jobs:
            try:
                exported_path = Path(exporter(path))
                artifact = self._artifact_for_path(
                    path=exported_path,
                    report_type=report_type,
                    metadata={
                        "session_id": session_id,
                        "mission_name": mission_name,
                        "target": target,
                        "report_id": report_id,
                    },
                )
                artifacts.append(artifact)
                self._record_report_artifact(session_id=session_id, artifact=artifact)
            except Exception as exc:
                errors.append(f"{report_type}:{type(exc).__name__}: {exc}")

        return ReportFinalizationResult(
            report_id=report_id,
            artifacts=artifacts,
            errors=errors,
        )

    def finalize_from_state(
        self,
        state: MissionState,
        session: MissionSession,
        reports_dir: str | Path,
    ) -> list[ReportArtifact]:
        """Export reports directly from a mission's final ``MissionState``.

        Mirrors :meth:`finalize` but derives the report document from the
        accumulated ``MissionState`` (via ``MissionStateReportAdapter``) instead
        of the persisted finding/observation stores. Reuses the exact same
        JSON/XLSX/Markdown/PDF exporters and artifact recording. Returns the
        exported artifacts; export failures are skipped best-effort so the JSON
        report is always emitted when possible.
        """

        report_id = f"report_{uuid4().hex[:12]}"
        session_id = state.session_id
        session_dir = Path(reports_dir) / session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        context = MissionStateReportAdapter().build_report_context(state, session)

        findings = [
            {
                "title": vuln.get("title") or "Vulnerability",
                "severity": vuln.get("severity"),
                "description": vuln.get("title") or "Vulnerability identified during the mission.",
                "references": list(vuln.get("evidence_refs") or []),
                "metadata": {
                    "host": vuln.get("host"),
                    "port": vuln.get("port"),
                    "identifier": vuln.get("identifier"),
                    "confirmed": vuln.get("confirmed"),
                },
            }
            for vuln in context["vulns"]
        ]
        observations = [
            {
                "kind": "action",
                "summary": (
                    f"{entry['tool_name']}.{entry['action']} -> "
                    f"{'ok' if entry['success'] else 'failed'}"
                ),
                "source_tool": entry["tool_name"],
                "data": entry,
            }
            for entry in context["timeline"]
        ]

        document = self.json_exporter.build_document(
            report_id=report_id,
            mission_name=session.mission_name,
            target=state.target.value,
            findings=findings,
            observations=observations,
            metadata={
                "session_id": session_id,
                "mission_state": context,
            },
        )

        export_jobs = self._build_export_jobs(document, session_dir)

        artifacts: list[ReportArtifact] = []
        for report_type, path, exporter in export_jobs:
            try:
                exported_path = Path(exporter(path))
            except Exception:
                continue
            artifact = self._artifact_for_path(
                path=exported_path,
                report_type=report_type,
                metadata={
                    "session_id": session_id,
                    "mission_name": session.mission_name,
                    "target": state.target.value,
                    "report_id": report_id,
                    "source": "mission_state",
                },
            )
            artifacts.append(artifact)
            self._record_report_artifact(session_id=session_id, artifact=artifact)

        return artifacts

    def _build_export_jobs(
        self,
        document: ReportDocument,
        session_dir: Path,
    ) -> list[tuple[str, Path, Any]]:
        """Return the ordered (report_type, path, exporter) jobs for a document.

        Single source of truth for the exporter-call pattern shared by
        :meth:`finalize` and :meth:`finalize_from_state`.
        """

        export_jobs: list[tuple[str, Path, Any]] = [
            (
                "json",
                session_dir / "findings.json",
                lambda path: self.json_exporter.export(document, path),
            ),
            (
                "xlsx",
                session_dir / "findings.xlsx",
                lambda path: self.xlsx_exporter.export(document, path),
            ),
        ]

        if self.export_markdown:
            export_jobs.extend(
                [
                    (
                        "markdown",
                        session_dir / "technical_report.md",
                        lambda path: self.pdf_exporter.export_markdown(
                            document,
                            path,
                            template_name="technical_report.md.j2",
                        ),
                    ),
                    (
                        "markdown",
                        session_dir / "executive_summary.md",
                        lambda path: self.pdf_exporter.export_markdown(
                            document,
                            path,
                            template_name="executive_summary.md.j2",
                        ),
                    ),
                ]
            )

        if self.export_pdf:
            export_jobs.extend(
                [
                    (
                        "pdf",
                        session_dir / "technical_report.pdf",
                        lambda path: self.pdf_exporter.export_pdf(
                            document,
                            path,
                            template_name="technical_report.md.j2",
                        ),
                    ),
                    (
                        "pdf",
                        session_dir / "executive_summary.pdf",
                        lambda path: self.pdf_exporter.export_pdf(
                            document,
                            path,
                            template_name="executive_summary.md.j2",
                        ),
                    ),
                ]
            )

        return export_jobs

    @staticmethod
    def _artifact_for_path(
        path: Path, report_type: str, metadata: dict[str, Any]
    ) -> ReportArtifact:
        return ReportArtifact(
            path=str(path),
            report_type=report_type,
            size_bytes=path.stat().st_size,
            sha256=ReportFinalizer._sha256(path),
            metadata=metadata,
        )

    def _record_report_artifact(self, *, session_id: str, artifact: ReportArtifact) -> None:
        """Best-effort insert into report_artifacts table."""

        if self.connection is None:
            return

        try:
            self.connection.execute(
                """
                INSERT INTO report_artifacts (
                    report_id, session_id, report_type, path, sha256,
                    size_bytes, metadata_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    f"artifact_{uuid4().hex[:12]}",
                    session_id,
                    artifact.report_type,
                    artifact.path,
                    artifact.sha256,
                    artifact.size_bytes,
                    self._json(artifact.metadata),
                ),
            )
        except Exception:
            return

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _json(value: Any) -> str:
        import json

        return json.dumps(value, sort_keys=True, default=str)
