"""Report finalizer tests."""

from __future__ import annotations

import json

from saber.core.result_processor import ResultProcessor
from saber.reporting.finalizer import ReportFinalizer
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore


def test_report_finalizer_exports_json_xlsx_markdown_and_pdf_or_error(tmp_path) -> None:
    db_path = tmp_path / "saber.db"
    reports_dir = tmp_path / "reports"

    connection = StorageConnection(db_path)
    connection.initialize()

    store = FindingStore(connection)
    processor = ResultProcessor(
        evidence_index=EvidenceIndex(connection),
        finding_store=store,
        graph_store=GraphStore(connection),
        evidence_root=tmp_path / "evidence",
    )

    processor._ensure_session_exists("report_session")

    store.save_observation(
        session_id="report_session",
        step_id="step1",
        observation={
            "kind": "service",
            "summary": "Open HTTP service observed.",
            "source_tool": "nmap",
            "data": {"host": "127.0.0.1", "port": 80, "service": "http"},
            "metadata": {},
        },
    )

    store.save_finding(
        session_id="report_session",
        step_id="step1",
        finding={
            "title": "Open service discovered: 127.0.0.1:80/tcp",
            "severity": "info",
            "description": "HTTP service was discovered.",
            "source_tool": "nmap",
            "evidence": {"host": "127.0.0.1", "port": 80, "service": "http"},
            "references": [],
            "metadata": {"finding_type": "open_service"},
        },
    )

    finalizer = ReportFinalizer(
        finding_store=store,
        output_dir=reports_dir,
        connection=connection,
    )

    result = finalizer.finalize(
        session_id="report_session",
        mission_name="Report Test",
        target="127.0.0.1",
    )

    artifact_types = {artifact.report_type for artifact in result.artifacts}

    assert "json" in artifact_types
    assert "xlsx" in artifact_types
    assert "markdown" in artifact_types

    json_path = reports_dir / "report_session" / "findings.json"
    xlsx_path = reports_dir / "report_session" / "findings.xlsx"
    tech_md_path = reports_dir / "report_session" / "technical_report.md"
    exec_md_path = reports_dir / "report_session" / "executive_summary.md"

    assert json_path.exists()
    assert xlsx_path.exists()
    assert tech_md_path.exists()
    assert exec_md_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["finding_count"] == 1
    assert data["observation_count"] == 1
    assert data["findings"][0]["title"].startswith("Open service discovered")

    # PDF should exist when reportlab is installed; otherwise finalizer reports a non-fatal error.
    pdf_paths = [
        reports_dir / "report_session" / "technical_report.pdf",
        reports_dir / "report_session" / "executive_summary.pdf",
    ]
    assert any(path.exists() for path in pdf_paths) or result.errors

    connection.close()
