"""Report finalizer tests."""

from __future__ import annotations

import json
from pathlib import Path

from saber.core.result_processor import ResultProcessor
from saber.models.session import MissionSession
from saber.orchestration.mission_orchestrator import MissionArtifact, MissionRunResult, MissionRunStatus, MissionOrchestrator
from saber.reporting.finalizer import ReportFinalizer
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.tools.registry import ToolRegistry


class NoopPlan:
    def to_dict(self):
        return {"plan": "noop"}


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


def test_orchestrator_finalize_auto_exports_reports(tmp_path) -> None:
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
    processor._ensure_session_exists("auto_report_session")

    store.save_finding(
        session_id="auto_report_session",
        step_id="step1",
        finding={
            "title": "Open service discovered: 127.0.0.1:111/tcp",
            "severity": "info",
            "description": "RPC service was discovered.",
            "source_tool": "nmap",
            "evidence": {"host": "127.0.0.1", "port": 111, "service": "rpcbind"},
            "references": [],
            "metadata": {"finding_type": "open_service"},
        },
    )

    finalizer = ReportFinalizer(
        finding_store=store,
        output_dir=reports_dir,
        connection=connection,
    )

    orchestrator = MissionOrchestrator(
        agents={"noop": object()},
        tool_registry=ToolRegistry(),
        sandbox=object(),
        step_runner=object(),
        chain_runner=object(),
        result_processor=processor,
        report_finalizer=finalizer,
        reports_dir=reports_dir,
    )

    result = MissionRunResult(
        session=MissionSession(
            session_id="auto_report_session",
            mission_name="Auto Report Test",
        ),
        plan=NoopPlan(),
        status=MissionRunStatus.COMPLETED,
        observations=[],
        records=[],
        metadata={"target": "127.0.0.1"},
        artifacts=[],
    )

    finalized = orchestrator._finalize_result(result)

    kinds = {artifact.kind for artifact in finalized.artifacts}
    assert "report_json" in kinds
    assert "report_xlsx" in kinds
    assert "report_markdown" in kinds
    assert "mission_result_json" in kinds

    assert (reports_dir / "auto_report_session" / "findings.json").exists()
    assert (reports_dir / "auto_report_session" / "findings.xlsx").exists()
    assert (reports_dir / "auto_report_session" / "mission_result.json").exists()

    connection.close()
