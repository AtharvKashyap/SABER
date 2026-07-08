"""Report web routes for SABER."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from saber.reporting.json_exporter import JsonExporter
from saber.reporting.pdf_exporter import PdfExporter
from saber.reporting.xlsx_exporter import XlsxExporter
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.session_store import SessionStore


router = APIRouter(tags=["reports"])


class ReportGenerateRequest(BaseModel):
    """Report generation request."""

    format: str = Field(..., pattern="^(json|xlsx|pdf|markdown)$")
    target: str = Field(default="unknown", max_length=512)
    mission_name: str | None = Field(default=None, max_length=256)


def _session_store(request: Request) -> SessionStore:
    """Return SessionStore from app state."""

    return request.app.state.session_store


def _finding_store(request: Request) -> FindingStore:
    """Return FindingStore from app state."""

    return request.app.state.finding_store


def _evidence_index(request: Request) -> EvidenceIndex:
    """Return EvidenceIndex from app state."""

    return request.app.state.evidence_index


def _reports_root(request: Request) -> Path:
    """Return safe reports root."""

    return Path(request.app.state.reports_dir).resolve()


@router.get("/reports")
def list_all_reports(request: Request) -> dict[str, Any]:
    """List reports across sessions."""

    session_store = _session_store(request)
    reports: list[dict[str, Any]] = []

    for session in session_store.list_sessions(limit=1000):
        reports.extend(session_store.list_report_artifacts(session["session_id"]))

    return {
        "reports": reports,
        "count": len(reports),
    }


@router.get("/sessions/{session_id}/reports")
def list_session_reports(request: Request, session_id: str) -> dict[str, Any]:
    """List reports for one session."""

    _ensure_session(request, session_id)
    reports = _session_store(request).list_report_artifacts(session_id)

    return {
        "session_id": session_id,
        "reports": reports,
        "count": len(reports),
    }


@router.post("/sessions/{session_id}/reports/generate")
def generate_report(
    request: Request,
    session_id: str,
    generate_request: ReportGenerateRequest,
) -> dict[str, Any]:
    """Generate a report artifact for a session.

    Output path is server-controlled to prevent arbitrary file write/path traversal.
    """

    session_store = _session_store(request)
    finding_store = _finding_store(request)
    evidence_index = _evidence_index(request)

    session = _ensure_session(request, session_id)
    findings = finding_store.list_findings(session_id)
    observations = finding_store.list_observations(session_id)
    evidence = evidence_index.list_evidence(session_id)

    mission_name = generate_request.mission_name or session.get("mission_name") or session_id

    document = JsonExporter().build_document(
        mission_name=mission_name,
        target=generate_request.target,
        observations=observations,
        findings=findings,
        metadata={
            "session": session,
            "evidence": evidence,
        },
    )

    suffix = "md" if generate_request.format == "markdown" else generate_request.format
    output_path = _safe_report_path(
        root=_reports_root(request),
        session_id=session_id,
        suffix=suffix,
    )

    if generate_request.format == "json":
        path = JsonExporter().export(document, output_path)
    elif generate_request.format == "xlsx":
        path = XlsxExporter().export(document, output_path)
    elif generate_request.format == "pdf":
        path = PdfExporter().export_pdf(document, output_path)
    elif generate_request.format == "markdown":
        path = PdfExporter().export_markdown(document, output_path)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported report format: {generate_request.format}")

    artifact_id = session_store.save_report_artifact(
        session_id=session_id,
        report_type=generate_request.format,
        path=path,
        metadata={"generated_by": "saber-web"},
    )

    artifact = next(
        (
            item
            for item in session_store.list_report_artifacts(session_id)
            if item.get("report_id") == artifact_id
        ),
        None,
    )

    return {
        "session_id": session_id,
        "report_id": artifact_id,
        "path": str(path),
        "artifact": artifact,
    }


@router.get("/reports/{report_id}")
def get_report_artifact(request: Request, report_id: str) -> dict[str, Any]:
    """Get one report artifact by ID."""

    session_store = _session_store(request)

    for session in session_store.list_sessions(limit=1000):
        for artifact in session_store.list_report_artifacts(session["session_id"]):
            if artifact.get("report_id") == report_id:
                _safe_existing_file(_reports_root(request), Path(str(artifact.get("path"))))
                return {"report": artifact}

    raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")


@router.get("/reports/{report_id}/download")
def download_report_artifact(request: Request, report_id: str) -> FileResponse:
    """Download a report artifact by ID."""

    report = get_report_artifact(request, report_id)["report"]
    path = _safe_existing_file(_reports_root(request), Path(str(report.get("path"))))

    return FileResponse(
        path=path,
        filename=path.name,
        media_type=_media_type(report.get("report_type")),
    )


def _ensure_session(request: Request, session_id: str) -> dict[str, Any]:
    """Raise 404 when session does not exist."""

    session = _session_store(request).get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    return session


def _safe_report_path(root: Path, session_id: str, suffix: str) -> Path:
    """Build a safe server-controlled report path."""

    safe_session_id = "".join(character if character.isalnum() or character in {"_", "-"} else "_" for character in session_id)
    safe_suffix = "".join(character for character in suffix.lower() if character.isalnum())

    if not safe_session_id:
        raise HTTPException(status_code=400, detail="Invalid session ID.")
    if safe_suffix not in {"json", "xlsx", "pdf", "md"}:
        raise HTTPException(status_code=400, detail="Invalid report suffix.")

    path = (root / f"{safe_session_id}_report.{safe_suffix}").resolve()
    _ensure_under_root(root, path)
    return path


def _safe_existing_file(root: Path, path: Path) -> Path:
    """Resolve and validate existing report path."""

    resolved = path.resolve()
    _ensure_under_root(root, resolved)

    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail=f"Report file not found: {resolved.name}")

    return resolved


def _ensure_under_root(root: Path, path: Path) -> None:
    """Ensure path is inside root."""

    try:
        path.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Report path is outside the configured reports directory.") from exc


def _media_type(report_type: str | None) -> str:
    """Return response media type for report type."""

    mapping = {
        "json": "application/json",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pdf": "application/pdf",
        "markdown": "text/markdown",
    }
    return mapping.get(str(report_type), "application/octet-stream")
