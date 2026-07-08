"""Finding web routes for SABER."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from saber.storage.finding_store import FindingStore
from saber.storage.session_store import SessionStore


router = APIRouter(tags=["findings"])


class FindingStatusUpdate(BaseModel):
    """Finding status update request."""

    status: str = Field(..., min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _finding_store(request: Request) -> FindingStore:
    """Return FindingStore from app state."""

    return request.app.state.finding_store


def _session_store(request: Request) -> SessionStore:
    """Return SessionStore from app state."""

    return request.app.state.session_store


@router.get("/findings")
def list_all_findings(
    request: Request,
    session_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """List findings.

    If session_id is omitted, findings are collected across known sessions.
    """

    finding_store = _finding_store(request)
    session_store = _session_store(request)

    if session_id:
        _ensure_session(request, session_id)
        findings = finding_store.list_findings(session_id, severity=severity, status=status)
    else:
        findings = []
        for session in session_store.list_sessions(limit=1000):
            findings.extend(
                finding_store.list_findings(
                    session["session_id"],
                    severity=severity,
                    status=status,
                )
            )

    severity_counts = Counter(str(finding.get("severity") or "unknown") for finding in findings)
    status_counts = Counter(str(finding.get("status") or "unknown") for finding in findings)
    source_counts = Counter(str(finding.get("source_tool") or "unknown") for finding in findings)

    return {
        "findings": findings,
        "count": len(findings),
        "summary": {
            "severity_counts": _severity_counts_dict(severity_counts),
            "status_counts": dict(status_counts),
            "source_tool_counts": dict(source_counts),
        },
        "charts": {
            "severity": _severity_chart(severity_counts),
            "status": _chart_rows(status_counts, "status"),
            "source_tools": _chart_rows(source_counts, "source_tool"),
        },
    }


@router.get("/findings/{finding_id}")
def get_finding(request: Request, finding_id: str) -> dict[str, Any]:
    """Get one finding."""

    finding = _finding_store(request).get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    return {"finding": finding}


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    request: Request,
    finding_id: str,
    update: FindingStatusUpdate,
) -> dict[str, Any]:
    """Update finding status."""

    finding_store = _finding_store(request)

    try:
        finding_store.update_finding_status(
            finding_id=finding_id,
            status=update.status,
            metadata=update.metadata,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    finding = finding_store.get_finding(finding_id)
    return {"finding": finding}


@router.get("/sessions/{session_id}/findings")
def list_session_findings(
    request: Request,
    session_id: str,
    severity: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """List findings for one session."""

    _ensure_session(request, session_id)

    findings = _finding_store(request).list_findings(
        session_id,
        severity=severity,
        status=status,
    )

    severity_counts = Counter(str(finding.get("severity") or "unknown") for finding in findings)
    status_counts = Counter(str(finding.get("status") or "unknown") for finding in findings)
    source_counts = Counter(str(finding.get("source_tool") or "unknown") for finding in findings)

    return {
        "session_id": session_id,
        "findings": findings,
        "count": len(findings),
        "summary": {
            "severity_counts": _severity_counts_dict(severity_counts),
            "status_counts": dict(status_counts),
            "source_tool_counts": dict(source_counts),
        },
        "charts": {
            "severity": _severity_chart(severity_counts),
            "status": _chart_rows(status_counts, "status"),
            "source_tools": _chart_rows(source_counts, "source_tool"),
        },
    }


@router.get("/sessions/{session_id}/observations")
def list_session_observations(
    request: Request,
    session_id: str,
    kind: str | None = None,
    source_tool: str | None = None,
) -> dict[str, Any]:
    """List observations for one session."""

    _ensure_session(request, session_id)

    observations = _finding_store(request).list_observations(
        session_id,
        kind=kind,
        source_tool=source_tool,
    )

    kind_counts = Counter(str(observation.get("kind") or "unknown") for observation in observations)
    source_counts = Counter(str(observation.get("source_tool") or "unknown") for observation in observations)

    return {
        "session_id": session_id,
        "observations": observations,
        "count": len(observations),
        "summary": {
            "kind_counts": dict(kind_counts),
            "source_tool_counts": dict(source_counts),
        },
        "charts": {
            "kinds": _chart_rows(kind_counts, "kind"),
            "source_tools": _chart_rows(source_counts, "source_tool"),
        },
    }


def _ensure_session(request: Request, session_id: str) -> dict[str, Any]:
    """Raise 404 when session does not exist."""

    session = _session_store(request).get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")
    return session


def _severity_counts_dict(counts: Counter[str]) -> dict[str, int]:
    """Return severity counts with stable keys."""

    return {
        severity: counts.get(severity, 0)
        for severity in ("critical", "high", "medium", "low", "info", "unknown")
    }


def _severity_chart(counts: Counter[str]) -> list[dict[str, Any]]:
    """Return severity chart rows in stable order."""

    return [
        {"severity": severity, "count": counts.get(severity, 0)}
        for severity in ("critical", "high", "medium", "low", "info", "unknown")
    ]


def _chart_rows(counts: Counter[str], key: str) -> list[dict[str, Any]]:
    """Return generic chart rows."""

    return [
        {key: name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
