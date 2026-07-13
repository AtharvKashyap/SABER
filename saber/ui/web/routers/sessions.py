"""Session web routes for SABER."""

from __future__ import annotations

from collections import Counter
from threading import Thread
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore
from saber.storage.session_store import SessionStore
from saber.ui.cli.run_command import PROFILE_AGENTS, run_cli_mission


router = APIRouter(prefix="/sessions", tags=["sessions"])


class MissionRunRequest(BaseModel):
    """Start mission request from the web UI."""

    target: str = Field(..., min_length=1, max_length=512)
    profile: str = Field(default="recon", min_length=1, max_length=64)
    mission_name: str | None = Field(default=None, max_length=256)
    objective: str | None = Field(default=None, max_length=2048)
    max_steps: int = Field(default=20, ge=1, le=200)
    require_approval: bool = True
    dry_run: bool = False
    agent_mode: str = Field(default="deterministic", pattern="^(deterministic|llm)$")



def _session_store(request: Request) -> SessionStore:
    """Return SessionStore from app state."""

    return request.app.state.session_store


def _finding_store(request: Request) -> FindingStore:
    """Return FindingStore from app state."""

    return request.app.state.finding_store


def _evidence_index(request: Request) -> EvidenceIndex:
    """Return EvidenceIndex from app state."""

    return request.app.state.evidence_index


def _graph_store(request: Request) -> GraphStore:
    """Return GraphStore from app state."""

    return request.app.state.graph_store


@router.get("")
def list_sessions(request: Request, limit: int = 100) -> dict[str, Any]:
    """List mission sessions."""

    sessions = _session_store(request).list_sessions(limit=limit)
    status_counts = Counter(str(session.get("status") or "unknown") for session in sessions)

    return {
        "sessions": sessions,
        "count": len(sessions),
        "status_counts": dict(status_counts),
        "charts": {
            "mission_status": _chart_rows(status_counts, "status"),
        },
    }



@router.post("/run")
def run_mission_from_web(request: Request, run_request: MissionRunRequest) -> dict[str, Any]:
    """Start a SABER mission from the web UI.

    The mission runs in a daemon thread. The response returns immediately with a
    session ID that the UI can poll through existing session/timeline/report APIs.
    """

    profile = run_request.profile.strip().lower()
    if profile not in PROFILE_AGENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported profile: {profile}. Expected one of: {', '.join(sorted(PROFILE_AGENTS))}",
        )

    session_id = f"session_{uuid4().hex[:12]}"
    db_path = str(getattr(request.app.state, "db_path", "runs/saber.db"))
    reports_dir = str(getattr(request.app.state, "reports_dir", "runs/reports"))
    evidence_dir = str(getattr(request.app.state, "evidence_dir", "runs/evidence"))

    kwargs = {
        "session_id": session_id,
        "target_value": run_request.target.strip(),
        "profile": profile,
        "mission_name": run_request.mission_name,
        "objective": run_request.objective,
        "db_path": db_path,
        "evidence_dir": evidence_dir,
        "reports_dir": reports_dir,
        "require_approval": run_request.require_approval,
        "max_steps": run_request.max_steps,
        "dry_run": run_request.dry_run,
        "agent_mode": run_request.agent_mode,
    }

    thread = Thread(target=run_cli_mission, kwargs=kwargs, daemon=True)
    thread.start()

    return {
        "session_id": session_id,
        "status": "started",
        "target": run_request.target.strip(),
        "profile": profile,
        "detail_url": f"/ui/sessions/{session_id}",
        "api_url": f"/sessions/{session_id}",
        "timeline_url": f"/sessions/{session_id}/timeline",
        "reports_url": f"/sessions/{session_id}/reports",
    }


@router.get("/{session_id}")
def get_session_detail(request: Request, session_id: str) -> dict[str, Any]:
    """Return full mission session detail."""

    session_store = _session_store(request)
    finding_store = _finding_store(request)
    evidence_index = _evidence_index(request)

    session = session_store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    steps = session_store.list_steps(session_id)
    records = session_store.list_step_records(session_id)
    approvals = session_store.list_pending_approvals(session_id)
    reports = session_store.list_report_artifacts(session_id)
    findings = finding_store.list_findings(session_id)
    observations = finding_store.list_observations(session_id)
    evidence = evidence_index.list_evidence(session_id)

    severity_counts = Counter(str(finding.get("severity") or "unknown") for finding in findings)
    step_status_counts = Counter(str(step.get("status") or "unknown") for step in steps)
    tool_counts = Counter(
        str(item.get("source_tool") or item.get("tool_name") or "unknown")
        for item in [*findings, *observations, *evidence]
    )

    return {
        "session": session,
        "summary": {
            "step_count": len(steps),
            "record_count": len(records),
            "finding_count": len(findings),
            "observation_count": len(observations),
            "evidence_count": len(evidence),
            "pending_approval_count": len(approvals),
            "report_count": len(reports),
            "severity_counts": _severity_counts_dict(severity_counts),
            "step_status_counts": dict(step_status_counts),
        },
        "steps": steps,
        "records": records,
        "pending_approvals": approvals,
        "findings": findings,
        "observations": observations,
        "evidence": evidence,
        "reports": reports,
        "charts": {
            "severity": _severity_chart(severity_counts),
            "step_status": _chart_rows(step_status_counts, "status"),
            "tools": _chart_rows(tool_counts, "tool"),
        },
    }


@router.get("/{session_id}/steps")
def list_steps(request: Request, session_id: str) -> dict[str, Any]:
    """List execution steps for a session."""

    _ensure_session(request, session_id)
    steps = _session_store(request).list_steps(session_id)
    status_counts = Counter(str(step.get("status") or "unknown") for step in steps)

    return {
        "session_id": session_id,
        "steps": steps,
        "count": len(steps),
        "status_counts": dict(status_counts),
        "charts": {
            "step_status": _chart_rows(status_counts, "status"),
        },
    }


@router.get("/{session_id}/timeline")
def get_timeline(request: Request, session_id: str) -> dict[str, Any]:
    """Return mission timeline from steps, records, approvals, evidence, and reports."""

    _ensure_session(request, session_id)

    session_store = _session_store(request)
    evidence_index = _evidence_index(request)

    steps = session_store.list_steps(session_id)
    records = session_store.list_step_records(session_id)
    approvals = session_store.list_pending_approvals(session_id)
    evidence = evidence_index.list_evidence(session_id)
    reports = session_store.list_report_artifacts(session_id)

    events: list[dict[str, Any]] = []

    for step in steps:
        events.append(
            {
                "type": "step",
                "timestamp": step.get("updated_at") or step.get("created_at"),
                "label": f"{step.get('agent_name')} {step.get('status')}",
                "data": step,
            }
        )

    for record in records:
        events.append(
            {
                "type": "step_record",
                "timestamp": record.get("created_at"),
                "label": f"{record.get('agent_name')} record {record.get('status')}",
                "data": record,
            }
        )

    for approval in approvals:
        events.append(
            {
                "type": "approval",
                "timestamp": approval.get("requested_at"),
                "label": f"Approval pending for {approval.get('step_id')}",
                "data": approval,
            }
        )

    for item in evidence:
        events.append(
            {
                "type": "evidence",
                "timestamp": item.get("created_at"),
                "label": f"Evidence saved: {item.get('title')}",
                "data": item,
            }
        )

    for report in reports:
        events.append(
            {
                "type": "report",
                "timestamp": report.get("created_at"),
                "label": f"Report generated: {report.get('report_type')}",
                "data": report,
            }
        )

    events.sort(key=lambda event: str(event.get("timestamp") or ""))

    return {
        "session_id": session_id,
        "events": events,
        "count": len(events),
    }


@router.get("/{session_id}/approvals")
def list_session_approvals(request: Request, session_id: str) -> dict[str, Any]:
    """List pending approvals for a session."""

    _ensure_session(request, session_id)
    approvals = _session_store(request).list_pending_approvals(session_id)

    return {
        "session_id": session_id,
        "pending_approvals": approvals,
        "count": len(approvals),
    }


@router.get("/{session_id}/evidence")
def list_session_evidence(request: Request, session_id: str) -> dict[str, Any]:
    """List evidence for a session."""

    _ensure_session(request, session_id)
    evidence = _evidence_index(request).list_evidence(session_id)

    return {
        "session_id": session_id,
        "evidence": evidence,
        "count": len(evidence),
    }


@router.get("/{session_id}/graph")
def get_session_graph(request: Request, session_id: str) -> dict[str, Any]:
    """Return AD graph data for a session."""

    _ensure_session(request, session_id)

    graph_store = _graph_store(request)
    nodes = graph_store.list_nodes(session_id)
    edges = graph_store.list_edges(session_id)
    attack_paths = graph_store.list_attack_paths(session_id)

    node_kind_counts = Counter(str(node.get("kind") or "unknown") for node in nodes)
    relationship_counts = Counter(str(edge.get("relationship") or "unknown") for edge in edges)
    target_counts = Counter(str(path.get("target") or "unknown") for path in attack_paths)

    return {
        "session_id": session_id,
        "nodes": nodes,
        "edges": edges,
        "attack_paths": attack_paths,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "attack_path_count": len(attack_paths),
            "node_kind_counts": dict(node_kind_counts),
            "relationship_counts": dict(relationship_counts),
            "attack_path_target_counts": dict(target_counts),
        },
        "charts": {
            "nodes_by_kind": _chart_rows(node_kind_counts, "kind"),
            "edges_by_relationship": _chart_rows(relationship_counts, "relationship"),
            "attack_paths_by_target": _chart_rows(target_counts, "target"),
        },
    }


@router.get("/{session_id}/charts/severity")
def get_severity_chart(request: Request, session_id: str) -> dict[str, Any]:
    """Return finding severity chart data."""

    _ensure_session(request, session_id)
    findings = _finding_store(request).list_findings(session_id)
    counts = Counter(str(finding.get("severity") or "unknown") for finding in findings)

    return {
        "session_id": session_id,
        "chart_type": "bar",
        "title": "Findings by Severity",
        "data": _severity_chart(counts),
    }


@router.get("/{session_id}/charts/steps")
def get_step_status_chart(request: Request, session_id: str) -> dict[str, Any]:
    """Return step status chart data."""

    _ensure_session(request, session_id)
    steps = _session_store(request).list_steps(session_id)
    counts = Counter(str(step.get("status") or "unknown") for step in steps)

    return {
        "session_id": session_id,
        "chart_type": "bar",
        "title": "Steps by Status",
        "data": _chart_rows(counts, "status"),
    }


@router.get("/{session_id}/charts/tools")
def get_tool_chart(request: Request, session_id: str) -> dict[str, Any]:
    """Return source-tool chart data."""

    _ensure_session(request, session_id)
    finding_store = _finding_store(request)
    evidence_index = _evidence_index(request)

    findings = finding_store.list_findings(session_id)
    observations = finding_store.list_observations(session_id)
    evidence = evidence_index.list_evidence(session_id)

    counts = Counter(
        str(item.get("source_tool") or item.get("tool_name") or "unknown")
        for item in [*findings, *observations, *evidence]
    )

    return {
        "session_id": session_id,
        "chart_type": "bar",
        "title": "Evidence and Findings by Tool",
        "data": _chart_rows(counts, "tool"),
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
