"""GUI endpoints for live MissionState.

Exposes the accumulating working-memory snapshot (hosts, services,
technologies, vulns, hypotheses, and the attempted-action timeline) that the
agentic mission loop persists per session. The mission-detail page polls this
endpoint to render a live view alongside the existing progress poll.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from saber.storage.mission_state_store import MissionStateStore

router = APIRouter(prefix="/api/sessions", tags=["mission-state"])


def _mission_state_store(request: Request) -> MissionStateStore:
    """Return the MissionStateStore from app state."""

    return request.app.state.mission_state_store


@router.get("/{session_id}/state")
def get_mission_state(request: Request, session_id: str) -> dict[str, Any]:
    """Return the live MissionState snapshot for a session.

    Raises:
        HTTPException: 404 when no MissionState snapshot is stored for the session.
    """

    state = _mission_state_store(request).load(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Mission state not found: {session_id}")

    return {
        "summary": state.to_summary_dict(),
        "hosts": [host.model_dump() for host in state.hosts],
        "services": [service.model_dump() for service in state.services],
        "technologies": [technology.model_dump() for technology in state.technologies],
        "vulns": [vuln.model_dump() for vuln in state.vulns],
        "hypotheses": [hypothesis.model_dump() for hypothesis in state.hypotheses],
        "timeline": [
            {
                "tool_name": action.tool_name,
                "action": action.action,
                "success": action.success,
                "reason": action.reason,
            }
            for action in state.attempted_actions
        ],
    }
