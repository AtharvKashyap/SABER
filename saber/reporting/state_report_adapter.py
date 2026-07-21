"""Adapt a final MissionState into a report context."""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import MissionState
from saber.models.session import MissionSession


class MissionStateReportAdapter:
    """Build an evidence-backed report context from final MissionState."""

    def build_report_context(self, state: MissionState, session: MissionSession) -> dict[str, Any]:
        """Return a JSON-compatible report context."""

        return {
            "summary": state.to_summary_dict(),
            "session": session.to_summary_dict(),
            "hosts": [h.model_dump() for h in state.hosts],
            "services": [s.model_dump() for s in state.services],
            "technologies": [t.model_dump() for t in state.technologies],
            "credentials": [
                {
                    **c.model_dump(exclude={"secret"}),
                    "secret": ("***redacted***" if c.secret else None),
                }
                for c in state.credentials
            ],
            "vulns": [v.model_dump() for v in state.vulns],
            "hypotheses": [h.model_dump() for h in state.hypotheses],
            "timeline": [
                {
                    "tool_name": a.tool_name,
                    "action": a.action,
                    "success": a.success,
                    "reason": a.reason,
                    "at": a.at.isoformat(),
                }
                for a in state.attempted_actions
            ],
            "evidence_refs": state.evidence_refs,
            "finding_refs": state.finding_refs,
            "stop_reason": state.stop_reason,
        }
