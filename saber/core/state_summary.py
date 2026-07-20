"""Token-bounded summary of MissionState for the decider prompt."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.models.mission_state import MissionState

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class StateSummary:
    """Compact, prioritized view of MissionState for the decider."""

    objective: str
    target: dict[str, Any]
    autonomy_level: str
    counts: dict[str, int]
    services: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    recent_failures: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible payload for the LLM."""

        return {
            "objective": self.objective,
            "target": self.target,
            "autonomy_level": self.autonomy_level,
            "counts": self.counts,
            "services": self.services,
            "technologies": self.technologies,
            "credentials": self.credentials,
            "vulns": self.vulns,
            "hypotheses": self.hypotheses,
            "recent_failures": self.recent_failures,
        }


class StateSummarizer:
    """Build a bounded StateSummary from MissionState."""

    def __init__(self, max_items: int = 20) -> None:
        """Initialize summarizer."""

        self.max_items = max_items

    def summarize(self, state: MissionState) -> StateSummary:
        """Return a prioritized, capped summary."""

        open_services = [svc for svc in state.services if svc.state == "open"]
        credentials_sorted = sorted(state.credentials, key=lambda c: not c.validated)
        vulns_sorted = sorted(
            state.vulns, key=lambda v: (v.confirmed, _SEVERITY_RANK.get(v.severity, 5))
        )
        open_hypotheses = [h for h in state.hypotheses if h.status == "open"]

        return StateSummary(
            objective=state.objective,
            target=state.target.to_agent_dict(),
            autonomy_level=state.autonomy_level.value,
            counts=state.to_summary_dict()["counts"],
            services=[svc.model_dump() for svc in open_services[: self.max_items]],
            technologies=[t.model_dump() for t in state.technologies[: self.max_items]],
            credentials=[
                c.model_dump(exclude={"secret"}) for c in credentials_sorted[: self.max_items]
            ],
            vulns=[v.model_dump() for v in vulns_sorted[: self.max_items]],
            hypotheses=[h.model_dump() for h in open_hypotheses[: self.max_items]],
            recent_failures=[
                {"tool_name": a.tool_name, "action": a.action, "reason": a.reason}
                for a in state.failed_actions[-self.max_items :]
            ],
        )
