"""Live mission status panel for SABER CLI."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.session_store import SessionStore


@dataclass(frozen=True)
class LivePanelSnapshot:
    """One mission status snapshot."""

    session: dict[str, Any] | None
    steps: list[dict[str, Any]]
    records: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    approvals: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible snapshot."""

        return {
            "session": self.session,
            "steps": self.steps,
            "records": self.records,
            "findings": self.findings,
            "observations": self.observations,
            "evidence": self.evidence,
            "approvals": self.approvals,
        }


class LivePanel:
    """Render live terminal mission status."""

    def __init__(
        self,
        session_store: SessionStore,
        finding_store: FindingStore,
        evidence_index: EvidenceIndex,
    ) -> None:
        """Initialize panel."""

        self.session_store = session_store
        self.finding_store = finding_store
        self.evidence_index = evidence_index

    def snapshot(self, session_id: str) -> LivePanelSnapshot:
        """Build one snapshot from storage."""

        return LivePanelSnapshot(
            session=self.session_store.get_session(session_id),
            steps=self.session_store.list_steps(session_id),
            records=self.session_store.list_step_records(session_id),
            findings=self.finding_store.list_findings(session_id),
            observations=self.finding_store.list_observations(session_id),
            evidence=self.evidence_index.list_evidence(session_id),
            approvals=self.session_store.list_pending_approvals(session_id),
        )

    def render(self, session_id: str) -> str:
        """Render one snapshot."""

        snapshot = self.snapshot(session_id)
        session = snapshot.session or {}

        lines = [
            "SABER Live Mission Panel",
            "",
            f"Session: {session.get('session_id', session_id)}",
            f"Mission: {session.get('mission_name', 'unknown')}",
            f"Status:  {session.get('status', 'unknown')}",
            "",
            "Counts:",
            f"  Steps:        {len(snapshot.steps)}",
            f"  Records:      {len(snapshot.records)}",
            f"  Findings:     {len(snapshot.findings)}",
            f"  Observations: {len(snapshot.observations)}",
            f"  Evidence:     {len(snapshot.evidence)}",
            f"  Approvals:    {len(snapshot.approvals)}",
            "",
            "Step Status:",
        ]

        if snapshot.steps:
            for step in snapshot.steps:
                lines.append(
                    f"  {step.get('step_id', ''):<20} "
                    f"{step.get('agent_name', ''):<28} "
                    f"{step.get('status', '')}"
                )
        else:
            lines.append("  No steps stored.")

        lines.extend(["", "Findings by Severity:"])
        severity_counts = self._severity_counts(snapshot.findings)
        for severity in ("critical", "high", "medium", "low", "info", "unknown"):
            lines.append(f"  {severity:<9} {severity_counts.get(severity, 0)}")

        lines.extend(["", "Latest Activity:"])
        for record in snapshot.records[-5:]:
            lines.append(
                f"  {record.get('created_at', '')} | "
                f"{record.get('agent_name', '')} | "
                f"{record.get('status', '')}"
            )

        if not snapshot.records:
            lines.append("  No step records stored.")

        if snapshot.approvals:
            lines.extend(["", "Pending Approvals:"])
            for approval in snapshot.approvals:
                lines.append(
                    f"  {approval.get('approval_id')} | "
                    f"step={approval.get('step_id')} | "
                    f"{approval.get('reason')}"
                )

        return "\n".join(lines)

    def watch(
        self,
        session_id: str,
        interval_seconds: float = 2.0,
        iterations: int | None = None,
        print_func: Any = print,
        clear: bool = True,
    ) -> None:
        """Watch mission status until interrupted or iteration limit reached."""

        count = 0
        while iterations is None or count < iterations:
            if clear:
                os.system("cls" if os.name == "nt" else "clear")
            print_func(self.render(session_id))
            count += 1
            if iterations is not None and count >= iterations:
                break
            time.sleep(interval_seconds)

    @staticmethod
    def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings by severity."""

        counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info", "unknown")}
        for finding in findings:
            severity = str(finding.get("severity") or "unknown")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
