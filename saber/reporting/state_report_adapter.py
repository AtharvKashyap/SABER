"""Adapt a final MissionState into a phased PTES report context.

Before F9 this adapter emitted hosts/services/technologies/credentials/vulns only —
so a mission that established sessions, dumped loot and captured a flag reported
none of it. Everything the extended arsenal produces now reaches the report.

The structure follows PTES rather than dumping state lists:

- ``methodology``  — every phase in order, whether it was reached, and the EVIDENCE
  that completed it (recovered from the phase-transition notes ``MissionLoop`` writes)
- ``attack_chain`` — an ordered narrative of the milestones that mattered, so the
  report says how access was obtained rather than only what was found
- ``access`` / ``collected`` — what the engagement actually got: sessions,
  credentials, accounts, shares / loot, flags
- ``findings``, ``timeline``, ``evidence_refs`` — as before

Secrets: credential secrets are redacted, and inline ``user:password@host`` strings
inside loot descriptions are masked. The finding survives; the password does not get
printed into a PDF that gets emailed around.
"""

from __future__ import annotations

import re
from typing import Any

from saber.models.mission_state import MissionState, PtesPhase
from saber.models.session import MissionSession

_REDACTED = "***redacted***"
# "postgres://user:secret@host/db" -> keep the shape, drop the secret.
_INLINE_CREDENTIAL_RE = re.compile(r"(?P<scheme>\w+://)(?P<user>[^:/@\s]+):(?P<secret>[^@\s]+)@")
# "password=hunter2", "api_key: abc123"
_ASSIGNED_SECRET_RE = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|secret|api_?key|token)\b\s*[=:]\s*)(?P<value>\S+)",
    re.IGNORECASE,
)
# "Phase complete: recon -> vuln_assessment"
_PHASE_NOTE_PREFIX = "Phase complete:"


class MissionStateReportAdapter:
    """Build an evidence-backed, phased report context from final MissionState."""

    def build_report_context(self, state: MissionState, session: MissionSession) -> dict[str, Any]:
        """Return a JSON-compatible report context."""

        phase_events = self._phase_events(state)
        credentials = [self._redact_credential(c) for c in state.credentials]

        return {
            "summary": state.to_summary_dict(),
            "session": session.to_summary_dict(),
            "current_phase": state.current_phase.value,
            "methodology": self._methodology(state, phase_events),
            "attack_chain": self._attack_chain(state, phase_events),
            # --- what was discovered -------------------------------------------
            "hosts": [h.model_dump() for h in state.hosts],
            "services": [s.model_dump() for s in state.services],
            "technologies": [t.model_dump() for t in state.technologies],
            "vulns": [v.model_dump() for v in state.vulns],
            # Kept at the top level as well as under "access": this is the adapter's
            # long-standing key and existing report consumers read it here. The
            # nested copy is the phased view, not a replacement.
            "credentials": credentials,
            # --- what access was obtained --------------------------------------
            "access": {
                "sessions": [s.model_dump() for s in state.sessions],
                "credentials": credentials,
                "accounts": [a.model_dump() for a in state.accounts],
                "shares": [s.model_dump() for s in state.shares],
            },
            # --- what was taken away -------------------------------------------
            "collected": {
                "loot": [self._redact_loot(item) for item in state.loot],
                "flags": [f.model_dump() for f in state.flags],
            },
            "notes": [n.model_dump() for n in state.notes],
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

    # --- methodology / narrative --------------------------------------------------

    @staticmethod
    def _phase_events(state: MissionState) -> dict[str, dict[str, Any]]:
        """Recover phase completions from the notes the loop wrote.

        ``MissionLoop._advance_phase`` records one note per transition; this reads
        them back so the report can state what evidence completed each phase.
        """

        events: dict[str, dict[str, Any]] = {}
        for note in state.notes:
            if not note.title.startswith(_PHASE_NOTE_PREFIX):
                continue
            from_phase = str(note.metadata.get("from_phase") or "")
            if not from_phase:
                continue
            events[from_phase] = {
                "completed": True,
                "evidence": note.detail,
                "to_phase": note.metadata.get("to_phase"),
                "step": note.metadata.get("step"),
            }
        return events

    @staticmethod
    def _methodology(
        state: MissionState, phase_events: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return every PTES phase in order with whether it was reached."""

        reached_index = state.current_phase.index_in_order()
        methodology: list[dict[str, Any]] = []

        for position, phase in enumerate(PtesPhase.ordered()):
            event = phase_events.get(phase.value, {})
            methodology.append(
                {
                    "phase": phase.value,
                    "reached": position <= reached_index,
                    "completed": bool(event.get("completed")),
                    "evidence": event.get("evidence"),
                    "completed_at_step": event.get("step"),
                }
            )
        return methodology

    def _attack_chain(
        self, state: MissionState, phase_events: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return an ordered narrative of the milestones that mattered.

        This is what makes it a pentest report rather than an inventory: it says how
        the engagement got from a target to impact.
        """

        chain: list[dict[str, Any]] = []

        if state.hosts:
            chain.append(
                {
                    "step": "reconnaissance",
                    "detail": (
                        f"Identified {len(state.hosts)} host(s) and "
                        f"{len(state.services)} service(s) in scope."
                    ),
                }
            )
        if state.vulns:
            confirmed = [v for v in state.vulns if v.confirmed]
            chain.append(
                {
                    "step": "vulnerability_identified",
                    "detail": (
                        f"{len(state.vulns)} vulnerability/ies identified, "
                        f"{len(confirmed)} confirmed."
                    ),
                }
            )
        validated = [c for c in state.credentials if c.validated]
        if validated:
            chain.append(
                {
                    "step": "credentials_validated",
                    "detail": f"{len(validated)} credential(s) confirmed working.",
                }
            )
        if state.sessions:
            hosts = sorted({s.host for s in state.sessions})
            chain.append(
                {
                    "step": "foothold_established",
                    "detail": f"Interactive access obtained on {', '.join(hosts)}.",
                }
            )
            if len(hosts) > 1:
                chain.append(
                    {
                        "step": "lateral_movement",
                        "detail": f"Access extended across {len(hosts)} hosts.",
                    }
                )
        if state.loot:
            chain.append(
                {
                    "step": "data_collected",
                    "detail": f"{len(state.loot)} artifact(s) of value collected.",
                }
            )
        if state.flags:
            chain.append(
                {
                    "step": "objective_proven",
                    "detail": f"{len(state.flags)} flag(s)/proof token(s) captured.",
                }
            )

        # Phase transitions carry the deterministic evidence, so append them as the
        # audit trail behind the narrative above.
        for phase in PtesPhase.ordered():
            event = phase_events.get(phase.value)
            if event:
                chain.append(
                    {
                        "step": f"phase_complete:{phase.value}",
                        "detail": str(event.get("evidence") or ""),
                    }
                )
        return chain

    # --- redaction ----------------------------------------------------------------

    @staticmethod
    def _redact_credential(credential: Any) -> dict[str, Any]:
        """Return a credential with its secret removed but its existence recorded."""

        return {
            **credential.model_dump(exclude={"secret"}),
            "secret": (_REDACTED if credential.secret else None),
        }

    @classmethod
    def _redact_loot(cls, loot: Any) -> dict[str, Any]:
        """Return loot with inline secrets masked.

        Loot descriptions legitimately quote what was found — a connection string, a
        secret assignment — so the finding is kept and only the secret value is
        masked. A report should prove the exposure without republishing the password.
        """

        payload = loot.model_dump()
        description = str(payload.get("description") or "")
        payload["description"] = cls.redact_secrets(description)
        return payload

    @staticmethod
    def redact_secrets(text: str) -> str:
        """Mask inline credentials and secret assignments in free text."""

        masked = _INLINE_CREDENTIAL_RE.sub(
            lambda m: f"{m.group('scheme')}{m.group('user')}:{_REDACTED}@", text
        )
        return _ASSIGNED_SECRET_RE.sub(lambda m: f"{m.group('key')}{_REDACTED}", masked)
