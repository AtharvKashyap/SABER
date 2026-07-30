"""Working-memory state for the SABER agentic mission loop.

MissionState is distinct from MissionSession. MissionSession is the lifecycle
record (status, phases, approvals). MissionState is the accumulating knowledge
the loop reasons over each iteration: hosts, services, credentials, vulns,
hypotheses, and the trace of attempted/failed actions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from saber.models.scope import MissionScope
from saber.models.target import Target


class AutonomyLevel(StrEnum):
    """How much the loop may do without a human confirmation."""

    RECON_ONLY = "recon_only"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"


class PtesPhase(StrEnum):
    """Where the mission is in the PTES methodology.

    The loop advances through these in order. Transitions are decided by the
    deterministic ``PhaseGoalChecker`` (``saber/orchestration/phase_gate.py``) from
    what is actually in ``MissionState`` — not by the decider's free choice — so
    phase progression is unit-testable rather than a matter of model mood.
    """

    PRE_ENGAGEMENT = "pre_engagement"
    RECON = "recon"
    VULN_ASSESSMENT = "vuln_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PROOF_OF_CONCEPT = "proof_of_concept"
    POST_ENGAGEMENT = "post_engagement"

    @classmethod
    def ordered(cls) -> tuple[PtesPhase, ...]:
        """Return the phases in methodology order."""

        return (
            cls.PRE_ENGAGEMENT,
            cls.RECON,
            cls.VULN_ASSESSMENT,
            cls.EXPLOITATION,
            cls.POST_EXPLOITATION,
            cls.LATERAL_MOVEMENT,
            cls.PROOF_OF_CONCEPT,
            cls.POST_ENGAGEMENT,
        )

    def next_phase(self) -> PtesPhase | None:
        """Return the phase after this one, or None at the end."""

        phases = self.ordered()
        position = phases.index(self)
        if position + 1 >= len(phases):
            return None
        return phases[position + 1]


class KnownHost(BaseModel):
    """A host the loop has learned about."""

    address: str
    hostnames: list[str] = Field(default_factory=list)
    os: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownService(BaseModel):
    """An open service on a host."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        """Return the natural dedupe key."""

        return f"{self.host}:{self.port}/{self.protocol}"


class KnownTechnology(BaseModel):
    """A technology/product fingerprinted on a host or URL."""

    host: str
    name: str
    version: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownCredential(BaseModel):
    """A credential discovered or validated during the mission."""

    username: str
    secret: str | None = None
    kind: str = "password"  # password | hash | key | token
    host: str | None = None
    service: str | None = None
    validated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownVuln(BaseModel):
    """A candidate or confirmed vulnerability."""

    title: str
    host: str | None = None
    port: int | None = None
    severity: str = "info"
    identifier: str | None = None  # CVE id, nuclei template id, etc.
    confirmed: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownShare(BaseModel):
    """A network share discovered on a host."""

    host: str
    name: str
    type: str = "smb"  # smb | nfs | ...
    access: str = "none"  # read | write | none
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownAccount(BaseModel):
    """A user/computer account discovered (distinct from a usable credential)."""

    username: str
    domain: str | None = None
    host: str | None = None
    source: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownSession(BaseModel):
    """An interactive foothold established on a host."""

    host: str
    kind: str = "shell"  # shell | meterpreter | winrm | ssh
    user: str | None = None
    privilege: str = "user"  # user | root | system
    ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownLoot(BaseModel):
    """A collected artifact of value (file/hash/key/config)."""

    description: str
    kind: str = "file"  # file | hash | key | config
    host: str | None = None
    path: str | None = None
    evidence_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownFlag(BaseModel):
    """A captured flag / proof token."""

    value: str
    host: str | None = None
    location: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MissionNote(BaseModel):
    """Free-form knowledge the decider should see (e.g. custom_cli output)."""

    title: str
    detail: str = ""
    severity: str = "info"
    refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    """A ranked belief the loop is reasoning about."""

    statement: str
    confidence: float = 0.5
    supporting_evidence: list[str] = Field(default_factory=list)
    status: str = "open"  # open | confirmed | rejected
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttemptedAction(BaseModel):
    """One action the loop has run, with outcome."""

    tool_name: str
    action: str
    args: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    reason: str = ""
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def signature(self) -> str:
        """Return a stable, order-independent identity for repeat detection."""

        args = json.dumps(self.args, sort_keys=True, default=str)
        return f"{self.tool_name}:{self.action}:{args}"


class MissionState(BaseModel):
    """Accumulating working memory for one mission."""

    session_id: str
    target: Target
    objective: str = ""
    scope: MissionScope | None = None
    autonomy_level: AutonomyLevel = AutonomyLevel.AUTONOMOUS
    roe: dict[str, Any] = Field(default_factory=dict)

    hosts: list[KnownHost] = Field(default_factory=list)
    services: list[KnownService] = Field(default_factory=list)
    technologies: list[KnownTechnology] = Field(default_factory=list)
    credentials: list[KnownCredential] = Field(default_factory=list)
    vulns: list[KnownVuln] = Field(default_factory=list)
    shares: list[KnownShare] = Field(default_factory=list)
    accounts: list[KnownAccount] = Field(default_factory=list)
    sessions: list[KnownSession] = Field(default_factory=list)
    loot: list[KnownLoot] = Field(default_factory=list)
    flags: list[KnownFlag] = Field(default_factory=list)
    notes: list[MissionNote] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    attempted_actions: list[AttemptedAction] = Field(default_factory=list)

    finding_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    # Defaults to RECON (not PRE_ENGAGEMENT) for back-compat: existing snapshots and
    # callers predate this field, and every current mission starts by looking around.
    current_phase: PtesPhase = PtesPhase.RECON

    objective_met: bool = False
    stop_reason: str | None = None
    step_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def failed_actions(self) -> list[AttemptedAction]:
        """Return only the actions that failed."""

        return [action for action in self.attempted_actions if not action.success]

    @property
    def failed_signatures(self) -> set[str]:
        """Return the signatures of every action that has already failed.

        The decider uses this to avoid re-proposing something that did not work:
        repeating a failed action burns a step and, after ``max_repeat_failures``,
        ends the mission via ``StopEvaluator``.
        """

        return {action.signature for action in self.failed_actions}

    def record_attempt(self, attempt: AttemptedAction) -> MissionState:
        """Return a copy with one more attempted action and updated timestamp."""

        return self.model_copy(
            update={
                "attempted_actions": [*self.attempted_actions, attempt],
                "step_count": self.step_count + 1,
                "updated_at": datetime.now(UTC),
            }
        )

    def touch(self) -> MissionState:
        """Return a copy with a bumped updated_at timestamp."""

        return self.model_copy(update={"updated_at": datetime.now(UTC)})

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact JSON-compatible snapshot for CLI/GUI/report."""

        return {
            "session_id": self.session_id,
            "target": self.target.to_agent_dict(),
            "objective": self.objective,
            "autonomy_level": self.autonomy_level.value,
            "counts": {
                "hosts": len(self.hosts),
                "services": len(self.services),
                "technologies": len(self.technologies),
                "credentials": len(self.credentials),
                "vulns": len(self.vulns),
                "shares": len(self.shares),
                "accounts": len(self.accounts),
                "sessions": len(self.sessions),
                "loot": len(self.loot),
                "flags": len(self.flags),
                "notes": len(self.notes),
                "hypotheses": len(self.hypotheses),
                "attempted_actions": len(self.attempted_actions),
                "failed_actions": len(self.failed_actions),
            },
            "objective_met": self.objective_met,
            "stop_reason": self.stop_reason,
            "step_count": self.step_count,
            "updated_at": self.updated_at.isoformat(),
        }
