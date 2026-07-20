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
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    attempted_actions: list[AttemptedAction] = Field(default_factory=list)

    finding_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    objective_met: bool = False
    stop_reason: str | None = None
    step_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def failed_actions(self) -> list[AttemptedAction]:
        """Return only the actions that failed."""

        return [action for action in self.attempted_actions if not action.success]

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
                "hypotheses": len(self.hypotheses),
                "attempted_actions": len(self.attempted_actions),
                "failed_actions": len(self.failed_actions),
            },
            "objective_met": self.objective_met,
            "stop_reason": self.stop_reason,
            "step_count": self.step_count,
            "updated_at": self.updated_at.isoformat(),
        }
