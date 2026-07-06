

"""Mission scope enforcement for SABER.

This module defines ScopeGuard, the central policy gate used before agents or
tool wrappers execute actions. ScopeGuard is intentionally pure logic: it does not
run commands, call Docker, write files, access the database, or call an LLM.

Inputs:
    - MissionScope objects from saber.models.scope.
    - Target objects from saber.models.target.
    - AssessmentPhase values describing the requested phase.
    - Action, tool, and TTP names proposed by planners or wrappers.

Outputs:
    - ScopeDecision objects explaining whether an action is allowed, denied, or
      requires human review.

Used by:
    - saber.core.approval_gate
    - saber.core.phase_graph
    - saber.core.mission
    - saber.tools.* wrappers
    - saber.agents.* planners
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.models.scope import AssessmentPhase, ExecutionMode, MissionScope, ScopeDecision
from saber.models.target import ScopeStatus, Target


class ScopeGuardReason(StrEnum):
    """Reason codes returned by ScopeGuard decisions.

    Values:
        TARGET_IN_SCOPE: Target is explicitly in scope.
        TARGET_OUT_OF_SCOPE: Target is explicitly out of scope.
        TARGET_REQUIRES_REVIEW: Target exists but requires operator review.
        TARGET_UNKNOWN: Target was not found in the mission scope.
        PHASE_ALLOWED: Requested phase is allowed.
        PHASE_DENIED: Requested phase is not allowed.
        TTP_ALLOWED: Requested TTP is allowed.
        TTP_DENIED: Requested TTP is not allowed.
        ACTION_ALLOWED: Requested action is allowed.
        ACTION_PROHIBITED: Requested action is explicitly prohibited.
        ACTION_REQUIRES_APPROVAL: Requested action requires explicit approval.
        EXECUTION_MODE_DENIED: Execution mode blocks the request.
        REQUEST_ALLOWED: Full request is allowed.
        REQUEST_REQUIRES_REVIEW: Full request requires review.
    """

    TARGET_IN_SCOPE = "target_in_scope"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    TARGET_REQUIRES_REVIEW = "target_requires_review"
    TARGET_UNKNOWN = "target_unknown"
    PHASE_ALLOWED = "phase_allowed"
    PHASE_DENIED = "phase_denied"
    TTP_ALLOWED = "ttp_allowed"
    TTP_DENIED = "ttp_denied"
    ACTION_ALLOWED = "action_allowed"
    ACTION_PROHIBITED = "action_prohibited"
    ACTION_REQUIRES_APPROVAL = "action_requires_approval"
    EXECUTION_MODE_DENIED = "execution_mode_denied"
    REQUEST_ALLOWED = "request_allowed"
    REQUEST_REQUIRES_REVIEW = "request_requires_review"


class RequestedActionCategory(StrEnum):
    """High-level requested action category.

    Values:
        RECON: Passive or low-risk reconnaissance.
        WEB: Web application testing.
        NETWORK: Network service testing.
        ACTIVE_DIRECTORY: Active Directory enumeration or analysis.
        EXPLOITATION: Exploit validation or exploitation activity.
        POST_EXPLOITATION: Post-exploitation activity.
        PASSWORD_CRACKING: Password guessing, cracking, or credential validation.
        REPORTING: Report generation or evidence summarization.
        UNKNOWN: Category is not known.
    """

    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    ACTIVE_DIRECTORY = "active_directory"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_CRACKING = "password_cracking"
    REPORTING = "reporting"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolRequest:
    """Structured request to evaluate before tool execution.

    Args:
        tool_name: Name of the tool or wrapper being requested.
        action: Human-readable action name.
        phase: Assessment phase the action belongs to.
        target: Optional target the action applies to.
        category: High-level action category.
        ttp: Optional TTP or technique identifier/name.
        requires_explicit_authorization: Whether this request needs operator approval.
        metadata: Optional structured context from the caller.

    Returns:
        An immutable request object that can be evaluated by ScopeGuard.
    """

    tool_name: str
    action: str
    phase: AssessmentPhase
    target: Target | None = None
    category: RequestedActionCategory = RequestedActionCategory.UNKNOWN
    ttp: str | None = None
    requires_explicit_authorization: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class ScopeGuard:
    """Evaluate whether requested SABER actions are allowed by mission scope.

    Args:
        scope: MissionScope containing targets, excluded targets, phase policy,
            allowed TTPs, prohibited actions, and execution-mode settings.

    Returns:
        A ScopeGuard instance that can evaluate targets, phases, TTPs, actions,
        and full tool execution requests.
    """

    def __init__(self, scope: MissionScope) -> None:
        """Initialize ScopeGuard.

        Args:
            scope: Mission scope policy to enforce.
        """

        self.scope = scope

    def evaluate_target(self, target: Target | None) -> ScopeDecision:
        """Evaluate whether a target is allowed by the mission scope.

        Args:
            target: Target to evaluate. None means the action is targetless.

        Returns:
            ScopeDecision describing allow, deny, or review outcome.
        """

        if target is None:
            return ScopeDecision.allow(
                reason="Targetless action is allowed by target scope.",
                metadata={"reason_code": ScopeGuardReason.TARGET_IN_SCOPE.value},
            )

        if self._matches_any(target, self.scope.out_of_scope):
            return ScopeDecision.deny(
                reason=f"Target {target.value} is explicitly out of scope.",
                metadata={"reason_code": ScopeGuardReason.TARGET_OUT_OF_SCOPE.value},
            )

        matching_target = self._matching_target(target, self.scope.targets)
        if matching_target is None:
            return ScopeDecision.review(
                reason=f"Target {target.value} is not listed in mission scope.",
                metadata={"reason_code": ScopeGuardReason.TARGET_UNKNOWN.value},
            )

        if matching_target.scope_status == ScopeStatus.OUT_OF_SCOPE:
            return ScopeDecision.deny(
                reason=f"Target {target.value} is marked out of scope.",
                metadata={"reason_code": ScopeGuardReason.TARGET_OUT_OF_SCOPE.value},
            )

        if matching_target.scope_status == ScopeStatus.REQUIRES_REVIEW:
            return ScopeDecision.review(
                reason=f"Target {target.value} requires operator review.",
                metadata={"reason_code": ScopeGuardReason.TARGET_REQUIRES_REVIEW.value},
            )

        if matching_target.scope_status == ScopeStatus.UNKNOWN:
            return ScopeDecision.review(
                reason=f"Target {target.value} has unknown scope status.",
                metadata={"reason_code": ScopeGuardReason.TARGET_UNKNOWN.value},
            )

        return ScopeDecision.allow(
            reason=f"Target {target.value} is in scope.",
            metadata={"reason_code": ScopeGuardReason.TARGET_IN_SCOPE.value},
        )

    def evaluate_phase(self, phase: AssessmentPhase) -> ScopeDecision:
        """Evaluate whether a phase is allowed.

        Args:
            phase: Requested assessment phase.

        Returns:
            ScopeDecision describing allow or deny outcome.
        """

        if self.scope.is_phase_allowed(phase):
            return ScopeDecision.allow(
                reason=f"Phase {phase.value} is allowed.",
                metadata={"reason_code": ScopeGuardReason.PHASE_ALLOWED.value},
            )

        return ScopeDecision.deny(
            reason=f"Phase {phase.value} is not allowed by mission scope.",
            metadata={"reason_code": ScopeGuardReason.PHASE_DENIED.value},
        )

    def evaluate_ttp(self, ttp: str | None) -> ScopeDecision:
        """Evaluate whether a TTP is allowed.

        Args:
            ttp: Optional TTP or technique name.

        Returns:
            ScopeDecision describing allow or deny outcome.
        """

        if not ttp:
            return ScopeDecision.allow(
                reason="No TTP was provided, so TTP policy does not block the action.",
                metadata={"reason_code": ScopeGuardReason.TTP_ALLOWED.value},
            )

        if self.scope.is_ttp_allowed(ttp):
            return ScopeDecision.allow(
                reason=f"TTP {ttp} is allowed.",
                metadata={"reason_code": ScopeGuardReason.TTP_ALLOWED.value},
            )

        return ScopeDecision.deny(
            reason=f"TTP {ttp} is not allowed by mission scope.",
            metadata={"reason_code": ScopeGuardReason.TTP_DENIED.value},
        )

    def evaluate_action(
        self,
        action: str,
        requires_explicit_authorization: bool = False,
    ) -> ScopeDecision:
        """Evaluate whether an action name is allowed.

        Args:
            action: Action name proposed by an agent or wrapper.
            requires_explicit_authorization: Whether the action needs operator approval.

        Returns:
            ScopeDecision describing allow, deny, or review outcome.
        """

        normalized_action = _normalize_policy_text(action)

        if self.scope.is_action_prohibited(normalized_action):
            return ScopeDecision.deny(
                reason=f"Action {normalized_action} is explicitly prohibited.",
                metadata={"reason_code": ScopeGuardReason.ACTION_PROHIBITED.value},
            )

        if requires_explicit_authorization or self.scope.action_requires_explicit_authorization(
            normalized_action
        ):
            return ScopeDecision.review(
                reason=f"Action {normalized_action} requires explicit authorization.",
                metadata={"reason_code": ScopeGuardReason.ACTION_REQUIRES_APPROVAL.value},
            )

        return ScopeDecision.allow(
            reason=f"Action {normalized_action} is allowed.",
            metadata={"reason_code": ScopeGuardReason.ACTION_ALLOWED.value},
        )

    def evaluate_execution_mode(
        self,
        category: RequestedActionCategory,
        phase: AssessmentPhase,
    ) -> ScopeDecision:
        """Evaluate whether execution mode permits a request category.

        Args:
            category: High-level action category.
            phase: Requested assessment phase.

        Returns:
            ScopeDecision describing allow or deny outcome.
        """

        if self.scope.execution_mode == ExecutionMode.REPORT_ONLY:
            if category == RequestedActionCategory.REPORTING and phase == AssessmentPhase.REPORTING:
                return ScopeDecision.allow(
                    reason="Report-only mode allows reporting actions.",
                    metadata={"reason_code": ScopeGuardReason.REQUEST_ALLOWED.value},
                )
            return ScopeDecision.deny(
                reason="Report-only mode blocks non-reporting actions.",
                metadata={"reason_code": ScopeGuardReason.EXECUTION_MODE_DENIED.value},
            )

        if self.scope.execution_mode == ExecutionMode.RECON_ONLY:
            allowed_categories = {
                RequestedActionCategory.RECON,
                RequestedActionCategory.REPORTING,
                RequestedActionCategory.UNKNOWN,
            }
            allowed_phases = {AssessmentPhase.RECON, AssessmentPhase.REPORTING}
            if category in allowed_categories and phase in allowed_phases:
                return ScopeDecision.allow(
                    reason="Recon-only mode allows recon/reporting actions.",
                    metadata={"reason_code": ScopeGuardReason.REQUEST_ALLOWED.value},
                )
            return ScopeDecision.deny(
                reason="Recon-only mode blocks active testing, exploitation, and password actions.",
                metadata={"reason_code": ScopeGuardReason.EXECUTION_MODE_DENIED.value},
            )

        if self.scope.execution_mode == ExecutionMode.ASSESSMENT:
            blocked_categories = {
                RequestedActionCategory.EXPLOITATION,
                RequestedActionCategory.POST_EXPLOITATION,
                RequestedActionCategory.PASSWORD_CRACKING,
            }
            if category in blocked_categories:
                return ScopeDecision.review(
                    reason="Assessment mode requires review for high-risk action categories.",
                    metadata={"reason_code": ScopeGuardReason.REQUEST_REQUIRES_REVIEW.value},
                )

        return ScopeDecision.allow(
            reason="Execution mode allows this request.",
            metadata={"reason_code": ScopeGuardReason.REQUEST_ALLOWED.value},
        )

    def evaluate_tool_request(self, request: ToolRequest) -> ScopeDecision:
        """Evaluate a full tool execution request.

        Args:
            request: Structured tool request from a planner or wrapper.

        Returns:
            ScopeDecision describing whether the tool request is allowed, denied,
            or requires operator review.
        """

        decisions = [
            self.evaluate_execution_mode(request.category, request.phase),
            self.evaluate_phase(request.phase),
            self.evaluate_target(request.target),
            self.evaluate_ttp(request.ttp),
            self.evaluate_action(request.action, request.requires_explicit_authorization),
        ]

        denied = [decision for decision in decisions if not decision.allowed and not decision.requires_review]
        if denied:
            return ScopeDecision.deny(
                reason="Tool request denied by ScopeGuard.",
                metadata={
                    "reason_code": denied[0].metadata.get("reason_code"),
                    "tool_name": request.tool_name,
                    "action": request.action,
                    "denials": [decision.reason for decision in denied],
                    "all_decisions": [decision.to_agent_dict() for decision in decisions],
                },
            )

        reviews = [decision for decision in decisions if decision.requires_review]
        if reviews:
            return ScopeDecision.review(
                reason="Tool request requires operator review.",
                metadata={
                    "reason_code": ScopeGuardReason.REQUEST_REQUIRES_REVIEW.value,
                    "tool_name": request.tool_name,
                    "action": request.action,
                    "reviews": [decision.reason for decision in reviews],
                    "all_decisions": [decision.to_agent_dict() for decision in decisions],
                },
            )

        return ScopeDecision.allow(
            reason="Tool request is allowed by ScopeGuard.",
            metadata={
                "reason_code": ScopeGuardReason.REQUEST_ALLOWED.value,
                "tool_name": request.tool_name,
                "action": request.action,
                "all_decisions": [decision.to_agent_dict() for decision in decisions],
            },
        )

    @staticmethod
    def _matching_target(target: Target, candidates: list[Target]) -> Target | None:
        """Return a matching target from a candidate list.

        Args:
            target: Target to search for.
            candidates: Candidate targets to compare against.

        Returns:
            The matching Target, or None if no match exists.
        """

        for candidate in candidates:
            if candidate.type == target.type and candidate.value == target.value:
                return candidate
        return None

    @classmethod
    def _matches_any(cls, target: Target, candidates: list[Target]) -> bool:
        """Return whether target matches any candidate.

        Args:
            target: Target to search for.
            candidates: Candidate targets to compare against.

        Returns:
            True when a matching target exists.
        """

        return cls._matching_target(target, candidates) is not None


def _normalize_policy_text(value: str) -> str:
    """Normalize action, TTP, and policy text.

    Args:
        value: Raw policy text.

    Returns:
        Lowercase, stripped, underscore-separated text.
    """

    return value.strip().lower().replace(" ", "_")