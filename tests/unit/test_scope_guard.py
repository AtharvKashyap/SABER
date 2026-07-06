

"""Tests for SABER ScopeGuard.

This file verifies that `saber.core.scope_guard` enforces mission scope policy
before agents or tool wrappers execute actions. ScopeGuard tests are pure unit
tests: they do not execute tools, touch Docker, access a database, or call an LLM.
"""

from __future__ import annotations

from saber.core.scope_guard import (
    RequestedActionCategory,
    ScopeGuard,
    ScopeGuardReason,
    ToolRequest,
)
from saber.models.scope import AssessmentPhase, ExecutionMode, MissionScope
from saber.models.target import ScopeStatus, Target, TargetType


def make_domain_target(
    value: str = "example.com",
    scope_status: ScopeStatus = ScopeStatus.IN_SCOPE,
) -> Target:
    """Create a reusable domain target.

    Args:
        value: Domain value to assign.
        scope_status: Scope status to assign.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.DOMAIN, value=value, scope_status=scope_status)


def make_ip_target(
    value: str = "10.0.0.5",
    scope_status: ScopeStatus = ScopeStatus.IN_SCOPE,
) -> Target:
    """Create a reusable IP target.

    Args:
        value: IP address value to assign.
        scope_status: Scope status to assign.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.IP, value=value, scope_status=scope_status)


def make_scope(
    execution_mode: ExecutionMode = ExecutionMode.ASSESSMENT,
    targets: list[Target] | None = None,
    out_of_scope: list[Target] | None = None,
    allowed_phases: list[AssessmentPhase] | None = None,
    allowed_ttps: list[str] | None = None,
    prohibited_actions: list[str] | None = None,
    requires_explicit_authorization: list[str] | None = None,
) -> MissionScope:
    """Create a reusable mission scope for ScopeGuard tests.

    Args:
        execution_mode: Mission execution mode to assign.
        targets: In-scope targets.
        out_of_scope: Explicitly excluded targets.
        allowed_phases: Allowed assessment phases.
        allowed_ttps: Allowed TTP strings.
        prohibited_actions: Prohibited action strings.
        requires_explicit_authorization: Actions requiring explicit authorization.

    Returns:
        A validated MissionScope object.
    """

    return MissionScope(
        mission_name="ScopeGuard Test Mission",
        execution_mode=execution_mode,
        targets=targets if targets is not None else [make_domain_target()],
        out_of_scope=out_of_scope if out_of_scope is not None else [],
        allowed_phases=allowed_phases
        if allowed_phases is not None
        else [AssessmentPhase.RECON, AssessmentPhase.WEB, AssessmentPhase.REPORTING],
        allowed_ttps=allowed_ttps if allowed_ttps is not None else [],
        prohibited_actions=prohibited_actions if prohibited_actions is not None else [],
        requires_explicit_authorization=requires_explicit_authorization
        if requires_explicit_authorization is not None
        else [],
    )


def make_guard(scope: MissionScope | None = None) -> ScopeGuard:
    """Create a ScopeGuard for tests.

    Args:
        scope: Optional scope to wrap.

    Returns:
        A ScopeGuard instance.
    """

    return ScopeGuard(scope or make_scope())


class TestEvaluateTarget:
    """Validate target scope decisions."""

    def test_targetless_action_is_allowed(self) -> None:
        """Targetless actions should pass target-scope checks."""

        decision = make_guard().evaluate_target(None)

        assert decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.TARGET_IN_SCOPE.value

    def test_in_scope_target_is_allowed(self) -> None:
        """Targets listed in mission scope should be allowed."""

        target = make_domain_target()
        decision = make_guard().evaluate_target(target)

        assert decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.TARGET_IN_SCOPE.value

    def test_explicit_out_of_scope_target_is_denied(self) -> None:
        """Targets listed in out_of_scope should be denied."""

        target = make_domain_target("blocked.example.com")
        scope = make_scope(out_of_scope=[target])
        decision = make_guard(scope).evaluate_target(target)

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.TARGET_OUT_OF_SCOPE.value

    def test_unknown_target_requires_review(self) -> None:
        """Targets not listed in mission scope should require review."""

        decision = make_guard().evaluate_target(make_domain_target("unknown.example.com"))

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.TARGET_UNKNOWN.value

    def test_review_and_unknown_scope_status_are_normalized_by_mission_scope(self) -> None:
        """MissionScope should normalize listed targets to in-scope before guard checks."""

        review_target = make_domain_target(
            "review.example.com",
            scope_status=ScopeStatus.REQUIRES_REVIEW,
        )
        unknown_target = make_domain_target(
            "unknown-status.example.com",
            scope_status=ScopeStatus.UNKNOWN,
        )
        scope = make_scope(targets=[review_target, unknown_target])
        guard = make_guard(scope)

        review_decision = guard.evaluate_target(review_target)
        unknown_decision = guard.evaluate_target(unknown_target)

        assert review_decision.allowed
        assert not review_decision.requires_review
        assert review_decision.metadata["reason_code"] == ScopeGuardReason.TARGET_IN_SCOPE.value

        assert unknown_decision.allowed
        assert not unknown_decision.requires_review
        assert unknown_decision.metadata["reason_code"] == ScopeGuardReason.TARGET_IN_SCOPE.value


class TestEvaluatePhaseTtpAndAction:
    """Validate phase, TTP, and action policy decisions."""

    def test_allowed_phase_is_allowed(self) -> None:
        """Allowed phases should pass phase checks."""

        decision = make_guard().evaluate_phase(AssessmentPhase.RECON)

        assert decision.allowed
        assert decision.metadata["reason_code"] == ScopeGuardReason.PHASE_ALLOWED.value

    def test_disallowed_phase_is_denied(self) -> None:
        """Phases outside mission policy should be denied."""

        decision = make_guard().evaluate_phase(AssessmentPhase.EXPLOITATION)

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.PHASE_DENIED.value

    def test_missing_ttp_is_allowed(self) -> None:
        """Missing TTP should not block an action."""

        decision = make_guard().evaluate_ttp(None)

        assert decision.allowed
        assert decision.metadata["reason_code"] == ScopeGuardReason.TTP_ALLOWED.value

    def test_allowed_ttp_is_allowed(self) -> None:
        """Configured TTPs should be allowed."""

        scope = make_scope(allowed_ttps=["T1046"])
        decision = make_guard(scope).evaluate_ttp("T1046")

        assert decision.allowed
        assert decision.metadata["reason_code"] == ScopeGuardReason.TTP_ALLOWED.value

    def test_disallowed_ttp_is_denied(self) -> None:
        """Unconfigured TTPs should be denied when allowed_ttps is restrictive."""

        scope = make_scope(allowed_ttps=["T1046"])
        decision = make_guard(scope).evaluate_ttp("T1110")

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.TTP_DENIED.value

    def test_normal_action_is_allowed(self) -> None:
        """Non-prohibited actions should be allowed when no approval is required."""

        decision = make_guard().evaluate_action("run_nmap_scan")

        assert decision.allowed
        assert decision.metadata["reason_code"] == ScopeGuardReason.ACTION_ALLOWED.value

    def test_prohibited_action_is_denied(self) -> None:
        """Explicitly prohibited actions should be denied."""

        scope = make_scope(prohibited_actions=["dump_secrets"])
        decision = make_guard(scope).evaluate_action(" dump secrets ")

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.ACTION_PROHIBITED.value

    def test_explicit_authorization_action_requires_review(self) -> None:
        """Actions requiring authorization should require review."""

        scope = make_scope(requires_explicit_authorization=["run_exploit_validation"])
        decision = make_guard(scope).evaluate_action("run exploit validation")

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.ACTION_REQUIRES_APPROVAL.value

    def test_request_flag_can_require_explicit_authorization(self) -> None:
        """Caller-provided authorization requirement should force review."""

        decision = make_guard().evaluate_action(
            "run_nuclei_scan",
            requires_explicit_authorization=True,
        )

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.ACTION_REQUIRES_APPROVAL.value


class TestEvaluateExecutionMode:
    """Validate execution-mode policy decisions."""

    def test_report_only_allows_reporting(self) -> None:
        """Report-only mode should allow reporting actions."""

        scope = make_scope(
            execution_mode=ExecutionMode.REPORT_ONLY,
            targets=[],
            allowed_phases=[AssessmentPhase.REPORTING],
        )
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.REPORTING,
            AssessmentPhase.REPORTING,
        )

        assert decision.allowed

    def test_report_only_blocks_non_reporting(self) -> None:
        """Report-only mode should deny non-reporting actions."""

        scope = make_scope(
            execution_mode=ExecutionMode.REPORT_ONLY,
            targets=[],
            allowed_phases=[AssessmentPhase.REPORTING],
        )
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.RECON,
            AssessmentPhase.RECON,
        )

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.EXECUTION_MODE_DENIED.value

    def test_recon_only_allows_recon(self) -> None:
        """Recon-only mode should allow recon actions."""

        scope = make_scope(execution_mode=ExecutionMode.RECON_ONLY)
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.RECON,
            AssessmentPhase.RECON,
        )

        assert decision.allowed

    def test_recon_only_blocks_exploitation(self) -> None:
        """Recon-only mode should deny exploitation actions."""

        scope = make_scope(execution_mode=ExecutionMode.RECON_ONLY)
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.EXPLOITATION,
            AssessmentPhase.EXPLOITATION,
        )

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.EXECUTION_MODE_DENIED.value

    def test_assessment_mode_requires_review_for_exploitation(self) -> None:
        """Assessment mode should review high-risk action categories."""

        scope = make_scope(execution_mode=ExecutionMode.ASSESSMENT)
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.EXPLOITATION,
            AssessmentPhase.EXPLOITATION,
        )

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.REQUEST_REQUIRES_REVIEW.value

    def test_lab_exploit_mode_allows_exploitation_by_mode(self) -> None:
        """Lab exploit mode should not block exploitation at execution-mode level."""

        scope = make_scope(execution_mode=ExecutionMode.LAB_EXPLOIT)
        decision = make_guard(scope).evaluate_execution_mode(
            RequestedActionCategory.EXPLOITATION,
            AssessmentPhase.EXPLOITATION,
        )

        assert decision.allowed


class TestEvaluateToolRequest:
    """Validate full ToolRequest decisions."""

    def test_allowed_tool_request(self) -> None:
        """A fully in-scope recon request should be allowed."""

        target = make_domain_target()
        request = ToolRequest(
            tool_name="nmap",
            action="run_nmap_scan",
            phase=AssessmentPhase.RECON,
            target=target,
            category=RequestedActionCategory.RECON,
            ttp=None,
        )

        decision = make_guard().evaluate_tool_request(request)

        assert decision.allowed
        assert not decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.REQUEST_ALLOWED.value
        assert decision.metadata["tool_name"] == "nmap"
        assert decision.metadata["action"] == "run_nmap_scan"
        assert len(decision.metadata["all_decisions"]) == 5

    def test_tool_request_denied_by_target(self) -> None:
        """A request against out-of-scope target should be denied."""

        target = make_domain_target("blocked.example.com")
        scope = make_scope(out_of_scope=[target])
        request = ToolRequest(
            tool_name="httpx",
            action="probe_http",
            phase=AssessmentPhase.RECON,
            target=target,
            category=RequestedActionCategory.RECON,
        )

        decision = make_guard(scope).evaluate_tool_request(request)

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["tool_name"] == "httpx"
        assert decision.metadata["denials"]
        assert ScopeGuardReason.TARGET_OUT_OF_SCOPE.value == decision.metadata["reason_code"]

    def test_tool_request_requires_review_for_unknown_target(self) -> None:
        """A request against an unknown target should require review."""

        request = ToolRequest(
            tool_name="whatweb",
            action="fingerprint_web_stack",
            phase=AssessmentPhase.RECON,
            target=make_domain_target("unknown.example.com"),
            category=RequestedActionCategory.RECON,
        )

        decision = make_guard().evaluate_tool_request(request)

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.REQUEST_REQUIRES_REVIEW.value
        assert decision.metadata["reviews"]

    def test_tool_request_denied_by_phase(self) -> None:
        """A request in a disallowed phase should be denied."""

        request = ToolRequest(
            tool_name="nuclei",
            action="run_nuclei_scan",
            phase=AssessmentPhase.EXPLOITATION,
            target=make_domain_target(),
            category=RequestedActionCategory.EXPLOITATION,
        )

        decision = make_guard().evaluate_tool_request(request)

        assert not decision.allowed
        assert not decision.requires_review
        assert ScopeGuardReason.PHASE_DENIED.value == decision.metadata["reason_code"]

    def test_tool_request_requires_review_for_explicit_authorization(self) -> None:
        """Requests marked as needing explicit authorization should require review."""

        request = ToolRequest(
            tool_name="nuclei",
            action="run_nuclei_scan",
            phase=AssessmentPhase.WEB,
            target=make_domain_target(),
            category=RequestedActionCategory.WEB,
            requires_explicit_authorization=True,
        )

        decision = make_guard().evaluate_tool_request(request)

        assert not decision.allowed
        assert decision.requires_review
        assert decision.metadata["reason_code"] == ScopeGuardReason.REQUEST_REQUIRES_REVIEW.value

    def test_tool_request_denial_precedence_over_review(self) -> None:
        """Hard denials should take precedence over review requirements."""

        target = make_domain_target("blocked.example.com")
        scope = make_scope(
            out_of_scope=[target],
            requires_explicit_authorization=["run_nuclei_scan"],
        )
        request = ToolRequest(
            tool_name="nuclei",
            action="run_nuclei_scan",
            phase=AssessmentPhase.WEB,
            target=target,
            category=RequestedActionCategory.WEB,
        )

        decision = make_guard(scope).evaluate_tool_request(request)

        assert not decision.allowed
        assert not decision.requires_review
        assert decision.metadata["denials"]
        assert ScopeGuardReason.TARGET_OUT_OF_SCOPE.value == decision.metadata["reason_code"]