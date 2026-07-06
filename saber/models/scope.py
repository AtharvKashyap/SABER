

"""Scope models used across SABER.

This file defines the validated structure for SABER mission scope data. Scope
models describe what the operator is allowed to test, what is excluded, which
assessment phases are permitted, and what safety limits apply.

Inputs:
    - Parsed scope YAML data from `config/scope.yaml` or another mission file.
    - Target definitions from the CLI, planner, or imported configuration.

Outputs:
    - Normalized, validated MissionScope objects.
    - Helper methods for ScopeGuard, agents, tool wrappers, and reporting.

Used by:
    - saber.core.scope_guard
    - saber.core.mission
    - saber.core.phase_graph
    - saber.agents.*
    - saber.tools.* wrappers
    - saber.reporting exporters
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from saber.models.target import ScopeStatus, Target, TargetType


class ExecutionMode(StrEnum):
    """Supported SABER mission execution modes.

    Values:
        RECON_ONLY: Discovery and enumeration only.
        ASSESSMENT: Recon, scanning, and safe validation by default.
        LAB_EXPLOIT: Controlled exploitation in an explicitly authorized lab.
        REPORT_ONLY: No scanning; report generation from existing evidence only.
    """

    RECON_ONLY = "recon_only"
    ASSESSMENT = "assessment"
    LAB_EXPLOIT = "lab_exploit"
    REPORT_ONLY = "report_only"


class AssessmentPhase(StrEnum):
    """Supported SABER assessment phases.

    Values:
        RECON: Host, DNS, service, and technology discovery.
        WEB: Web application assessment.
        NETWORK: Internal network service assessment.
        ACTIVE_DIRECTORY: Active Directory-specific assessment.
        EXPLOITATION: Controlled proof-of-exploitability.
        POST_EXPLOITATION: Minimal authorized impact evidence collection.
        PASSWORD_CRACKING: Offline password/hash cracking when allowed.
        REPORTING: Report generation and evidence packaging.
    """

    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    ACTIVE_DIRECTORY = "active_directory"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_CRACKING = "password_cracking"
    REPORTING = "reporting"


class RateLimitConfig(BaseModel):
    """Rate and concurrency limits for a mission.

    Args:
        max_concurrent_targets: Maximum number of targets SABER should process at once.
        max_requests_per_second: Maximum request rate for web or API-like actions.
        max_scan_rate: Optional packet/probe rate for scan tools that support rate limiting.
        max_runtime_minutes: Optional mission or phase runtime limit.
        max_retries: Maximum retry count for transient tool failures.

    Returns:
        A validated rate-limit configuration object.
    """

    max_concurrent_targets: int = Field(default=4, ge=1)
    max_requests_per_second: float = Field(default=5.0, gt=0)
    max_scan_rate: int | None = Field(default=None, gt=0)
    max_runtime_minutes: int | None = Field(default=None, gt=0)
    max_retries: int = Field(default=2, ge=0)


class EvidenceConfig(BaseModel):
    """Evidence collection settings for a mission.

    Args:
        save_raw_output: Whether raw stdout/stderr and tool files should be saved.
        save_screenshots: Whether screenshot evidence should be collected when available.
        redact_secrets: Whether reports should redact secrets by default.
        evidence_dir: Directory where raw evidence should be stored.
        bundle_evidence: Whether final reports should include an evidence bundle reference.

    Returns:
        A validated evidence configuration object.
    """

    save_raw_output: bool = True
    save_screenshots: bool = True
    redact_secrets: bool = True
    evidence_dir: str = "evidence"
    bundle_evidence: bool = True


class SandboxConfig(BaseModel):
    """Sandbox settings for tool execution.

    Args:
        enabled: Whether tools should run through the Docker sandbox.
        image: Docker image used for sandboxed tool execution.
        network_name: Docker network name or mode used for sandbox runs.
        cpu_limit: Optional CPU limit for sandbox execution.
        memory_limit: Optional memory limit for sandbox execution.

    Returns:
        A validated sandbox configuration object.
    """

    enabled: bool = True
    image: str = "saber/sandbox:kali-last-release"
    network_name: str = "saber-dev-net"
    cpu_limit: float | None = Field(default=2.0, gt=0)
    memory_limit: str | None = "4g"


class ReportingConfig(BaseModel):
    """Report generation settings for a mission.

    Args:
        formats: Report formats SABER should generate.
        include_unverified_findings: Whether unverified observations should appear as findings.
        output_dir: Directory where reports should be written.
        report_basename: Optional base filename for generated reports.

    Returns:
        A validated reporting configuration object.
    """

    formats: list[str] = Field(default_factory=lambda: ["pdf", "xlsx", "json"])
    include_unverified_findings: bool = False
    output_dir: str = "output"
    report_basename: str | None = None

    @field_validator("formats")
    @classmethod
    def normalize_formats(cls, formats: list[str]) -> list[str]:
        """Normalize and validate report formats.

        Args:
            formats: Raw report format strings.

        Returns:
            Lowercase, de-duplicated format strings.

        Raises:
            ValueError: If no formats are provided or an unsupported format appears.
        """

        allowed_formats = {"pdf", "xlsx", "json", "md"}
        normalized_formats = _normalize_string_list(formats)

        if not normalized_formats:
            raise ValueError("at least one report format is required")

        unsupported = sorted(set(normalized_formats) - allowed_formats)
        if unsupported:
            raise ValueError(f"unsupported report formats: {', '.join(unsupported)}")

        return normalized_formats


class MissionScope(BaseModel):
    """Validated SABER mission scope.

    Args:
        mission_name: Human-readable mission name.
        client_name: Optional client or organization name.
        operator_name: Optional operator running the assessment.
        execution_mode: Mission mode controlling allowed behavior.
        interactive: Whether high-risk actions should pause for operator approval.
        targets: Explicitly authorized targets.
        out_of_scope: Explicitly excluded targets.
        allowed_phases: Assessment phases permitted for this mission.
        allowed_ttps: Named TTPs/tool-action categories permitted for this mission.
        prohibited_actions: Actions that are explicitly blocked.
        requires_explicit_authorization: High-impact actions that need separate approval.
        rate_limits: Rate and concurrency limits.
        evidence: Evidence collection settings.
        sandbox: Sandbox execution settings.
        reporting: Report generation settings.
        metadata: Optional additional mission context.

    Returns:
        A normalized, validated scope object used by ScopeGuard and the mission
        orchestrator.
    """

    mission_name: str = Field(..., min_length=1)
    client_name: str | None = None
    operator_name: str | None = None
    execution_mode: ExecutionMode = ExecutionMode.ASSESSMENT
    interactive: bool = False
    targets: list[Target] = Field(default_factory=list)
    out_of_scope: list[Target] = Field(default_factory=list)
    allowed_phases: list[AssessmentPhase] = Field(
        default_factory=lambda: [
            AssessmentPhase.RECON,
            AssessmentPhase.WEB,
            AssessmentPhase.NETWORK,
            AssessmentPhase.REPORTING,
        ]
    )
    allowed_ttps: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    requires_explicit_authorization: list[str] = Field(default_factory=list)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mission_name", "client_name", "operator_name", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        """Normalize mission text fields.

        Args:
            value: Raw text value or None.

        Returns:
            Stripped text, or None if the value is empty.
        """

        if value is None:
            return None

        normalized = value.strip()
        return normalized or None

    @field_validator("allowed_ttps", "prohibited_actions", "requires_explicit_authorization")
    @classmethod
    def normalize_policy_lists(cls, values: list[str]) -> list[str]:
        """Normalize policy string lists.

        Args:
            values: Raw policy strings from the scope file.

        Returns:
            Lowercase, stripped, de-duplicated strings.
        """

        return _normalize_string_list(values)

    @field_validator("targets")
    @classmethod
    def mark_targets_in_scope(cls, targets: list[Target]) -> list[Target]:
        """Mark explicit mission targets as in scope.

        Args:
            targets: Targets from the authorized target list.

        Returns:
            Targets with scope_status set to IN_SCOPE.
        """

        return [target.mark_in_scope() for target in targets]

    @field_validator("out_of_scope")
    @classmethod
    def mark_targets_out_of_scope(cls, targets: list[Target]) -> list[Target]:
        """Mark explicit exclusions as out of scope.

        Args:
            targets: Targets from the exclusion list.

        Returns:
            Targets with scope_status set to OUT_OF_SCOPE.
        """

        return [target.mark_out_of_scope() for target in targets]

    @model_validator(mode="after")
    def validate_scope_consistency(self) -> MissionScope:
        """Validate cross-field mission scope consistency.

        Returns:
            The validated MissionScope object.

        Raises:
            ValueError: If required targets/phases are missing or unsafe mode rules conflict.
        """

        if self.execution_mode != ExecutionMode.REPORT_ONLY and not self.targets:
            raise ValueError("non-report-only missions require at least one in-scope target")

        if self.execution_mode == ExecutionMode.RECON_ONLY:
            self.allowed_phases = [
                phase
                for phase in self.allowed_phases
                if phase in {AssessmentPhase.RECON, AssessmentPhase.REPORTING}
            ]

        if self.execution_mode == ExecutionMode.REPORT_ONLY:
            self.allowed_phases = [AssessmentPhase.REPORTING]

        if not self.allowed_phases:
            raise ValueError("at least one allowed phase is required")

        self._validate_no_exact_target_conflicts()
        return self

    @property
    def in_scope_targets(self) -> list[Target]:
        """Return explicitly authorized targets.

        Returns:
            Targets marked as IN_SCOPE.
        """

        return [target for target in self.targets if target.scope_status == ScopeStatus.IN_SCOPE]

    @property
    def excluded_targets(self) -> list[Target]:
        """Return explicitly excluded targets.

        Returns:
            Targets marked as OUT_OF_SCOPE.
        """

        return [target for target in self.out_of_scope if target.scope_status == ScopeStatus.OUT_OF_SCOPE]

    @property
    def network_targets(self) -> list[Target]:
        """Return in-scope targets usable by network tools.

        Returns:
            In-scope IP, CIDR, IP range, domain, and host targets.
        """

        return [target for target in self.in_scope_targets if target.is_network_target]

    @property
    def web_targets(self) -> list[Target]:
        """Return in-scope targets directly usable by web tools.

        Returns:
            In-scope URL targets.
        """

        return [target for target in self.in_scope_targets if target.is_web_target]

    def is_phase_allowed(self, phase: AssessmentPhase | str) -> bool:
        """Return whether an assessment phase is allowed.

        Args:
            phase: AssessmentPhase enum value or raw phase string.

        Returns:
            True if the phase is present in allowed_phases.
        """

        normalized_phase = AssessmentPhase(phase)
        return normalized_phase in self.allowed_phases

    def is_ttp_allowed(self, ttp: str) -> bool:
        """Return whether a named TTP/action category is allowed.

        Args:
            ttp: TTP string from planner or agent output.

        Returns:
            True when the normalized TTP is listed in allowed_ttps.
        """

        normalized_ttp = _normalize_policy_value(ttp)
        return normalized_ttp in self.allowed_ttps

    def is_action_prohibited(self, action: str) -> bool:
        """Return whether an action is explicitly prohibited.

        Args:
            action: Action or TTP string from planner or agent output.

        Returns:
            True when the normalized action is listed in prohibited_actions.
        """

        normalized_action = _normalize_policy_value(action)
        return normalized_action in self.prohibited_actions

    def action_requires_explicit_authorization(self, action: str) -> bool:
        """Return whether an action requires separate approval.

        Args:
            action: Action or TTP string from planner or agent output.

        Returns:
            True when the normalized action is listed in requires_explicit_authorization.
        """

        normalized_action = _normalize_policy_value(action)
        return normalized_action in self.requires_explicit_authorization

    def target_values(self, target_type: TargetType | None = None) -> list[str]:
        """Return normalized in-scope target values.

        Args:
            target_type: Optional target type filter.

        Returns:
            Target values for all in-scope targets matching the optional type.
        """

        targets = self.in_scope_targets
        if target_type is not None:
            targets = [target for target in targets if target.type == target_type]

        return [target.value for target in targets]

    def to_agent_context(self) -> dict[str, Any]:
        """Return a compact JSON-compatible scope context for agents.

        Returns:
            A dictionary containing the mission summary, targets, exclusions,
            allowed phases, TTP policy, safety policy, and rate limits.
        """

        return {
            "mission_name": self.mission_name,
            "client_name": self.client_name,
            "operator_name": self.operator_name,
            "execution_mode": self.execution_mode.value,
            "interactive": self.interactive,
            "targets": [target.to_agent_dict() for target in self.in_scope_targets],
            "out_of_scope": [target.to_agent_dict() for target in self.excluded_targets],
            "allowed_phases": [phase.value for phase in self.allowed_phases],
            "allowed_ttps": self.allowed_ttps,
            "prohibited_actions": self.prohibited_actions,
            "requires_explicit_authorization": self.requires_explicit_authorization,
            "rate_limits": self.rate_limits.model_dump(),
            "evidence": self.evidence.model_dump(),
            "sandbox": self.sandbox.model_dump(),
            "reporting": self.reporting.model_dump(),
        }

    def _validate_no_exact_target_conflicts(self) -> None:
        """Ensure the same exact target is not both in and out of scope.

        Raises:
            ValueError: If a target appears in both `targets` and `out_of_scope`.
        """

        included = {(target.type, target.value) for target in self.targets}
        excluded = {(target.type, target.value) for target in self.out_of_scope}
        conflicts = included & excluded

        if conflicts:
            formatted = ", ".join(
                f"{target_type.value}:{target_value}"
                for target_type, target_value in sorted(conflicts, key=lambda item: item[1])
            )
            raise ValueError(f"targets cannot be both in scope and out of scope: {formatted}")


class ScopeDecision(BaseModel):
    """Decision returned by scope checks.

    Args:
        target: Optional target this decision applies to.
        status: Scope status produced by the decision.
        allowed: Whether the request is allowed.
        requires_review: Whether the request requires operator review.
        reason: Human-readable decision reason.
        metadata: Optional structured decision metadata.

    Returns:
        A validated scope decision object.
    """

    target: Target | None = None
    status: ScopeStatus = ScopeStatus.UNKNOWN
    allowed: bool
    requires_review: bool = False
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def allow(
        cls,
        target: Target | None = None,
        reason: str = "target is explicitly in scope",
        metadata: dict[str, Any] | None = None,
    ) -> "ScopeDecision":
        """Create an allow decision.

        Args:
            target: Optional target this decision applies to.
            reason: Human-readable decision reason.
            metadata: Optional structured decision metadata.

        Returns:
            A ScopeDecision allowing the request.
        """

        marked_target = target.mark_in_scope() if target else None
        return cls(
            target=marked_target,
            status=ScopeStatus.IN_SCOPE,
            allowed=True,
            requires_review=False,
            reason=reason,
            metadata=metadata or {},
        )

    @classmethod
    def deny(
        cls,
        target: Target | None = None,
        reason: str = "target is explicitly out of scope",
        metadata: dict[str, Any] | None = None,
    ) -> "ScopeDecision":
        """Create a deny decision.

        Args:
            target: Optional target this decision applies to.
            reason: Human-readable decision reason.
            metadata: Optional structured decision metadata.

        Returns:
            A ScopeDecision denying the request.
        """

        marked_target = target.mark_out_of_scope() if target else None
        return cls(
            target=marked_target,
            status=ScopeStatus.OUT_OF_SCOPE,
            allowed=False,
            requires_review=False,
            reason=reason,
            metadata=metadata or {},
        )

    @classmethod
    def review(
        cls,
        target: Target | None = None,
        reason: str = "target requires operator review",
        metadata: dict[str, Any] | None = None,
    ) -> "ScopeDecision":
        """Create a review decision.

        Args:
            target: Optional target this decision applies to.
            reason: Human-readable decision reason.
            metadata: Optional structured decision metadata.

        Returns:
            A ScopeDecision requiring operator review.
        """

        marked_target = target.mark_requires_review() if target else None
        return cls(
            target=marked_target,
            status=ScopeStatus.REQUIRES_REVIEW,
            allowed=False,
            requires_review=True,
            reason=reason,
            metadata=metadata or {},
        )

    def to_agent_dict(self) -> dict[str, Any]:
        """Return compact scope decision data for agent handoff.

        Returns:
            JSON-compatible decision metadata.
        """

        return {
            "target": self.target.to_agent_dict() if self.target else None,
            "status": self.status.value,
            "allowed": self.allowed,
            "requires_review": self.requires_review,
            "reason": self.reason,
            "metadata": self.metadata,
        }


def _normalize_string_list(values: list[str]) -> list[str]:
    """Normalize a list of policy/report strings.

    Args:
        values: Raw string values.

    Returns:
        Lowercase, stripped, de-duplicated strings in original order.
    """

    seen: set[str] = set()
    normalized_values: list[str] = []

    for value in values:
        normalized = _normalize_policy_value(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            normalized_values.append(normalized)

    return normalized_values


def _normalize_policy_value(value: str) -> str:
    """Normalize one policy string.

    Args:
        value: Raw policy string.

    Returns:
        Lowercase string with surrounding whitespace removed and spaces converted to underscores.
    """

    return value.strip().lower().replace(" ", "_")