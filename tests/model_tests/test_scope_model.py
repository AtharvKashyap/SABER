

"""Tests for SABER scope models.

This file verifies that `saber.models.scope` correctly validates mission scope,
normalizes policy fields, enforces execution-mode constraints, and exposes helper
methods used by agents, tool wrappers, and reporting.
"""

from __future__ import annotations

import pytest

from saber.models.scope import (
    AssessmentPhase,
    ExecutionMode,
    MissionScope,
    ReportingConfig,
)
from saber.models.target import ScopeStatus, Target, TargetType


def make_target(
    target_type: TargetType = TargetType.DOMAIN,
    value: str = "example.com",
) -> Target:
    """Create a reusable target for scope model tests.

    Args:
        target_type: Target type to create.
        value: Target value to validate and normalize.

    Returns:
        A validated Target object.
    """

    return Target(type=target_type, value=value)


class TestMissionScopeCreation:
    """Validate basic MissionScope construction and defaults."""

    def test_valid_scope_creation(self) -> None:
        """A mission scope with one target should be valid."""

        scope = MissionScope(
            mission_name="Internal Assessment",
            targets=[make_target()],
        )

        assert scope.mission_name == "Internal Assessment"
        assert scope.execution_mode == ExecutionMode.ASSESSMENT
        assert scope.interactive is False
        assert scope.targets[0].scope_status == ScopeStatus.IN_SCOPE
        assert AssessmentPhase.RECON in scope.allowed_phases
        assert AssessmentPhase.REPORTING in scope.allowed_phases

    def test_text_fields_are_trimmed(self) -> None:
        """Mission, client, and operator names should be stripped."""

        scope = MissionScope(
            mission_name="  Q3 Assessment  ",
            client_name="  Example Corp  ",
            operator_name="  Atharv  ",
            targets=[make_target()],
        )

        assert scope.mission_name == "Q3 Assessment"
        assert scope.client_name == "Example Corp"
        assert scope.operator_name == "Atharv"

    def test_empty_optional_text_becomes_none(self) -> None:
        """Empty optional text fields should normalize to None."""

        scope = MissionScope(
            mission_name="Assessment",
            client_name="   ",
            operator_name="   ",
            targets=[make_target()],
        )

        assert scope.client_name is None
        assert scope.operator_name is None

    def test_non_report_only_scope_requires_at_least_one_target(self) -> None:
        """Assessment-style missions should require at least one target."""

        with pytest.raises(ValueError):
            MissionScope(mission_name="Assessment")

    def test_report_only_scope_allows_no_targets(self) -> None:
        """Report-only missions should be allowed without scan targets."""

        scope = MissionScope(
            mission_name="Report Only",
            execution_mode=ExecutionMode.REPORT_ONLY,
        )

        assert scope.targets == []
        assert scope.allowed_phases == [AssessmentPhase.REPORTING]


class TestMissionScopeNormalization:
    """Validate scope normalization behavior."""

    def test_targets_are_marked_in_scope(self) -> None:
        """Explicit targets should be marked IN_SCOPE."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[make_target(TargetType.IP, "192.168.1.10")],
        )

        assert scope.targets[0].scope_status == ScopeStatus.IN_SCOPE
        assert scope.in_scope_targets[0].value == "192.168.1.10"

    def test_out_of_scope_targets_are_marked_out_of_scope(self) -> None:
        """Explicit exclusions should be marked OUT_OF_SCOPE."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[make_target(TargetType.DOMAIN, "example.com")],
            out_of_scope=[make_target(TargetType.DOMAIN, "admin.example.com")],
        )

        assert scope.out_of_scope[0].scope_status == ScopeStatus.OUT_OF_SCOPE
        assert scope.excluded_targets[0].value == "admin.example.com"

    def test_policy_lists_are_normalized(self) -> None:
        """Policy lists should be stripped, lowercased, underscored, and deduplicated."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[make_target()],
            allowed_ttps=[" Web Vuln Scan ", "web_vuln_scan", "SMB Enum"],
            prohibited_actions=[" Denial Of Service ", "denial_of_service"],
            requires_explicit_authorization=[" Remote Code Execution ", "remote_code_execution"],
        )

        assert scope.allowed_ttps == ["web_vuln_scan", "smb_enum"]
        assert scope.prohibited_actions == ["denial_of_service"]
        assert scope.requires_explicit_authorization == ["remote_code_execution"]

    def test_recon_only_mode_limits_allowed_phases(self) -> None:
        """Recon-only mode should remove non-recon/non-reporting phases."""

        scope = MissionScope(
            mission_name="Recon Only",
            execution_mode=ExecutionMode.RECON_ONLY,
            targets=[make_target()],
            allowed_phases=[
                AssessmentPhase.RECON,
                AssessmentPhase.WEB,
                AssessmentPhase.EXPLOITATION,
                AssessmentPhase.REPORTING,
            ],
        )

        assert scope.allowed_phases == [AssessmentPhase.RECON, AssessmentPhase.REPORTING]

    def test_report_only_mode_forces_reporting_phase(self) -> None:
        """Report-only mode should force reporting as the only phase."""

        scope = MissionScope(
            mission_name="Report Only",
            execution_mode=ExecutionMode.REPORT_ONLY,
            allowed_phases=[AssessmentPhase.RECON, AssessmentPhase.WEB],
        )

        assert scope.allowed_phases == [AssessmentPhase.REPORTING]

    def test_exact_target_conflict_raises_error(self) -> None:
        """The same exact target cannot be both included and excluded."""

        with pytest.raises(ValueError):
            MissionScope(
                mission_name="Conflict",
                targets=[make_target(TargetType.DOMAIN, "example.com")],
                out_of_scope=[make_target(TargetType.DOMAIN, "example.com")],
            )


class TestMissionScopeHelpers:
    """Validate helper methods and properties on MissionScope."""

    def test_network_and_web_target_helpers(self) -> None:
        """Network and web target properties should split targets by usability."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[
                make_target(TargetType.IP, "192.168.1.10"),
                make_target(TargetType.CIDR, "10.0.0.0/24"),
                make_target(TargetType.URL, "https://example.com/login"),
            ],
        )

        assert [target.value for target in scope.network_targets] == [
            "192.168.1.10",
            "10.0.0.0/24",
        ]
        assert [target.value for target in scope.web_targets] == ["https://example.com/login"]

    def test_is_phase_allowed(self) -> None:
        """Phase helper should support enum and string inputs."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[make_target()],
            allowed_phases=[AssessmentPhase.RECON, AssessmentPhase.REPORTING],
        )

        assert scope.is_phase_allowed(AssessmentPhase.RECON)
        assert scope.is_phase_allowed("reporting")
        assert not scope.is_phase_allowed(AssessmentPhase.WEB)

    def test_policy_helper_methods(self) -> None:
        """TTP, prohibited action, and explicit auth helpers should normalize input."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[make_target()],
            allowed_ttps=["smb_enum"],
            prohibited_actions=["denial_of_service"],
            requires_explicit_authorization=["remote_code_execution"],
        )

        assert scope.is_ttp_allowed("SMB Enum")
        assert not scope.is_ttp_allowed("credential_dumping")
        assert scope.is_action_prohibited("Denial Of Service")
        assert not scope.is_action_prohibited("web_fingerprinting")
        assert scope.action_requires_explicit_authorization("Remote Code Execution")
        assert not scope.action_requires_explicit_authorization("dns_enum")

    def test_target_values_without_filter(self) -> None:
        """target_values should return all in-scope values by default."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[
                make_target(TargetType.DOMAIN, "example.com"),
                make_target(TargetType.URL, "https://example.com/login"),
            ],
        )

        assert scope.target_values() == ["example.com", "https://example.com/login"]

    def test_target_values_with_type_filter(self) -> None:
        """target_values should support filtering by TargetType."""

        scope = MissionScope(
            mission_name="Assessment",
            targets=[
                make_target(TargetType.DOMAIN, "example.com"),
                make_target(TargetType.URL, "https://example.com/login"),
            ],
        )

        assert scope.target_values(TargetType.URL) == ["https://example.com/login"]

    def test_to_agent_context(self) -> None:
        """Agent context should return compact JSON-compatible scope data."""

        scope = MissionScope(
            mission_name="Assessment",
            client_name="Example Corp",
            operator_name="Atharv",
            execution_mode=ExecutionMode.ASSESSMENT,
            interactive=True,
            targets=[make_target(TargetType.DOMAIN, "example.com")],
            out_of_scope=[make_target(TargetType.DOMAIN, "admin.example.com")],
            allowed_phases=[AssessmentPhase.RECON, AssessmentPhase.REPORTING],
            allowed_ttps=["dns_enum"],
            prohibited_actions=["denial_of_service"],
            requires_explicit_authorization=["remote_code_execution"],
        )

        context = scope.to_agent_context()

        assert context["mission_name"] == "Assessment"
        assert context["client_name"] == "Example Corp"
        assert context["operator_name"] == "Atharv"
        assert context["execution_mode"] == "assessment"
        assert context["interactive"] is True
        assert context["targets"] == [{"type": "domain", "value": "example.com"}]
        assert context["out_of_scope"] == [{"type": "domain", "value": "admin.example.com"}]
        assert context["allowed_phases"] == ["recon", "reporting"]
        assert context["allowed_ttps"] == ["dns_enum"]
        assert context["prohibited_actions"] == ["denial_of_service"]
        assert context["requires_explicit_authorization"] == ["remote_code_execution"]
        assert "rate_limits" in context
        assert "evidence" in context
        assert "sandbox" in context
        assert "reporting" in context


class TestReportingConfig:
    """Validate reporting configuration behavior."""

    def test_reporting_formats_are_normalized(self) -> None:
        """Report formats should be normalized and deduplicated."""

        config = ReportingConfig(formats=[" PDF ", "pdf", "JSON", "xlsx"])

        assert config.formats == ["pdf", "json", "xlsx"]

    def test_unsupported_reporting_format_raises_error(self) -> None:
        """Unsupported report formats should be rejected."""

        with pytest.raises(ValueError):
            ReportingConfig(formats=["pdf", "docx"])

    def test_empty_reporting_formats_raise_error(self) -> None:
        """At least one report format should be required."""

        with pytest.raises(ValueError):
            ReportingConfig(formats=[])

