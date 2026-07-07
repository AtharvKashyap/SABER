

"""Tests for SABER Active Directory tool wrappers.

These tests validate the Active Directory wrapper layer without executing real
BloodHound, Impacket, or NetExec commands. The wrappers should build safe command
plans and delegate execution through the shared BaseToolWrapper/Sandbox path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.active_directory import BloodHoundWrapper, ImpacketToolsWrapper, NetExecWrapper
from saber.tools.active_directory.bloodhound import DEFAULT_BLOODHOUND_COLLECTION_METHODS
from saber.tools.base_wrapper import ToolCommand, ToolWrapperConfig


@dataclass
class FakeSandbox:
    """Fake sandbox that records wrapper execution requests."""

    result: SandboxExecutionResult

    def __post_init__(self) -> None:
        """Initialize recorded calls."""

        self.calls: list[SandboxExecutionRequest] = []

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record a request and return the configured result.

        Args:
            request: Sandbox request produced by a wrapper.

        Returns:
            Configured sandbox result.
        """

        self.calls.append(request)
        return self.result


def make_domain_target() -> Target:
    """Create a reusable AD domain target.

    Returns:
        Validated Target object.
    """

    return Target(type=TargetType.DOMAIN, value="corp.example.com")


def make_host_target() -> Target:
    """Create a reusable AD host target.

    Returns:
        Validated Target object.
    """

    return Target(type=TargetType.HOST, value="dc01.corp.example.com")


def make_session() -> MissionSession:
    """Create a reusable mission session.

    Returns:
        Validated MissionSession object.
    """

    return MissionSession(
        session_id="session_ad_1",
        mission_name="AD Wrapper Test Mission",
        status=SessionStatus.CREATED,
    )


def make_sandbox_result(
    outcome: SandboxOutcome = SandboxOutcome.EXECUTED,
    allowed: bool = True,
    session: MissionSession | None = None,
) -> SandboxExecutionResult:
    """Create a reusable sandbox result.

    Args:
        outcome: Sandbox outcome.
        allowed: Whether execution was allowed.
        session: Optional mission session.

    Returns:
        SandboxExecutionResult object.
    """

    return SandboxExecutionResult(
        outcome=outcome,
        allowed=allowed,
        session=session or make_session(),
        return_code=0 if outcome == SandboxOutcome.EXECUTED else None,
        stdout="wrapper stdout" if outcome == SandboxOutcome.EXECUTED else "",
        stderr="",
        reason="AD wrapper test result.",
        metadata={"source": "active-directory-wrapper-test"},
    )


def make_fake_sandbox(session: MissionSession | None = None) -> FakeSandbox:
    """Create a fake sandbox for wrapper tests.

    Args:
        session: Optional mission session.

    Returns:
        FakeSandbox instance.
    """

    return FakeSandbox(make_sandbox_result(session=session))


class TestActiveDirectoryExports:
    """Validate active_directory package exports."""

    def test_active_directory_package_exports_wrappers(self) -> None:
        """The AD package should export stable wrapper classes."""

        assert BloodHoundWrapper.__name__ == "BloodHoundWrapper"
        assert ImpacketToolsWrapper.__name__ == "ImpacketToolsWrapper"
        assert NetExecWrapper.__name__ == "NetExecWrapper"


class TestBloodHoundWrapper:
    """Validate BloodHound wrapper command planning and delegation."""

    def test_default_config(self) -> None:
        """BloodHoundWrapper should use AD defaults."""

        wrapper = BloodHoundWrapper(make_fake_sandbox())

        assert wrapper.config.tool_name == "bloodhound"
        assert wrapper.config.image == "saber/bloodhound-python:latest"
        assert wrapper.config.phase == AssessmentPhase.ACTIVE_DIRECTORY
        assert wrapper.config.requested_by == "BloodHoundWrapper"
        assert wrapper.config.default_timeout_seconds == 1800
        assert wrapper.config.default_metadata == {
            "tool_family": "active_directory",
            "tool": "bloodhound",
        }

    def test_build_collect_command_uses_collection_methods_and_env_placeholder(self) -> None:
        """BloodHound collection should build a command without raw password material."""

        target = make_domain_target()
        wrapper = BloodHoundWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="collect",
            domain="corp.example.com",
            username="alice",
            password_env_var="AD_PASSWORD",
            collection_methods=["DCOnly", "Group"],
            nameserver="10.0.0.10",
            dc_host="dc01.corp.example.com",
            output_prefix="bh_test",
            requires_explicit_authorization=True,
        )

        assert isinstance(command, ToolCommand)
        assert command.command == [
            "bloodhound-python",
            "-d",
            "corp.example.com",
            "-u",
            "alice",
            "-p",
            "$AD_PASSWORD",
            "-c",
            "DCOnly,Group",
            "--zip",
            "-op",
            "bh_test",
            "-ns",
            "10.0.0.10",
            "-dc",
            "dc01.corp.example.com",
        ]
        assert command.action == "bloodhound_collect"
        assert command.evidence_title == "BloodHound collection: corp.example.com"
        assert command.evidence_relative_dir == "active_directory/bloodhound"
        assert command.requires_explicit_authorization is True
        assert command.environment == {"AD_PASSWORD": ""}
        assert command.runner_options == {"requires_shell_expansion": True}
        assert command.metadata["collection_methods"] == ["DCOnly", "Group"]
        assert command.metadata["password_env_var"] == "AD_PASSWORD"

    def test_build_collect_command_uses_default_methods(self) -> None:
        """BloodHound collection should default to the module method list."""

        target = make_domain_target()
        wrapper = BloodHoundWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="collect",
            domain="corp.example.com",
            username="alice",
        )

        assert ",".join(DEFAULT_BLOODHOUND_COLLECTION_METHODS) in command.command
        assert command.requires_explicit_authorization is True

    def test_collect_delegates_to_sandbox(self) -> None:
        """collect() should delegate through BaseToolWrapper/Sandbox."""

        target = make_domain_target()
        session = make_session()
        sandbox = make_fake_sandbox(session=session)
        wrapper = BloodHoundWrapper(sandbox)

        result = wrapper.collect(
            target=target,
            session=session,
            domain="corp.example.com",
            username="alice",
            collection_methods=["DCOnly"],
        )

        assert result == sandbox.result
        assert len(sandbox.calls) == 1
        request = sandbox.calls[0]
        assert request.tool_request.tool_name == "bloodhound"
        assert request.tool_request.action == "bloodhound_collect"
        assert request.tool_request.requires_explicit_authorization is True
        assert request.command[:2] == ["bloodhound-python", "-d"]
        assert request.evidence_relative_dir == "active_directory/bloodhound"
        assert request.session == session

    def test_collect_safe_defaults_disables_explicit_authorization(self) -> None:
        """collect_safe_defaults() should mark constrained collection as lower risk."""

        target = make_domain_target()
        session = make_session()
        sandbox = make_fake_sandbox(session=session)
        wrapper = BloodHoundWrapper(sandbox)

        wrapper.collect_safe_defaults(
            target=target,
            session=session,
            domain="corp.example.com",
            username="alice",
        )

        request = sandbox.calls[0]
        assert request.tool_request.requires_explicit_authorization is False
        assert request.metadata["collection_methods"] == ["DCOnly", "Group", "Trusts"]
        assert "bloodhound_safe" in request.command

    def test_ingest_existing_zip_builds_parser_command(self) -> None:
        """ingest_existing_zip() should build a parser ingestion command."""

        target = make_domain_target()
        session = make_session()
        sandbox = make_fake_sandbox(session=session)
        wrapper = BloodHoundWrapper(sandbox)

        wrapper.ingest_existing_zip(target=target, session=session, zip_path="/tmp/bh.zip")

        request = sandbox.calls[0]
        assert request.command == ["python", "-m", "saber.parsers.bloodhound", "ingest", "/tmp/bh.zip"]
        assert request.tool_request.action == "bloodhound_ingest_existing_zip"
        assert request.tool_request.requires_explicit_authorization is False
        assert request.metadata["zip_path"] == "/tmp/bh.zip"


class TestImpacketToolsWrapper:
    """Validate Impacket wrapper command planning and delegation."""

    def test_default_config(self) -> None:
        """ImpacketToolsWrapper should use AD defaults."""

        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        assert wrapper.config.tool_name == "impacket"
        assert wrapper.config.image == "saber/impacket:latest"
        assert wrapper.config.phase == AssessmentPhase.ACTIVE_DIRECTORY
        assert wrapper.config.requested_by == "ImpacketToolsWrapper"
        assert wrapper.config.default_timeout_seconds == 900

    def test_get_ad_users_command(self) -> None:
        """GetADUsers should build authenticated enumeration command."""

        target = make_domain_target()
        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="get_ad_users",
            domain="CORP",
            username="alice",
            password_env_var="AD_PASSWORD",
            dc_ip="10.0.0.10",
        )

        assert command.command == [
            "GetADUsers.py",
            "CORP/alice:$AD_PASSWORD",
            "-all",
            "-dc-ip",
            "10.0.0.10",
        ]
        assert command.action == "impacket_get_ad_users"
        assert command.requires_explicit_authorization is False
        assert command.environment == {"AD_PASSWORD": ""}
        assert command.runner_options == {"requires_shell_expansion": True}

    def test_get_spns_without_ticket_request_is_not_approval_required(self) -> None:
        """GetUserSPNs without -request should not force approval."""

        target = make_domain_target()
        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="get_spns",
            domain="CORP",
            username="alice",
            password_env_var="AD_PASSWORD",
            request_tickets=False,
        )

        assert command.command == ["GetUserSPNs.py", "CORP/alice:$AD_PASSWORD"]
        assert command.action == "impacket_get_spns"
        assert command.requires_explicit_authorization is False
        assert command.metadata["request_tickets"] is False

    def test_get_spns_with_ticket_request_requires_approval(self) -> None:
        """GetUserSPNs with -request should require explicit approval."""

        target = make_domain_target()
        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="get_spns",
            domain="CORP",
            username="alice",
            password_env_var="AD_PASSWORD",
            dc_ip="10.0.0.10",
            request_tickets=True,
        )

        assert command.command == [
            "GetUserSPNs.py",
            "CORP/alice:$AD_PASSWORD",
            "-request",
            "-dc-ip",
            "10.0.0.10",
        ]
        assert command.requires_explicit_authorization is True
        assert command.metadata["request_tickets"] is True

    def test_get_asrep_candidates_requires_approval(self) -> None:
        """GetNPUsers candidate checks should require approval."""

        target = make_domain_target()
        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="get_asrep_candidates",
            domain="CORP",
            username_file="/evidence/users.txt",
            dc_ip="10.0.0.10",
        )

        assert command.command == [
            "GetNPUsers.py",
            "CORP",
            "-usersfile",
            "/evidence/users.txt",
            "-no-pass",
            "-dc-ip",
            "10.0.0.10",
        ]
        assert command.action == "impacket_get_asrep_candidates"
        assert command.requires_explicit_authorization is True
        assert command.metadata["username_file"] == "/evidence/users.txt"

    def test_smb_exec_check_requires_approval(self) -> None:
        """psexec validation should always require explicit approval."""

        target = make_host_target()
        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="smb_exec_check",
            domain="CORP",
            username="alice",
            password_env_var="AD_PASSWORD",
        )

        assert command.command == [
            "psexec.py",
            "CORP/alice:$AD_PASSWORD",
            "@dc01.corp.example.com",
            "whoami",
        ]
        assert command.action == "impacket_smb_exec_check"
        assert command.requires_explicit_authorization is True

    def test_public_methods_delegate_to_sandbox(self) -> None:
        """Impacket public methods should call the shared sandbox path."""

        target = make_domain_target()
        session = make_session()
        sandbox = make_fake_sandbox(session=session)
        wrapper = ImpacketToolsWrapper(sandbox)

        wrapper.get_ad_users(target=target, session=session, domain="CORP", username="alice")
        wrapper.get_spns(target=target, session=session, domain="CORP", username="alice", request_tickets=True)
        wrapper.get_asrep_candidates(
            target=target,
            session=session,
            domain="CORP",
            username_file="/evidence/users.txt",
        )

        assert len(sandbox.calls) == 3
        assert sandbox.calls[0].tool_request.action == "impacket_get_ad_users"
        assert sandbox.calls[1].tool_request.action == "impacket_get_spns"
        assert sandbox.calls[1].tool_request.requires_explicit_authorization is True
        assert sandbox.calls[2].tool_request.action == "impacket_get_asrep_candidates"

    def test_unsupported_action_raises(self) -> None:
        """Unknown Impacket actions should fail before execution."""

        wrapper = ImpacketToolsWrapper(make_fake_sandbox())

        with pytest.raises(ValueError, match="Unsupported Impacket action"):
            wrapper.build_command(make_domain_target(), action="bad_action")


class TestNetExecWrapper:
    """Validate NetExec wrapper command planning and delegation."""

    def test_default_config(self) -> None:
        """NetExecWrapper should use AD defaults."""

        wrapper = NetExecWrapper(make_fake_sandbox())

        assert wrapper.config.tool_name == "netexec"
        assert wrapper.config.image == "saber/netexec:latest"
        assert wrapper.config.phase == AssessmentPhase.ACTIVE_DIRECTORY
        assert wrapper.config.requested_by == "NetExecWrapper"
        assert wrapper.config.default_timeout_seconds == 900

    def test_smb_auth_check_command(self) -> None:
        """smb_auth_check should build a basic NetExec SMB command."""

        target = make_host_target()
        wrapper = NetExecWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="smb_auth_check",
            domain="CORP",
            username="alice",
            password_env_var="AD_PASSWORD",
        )

        assert command.command == [
            "nxc",
            "smb",
            "dc01.corp.example.com",
            "-d",
            "CORP",
            "-u",
            "alice",
            "-p",
            "$AD_PASSWORD",
        ]
        assert command.action == "netexec_smb_auth_check"
        assert command.requires_explicit_authorization is False
        assert command.environment == {"AD_PASSWORD": ""}
        assert command.runner_options == {"requires_shell_expansion": True}

    def test_smb_shares_command(self) -> None:
        """smb_shares should add --shares."""

        target = make_host_target()
        wrapper = NetExecWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="smb_shares",
            domain="CORP",
            username="alice",
        )

        assert command.command[-1] == "--shares"
        assert command.action == "netexec_smb_shares"
        assert command.evidence_title == "NetExec SMB shares: dc01.corp.example.com"

    def test_ldap_users_command_uses_ldap_protocol(self) -> None:
        """ldap_users should use the NetExec LDAP protocol."""

        target = make_host_target()
        wrapper = NetExecWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="ldap_users",
            domain="CORP",
            username="alice",
        )

        assert command.command[:3] == ["nxc", "ldap", "dc01.corp.example.com"]
        assert command.command[-1] == "--users"
        assert command.action == "netexec_ldap_users"

    def test_local_admin_check_requires_approval(self) -> None:
        """local_admin_check should be approval-required."""

        target = make_host_target()
        wrapper = NetExecWrapper(make_fake_sandbox())

        command = wrapper.build_command(
            target,
            action="local_admin_check",
            domain="CORP",
            username="alice",
        )

        assert command.command[-1] == "--local-auth"
        assert command.action == "netexec_local_admin_check"
        assert command.requires_explicit_authorization is True

    def test_public_methods_delegate_to_sandbox(self) -> None:
        """NetExec public methods should call the shared sandbox path."""

        target = make_host_target()
        session = make_session()
        sandbox = make_fake_sandbox(session=session)
        wrapper = NetExecWrapper(sandbox)

        wrapper.smb_auth_check(target=target, session=session, domain="CORP", username="alice")
        wrapper.smb_shares(target=target, session=session, domain="CORP", username="alice")
        wrapper.ldap_users(target=target, session=session, domain="CORP", username="alice")
        wrapper.local_admin_check_requires_approval(
            target=target,
            session=session,
            domain="CORP",
            username="alice",
        )

        assert len(sandbox.calls) == 4
        assert sandbox.calls[0].tool_request.action == "netexec_smb_auth_check"
        assert sandbox.calls[1].tool_request.action == "netexec_smb_shares"
        assert sandbox.calls[2].tool_request.action == "netexec_ldap_users"
        assert sandbox.calls[3].tool_request.action == "netexec_local_admin_check"
        assert sandbox.calls[3].tool_request.requires_explicit_authorization is True

    def test_unsupported_action_raises(self) -> None:
        """Unknown NetExec actions should fail before execution."""

        wrapper = NetExecWrapper(make_fake_sandbox())

        with pytest.raises(ValueError, match="Unsupported NetExec action"):
            wrapper.build_command(
                make_host_target(),
                action="bad_action",
                domain="CORP",
                username="alice",
            )


class TestCustomConfigs:
    """Validate custom wrapper config support."""

    def test_bloodhound_accepts_custom_config(self) -> None:
        """BloodHoundWrapper should accept custom ToolWrapperConfig."""

        config = ToolWrapperConfig(
            tool_name="custom-bloodhound",
            image="custom/bloodhound:latest",
            phase=AssessmentPhase.ACTIVE_DIRECTORY,
            category=BloodHoundWrapper(make_fake_sandbox()).config.category,
            requested_by="CustomBloodHound",
            default_timeout_seconds=60,
            default_metadata={"profile": "custom"},
        )
        wrapper = BloodHoundWrapper(make_fake_sandbox(), config=config)

        assert wrapper.config.tool_name == "custom-bloodhound"
        assert wrapper.config.image == "custom/bloodhound:latest"
        assert wrapper.config.requested_by == "CustomBloodHound"
        assert wrapper.to_summary_dict()["default_metadata"] == {"profile": "custom"}

    def test_impacket_accepts_custom_config(self) -> None:
        """ImpacketToolsWrapper should accept custom ToolWrapperConfig."""

        config = ToolWrapperConfig(
            tool_name="custom-impacket",
            image="custom/impacket:latest",
            phase=AssessmentPhase.ACTIVE_DIRECTORY,
            category=ImpacketToolsWrapper(make_fake_sandbox()).config.category,
            requested_by="CustomImpacket",
            default_timeout_seconds=60,
        )
        wrapper = ImpacketToolsWrapper(make_fake_sandbox(), config=config)

        assert wrapper.config.tool_name == "custom-impacket"
        assert wrapper.config.image == "custom/impacket:latest"
        assert wrapper.config.requested_by == "CustomImpacket"

    def test_netexec_accepts_custom_config(self) -> None:
        """NetExecWrapper should accept custom ToolWrapperConfig."""

        config = ToolWrapperConfig(
            tool_name="custom-netexec",
            image="custom/netexec:latest",
            phase=AssessmentPhase.ACTIVE_DIRECTORY,
            category=NetExecWrapper(make_fake_sandbox()).config.category,
            requested_by="CustomNetExec",
            default_timeout_seconds=60,
        )
        wrapper = NetExecWrapper(make_fake_sandbox(), config=config)

        assert wrapper.config.tool_name == "custom-netexec"
        assert wrapper.config.image == "custom/netexec:latest"
        assert wrapper.config.requested_by == "CustomNetExec"