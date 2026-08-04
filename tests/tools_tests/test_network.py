"""Tests for network tool wrappers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.base_wrapper import ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.network import (
    BettercapWrapper,
    Enum4LinuxWrapper,
    OpenVASApiWrapper,
    ResponderWrapper,
    SnmpwalkWrapper,
)


@dataclass
class FakeSandbox:
    """Fake sandbox that records requests and returns a configured result."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request and return result."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_target() -> Target:
    """Create reusable target."""

    return Target(type=TargetType.HOST, value="192.0.2.10")


def make_session() -> MissionSession:
    """Create reusable session."""

    return MissionSession(
        session_id="session_network_1",
        mission_name="Network Wrapper Test Mission",
        status=SessionStatus.CREATED,
    )


def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create reusable sandbox result."""

    return SandboxExecutionResult(
        outcome=SandboxOutcome.EXECUTED,
        allowed=True,
        session=session or make_session(),
        evidence=None,
        return_code=0,
        stdout="ok",
        stderr="",
        reason="Command executed and evidence was saved.",
        metadata={"backend": "fake", "finished_at": datetime.now(UTC).isoformat()},
    )


class TestNetworkExports:
    """Validate network package exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export network wrappers."""

        assert BettercapWrapper is not None
        assert Enum4LinuxWrapper is not None
        assert OpenVASApiWrapper is not None
        assert ResponderWrapper is not None
        assert SnmpwalkWrapper is not None


class TestSnmpwalkWrapper:
    """Validate SNMPWalk wrapper."""

    def test_default_config(self) -> None:
        """SNMPWalk should use network defaults."""

        wrapper = SnmpwalkWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "snmpwalk"
        assert wrapper.config.image == "saber/snmpwalk:latest"
        assert wrapper.config.phase == AssessmentPhase.NETWORK
        assert wrapper.config.category == RequestedActionCategory.NETWORK

    def test_walk_command(self) -> None:
        """Walk command should include version, community, target, and OID."""

        wrapper = SnmpwalkWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="walk",
            community="public",
            oid="1.3.6.1.2.1.1",
            version="2c",
        )

        assert command.command == ["snmpwalk", "-v", "2c", "-c", "public", "192.0.2.10", "1.3.6.1.2.1.1"]
        assert command.action == "walk"
        assert command.metadata["target"] == "192.0.2.10"

    def test_walk_delegates_to_sandbox(self) -> None:
        """Public walk should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SnmpwalkWrapper(sandbox)

        wrapper.walk(target=make_target(), session=make_session(), community="private")

        assert sandbox.requests[0].command == ["snmpwalk", "-v", "2c", "-c", "private", "192.0.2.10", "1.3.6.1.2.1"]
        assert sandbox.requests[0].tool_request.tool_name == "snmpwalk"
        assert sandbox.requests[0].tool_request.action == "walk"

    def test_system_info_uses_system_oid(self) -> None:
        """System info should use system OID."""

        sandbox = FakeSandbox()
        wrapper = SnmpwalkWrapper(sandbox)

        wrapper.system_info(target=make_target(), session=make_session())

        assert sandbox.requests[0].command[-1] == "1.3.6.1.2.1.1"

    def test_missing_community_falls_back_to_public(self) -> None:
        """An empty community falls back to "public" rather than raising.

        F2: the CONTRACT declares community as optional with default "public",
        so the wrapper must apply that default — a contract that advertises a
        default while the wrapper raises is exactly the drift this workstream
        removes. "public" is also the right first guess for an autonomous run.
        """

        wrapper = SnmpwalkWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(), action="walk", community="", oid="1.3.6.1", version="2c"
        )

        assert command.command == ["snmpwalk", "-v", "2c", "-c", "public", "192.0.2.10", "1.3.6.1"]


class TestEnum4LinuxWrapper:
    """Validate enum4linux wrapper."""

    def test_default_config(self) -> None:
        """enum4linux should use network defaults."""

        wrapper = Enum4LinuxWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "enum4linux"
        assert wrapper.config.image == "saber/enum4linux:latest"
        assert wrapper.config.phase == AssessmentPhase.NETWORK
        assert wrapper.config.category == RequestedActionCategory.NETWORK

    def test_full_enum_command(self) -> None:
        """Full enum command should include -a."""

        wrapper = Enum4LinuxWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_target(), action="full_enum")

        assert command.command == ["enum4linux", "-o", "-a", "192.0.2.10"]
        assert command.evidence_relative_dir == "network/enum4linux/full"

    def test_users_command_with_creds(self) -> None:
        """Users command should include username and password while metadata redacts password."""

        wrapper = Enum4LinuxWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="users",
            username="alice",
            password="secret",
        )

        assert command.command == ["enum4linux", "-o", "-U", "-u", "alice", "-p", "secret", "192.0.2.10"]
        assert command.metadata["password"] == "<redacted>"

    def test_shares_delegates_to_sandbox(self) -> None:
        """Shares method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = Enum4LinuxWrapper(sandbox)

        wrapper.shares(target=make_target(), session=make_session())

        assert sandbox.requests[0].command == ["enum4linux", "-o", "-S", "192.0.2.10"]
        assert sandbox.requests[0].tool_request.action == "shares"

    def test_unsupported_action_raises(self) -> None:
        """Unsupported action should raise."""

        wrapper = Enum4LinuxWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported enum4linux action"):
            wrapper.build_command(target=make_target(), action="bad")


class TestResponderWrapper:
    """Validate Responder wrapper."""

    def test_default_config(self) -> None:
        """Responder should use network defaults."""

        wrapper = ResponderWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "responder"
        assert wrapper.config.image == "saber/responder:latest"
        assert wrapper.config.phase == AssessmentPhase.NETWORK

    def test_analyze_command(self) -> None:
        """Analyze mode should append -A and not require explicit auth."""

        wrapper = ResponderWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_target(), action="listen", interface="eth0", analyze_only=True)

        assert command.command == ["responder", "-I", "eth0", "-A"]
        assert command.requires_explicit_authorization is False

    def test_listen_command_requires_auth_when_not_analyze_only(self) -> None:
        """Non-analyze listener should be marked explicit authorization."""

        wrapper = ResponderWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_target(), action="listen", interface="eth0", analyze_only=False)

        assert command.command == ["responder", "-I", "eth0"]
        assert command.requires_explicit_authorization is True

    def test_analyze_delegates_to_sandbox(self) -> None:
        """Analyze method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = ResponderWrapper(sandbox)

        wrapper.analyze(target=make_target(), session=make_session(), interface="eth0")

        assert sandbox.requests[0].command == ["responder", "-I", "eth0", "-A"]
        assert sandbox.requests[0].tool_request.action == "listen"

    def test_missing_interface_raises(self) -> None:
        """Missing interface should raise."""

        wrapper = ResponderWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="interface is required"):
            wrapper.build_command(target=make_target(), action="listen", interface="")


class TestBettercapWrapper:
    """Validate Bettercap wrapper."""

    def test_default_config(self) -> None:
        """Bettercap should use network defaults."""

        wrapper = BettercapWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "bettercap"
        assert wrapper.config.image == "saber/bettercap:latest"
        assert wrapper.config.phase == AssessmentPhase.NETWORK

    def test_net_probe_command(self) -> None:
        """Net probe command should use bettercap eval."""

        wrapper = BettercapWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_target(), action="net_probe", interface="eth0")

        assert command.command == ["bettercap", "-iface", "eth0", "-eval", "net.probe on; sleep 10; net.show; quit"]
        assert command.requires_explicit_authorization is False

    def test_net_recon_delegates_to_sandbox(self) -> None:
        """Net recon method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = BettercapWrapper(sandbox)

        wrapper.net_recon(target=make_target(), session=make_session(), interface="eth0")

        assert sandbox.requests[0].command == ["bettercap", "-iface", "eth0", "-eval", "net.recon on; sleep 10; net.show; quit"]
        assert sandbox.requests[0].tool_request.action == "net_recon"

    def test_caplet_requires_auth(self) -> None:
        """Caplet execution should be marked explicit authorization."""

        wrapper = BettercapWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="caplet",
            interface="eth0",
            caplet_path="caplets/netmon.cap",
        )

        assert command.command == ["bettercap", "-iface", "eth0", "-caplet", "caplets/netmon.cap"]
        assert command.requires_explicit_authorization is True

    def test_missing_caplet_path_raises(self) -> None:
        """Missing caplet path should raise."""

        wrapper = BettercapWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="caplet_path is required"):
            wrapper.build_command(target=make_target(), action="caplet", interface="eth0", caplet_path="")


class TestOpenVASApiWrapper:
    """Validate OpenVAS API wrapper."""

    def test_default_config(self) -> None:
        """OpenVAS API should use network defaults."""

        wrapper = OpenVASApiWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "openvas_api"
        assert wrapper.config.image == "saber/openvas-api:latest"
        assert wrapper.config.phase == AssessmentPhase.NETWORK

    def test_create_target_command(self) -> None:
        """Create target command should include name and hosts."""

        wrapper = OpenVASApiWrapper(FakeSandbox())
        command = wrapper.build_command(target=make_target(), action="create_target", name="lab-host")

        assert command.command == ["openvas-cli", "target-create", "--name", "lab-host", "--hosts", "192.0.2.10"]
        assert command.action == "create_target"

    def test_create_task_command(self) -> None:
        """Create task command should include target and scan config IDs."""

        wrapper = OpenVASApiWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="create_task",
            name="lab-task",
            target_id="target-1",
            scan_config_id="config-1",
        )

        assert command.command == [
            "openvas-cli",
            "task-create",
            "--name",
            "lab-task",
            "--target-id",
            "target-1",
            "--scan-config-id",
            "config-1",
        ]
        assert command.metadata["target_id"] == "target-1"

    def test_start_task_delegates_to_sandbox(self) -> None:
        """Start task method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = OpenVASApiWrapper(sandbox)

        wrapper.start_task(target=make_target(), session=make_session(), task_id="task-1")

        assert sandbox.requests[0].command == ["openvas-cli", "task-start", "--task-id", "task-1"]
        assert sandbox.requests[0].tool_request.action == "start_task"

    def test_get_report_command(self) -> None:
        """Get report command should include report ID and format."""

        wrapper = OpenVASApiWrapper(FakeSandbox())
        command = wrapper.build_command(action="get_report", report_id="report-1", output_format="json")

        assert command.command == ["openvas-cli", "report-get", "--report-id", "report-1", "--format", "json"]

    def test_bad_report_format_raises(self) -> None:
        """Bad report format should raise."""

        wrapper = OpenVASApiWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="output_format must be one of"):
            wrapper.build_command(action="get_report", report_id="report-1", output_format="html")


class TestCustomConfigs:
    """Validate custom config support."""

    def test_custom_snmpwalk_config(self) -> None:
        """SNMPWalk should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_snmpwalk",
            image="custom/snmpwalk:dev",
            phase=AssessmentPhase.NETWORK,
            category=RequestedActionCategory.NETWORK,
            requested_by="CustomSNMP",
        )

        wrapper = SnmpwalkWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_snmpwalk"
        assert wrapper.config.image == "custom/snmpwalk:dev"


class TestToolCommandValidation:
    """Validate ToolCommand remains available."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
