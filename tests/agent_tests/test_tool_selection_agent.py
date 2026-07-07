"""Tests for ToolSelectionAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.tool_selection_agent import ToolSelection, ToolSelectionAgent
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.registry import ToolRegistry


@dataclass
class FakeSandbox:
    """Fake sandbox."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_session() -> MissionSession:
    """Create session."""

    return MissionSession(
        session_id="tool_selection_session_1",
        mission_name="Tool Selection Agent Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target(target_type: TargetType = TargetType.HOST, value: str = "example.com") -> Target:
    """Create target."""

    return Target(type=target_type, value=value)


def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create sandbox result."""

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


def make_context(
    objective: str,
    observations: list[AgentObservation] | None = None,
    metadata: dict | None = None,
    target: Target | None = None,
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=target or make_target(),
        sandbox=FakeSandbox(),
        tool_registry=ToolRegistry([]),
        objective=objective,
        phase=AssessmentPhase.RECON,
        observations=observations or [],
        metadata=metadata or {},
    )


class TestToolSelectionModel:
    """Validate ToolSelection model."""

    def test_validates_tool_name(self) -> None:
        """Empty tool name should raise."""

        with pytest.raises(ValueError, match="ToolSelection.tool_name cannot be empty"):
            ToolSelection(tool_name="", action="scan")

    def test_validates_action(self) -> None:
        """Empty action should raise."""

        with pytest.raises(ValueError, match="ToolSelection.action cannot be empty"):
            ToolSelection(tool_name="nmap", action="")

    def test_to_tool_call_and_dict(self) -> None:
        """Selection should convert to tool call and dict."""

        selection = ToolSelection(
            tool_name="nmap",
            action="service_scan",
            args={"ports": "1-1000"},
            reason="Need service scan.",
            metadata={"rule": "service"},
        )

        call = selection.to_tool_call()
        data = selection.to_dict()

        assert call.tool_name == "nmap"
        assert call.action == "service_scan"
        assert call.args == {"ports": "1-1000"}
        assert data["tool_name"] == "nmap"
        assert data["metadata"] == {"rule": "service"}


class TestToolSelectionAgent:
    """Validate ToolSelectionAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = ToolSelectionAgent()

        assert agent.config.name == "tool_selection_agent"
        assert agent.config.phase == AssessmentPhase.RECON
        assert agent.config.prompt_path == "prompts/tool_selection_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "tool_selection"

    def test_selects_nmap_for_service_scan(self) -> None:
        """Service scan objective should select nmap."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(make_context("Run service scan for open ports."))

        assert selection is not None
        assert selection.tool_name == "nmap"
        assert selection.action == "service_scan"
        assert selection.args["ports"] == "1-1000"
        assert selection.metadata["selection_rule"] == "service_discovery"

    def test_selects_subfinder_for_subdomains(self) -> None:
        """Subdomain objective should select subfinder."""

        agent = ToolSelectionAgent()
        target = make_target(TargetType.DOMAIN, "example.com")

        selection = agent.select_tool(make_context("Find subdomains.", target=target))

        assert selection is not None
        assert selection.tool_name == "subfinder"
        assert selection.action == "passive"
        assert selection.args["domain"] == "example.com"

    def test_selects_feroxbuster_for_content_discovery(self) -> None:
        """Content discovery objective should select feroxbuster."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(make_context("Run directory content discovery."))

        assert selection is not None
        assert selection.tool_name == "feroxbuster"
        assert selection.action == "directory_bruteforce"
        assert selection.args["wordlist"] == "wordlists/common.txt"

    def test_selects_sqlmap_for_sqli(self) -> None:
        """SQL injection objective should select sqlmap."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(make_context("Validate possible SQL injection."))

        assert selection is not None
        assert selection.tool_name == "sqlmap"
        assert selection.action == "test_url"
        assert selection.args == {"risk": 1, "level": 1, "batch": True}

    def test_selects_zap_active_scan_with_approval(self) -> None:
        """ZAP active scan should require approval."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(make_context("Run ZAP active scan."))

        assert selection is not None
        assert selection.tool_name == "zap_api"
        assert selection.action == "active_scan"
        assert selection.requires_approval is True

    def test_selects_searchsploit_for_cve(self) -> None:
        """CVE objective should select SearchSploit."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(make_context("Look up CVE-2024-0001 exploit references."))

        assert selection is not None
        assert selection.tool_name == "searchsploit"
        assert selection.action == "cve_search"
        assert selection.args["cve_id"] == "CVE-2024-0001"

    def test_selects_checksec_with_binary_path_metadata(self) -> None:
        """Checksec objective should use binary path metadata."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(
            make_context(
                "Run checksec for binary hardening.",
                metadata={"binary_path": "samples/app"},
            )
        )

        assert selection is not None
        assert selection.tool_name == "checksec"
        assert selection.action == "binary"
        assert selection.args["binary_path"] == "samples/app"

    def test_custom_cli_selection_requires_approval(self) -> None:
        """Custom CLI selection should require approval."""

        agent = ToolSelectionAgent()

        selection = agent.select_tool(
            make_context(
                "Run custom CLI one-off command.",
                metadata={
                    "command": "curl -I https://example.com",
                    "reason": "Need headers.",
                    "expected_output": "headers",
                    "risk_level": "low",
                },
            )
        )

        assert selection is not None
        assert selection.tool_name == "custom_cli"
        assert selection.action == "run_command"
        assert selection.requires_approval is True
        assert selection.args["command"] == "curl -I https://example.com"

    def test_decide_returns_tool_decision(self) -> None:
        """Decision should wrap selection as tool call."""

        agent = ToolSelectionAgent()

        decision = agent.decide(make_context("Run service scan for open ports."))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "nmap"
        assert decision.metadata["selection"]["tool_name"] == "nmap"

    def test_decide_returns_stop_when_no_selection(self) -> None:
        """Unknown objective should stop."""

        agent = ToolSelectionAgent()

        decision = agent.decide(make_context("Do something totally undefined."))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "no_tool_selected"

    def test_run_approval_selection_returns_needs_approval(self) -> None:
        """Approval-required selection should return NEEDS_APPROVAL."""

        agent = ToolSelectionAgent()

        result = agent.run(make_context("Run ZAP active scan."))

        assert result.status == AgentRunStatus.NEEDS_APPROVAL
        assert result.decision.requires_approval is True
