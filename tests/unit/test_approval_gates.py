"""Approval gate tests for high-risk SABER actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentRunStatus,
    AgentToolCall,
    BaseAgent,
)
from saber.agents.exploit_agent import ExploitAgent
from saber.agents.network_agent import NetworkAgent
from saber.agents.recon_agent import ReconAgent
from saber.agents.web_agent import WebAgent
from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunner
from saber.tools.exploitation.metasploit import MetasploitWrapper
from saber.tools.registry import ToolRegistry
from saber.tools.web.sqlmap import SqlmapWrapper


@dataclass
class NoExecuteRunner:
    """Runner that fails if anything tries to execute."""

    def run(self, command, **kwargs):
        raise AssertionError(f"Approval-gated test should not execute command: {command}")


class ToolCallApprovalAgent(BaseAgent):
    """Agent that returns TOOL with tool_call.requires_approval=True."""

    def __init__(self) -> None:
        super().__init__(
            AgentConfig(
                name="tool_call_approval_agent",
                phase=AssessmentPhase.EXPLOITATION,
                description="Approval gate test agent.",
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        return AgentDecision(
            action_type=AgentActionType.TOOL,
            objective="Attempt high-risk tool call.",
            requires_approval=False,
            tool_call=AgentToolCall(
                tool_name="metasploit",
                action="run_module",
                args={
                    "module": "exploit/test/module",
                    "options": {"RHOSTS": context.target.tool_value()},
                },
                reason="High-risk action must pause.",
                requires_approval=True,
            ),
        )


class DecisionApprovalAgent(BaseAgent):
    """Agent that returns ASK_APPROVAL."""

    def __init__(self) -> None:
        super().__init__(
            AgentConfig(
                name="decision_approval_agent",
                phase=AssessmentPhase.EXPLOITATION,
                description="Approval gate test agent.",
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective="Request approval.",
            requires_approval=True,
            message="Approval required.",
            tool_call=AgentToolCall(
                tool_name="custom_cli",
                action="run_command",
                args={"command": "id"},
                reason="Custom command requires approval.",
                requires_approval=True,
            ),
        )


def _context(agent: BaseAgent) -> AgentContext:
    return AgentContext(
        session=MissionSession(
            session_id="approval_test_session",
            mission_name="Approval Gate Test",
        ),
        target=Target(type=TargetType.HOST, value="127.0.0.1"),
        sandbox=Sandbox(EvidenceStore("runs/test-evidence"), NoExecuteRunner()),
        tool_registry=ToolRegistry(),
        objective="Approval gate test.",
        phase=agent.config.phase,
        observations=[],
        constraints={"agent_mode": "deterministic"},
        metadata={},
    )


def test_webagent_sqlmap_schema_dump_requires_approval() -> None:
    decision = WebAgent().build_sqlmap_schema_approval_decision(reason="Need schema enumeration.")

    assert decision.action_type == AgentActionType.ASK_APPROVAL
    assert decision.requires_approval is True
    assert decision.tool_call is not None
    assert decision.tool_call.tool_name == "sqlmap"
    assert decision.tool_call.action == "dump_schema"
    assert decision.tool_call.requires_approval is True


def test_webagent_zap_active_scan_requires_approval() -> None:
    decision = WebAgent().build_zap_active_scan_approval_decision(reason="Need active scan.")

    assert decision.action_type == AgentActionType.ASK_APPROVAL
    assert decision.requires_approval is True
    assert decision.tool_call is not None
    assert decision.tool_call.tool_name == "zap_api"
    assert decision.tool_call.action == "active_scan"
    assert decision.tool_call.requires_approval is True


def test_networkagent_responder_and_bettercap_require_approval() -> None:
    responder = NetworkAgent().build_responder_approval_decision(
        interface="eth0",
        reason="Capture workflow.",
    )
    bettercap = NetworkAgent().build_bettercap_approval_decision(
        interface="eth0",
        reason="Network manipulation workflow.",
    )

    for decision in [responder, bettercap]:
        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.requires_approval is True


def test_reconagent_custom_cli_requires_approval() -> None:
    decision = ReconAgent().build_custom_cli_decision(
        command="nmap --script vuln 127.0.0.1",
        reason="Custom recon command.",
    )

    assert decision.action_type == AgentActionType.ASK_APPROVAL
    assert decision.requires_approval is True
    assert decision.tool_call is not None
    assert decision.tool_call.tool_name == "custom_cli"
    assert decision.tool_call.requires_approval is True


def test_exploitagent_metasploit_check_and_run_require_approval() -> None:
    agent = ExploitAgent()

    check = agent.build_metasploit_check_decision(
        module="auxiliary/scanner/test",
        options={"RHOSTS": "127.0.0.1"},
    )
    run = agent.build_metasploit_run_decision(
        module="exploit/test/module",
        options={"RHOSTS": "127.0.0.1"},
    )
    custom = agent.build_custom_cli_decision(
        command="python exploit.py",
        reason="Exploit command.",
    )

    for decision in [check, run, custom]:
        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.requires_approval is True


def test_baseagent_blocks_tool_call_requires_approval_without_execution() -> None:
    agent = ToolCallApprovalAgent()
    result = agent.run(_context(agent))

    assert result.status == AgentRunStatus.NEEDS_APPROVAL
    assert result.observations == []
    assert result.metadata["approval_gate"] is True
    assert result.metadata["tool_call_requires_approval"] is True


def test_steprunner_pauses_approval_decision_without_execution(tmp_path) -> None:
    agent = DecisionApprovalAgent()

    step_runner = StepRunner(
        agents={"decision_approval_agent": agent},
        tool_registry=ToolRegistry(),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), NoExecuteRunner()),
    )

    session = MissionSession(
        session_id="approval_step_session",
        mission_name="Approval Step Test",
    )
    target = Target(type=TargetType.HOST, value="127.0.0.1")

    step = ExecutionStep(
        step_id="approval_step",
        agent_name="decision_approval_agent",
        objective="Request high-risk approval.",
        phase=AssessmentPhase.EXPLOITATION,
        target=target,
    )

    record = step_runner.run_step(
        step=step,
        session=session,
        target=target,
        observations=[],
        constraints={"agent_mode": "deterministic"},
        metadata={},
    )

    assert record.status == ExecutionStepStatus.NEEDS_APPROVAL
    assert record.requires_approval is True
    assert record.new_observations == []


def test_high_risk_wrappers_mark_commands_as_requiring_authorization() -> None:
    target = Target(type=TargetType.URL, value="http://example.test/?id=1")

    sqlmap = SqlmapWrapper(sandbox=object())
    dump_schema = sqlmap.build_command(
        target=target,
        action="dump_schema",
        batch=True,
    )
    test_url = sqlmap.build_command(
        target=target,
        action="test_url",
        risk=1,
        level=1,
        batch=True,
    )

    assert dump_schema.requires_explicit_authorization is True
    assert test_url.requires_explicit_authorization is False

    metasploit = MetasploitWrapper(sandbox=object())
    search = metasploit.build_command(
        action="search_modules",
        query="apache",
    )
    check = metasploit.build_command(
        action="check_module",
        module="auxiliary/scanner/test",
        options={"RHOSTS": "127.0.0.1"},
    )
    run = metasploit.build_command(
        action="run_module",
        module="exploit/test/module",
        options={"RHOSTS": "127.0.0.1"},
    )

    assert search.requires_explicit_authorization is False
    assert check.requires_explicit_authorization is True
    assert run.requires_explicit_authorization is True
