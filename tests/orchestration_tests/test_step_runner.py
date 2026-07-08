"""Tests for StepRunner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    AgentRunResult,
    AgentRunStatus,
    BaseAgent,
)
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunRecord, StepRunner
from saber.tools.registry import ToolRegistry


@dataclass
class FakeSandbox:
    """Fake sandbox."""

    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request."""

        self.requests.append(request)
        return SandboxExecutionResult(
            outcome=SandboxOutcome.EXECUTED,
            allowed=True,
            session=request.session,
            evidence=None,
            return_code=0,
            stdout="ok",
            stderr="",
            reason="ok",
            metadata={"backend": "fake"},
        )


class StaticAgent(BaseAgent):
    """Agent returning static result."""

    def __init__(self, name: str, phase: AssessmentPhase, result_status: AgentRunStatus) -> None:
        """Initialize static agent."""

        super().__init__(AgentConfig(name=name, phase=phase))
        self.result_status = result_status
        self.contexts: list[AgentContext] = []

    def decide(self, context: AgentContext) -> AgentDecision:
        """Return decision based on configured status."""

        self.contexts.append(context)

        if self.result_status == AgentRunStatus.HANDOFF:
            return AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=context.objective,
                handoff_agent="web_agent",
                message="Hand off.",
            )

        if self.result_status == AgentRunStatus.NEEDS_APPROVAL:
            return AgentDecision(
                action_type=AgentActionType.ASK_APPROVAL,
                objective=context.objective,
                requires_approval=True,
                message="Approval needed.",
            )

        if self.result_status == AgentRunStatus.STOPPED:
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=context.objective,
                message="Stopped.",
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=context.objective,
            message="Completed decision.",
        )

    def run(self, context: AgentContext) -> AgentRunResult:
        """Return configured run result."""

        self.contexts.append(context)

        if self.result_status == AgentRunStatus.HANDOFF:
            decision = AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=context.objective,
                handoff_agent="web_agent",
                message="Hand off.",
            )
        elif self.result_status == AgentRunStatus.NEEDS_APPROVAL:
            decision = AgentDecision(
                action_type=AgentActionType.ASK_APPROVAL,
                objective=context.objective,
                requires_approval=True,
                message="Approval needed.",
            )
        elif self.result_status == AgentRunStatus.FAILED:
            decision = AgentDecision(
                action_type=AgentActionType.STOP,
                objective=context.objective,
                message="Failed.",
            )
        else:
            decision = AgentDecision(
                action_type=AgentActionType.STOP,
                objective=context.objective,
                message="Done.",
            )

        observations = [
            AgentObservation(
                summary=f"{self.config.name} observation.",
                tool_name=None,
                action=None,
                success=self.result_status != AgentRunStatus.FAILED,
                metadata={"agent": self.config.name},
            )
        ]

        return AgentRunResult(
            agent_name=self.config.name,
            status=self.result_status,
            decision=decision,
            observations=observations,
            metadata={"agent": self.config.name},
        )


class ExplodingAgent(BaseAgent):
    """Agent that raises."""

    def __init__(self) -> None:
        """Initialize exploding agent."""

        super().__init__(AgentConfig(name="exploding_agent", phase=AssessmentPhase.RECON))

    def decide(self, context: AgentContext) -> AgentDecision:
        """Unused."""

        raise RuntimeError("boom")

    def run(self, context: AgentContext) -> AgentRunResult:
        """Raise."""

        raise RuntimeError("boom")


def make_session() -> MissionSession:
    """Create session."""

    return MissionSession(
        session_id="step_runner_session_1",
        mission_name="Step Runner Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_step(agent_name: str = "test_agent") -> ExecutionStep:
    """Create step."""

    return ExecutionStep(
        step_id="step1",
        agent_name=agent_name,
        objective="Run test step.",
        phase=AssessmentPhase.RECON,
        target=make_target(),
    )


def make_runner(agent: BaseAgent, name: str = "test_agent") -> StepRunner:
    """Create runner."""

    return StepRunner(
        agents={name: agent},
        tool_registry=ToolRegistry([]),
        sandbox=FakeSandbox(),
    )


class TestStepRunRecord:
    """Validate StepRunRecord."""

    def test_to_dict(self) -> None:
        """Record should serialize."""

        decision = AgentDecision(action_type=AgentActionType.STOP, objective="Stop.", message="Done.")
        result = AgentRunResult(
            agent_name="test_agent",
            status=AgentRunStatus.STOPPED,
            decision=decision,
            observations=[],
        )
        record = StepRunRecord(
            step_id="step1",
            agent_name="test_agent",
            status=ExecutionStepStatus.STOPPED,
            agent_result=result,
            new_observations=[AgentObservation(summary="Observed.", metadata={"time": datetime.now(UTC).isoformat()})],
            metadata={"key": "value"},
        )

        data = record.to_dict()

        assert data["step_id"] == "step1"
        assert data["status"] == "stopped"
        assert data["new_observations"][0]["summary"] == "Observed."
        assert data["metadata"]["key"] == "value"


class TestStepRunner:
    """Validate StepRunner."""

    def test_requires_agents(self) -> None:
        """StepRunner should require agents."""

        with pytest.raises(ValueError, match="requires at least one agent"):
            StepRunner(agents={}, tool_registry=ToolRegistry([]), sandbox=FakeSandbox())

    @pytest.mark.parametrize(
        ("agent_status", "expected_step_status"),
        [
            (AgentRunStatus.COMPLETED, ExecutionStepStatus.COMPLETED),
            (AgentRunStatus.NEEDS_APPROVAL, ExecutionStepStatus.NEEDS_APPROVAL),
            (AgentRunStatus.HANDOFF, ExecutionStepStatus.HANDOFF),
            (AgentRunStatus.STOPPED, ExecutionStepStatus.STOPPED),
            (AgentRunStatus.FAILED, ExecutionStepStatus.FAILED),
        ],
    )
    def test_maps_agent_statuses(
        self,
        agent_status: AgentRunStatus,
        expected_step_status: ExecutionStepStatus,
    ) -> None:
        """Agent statuses should map to execution step statuses."""

        agent = StaticAgent("test_agent", AssessmentPhase.RECON, agent_status)
        runner = make_runner(agent)

        record = runner.run_step(
            step=make_step(),
            session=make_session(),
            target=make_target(),
            observations=[],
        )

        assert record.status == expected_step_status
        assert record.agent_name == "test_agent"
        assert record.new_observations[0].metadata["agent"] == "test_agent"

    def test_builds_agent_context(self) -> None:
        """StepRunner should pass correct context into agent."""

        agent = StaticAgent("test_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED)
        runner = make_runner(agent)
        observation = AgentObservation(summary="Existing observation.")

        runner.run_step(
            step=make_step(),
            session=make_session(),
            target=make_target(),
            observations=[observation],
            constraints={"max_depth": 2},
            metadata={"run_id": "abc"},
        )

        context = agent.contexts[0]

        assert context.objective == "Run test step."
        assert context.phase == AssessmentPhase.RECON
        assert context.observations == [observation]
        assert context.constraints == {"max_depth": 2}
        assert context.metadata["step_id"] == "step1"
        assert context.metadata["run_id"] == "abc"

    def test_handoff_record_includes_handoff_agent(self) -> None:
        """Handoff result should include handoff agent."""

        agent = StaticAgent("test_agent", AssessmentPhase.RECON, AgentRunStatus.HANDOFF)
        runner = make_runner(agent)

        record = runner.run_step(make_step(), make_session(), make_target(), [])

        assert record.status == ExecutionStepStatus.HANDOFF
        assert record.handoff_agent == "web_agent"

    def test_approval_record_sets_requires_approval(self) -> None:
        """Approval result should set requires_approval."""

        agent = StaticAgent("test_agent", AssessmentPhase.RECON, AgentRunStatus.NEEDS_APPROVAL)
        runner = make_runner(agent)

        record = runner.run_step(make_step(), make_session(), make_target(), [])

        assert record.status == ExecutionStepStatus.NEEDS_APPROVAL
        assert record.requires_approval is True

    def test_missing_agent_raises_failure_record(self) -> None:
        """Missing agent should return failed record."""

        runner = StepRunner(
            agents={"other_agent": StaticAgent("other_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED)},
            tool_registry=ToolRegistry([]),
            sandbox=FakeSandbox(),
        )

        with pytest.raises(KeyError, match="Agent not registered"):
            runner.run_step(make_step(agent_name="missing_agent"), make_session(), make_target(), [])

    def test_agent_exception_returns_failed_record(self) -> None:
        """Agent exception should be captured as failed record."""

        runner = make_runner(ExplodingAgent(), name="exploding_agent")

        record = runner.run_step(
            step=make_step(agent_name="exploding_agent"),
            session=make_session(),
            target=make_target(),
            observations=[],
        )

        assert record.status == ExecutionStepStatus.FAILED
        assert record.agent_result.status == AgentRunStatus.FAILED
        assert record.metadata["error"] == "boom"
        assert record.metadata["error_type"] == "RuntimeError"
