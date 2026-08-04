from saber.agents.base_agent import AgentConfig, BaseAgent
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import MissionState
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutor


class _FakeSandboxResult:
    allowed = True
    return_code = 0
    reason = "ok"
    metadata: dict = {}
    stdout = "PORT 80 open"


class _FakeAgent(BaseAgent):
    def __init__(self):
        super().__init__(AgentConfig(name="recon_agent", phase=AssessmentPhase.RECON))
        self.calls = []

    def decide(self, context):  # pragma: no cover - must NOT be called by executor
        raise AssertionError("executor must not call decide()")

    def execute_tool(self, context, tool_call):
        self.calls.append((tool_call.tool_name, tool_call.action))
        return _FakeSandboxResult()


def _action():
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="nmap",
        tool_action="service_scan",
        args={"target": "10.0.0.5"},
        agent_name="recon_agent",
        objective="scan",
        risk=RiskLevel.LOW,
    )


def test_executor_dispatches_to_named_agent():
    agent = _FakeAgent()
    executor = ActionExecutor(
        agents={"recon_agent": agent}, tool_registry=object(), sandbox=object()
    )
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    session = MissionSession(session_id="s", mission_name="m")

    record = executor.execute(state, session, _action())

    assert agent.calls == [("nmap", "service_scan")]
    assert record.error is None
    assert record.observation.success is True


def test_executor_captures_errors():
    class _Boom(_FakeAgent):
        def execute_tool(self, context, tool_call):
            raise RuntimeError("sandbox down")

    executor = ActionExecutor(
        agents={"recon_agent": _Boom()}, tool_registry=object(), sandbox=object()
    )
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    session = MissionSession(session_id="s", mission_name="m")

    record = executor.execute(state, session, _action())
    assert record.error is not None
    assert record.observation.success is False
