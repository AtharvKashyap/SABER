"""Guard the execute_tool CALL SITE, not just the helper it uses.

`tests/agent_tests/test_execute_tool_args.py` tests `BaseAgent._safe_tool_args` in
isolation. The bug it documents was in `execute_tool` PASSING `target=` twice —
rewriting that call to use `dict(...)` instead of `_safe_tool_args(...)` reintroduces
the live defect and the isolated test still passes.

So this drives the real path: a decider-shaped args dict containing a reserved key,
through a real wrapper from the real registry, against a fake sandbox.
"""

from typing import Any

from saber.agents.base_agent import AgentConfig, AgentContext, AgentToolCall, BaseAgent
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.tools.registry import build_default_registry


class _FakeSandbox:
    """Captures the built request instead of executing anything."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    def execute(self, request: Any) -> Any:
        self.requests.append(request)
        return type(
            "R",
            (),
            {"allowed": True, "return_code": 0, "reason": "ok", "metadata": {}, "stdout": ""},
        )()


class _Agent(BaseAgent):
    """Minimal concrete agent; execute_tool lives on the base class."""

    def __init__(self) -> None:
        super().__init__(
            config=AgentConfig(
                name="test_agent",
                phase=AssessmentPhase.RECON,
                description="test",
            )
        )

    def decide(self, context):  # pragma: no cover - not used by these tests
        raise NotImplementedError


def _context(sandbox: _FakeSandbox) -> AgentContext:
    return AgentContext(
        session=MissionSession(session_id="s", mission_name="m"),
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        sandbox=sandbox,
        tool_registry=build_default_registry(),
        objective="scan",
        phase=AssessmentPhase.RECON,
        observations=[],
        constraints={},
        metadata={},
    )


def test_reserved_target_in_args_does_not_raise_and_real_args_survive():
    """The exact live bug: a decider-supplied "target" collided with run(target=...).

    Without the strip this raises TypeError: got multiple values for argument 'target'
    — and the loop would record a failed step for a perfectly valid action.
    """

    sandbox = _FakeSandbox()
    agent = _Agent()

    agent.execute_tool(
        context=_context(sandbox),
        tool_call=AgentToolCall(
            tool_name="nmap",
            action="service_scan",
            # A decider that helpfully echoes the target used to kill the call.
            args={"target": "10.0.0.5", "ports": "1-1000"},
            reason="scan",
        ),
    )

    assert sandbox.requests, "the tool call never reached the sandbox"
    command = sandbox.requests[0].command
    # The real arg must survive the reserved-key strip.
    assert "1-1000" in command, command
    # The loop's Target, not the decider's echo, decides the destination.
    assert command[-1] == "10.0.0.5"


def test_all_reserved_keys_are_stripped_at_the_call_site():
    sandbox = _FakeSandbox()
    agent = _Agent()

    agent.execute_tool(
        context=_context(sandbox),
        tool_call=AgentToolCall(
            tool_name="nmap",
            action="service_scan",
            args={
                "target": "evil.example.com",
                "session": "nonsense",
                "action": "nonsense",
                "metadata": {"injected": True},
                "ports": "80",
            },
            reason="scan",
        ),
    )

    command = sandbox.requests[0].command
    assert "evil.example.com" not in command, "a decider-supplied target overrode the loop's"
    assert "80" in command


def test_execute_tool_still_uses_the_reserved_kwarg_filter():
    """Structural guard: the mutation that swapped in dict(...) passed every test."""

    import inspect

    source = inspect.getsource(BaseAgent.execute_tool)
    assert "_safe_tool_args" in source, "execute_tool no longer filters reserved kwargs"
