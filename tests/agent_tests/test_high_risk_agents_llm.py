"""LLM-mode safety tests for high-risk SABER agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext
from saber.agents.exploit_agent import ExploitAgent
from saber.agents.lateral_movement_agent import LateralMovementAgent
from saber.agents.llm_decision_engine import LlmDecisionEngine
from saber.agents.post_exploit_agent import PostExploitAgent
from saber.agents.reverse_engineering_agent import ReverseEngineerAgent
from saber.core.evidence_store import EvidenceStore
from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider
from saber.core.prompt_loader import PromptLoader
from saber.core.runtime import LocalSubprocessRunner
from saber.core.sandbox import Sandbox
from saber.core.tool_catalog import ToolCatalog
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.tools.registry import build_default_registry


@dataclass
class FakeLlmClient(LlmClient):
    response: dict[str, Any]

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        super().__init__(
            LlmConfig(
                provider=LlmProvider.OPENAI_COMPATIBLE,
                api_key="test-key",
                base_url="https://example.test/v1",
            )
        )

    def complete_json(self, **kwargs: Any) -> dict[str, Any]:
        return self.response


def _context(tmp_path, registry, *, agent_mode: str = "llm") -> AgentContext:
    return AgentContext(
        session=MissionSession(session_id="test_session", mission_name="Test Mission"),
        target=Target(type=TargetType.HOST, value="127.0.0.1"),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), LocalSubprocessRunner()),
        tool_registry=registry,
        objective="Continue authorized assessment.",
        constraints={
            "agent_mode": agent_mode,
            "profile": "full",
            "execution_mode": "assessment",
            "scope": {"in_scope": ["127.0.0.1"]},
            "roe": {"approval_required": True},
        },
    )


def _engine(tmp_path, registry, response: dict[str, Any]) -> LlmDecisionEngine:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir(exist_ok=True)
    (prompt_dir / "common_agent_policy.txt").write_text("COMMON", encoding="utf-8")
    return LlmDecisionEngine(
        llm_client=FakeLlmClient(response),
        tool_catalog=ToolCatalog.from_registry(registry),
        prompt_loader=PromptLoader(prompt_dir),
    )


@pytest.mark.parametrize(
    ("agent_cls", "tool_name", "tool_action"),
    [
        (ExploitAgent, "sqlmap", "injection_test"),
        (PostExploitAgent, "mimikatz", "default"),
        (LateralMovementAgent, "impacket", "default"),
        (ReverseEngineerAgent, "hashcat", "default"),
    ],
)
def test_high_risk_llm_decisions_are_approval_gated(tmp_path, agent_cls, tool_name, tool_action) -> None:
    registry = build_default_registry()
    engine = _engine(
        tmp_path,
        registry,
        {
            "decision": "run_tool",
            "agent": agent_cls().config.name,
            "tool_name": tool_name,
            "tool_action": tool_action,
            "args": {},
            "requires_approval": False,
            "risk": "high",
            "reason": "High-risk validation requires operator approval.",
            "expected_evidence": "Approval-gated evidence.",
            "handoff_agent": None,
        },
    )

    agent = agent_cls()
    agent.set_llm_decision_engine(engine)

    decision = agent.decide(_context(tmp_path, registry))

    assert decision.action_type == AgentActionType.ASK_APPROVAL
    assert decision.requires_approval is True
    assert decision.tool_call is not None
    assert decision.tool_call.requires_approval is True


def test_high_risk_llm_unknown_tool_stops_safely(tmp_path) -> None:
    registry = build_default_registry()
    agent = ExploitAgent()
    agent.set_llm_decision_engine(
        _engine(
            tmp_path,
            registry,
            {
                "decision": "run_tool",
                "agent": "exploit_agent",
                "tool_name": "evil_fake_tool",
                "tool_action": "own_everything",
                "args": {},
                "requires_approval": False,
                "risk": "high",
                "reason": "Invalid hallucinated action.",
            },
        )
    )

    decision = agent.decide(_context(tmp_path, registry))

    assert decision.action_type == AgentActionType.STOP
    assert decision.metadata["reason"] == "llm_decision_invalid"
