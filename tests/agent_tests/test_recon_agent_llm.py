"""Tests for ReconAgent LLM decision mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saber.agents.base_agent import AgentActionType
from saber.agents.llm_decision_engine import LlmDecisionEngine
from saber.agents.recon_agent import ReconAgent
from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider
from saber.core.prompt_loader import PromptLoader
from saber.core.sandbox import Sandbox
from saber.core.evidence_store import EvidenceStore
from saber.core.runtime import LocalSubprocessRunner
from saber.core.tool_catalog import ToolCatalog
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.agents.base_agent import AgentContext
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


def test_recon_agent_uses_llm_decision_in_llm_mode(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "common_agent_policy.txt").write_text("COMMON", encoding="utf-8")
    (prompt_dir / "recon_agent_prompt.txt").write_text("RECON", encoding="utf-8")

    registry = build_default_registry()
    catalog = ToolCatalog.from_registry(registry)

    engine = LlmDecisionEngine(
        llm_client=FakeLlmClient(
            {
                "decision": "run_tool",
                "agent": "recon_agent",
                "tool_name": "nmap",
                "tool_action": "service_scan",
                "args": {"ports": "1-1000"},
                "requires_approval": False,
                "risk": "low",
                "reason": "Need baseline service discovery.",
                "expected_evidence": "Open ports and services.",
            }
        ),
        tool_catalog=catalog,
        prompt_loader=PromptLoader(prompt_dir),
    )

    agent = ReconAgent()
    agent.set_llm_decision_engine(engine)

    context = AgentContext(
        session=MissionSession(session_id="test_session", mission_name="Test Mission"),
        target=Target(type=TargetType.HOST, value="127.0.0.1"),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), LocalSubprocessRunner()),
        tool_registry=registry,
        objective="Perform recon.",
        constraints={"agent_mode": "llm", "profile": "recon"},
    )

    decision = agent.decide(context)

    assert decision.action_type == AgentActionType.TOOL
    assert decision.tool_call is not None
    assert decision.tool_call.tool_name == "nmap"
    assert decision.tool_call.action == "service_scan"
    assert decision.metadata["workflow_step"] == "llm_selected_action"


def test_recon_agent_rejects_invalid_llm_tool(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()

    registry = build_default_registry()
    catalog = ToolCatalog.from_registry(registry)

    engine = LlmDecisionEngine(
        llm_client=FakeLlmClient(
            {
                "decision": "run_tool",
                "agent": "recon_agent",
                "tool_name": "made_up_tool",
                "tool_action": "scan",
                "args": {},
                "risk": "low",
            }
        ),
        tool_catalog=catalog,
        prompt_loader=PromptLoader(prompt_dir),
    )

    agent = ReconAgent()
    agent.set_llm_decision_engine(engine)

    context = AgentContext(
        session=MissionSession(session_id="test_session", mission_name="Test Mission"),
        target=Target(type=TargetType.HOST, value="127.0.0.1"),
        sandbox=Sandbox(EvidenceStore(tmp_path / "evidence"), LocalSubprocessRunner()),
        tool_registry=registry,
        objective="Perform recon.",
        constraints={"agent_mode": "llm", "profile": "recon"},
    )

    decision = agent.decide(context)

    assert decision.action_type == AgentActionType.STOP
    assert decision.metadata["reason"] == "llm_decision_invalid"
