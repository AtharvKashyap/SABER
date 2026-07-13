"""Tests for SABER LLM decision engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saber.agents.llm_decision import LlmDecisionType
from saber.agents.llm_decision_engine import LlmDecisionContext, LlmDecisionEngine
from saber.core.llm_client import LlmClient, LlmConfig, LlmProvider
from saber.core.prompt_loader import PromptLoader
from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry


@dataclass
class FakeLlmClient(LlmClient):
    """Fake enabled LLM client."""

    response: dict[str, Any]

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        super().__init__(
            LlmConfig(
                provider=LlmProvider.OPENROUTER,
                model="anthropic/claude-3.5-sonnet",
                api_key="test-key",
                base_url="https://example.test/v1",
            )
        )

    def complete_json(self, **kwargs: Any) -> dict[str, Any]:
        self.last_kwargs = kwargs
        return self.response


def test_llm_decision_engine_accepts_direct_decision(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "common_agent_policy.txt").write_text("COMMON", encoding="utf-8")
    (prompt_dir / "recon_agent.txt").write_text("RECON", encoding="utf-8")

    engine = LlmDecisionEngine(
        llm_client=FakeLlmClient(
            {
                "decision": "run_tool",
                "agent": "recon_agent",
                "tool_name": "nmap",
                "tool_action": "service_scan",
                "args": {"target": "127.0.0.1"},
                "requires_approval": False,
                "risk": "low",
                "reason": "Need baseline service discovery.",
                "expected_evidence": "Open ports and services.",
                "handoff_agent": None,
            }
        ),
        tool_catalog=ToolCatalog.from_registry(build_default_registry()),
        prompt_loader=PromptLoader(prompt_dir),
    )

    result = engine.decide(
        LlmDecisionContext(
            agent_name="recon_agent",
            objective="Perform recon.",
            target={"type": "host", "value": "127.0.0.1"},
        )
    )

    assert result.valid is True
    assert result.decision.decision == LlmDecisionType.RUN_TOOL
    assert result.decision.tool_name == "nmap"
    assert result.decision.tool_action == "service_scan"
    assert "COMMON" in result.system_prompt
    assert "RECON" in result.system_prompt
    assert "tool_catalog" in result.user_prompt


def test_llm_decision_engine_normalizes_rich_selected_action(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "web_agent.txt").write_text("WEB", encoding="utf-8")

    engine = LlmDecisionEngine(
        llm_client=FakeLlmClient(
            {
                "agent": "ToolSelectionAgent",
                "selected_action": {
                    "id": "act_1",
                    "decision": "request_approval",
                    "tool": "nuclei",
                    "action": "template_scan",
                    "target": {"type": "url", "value": "http://127.0.0.1"},
                    "arguments": {"target": "http://127.0.0.1"},
                    "risk_level": "moderate",
                    "requires_approval": True,
                    "expected_evidence": ["Matched templates"],
                    "stop_conditions": ["approval denied"],
                    "handoff_target": "reporter_agent",
                },
            }
        ),
        tool_catalog=ToolCatalog.from_registry(build_default_registry()),
        prompt_loader=PromptLoader(prompt_dir),
    )

    result = engine.decide(
        LlmDecisionContext(
            agent_name="web_agent",
            objective="Assess web service.",
            target={"type": "url", "value": "http://127.0.0.1"},
        )
    )

    assert result.valid is True
    assert result.decision.decision == LlmDecisionType.REQUEST_APPROVAL
    assert result.decision.tool_name == "nuclei"
    assert result.decision.tool_action == "template_scan"
    assert result.decision.risk.value == "medium"
    assert result.validation.normalized_requires_approval is True


def test_llm_decision_engine_rejects_unknown_tool(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()

    engine = LlmDecisionEngine(
        llm_client=FakeLlmClient(
            {
                "decision": "run_tool",
                "agent": "recon_agent",
                "tool_name": "made_up_tool",
                "tool_action": "scan_everything",
                "args": {},
                "risk": "low",
            }
        ),
        tool_catalog=ToolCatalog.from_registry(build_default_registry()),
        prompt_loader=PromptLoader(prompt_dir),
    )

    result = engine.decide(
        LlmDecisionContext(
            agent_name="recon_agent",
            objective="Perform recon.",
            target={"type": "host", "value": "127.0.0.1"},
        )
    )

    assert result.valid is False
    assert "unknown tool/action" in result.validation.errors[0]
