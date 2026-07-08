"""Tests for LLM decision schema/validator."""

from __future__ import annotations

from saber.agents.llm_decision import LlmDecision, LlmDecisionType, LlmDecisionValidator
from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry


def test_llm_decision_from_dict() -> None:
    decision = LlmDecision.from_dict(
        {
            "decision": "run_tool",
            "agent": "recon_agent",
            "tool_name": "nmap",
            "tool_action": "service_scan",
            "args": {"target": "127.0.0.1"},
            "risk": "low",
            "reason": "baseline recon",
        }
    )

    assert decision.decision == LlmDecisionType.RUN_TOOL
    assert decision.tool_name == "nmap"
    assert decision.tool_action == "service_scan"


def test_validator_accepts_known_tool_action() -> None:
    catalog = ToolCatalog.from_registry(build_default_registry())
    validator = LlmDecisionValidator(catalog)

    decision = LlmDecision.from_dict(
        {
            "decision": "run_tool",
            "agent": "recon_agent",
            "tool_name": "nmap",
            "tool_action": "service_scan",
            "args": {"target": "127.0.0.1"},
            "risk": "low",
            "reason": "baseline recon",
        }
    )

    result = validator.validate(decision)

    assert result.valid is True
    assert result.action_spec is not None
    assert result.normalized_requires_approval is False


def test_validator_rejects_unknown_tool_action() -> None:
    catalog = ToolCatalog.from_registry(build_default_registry())
    validator = LlmDecisionValidator(catalog)

    decision = LlmDecision.from_dict(
        {
            "decision": "run_tool",
            "agent": "recon_agent",
            "tool_name": "fake_tool",
            "tool_action": "fake_action",
        }
    )

    result = validator.validate(decision)

    assert result.valid is False
    assert "unknown tool/action" in result.errors[0]


def test_validator_forces_approval_for_risky_catalog_action() -> None:
    catalog = ToolCatalog.from_registry(build_default_registry())
    validator = LlmDecisionValidator(catalog)

    decision = LlmDecision.from_dict(
        {
            "decision": "run_tool",
            "agent": "web_agent",
            "tool_name": "nuclei",
            "tool_action": "template_scan",
            "requires_approval": False,
            "risk": "medium",
        }
    )

    result = validator.validate(decision)

    assert result.valid is True
    assert result.normalized_requires_approval is True
