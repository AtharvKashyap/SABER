"""LLM decision engine for SABER agents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from saber.agents.llm_decision import LlmDecision, LlmDecisionValidationResult, LlmDecisionValidator
from saber.core.llm_client import LlmClient
from saber.core.prompt_loader import PromptLoader
from saber.core.tool_catalog import ToolCatalog


@dataclass(frozen=True)
class LlmDecisionContext:
    """State passed to the LLM decision engine."""

    agent_name: str
    objective: str
    target: dict[str, Any]
    profile: str = "recon"
    execution_mode: str = "assessment"
    scope: dict[str, Any] = field(default_factory=dict)
    roe: dict[str, Any] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    failed_attempts: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_prompt_payload(self, tool_catalog: ToolCatalog) -> dict[str, Any]:
        """Return JSON payload for the LLM."""

        return {
            "agent_name": self.agent_name,
            "objective": self.objective,
            "target": self.target,
            "profile": self.profile,
            "execution_mode": self.execution_mode,
            "scope": self.scope,
            "roe": self.roe,
            "observations": self.observations,
            "findings": self.findings,
            "evidence": self.evidence,
            "approvals": self.approvals,
            "failed_attempts": self.failed_attempts,
            "metadata": self.metadata,
            "tool_catalog": tool_catalog.to_dict(),
            "instruction": (
                "Return one strict JSON decision. Use only exact tool/action names "
                "from tool_catalog. Do not include Markdown."
            ),
        }


@dataclass(frozen=True)
class LlmDecisionEngineResult:
    """Decision engine result."""

    decision: LlmDecision
    validation: LlmDecisionValidationResult
    raw_response: dict[str, Any]
    system_prompt: str
    user_prompt: str

    @property
    def valid(self) -> bool:
        """Return True if validated."""

        return self.validation.valid


class LlmDecisionEngine:
    """Build prompts, call LLM, parse and validate decisions."""

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        tool_catalog: ToolCatalog,
        prompt_loader: PromptLoader | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.tool_catalog = tool_catalog
        self.prompt_loader = prompt_loader or PromptLoader()
        self.validator = LlmDecisionValidator(tool_catalog)

    def decide(self, context: LlmDecisionContext) -> LlmDecisionEngineResult:
        """Ask the configured LLM for one validated decision."""

        if not self.llm_client.enabled:
            raise RuntimeError("LLM decision mode requested, but LLM client is disabled.")

        prompt = self.prompt_loader.load_agent_prompt(context.agent_name)

        system_prompt = prompt.system_prompt
        user_payload = context.to_prompt_payload(self.tool_catalog)
        user_prompt = json.dumps(user_payload, indent=2, sort_keys=True, default=str)

        raw_response = self.llm_client.complete_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            metadata={
                "agent_name": context.agent_name,
                "profile": context.profile,
                "execution_mode": context.execution_mode,
            },
        )

        decision = LlmDecision.from_dict(_normalize_agent_decision(raw_response, context.agent_name))
        validation = self.validator.validate(decision)

        return LlmDecisionEngineResult(
            decision=decision,
            validation=validation,
            raw_response=raw_response,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


def _normalize_agent_decision(raw: dict[str, Any], agent_name: str) -> dict[str, Any]:
    """Normalize detailed agent prompt JSON into generic LlmDecision schema.

    Some SABER prompts return rich objects with recommended_actions or
    selected_action. This extracts a single next decision for the orchestrator.
    """

    if "decision" in raw:
        normalized = dict(raw)
        normalized.setdefault("agent", agent_name)
        return normalized

    selected = raw.get("selected_action")
    if isinstance(selected, dict):
        return _normalize_selected_action(selected, raw, agent_name)

    recommended = raw.get("recommended_actions")
    if isinstance(recommended, list) and recommended:
        first = recommended[0]
        if isinstance(first, dict):
            return _normalize_recommended_action(first, raw, agent_name)

    handoff = raw.get("handoff")
    if isinstance(handoff, dict):
        next_agent = (
            handoff.get("recommended_next_agent")
            or _first_string(handoff.get("handoff_targets"))
            or _first_string(handoff.get("to_reporter_agent"))
        )
        if next_agent:
            return {
                "decision": "handoff",
                "agent": agent_name,
                "handoff_agent": next_agent,
                "reason": handoff.get("reason") or "Agent recommended handoff.",
                "risk": "low",
                "requires_approval": False,
                "args": {},
            }

    return {
        "decision": "stop",
        "agent": agent_name,
        "tool_name": None,
        "tool_action": None,
        "args": {},
        "requires_approval": False,
        "risk": "low",
        "reason": "No executable action was recommended.",
        "expected_evidence": "",
        "handoff_agent": None,
    }


def _normalize_selected_action(selected: dict[str, Any], raw: dict[str, Any], agent_name: str) -> dict[str, Any]:
    """Normalize selected_action object."""

    decision = selected.get("decision") or ("request_approval" if selected.get("requires_approval") else "run_tool")
    tool_name = selected.get("tool") or selected.get("tool_name")
    tool_action = selected.get("action") or selected.get("tool_action")

    reason = (
        selected.get("reason")
        or _first_string(raw.get("summary", {}).get("notes") if isinstance(raw.get("summary"), dict) else None)
        or selected.get("reason_selected_or_rejected")
        or f"{tool_name}/{tool_action} was selected as the next action."
    )

    return {
        "decision": decision,
        "agent": agent_name,
        "tool_name": tool_name,
        "tool_action": tool_action,
        "args": selected.get("arguments") or selected.get("args") or {},
        "requires_approval": bool(selected.get("requires_approval", False)),
        "risk": _risk(selected.get("risk_level") or selected.get("risk")),
        "reason": reason,
        "expected_evidence": _join(selected.get("expected_evidence")),
        "handoff_agent": selected.get("handoff_target") or selected.get("handoff_agent"),
    }


def _normalize_recommended_action(action: dict[str, Any], raw: dict[str, Any], agent_name: str) -> dict[str, Any]:
    """Normalize first recommended action."""

    requires_approval = bool(action.get("requires_approval", False))
    decision = "request_approval" if requires_approval else "run_tool"

    return {
        "decision": decision,
        "agent": agent_name,
        "tool_name": action.get("tool") or action.get("tool_name"),
        "tool_action": action.get("action") or action.get("tool_action"),
        "args": action.get("arguments") or action.get("args") or {},
        "requires_approval": requires_approval,
        "risk": _risk(action.get("risk_level") or action.get("risk")),
        "reason": _first_string(raw.get("summary", {}).get("notes")) or "Agent recommended next action.",
        "expected_evidence": _join(action.get("expected_evidence")),
        "handoff_agent": _first_string(action.get("handoff_targets")),
    }


def _risk(value: Any) -> str:
    """Normalize risk words."""

    text = str(value or "low").strip().lower()
    if text == "moderate":
        return "medium"
    if text in {"low", "medium", "high"}:
        return text
    return "low"


def _join(value: Any) -> str:
    """Join list-ish values."""

    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _first_string(value: Any) -> str | None:
    """Return first string from value."""

    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str) and value:
        return value
    return None
