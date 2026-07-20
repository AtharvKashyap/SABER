"""LLM-primary decider for the mission loop."""

from __future__ import annotations

import json
from typing import Any

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction, RiskLevel
from saber.core.prompt_loader import PromptLoader
from saber.core.state_summary import StateSummary
from saber.core.tool_catalog import ToolCatalog
from saber.models.mission_state import MissionState


class LlmDecider(NextActionDecider):
    """Ask the configured LLM for the next action, validated against the catalog."""

    def __init__(
        self,
        llm_client: Any,
        tool_catalog: ToolCatalog,
        prompt_loader: PromptLoader | None = None,
        prompt_name: str = "next_action",
    ) -> None:
        """Initialize the LLM decider."""

        self.llm_client = llm_client
        self.tool_catalog = tool_catalog
        self.prompt_loader = prompt_loader or PromptLoader()
        self.prompt_name = prompt_name

    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the next action chosen by the LLM."""

        if not getattr(self.llm_client, "enabled", False):
            return self._stop("LLM client disabled")

        system_prompt = self._load_prompt()
        payload = {
            "summary": summary.to_dict(),
            "tool_catalog": self.tool_catalog.to_dict(),
            "autonomy_level": state.autonomy_level.value,
            "scope": state.scope.to_agent_context() if state.scope else None,
        }
        user_prompt = json.dumps(payload, indent=2, sort_keys=True, default=str)

        try:
            raw = self.llm_client.complete_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                metadata={"component": "next_action_decider"},
            )
        except Exception as exc:  # noqa: BLE001 - decider must never crash the loop
            return self._stop(f"LLM error: {exc}")

        return self._parse(raw)

    def _parse(self, raw: dict[str, Any]) -> ProposedAction:
        kind = str(raw.get("kind") or "").strip().lower()

        if kind == "report":
            return ProposedAction(
                kind=ActionKind.REPORT,
                objective="Generate final report.",
                rationale=str(raw.get("rationale") or ""),
            )
        if kind == "stop":
            return self._stop(str(raw.get("rationale") or "LLM requested stop"))

        tool_name = raw.get("tool_name")
        tool_action = raw.get("tool_action")
        if not self._catalog_has(tool_name, tool_action):
            return self._stop(f"unknown tool/action: {tool_name}/{tool_action}")

        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name=str(tool_name),
            tool_action=str(tool_action),
            args=raw.get("args") if isinstance(raw.get("args"), dict) else {},
            agent_name=raw.get("agent_name"),
            objective=str(raw.get("rationale") or f"Run {tool_name}.{tool_action}"),
            risk=RiskLevel.from_str(raw.get("risk")),
            requires_confirmation=bool(raw.get("requires_confirmation", False)),
            rationale=str(raw.get("rationale") or ""),
            expected_evidence=str(raw.get("expected_evidence") or ""),
            metadata={"category": str(raw.get("category") or ""), "llm_raw": raw},
        )

    def _catalog_has(self, tool_name: Any, tool_action: Any) -> bool:
        if not tool_name or not tool_action:
            return False
        for tool in self.tool_catalog.tools:
            if tool.name == tool_name:
                return any(action.action == tool_action for action in tool.actions)
        return False

    def _load_prompt(self) -> str:
        try:
            prompt = self.prompt_loader.load_agent_prompt(self.prompt_name)
            return getattr(prompt, "system_prompt", None) or str(prompt)
        except Exception:  # noqa: BLE001 - fall back to inline instruction
            return "Return one strict JSON decision using only tools from tool_catalog."

    @staticmethod
    def _stop(reason: str) -> ProposedAction:
        return ProposedAction(kind=ActionKind.STOP, objective="Stop mission.", rationale=reason)
