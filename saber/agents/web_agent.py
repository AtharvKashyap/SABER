"""Web agent for SABER.

The WebAgent owns web application testing decisions. It selects web wrappers for
fingerprinting, content discovery, template scanning, SQL injection validation,
and ZAP workflows through the normal ToolRegistry -> ToolWrapper -> Sandbox
path.
"""

from __future__ import annotations

from typing import Any

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    AgentToolCall,
    BaseAgent,
)
from saber.models.scope import AssessmentPhase


class WebAgent(BaseAgent):
    """Plan web application testing workflows."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize web agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="web_agent",
                phase=AssessmentPhase.RECON,
                prompt_path="prompts/web_agent_prompt.txt",
                description="Tests discovered web applications and web services.",
                default_metadata={"agent_type": "web"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next web testing step."""

        objective = context.objective.strip() or "Test web application."

        if llm_decision := self.try_llm_decision(context, objective=objective):
            return llm_decision

        if self._is_complete(context):
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="Web testing objective is already complete.",
                metadata={"reason": "web_complete"},
            )

        if not self._has_fingerprint(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Fingerprint web technologies.",
                tool_call=AgentToolCall(
                    tool_name="whatweb",
                    action="fingerprint",
                    args={"aggression": 1},
                    reason="Start web testing with safe technology fingerprinting.",
                    metadata={"workflow_step": "web_fingerprinting"},
                ),
                metadata={"workflow_step": "web_fingerprinting"},
            )

        if self._needs_content_discovery(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Discover web directories and files.",
                tool_call=AgentToolCall(
                    tool_name="feroxbuster",
                    action="directory_bruteforce",
                    args={
                        "wordlist": context.metadata.get("wordlist", "wordlists/common.txt"),
                        "threads": context.metadata.get("threads", 50),
                    },
                    reason="Web surface exists; run content discovery.",
                    metadata={"workflow_step": "content_discovery"},
                ),
                metadata={"workflow_step": "content_discovery"},
            )

        if self._needs_web_server_scan(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run web server misconfiguration scan.",
                tool_call=AgentToolCall(
                    tool_name="nikto",
                    action="scan",
                    args={"output_format": "json"} if context.metadata.get("json_output") else {},
                    reason="Web server scan requested or misconfiguration evidence exists.",
                    metadata={"workflow_step": "web_server_scan"},
                ),
                metadata={"workflow_step": "web_server_scan"},
            )

        if self._needs_template_scan(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run template-based vulnerability scan.",
                tool_call=AgentToolCall(
                    tool_name="nuclei",
                    action="scan",
                    args={
                        "severity": context.metadata.get("severity", "medium,high,critical"),
                        "templates": context.metadata.get("templates"),
                    },
                    reason="Template-based web vulnerability scan requested.",
                    metadata={"workflow_step": "template_scan"},
                ),
                metadata={"workflow_step": "template_scan"},
            )

        if self._has_possible_sqli(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Validate possible SQL injection safely.",
                tool_call=AgentToolCall(
                    tool_name="sqlmap",
                    action="test_url",
                    args={"risk": 1, "level": 1, "batch": True},
                    reason="Possible SQL injection evidence exists; run low-risk validation only.",
                    metadata={"workflow_step": "sqli_validation"},
                ),
                metadata={"workflow_step": "sqli_validation"},
            )

        if self._needs_zap_baseline(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run ZAP baseline scan.",
                tool_call=AgentToolCall(
                    tool_name="zap_api",
                    action="baseline_scan",
                    args={"report_file": context.metadata.get("report_file")} if context.metadata.get("report_file") else {},
                    reason="ZAP baseline scan requested.",
                    metadata={"workflow_step": "zap_baseline"},
                ),
                metadata={"workflow_step": "zap_baseline"},
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="No additional web action was selected.",
            metadata={"reason": "no_web_action"},
        )

    def build_zap_active_scan_approval_decision(
        self,
        reason: str,
        objective: str = "Request approval for ZAP active scan.",
        zap_url: str = "http://127.0.0.1:8080",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated ZAP active scan decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message="Approval required before ZAP active scan.",
            tool_call=AgentToolCall(
                tool_name="zap_api",
                action="active_scan",
                args={"zap_url": zap_url},
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"approval_type": "zap_active_scan", **(metadata or {})},
        )

    def build_sqlmap_schema_approval_decision(
        self,
        reason: str,
        objective: str = "Request approval for sqlmap schema enumeration.",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated sqlmap schema enumeration decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message="Approval required before sqlmap schema enumeration.",
            tool_call=AgentToolCall(
                tool_name="sqlmap",
                action="dump_schema",
                args={"batch": True},
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"approval_type": "sqlmap_dump_schema", **(metadata or {})},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom web command.",
        expected_output: str | None = None,
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated custom CLI decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom web command: {reason}",
            tool_call=AgentToolCall(
                tool_name="custom_cli",
                action="run_command",
                args={
                    "command": command,
                    "reason": reason,
                    "expected_output": expected_output,
                    "risk_level": risk_level,
                },
                reason=reason,
                requires_approval=True,
                metadata=metadata or {},
            ),
            metadata={"custom_cli": True, **(metadata or {})},
        )

    @staticmethod
    def _is_complete(context: AgentContext) -> bool:
        """Return whether web testing is complete."""

        return WebAgent._context_contains(context, ["web complete", "web testing complete", "no further web testing"])

    @staticmethod
    def _has_fingerprint(observations: list[AgentObservation]) -> bool:
        """Return whether web fingerprinting exists."""

        return any(
            WebAgent._contains_any(observation, ["whatweb", "fingerprint", "nginx", "apache", "iis", "wordpress"])
            or observation.tool_name == "whatweb"
            for observation in observations
        )

    @staticmethod
    def _needs_content_discovery(context: AgentContext) -> bool:
        """Return whether content discovery should run."""

        return WebAgent._context_contains(
            context,
            ["directory", "directories", "content discovery", "hidden path", "hidden paths", "feroxbuster"],
        )

    @staticmethod
    def _needs_web_server_scan(context: AgentContext) -> bool:
        """Return whether Nikto-like web server scan should run."""

        return WebAgent._context_contains(context, ["nikto", "web server scan", "misconfiguration", "server headers"])

    @staticmethod
    def _needs_template_scan(context: AgentContext) -> bool:
        """Return whether Nuclei-like template scan should run."""

        return WebAgent._context_contains(context, ["nuclei", "template scan", "cves", "exposures", "known vulnerabilities"])

    @staticmethod
    def _has_possible_sqli(context: AgentContext) -> bool:
        """Return whether SQLi validation should run."""

        return WebAgent._context_contains(context, ["sqli", "sql injection", "injectable parameter", "parameter appears injectable"])

    @staticmethod
    def _needs_zap_baseline(context: AgentContext) -> bool:
        """Return whether ZAP baseline should run."""

        return WebAgent._context_contains(context, ["zap baseline", "baseline web scan", "passive web scan"])

    @staticmethod
    def _context_contains(context: AgentContext, needles: list[str]) -> bool:
        """Check objective and observations for terms."""

        observations = " ".join(f"{obs.summary} {obs.metadata}" for obs in context.observations)
        text = f"{context.objective} {context.metadata} {observations}".lower()
        return any(needle in text for needle in needles)

    @staticmethod
    def _contains_any(observation: AgentObservation, needles: list[str]) -> bool:
        """Check observation summary and metadata for terms."""

        text = f"{observation.summary} {observation.metadata}".lower()
        return any(needle in text for needle in needles)
