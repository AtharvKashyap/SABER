"""Reverse engineering agent for SABER.

The ReverseEngineerAgent owns static binary triage and analysis decisions. It
uses file, strings, checksec, radare2, and Ghidra wrappers through the normal
ToolRegistry -> ToolWrapper -> Sandbox path.
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


class ReverseEngineerAgent(BaseAgent):
    """Plan static binary analysis workflows."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize reverse engineering agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="reverse_engineer_agent",
                phase=AssessmentPhase.RECON,
                prompt_path="prompts/reverse_engineer_agent_prompt.txt",
                description="Analyzes binaries, protections, strings, and functions.",
                default_metadata={"agent_type": "reverse_engineering"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Decide the next reverse engineering step."""

        objective = context.objective.strip() or "Analyze binary."

        if self._is_complete(context):
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="Reverse engineering analysis is already complete.",
                metadata={"reason": "reverse_engineering_complete"},
            )

        if not self._has_file_identification(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Identify binary/file type.",
                tool_call=AgentToolCall(
                    tool_name="file",
                    action="identify",
                    args={"file_path": self._file_path(context)},
                    reason="Start reverse engineering with file type identification.",
                    metadata={"workflow_step": "file_identification"},
                ),
                metadata={"workflow_step": "file_identification"},
            )

        if not self._has_strings(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Extract interesting printable strings.",
                tool_call=AgentToolCall(
                    tool_name="strings",
                    action="extract",
                    args={"file_path": self._file_path(context), "min_length": 4},
                    reason="File was identified; extract printable strings.",
                    metadata={"workflow_step": "strings_extraction"},
                ),
                metadata={"workflow_step": "strings_extraction"},
            )

        if self._looks_executable(context.observations) and not self._has_checksec(context.observations):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Inspect binary hardening protections.",
                tool_call=AgentToolCall(
                    tool_name="checksec",
                    action="binary",
                    args={"binary_path": self._file_path(context), "output_format": "json"},
                    reason="Executable binary observed; check hardening protections.",
                    metadata={"workflow_step": "binary_hardening"},
                ),
                metadata={"workflow_step": "binary_hardening"},
            )

        if self._needs_function_analysis(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="List functions with radare2.",
                tool_call=AgentToolCall(
                    tool_name="radare2",
                    action="functions",
                    args={"binary_path": self._file_path(context), "json_output": True},
                    reason="Function analysis requested or useful from current evidence.",
                    metadata={"workflow_step": "function_listing"},
                ),
                metadata={"workflow_step": "function_listing"},
            )

        if self._needs_deep_analysis(context):
            return AgentDecision(
                action_type=AgentActionType.TOOL,
                objective="Run deep Ghidra headless analysis.",
                tool_call=AgentToolCall(
                    tool_name="ghidra_headless",
                    action="analyze_binary",
                    args={
                        "binary_path": self._file_path(context),
                        "project_dir": context.metadata.get("project_dir", "ghidra_projects"),
                        "project_name": context.metadata.get("project_name", "saber_project"),
                    },
                    reason="Deep static analysis requested.",
                    metadata={"workflow_step": "ghidra_analysis"},
                ),
                metadata={"workflow_step": "ghidra_analysis"},
            )

        return AgentDecision(
            action_type=AgentActionType.STOP,
            objective=objective,
            message="No additional reverse engineering step was selected.",
            metadata={"reason": "no_reverse_engineering_action"},
        )

    def build_custom_cli_decision(
        self,
        command: str,
        reason: str,
        objective: str = "Run an explicitly authorized custom reverse engineering command.",
        expected_output: str | None = None,
        risk_level: str = "low",
        metadata: dict[str, Any] | None = None,
    ) -> AgentDecision:
        """Build approval-gated custom CLI decision."""

        return AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective=objective,
            requires_approval=True,
            message=f"Approval required before custom reverse engineering command: {reason}",
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
    def _file_path(context: AgentContext) -> str:
        """Resolve binary/file path from context metadata or target."""

        return str(context.metadata.get("binary_path") or context.metadata.get("file_path") or context.target.tool_value())

    @staticmethod
    def _is_complete(context: AgentContext) -> bool:
        """Return whether reverse engineering is complete."""

        return ReverseEngineerAgent._context_contains(
            context,
            ["reverse engineering complete", "binary analysis complete", "static analysis complete"],
        )

    @staticmethod
    def _has_file_identification(observations: list[AgentObservation]) -> bool:
        """Return whether file identification exists."""

        return any(
            ReverseEngineerAgent._contains_any(observation, ["elf", "pe32", "mach-o", "file type", "executable"])
            or observation.tool_name == "file"
            for observation in observations
        )

    @staticmethod
    def _has_strings(observations: list[AgentObservation]) -> bool:
        """Return whether strings extraction exists."""

        return any(
            ReverseEngineerAgent._contains_any(observation, ["strings extracted", "printable strings", "interesting strings"])
            or observation.tool_name == "strings"
            for observation in observations
        )

    @staticmethod
    def _has_checksec(observations: list[AgentObservation]) -> bool:
        """Return whether checksec output exists."""

        return any(
            ReverseEngineerAgent._contains_any(observation, ["checksec", "relro", "canary", "nx", "pie"])
            or observation.tool_name == "checksec"
            for observation in observations
        )

    @staticmethod
    def _looks_executable(observations: list[AgentObservation]) -> bool:
        """Return whether observations suggest executable binary."""

        return any(
            ReverseEngineerAgent._contains_any(
                observation,
                ["elf", "pe32", "mach-o", "executable", "x86_64", "aarch64"],
            )
            for observation in observations
        )

    @staticmethod
    def _needs_function_analysis(context: AgentContext) -> bool:
        """Return whether function analysis is requested."""

        return ReverseEngineerAgent._context_contains(
            context,
            ["function", "functions", "radare2", "r2", "symbol", "symbols"],
        )

    @staticmethod
    def _needs_deep_analysis(context: AgentContext) -> bool:
        """Return whether deep Ghidra analysis is requested."""

        return ReverseEngineerAgent._context_contains(
            context,
            ["ghidra", "decompile", "decompiler", "deep analysis", "control flow"],
        )

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
