"""Tool selection agent for SABER.

The ToolSelectionAgent maps objectives and evidence to concrete tool/action
choices. It does not execute tools directly. It returns structured
AgentToolCall objects that other agents or orchestrators can execute through
ToolRegistry -> ToolWrapper -> Sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class ToolSelection:
    """Selected tool/action pair."""

    tool_name: str
    action: str
    args: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    requires_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate selection basics."""

        if not self.tool_name.strip():
            raise ValueError("ToolSelection.tool_name cannot be empty.")
        if not self.action.strip():
            raise ValueError("ToolSelection.action cannot be empty.")

    def to_tool_call(self) -> AgentToolCall:
        """Convert selection to AgentToolCall."""

        return AgentToolCall(
            tool_name=self.tool_name,
            action=self.action,
            args=self.args,
            reason=self.reason,
            requires_approval=self.requires_approval,
            metadata=self.metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible selection."""

        return {
            "tool_name": self.tool_name,
            "action": self.action,
            "args": self.args,
            "reason": self.reason,
            "requires_approval": self.requires_approval,
            "metadata": self.metadata,
        }


class ToolSelectionAgent(BaseAgent):
    """Select the best available tool/action for an objective."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        """Initialize tool selection agent."""

        super().__init__(
            config=config
            or AgentConfig(
                name="tool_selection_agent",
                phase=AssessmentPhase.RECON,
                prompt_path="prompts/tool_selection_agent_prompt.txt",
                description="Selects concrete tool actions from objectives and evidence.",
                default_metadata={"agent_type": "tool_selection"},
            )
        )

    def decide(self, context: AgentContext) -> AgentDecision:
        """Select a tool and return a TOOL decision."""

        objective = context.objective.strip() or "Select the next tool."
        selection = self.select_tool(context)

        if selection is None:
            return AgentDecision(
                action_type=AgentActionType.STOP,
                objective=objective,
                message="No suitable tool selection was found.",
                metadata={"reason": "no_tool_selected"},
            )

        return AgentDecision(
            action_type=AgentActionType.TOOL,
            objective=objective,
            tool_call=selection.to_tool_call(),
            requires_approval=selection.requires_approval,
            message=f"Selected {selection.tool_name}:{selection.action}.",
            metadata={"selection": selection.to_dict()},
        )

    def select_tool(self, context: AgentContext) -> ToolSelection | None:
        """Return the best tool selection for the current objective/context."""

        text = self._context_text(context)

        if self._contains_any(text, ["custom cli", "custom command", "one-off command", "raw command"]):
            return ToolSelection(
                tool_name="custom_cli",
                action="run_command",
                args={
                    "command": context.metadata.get("command", ""),
                    "reason": context.metadata.get("reason", "Custom command requested by agent objective."),
                    "expected_output": context.metadata.get("expected_output"),
                    "risk_level": context.metadata.get("risk_level", "medium"),
                },
                reason="Objective requested a custom CLI command.",
                requires_approval=True,
                metadata={"selection_rule": "custom_cli"},
            )

        if self._contains_any(text, ["subdomain", "subdomains"]):
            return ToolSelection(
                tool_name="subfinder",
                action="passive",
                args={"domain": context.target.tool_value()},
                reason="Subdomain discovery objective detected.",
                metadata={"selection_rule": "subdomain_discovery"},
            )

        if self._contains_any(text, ["dns", "mx record", "txt record", "nameserver", "zone"]):
            return ToolSelection(
                tool_name="dnsrecon",
                action="standard",
                args={"domain": context.target.tool_value()},
                reason="DNS enumeration objective detected.",
                metadata={"selection_rule": "dns_enumeration"},
            )

        if self._contains_any(text, ["fast scan", "wide scan", "large range", "many hosts", "masscan"]):
            return ToolSelection(
                tool_name="masscan",
                action="top_ports",
                args={"ports": "1-1000", "rate": 1000},
                reason="Fast port discovery objective detected.",
                metadata={"selection_rule": "fast_port_discovery"},
            )

        if self._contains_any(text, ["service scan", "open ports", "port scan", "nmap"]):
            return ToolSelection(
                tool_name="nmap",
                action="service_scan",
                args={"ports": "1-1000"},
                reason="Service discovery objective detected.",
                metadata={"selection_rule": "service_discovery"},
            )

        if self._contains_any(text, ["directory", "content discovery", "hidden paths", "feroxbuster"]):
            return ToolSelection(
                tool_name="feroxbuster",
                action="directory_bruteforce",
                args={"wordlist": "wordlists/common.txt", "threads": 50},
                reason="Web content discovery objective detected.",
                metadata={"selection_rule": "web_content_discovery"},
            )

        if self._contains_any(text, ["web server scan", "nikto", "misconfiguration"]):
            return ToolSelection(
                tool_name="nikto",
                action="scan",
                args={},
                reason="Web server scanning objective detected.",
                metadata={"selection_rule": "nikto_scan"},
            )

        if self._contains_any(text, ["template scan", "nuclei", "cves", "exposures"]):
            return ToolSelection(
                tool_name="nuclei",
                action="scan",
                args={"severity": "medium,high,critical"},
                reason="Template-based vulnerability scan objective detected.",
                metadata={"selection_rule": "nuclei_scan"},
            )

        if self._contains_any(text, ["sqli", "sql injection", "injectable parameter"]):
            return ToolSelection(
                tool_name="sqlmap",
                action="test_url",
                args={"risk": 1, "level": 1, "batch": True},
                reason="SQL injection validation objective detected.",
                metadata={"selection_rule": "sqlmap_validation"},
            )

        if self._contains_any(text, ["zap", "active scan"]):
            return ToolSelection(
                tool_name="zap_api",
                action="active_scan",
                args={"zap_url": "http://127.0.0.1:8080"},
                reason="ZAP active scan objective detected.",
                requires_approval=True,
                metadata={"selection_rule": "zap_active_scan"},
            )

        if self._contains_any(text, ["baseline web scan", "zap baseline"]):
            return ToolSelection(
                tool_name="zap_api",
                action="baseline_scan",
                args={},
                reason="ZAP baseline scan objective detected.",
                metadata={"selection_rule": "zap_baseline"},
            )

        if self._contains_any(text, ["smb", "shares", "port 445"]):
            return ToolSelection(
                tool_name="enum4linux",
                action="shares",
                args={},
                reason="SMB enumeration objective detected.",
                metadata={"selection_rule": "smb_enum"},
            )

        if self._contains_any(text, ["snmp", "port 161", "udp/161"]):
            return ToolSelection(
                tool_name="snmpwalk",
                action="walk",
                args={"community": "public", "oid": "1.3.6.1.2.1", "version": "2c"},
                reason="SNMP enumeration objective detected.",
                metadata={"selection_rule": "snmp_enum"},
            )

        if self._contains_any(text, ["cve-", "exploit-db", "searchsploit"]):
            cve_id = self._extract_cve(text)
            return ToolSelection(
                tool_name="searchsploit",
                action="cve_search" if cve_id else "search",
                args={"cve_id": cve_id} if cve_id else {"query": context.objective},
                reason="Exploit reference lookup objective detected.",
                metadata={"selection_rule": "exploit_lookup", "cve_id": cve_id},
            )

        if self._contains_any(text, ["metasploit", "module search"]):
            return ToolSelection(
                tool_name="metasploit",
                action="search_modules",
                args={"query": context.objective},
                reason="Metasploit module search objective detected.",
                metadata={"selection_rule": "metasploit_search"},
            )

        if self._contains_any(text, ["checksec", "binary hardening", "pie", "nx", "relro"]):
            return ToolSelection(
                tool_name="checksec",
                action="binary",
                args={"binary_path": context.metadata.get("binary_path", context.target.tool_value())},
                reason="Binary hardening inspection objective detected.",
                metadata={"selection_rule": "checksec_binary"},
            )

        if self._contains_any(text, ["strings", "extract strings"]):
            return ToolSelection(
                tool_name="strings",
                action="extract",
                args={"file_path": context.metadata.get("file_path", context.target.tool_value()), "min_length": 4},
                reason="String extraction objective detected.",
                metadata={"selection_rule": "strings_extract"},
            )

        if self._contains_any(text, ["file type", "identify file", "mime"]):
            return ToolSelection(
                tool_name="file",
                action="identify",
                args={"file_path": context.metadata.get("file_path", context.target.tool_value())},
                reason="File identification objective detected.",
                metadata={"selection_rule": "file_identify"},
            )

        if self._contains_any(text, ["radare2", "r2", "functions"]):
            return ToolSelection(
                tool_name="radare2",
                action="functions",
                args={"binary_path": context.metadata.get("binary_path", context.target.tool_value())},
                reason="radare2 function listing objective detected.",
                metadata={"selection_rule": "radare2_functions"},
            )

        if self._contains_any(text, ["ghidra", "decompile", "headless"]):
            return ToolSelection(
                tool_name="ghidra_headless",
                action="analyze_binary",
                args={
                    "binary_path": context.metadata.get("binary_path", context.target.tool_value()),
                    "project_dir": context.metadata.get("project_dir", "ghidra_projects"),
                    "project_name": context.metadata.get("project_name", "saber_project"),
                },
                reason="Ghidra headless analysis objective detected.",
                metadata={"selection_rule": "ghidra_analyze"},
            )

        return None

    @staticmethod
    def _context_text(context: AgentContext) -> str:
        """Flatten context into searchable text."""

        observations = " ".join(f"{obs.summary} {obs.metadata}" for obs in context.observations)
        return f"{context.objective} {context.metadata} {observations}".lower()

    @staticmethod
    def _contains_any(text: str, needles: list[str]) -> bool:
        """Return whether text contains any needle."""

        return any(needle in text for needle in needles)

    @staticmethod
    def _extract_cve(text: str) -> str | None:
        """Extract a CVE-like token."""

        for raw_token in text.replace(",", " ").replace(";", " ").split():
            token = raw_token.strip(" .()[]{}").upper()
            if token.startswith("CVE-") and len(token.split("-")) >= 3:
                return token
        return None
