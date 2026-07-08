"""Tool catalog for LLM-aware SABER agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ToolActionSpec:
    """One action an agent may request."""

    tool_name: str
    action: str
    description: str
    risk: str = "low"
    requires_approval: bool = False
    example_args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolSpec:
    """LLM-readable tool description."""

    name: str
    category: str
    phase: str
    description: str
    image: str | None = None
    actions: list[ToolActionSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolCatalog:
    """Catalog of exact tool capabilities available to agents."""

    def __init__(self, tools: list[ToolSpec]) -> None:
        self.tools = tools

    @classmethod
    def from_registry(cls, registry: ToolRegistry) -> "ToolCatalog":
        """Build a catalog from ToolRegistry entries.

        This intentionally tolerates multiple registry entry shapes because
        ToolRegistryEntry is an internal object and older tests/branches may
        store wrapper class, wrapper factory, config, or just metadata.
        """

        specs: list[ToolSpec] = []

        for entry in registry.list_entries():
            entry_data = _to_dict(entry)

            name = (
                _get(entry, "tool_name")
                or _get(entry, "name")
                or entry_data.get("tool_name")
                or entry_data.get("name")
                or entry_data.get("registry_name")
                or "unknown"
            )

            config = (
                _get(entry, "config")
                or _get(_get(entry, "wrapper"), "config")
                or _get(_get(entry, "tool"), "config")
                or _get(_get(entry, "wrapper_class"), "config")
                or _get(_get(entry, "wrapper_cls"), "config")
            )

            if config is not None:
                name = _get(config, "tool_name") or name
                category = _stringify(_get(config, "category") or entry_data.get("category") or "unknown")
                phase = _stringify(_get(config, "phase") or entry_data.get("phase") or _phase_for_tool(str(name)))
                image = _get(config, "image") or entry_data.get("image")
            else:
                category = _stringify(entry_data.get("category") or _get(entry, "category") or _category_for_tool(str(name)))
                phase = _stringify(entry_data.get("phase") or _get(entry, "phase") or _phase_for_tool(str(name)))
                image = entry_data.get("image") or _get(entry, "image")

            aliases = (
                entry_data.get("aliases")
                or _get(entry, "aliases")
                or _get(entry, "alias_names")
                or []
            )

            specs.append(
                ToolSpec(
                    name=str(name),
                    category=str(category),
                    phase=str(phase),
                    image=str(image) if image else None,
                    description=_description_for_tool(str(name)),
                    actions=_infer_actions(name=str(name), category=str(category), phase=str(phase)),
                    metadata={
                        "registry_name": str(_get(entry, "name") or entry_data.get("name") or name),
                        "aliases": list(aliases or []),
                        "entry_type": type(entry).__name__,
                    },
                )
            )

        # Deduplicate by tool name while preserving first useful entry.
        deduped: dict[str, ToolSpec] = {}
        for spec in specs:
            deduped.setdefault(spec.name, spec)

        return cls(sorted(deduped.values(), key=lambda item: item.name))

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible catalog."""

        return {
            "tools": [
                {
                    "name": tool.name,
                    "category": tool.category,
                    "phase": tool.phase,
                    "description": tool.description,
                    "image": tool.image,
                    "actions": [
                        {
                            "tool_name": action.tool_name,
                            "action": action.action,
                            "description": action.description,
                            "risk": action.risk,
                            "requires_approval": action.requires_approval,
                            "example_args": action.example_args,
                        }
                        for action in tool.actions
                    ],
                    "metadata": tool.metadata,
                }
                for tool in self.tools
            ]
        }

    def to_prompt_text(self) -> str:
        """Return compact prompt-ready tool catalog text."""

        lines: list[str] = []

        for tool in self.tools:
            lines.append(f"- {tool.name} [{tool.phase}/{tool.category}]")
            lines.append(f"  Description: {tool.description}")
            if tool.image:
                lines.append(f"  Docker image: {tool.image}")
            for action in tool.actions:
                approval = "approval required" if action.requires_approval else "auto allowed"
                lines.append(
                    f"  - action={action.action}; risk={action.risk}; {approval}; "
                    f"{action.description}; example_args={action.example_args}"
                )

        return "\n".join(lines)

    def actions_for_phase(self, phase: str) -> list[ToolActionSpec]:
        """Return actions matching a phase."""

        normalized = phase.lower()
        actions: list[ToolActionSpec] = []

        for tool in self.tools:
            if tool.phase.lower() == normalized or tool.category.lower() == normalized:
                actions.extend(tool.actions)

        return actions


def _infer_actions(*, name: str, category: str, phase: str) -> list[ToolActionSpec]:
    """Infer stable action specs for current wrappers.

    The LLM must choose one of these known actions instead of inventing commands.
    """

    known: dict[str, list[ToolActionSpec]] = {
        "nmap": [
            ToolActionSpec(
                tool_name="nmap",
                action="service_scan",
                description="TCP service discovery and version detection.",
                risk="low",
                requires_approval=False,
                example_args={"target": "127.0.0.1", "ports": "1-1000"},
            ),
            ToolActionSpec(
                tool_name="nmap",
                action="udp_scan",
                description="UDP service discovery. Slower and noisier than TCP service scan.",
                risk="medium",
                requires_approval=True,
                example_args={"target": "127.0.0.1", "ports": "top-100"},
            ),
        ],
        "masscan": [
            ToolActionSpec(
                tool_name="masscan",
                action="fast_port_scan",
                description="High-speed port discovery. Can be noisy.",
                risk="medium",
                requires_approval=True,
                example_args={"target": "127.0.0.1", "ports": "1-65535", "rate": "1000"},
            )
        ],
        "subfinder": [
            ToolActionSpec(
                tool_name="subfinder",
                action="subdomain_enum",
                description="Passive subdomain enumeration for a domain target.",
                risk="low",
                requires_approval=False,
                example_args={"domain": "example.com"},
            )
        ],
        "amass": [
            ToolActionSpec(
                tool_name="amass",
                action="passive_enum",
                description="Passive DNS/subdomain enumeration.",
                risk="low",
                requires_approval=False,
                example_args={"domain": "example.com"},
            )
        ],
        "dnsrecon": [
            ToolActionSpec(
                tool_name="dnsrecon",
                action="dns_enum",
                description="DNS record enumeration.",
                risk="low",
                requires_approval=False,
                example_args={"domain": "example.com"},
            )
        ],
        "whatweb": [
            ToolActionSpec(
                tool_name="whatweb",
                action="fingerprint",
                description="Web technology fingerprinting.",
                risk="low",
                requires_approval=False,
                example_args={"url": "http://127.0.0.1"},
            )
        ],
        "nuclei": [
            ToolActionSpec(
                tool_name="nuclei",
                action="template_scan",
                description="Template-based vulnerability scanning.",
                risk="medium",
                requires_approval=True,
                example_args={"target": "http://127.0.0.1", "severity": "low,medium,high,critical"},
            )
        ],
        "nikto": [
            ToolActionSpec(
                tool_name="nikto",
                action="web_scan",
                description="Web server vulnerability and misconfiguration scan.",
                risk="medium",
                requires_approval=True,
                example_args={"url": "http://127.0.0.1"},
            )
        ],
        "searchsploit": [
            ToolActionSpec(
                tool_name="searchsploit",
                action="exploit_search",
                description="Search Exploit-DB for known exploit references.",
                risk="low",
                requires_approval=False,
                example_args={"query": "OpenSSH 8.2"},
            )
        ],
        "sqlmap": [
            ToolActionSpec(
                tool_name="sqlmap",
                action="injection_test",
                description="SQL injection validation. Can be intrusive.",
                risk="high",
                requires_approval=True,
                example_args={"url": "http://127.0.0.1/item?id=1"},
            )
        ],
        "hydra": [
            ToolActionSpec(
                tool_name="hydra",
                action="password_audit",
                description="Password guessing/audit against an approved service.",
                risk="high",
                requires_approval=True,
                example_args={"target": "127.0.0.1", "service": "ssh", "username": "test"},
            )
        ],
        "custom_cli": [
            ToolActionSpec(
                tool_name="custom_cli",
                action="custom_script",
                description="Run a custom command/script inside the approved sandbox.",
                risk="high",
                requires_approval=True,
                example_args={"command": ["python3", "script.py"]},
            )
        ],
    }

    if name in known:
        return known[name]

    high_risk_phases = {"exploitation", "post_exploitation", "lateral_movement", "password"}
    return [
        ToolActionSpec(
            tool_name=name,
            action="default",
            description=f"Default action for {name}.",
            risk="high" if phase in high_risk_phases else "low",
            requires_approval=phase in high_risk_phases,
            example_args={},
        )
    ]


def _description_for_tool(name: str) -> str:
    """Human/LLM-readable tool description."""

    descriptions = {
        "nmap": "Network scanner for host discovery, port scanning, and service/version detection.",
        "masscan": "Very fast port scanner for broad network discovery.",
        "subfinder": "Passive subdomain discovery tool.",
        "amass": "Attack surface and DNS/subdomain enumeration tool.",
        "dnsrecon": "DNS enumeration and record discovery tool.",
        "whatweb": "Web technology fingerprinting tool.",
        "nuclei": "Template-driven vulnerability scanner.",
        "nikto": "Web server vulnerability and misconfiguration scanner.",
        "searchsploit": "Exploit-DB local exploit search interface.",
        "sqlmap": "SQL injection testing and exploitation framework.",
        "hydra": "Network login/password auditing tool.",
        "bloodhound": "Active Directory attack path analysis tooling.",
        "custom_cli": "Approved custom command execution inside SABER sandbox.",
    }
    return descriptions.get(name, f"SABER tool wrapper for {name}.")


def _category_for_tool(name: str) -> str:
    """Best-effort category for known tools."""

    categories = {
        "nmap": "recon",
        "masscan": "recon",
        "subfinder": "recon",
        "amass": "recon",
        "dnsrecon": "recon",
        "whatweb": "web",
        "nuclei": "web",
        "nikto": "web",
        "searchsploit": "exploitation",
        "sqlmap": "exploitation",
        "hydra": "password",
        "bloodhound": "active_directory",
        "custom_cli": "custom",
    }
    return categories.get(name, "unknown")


def _phase_for_tool(name: str) -> str:
    """Best-effort phase for known tools."""

    phases = {
        "nmap": "recon",
        "masscan": "recon",
        "subfinder": "recon",
        "amass": "recon",
        "dnsrecon": "recon",
        "whatweb": "web",
        "nuclei": "web",
        "nikto": "web",
        "searchsploit": "exploitation",
        "sqlmap": "exploitation",
        "hydra": "password",
        "bloodhound": "active_directory",
        "custom_cli": "custom",
    }
    return phases.get(name, "unknown")


def _get(obj: object, name: str) -> Any:
    """Read attribute/key safely."""

    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _to_dict(obj: object) -> dict[str, Any]:
    """Best-effort dict conversion."""

    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        try:
            value = obj.to_dict()
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}
    if hasattr(obj, "model_dump"):
        try:
            value = obj.model_dump(mode="json")
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    data: dict[str, Any] = {}
    for key in ("name", "tool_name", "category", "phase", "image", "aliases"):
        value = getattr(obj, key, None)
        if value is not None:
            data[key] = value
    return data


def _stringify(value: object) -> str:
    """Convert enum/string-ish values to readable strings."""

    if value is None:
        return "unknown"
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)
