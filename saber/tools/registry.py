"""Tool wrapper registry for SABER.

The registry keeps wrapper discovery centralized without forcing eager imports
from saber.tools.__init__.py. This avoids circular imports while still giving
agents and orchestration layers a single place to resolve tools by name,
category, or phase.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import import_module
from typing import Any

from saber.core.sandbox import Sandbox
from saber.models.scope import AssessmentPhase
from saber.tools.base_wrapper import BaseToolWrapper
from saber.tools.capability import RequestedActionCategory


@dataclass(frozen=True)
class ToolRegistryEntry:
    """Registry entry for one tool wrapper."""

    name: str
    import_path: str
    class_name: str
    category: RequestedActionCategory
    phase: AssessmentPhase
    description: str = ""
    aliases: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate registry entry basics."""

        if not self.name.strip():
            raise ValueError("ToolRegistryEntry.name cannot be empty.")
        if not self.import_path.strip():
            raise ValueError("ToolRegistryEntry.import_path cannot be empty.")
        if not self.class_name.strip():
            raise ValueError("ToolRegistryEntry.class_name cannot be empty.")

    @property
    def keys(self) -> tuple[str, ...]:
        """Return lookup keys for this entry."""

        return (self.name, *self.aliases)

    def load_class(self) -> type[BaseToolWrapper]:
        """Import and return the wrapper class."""

        module = import_module(self.import_path)
        wrapper_cls = getattr(module, self.class_name)

        if not issubclass(wrapper_cls, BaseToolWrapper):
            raise TypeError(f"{self.import_path}.{self.class_name} is not a BaseToolWrapper subclass")

        return wrapper_cls

    def create(self, sandbox: Sandbox, **kwargs: Any) -> BaseToolWrapper:
        """Instantiate the registered wrapper."""

        wrapper_cls = self.load_class()
        return wrapper_cls(sandbox=sandbox, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible entry summary."""

        return {
            "name": self.name,
            "import_path": self.import_path,
            "class_name": self.class_name,
            "category": self.category.value,
            "phase": self.phase.value,
            "description": self.description,
            "aliases": list(self.aliases),
            "metadata": self.metadata,
        }


class ToolRegistry:
    """Registry for available SABER tool wrappers."""

    def __init__(self, entries: Iterable[ToolRegistryEntry] | None = None) -> None:
        """Initialize registry."""

        self._entries: dict[str, ToolRegistryEntry] = {}
        if entries:
            for entry in entries:
                self.register(entry)

    def register(self, entry: ToolRegistryEntry) -> None:
        """Register one tool entry.

        Raises:
            ValueError: If any lookup key is already registered.
        """

        for key in entry.keys:
            normalized = self._normalize_key(key)
            if normalized in self._entries:
                raise ValueError(f"Tool registry key already registered: {key}")

        for key in entry.keys:
            self._entries[self._normalize_key(key)] = entry

    def get(self, name: str) -> ToolRegistryEntry:
        """Return a registry entry by name or alias."""

        normalized = self._normalize_key(name)
        try:
            return self._entries[normalized]
        except KeyError as exc:
            raise KeyError(f"Unknown tool: {name}") from exc

    def has(self, name: str) -> bool:
        """Return whether a tool name or alias exists."""

        return self._normalize_key(name) in self._entries

    def create(self, name: str, sandbox: Sandbox, **kwargs: Any) -> BaseToolWrapper:
        """Instantiate a wrapper by name or alias."""

        return self.get(name).create(sandbox=sandbox, **kwargs)

    def list_entries(self) -> list[ToolRegistryEntry]:
        """Return unique registry entries sorted by name."""

        unique = {entry.name: entry for entry in self._entries.values()}
        return [unique[name] for name in sorted(unique)]

    def by_category(self, category: RequestedActionCategory) -> list[ToolRegistryEntry]:
        """Return entries matching a requested action category."""

        return [entry for entry in self.list_entries() if entry.category == category]

    def by_phase(self, phase: AssessmentPhase) -> list[ToolRegistryEntry]:
        """Return entries matching an assessment phase."""

        return [entry for entry in self.list_entries() if entry.phase == phase]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible registry summary."""

        return {"tools": [entry.to_dict() for entry in self.list_entries()]}

    @staticmethod
    def _normalize_key(value: str) -> str:
        """Normalize lookup keys."""

        key = value.strip().lower().replace("-", "_")
        if not key:
            raise ValueError("tool registry key cannot be empty")
        return key


def default_tool_entries() -> list[ToolRegistryEntry]:
    """Return SABER's built-in tool registry entries."""

    return [
        ToolRegistryEntry(
            name="bloodhound",
            import_path="saber.tools.active_directory.bloodhound",
            class_name="BloodHoundWrapper",
            category=RequestedActionCategory.ACTIVE_DIRECTORY,
            phase=AssessmentPhase.EXPLOITATION,
            description="Active Directory graph collection.",
            aliases=("bloodhound_python",),
        ),
        ToolRegistryEntry(
            name="netexec",
            import_path="saber.tools.active_directory.netexec",
            class_name="NetExecWrapper",
            category=RequestedActionCategory.ACTIVE_DIRECTORY,
            phase=AssessmentPhase.EXPLOITATION,
            description="Network service and AD enumeration.",
            aliases=("nxc",),
        ),
        ToolRegistryEntry(
            name="impacket",
            import_path="saber.tools.active_directory.impacket",
            class_name="ImpacketWrapper",
            category=RequestedActionCategory.ACTIVE_DIRECTORY,
            phase=AssessmentPhase.EXPLOITATION,
            description="Impacket AD and Windows protocol utilities.",
        ),
        ToolRegistryEntry(
            name="metasploit",
            import_path="saber.tools.exploitation.metasploit",
            class_name="MetasploitWrapper",
            category=RequestedActionCategory.EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Metasploit module workflows.",
            aliases=("msfconsole",),
        ),
        ToolRegistryEntry(
            name="searchsploit",
            import_path="saber.tools.exploitation.searchsploit",
            class_name="SearchSploitWrapper",
            category=RequestedActionCategory.EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Exploit-DB lookup.",
        ),
        ToolRegistryEntry(
            name="plan",
            import_path="saber.tools.lateral_movement.plan",
            class_name="LateralMovementPlannerWrapper",
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            description="Lateral movement path planning.",
            aliases=("lateral_movement_planner",),
        ),
        ToolRegistryEntry(
            name="path_validation",
            import_path="saber.tools.lateral_movement.path_validation",
            class_name="PathValidationWrapper",
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            description="Lateral movement path validation.",
        ),
        ToolRegistryEntry(
            name="session_checks",
            import_path="saber.tools.lateral_movement.session_checks",
            class_name="SessionChecksWrapper",
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            description="Session validation and reachability checks.",
        ),
        ToolRegistryEntry(
            name="snmpwalk",
            import_path="saber.tools.network.snmpwalk",
            class_name="SnmpwalkWrapper",
            category=RequestedActionCategory.NETWORK,
            phase=AssessmentPhase.NETWORK,
            description="SNMP enumeration.",
        ),
        ToolRegistryEntry(
            name="enum4linux",
            import_path="saber.tools.network.enum4linux",
            class_name="Enum4LinuxWrapper",
            category=RequestedActionCategory.NETWORK,
            phase=AssessmentPhase.NETWORK,
            description="SMB enumeration.",
        ),
        ToolRegistryEntry(
            name="responder",
            import_path="saber.tools.network.responder",
            class_name="ResponderWrapper",
            category=RequestedActionCategory.NETWORK,
            phase=AssessmentPhase.NETWORK,
            description="Network poisoning capture workflow.",
        ),
        ToolRegistryEntry(
            name="bettercap",
            import_path="saber.tools.network.bettercap",
            class_name="BettercapWrapper",
            category=RequestedActionCategory.NETWORK,
            phase=AssessmentPhase.NETWORK,
            description="Network reconnaissance workflow.",
        ),
        ToolRegistryEntry(
            name="openvas",
            import_path="saber.tools.network.openvas_api",
            class_name="OpenVASApiWrapper",
            category=RequestedActionCategory.NETWORK,
            phase=AssessmentPhase.NETWORK,
            description="OpenVAS/GVM API workflow.",
            aliases=("openvas_api",),
        ),
        ToolRegistryEntry(
            name="hashcat",
            import_path="saber.tools.password.hashcat",
            class_name="HashcatWrapper",
            category=RequestedActionCategory.PASSWORD_CRACKING,
            phase=AssessmentPhase.EXPLOITATION,
            description="Hashcat password hash auditing.",
        ),
        ToolRegistryEntry(
            name="john",
            import_path="saber.tools.password.john",
            class_name="JohnWrapper",
            category=RequestedActionCategory.PASSWORD_CRACKING,
            phase=AssessmentPhase.EXPLOITATION,
            description="John the Ripper hash auditing.",
        ),
        ToolRegistryEntry(
            name="chisel",
            import_path="saber.tools.post_exploit.chisel",
            class_name="ChiselWrapper",
            category=RequestedActionCategory.POST_EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Tunneling and pivot transport.",
        ),
        ToolRegistryEntry(
            name="linpeas",
            import_path="saber.tools.post_exploit.linpeas",
            class_name="LinpeasWrapper",
            category=RequestedActionCategory.POST_EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Linux privilege escalation checks.",
        ),
        ToolRegistryEntry(
            name="winpeas",
            import_path="saber.tools.post_exploit.winpeas",
            class_name="WinpeasWrapper",
            category=RequestedActionCategory.POST_EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Windows privilege escalation checks.",
        ),
        ToolRegistryEntry(
            name="mimikatz",
            import_path="saber.tools.post_exploit.mimikatz",
            class_name="MimikatzWrapper",
            category=RequestedActionCategory.POST_EXPLOITATION,
            phase=AssessmentPhase.EXPLOITATION,
            description="Credential material inspection workflow.",
        ),
        ToolRegistryEntry(
            name="amass",
            import_path="saber.tools.recon.amass",
            class_name="AmassWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="DNS and subdomain enumeration.",
        ),
        ToolRegistryEntry(
            name="dnsrecon",
            import_path="saber.tools.recon.dnsrecon",
            class_name="DNSReconWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="DNS enumeration.",
        ),
        ToolRegistryEntry(
            name="masscan",
            import_path="saber.tools.recon.masscan",
            class_name="MasscanWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="High-speed port discovery.",
        ),
        ToolRegistryEntry(
            name="nmap",
            import_path="saber.tools.recon.nmap",
            class_name="NmapWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="Network discovery and service enumeration.",
        ),
        ToolRegistryEntry(
            name="subfinder",
            import_path="saber.tools.recon.subfinder",
            class_name="SubfinderWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="Passive subdomain discovery.",
        ),
        ToolRegistryEntry(
            name="theharvester",
            import_path="saber.tools.recon.theharvester",
            class_name="TheHarvesterWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="OSINT email, host, and domain harvesting.",
            aliases=("harvester",),
        ),
        ToolRegistryEntry(
            name="whatweb",
            import_path="saber.tools.recon.whatweb",
            class_name="WhatWebWrapper",
            category=RequestedActionCategory.RECON,
            phase=AssessmentPhase.RECON,
            description="Web technology fingerprinting.",
        ),
        ToolRegistryEntry(
            name="checksec",
            import_path="saber.tools.reverse_engineering.checksec",
            class_name="ChecksecWrapper",
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            phase=AssessmentPhase.RECON,
            description="Binary hardening inspection.",
        ),
        ToolRegistryEntry(
            name="file",
            import_path="saber.tools.reverse_engineering.file",
            class_name="FileWrapper",
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            phase=AssessmentPhase.RECON,
            description="File type identification.",
        ),
        ToolRegistryEntry(
            name="ghidra_headless",
            import_path="saber.tools.reverse_engineering.ghidra_headless",
            class_name="GhidraHeadlessWrapper",
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            phase=AssessmentPhase.RECON,
            description="Headless Ghidra analysis.",
            aliases=("ghidra",),
        ),
        ToolRegistryEntry(
            name="radare2",
            import_path="saber.tools.reverse_engineering.radare2",
            class_name="Radare2Wrapper",
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            phase=AssessmentPhase.RECON,
            description="radare2 static analysis.",
            aliases=("r2",),
        ),
        ToolRegistryEntry(
            name="strings",
            import_path="saber.tools.reverse_engineering.strings",
            class_name="StringsWrapper",
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            phase=AssessmentPhase.RECON,
            description="Printable string extraction.",
        ),
        ToolRegistryEntry(
            name="feroxbuster",
            import_path="saber.tools.web.feroxbuster",
            class_name="FeroxbusterWrapper",
            category=RequestedActionCategory.WEB,
            phase=AssessmentPhase.RECON,
            description="Web content discovery.",
        ),
        ToolRegistryEntry(
            name="nikto",
            import_path="saber.tools.web.nikto",
            class_name="NiktoWrapper",
            category=RequestedActionCategory.WEB,
            phase=AssessmentPhase.RECON,
            description="Web server vulnerability scanning.",
        ),
        ToolRegistryEntry(
            name="nuclei",
            import_path="saber.tools.web.nuclei",
            class_name="NucleiWrapper",
            category=RequestedActionCategory.WEB,
            phase=AssessmentPhase.RECON,
            description="Template-based vulnerability scanning.",
        ),
        ToolRegistryEntry(
            name="sqlmap",
            import_path="saber.tools.web.sqlmap",
            class_name="SqlmapWrapper",
            category=RequestedActionCategory.WEB,
            phase=AssessmentPhase.EXPLOITATION,
            description="SQL injection testing.",
        ),
        ToolRegistryEntry(
            name="zap_api",
            import_path="saber.tools.web.zap_api",
            class_name="ZAPApiWrapper",
            category=RequestedActionCategory.WEB,
            phase=AssessmentPhase.RECON,
            description="OWASP ZAP API workflows.",
            aliases=("zap",),
        ),
    ]


def build_default_registry() -> ToolRegistry:
    """Build registry populated with SABER's built-in tools."""

    return ToolRegistry(default_tool_entries())
