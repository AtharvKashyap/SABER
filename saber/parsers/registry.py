"""Parser registry for SABER tool results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.parsers.amass import AmassParser
from saber.parsers.base import BaseParser, ParserResult
from saber.parsers.bettercap import BettercapParser
from saber.parsers.bloodhound import BloodHoundParser
from saber.parsers.checksec import ChecksecParser
from saber.parsers.chisel import ChiselParser
from saber.parsers.dnsrecon import DNSReconParser
from saber.parsers.enum4linux import Enum4LinuxParser
from saber.parsers.feroxbuster import FeroxbusterParser
from saber.parsers.file import FileParser
from saber.parsers.ghidra_headless import GhidraHeadlessParser
from saber.parsers.hashcat import HashcatParser
from saber.parsers.impacket import ImpacketParser
from saber.parsers.john import JohnParser
from saber.parsers.linpeas import LinpeasParser
from saber.parsers.masscan import MasscanParser
from saber.parsers.metasploit import MetasploitParser
from saber.parsers.mimikatz import MimikatzParser
from saber.parsers.netexec import NetExecParser
from saber.parsers.nikto import NiktoParser
from saber.parsers.nmap import NmapParser
from saber.parsers.nuclei import NucleiParser
from saber.parsers.openvas import OpenVASParser
from saber.parsers.path_validation import PathValidationParser
from saber.parsers.plan import PlanParser
from saber.parsers.pwntools import PwntoolsParser
from saber.parsers.radare2 import Radare2Parser
from saber.parsers.responder import ResponderParser
from saber.parsers.session_checks import SessionChecksParser
from saber.parsers.searchsploit import SearchSploitParser
from saber.parsers.snmpwalk import SnmpwalkParser
from saber.parsers.sqlmap import SqlmapParser
from saber.parsers.strings import StringsParser
from saber.parsers.subfinder import SubfinderParser
from saber.parsers.theharvester import TheHarvesterParser
from saber.parsers.whatweb import WhatWebParser
from saber.parsers.winpeas import WinpeasParser
from saber.parsers.zap import ZapParser


@dataclass(frozen=True)
class ParserRegistryEntry:
    """One parser registry entry."""

    tool_name: str
    parser: BaseParser
    aliases: tuple[str, ...] = field(default_factory=tuple)
    file_extensions: tuple[str, ...] = field(default_factory=tuple)

    def matches_tool(self, tool_name: str) -> bool:
        """Return whether this entry matches a tool name."""

        normalized = _normalize_tool_name(tool_name)
        names = {_normalize_tool_name(self.tool_name)}
        names.update(_normalize_tool_name(alias) for alias in self.aliases)
        return normalized in names

    def matches_path(self, path: str | Path) -> bool:
        """Return whether this entry matches a path extension."""

        suffix = Path(path).suffix.lower().lstrip(".")
        return bool(suffix and suffix in {ext.lower().lstrip(".") for ext in self.file_extensions})


@dataclass(frozen=True)
class ParserDispatchResult:
    """Result from parser dispatch."""

    parser_used: str | None
    result: ParserResult | None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible dispatch result."""

        return {
            "parser_used": self.parser_used,
            "result": self.result.to_dict() if self.result and hasattr(self.result, "to_dict") else self.result,
            "errors": self.errors,
        }


class ParserRegistry:
    """Registry that maps tool names and output files to parsers."""

    def __init__(self, entries: list[ParserRegistryEntry] | None = None) -> None:
        """Initialize parser registry."""

        self._entries: list[ParserRegistryEntry] = list(entries or [])

    def register(
        self,
        tool_name: str,
        parser: BaseParser,
        aliases: tuple[str, ...] = (),
        file_extensions: tuple[str, ...] = (),
    ) -> None:
        """Register a parser."""

        if not tool_name or not tool_name.strip():
            raise ValueError("tool_name is required")

        self._entries.append(
            ParserRegistryEntry(
                tool_name=tool_name,
                parser=parser,
                aliases=aliases,
                file_extensions=file_extensions,
            )
        )

    def get(self, tool_name: str) -> BaseParser | None:
        """Get parser for a tool name."""

        for entry in self._entries:
            if entry.matches_tool(tool_name):
                return entry.parser
        return None

    def get_entry(self, tool_name: str) -> ParserRegistryEntry | None:
        """Get registry entry for a tool name."""

        for entry in self._entries:
            if entry.matches_tool(tool_name):
                return entry
        return None

    def get_for_path(self, path: str | Path) -> BaseParser | None:
        """Get parser for a file path extension."""

        for entry in self._entries:
            if entry.matches_path(path):
                return entry.parser
        return None

    def list_entries(self) -> list[dict[str, Any]]:
        """List registered parsers."""

        return [
            {
                "tool_name": entry.tool_name,
                "aliases": list(entry.aliases),
                "file_extensions": list(entry.file_extensions),
                "parser": entry.parser.__class__.__name__,
            }
            for entry in self._entries
        ]

    def parse_text(
        self,
        tool_name: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ParserDispatchResult:
        """Parse text output for a tool."""

        parser = self.get(tool_name)
        if parser is None:
            return ParserDispatchResult(
                parser_used=None,
                result=None,
                errors=[f"No parser registered for tool: {tool_name}"],
            )

        try:
            result = parser.parse_text(text, metadata=metadata or {})
            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=result,
                errors=list(getattr(result, "errors", []) or []),
            )
        except Exception as exc:
            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=None,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    def parse_json(
        self,
        tool_name: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> ParserDispatchResult:
        """Parse JSON output for a tool."""

        parser = self.get(tool_name)
        if parser is None:
            return ParserDispatchResult(
                parser_used=None,
                result=None,
                errors=[f"No parser registered for tool: {tool_name}"],
            )

        try:
            result = parser.parse_json(payload, metadata=metadata or {})
            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=result,
                errors=list(getattr(result, "errors", []) or []),
            )
        except Exception as exc:
            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=None,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

    def parse_file(
        self,
        tool_name: str,
        path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> ParserDispatchResult:
        """Parse file output for a tool."""

        parser = self.get(tool_name) or self.get_for_path(path)
        if parser is None:
            return ParserDispatchResult(
                parser_used=None,
                result=None,
                errors=[f"No parser registered for tool/path: {tool_name} / {path}"],
            )

        try:
            try:
                result = parser.parse_file(path, metadata=metadata or {})
            except TypeError as exc:
                if "metadata" not in str(exc):
                    raise
                result = parser.parse_file(path)

            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=result,
                errors=list(getattr(result, "errors", []) or []),
            )
        except Exception as exc:
            return ParserDispatchResult(
                parser_used=parser.__class__.__name__,
                result=None,
                errors=[f"{type(exc).__name__}: {exc}"],
            )


def default_parser_entries() -> list[ParserRegistryEntry]:
    """Return default SABER parser registry entries."""

    return [
        ParserRegistryEntry(
            tool_name="nmap",
            parser=NmapParser(),
            aliases=("nmap_service_scan", "nmap_tcp", "nmap_udp"),
            file_extensions=("xml",),
        ),
        ParserRegistryEntry(
            tool_name="whatweb",
            parser=WhatWebParser(),
            aliases=("web_fingerprint", "whatweb_fingerprint"),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="nuclei",
            parser=NucleiParser(),
            aliases=("nuclei_scan", "template_scan"),
            file_extensions=("json", "jsonl"),
        ),
        ParserRegistryEntry(
            tool_name="nikto",
            parser=NiktoParser(),
            aliases=("nikto_scan", "web_scan"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="searchsploit",
            parser=SearchSploitParser(),
            aliases=("exploitdb", "exploit_search"),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="sqlmap",
            parser=SqlmapParser(),
            aliases=("injection_test", "sql_injection"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="bloodhound",
            parser=BloodHoundParser(),
            aliases=("bloodhound-python", "sharphound", "ad_graph"),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="masscan",
            parser=MasscanParser(),
            aliases=("masscan_scan", "port_sweep", "scan_ports"),
            file_extensions=("json", "txt", "list"),
        ),
        ParserRegistryEntry(
            tool_name="subfinder",
            parser=SubfinderParser(),
            aliases=("subdomain_enum", "passive_subdomains"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="amass",
            parser=AmassParser(),
            aliases=("amass_enum", "asset_enum"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="dnsrecon",
            parser=DNSReconParser(),
            aliases=("dns_enum", "dns_recon"),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="theharvester",
            parser=TheHarvesterParser(),
            aliases=("theHarvester", "osint_harvest", "email_harvest"),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="responder",
            parser=ResponderParser(),
            aliases=("responder_listen", "llmnr_poison", "ntlm_capture"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="snmpwalk",
            parser=SnmpwalkParser(),
            aliases=("snmp_enum", "snmp_walk"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="zap",
            parser=ZapParser(),
            aliases=("zap_api", "owasp_zap"),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="feroxbuster",
            parser=FeroxbusterParser(),
            aliases=("content_discovery", "dirbust"),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="openvas",
            parser=OpenVASParser(),
            aliases=("openvas_api", "gvm"),
            file_extensions=("xml",),
        ),
        ParserRegistryEntry(
            tool_name="bettercap",
            parser=BettercapParser(),
            aliases=("net_probe", "net_recon", "net_show"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="netexec",
            parser=NetExecParser(),
            aliases=("nxc", "netexec_smb", "netexec_ldap"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="enum4linux",
            parser=Enum4LinuxParser(),
            aliases=("enum4linux-ng", "smb_enum", "smb_enumeration"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="checksec",
            parser=ChecksecParser(),
            aliases=("binary_hardening",),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="file",
            parser=FileParser(),
            aliases=("file_identify", "libmagic"),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="strings",
            parser=StringsParser(),
            aliases=("string_extract",),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="pwntools",
            parser=PwntoolsParser(),
            aliases=("pwn", "gdb", "binary_exploit"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="radare2",
            parser=Radare2Parser(),
            aliases=("r2",),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="ghidra_headless",
            parser=GhidraHeadlessParser(),
            aliases=("ghidra",),
            file_extensions=("txt",),
        ),
        ParserRegistryEntry(
            tool_name="linpeas",
            parser=LinpeasParser(),
            aliases=("linux_privesc_enum",),
            file_extensions=("txt", "out", "log"),
        ),
        ParserRegistryEntry(
            tool_name="winpeas",
            parser=WinpeasParser(),
            aliases=("windows_privesc_enum",),
            file_extensions=("txt", "out", "log"),
        ),
        ParserRegistryEntry(
            tool_name="plan",
            parser=PlanParser(),
            aliases=("lateral_movement_planner",),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="path_validation",
            parser=PathValidationParser(),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="session_checks",
            parser=SessionChecksParser(),
            file_extensions=("json",),
        ),
        ParserRegistryEntry(
            tool_name="metasploit",
            parser=MetasploitParser(),
            aliases=("msfconsole", "msf_module"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="mimikatz",
            parser=MimikatzParser(),
            aliases=("credential_dump", "sekurlsa"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="hashcat",
            parser=HashcatParser(),
            aliases=("hashcat_show", "hashcat_crack"),
            file_extensions=("txt", "pot"),
        ),
        ParserRegistryEntry(
            tool_name="john",
            parser=JohnParser(),
            aliases=("john_the_ripper",),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="chisel",
            parser=ChiselParser(),
            aliases=("tunnel", "reverse_socks"),
            file_extensions=("txt", "log"),
        ),
        ParserRegistryEntry(
            tool_name="impacket",
            parser=ImpacketParser(),
            aliases=(
                "impacket_get_ad_users",
                "impacket_get_spns",
                "impacket_get_asrep_candidates",
                "impacket_smb_exec_check",
            ),
            file_extensions=("txt",),
        ),
    ]


def build_default_parser_registry() -> ParserRegistry:
    """Build default parser registry."""

    return ParserRegistry(entries=default_parser_entries())


def _normalize_tool_name(tool_name: str) -> str:
    """Normalize tool name for matching."""

    return str(tool_name or "").strip().lower().replace("-", "_").replace(" ", "_")
