"""Parser registry for SABER tool results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.parsers.base import BaseParser, ParserResult
from saber.parsers.bloodhound import BloodHoundParser
from saber.parsers.nmap import NmapParser
from saber.parsers.nuclei import NucleiParser
from saber.parsers.searchsploit import SearchSploitParser
from saber.parsers.whatweb import WhatWebParser


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
            tool_name="searchsploit",
            parser=SearchSploitParser(),
            aliases=("exploitdb", "exploit_search"),
            file_extensions=("json", "txt"),
        ),
        ParserRegistryEntry(
            tool_name="bloodhound",
            parser=BloodHoundParser(),
            aliases=("bloodhound-python", "sharphound", "ad_graph"),
            file_extensions=("json",),
        ),
    ]


def build_default_parser_registry() -> ParserRegistry:
    """Build default parser registry."""

    return ParserRegistry(entries=default_parser_entries())


def _normalize_tool_name(tool_name: str) -> str:
    """Normalize tool name for matching."""

    return str(tool_name or "").strip().lower().replace("-", "_").replace(" ", "_")
