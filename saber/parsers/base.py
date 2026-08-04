"""Base parser models and interfaces for SABER.

Canonical observation schema (single source of truth)
-----------------------------------------------------
Every ``ParsedObservation.kind`` a parser emits MUST be one of the fixed
canonical kinds below, and each kind carries a fixed ``data`` schema. This is
the vocabulary ``StateMerger`` folds into ``MissionState`` (one merger per
kind). Required fields are marked ``(req)``. ``kind -> MissionState list``:

- host -> hosts (KnownHost):
    address (req), hostnames: list[str], os, metadata
- service -> services (KnownService):
    host (req), port (req, int), protocol, service, product, version, state
- technology -> technologies (KnownTechnology):
    host (req), name (req), version, metadata
- credential -> credentials (KnownCredential):
    username (req), secret, kind (password|hash|key|token), host, service,
    validated: bool
- vuln -> vulns (KnownVuln):
    title (req), host, port, severity, identifier (CVE/template id),
    confirmed: bool
- share -> shares (KnownShare):
    host (req), name (req), type (smb|nfs|...), access (read|write|none),
    metadata
- account -> accounts (KnownAccount):
    username (req), domain, host, source, enabled: bool, metadata
- session -> sessions (KnownSession):
    host (req), kind (shell|meterpreter|winrm|ssh|smb), user,
    privilege (user|root|system|admin), ref, metadata
    ``smb``/``admin`` cover proven administrative access over a protocol that is not
    itself an interactive shell (netexec "Pwn3d!"), which is a real foothold and can
    be turned into a shell. Do NOT record mere reachability as a session — see
    saber/parsers/chisel.py for the counter-example.
- loot -> loot (KnownLoot):
    host, path, kind (file|hash|key|config), description (req), evidence_ref,
    metadata
- flag -> flags (KnownFlag):
    value (req), host, location, metadata
- note -> notes (list[MissionNote]):
    title (req), detail, severity, refs: list[str], metadata

Note on ``finding``/``note``: the observation-level ``kind`` string is always
``"note"`` (title+detail+refs); a parser MAY set ``data["kind"]`` sub-fields.

All parser entry points (``parse_text``/``parse_json``/``parse_file``) accept an
optional ``metadata`` kwarg carrying target/url context so parsers can derive a
``host`` when tool output omits it.
"""

from __future__ import annotations

import json
import re
from abc import ABC
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class ParserSeverity(StrEnum):
    """Normalized parser severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ParsedObservation:
    """Normalized observation extracted from tool output."""

    kind: str
    summary: str
    source_tool: str
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate observation basics."""

        if not self.kind.strip():
            raise ValueError("ParsedObservation.kind cannot be empty.")
        if not self.summary.strip():
            raise ValueError("ParsedObservation.summary cannot be empty.")
        if not self.source_tool.strip():
            raise ValueError("ParsedObservation.source_tool cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible observation."""

        return {
            "kind": self.kind,
            "summary": self.summary,
            "source_tool": self.source_tool,
            "data": self.data,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ParsedFinding:
    """Normalized finding extracted from tool output."""

    title: str
    severity: ParserSeverity
    description: str
    source_tool: str
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate finding basics."""

        if not self.title.strip():
            raise ValueError("ParsedFinding.title cannot be empty.")
        if not self.description.strip():
            raise ValueError("ParsedFinding.description cannot be empty.")
        if not self.source_tool.strip():
            raise ValueError("ParsedFinding.source_tool cannot be empty.")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible finding."""

        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "source_tool": self.source_tool,
            "evidence": self.evidence,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ParserResult:
    """Result returned by a parser."""

    source_tool: str
    success: bool
    observations: list[ParsedObservation] = field(default_factory=list)
    findings: list[ParsedFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate parser result basics."""

        if not self.source_tool.strip():
            raise ValueError("ParserResult.source_tool cannot be empty.")

    def has_data(self) -> bool:
        """Return whether parser extracted observations or findings."""

        return bool(self.observations or self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible parser result."""

        return {
            "source_tool": self.source_tool,
            "success": self.success,
            "observations": [observation.to_dict() for observation in self.observations],
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }


# Terminal colouring, in both the form tools emit and the form that survives a
# round trip through storage. Several CLI tools colour stdout by default and
# interleave the escapes with the data, so leaving them in does not just look
# untidy — it corrupts the parse. whatweb produced a technology named "0m", and
# nuclei produced findings whose severity could not be read at all.
_ANSI_RE = re.compile(r"(?:\x1b|\033)\[[0-9;]*[A-Za-z]|(?<!\w)\[[0-9;]{1,6}m")


class BaseParser(ABC):
    """Base parser interface."""

    source_tool: str = "unknown"

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Remove terminal colouring from tool output.

        Handles the real escape sequence and the bare "[92m" residue left behind
        when the ESC byte is lost in transit. Parsers that read human-facing
        stdout should call this before anything else; passing --no-color to the
        tool is the other half, and both are needed because stored evidence
        predates the flag.
        """

        return _ANSI_RE.sub("", text or "")

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse text output. `metadata` may carry target/url context for host derivation."""

        raise NotImplementedError(f"{type(self).__name__}.parse_text is not implemented.")

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse JSON-compatible data. `metadata` may carry target/url context."""

        raise NotImplementedError(f"{type(self).__name__}.parse_json is not implemented.")

    def parse_file(
        self,
        path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse file by extension/content. `metadata` threads through to parse_*."""

        file_path = Path(path)
        if not file_path.exists():
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=[f"Parser input file does not exist: {file_path}"],
            )

        text = file_path.read_text(errors="replace")
        suffix = file_path.suffix.lower()

        if suffix in {".json", ".jsonl"}:
            try:
                if suffix == ".jsonl":
                    return self.parse_json(
                        [json.loads(line) for line in text.splitlines() if line.strip()],
                        metadata=metadata,
                    )
                return self.parse_json(json.loads(text), metadata=metadata)
            except json.JSONDecodeError:
                return self.parse_text(text, metadata=metadata)

        return self.parse_text(text, metadata=metadata)

    @staticmethod
    def severity_from_string(value: str | None) -> ParserSeverity:
        """Normalize severity string."""

        if not value:
            return ParserSeverity.UNKNOWN

        normalized = value.strip().lower()
        mapping = {
            "info": ParserSeverity.INFO,
            "informational": ParserSeverity.INFO,
            "low": ParserSeverity.LOW,
            "medium": ParserSeverity.MEDIUM,
            "med": ParserSeverity.MEDIUM,
            "high": ParserSeverity.HIGH,
            "critical": ParserSeverity.CRITICAL,
            "crit": ParserSeverity.CRITICAL,
            "unknown": ParserSeverity.UNKNOWN,
        }
        return mapping.get(normalized, ParserSeverity.UNKNOWN)

    @staticmethod
    def safe_json_loads(text: str) -> dict[str, Any] | list[Any] | None:
        """Safely parse JSON text."""

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def parse_json_lines(text: str) -> tuple[list[Any], list[str]]:
        """Parse JSON lines and return parsed objects plus errors."""

        objects: list[Any] = []
        errors: list[str] = []

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_number}: {exc}")

        return objects, errors
