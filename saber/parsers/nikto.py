"""Nikto output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_OSVDB_RE = re.compile(r"OSVDB-(\d+)")
_TARGET_IP_RE = re.compile(r"^\+\s*Target IP:\s*(\S+)", re.IGNORECASE)
_TARGET_HOST_RE = re.compile(r"^\+\s*Target Hostname:\s*(\S+)", re.IGNORECASE)
_SEVERITY_KEYWORDS = ("critical", "high", "medium", "low", "info")


class NiktoParser(BaseParser):
    """Parse Nikto stdout report text into vulnerability findings."""

    source_tool = "nikto"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Nikto stdout output.

        Each ``+ OSVDB-<id>: ...`` line becomes one ``kind="vuln"`` observation.
        ``host`` prefers ``metadata["target"]``, falling back to the
        ``Target IP``/``Target Hostname`` lines in the report itself.
        """

        stripped = text.strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Nikto output is empty."],
            )

        metadata = metadata or {}
        host = str(metadata.get("target") or "").strip() or None

        observations: list[ParsedObservation] = []

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line.startswith("+"):
                continue

            if host is None:
                ip_match = _TARGET_IP_RE.match(line)
                host_match = _TARGET_HOST_RE.match(line)
                if ip_match:
                    host = ip_match.group(1)
                elif host_match:
                    host = host_match.group(1)

            osvdb_match = _OSVDB_RE.search(line)
            if not osvdb_match:
                continue

            identifier = f"OSVDB-{osvdb_match.group(1)}"
            title = line.lstrip("+").strip()
            severity = self._severity_for_line(line)

            observations.append(
                ParsedObservation(
                    kind="vuln",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "host": host,
                        "severity": severity,
                        "identifier": identifier,
                        "confirmed": True,
                    },
                    metadata={"raw": line},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Nikto findings could be parsed."],
            metadata={"format": "stdout", "finding_count": len(observations)},
        )

    def _severity_for_line(self, line: str) -> str:
        """Return a severity string for a Nikto finding line.

        Nikto findings do not carry an explicit severity; if the line mentions
        one of the normalized severity keywords it is used, otherwise the
        finding defaults to "info".
        """

        lowered = line.lower()
        for keyword in _SEVERITY_KEYWORDS:
            if keyword in lowered:
                return self.severity_from_string(keyword).value
        return "info"
