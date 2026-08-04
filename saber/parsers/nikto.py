"""Nikto output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_OSVDB_RE = re.compile(r"OSVDB-(\d+)")
_TARGET_IP_RE = re.compile(r"^\+\s*Target IP:\s*(\S+)", re.IGNORECASE)
_TARGET_HOST_RE = re.compile(r"^\+\s*Target Hostname:\s*(\S+)", re.IGNORECASE)
# Nikto 2.5+ cites CVEs and its own references instead of OSVDB, which was retired
# in 2016. Keying only on OSVDB meant a real modern scan produced ZERO observations.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# Header/administrivia lines that start with "+" but are not findings.
_NON_FINDING_RE = re.compile(
    r"^\+\s*(?:Target (?:IP|Hostname|Port)|Start Time|End Time|Server:|SSL Info|"
    r"\d+ host\(s\) tested|"
    # "+ 7915 requests: 0 error(s) and 3 item(s) reported on remote host"
    r"\d+ requests:)",
    re.IGNORECASE,
)
# Severity keywords must match as WORDS. Substring matching made "low" fire on
# "allow"/"follow"/"below" and "info" fire on "information", so
# "+ OPTIONS: Allowed HTTP methods" was tagged low.
_SEVERITY_WORD_RES = tuple(
    (keyword, re.compile(rf"\b{keyword}\b", re.IGNORECASE))
    for keyword in ("critical", "high", "medium", "low", "info")
)


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

            # Skip header/administrivia lines, which also begin with "+".
            if _NON_FINDING_RE.match(line):
                continue

            osvdb_match = _OSVDB_RE.search(line)
            cve_match = _CVE_RE.search(line)
            if osvdb_match:
                identifier = f"OSVDB-{osvdb_match.group(1)}"
            elif cve_match:
                identifier = cve_match.group(0).upper()
            else:
                # Nikto 2.5 emits plenty of real findings with no identifier at all
                # (exposed files, dangerous methods, missing headers). Requiring an
                # identifier discarded them and made a modern scan look clean.
                identifier = None

            title = line.lstrip("+").strip()
            if not title:
                continue
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

        for keyword, pattern in _SEVERITY_WORD_RES:
            if pattern.search(line):
                return self.severity_from_string(keyword).value
        return "info"
