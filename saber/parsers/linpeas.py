"""LinPEAS output parser for SABER.

LinPEAS prints thousands of lines. Emitting one observation per line would
flood ``MissionState`` and bury the handful of findings that actually matter, so
this parser distils:

- LinPEAS' own 95%/99% privilege-escalation probability highlights -> ``note``
  (severity ``high``/``critical``, because LinPEAS is asserting a likely root path)
- sudo, SUID and writable-service misconfigurations -> ``note`` (``medium``)
- credential-bearing files it stumbles on -> ``loot`` (``kind="file"``)
- one summary ``note`` recording how much output was seen but not surfaced

Note titles must be unique because ``StateMerger``'s note merger dedupes on
title; each title therefore embeds the specific finding.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Strips BOTH real escape sequences ("\x1b[1;31m") and the bare bracket form
# ("[1;31m") that survives when something upstream ate the ESC byte — evidence
# capture, a log pipeline, or a fixture. Matching only the ESC form let residue
# like "...privilege escalation[0m" into note titles, which were then persisted to
# MissionState and rendered into the report.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\[[0-9]{1,2}(?:;[0-9]{1,2})*m")
# "╔══════════╣ ..." / "═╣" section banners are noise, but the PE probability
# highlights look like: "99% PE - CVE-2021-4034 (pwnkit)"
_PROBABILITY_RE = re.compile(r"(?P<pct>\d{2,3})%\s*PE\s*[-:]?\s*(?P<detail>.+)", re.IGNORECASE)
_SUDO_RE = re.compile(r"^\s*\(.*\)\s+(?P<nopasswd>NOPASSWD:)?\s*(?P<cmd>/\S+)")
_SUID_RE = re.compile(r"(?P<path>/\S+)\s*(?:-->|=>)\s*(?P<note>.+)")
_WRITABLE_SERVICE_RE = re.compile(
    r"(?P<path>/\S+\.service)\s+is\s+writable|writable.*?(?P<path2>/\S+\.service)",
    re.IGNORECASE,
)
_CREDENTIAL_FILE_RE = re.compile(
    r"(?P<path>/\S*(?:id_rsa|id_ed25519|\.kdbx|shadow|credentials?|\.pgpass|\.netrc)\S*)",
    re.IGNORECASE,
)

_HIGH_CONFIDENCE = 95


class LinpeasParser(BaseParser):
    """Distil LinPEAS output into canonical note and loot observations."""

    source_tool = "linpeas"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse LinPEAS stdout, keeping only the actionable findings."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["LinPEAS output is empty."],
            )

        host = str((metadata or {}).get("target") or "").strip() or None

        observations: list[ParsedObservation] = []
        seen_titles: set[str] = set()
        seen_loot: set[str] = set()
        line_count = 0

        def add_note(title: str, detail: str, severity: str, extra: dict[str, Any]) -> None:
            if title in seen_titles:
                return
            seen_titles.add(title)
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": detail,
                        "severity": severity,
                        "metadata": {**extra, "host": host},
                    },
                )
            )

        for raw_line in stripped.splitlines():
            line_count += 1
            line = _ANSI_RE.sub("", raw_line).strip()
            if not line:
                continue

            probability = _PROBABILITY_RE.search(line)
            if probability is not None:
                try:
                    percent = int(probability.group("pct"))
                except ValueError:
                    percent = 0
                detail = probability.group("detail").strip()
                severity = "critical" if percent >= _HIGH_CONFIDENCE else "high"
                add_note(
                    f"LinPEAS PE vector ({percent}%): {detail}",
                    f"LinPEAS rates this a {percent}% likely privilege-escalation route.",
                    severity,
                    {"probability": percent, "finding": detail},
                )
                continue

            credential_file = _CREDENTIAL_FILE_RE.search(line)
            if credential_file is not None:
                path = credential_file.group("path")
                if path not in seen_loot:
                    seen_loot.add(path)
                    observations.append(
                        ParsedObservation(
                            kind="loot",
                            summary=f"Credential-bearing file readable: {path}",
                            source_tool=self.source_tool,
                            data={
                                "description": f"LinPEAS found a sensitive file at {path}.",
                                "kind": "file",
                                "path": path,
                                "host": host,
                                "metadata": {"raw": line[:200]},
                            },
                        )
                    )
                continue

            writable = _WRITABLE_SERVICE_RE.search(line)
            if writable is not None:
                path = writable.group("path") or writable.group("path2")
                add_note(
                    f"Writable service unit: {path}",
                    f"{path} is writable by the current user, allowing service hijack.",
                    "high",
                    {"path": path},
                )
                continue

            if "NOPASSWD" in line:
                sudo = _SUDO_RE.match(line)
                command = sudo.group("cmd") if sudo else line
                add_note(
                    f"Passwordless sudo: {command}",
                    f"The current user may run {command} via sudo without a password.",
                    "high",
                    {"command": command},
                )
                continue

            if "suid" in line.lower():
                suid = _SUID_RE.search(line)
                if suid is not None:
                    path = suid.group("path")
                    add_note(
                        f"Notable SUID binary: {path}",
                        f"{path} is SUID and flagged by LinPEAS: {suid.group('note').strip()}",
                        "medium",
                        {"path": path},
                    )
                    continue

        if observations:
            title = "LinPEAS enumeration summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Reviewed {line_count} lines of LinPEAS output and surfaced "
                            f"{len(seen_titles)} finding(s) and {len(seen_loot)} sensitive "
                            f"file(s). Full output is retained as evidence."
                        ),
                        "severity": "info",
                        "metadata": {
                            "lines_reviewed": line_count,
                            "findings": len(seen_titles),
                            "loot": len(seen_loot),
                            "host": host,
                        },
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No LinPEAS findings could be parsed."],
            metadata={
                "format": "stdout",
                "lines_reviewed": line_count,
                "note_count": len(seen_titles),
                "loot_count": len(seen_loot),
            },
        )
