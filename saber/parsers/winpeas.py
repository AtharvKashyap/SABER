"""winPEAS output parser for SABER.

Like LinPEAS, winPEAS prints thousands of lines, so this parser distils rather
than emitting per-line observations (which would flood ``MissionState`` and bury
the findings that matter):

- unquoted service paths, AlwaysInstallElevated, writable service binaries and
  impersonation privileges -> ``note`` (these are the classic SYSTEM routes)
- stored credentials (autologon, saved RDP/WiFi creds, credential files) -> ``loot``
- one summary ``note`` recording how much output was reviewed

Note titles must be unique because ``StateMerger``'s note merger dedupes on
title; each title therefore embeds the specific finding.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Strips BOTH real escape sequences and the bare bracket form that survives when
# something upstream ate the ESC byte. See the note in saber/parsers/linpeas.py.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\[[0-9]{1,2}(?:;[0-9]{1,2})*m")
_UNQUOTED_RE = re.compile(
    r"(?:unquoted\s+service\s+path|no\s+quotes\s+and\s+space\s+detected).*?"
    r"(?P<path>[A-Za-z]:\\[^\r\n\"]+)",
    re.IGNORECASE,
)
_ALWAYS_ELEVATED_RE = re.compile(r"AlwaysInstallElevated.*?(?:set|enabled|1)", re.IGNORECASE)
_MODIFIABLE_RE = re.compile(
    r"(?:you\s+can\s+modify|modifiable|writable).*?(?P<path>[A-Za-z]:\\[^\r\n\"]+)",
    re.IGNORECASE,
)
_PRIVILEGE_RE = re.compile(r"(?P<priv>Se\w+Privilege)\s*:?\s*(?P<state>ENABLED|Enabled)")
_AUTOLOGON_RE = re.compile(
    r"(?:DefaultUserName|DefaultPassword|AutoAdminLogon)\s*[:=]\s*(?P<value>\S+)",
    re.IGNORECASE,
)
_CREDENTIAL_FILE_RE = re.compile(
    r"(?P<path>[A-Za-z]:\\[^\r\n\"]*(?:unattend\.xml|sysprep\.inf|\.kdbx|"
    r"credentials?|web\.config|id_rsa)[^\r\n\"]*)",
    re.IGNORECASE,
)

# Privileges that hand you SYSTEM outright.
_CRITICAL_PRIVILEGES = {
    "seimpersonateprivilege",
    "seassignprimarytokenprivilege",
    "sedebugprivilege",
    "setakeownershipprivilege",
    "sebackupprivilege",
    "serestoreprivilege",
}


class WinpeasParser(BaseParser):
    """Distil winPEAS output into canonical note and loot observations."""

    source_tool = "winpeas"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse winPEAS stdout, keeping only the actionable findings."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["winPEAS output is empty."],
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

        def add_loot(description: str, path: str | None, loot_kind: str, raw: str) -> None:
            key = path or description
            if key in seen_loot:
                return
            seen_loot.add(key)
            observations.append(
                ParsedObservation(
                    kind="loot",
                    summary=description,
                    source_tool=self.source_tool,
                    data={
                        "description": description,
                        "kind": loot_kind,
                        "path": path,
                        "host": host,
                        "metadata": {"raw": raw[:200]},
                    },
                )
            )

        for raw_line in stripped.splitlines():
            line_count += 1
            line = _ANSI_RE.sub("", raw_line).strip()
            if not line:
                continue

            unquoted = _UNQUOTED_RE.search(line)
            if unquoted is not None:
                path = unquoted.group("path").strip()
                add_note(
                    f"Unquoted service path: {path}",
                    f"{path} is an unquoted service path, allowing binary planting.",
                    "high",
                    {"path": path},
                )
                continue

            if _ALWAYS_ELEVATED_RE.search(line):
                add_note(
                    "AlwaysInstallElevated is enabled",
                    "MSI packages install as SYSTEM, giving a direct escalation route.",
                    "critical",
                    {"finding": "AlwaysInstallElevated"},
                )
                continue

            autologon = _AUTOLOGON_RE.search(line)
            if autologon is not None:
                add_loot(
                    f"Autologon credential material in registry: {line.split(':')[0].strip()}",
                    None,
                    "config",
                    line,
                )
                continue

            credential_file = _CREDENTIAL_FILE_RE.search(line)
            if credential_file is not None:
                path = credential_file.group("path").strip()
                add_loot(f"Credential-bearing file found: {path}", path, "file", line)
                continue

            privilege = _PRIVILEGE_RE.search(line)
            if privilege is not None:
                priv = privilege.group("priv")
                severity = "critical" if priv.lower() in _CRITICAL_PRIVILEGES else "medium"
                add_note(
                    f"Token privilege enabled: {priv}",
                    f"The current token holds {priv}, which is a known escalation primitive.",
                    severity,
                    {"privilege": priv},
                )
                continue

            modifiable = _MODIFIABLE_RE.search(line)
            if modifiable is not None:
                path = modifiable.group("path").strip()
                add_note(
                    f"Writable privileged path: {path}",
                    f"{path} is modifiable by the current user, allowing service/binary hijack.",
                    "high",
                    {"path": path},
                )

        if observations:
            title = "winPEAS enumeration summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Reviewed {line_count} lines of winPEAS output and surfaced "
                            f"{len(seen_titles)} finding(s) and {len(seen_loot)} credential "
                            f"artifact(s). Full output is retained as evidence."
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
            errors=[] if observations else ["No winPEAS findings could be parsed."],
            metadata={
                "format": "stdout",
                "lines_reviewed": line_count,
                "note_count": len(seen_titles),
                "loot_count": len(seen_loot),
            },
        )
