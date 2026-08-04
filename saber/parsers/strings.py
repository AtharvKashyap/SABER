"""`strings` output parser for SABER.

A strings dump of a real binary is thousands of lines of library symbols. Emitting
an observation per line would bury everything, so this parser matches only what is
worth acting on and folds the residue into one summary note:

- CTF flags (``flag{...}`` and common variants) -> ``kind="flag"``; the mission
  loop's flag handling keys on this canonical kind (see ``saber/core/flag_detector.py``)
- credential material — connection strings, private-key headers, cloud access
  keys, explicit password assignments -> ``kind="loot"`` (``kind="key"``/``"config"``)
- merely notable strings — URLs, absolute system paths, format-string primitives,
  embedded shell commands -> ``kind="note"``

Note titles must be unique because the note merger dedupes on title.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_FLAG_RE = re.compile(
    r"\b(?:flag|FLAG|HTB|picoCTF|CTF|key)\{[^{}]{1,256}\}",
)
_CONNECTION_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql)(?:\+\w+)?://\S+:\S+@\S+",
    re.IGNORECASE,
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_CLOUD_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PASSWORD_ASSIGN_RE = re.compile(
    r"\b(?:password|passwd|pwd|secret|api_?key|token)\s*[=:]\s*(?P<value>\S{3,})",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"']{4,}", re.IGNORECASE)
_PATH_RE = re.compile(r"^/(?:etc|root|home|var|opt|usr/local)/\S{2,}$")
_FORMAT_STRING_RE = re.compile(r"%[0-9$]*[sxnp]")
# No surrounding \b: "/bin/sh" starts with a non-word char and "system(" ends with
# one, so word-boundary anchors would never match either.
_SHELL_CMD_RE = re.compile(r"/bin/(?:sh|bash)|system\(|\bexecve\b|\bpopen\b")


class StringsParser(BaseParser):
    """Distil a strings dump into flags, loot and notes."""

    source_tool = "strings"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse `strings` output, keeping only the interesting lines."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["strings output is empty."],
            )

        context = metadata or {}
        path = str(context.get("file_path") or "").strip() or None
        host = str(context.get("target") or "").strip() or None

        observations: list[ParsedObservation] = []
        seen_flags: set[str] = set()
        seen_loot: set[str] = set()
        seen_notes: set[str] = set()
        line_count = 0

        def add_note(title: str, detail: str, severity: str, extra: dict[str, Any]) -> None:
            if title in seen_notes:
                return
            seen_notes.add(title)
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": detail,
                        "severity": severity,
                        "metadata": {**extra, "path": path},
                    },
                )
            )

        def add_loot(description: str, loot_kind: str, raw: str) -> None:
            if description in seen_loot:
                return
            seen_loot.add(description)
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
            line = raw_line.strip()
            if not line:
                continue

            flag = _FLAG_RE.search(line)
            if flag is not None:
                value = flag.group(0)
                if value not in seen_flags:
                    seen_flags.add(value)
                    observations.append(
                        ParsedObservation(
                            kind="flag",
                            summary=f"Flag recovered from {path or 'binary'}: {value}",
                            source_tool=self.source_tool,
                            data={
                                "value": value,
                                "host": host,
                                "location": path,
                                "metadata": {"source": "strings"},
                            },
                        )
                    )
                continue

            if _PRIVATE_KEY_RE.search(line):
                add_loot("Embedded private key material", "key", line)
                continue

            connection = _CONNECTION_RE.search(line)
            if connection is not None:
                add_loot(
                    f"Embedded connection string: {connection.group(0)}",
                    "config",
                    line,
                )
                continue

            cloud_key = _CLOUD_KEY_RE.search(line)
            if cloud_key is not None:
                add_loot(f"Embedded cloud access key: {cloud_key.group(0)}", "key", line)
                continue

            assignment = _PASSWORD_ASSIGN_RE.search(line)
            if assignment is not None:
                add_loot(f"Embedded secret assignment: {line}", "config", line)
                continue

            url = _URL_RE.search(line)
            if url is not None:
                value = url.group(0)
                add_note(
                    f"Embedded URL: {value}",
                    f"The binary references {value}.",
                    "low",
                    {"url": value},
                )
                continue

            if _SHELL_CMD_RE.search(line):
                add_note(
                    f"Shell execution primitive: {line}",
                    f"The binary references {line}, suggesting command execution.",
                    "medium",
                    {"primitive": line},
                )
                continue

            if _FORMAT_STRING_RE.search(line) and "%" in line:
                add_note(
                    f"Format string present: {line}",
                    f"{line} may be a format-string primitive.",
                    "low",
                    {"format_string": line},
                )
                continue

            if _PATH_RE.match(line):
                add_note(
                    f"Referenced system path: {line}",
                    f"The binary references {line}.",
                    "info",
                    {"referenced_path": line},
                )

        if observations:
            title = f"strings summary: {path or 'binary'}"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Reviewed {line_count} extracted strings and surfaced "
                            f"{len(seen_flags)} flag(s), {len(seen_loot)} secret(s) and "
                            f"{len(seen_notes)} notable string(s)."
                        ),
                        "severity": "info",
                        "metadata": {
                            "strings_reviewed": line_count,
                            "flags": len(seen_flags),
                            "loot": len(seen_loot),
                            "path": path,
                        },
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No notable strings could be parsed."],
            metadata={
                "format": "stdout",
                "strings_reviewed": line_count,
                "flag_count": len(seen_flags),
                "loot_count": len(seen_loot),
                "note_count": len(seen_notes),
            },
        )
