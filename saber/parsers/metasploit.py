"""Metasploit (msfconsole) output parser for SABER.

msfconsole has no stable machine-readable output format, so this parses the
human-readable console transcript that ``MetasploitWrapper`` produces via
``msfconsole -q -x "<script>; exit -y"``:

- A module search results table (``search_modules``) -- one row per matching
  module -- becomes one ``note`` observation per module (read-only, no
  session/vuln is ever implied by a search).
- ``Meterpreter session N opened (...)`` (``run_module``) becomes a
  ``session`` observation (``data["kind"] = "meterpreter"``, ``ref`` = the
  session id).
- A ``[+]`` line that confirms the target is vulnerable (``check_module``)
  becomes a ``vuln`` observation (``confirmed=True``).
- Any other ``[+]`` success line becomes a generic ``note`` observation.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "   0  exploit/windows/smb/ms17_010_eternalblue   2017-03-14  average  Yes  MS17-010 ..."
_SEARCH_ROW_RE = re.compile(
    r"^\s*\d+\s+(?P<module>\S+/\S+)\s+(?P<date>\S+)\s+(?P<rank>\S+)\s+"
    r"(?P<check>Yes|No)\s+(?P<description>.+?)\s*$"
)

# "msf6 > use exploit/windows/smb/ms17_010_eternalblue"
_USE_MODULE_RE = re.compile(r"^msf\d*\s*(?:\S+\s*)?>\s*use\s+(?P<module>\S+)\s*$")

# "Meterpreter session 1 opened (10.10.14.5:4444 -> 10.129.42.10:49158) at ..."
_SESSION_RE = re.compile(
    r"Meterpreter session (?P<id>\d+) opened\s*"
    r"\((?P<lhost>[^:]+):(?P<lport>\d+)\s*->\s*(?P<rhost>[^:]+):(?P<rport>\d+)\)"
)

# "[+] 10.129.42.10:445 - The target is vulnerable."
_VULN_RE = re.compile(
    r"^\[\+\]\s+(?P<host>[\d.]+)(?::(?P<port>\d+))?\s*-\s*(?P<message>.*\bvulnerable\b.*)$",
    re.IGNORECASE,
)

# Any other "[+] ..." success line.
_NOTE_RE = re.compile(r"^\[\+\]\s*(?P<message>.+)$")


class MetasploitParser(BaseParser):
    """Parse msfconsole console transcripts into canonical observations."""

    source_tool = "metasploit"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse an msfconsole console transcript."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Metasploit output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen_notes: set[str] = set()
        seen_vulns: set[tuple[str, str | None]] = set()
        seen_sessions: set[int] = set()
        current_module: str | None = None

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            use_match = _USE_MODULE_RE.match(line)
            if use_match is not None:
                current_module = use_match.group("module")
                continue

            search_match = _SEARCH_ROW_RE.match(line)
            if search_match is not None:
                observation = self._search_row(search_match, seen_notes)
                if observation is not None:
                    observations.append(observation)
                continue

            session_match = _SESSION_RE.search(line)
            if session_match is not None:
                observation = self._session(session_match, seen_sessions)
                if observation is not None:
                    observations.append(observation)
                continue

            vuln_match = _VULN_RE.match(line)
            if vuln_match is not None:
                observation = self._vuln(vuln_match, current_module, seen_vulns)
                if observation is not None:
                    observations.append(observation)
                continue

            note_match = _NOTE_RE.match(line)
            if note_match is not None:
                observation = self._note(note_match, seen_notes)
                if observation is not None:
                    observations.append(observation)
                continue

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Metasploit results could be parsed."],
            metadata={
                "note_count": len(seen_notes),
                "vuln_count": len(seen_vulns),
                "session_count": len(seen_sessions),
            },
        )

    def _search_row(
        self, match: re.Match[str], seen_notes: set[str]
    ) -> ParsedObservation | None:
        """Build a note observation from one module-search results row."""

        module = match.group("module")
        title = f"Metasploit search match: {module}"
        if title in seen_notes:
            return None
        seen_notes.add(title)

        description = match.group("description").strip()
        return ParsedObservation(
            kind="note",
            summary=f"Metasploit search matched module {module}",
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": description,
                "severity": "info",
                "refs": [],
                "metadata": {"rank": match.group("rank"), "check": match.group("check")},
            },
        )

    def _session(
        self, match: re.Match[str], seen_sessions: set[int]
    ) -> ParsedObservation | None:
        """Build a session observation from a Meterpreter session-open line."""

        session_id = int(match.group("id"))
        if session_id in seen_sessions:
            return None
        seen_sessions.add(session_id)

        rhost = match.group("rhost")
        return ParsedObservation(
            kind="session",
            summary=f"Meterpreter session {session_id} opened on {rhost}",
            source_tool=self.source_tool,
            data={
                "host": rhost,
                "kind": "meterpreter",
                "privilege": "user",
                "ref": str(session_id),
                "metadata": {"lhost": match.group("lhost"), "lport": match.group("lport")},
            },
        )

    def _vuln(
        self,
        match: re.Match[str],
        current_module: str | None,
        seen_vulns: set[tuple[str, str | None]],
    ) -> ParsedObservation | None:
        """Build a vuln observation from a confirmed-vulnerable check line."""

        host = match.group("host")
        title = f"Metasploit: {current_module or 'target'} confirmed vulnerable"
        key = (host, current_module)
        if key in seen_vulns:
            return None
        seen_vulns.add(key)

        return ParsedObservation(
            kind="vuln",
            summary=f"Metasploit confirmed {current_module or 'module'} is exploitable on {host}",
            source_tool=self.source_tool,
            data={
                "title": title,
                "host": host,
                "port": int(match.group("port")) if match.group("port") else None,
                "severity": "high",
                "identifier": current_module,
                "confirmed": True,
            },
            metadata={"message": match.group("message").strip()},
        )

    def _note(self, match: re.Match[str], seen_notes: set[str]) -> ParsedObservation | None:
        """Build a generic note observation from a ``[+]`` success line."""

        message = match.group("message").strip()
        title = f"Metasploit: {message}"
        if title in seen_notes:
            return None
        seen_notes.add(title)

        return ParsedObservation(
            kind="note",
            summary=f"Metasploit: {message}",
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": message,
                "severity": "info",
                "refs": [],
                "metadata": {},
            },
        )
