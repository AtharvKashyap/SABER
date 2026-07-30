"""pwntools / gdb output parser for SABER.

The whole point of this parser is to make an exploit *attempt* legible to the
decider so it can revise and try again. So it reports failure as carefully as
success:

- a recovered flag -> ``kind="flag"`` (the mission objective on a CTF target)
- a crash (SIGSEGV / "Program received signal") -> ``kind="note"``, severity high:
  a segfault means the input reached the instruction pointer, which is progress
- a leaked address, a "corrupted"/canary message, an EOF -> ``kind="note"``, so the
  next attempt can use the leak or fix the offset
- a Python traceback from the script itself -> ``kind="note"``, severity high: the
  script is broken, which is a different problem from the exploit being wrong

Note titles are unique per finding because the note merger dedupes on title.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_FLAG_RE = re.compile(r"\b(?:flag|FLAG|HTB|picoCTF|CTF)\{[^{}]{1,256}\}")
_SIGNAL_RE = re.compile(
    r"Program received signal\s+(?P<signal>SIG\w+)|(?P<segv>SIGSEGV|Segmentation fault)",
)
_LEAK_RE = re.compile(r"(?:leak(?:ed)?|address|canary)\D{0,20}(?P<value>0x[0-9a-fA-F]{6,16})")
_CANARY_RE = re.compile(r"stack smashing detected|\*\*\* stack smashing|canary\s+(?:found|value)")
_EOF_RE = re.compile(r"\bEOFError\b|Got EOF while|pwnlib.*EOF")
_TRACEBACK_RE = re.compile(r"^Traceback \(most recent call last\)")
_EXITED_RE = re.compile(r"\[Inferior \d+ .*exited (?:normally|with code (?P<code>\d+))\]")


class PwntoolsParser(BaseParser):
    """Parse exploit-attempt output into flags and iteration-useful notes."""

    source_tool = "pwntools"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse pwntools/gdb stdout+stderr."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["pwntools output is empty."],
            )

        context = metadata or {}
        binary_path = str(context.get("binary_path") or "").strip() or None
        host = str(context.get("target") or "").strip() or None

        observations: list[ParsedObservation] = []
        seen_flags: set[str] = set()
        seen_titles: set[str] = set()

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
                        "metadata": {**extra, "binary_path": binary_path},
                    },
                )
            )

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            for flag in _FLAG_RE.findall(line):
                if flag in seen_flags:
                    continue
                seen_flags.add(flag)
                observations.append(
                    ParsedObservation(
                        kind="flag",
                        summary=f"Flag recovered via exploit: {flag}",
                        source_tool=self.source_tool,
                        data={
                            "value": flag,
                            "host": host,
                            "location": binary_path,
                            "metadata": {"source": "pwntools"},
                        },
                    )
                )

            if _TRACEBACK_RE.match(line):
                add_note(
                    "Exploit script raised a Python traceback",
                    (
                        "The pwntools script itself failed to run. Fix the script before "
                        "concluding anything about the binary."
                    ),
                    "high",
                    {"outcome": "script_error"},
                )
                continue

            signal = _SIGNAL_RE.search(line)
            if signal is not None:
                name = signal.group("signal") or "SIGSEGV"
                add_note(
                    f"Binary crashed with {name}",
                    (
                        f"The target terminated on {name}. Control of the instruction "
                        f"pointer is plausible — refine the offset and payload."
                    ),
                    "high",
                    {"outcome": "crash", "signal": name},
                )
                continue

            if _CANARY_RE.search(line):
                add_note(
                    "Stack canary tripped",
                    (
                        "The overflow was detected by a stack canary. A straight return-"
                        "address overwrite will not work; leak the canary or find another path."
                    ),
                    "medium",
                    {"outcome": "canary"},
                )
                continue

            leak = _LEAK_RE.search(line)
            if leak is not None:
                value = leak.group("value")
                add_note(
                    f"Address leaked: {value}",
                    f"The target disclosed {value}; usable to defeat ASLR/PIE in the next attempt.",
                    "high",
                    {"outcome": "leak", "address": value},
                )
                continue

            if _EOF_RE.search(line):
                add_note(
                    "Target closed the connection (EOF)",
                    (
                        "The process ended before the script finished interacting. The payload "
                        "may be malformed or the offset wrong."
                    ),
                    "medium",
                    {"outcome": "eof"},
                )
                continue

            exited = _EXITED_RE.search(line)
            if exited is not None:
                code = exited.group("code")
                add_note(
                    f"Binary exited cleanly (code {code or '0'})",
                    "The target ran to completion without crashing; the payload had no effect.",
                    "info",
                    {"outcome": "clean_exit", "exit_code": code or "0"},
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No exploit outcome could be parsed."],
            metadata={
                "format": "stdout",
                "flag_count": len(seen_flags),
                "note_count": len(seen_titles),
            },
        )
