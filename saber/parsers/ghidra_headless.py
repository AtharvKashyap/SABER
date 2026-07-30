"""Ghidra headless output parser for SABER.

``analyzeHeadless`` (and any -postScript it runs) prints large volumes of
analysis log noise. This parser distils that stream down to what a decider
planning a binary exploit actually needs:

- ``DECOMPILE SUMMARY: <function> @ <addr> -- <highlight>`` lines emitted by a
  decompiled-summary export script -> one ``kind="note"`` per function
  highlight (severity raised for exec/overflow-flavoured highlights).
- ``ERROR ...`` lines -> one ``kind="note"`` per distinct error message.
- one summary ``note`` recording how much log output was seen.

Note titles must be unique because ``StateMerger``'s note merger dedupes on
title; each title embeds the specific function/error.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_SUMMARY_RE = re.compile(
    r"^DECOMPILE SUMMARY:\s*(?P<func>\S+)\s*@\s*(?P<addr>\S+)\s*--\s*(?P<detail>.+)$"
)
_ERROR_RE = re.compile(r"^(?:ERROR|SEVERE)\b[:\s]*(?P<message>.+)$", re.IGNORECASE)
_HIGH_RISK_KEYWORDS = ("system(", "exec(", "overflow", "unsanitized", "buffer")


class GhidraHeadlessParser(BaseParser):
    """Distil Ghidra headless log output into canonical note observations."""

    source_tool = "ghidra_headless"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Ghidra headless stdout, keeping only decompiled-summary highlights."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Ghidra headless output is empty."],
            )

        metadata = metadata or {}
        binary_path = str(metadata.get("binary_path") or "").strip() or "unknown binary"

        observations: list[ParsedObservation] = []
        seen_titles: set[str] = set()
        line_count = 0
        summary_count = 0
        error_count = 0

        for raw_line in stripped.splitlines():
            line_count += 1
            line = raw_line.strip()
            if not line:
                continue

            summary_match = _SUMMARY_RE.match(line)
            if summary_match is not None:
                func = summary_match.group("func")
                detail = summary_match.group("detail").strip()
                title = f"Ghidra decompiled summary: {func} ({binary_path})"
                if title not in seen_titles:
                    seen_titles.add(title)
                    summary_count += 1
                    lowered = detail.lower()
                    severity = (
                        "high"
                        if any(keyword in lowered for keyword in _HIGH_RISK_KEYWORDS)
                        else "medium"
                    )
                    observations.append(
                        ParsedObservation(
                            kind="note",
                            summary=title,
                            source_tool=self.source_tool,
                            data={
                                "title": title,
                                "detail": detail,
                                "severity": severity,
                                "metadata": {
                                    "binary_path": binary_path,
                                    "function": func,
                                    "address": summary_match.group("addr"),
                                },
                            },
                        )
                    )
                continue

            error_match = _ERROR_RE.match(line)
            if error_match is not None:
                message = error_match.group("message").strip()
                title = f"Ghidra analysis error: {message[:120]}"
                if title not in seen_titles:
                    seen_titles.add(title)
                    error_count += 1
                    observations.append(
                        ParsedObservation(
                            kind="note",
                            summary=title,
                            source_tool=self.source_tool,
                            data={
                                "title": title,
                                "detail": message,
                                "severity": "high",
                                "metadata": {"binary_path": binary_path},
                            },
                        )
                    )
                continue

        if observations:
            title = f"Ghidra headless analysis summary: {binary_path}"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Reviewed {line_count} line(s) of Ghidra headless output and "
                            f"surfaced {summary_count} decompiled-summary highlight(s) and "
                            f"{error_count} error(s)."
                        ),
                        "severity": "info",
                        "metadata": {
                            "binary_path": binary_path,
                            "lines_reviewed": line_count,
                            "summary_count": summary_count,
                            "error_count": error_count,
                        },
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Ghidra decompiled-summary highlights found."],
            metadata={
                "format": "stdout",
                "lines_reviewed": line_count,
                "summary_count": summary_count,
                "error_count": error_count,
            },
        )
