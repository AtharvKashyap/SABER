"""radare2 output parser for SABER.

radare2 emits a different shape per action:

- ``info`` (``ij``) -> one JSON object describing arch/bits/hardening.
- ``functions`` (``aflj``) -> a JSON array of function entries; dumping every
  symbol would flood ``MissionState``, so this distils to the functions a
  decider planning a binary exploit actually cares about (gets, strcpy,
  system, memcpy, and similar dangerous sinks).
- ``analyze``/``custom_commands`` -> free-form r2 console text (often empty
  for a bare ``aaa`` analysis run).

Every action still folds into a single ``kind="note"`` observation per
finding. Note titles must be unique because ``StateMerger``'s note merger
dedupes on title.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_DANGEROUS_FUNCTIONS: dict[str, tuple[str, str]] = {
    "gets": ("high", "gets() has no bounds checking and is a classic stack-overflow sink."),
    "strcpy": (
        "high",
        "strcpy() copies until a NUL byte with no length check; a common overflow sink.",
    ),
    "system": (
        "high",
        "system() runs a shell command; if any argument is attacker-influenced this is a "
        "command-injection/exec sink.",
    ),
    "memcpy": (
        "medium",
        "memcpy() has no bounds checking of its own; an attacker-controlled size or source "
        "can overflow the destination.",
    ),
}

_MAX_RAW_DETAIL = 500


class Radare2Parser(BaseParser):
    """Distil radare2 output into canonical note observations."""

    source_tool = "radare2"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse radare2 output, branching on the action that produced it."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["radare2 output is empty."],
            )

        metadata = metadata or {}
        action = str(metadata.get("action") or "").strip().lower()
        binary_path = str(metadata.get("binary_path") or "").strip() or "unknown binary"

        if action == "info":
            return self._parse_info(stripped, binary_path)
        if action == "functions":
            return self._parse_functions(stripped, binary_path)
        return self._parse_raw(stripped, binary_path, action or "analyze")

    def _parse_info(self, text: str, binary_path: str) -> ParserResult:
        """Parse `ij` JSON info output into an arch/bits/protections note."""

        payload = self.safe_json_loads(text)
        if not isinstance(payload, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["radare2 info output was not valid JSON."],
            )

        bin_info = payload.get("bin")
        if not isinstance(bin_info, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["radare2 info JSON had no 'bin' section."],
            )

        arch = str(bin_info.get("arch") or "unknown")
        bits = bin_info.get("bits")
        canary = bool(bin_info.get("canary", False))
        nx = bool(bin_info.get("nx", False))
        pic = bool(bin_info.get("pic", False))
        relro = str(bin_info.get("relro") or "no")
        stripped_syms = bool(bin_info.get("stripped", False))
        os_name = str(bin_info.get("os") or "unknown")

        weak = []
        if not canary:
            weak.append("no stack canary")
        if not nx:
            weak.append("NX/DEP disabled")
        if not pic:
            weak.append("no PIE/ASLR")
        if relro.lower() in {"no", "none", "partial"}:
            weak.append(f"RELRO={relro}")

        severity = "high" if weak else "info"
        detail = (
            f"{arch} ({bits}-bit, {os_name}). Protections: "
            f"canary={canary}, nx={nx}, pic={pic}, relro={relro}, stripped={stripped_syms}."
        )
        if weak:
            detail += f" Weak: {', '.join(weak)}."

        title = f"radare2 binary info: {binary_path}"
        observation = ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": detail,
                "severity": severity,
                "metadata": {
                    "binary_path": binary_path,
                    "arch": arch,
                    "bits": bits,
                    "canary": canary,
                    "nx": nx,
                    "pic": pic,
                    "relro": relro,
                    "stripped": stripped_syms,
                    "os": os_name,
                },
            },
        )

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=[observation],
            metadata={"format": "info_json", "weak_protections": len(weak)},
        )

    def _parse_functions(self, text: str, binary_path: str) -> ParserResult:
        """Parse `aflj` JSON function list, surfacing only dangerous sinks."""

        payload = self.safe_json_loads(text)
        if not isinstance(payload, list):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["radare2 functions output was not a valid JSON array."],
            )

        observations: list[ParsedObservation] = []
        seen_titles: set[str] = set()
        dangerous_count = 0

        for entry in payload:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            offset = entry.get("offset")

            matched = None
            for needle, (severity, explanation) in _DANGEROUS_FUNCTIONS.items():
                if needle in name.lower():
                    matched = (needle, severity, explanation)
                    break
            if matched is None:
                continue

            needle, severity, explanation = matched
            dangerous_count += 1
            title = f"Dangerous function referenced: {name}"
            if title in seen_titles:
                continue
            seen_titles.add(title)

            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": explanation,
                        "severity": severity,
                        "metadata": {
                            "binary_path": binary_path,
                            "function": name,
                            "offset": offset,
                            "matched": needle,
                        },
                    },
                )
            )

        summary_title = f"radare2 function scan summary: {binary_path}"
        observations.append(
            ParsedObservation(
                kind="note",
                summary=summary_title,
                source_tool=self.source_tool,
                data={
                    "title": summary_title,
                    "detail": (
                        f"Reviewed {len(payload)} function(s) and flagged {dangerous_count} "
                        f"as notable/dangerous sinks."
                    ),
                    "severity": "info",
                    "metadata": {
                        "binary_path": binary_path,
                        "functions_reviewed": len(payload),
                        "dangerous_count": dangerous_count,
                    },
                },
            )
        )

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=observations,
            metadata={"format": "functions_json", "functions_reviewed": len(payload)},
        )

    def _parse_raw(self, text: str, binary_path: str, action: str) -> ParserResult:
        """Parse free-form r2 console output (analyze/custom_commands)."""

        cleaned = re.sub(r"\s+", " ", text).strip()
        if not cleaned:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["radare2 produced no console output to parse."],
            )

        truncated = cleaned[:_MAX_RAW_DETAIL]
        title = f"radare2 {action} output: {binary_path}"
        observation = ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": truncated,
                "severity": "info",
                "metadata": {
                    "binary_path": binary_path,
                    "action": action,
                    "output_length": len(text),
                    "truncated": len(text) > _MAX_RAW_DETAIL,
                },
            },
        )

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=[observation],
            metadata={"format": "raw_console", "output_length": len(text)},
        )
