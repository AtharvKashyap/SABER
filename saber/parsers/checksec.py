"""checksec output parser for SABER.

Emits one ``kind="note"`` per checked binary. The note's ``metadata`` carries a
stable flags dict that downstream binary-exploitation work reads to decide which
technique is viable:

    {"nx": bool, "pie": bool, "relro": "full"|"partial"|"none",
     "canary": bool, "fortify": bool, "stripped": bool | None}

Those keys are the contract with the exploit loop — do not rename them. Severity
reflects how soft the binary is: a binary with no NX, no PIE and no canary is
``high``, because it is directly exploitable.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_YES = {"yes", "true", "enabled", "1"}
# cli form: "RELRO   STACK CANARY  NX  PIE ...\nFull RELRO  Canary found  NX enabled  PIE enabled"
_CLI_ROW_RE = re.compile(
    r"(?P<relro>\w+\s+RELRO|No\s+RELRO).*?"
    r"(?P<canary>Canary\s+found|No\s+canary\s+found).*?"
    r"(?P<nx>NX\s+enabled|NX\s+disabled).*?"
    r"(?P<pie>PIE\s+enabled|No\s+PIE|PIE\s+disabled)",
    re.IGNORECASE | re.DOTALL,
)


class ChecksecParser(BaseParser):
    """Parse checksec output into a canonical note carrying a hardening flags dict."""

    source_tool = "checksec"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse checksec output (JSON when available, else the cli table)."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["checksec output is empty."],
            )

        if stripped.startswith("{"):
            decoded = self.safe_json_loads(stripped)
            if decoded is not None:
                return self.parse_json(decoded, metadata=metadata)

        match = _CLI_ROW_RE.search(stripped)
        if match is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["No checksec results could be parsed."],
            )

        path = str((metadata or {}).get("binary_path") or "unknown binary")
        flags = {
            "relro": self._relro_from_text(match.group("relro")),
            "canary": "found" in match.group("canary").lower(),
            "nx": "enabled" in match.group("nx").lower(),
            "pie": "enabled" in match.group("pie").lower(),
            "fortify": False,
            "stripped": None,
        }
        return self._result({path: flags}, output_format="cli")

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse checksec ``--output=json``: {"<path>": {"nx": "yes", ...}, ...}."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["checksec JSON output is not an object."],
            )

        binaries: dict[str, dict[str, Any]] = {}
        for path, entry in data.items():
            if not isinstance(entry, dict):
                continue
            binaries[str(path)] = {
                "relro": self._relro_from_text(str(entry.get("relro", ""))),
                "canary": self._is_yes(entry.get("canary")),
                "nx": self._is_yes(entry.get("nx")),
                "pie": self._is_yes(entry.get("pie")),
                "fortify": self._is_yes(entry.get("fortify_source") or entry.get("fortify")),
                # checksec reports symbols:"yes" when symbols are PRESENT, which
                # means the binary is NOT stripped. Passing it through unchanged
                # inverted the flag the exploit loop reads.
                "stripped": self._optional_no(entry.get("symbols")),
            }

        return self._result(binaries, output_format="json")

    def _result(self, binaries: dict[str, dict[str, Any]], *, output_format: str) -> ParserResult:
        """Build one note observation per checked binary."""

        observations: list[ParsedObservation] = []

        for path, flags in binaries.items():
            enabled = [name for name in ("nx", "pie", "canary", "fortify") if flags.get(name)]
            missing = [name for name in ("nx", "pie", "canary", "fortify") if not flags.get(name)]
            title = f"Binary hardening: {path}"
            detail = (
                f"RELRO={flags['relro']}; enabled: {', '.join(enabled) or 'none'}; "
                f"missing: {', '.join(missing) or 'none'}."
            )
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": detail,
                        "severity": self._severity_for(flags),
                        "metadata": {**flags, "path": path},
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No checksec results could be parsed."],
            metadata={"format": output_format, "binary_count": len(observations)},
        )

    @staticmethod
    def _severity_for(flags: dict[str, Any]) -> str:
        """Rate how exploitable the binary looks from its missing mitigations."""

        missing = sum(1 for name in ("nx", "pie", "canary") if not flags.get(name))
        if missing >= 3:
            return "high"
        if missing == 2:
            return "medium"
        if missing == 1:
            return "low"
        return "info"

    @staticmethod
    def _relro_from_text(value: str) -> str:
        """Normalize RELRO to full|partial|none."""

        lowered = value.strip().lower()
        if "full" in lowered:
            return "full"
        if "partial" in lowered:
            return "partial"
        return "none"

    @staticmethod
    def _is_yes(value: Any) -> bool:
        """Interpret checksec's yes/no-ish values as a bool."""

        return str(value).strip().lower() in _YES

    @staticmethod
    def _optional_yes(value: Any) -> bool | None:
        """Return None when checksec did not report the field at all."""

        if value is None:
            return None
        return str(value).strip().lower() in _YES

    @staticmethod
    def _optional_no(value: Any) -> bool | None:
        """Inverse of ``_optional_yes``, for fields whose "yes" means "not X".

        ``symbols: "yes"`` means symbols exist, i.e. the binary is not stripped.
        """

        if value is None:
            return None
        return str(value).strip().lower() not in _YES
