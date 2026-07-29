"""SearchSploit output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class SearchSploitParser(BaseParser):
    """Parse SearchSploit JSON/stdout into canonical exploit-reference notes."""

    source_tool = "searchsploit"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse SearchSploit JSON or stdout."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(source_tool=self.source_tool, success=False, errors=["SearchSploit output is empty."])

        parsed = self.safe_json_loads(stripped)
        if parsed is not None:
            return self.parse_json(parsed)

        return self._parse_stdout(stripped)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse SearchSploit JSON output."""

        records = self._records_from_json(data)
        observations: list[ParsedObservation] = []

        for record in records:
            if not isinstance(record, dict):
                continue

            title = record.get("Title") or record.get("title") or record.get("Description") or "Exploit reference"
            edb_id = record.get("EDB-ID") or record.get("edb_id") or record.get("id")
            path = record.get("Path") or record.get("path")
            platform = record.get("Platform") or record.get("platform")
            exploit_type = record.get("Type") or record.get("type")
            date = record.get("Date") or record.get("date")

            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=self._summary(title=title, edb_id=edb_id, platform=platform, exploit_type=exploit_type),
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": self._detail(
                            path=path, platform=platform, exploit_type=exploit_type, date=date
                        ),
                        "severity": "info",
                        "refs": [str(edb_id)] if edb_id else [],
                        "edb_id": edb_id,
                        "path": path,
                        "platform": platform,
                        "type": exploit_type,
                        "date": date,
                        "metadata": {"raw": record},
                    },
                    metadata={"format": "json"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No SearchSploit exploit references could be parsed."],
            metadata={"format": "json", "reference_count": len(observations)},
        )

    def _parse_stdout(self, text: str) -> ParserResult:
        """Parse SearchSploit table stdout fallback."""

        observations: list[ParsedObservation] = []

        for line in text.splitlines():
            line = line.rstrip()
            if not line or line.startswith("-") or "Exploit Title" in line or "Shellcodes" in line:
                continue
            if "|" not in line:
                continue

            left, right = [part.strip() for part in line.split("|", 1)]
            if not left or not right:
                continue

            edb_id = self._extract_edb_id(right)
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=self._summary(title=left, edb_id=edb_id, platform=None, exploit_type=None),
                    source_tool=self.source_tool,
                    data={
                        "title": left,
                        "detail": self._detail(
                            path=right, platform=None, exploit_type=None, date=None
                        ),
                        "severity": "info",
                        "refs": [str(edb_id)] if edb_id else [],
                        "edb_id": edb_id,
                        "path": right,
                        "metadata": {"raw": line},
                    },
                    metadata={"format": "stdout"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No SearchSploit stdout references could be parsed."],
            metadata={"format": "stdout", "reference_count": len(observations)},
        )

    @staticmethod
    def _records_from_json(data: dict[str, Any] | list[Any]) -> list[Any]:
        """Extract result records from SearchSploit JSON variants."""

        if isinstance(data, list):
            return data

        for key in ("RESULTS_EXPLOIT", "results", "exploits", "RESULTS"):
            value = data.get(key)
            if isinstance(value, list):
                return value

        return [data]

    @staticmethod
    def _summary(title: str, edb_id: Any, platform: Any, exploit_type: Any) -> str:
        """Build exploit reference summary."""

        details = []
        if edb_id:
            details.append(f"EDB-ID {edb_id}")
        if platform:
            details.append(str(platform))
        if exploit_type:
            details.append(str(exploit_type))

        suffix = f" ({', '.join(details)})" if details else ""
        return f"Exploit reference found: {title}{suffix}."

    @staticmethod
    def _detail(path: Any, platform: Any, exploit_type: Any, date: Any) -> str:
        """Build a human-readable detail string for the note."""

        parts = []
        if path:
            parts.append(f"path={path}")
        if platform:
            parts.append(f"platform={platform}")
        if exploit_type:
            parts.append(f"type={exploit_type}")
        if date:
            parts.append(f"date={date}")
        return ", ".join(parts)

    @staticmethod
    def _extract_edb_id(path: str) -> str | None:
        """Extract EDB ID from exploit path when possible."""

        match = re.search(r"(\d+)\.[A-Za-z0-9]+$", path)
        return match.group(1) if match else None
