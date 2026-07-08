"""WhatWeb output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class WhatWebParser(BaseParser):
    """Parse WhatWeb JSON/stdout into web technology observations."""

    source_tool = "whatweb"

    def parse_text(self, text: str) -> ParserResult:
        """Parse WhatWeb JSON or stdout."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(source_tool=self.source_tool, success=False, errors=["WhatWeb output is empty."])

        parsed = self.safe_json_loads(stripped)
        if parsed is not None:
            return self.parse_json(parsed)

        return self._parse_stdout(stripped)

    def parse_json(self, data: dict[str, Any] | list[Any]) -> ParserResult:
        """Parse WhatWeb JSON output."""

        records = data if isinstance(data, list) else [data]
        observations: list[ParsedObservation] = []

        for record in records:
            if not isinstance(record, dict):
                continue

            url = record.get("target") or record.get("url") or record.get("uri")
            plugins = record.get("plugins", {})
            status = self._extract_status(plugins)
            title = self._extract_plugin_string(plugins, "Title")
            server = self._extract_plugin_string(plugins, "HTTPServer")
            technologies = self._extract_technologies(plugins)

            if not url and not technologies:
                continue

            summary_bits = [str(url or "Unknown target")]
            if status:
                summary_bits.append(f"returned {status}")
            if technologies:
                summary_bits.append(f"uses {', '.join(technologies[:5])}")

            observations.append(
                ParsedObservation(
                    kind="web_technology",
                    summary=" ".join(summary_bits) + ".",
                    source_tool=self.source_tool,
                    data={
                        "url": url,
                        "status": status,
                        "title": title,
                        "server": server,
                        "technologies": technologies,
                        "plugins": plugins,
                    },
                    metadata={"format": "json"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No WhatWeb JSON observations could be parsed."],
            metadata={"format": "json", "observation_count": len(observations)},
        )

    def _parse_stdout(self, text: str) -> ParserResult:
        """Parse common WhatWeb stdout."""

        observations: list[ParsedObservation] = []

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            url = line.split()[0]
            status = self._extract_bracket_value(line, r"\[(\d{3})\s+[^\]]+\]")
            title = self._extract_bracket_value(line, r"Title\[([^\]]+)\]")
            server = self._extract_bracket_value(line, r"HTTPServer\[([^\]]+)\]")
            technologies = self._extract_stdout_technologies(line)

            observations.append(
                ParsedObservation(
                    kind="web_technology",
                    summary=f"{url} fingerprinted with technologies: {', '.join(technologies) or 'unknown'}.",
                    source_tool=self.source_tool,
                    data={
                        "url": url,
                        "status": int(status) if status and status.isdigit() else None,
                        "title": title,
                        "server": server,
                        "technologies": technologies,
                        "raw": line,
                    },
                    metadata={"format": "stdout"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No WhatWeb stdout observations could be parsed."],
            metadata={"format": "stdout", "observation_count": len(observations)},
        )

    @staticmethod
    def _extract_plugin_string(plugins: dict[str, Any], key: str) -> str | None:
        """Extract a common WhatWeb plugin string."""

        value = plugins.get(key)
        if not value:
            return None

        if isinstance(value, dict):
            strings = value.get("string")
            if isinstance(strings, list) and strings:
                return str(strings[0])
            if isinstance(strings, str):
                return strings

        return str(value)

    @staticmethod
    def _extract_status(plugins: dict[str, Any]) -> int | None:
        """Extract HTTP status code."""

        status = plugins.get("HTTPStatus")
        if isinstance(status, dict):
            code = status.get("string")
            if isinstance(code, list) and code:
                code = code[0]
            try:
                return int(code)
            except (TypeError, ValueError):
                return None
        return None

    @staticmethod
    def _extract_technologies(plugins: dict[str, Any]) -> list[str]:
        """Extract technology names from plugin keys."""

        ignored = {"Title", "IP", "Country", "HTTPStatus", "RedirectLocation"}
        technologies: list[str] = []

        for key, value in plugins.items():
            if key in ignored:
                continue
            technologies.append(key)

            if isinstance(value, dict):
                for field in ("string", "version", "module"):
                    raw = value.get(field)
                    if isinstance(raw, list):
                        technologies.extend(str(item) for item in raw if item)
                    elif isinstance(raw, str):
                        technologies.append(raw)

        return sorted(set(technologies))

    @staticmethod
    def _extract_bracket_value(text: str, pattern: str) -> str | None:
        """Extract regex bracket value."""

        match = re.search(pattern, text)
        return match.group(1) if match else None

    @staticmethod
    def _extract_stdout_technologies(line: str) -> list[str]:
        """Extract plugin names from stdout."""

        names = re.findall(r"([A-Za-z0-9_\-]+)\[", line)
        ignored = {"Title", "IP", "Country"}
        return sorted({name for name in names if name not in ignored})
