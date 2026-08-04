"""Subfinder output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)


class SubfinderParser(BaseParser):
    """Parse Subfinder ``-silent`` output into canonical host observations.

    Subfinder emits one discovered subdomain per line and does not resolve
    them, so ``address`` is the name itself and ``hostnames`` carries the same
    name for downstream correlation.
    """

    source_tool = "subfinder"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse one-subdomain-per-line Subfinder output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Subfinder output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen: set[str] = set()

        for raw_line in stripped.splitlines():
            name = raw_line.strip().lower()
            if not name or name in seen:
                continue
            # Skip banner/progress noise: only accept bare hostnames with a dot.
            if "." not in name or not _HOSTNAME_RE.match(name):
                continue
            seen.add(name)
            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=f"Subdomain discovered: {name}",
                    source_tool=self.source_tool,
                    data={"address": name, "hostnames": [name]},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Subfinder subdomains could be parsed."],
            metadata={"format": "text", "subdomain_count": len(observations)},
        )
