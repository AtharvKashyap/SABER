"""sqlmap output parser for SABER."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class SqlmapParser(BaseParser):
    """Parse sqlmap stdout into canonical vuln/note observations.

    sqlmap has no stable machine-readable output format for injection
    findings, so this parses the human-readable console log: a confirmed
    injection point produces one or more ``vuln`` observations (one per
    detected technique); the absence of a confirmed injection point produces
    a single ``note`` observation instead.
    """

    source_tool = "sqlmap"

    _CONFIRMED_RE = re.compile(r"identified the following injection point", re.IGNORECASE)
    _PARAM_RE = re.compile(r"^Parameter:\s*(?P<param>\S+)\s*\((?P<method>[^)]+)\)", re.MULTILINE)
    _TITLE_RE = re.compile(r"^\s*Title:\s*(?P<title>.+)$", re.MULTILINE)
    _DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)", re.IGNORECASE)

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse sqlmap console output."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["sqlmap output is empty."],
            )

        meta = metadata or {}
        host = self._resolve_host(meta)

        if self._CONFIRMED_RE.search(stripped):
            observations = self._confirmed_observations(stripped, host)
            return ParserResult(
                source_tool=self.source_tool,
                success=bool(observations),
                observations=observations,
                errors=[]
                if observations
                else [
                    "sqlmap reported an injection point but no parameter details could be parsed."
                ],
                metadata={"confirmed": True, "vuln_count": len(observations)},
            )

        note = self._not_confirmed_note(stripped, host)
        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=[note],
            metadata={"confirmed": False, "vuln_count": 0},
        )

    def _confirmed_observations(self, text: str, host: str | None) -> list[ParsedObservation]:
        """Build one vuln observation per detected injection technique."""

        dbms_match = self._DBMS_RE.search(text)
        dbms = dbms_match.group("dbms").strip() if dbms_match else None

        observations: list[ParsedObservation] = []
        param_matches = list(self._PARAM_RE.finditer(text))
        for index, match in enumerate(param_matches):
            start = match.end()
            end = param_matches[index + 1].start() if index + 1 < len(param_matches) else len(text)
            block = text[start:end]
            param = match.group("param")
            method = match.group("method")

            titles = self._TITLE_RE.findall(block)
            if not titles:
                titles = [f"{param} injectable via {method}"]

            for title in titles:
                title = title.strip()
                observations.append(
                    ParsedObservation(
                        kind="vuln",
                        summary=(
                            f"sqlmap confirmed SQL injection on parameter "
                            f"'{param}' ({method}): {title}"
                        ),
                        source_tool=self.source_tool,
                        data={
                            "title": f"SQL injection: {title}",
                            "host": host,
                            "severity": "high",
                            "identifier": dbms,
                            "confirmed": True,
                        },
                        metadata={"parameter": param, "method": method, "dbms": dbms},
                    )
                )
        return observations

    def _not_confirmed_note(self, text: str, host: str | None) -> ParsedObservation:
        """Build a note observation when no injection point was confirmed."""

        return ParsedObservation(
            kind="note",
            summary="sqlmap did not confirm a SQL injection point.",
            source_tool=self.source_tool,
            data={
                "title": "sqlmap scan: no confirmed injection",
                "detail": text.strip().splitlines()[-1] if text.strip() else "",
                "severity": "info",
                "refs": [],
                "metadata": {"host": host} if host else {},
            },
            metadata={"confirmed": False},
        )

    @staticmethod
    def _resolve_host(metadata: dict[str, Any]) -> str | None:
        """Resolve a host from metadata (explicit host, target, or url)."""

        host = metadata.get("host")
        if host:
            return str(host)

        url = metadata.get("target") or metadata.get("url")
        if url:
            parsed = urlparse(str(url))
            return parsed.hostname or str(url)

        return None
