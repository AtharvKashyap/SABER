"""Feroxbuster output parser for SABER."""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Statuses worth surfacing individually: successful/redirect responses plus
# auth-gated paths, which are the interesting signal for a discovered-content scan.
_INTERESTING_STATUS_RANGES: tuple[tuple[int, int], ...] = ((200, 299), (300, 399))
_INTERESTING_STATUSES: frozenset[int] = frozenset({401, 403})


def _is_interesting(status: int) -> bool:
    """Return True for 2xx/3xx/401/403 responses worth an individual note."""

    if status in _INTERESTING_STATUSES:
        return True
    return any(low <= status <= high for low, high in _INTERESTING_STATUS_RANGES)


class FeroxbusterParser(BaseParser):
    """Parse Feroxbuster ``--json`` (newline-delimited JSON) output.

    Each discovered path with an interesting status (2xx/3xx/401/403) becomes its
    own ``note`` observation (``title`` = path, ``detail`` = status). Every other
    response status is folded into a single summary note so a noisy scan does not
    flood ``MissionState.notes`` with thousands of uninteresting entries.
    """

    source_tool = "feroxbuster"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Feroxbuster ``--json`` line output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Feroxbuster output is empty."],
            )

        records, _line_errors = self.parse_json_lines(stripped)
        return self._result(records)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse already-decoded Feroxbuster records (list of response objects)."""

        records = data if isinstance(data, list) else [data]
        return self._result(records)

    def _result(self, records: list[Any]) -> ParserResult:
        """Build a ParserResult from decoded Feroxbuster JSON-line records."""

        observations: list[ParsedObservation] = []
        seen_titles: set[str] = set()
        other_count = 0
        other_statuses: set[int] = set()

        for record in records:
            if not isinstance(record, dict):
                continue
            if str(record.get("type") or "") != "response":
                continue

            status_raw = record.get("status")
            if status_raw is None:
                continue
            try:
                status = int(status_raw)
            except (TypeError, ValueError):
                continue

            path = str(record.get("path") or "").strip()
            url = str(record.get("url") or "").strip()
            title = path or url
            if not title:
                continue

            if _is_interesting(status):
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                observations.append(
                    ParsedObservation(
                        kind="note",
                        summary=f"Feroxbuster discovered {title} (HTTP {status})",
                        source_tool=self.source_tool,
                        data={
                            "title": title,
                            "detail": f"HTTP {status}",
                            "severity": "info",
                            "metadata": {
                                "url": url,
                                "status": status,
                                "content_length": record.get("content_length"),
                            },
                        },
                    )
                )
            else:
                other_count += 1
                other_statuses.add(status)

        if other_count:
            statuses = ", ".join(str(code) for code in sorted(other_statuses))
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=f"Feroxbuster: {other_count} other response(s) folded into summary",
                    source_tool=self.source_tool,
                    data={
                        "title": "Feroxbuster: additional non-interesting responses",
                        "detail": f"{other_count} response(s) with status in [{statuses}]",
                        "severity": "info",
                        "metadata": {"count": other_count, "statuses": sorted(other_statuses)},
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Feroxbuster responses could be parsed."],
            metadata={"note_count": len(observations), "folded_count": other_count},
        )
