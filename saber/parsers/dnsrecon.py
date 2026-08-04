"""DNSRecon output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Stdout form: "[*]      A www.example.com 93.184.216.34"
_RECORD_RE = re.compile(
    r"^\[[*+\-]\]\s+(?P<type>[A-Z]{1,10})\s+(?P<name>\S+)(?:\s+(?P<value>\S+))?",
)
_ADDRESS_TYPES = {"A", "AAAA", "PTR"}
_NOTE_TYPES = {"CNAME", "MX", "NS", "SOA", "SRV", "TXT"}


class DNSReconParser(BaseParser):
    """Parse DNSRecon output into canonical host and note observations.

    A/AAAA/PTR records become ``kind="host"`` (``address`` = the IP, the DNS
    name in ``hostnames``). CNAME/MX/NS/SOA/SRV/TXT records become
    ``kind="note"`` so the loop can still reason over delegation and mail
    infrastructure. Handles both the default stdout form and the ``-j`` JSON
    form.
    """

    source_tool = "dnsrecon"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse DNSRecon stdout (or JSON, when the output is JSON)."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["DNSRecon output is empty."],
            )

        # dnsrecon's stdout lines also start with "[", so a failed decode must
        # fall through to the text form rather than short-circuiting.
        if stripped.startswith(("[", "{")):
            decoded = self.safe_json_loads(stripped)
            if decoded is not None:
                return self.parse_json(decoded, metadata=metadata)

        records: list[dict[str, Any]] = []
        for raw_line in stripped.splitlines():
            match = _RECORD_RE.match(raw_line.strip())
            if match is None:
                continue
            records.append(
                {
                    "type": match.group("type"),
                    "name": match.group("name"),
                    "address": match.group("value"),
                    "target": match.group("value"),
                }
            )

        return self._result(records, output_format="text")

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse DNSRecon ``-j`` records."""

        entries = data if isinstance(data, list) else [data]
        records = [entry for entry in entries if isinstance(entry, dict)]
        return self._result(records, output_format="json")

    def _result(self, records: list[dict[str, Any]], *, output_format: str) -> ParserResult:
        """Build a ParserResult from normalized DNSRecon record dicts."""

        observations: list[ParsedObservation] = []
        hosts: dict[str, list[str]] = {}
        seen_notes: set[str] = set()

        for record in records:
            record_type = str(record.get("type") or "").strip().upper()
            if not record_type or record_type == "SCANINFO":
                continue

            name = str(record.get("name") or "").strip().lower()
            address = str(record.get("address") or "").strip()
            target = str(record.get("target") or record.get("exchange") or "").strip().lower()

            if record_type in _ADDRESS_TYPES and address:
                hostnames = hosts.setdefault(address, [])
                if name and name not in hostnames:
                    hostnames.append(name)
                continue

            if record_type in _NOTE_TYPES:
                detail = target or address or ""
                title = f"DNS {record_type} {name or detail}".strip()
                if title in seen_notes:
                    continue
                seen_notes.add(title)
                observations.append(
                    ParsedObservation(
                        kind="note",
                        summary=title,
                        source_tool=self.source_tool,
                        data={
                            "title": title,
                            "detail": f"{record_type} {name} -> {detail}".strip(),
                            "severity": "info",
                            "metadata": {"record_type": record_type},
                        },
                    )
                )

        for address, hostnames in hosts.items():
            observations.insert(
                0,
                ParsedObservation(
                    kind="host",
                    summary=f"DNS record resolves to {address}",
                    source_tool=self.source_tool,
                    data={"address": address, "hostnames": hostnames},
                ),
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No DNSRecon records could be parsed."],
            metadata={
                "format": output_format,
                "host_count": len(hosts),
                "note_count": len(seen_notes),
            },
        )
