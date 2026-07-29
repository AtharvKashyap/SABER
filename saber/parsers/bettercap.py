"""Bettercap output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Strip ANSI colour/style escape sequences (bettercap colourizes its table output).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# "eth0: 192.168.1.50/24 ... 3 endpoints"
_BANNER_RE = re.compile(
    r"^(?P<interface>\S+):\s+\S+\s+.*?(?P<count>\d+)\s+endpoints?\s*$", re.IGNORECASE
)


class BettercapParser(BaseParser):
    """Parse Bettercap ``net.show`` table output into canonical host/note observations.

    Bettercap prints a box-drawing table with columns IP / MAC / Name / Vendor /
    Sent / Recvd / Last Seen. Each data row becomes one ``kind="host"``
    observation; a leading banner line (``"<iface>: ... N endpoints"``) becomes
    one ``kind="note"`` summarizing the scan.
    """

    source_tool = "bettercap"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Bettercap stdout/log output."""

        cleaned = _ANSI_RE.sub("", text or "")
        stripped = cleaned.strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Bettercap output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen_hosts: set[str] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            banner_match = _BANNER_RE.match(line)
            if banner_match is not None:
                observations.append(self._banner_note(banner_match))
                continue

            if "│" not in line:
                continue

            host_observation = self._host_row(line, seen_hosts)
            if host_observation is not None:
                observations.append(host_observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Bettercap hosts could be parsed."],
            metadata={"format": "net.show", "host_count": len(seen_hosts)},
        )

    def _host_row(self, line: str, seen: set[str]) -> ParsedObservation | None:
        """Build a host observation from one ``net.show`` table row, if it is one."""

        # Drop the empty leading/trailing cells produced by the outer "│ ... │" borders.
        raw_cells = line.split("│")
        raw_cells = raw_cells[1:-1] if len(raw_cells) >= 2 else raw_cells
        cells = [cell.strip() for cell in raw_cells]

        if len(cells) < 4:
            return None

        ip, mac, name, vendor = cells[0], cells[1], cells[2], cells[3]
        if not _IP_RE.match(ip) or not _MAC_RE.match(mac):
            return None

        if ip in seen:
            return None
        seen.add(ip)

        metadata: dict[str, Any] = {"mac": mac.lower()}
        if vendor:
            metadata["vendor"] = vendor

        return ParsedObservation(
            kind="host",
            summary=f"Bettercap host {ip} ({mac.lower()})",
            source_tool=self.source_tool,
            data={
                "address": ip,
                "hostnames": [name] if name else [],
                "metadata": metadata,
            },
        )

    def _banner_note(self, match: re.Match[str]) -> ParsedObservation:
        """Build a summary note from the net.show banner line."""

        interface = match.group("interface")
        count = match.group("count")
        title = f"Bettercap net table on {interface}"
        return ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": f"Bettercap reported {count} endpoint(s) discovered on {interface}.",
                "severity": "info",
                "metadata": {"interface": interface, "endpoint_count": count},
            },
        )
