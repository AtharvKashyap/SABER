"""Masscan output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Default stdout form: "Discovered open port 80/tcp on 192.168.56.101"
_STDOUT_RE = re.compile(
    r"Discovered\s+open\s+port\s+(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+on\s+(?P<host>\S+)",
    re.IGNORECASE,
)
# -oL list form: "open tcp 80 192.168.56.101 1690000000"
_LIST_RE = re.compile(
    r"^open\s+(?P<proto>tcp|udp|sctp)\s+(?P<port>\d+)\s+(?P<host>\S+)",
    re.IGNORECASE,
)


class MasscanParser(BaseParser):
    """Parse Masscan output into canonical host/service observations.

    Handles all three shapes the wrapper can produce: the default stdout
    ``Discovered open port`` lines, the ``-oL`` list form, and the ``-oJ`` JSON
    form. Masscan reports reachability only, so services carry no product or
    version.
    """

    source_tool = "masscan"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Masscan stdout, list, or JSON output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Masscan output is empty."],
            )

        # -oJ output is JSON; masscan's JSON writer is known to emit a trailing
        # comma, so fall through to the line forms when it does not decode.
        if stripped.startswith(("[", "{")):
            decoded = self.safe_json_loads(stripped)
            if decoded is None:
                decoded = self.safe_json_loads(self._repair_json(stripped))
            if decoded is not None:
                return self.parse_json(decoded, metadata=metadata)

        pairs: list[tuple[str, int, str]] = []
        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = _STDOUT_RE.search(line) or _LIST_RE.match(line)
            if match is None:
                continue
            pairs.append(
                (match.group("host"), int(match.group("port")), match.group("proto").lower())
            )

        return self._result(pairs, output_format="text")

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse Masscan ``-oJ`` records."""

        records = data if isinstance(data, list) else [data]
        pairs: list[tuple[str, int, str]] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            host = str(record.get("ip") or "").strip()
            if not host:
                continue
            for port_entry in record.get("ports") or []:
                if not isinstance(port_entry, dict):
                    continue
                port = port_entry.get("port")
                if port is None:
                    continue
                try:
                    port_number = int(port)
                except (TypeError, ValueError):
                    continue
                status = str(port_entry.get("status") or "open").lower()
                if status != "open":
                    continue
                protocol = str(port_entry.get("proto") or "tcp").lower()
                pairs.append((host, port_number, protocol))

        return self._result(pairs, output_format="json")

    def _result(self, pairs: list[tuple[str, int, str]], *, output_format: str) -> ParserResult:
        """Build a ParserResult from deduped (host, port, protocol) triples."""

        observations: list[ParsedObservation] = []
        seen_hosts: set[str] = set()
        seen_services: set[tuple[str, int, str]] = set()

        for host, port, protocol in pairs:
            if host not in seen_hosts:
                seen_hosts.add(host)
                observations.append(
                    ParsedObservation(
                        kind="host",
                        summary=f"Host {host} responded to masscan",
                        source_tool=self.source_tool,
                        data={"address": host},
                    )
                )
            if (host, port, protocol) in seen_services:
                continue
            seen_services.add((host, port, protocol))
            observations.append(
                ParsedObservation(
                    kind="service",
                    summary=f"{host}:{port}/{protocol} open",
                    source_tool=self.source_tool,
                    data={
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "state": "open",
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Masscan open ports could be parsed."],
            metadata={
                "format": output_format,
                "host_count": len(seen_hosts),
                "service_count": len(seen_services),
            },
        )

    @staticmethod
    def _repair_json(text: str) -> str:
        """Drop masscan's trailing comma before the closing bracket."""

        return re.sub(r",\s*\]\s*$", "]", text.strip())
