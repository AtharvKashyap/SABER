"""Amass output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "www.example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)"
_RELATION_RE = re.compile(
    r"^(?P<source>\S+)\s+\((?P<source_type>\w+)\)\s+-->\s+(?P<relation>\w+)\s+-->\s+"
    r"(?P<target>\S+)\s+\((?P<target_type>\w+)\)",
)
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)
_ADDRESS_RELATIONS = {"a_record", "aaaa_record"}


class AmassParser(BaseParser):
    """Parse Amass enum output into canonical host observations.

    Amass emits either bare subdomain names or ``name (FQDN) --> relation -->
    target (Type)`` relation lines. When a name resolves to an address the
    address becomes the canonical ``address`` with the name in ``hostnames``;
    otherwise the name itself is the address.
    """

    source_tool = "amass"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Amass enum output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Amass output is empty."],
            )

        # address -> hostnames, preserving discovery order.
        hosts: dict[str, list[str]] = {}

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            match = _RELATION_RE.match(line)
            if match is not None:
                self._record_relation(hosts, match)
                continue

            name = line.lower()
            if "." in name and _HOSTNAME_RE.match(name):
                self._add(hosts, name, name)

        observations = [
            ParsedObservation(
                kind="host",
                summary=f"Amass discovered {address}",
                source_tool=self.source_tool,
                data={"address": address, "hostnames": hostnames},
            )
            for address, hostnames in hosts.items()
        ]

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Amass hosts could be parsed."],
            metadata={"format": "text", "host_count": len(observations)},
        )

    def _record_relation(self, hosts: dict[str, list[str]], match: re.Match[str]) -> None:
        """Fold one Amass relation line into the host accumulator."""

        source = match.group("source").strip().lower()
        target = match.group("target").strip().lower()
        relation = match.group("relation").strip().lower()
        target_type = match.group("target_type").strip().lower()

        if relation in _ADDRESS_RELATIONS or target_type == "ipaddress":
            self._add(hosts, target, source)
            return

        # Non-address relations (cname/mx/ns) still reveal names worth probing.
        self._add(hosts, source, source)
        if _HOSTNAME_RE.match(target) and "." in target:
            self._add(hosts, target, target)

    @staticmethod
    def _add(hosts: dict[str, list[str]], address: str, hostname: str) -> None:
        """Record an address and associate a hostname with it."""

        if not address:
            return
        hostnames = hosts.setdefault(address, [])
        if hostname and hostname not in hostnames:
            hostnames.append(hostname)
