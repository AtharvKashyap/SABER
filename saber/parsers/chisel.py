"""Chisel output parser for SABER.

Chisel emits progress lines, not structured findings. Each meaningful line
becomes one ``kind="note"`` so the loop can reason about what reachability it
has gained and the report can show how the pivot was built.

Deliberately does NOT emit ``kind="session"``: ``KnownSession`` models an
interactive foothold (shell/meterpreter/winrm/ssh), whereas a tunnel only
provides network reachability. Recording a tunnel as a session would tell the
decider it has a shell it does not have.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "2026/07/29 12:00:00 server: Listening on http://0.0.0.0:8080"
_LISTEN_RE = re.compile(r"server:\s*Listening on\s+(?P<address>\S+)", re.IGNORECASE)
_REVERSE_RE = re.compile(r"server:\s*Reverse tunnelling enabled", re.IGNORECASE)
_CONNECTED_RE = re.compile(r"client:\s*Connected\s*\((?P<detail>[^)]*)\)", re.IGNORECASE)
# "server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening"
_PROXY_RE = re.compile(
    r"session#(?P<session>\d+):\s*tun:\s*proxy#(?P<spec>\S+?):\s*Listening",
    re.IGNORECASE,
)
_FINGERPRINT_RE = re.compile(r"Fingerprint\s+(?P<fingerprint>\S+)", re.IGNORECASE)


class ChiselParser(BaseParser):
    """Parse chisel server/client logs into canonical note observations."""

    source_tool = "chisel"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse chisel stdout/log output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Chisel output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen: set[str] = set()

        def add(title: str, detail: str, severity: str, extra: dict[str, Any]) -> None:
            if title in seen:
                return
            seen.add(title)
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": detail,
                        "severity": severity,
                        "metadata": extra,
                    },
                )
            )

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            listen = _LISTEN_RE.search(line)
            if listen is not None:
                address = listen.group("address")
                add(
                    f"Chisel listener on {address}",
                    f"Chisel server is accepting tunnel clients on {address}.",
                    "medium",
                    {"address": address, "role": "server"},
                )
                continue

            proxy = _PROXY_RE.search(line)
            if proxy is not None:
                spec = proxy.group("spec")
                session_id = proxy.group("session")
                add(
                    f"Chisel tunnel established: {spec}",
                    (
                        f"Tunnel {spec} is listening on chisel session #{session_id}; "
                        f"traffic can now be routed through the pivot."
                    ),
                    "high",
                    {"spec": spec, "chisel_session": session_id, "role": "tunnel"},
                )
                continue

            connected = _CONNECTED_RE.search(line)
            if connected is not None:
                detail = connected.group("detail").strip()
                add(
                    "Chisel client connected to server",
                    f"Pivot client established its control channel ({detail}).",
                    "medium",
                    {"connection_detail": detail, "role": "client"},
                )
                continue

            if _REVERSE_RE.search(line):
                add(
                    "Chisel reverse tunnelling enabled",
                    "The chisel server permits reverse port forwards from clients.",
                    "info",
                    {"role": "server"},
                )
                continue

            fingerprint = _FINGERPRINT_RE.search(line)
            if fingerprint is not None:
                value = fingerprint.group("fingerprint")
                add(
                    f"Chisel server fingerprint {value}",
                    f"Chisel server key fingerprint is {value}.",
                    "info",
                    {"fingerprint": value},
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Chisel tunnel events could be parsed."],
            metadata={"format": "stdout", "note_count": len(observations)},
        )
