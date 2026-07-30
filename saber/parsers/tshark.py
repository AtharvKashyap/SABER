"""tshark output parser for SABER.

A capture of any length is thousands of packets, so this parser aggregates rather
than reporting packet-by-packet:

- every distinct IP seen on the wire -> ``kind="host"``. This is the payoff of
  passive capture: a host that never answers a scan but does talk still shows up.
- one ``kind="note"`` per (protocol) summarising how much of it was seen, plus a
  conversation summary note — enough for the decider to know what is in use without
  drowning in packets.
- cleartext credentials (HTTP Basic, FTP/telnet/POP/IMAP logins) ->
  ``kind="credential"`` with ``validated=False``: sniffing a password proves it was
  sent, not that it still works.
- the pcap itself -> ``kind="loot"`` so the report can point at the evidence file.

Handles tshark ``-T json`` (a list of packet objects with ``_source.layers``) and the
plain one-line-per-packet summary form.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# "  1   0.000000 10.0.0.5 -> 10.0.0.9  TCP 74 4444 > 80 [SYN]"
_SUMMARY_RE = re.compile(
    r"(?P<src>(?:\d{1,3}\.){3}\d{1,3})\s*(?:->|→)\s*(?P<dst>(?:\d{1,3}\.){3}\d{1,3})"
    r"\s+(?P<protocol>[A-Za-z0-9_.-]+)",
)
_BASIC_AUTH_RE = re.compile(r"Basic\s+(?P<b64>[A-Za-z0-9+/=]{4,})")
_FTP_USER_RE = re.compile(r"^USER\s+(?P<username>\S+)", re.IGNORECASE | re.MULTILINE)
_FTP_PASS_RE = re.compile(r"^PASS\s+(?P<password>\S+)", re.IGNORECASE | re.MULTILINE)

_CLEARTEXT_PROTOCOLS = {"ftp", "telnet", "http", "pop", "imap", "smtp"}


class TsharkParser(BaseParser):
    """Aggregate a capture into hosts, protocol notes and sniffed credentials."""

    source_tool = "tshark"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse tshark output (JSON when available, else the summary form)."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["tshark output is empty."],
            )

        if stripped.startswith("["):
            decoded = self.safe_json_loads(stripped)
            if decoded is not None:
                return self.parse_json(decoded, metadata=metadata)

        addresses: Counter[str] = Counter()
        protocols: Counter[str] = Counter()
        conversations: Counter[tuple[str, str]] = Counter()

        for raw_line in stripped.splitlines():
            match = _SUMMARY_RE.search(raw_line)
            if match is None:
                continue
            src = match.group("src")
            dst = match.group("dst")
            addresses[src] += 1
            addresses[dst] += 1
            protocols[match.group("protocol").lower()] += 1
            conversations[(src, dst)] += 1

        credentials = self._credentials_from_text(stripped, None)
        return self._result(
            addresses,
            protocols,
            conversations,
            credentials,
            metadata or {},
            output_format="summary",
        )

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse tshark ``-T json`` packet records."""

        packets = data if isinstance(data, list) else [data]

        addresses: Counter[str] = Counter()
        protocols: Counter[str] = Counter()
        conversations: Counter[tuple[str, str]] = Counter()
        credentials: list[dict[str, Any]] = []
        # (src, dst) -> the FTP username seen but not yet paired with a password.
        pending_ftp: dict[tuple[str, str], str] = {}

        for packet in packets:
            if not isinstance(packet, dict):
                continue
            layers = (packet.get("_source") or {}).get("layers")
            if not isinstance(layers, dict):
                continue

            ip_layer = layers.get("ip") if isinstance(layers.get("ip"), dict) else {}
            src = str(ip_layer.get("ip.src") or "").strip()
            dst = str(ip_layer.get("ip.dst") or "").strip()
            if src:
                addresses[src] += 1
            if dst:
                addresses[dst] += 1
            if src and dst:
                conversations[(src, dst)] += 1

            frame = layers.get("frame") if isinstance(layers.get("frame"), dict) else {}
            protocol_chain = str(frame.get("frame.protocols") or "")
            if protocol_chain:
                # "eth:ethertype:ip:tcp:http" -> the outermost application protocol.
                protocols[protocol_chain.split(":")[-1].lower()] += 1

            credentials.extend(self._credentials_from_layers(layers, src, dst, pending_ftp))

        return self._result(
            addresses,
            protocols,
            conversations,
            credentials,
            metadata or {},
            output_format="json",
        )

    def _credentials_from_layers(
        self,
        layers: dict[str, Any],
        src: str,
        dst: str,
        pending_ftp: dict[tuple[str, str], str],
    ) -> list[dict[str, Any]]:
        """Extract cleartext credentials from a JSON packet's layers.

        ``pending_ftp`` carries FTP usernames between packets so a USER/PASS pair can
        be joined into one credential.
        """

        found: list[dict[str, Any]] = []

        http = layers.get("http") if isinstance(layers.get("http"), dict) else {}
        authorization = str(http.get("http.authorization") or "")
        decoded = self._decode_basic_auth(authorization)
        if decoded is not None:
            username, secret = decoded
            found.append(
                {
                    "username": username,
                    "secret": secret,
                    "kind": "password",
                    "host": dst or None,
                    "service": "http",
                    "validated": False,
                }
            )

        ftp = layers.get("ftp") if isinstance(layers.get("ftp"), dict) else {}
        request = str(ftp.get("ftp.request.command") or "")
        argument = str(ftp.get("ftp.request.arg") or "")
        # FTP USER and PASS arrive in SEPARATE packets, so they must be paired across
        # the packet loop. Emitting the PASS under a placeholder username relied on
        # the merger folding them together, which it cannot: the credential merger
        # keys on (username, host, service), so state ended up with the real username
        # holding secret=None PLUS a junk "(ftp user)" entry holding the real password.
        conversation = (src, dst)
        if request.upper() == "USER" and argument:
            pending_ftp[conversation] = argument
        elif request.upper() == "PASS" and argument:
            username = pending_ftp.pop(conversation, None)
            if username:
                found.append(
                    {
                        "username": username,
                        "secret": argument,
                        "kind": "password",
                        "host": dst or None,
                        "service": "ftp",
                        "validated": False,
                    }
                )
        return found

    def _credentials_from_text(self, text: str, host: str | None) -> list[dict[str, Any]]:
        """Extract cleartext credentials from the summary/ascii form."""

        found: list[dict[str, Any]] = []

        for match in _BASIC_AUTH_RE.finditer(text):
            decoded = self._decode_basic_auth(f"Basic {match.group('b64')}")
            if decoded is None:
                continue
            username, secret = decoded
            found.append(
                {
                    "username": username,
                    "secret": secret,
                    "kind": "password",
                    "host": host,
                    "service": "http",
                    "validated": False,
                }
            )

        users = _FTP_USER_RE.findall(text)
        passwords = _FTP_PASS_RE.findall(text)
        for index, username in enumerate(users):
            secret = passwords[index] if index < len(passwords) else None
            found.append(
                {
                    "username": username,
                    "secret": secret,
                    "kind": "password",
                    "host": host,
                    "service": "ftp",
                    "validated": False,
                }
            )
        return found

    @staticmethod
    def _decode_basic_auth(header: str) -> tuple[str, str] | None:
        """Return (username, password) from an HTTP Basic header, or None."""

        match = _BASIC_AUTH_RE.search(header or "")
        if match is None:
            return None
        try:
            raw = base64.b64decode(match.group("b64"), validate=True).decode(
                "utf-8", errors="replace"
            )
        except (binascii.Error, ValueError):
            return None
        if ":" not in raw:
            return None
        username, _, secret = raw.partition(":")
        if not username:
            return None
        return username, secret

    def _result(
        self,
        addresses: Counter[str],
        protocols: Counter[str],
        conversations: Counter[tuple[str, str]],
        credentials: list[dict[str, Any]],
        context: dict[str, Any],
        *,
        output_format: str,
    ) -> ParserResult:
        """Build the aggregated observation set."""

        observations: list[ParsedObservation] = []
        pcap_path = str(context.get("output_file") or context.get("pcap_path") or "").strip()

        for address, packet_count in addresses.most_common():
            if not _IPV4_RE.fullmatch(address):
                continue
            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=f"Host observed on the wire: {address}",
                    source_tool=self.source_tool,
                    data={
                        "address": address,
                        "metadata": {"packets_seen": packet_count, "discovered_by": "tshark"},
                    },
                )
            )

        for protocol, packet_count in protocols.most_common():
            severity = "medium" if protocol in _CLEARTEXT_PROTOCOLS else "info"
            title = f"Protocol observed: {protocol}"
            detail = f"{packet_count} packet(s) of {protocol} seen."
            if protocol in _CLEARTEXT_PROTOCOLS:
                detail += " This protocol carries credentials in the clear."
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": detail,
                        "severity": severity,
                        "metadata": {"protocol": protocol, "packets": packet_count},
                    },
                )
            )

        if conversations:
            top = conversations.most_common(5)
            title = "Capture conversation summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": "; ".join(
                            f"{src} -> {dst} ({count} pkt)" for (src, dst), count in top
                        ),
                        "severity": "info",
                        "metadata": {
                            "distinct_hosts": len(addresses),
                            "distinct_conversations": len(conversations),
                        },
                    },
                )
            )

        seen_credentials: set[tuple[str, Any, Any]] = set()
        for credential in credentials:
            key = (credential["username"], credential.get("host"), credential.get("service"))
            if key in seen_credentials:
                continue
            seen_credentials.add(key)
            observations.append(
                ParsedObservation(
                    kind="credential",
                    summary=(
                        f"Cleartext credential sniffed for {credential['username']} "
                        f"({credential.get('service')})"
                    ),
                    source_tool=self.source_tool,
                    data=credential,
                )
            )

        if pcap_path and observations:
            observations.append(
                ParsedObservation(
                    kind="loot",
                    summary=f"Packet capture retained: {pcap_path}",
                    source_tool=self.source_tool,
                    data={
                        "description": f"Packet capture written to {pcap_path}",
                        "kind": "file",
                        "path": pcap_path,
                        "metadata": {"distinct_hosts": len(addresses)},
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No packets could be parsed from tshark output."],
            metadata={
                "format": output_format,
                "host_count": len(addresses),
                "protocol_count": len(protocols),
                "credential_count": len(seen_credentials),
            },
        )
