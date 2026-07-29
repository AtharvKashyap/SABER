"""Responder output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "[SMB] NTLMv2-SSP Client   : 192.168.56.105"
_FIELD_RE = re.compile(
    r"^\[(?P<protocol>[A-Z0-9-]+)\]\s+(?P<scheme>NTLMv\d(?:-SSP)?)\s+"
    r"(?P<field>Client|Username|Hash)\s*:\s*(?P<value>.+?)\s*$",
    re.IGNORECASE,
)
# "[*] [LLMNR] Poisoned answer sent to 192.168.56.105 for name fileserver"
_POISON_RE = re.compile(
    r"\[(?P<protocol>LLMNR|NBT-NS|MDNS|DNS)\]\s+Poisoned answer sent to\s+(?P<victim>\S+)"
    r"(?:\s+for name\s+(?P<name>\S+))?",
    re.IGNORECASE,
)


class ResponderParser(BaseParser):
    """Parse Responder output into canonical credential and note observations.

    Responder prints each capture as a Client/Username/Hash block per protocol.
    A completed block becomes one ``kind="credential"`` with ``kind="hash"`` and
    ``validated=False`` — the hash still has to be cracked or relayed, so it is
    explicitly not a working credential yet. Poisoned-answer lines become
    ``kind="note"`` so the report can show what was coerced.
    """

    source_tool = "responder"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Responder stdout/log output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Responder output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen_credentials: set[tuple[str, str | None, str]] = set()
        seen_notes: set[str] = set()
        # One in-flight block per protocol; Responder interleaves protocols.
        blocks: dict[str, dict[str, str]] = {}

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            field_match = _FIELD_RE.match(line)
            if field_match is not None:
                protocol = field_match.group("protocol").upper()
                block = blocks.setdefault(protocol, {})
                block[field_match.group("field").lower()] = field_match.group("value").strip()
                block["scheme"] = field_match.group("scheme").upper()

                if "hash" in block and "username" in block:
                    observation = self._credential(protocol, block, seen_credentials)
                    if observation is not None:
                        observations.append(observation)
                    blocks.pop(protocol, None)
                continue

            poison_match = _POISON_RE.search(line)
            if poison_match is not None:
                observation = self._poison_note(poison_match, seen_notes)
                if observation is not None:
                    observations.append(observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Responder captures could be parsed."],
            metadata={
                "format": "stdout",
                "credential_count": len(seen_credentials),
                "note_count": len(seen_notes),
            },
        )

    def _credential(
        self,
        protocol: str,
        block: dict[str, str],
        seen: set[tuple[str, str | None, str]],
    ) -> ParsedObservation | None:
        """Build a credential observation from a completed capture block."""

        raw_username = block.get("username", "")
        secret = block.get("hash", "")
        if not raw_username or not secret:
            return None

        # Responder prints DOMAIN\user; keep the bare account as the username so
        # the value is directly usable by hashcat/relay, and retain the domain.
        domain, _, username = raw_username.replace("/", "\\").rpartition("\\")
        username = username.strip()
        if not username:
            return None

        host = block.get("client") or None
        key = (username, host, protocol)
        if key in seen:
            return None
        seen.add(key)

        scheme = block.get("scheme", "NTLM")
        return ParsedObservation(
            kind="credential",
            summary=f"{scheme} hash captured for {raw_username} via {protocol}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "secret": secret,
                "kind": "hash",
                "host": host,
                "service": protocol.lower(),
                "validated": False,
            },
            metadata={
                "domain": domain or None,
                "scheme": block.get("scheme"),
                "account": raw_username,
            },
        )

    def _poison_note(self, match: re.Match[str], seen: set[str]) -> ParsedObservation | None:
        """Build a note observation from a poisoned-answer line."""

        protocol = match.group("protocol").upper()
        victim = match.group("victim")
        name = match.group("name") or "?"
        title = f"{protocol} answer poisoned for {victim} ({name})"
        if title in seen:
            return None
        seen.add(title)

        return ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": (
                    f"Responder answered a {protocol} lookup for '{name}' from {victim}, "
                    f"coercing it to authenticate."
                ),
                "severity": "medium",
                "metadata": {"protocol": protocol, "victim": victim, "queried_name": name},
            },
        )
