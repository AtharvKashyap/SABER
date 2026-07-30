"""Hashcat output parser for SABER.

Hashcat's ``--show``/potfile-style output is one cracked entry per line in the
form ``<hash>:<plaintext>``, where ``<hash>`` is everything before the LAST
colon (so it may itself contain colons, e.g. NetNTLMv2 lines produced by
Responder/Impacket look like
``username::DOMAIN:serverchallenge:ntresponse:blob:plaintext``).

Every successfully cracked line becomes a ``kind="credential"`` observation
with ``data["kind"] = "password"`` and ``validated = False``: cracking proves
the *hash* was crackable, not that the account still authenticates today, so
it must never be marked validated.

Username choice: when the hash line carries an embedded account (the
NetNTLMv2 ``user::domain:...`` shape), that account becomes ``username`` (and
the domain is recorded in ``metadata``). A bare hash potfile line (e.g. NTLM,
NTLMv2, MD5 -- no embedded account) has no username at all, and
``StateMerger`` drops any credential with a blank username, so this parser
falls back to a stable identifier derived from the hash itself:
``"hash:<first 12 hex chars>"``. This keeps the observation from being
silently dropped while making clear in the state that the "username" is a
hash fingerprint, not a real account name.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Split "<hash>:<plaintext>" on the LAST colon: the hash side may itself
# contain colons (NetNTLMv2), the plaintext side is assumed colon-free.
_POTFILE_LINE_RE = re.compile(r"^(?P<hash>\S.*\S|\S):(?P<plaintext>[^:]+)$")

# NetNTLMv2/NetNTLM-style hash carrying an embedded account:
# "jdoe::LAB:1122334455667788:<32 hex>:<hex blob>"
_NETNTLM_RE = re.compile(
    r"^(?P<username>[^:]+)::(?P<domain>[^:]*):(?P<challenge>[0-9a-fA-F]+):"
    r"(?P<response>[0-9a-fA-F]+):(?P<blob>[0-9a-fA-F]+)$"
)


class HashcatParser(BaseParser):
    """Parse Hashcat potfile/``--show`` output into canonical credential observations."""

    source_tool = "hashcat"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Hashcat potfile-style stdout output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Hashcat output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen: set[tuple[str, str]] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            observation = self._cracked_line(line, seen)
            if observation is not None:
                observations.append(observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No cracked Hashcat entries could be parsed."],
            metadata={"credential_count": len(seen)},
        )

    def _cracked_line(
        self, line: str, seen: set[tuple[str, str]]
    ) -> ParsedObservation | None:
        """Build a credential observation from one cracked potfile line."""

        match = _POTFILE_LINE_RE.match(line)
        if match is None:
            return None

        hash_value = match.group("hash").strip()
        plaintext = match.group("plaintext").strip()
        if not hash_value or not plaintext:
            return None

        netntlm_match = _NETNTLM_RE.match(hash_value)
        domain: str | None = None
        if netntlm_match is not None:
            username = netntlm_match.group("username").strip()
            domain = netntlm_match.group("domain").strip() or None
            if not username:
                username = f"hash:{hash_value[:12]}"
        else:
            username = f"hash:{hash_value[:12]}"

        key = (username, hash_value)
        if key in seen:
            return None
        seen.add(key)

        return ParsedObservation(
            kind="credential",
            summary=f"Hashcat cracked {username}: {plaintext}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "secret": plaintext,
                "kind": "password",
                "validated": False,
            },
            metadata={"hash": hash_value, "domain": domain},
        )
