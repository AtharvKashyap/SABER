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
#
# The hash side must look like a HASH, not like prose. The original pattern was
# `^(\S.*\S|\S):([^:]+)$`, which matched any single-colon line — so hashcat's own
# status banner ("Status...........: Exhausted") became a credential. That poisoned
# state.credentials on every failed crack AND advanced the vuln_assessment phase
# goal, which fires on state.credentials being non-empty: a failed crack promoted
# the mission to EXPLOITATION.
# The hash side is 8+ characters from a hash-ish charset that excludes SPACES (so
# "0/1 (0.00%) Digests" cannot match) and may itself contain colons (NetNTLMv2's
# "jdoe::LAB:challenge:response:blob"). The length floor applies to the whole hash
# side, not the first segment — requiring 8+ per-segment rejected short usernames.
_POTFILE_LINE_RE = re.compile(
    r"^(?P<hash>[A-Za-z0-9+/=$*._:-]{8,}):(?P<plaintext>[^:]+)$"
)
# Status/progress lines hashcat prints around the cracked results. Dotted-label
# lines are the giveaway ("Recovered........: 0/1").
_STATUS_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 .#()/-]*\.{2,}\s*:", re.IGNORECASE)

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
            # Skip hashcat's own status/progress output before it can be mistaken
            # for a "hash:plaintext" pair.
            if _STATUS_LINE_RE.match(line):
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
