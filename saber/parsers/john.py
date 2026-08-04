"""John the Ripper output parser for SABER.

Only ``--show`` output carries a plaintext credential SABER can trust. A
``--show`` line looks like the target's passwd-style record with the
plaintext substituted for the hash::

    jdoe:Summer2023!:1001:1001:John Doe:/home/jdoe:/bin/bash

Cracking a hash proves the hash is well-formed and the wordlist/rules found a
preimage; it does NOT prove the account still authenticates against a live
service, so every emitted credential is ``validated=False``. The trailing
summary line John prints after ``--show`` (``"N password hashes cracked, M
left"``) carries no username/secret and must never become a credential.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "jdoe:Summer2023!:1001:1001:John Doe:/home/jdoe:/bin/bash"
# Only the first two colon-separated fields (username, plaintext secret) are
# used; any remaining passwd-style fields are ignored.
_SHOW_RE = re.compile(r"^(?P<username>[^:\s]+):(?P<secret>[^:]*)(?::.*)?$")

# "3 password hashes cracked, 1 left" — John's --show summary line.
_SUMMARY_RE = re.compile(r"^\d+\s+password\s+hashes?\s+cracked", re.IGNORECASE)

# A LIVE crack (dictionary_attack / single_crack) does not print --show format. It
# prints the recovered plaintext followed by the account in parentheses:
#   "Summer2023!      (jdoe)"
#   "                 (root)"      <- plaintext hidden, still a hit
# The spec routes those actions to this parser, so keying only on --show meant a
# SUCCESSFUL crack produced zero observations.
_CRACKED_RE = re.compile(r"^(?P<secret>.*?)\s*\((?P<username>[^()\s]+)\)\s*$")

# Progress/status noise a live run interleaves with results.
_NOISE_RE = re.compile(
    r"^(?:Using default input encoding|Loaded \d+ password hash|"
    r"Will run \d+ OpenMP|Press '?q'?|Almost done|Warning:|Proceeding with|"
    r"Session completed|Note: |Remaining \d+ password hash|"
    r"\d+g \d+:\d+:\d+:\d+)",
    re.IGNORECASE,
)


class JohnParser(BaseParser):
    """Parse John the Ripper ``--show`` stdout into canonical credential observations."""

    source_tool = "john"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse John ``--show`` stdout output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["John output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen: set[str] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line or _SUMMARY_RE.match(line):
                continue

            if _NOISE_RE.match(line):
                continue

            # Live-crack form first: "Summer2023!      (jdoe)". Checked before the
            # --show form because a passwd-style line has no trailing "(user)".
            cracked = _CRACKED_RE.match(line)
            if cracked is not None:
                username = cracked.group("username")
                secret = cracked.group("secret").strip()
                if username in seen:
                    continue
                seen.add(username)
                observations.append(self._credential(username, secret or None))
                continue

            match = _SHOW_RE.match(line)
            if match is None:
                continue

            username = match.group("username")
            secret = match.group("secret")
            if not secret:
                # No plaintext recovered for this entry — nothing to report.
                continue
            if username in seen:
                continue
            seen.add(username)

            observations.append(self._credential(username, secret))

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No John cracked credentials could be parsed."],
            metadata={"credential_count": len(seen)},
        )

    def _credential(self, username: str, secret: str | None) -> ParsedObservation:
        """Build one credential observation for a cracked account.

        ``validated=False`` always: cracking proves the hash, not that the account
        still authenticates.
        """

        return ParsedObservation(
            kind="credential",
            summary=f"John cracked a password for {username}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "secret": secret,
                "kind": "password",
                "validated": False,
            },
        )
