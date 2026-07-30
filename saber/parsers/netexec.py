"""NetExec (nxc) output parser for SABER.

NetExec prints one line per host per protocol module, e.g.::

    SMB   10.0.0.5   445   DC01   [+] LAB\\jdoe:Passw0rd! (Pwn3d!)
    SMB   10.0.0.5   445   DC01   ADMIN$          READ,WRITE      Remote Admin
    LDAP  10.0.0.5   389   DC01   jdoe                          Domain user

A successful authentication line becomes a validated ``credential`` and,
when NetExec flags the session as ``Pwn3d!`` (i.e. admin access confirmed),
an admin ``session`` observation too. ``--shares`` output rows with an
explicit permission become ``share`` observations; ``--users`` (LDAP) rows
become ``account`` observations.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "SMB   10.0.0.5   445   DC01   [+] LAB\jdoe:Passw0rd! (Pwn3d!)"
_AUTH_RE = re.compile(
    r"^(?P<proto>SMB|LDAP)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<hostname>\S+)\s+"
    r"\[\+\]\s+(?P<domain>[^\\\s]+)\\(?P<username>[^:\s]+):(?P<secret>\S+?)"
    r"(?:\s+\((?P<flags>[^)]*)\))?\s*$"
)

# "SMB   10.0.0.5   445   DC01   ADMIN$          READ,WRITE      Remote Admin"
_SHARE_RE = re.compile(
    r"^SMB\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<hostname>\S+)\s+"
    r"(?P<share>\S+)\s+(?P<perms>READ,WRITE|READ|WRITE)(?:\s+(?P<remark>.*?))?\s*$"
)

# "LDAP  10.0.0.5   389   DC01   jdoe                          Domain user"
# The username charset excludes "[" and "*" so banner lines like
# "[*] Enumerated users" simply fail to match rather than needing a denylist.
_USER_RE = re.compile(
    r"^LDAP\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<hostname>\S+)\s+"
    r"(?P<username>[A-Za-z0-9_.$-]+)(?:\s{2,}(?P<description>.+?))?\s*$"
)


class NetExecParser(BaseParser):
    """Parse NetExec (nxc) stdout into canonical credential/share/account/session observations."""

    source_tool = "netexec"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse NetExec stdout output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["NetExec output is empty."],
            )

        observations: list[ParsedObservation] = []
        seen_credentials: set[tuple[str, str, str]] = set()
        seen_sessions: set[tuple[str, str]] = set()
        seen_shares: set[tuple[str, str]] = set()
        seen_accounts: set[str] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            auth_match = _AUTH_RE.match(line)
            if auth_match is not None:
                observations.extend(self._auth(auth_match, seen_credentials, seen_sessions))
                continue

            share_match = _SHARE_RE.match(line)
            if share_match is not None:
                observation = self._share(share_match, seen_shares)
                if observation is not None:
                    observations.append(observation)
                continue

            user_match = _USER_RE.match(line)
            if user_match is not None:
                observation = self._account(user_match, seen_accounts)
                if observation is not None:
                    observations.append(observation)
                continue

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No NetExec results could be parsed."],
            metadata={
                "credential_count": len(seen_credentials),
                "session_count": len(seen_sessions),
                "share_count": len(seen_shares),
                "account_count": len(seen_accounts),
            },
        )

    def _auth(
        self,
        match: re.Match[str],
        seen_credentials: set[tuple[str, str, str]],
        seen_sessions: set[tuple[str, str]],
    ) -> list[ParsedObservation]:
        """Build credential (+ optional admin session) observations from an auth line."""

        observations: list[ParsedObservation] = []
        host = match.group("host")
        domain = match.group("domain")
        username = match.group("username")
        secret = match.group("secret")
        proto = match.group("proto").lower()
        flags = (match.group("flags") or "").strip()
        pwned = "pwn3d" in flags.lower()

        cred_key = (username, host, proto)
        if cred_key not in seen_credentials:
            seen_credentials.add(cred_key)
            observations.append(
                ParsedObservation(
                    kind="credential",
                    summary=f"NetExec validated {domain}\\{username} on {host} via {proto.upper()}",
                    source_tool=self.source_tool,
                    data={
                        "username": username,
                        "secret": secret,
                        "kind": "password",
                        "host": host,
                        "service": proto,
                        "validated": True,
                    },
                    metadata={"domain": domain, "pwned": pwned},
                )
            )

        if pwned:
            session_key = (host, username)
            if session_key not in seen_sessions:
                seen_sessions.add(session_key)
                observations.append(
                    ParsedObservation(
                        kind="session",
                        summary=f"NetExec confirmed admin session for {username} on {host}",
                        source_tool=self.source_tool,
                        data={
                            "host": host,
                            "kind": proto,
                            "user": username,
                            "privilege": "admin",
                        },
                        metadata={"domain": domain},
                    )
                )

        return observations

    def _share(
        self, match: re.Match[str], seen: set[tuple[str, str]]
    ) -> ParsedObservation | None:
        """Build a share observation from a ``--shares`` table row."""

        host = match.group("host")
        share = match.group("share")
        key = (host, share)
        if key in seen:
            return None
        seen.add(key)

        perms = match.group("perms")
        remark = (match.group("remark") or "").strip()
        access = "write" if "WRITE" in perms else "read"

        return ParsedObservation(
            kind="share",
            summary=f"SMB share {share} on {host} ({perms})",
            source_tool=self.source_tool,
            data={
                "host": host,
                "name": share,
                "type": "smb",
                "access": access,
                "metadata": {"permissions": perms, "remark": remark} if remark else {
                    "permissions": perms
                },
            },
        )

    def _account(self, match: re.Match[str], seen: set[str]) -> ParsedObservation | None:
        """Build an account observation from an ``--users`` (LDAP) row."""

        username = match.group("username")
        if username in seen:
            return None
        seen.add(username)

        description = (match.group("description") or "").strip()

        return ParsedObservation(
            kind="account",
            summary=f"NetExec-enumerated LDAP user {username}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "source": "netexec",
                "enabled": True,
                "metadata": {"description": description} if description else {},
            },
        )
