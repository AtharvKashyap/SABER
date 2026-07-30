"""Impacket output parser for SABER.

Covers the four Impacket AD utilities the CONTRACT declares
(``saber/tools/active_directory/impacket_tools.py``):

- ``GetADUsers.py`` (``get_ad_users``) — an enumerated-user table row becomes
  ``kind="account"``.
- ``GetUserSPNs.py`` (``get_spns``) with ``-request`` — a ``$krb5tgs$23$...``
  roastable ticket line becomes ``kind="credential"`` with
  ``data["kind"]="hash"`` and ``validated=False``.
- ``GetNPUsers.py`` (``get_asrep_candidates``) — a ``$krb5asrep$23$...`` line
  becomes ``kind="credential"`` with ``data["kind"]="hash"`` and
  ``validated=False``.
- ``psexec.py`` (``smb_exec_check``) — a confirmed remote-execution foothold
  (service started, followed by the ``whoami`` output) becomes
  ``kind="session"``.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "$krb5tgs$23$*svcsql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$<checksum>$<edata>"
_KRB5TGS_RE = re.compile(
    r"^\$krb5tgs\$23\$\*(?P<user>[^$]+)\$(?P<realm>[^$]+)\$(?P<spn>[^*]+)\*\$.+$"
)
# "$krb5asrep$23$alice@CORP.LOCAL:<checksum>$<edata>"
_KRB5ASREP_RE = re.compile(r"^\$krb5asrep\$23\$(?P<user>[^@]+)@(?P<realm>[^:]+):.+$")
# "Querying corp.local for information about domain."
_DOMAIN_QUERY_RE = re.compile(r"Querying\s+(?P<domain>\S+)\s+for information", re.IGNORECASE)
# GetADUsers.py table row: username, then 2+ spaces, then attribute columns.
_USER_ROW_RE = re.compile(r"^(?P<username>[A-Za-z0-9_.$-]+)\s{2,}\S")
_USER_ROW_SKIP = {"name", "email"}
# psexec.py service start confirms the remote command executed.
_SERVICE_STARTED_RE = re.compile(r"^\[\*\]\s+Starting service", re.IGNORECASE)
# psexec's "whoami" output: "DOMAIN\user".
#
# The domain charset MUST allow spaces: a psexec foothold normally lands as SYSTEM
# and whoami prints "nt authority\system". Without the space the normal, most
# important case never matched, so a successful psexec produced no session at all and
# the privilege="system" branch below was dead code.
_WHOAMI_RE = re.compile(r"^(?P<domain>[A-Za-z0-9_. -]+)\\(?P<user>[A-Za-z0-9_.$ -]+)$")


class ImpacketParser(BaseParser):
    """Parse Impacket stdout output into canonical account/credential/session observations."""

    source_tool = "impacket"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Impacket stdout output from any of the four AD utilities."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Impacket output is empty."],
            )

        metadata = metadata or {}
        default_host = str(metadata.get("target") or "").strip() or None

        observations: list[ParsedObservation] = []
        seen_accounts: set[str] = set()
        seen_hashes: set[str] = set()
        current_domain: str | None = None
        awaiting_whoami = False

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            domain_match = _DOMAIN_QUERY_RE.search(line)
            if domain_match is not None:
                current_domain = domain_match.group("domain")
                continue

            tgs_match = _KRB5TGS_RE.match(line)
            if tgs_match is not None:
                observation = self._spn_hash(line, tgs_match, seen_hashes)
                if observation is not None:
                    observations.append(observation)
                continue

            asrep_match = _KRB5ASREP_RE.match(line)
            if asrep_match is not None:
                observation = self._asrep_hash(line, asrep_match, seen_hashes)
                if observation is not None:
                    observations.append(observation)
                continue

            if _SERVICE_STARTED_RE.match(line):
                awaiting_whoami = True
                continue

            if awaiting_whoami:
                whoami_match = _WHOAMI_RE.match(line)
                if whoami_match is not None:
                    observations.append(self._session(whoami_match, default_host))
                    awaiting_whoami = False
                    continue
                if line.startswith("[") or line.startswith("[!]"):
                    # Status noise between "Starting service" and the whoami line.
                    continue
                awaiting_whoami = False

            user_match = _USER_ROW_RE.match(line)
            if user_match is not None and not _is_table_noise(line):
                username = user_match.group("username")
                if username.lower() not in _USER_ROW_SKIP:
                    observation = self._account(username, current_domain, seen_accounts)
                    if observation is not None:
                        observations.append(observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Impacket results could be parsed."],
            metadata={"format": "stdout", "observation_count": len(observations)},
        )

    def _account(
        self, username: str, domain: str | None, seen: set[str]
    ) -> ParsedObservation | None:
        """Build an account observation from a GetADUsers.py table row."""

        key = f"{domain}:{username}"
        if key in seen:
            return None
        seen.add(key)

        return ParsedObservation(
            kind="account",
            summary=f"AD account enumerated: {username}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "domain": domain,
                "source": "impacket_get_ad_users",
                "enabled": True,
            },
        )

    def _spn_hash(
        self, line: str, match: re.Match[str], seen: set[str]
    ) -> ParsedObservation | None:
        """Build a credential observation from a GetUserSPNs.py roastable ticket line."""

        if line in seen:
            return None
        seen.add(line)

        user = match.group("user")
        realm = match.group("realm")
        spn = match.group("spn")
        return ParsedObservation(
            kind="credential",
            summary=f"Kerberoastable TGS hash captured for {user} ({spn})",
            source_tool=self.source_tool,
            data={
                "username": user,
                "secret": line,
                "kind": "hash",
                "host": None,
                "service": "kerberos",
                "validated": False,
            },
            metadata={"domain": realm, "spn": spn},
        )

    def _asrep_hash(
        self, line: str, match: re.Match[str], seen: set[str]
    ) -> ParsedObservation | None:
        """Build a credential observation from a GetNPUsers.py AS-REP roast line."""

        if line in seen:
            return None
        seen.add(line)

        user = match.group("user")
        realm = match.group("realm")
        return ParsedObservation(
            kind="credential",
            summary=f"AS-REP roastable hash captured for {user}",
            source_tool=self.source_tool,
            data={
                "username": user,
                "secret": line,
                "kind": "hash",
                "host": None,
                "service": "kerberos",
                "validated": False,
            },
            metadata={"domain": realm},
        )

    def _session(self, match: re.Match[str], default_host: str | None) -> ParsedObservation:
        """Build a session observation from a confirmed psexec whoami foothold."""

        domain = match.group("domain")
        user = match.group("user")
        privilege = "system" if user.lower() == "system" else "user"
        return ParsedObservation(
            kind="session",
            summary=f"SMB exec foothold confirmed as {domain}\\{user}",
            source_tool=self.source_tool,
            data={
                "host": default_host or "unknown",
                "kind": "shell",
                "user": user,
                "privilege": privilege,
            },
            metadata={"domain": domain},
        )


def _is_table_noise(line: str) -> bool:
    """Return whether a line is a table separator/banner rather than a data row."""

    stripped_chars = set(line.replace(" ", ""))
    if stripped_chars and stripped_chars <= {"-"}:
        return True
    return line.startswith("[") or line.lower().startswith("impacket")
