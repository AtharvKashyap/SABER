"""Mimikatz output parser for SABER.

Targets the ``sekurlsa::logonpasswords`` block shape mimikatz prints for each
logon session:

    Authentication Id : 0 ; 996359 (00000000:000f3407)
    Session           : Interactive from 2
    User Name         : jdoe
    Domain            : CORP
    ...
            msv :
             [00000003] Primary
             * Username : jdoe
             * Domain   : CORP
             * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
            wdigest :
             * Username : jdoe
             * Domain   : CORP
             * Password : SuperSecretLab123!

Each block carries a top-level ``User Name``/``Domain`` pair (the logon
session's account) and one sub-section per credential provider (``msv``,
``wdigest``, ``kerberos``, ...), each of which may override the account with
its own ``* Username``/``* Domain`` and expose either ``* NTLM`` (a hash) or
``* Password`` (a recovered plaintext).

Every recovered secret becomes its own ``kind="credential"`` observation with
``data["kind"]`` set to ``"hash"`` (NTLM) or ``"password"`` (wdigest/kerberos
plaintext); the account it belongs to becomes one ``kind="account"``
observation. Both are ``validated=False`` — an NTLM hash still needs pass-the-
hash/relay/cracking and a recovered plaintext still needs to be tried against
a live service before either is proven to grant access.

``StateMerger`` dedupes credentials on ``(username, host, service)``. A hash
and a plaintext recovered for the *same* user would collide and one would be
silently dropped if they shared a ``service`` value, so this parser gives
each credential *kind* a distinct ``service``: the NTLM hash always uses
``"ntlm"``; a plaintext uses the provider section name it came from
(``"wdigest"``/``"kerberos"``/...). That keeps both entries alive in
``MissionState.credentials`` for the same account.
"""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_SECTION_RE = re.compile(r"^(msv|wdigest|kerberos|ssp|tspkg|credman)\s*:\s*$", re.IGNORECASE)
_TOP_USERNAME_RE = re.compile(r"^User Name\s*:\s*(?P<username>.+?)\s*$")
_TOP_DOMAIN_RE = re.compile(r"^Domain\s*:\s*(?P<domain>.+?)\s*$")
_SUB_USERNAME_RE = re.compile(r"^\*\s*Username\s*:\s*(?P<username>.+?)\s*$")
_SUB_DOMAIN_RE = re.compile(r"^\*\s*Domain\s*:\s*(?P<domain>.+?)\s*$")
_NTLM_RE = re.compile(r"^\*\s*NTLM\s*:\s*(?P<hash>[0-9a-fA-F]{32})\s*$")
_PASSWORD_RE = re.compile(r"^\*\s*Password\s*:\s*(?P<password>.+?)\s*$")

_BLANK_MARKERS = {"", "(null)"}


class MimikatzParser(BaseParser):
    """Parse Mimikatz ``sekurlsa::logonpasswords``-style stdout output."""

    source_tool = "mimikatz"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Mimikatz stdout output into credential/account observations."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Mimikatz output is empty."],
            )

        host = (metadata or {}).get("target") or None

        observations: list[ParsedObservation] = []
        seen_credentials: set[tuple[str, str | None, str]] = set()
        seen_accounts: set[tuple[str | None, str]] = set()

        top_username: str | None = None
        top_domain: str | None = None
        section: str | None = None
        sub_username: str | None = None
        sub_domain: str | None = None

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("Authentication Id"):
                top_username = top_domain = section = sub_username = sub_domain = None
                continue

            top_user_match = _TOP_USERNAME_RE.match(line)
            if top_user_match is not None:
                top_username = self._clean(top_user_match.group("username"))
                continue

            top_domain_match = _TOP_DOMAIN_RE.match(line)
            if top_domain_match is not None:
                top_domain = self._clean(top_domain_match.group("domain"))
                continue

            section_match = _SECTION_RE.match(line)
            if section_match is not None:
                section = section_match.group(1).lower()
                sub_username = sub_domain = None
                continue

            sub_user_match = _SUB_USERNAME_RE.match(line)
            if sub_user_match is not None:
                sub_username = self._clean(sub_user_match.group("username"))
                continue

            sub_domain_match = _SUB_DOMAIN_RE.match(line)
            if sub_domain_match is not None:
                sub_domain = self._clean(sub_domain_match.group("domain"))
                continue

            if section is None:
                continue

            username = sub_username or top_username
            domain = sub_domain or top_domain
            if not username:
                continue

            ntlm_match = _NTLM_RE.match(line)
            if ntlm_match is not None:
                self._emit_secret(
                    observations,
                    username=username,
                    domain=domain,
                    host=host,
                    kind="hash",
                    service="ntlm",
                    secret=ntlm_match.group("hash"),
                    seen_credentials=seen_credentials,
                    seen_accounts=seen_accounts,
                )
                continue

            password_match = _PASSWORD_RE.match(line)
            if password_match is not None:
                password = self._clean(password_match.group("password"))
                if password is None:
                    continue
                self._emit_secret(
                    observations,
                    username=username,
                    domain=domain,
                    host=host,
                    kind="password",
                    service=section,
                    secret=password,
                    seen_credentials=seen_credentials,
                    seen_accounts=seen_accounts,
                )
                continue

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Mimikatz credential material could be parsed."],
            metadata={
                "credential_count": len(seen_credentials),
                "account_count": len(seen_accounts),
            },
        )

    def _emit_secret(
        self,
        observations: list[ParsedObservation],
        *,
        username: str,
        domain: str | None,
        host: str | None,
        kind: str,
        service: str,
        secret: str,
        seen_credentials: set[tuple[str, str | None, str]],
        seen_accounts: set[tuple[str | None, str]],
    ) -> None:
        """Append a credential observation (and its account, once) if not already seen."""

        credential = self._credential(
            username=username,
            domain=domain,
            host=host,
            kind=kind,
            service=service,
            secret=secret,
            seen=seen_credentials,
        )
        if credential is None:
            return
        observations.append(credential)

        account = self._account(username, domain, host, seen_accounts)
        if account is not None:
            observations.append(account)

    def _credential(
        self,
        *,
        username: str,
        domain: str | None,
        host: str | None,
        kind: str,
        service: str,
        secret: str,
        seen: set[tuple[str, str | None, str]],
    ) -> ParsedObservation | None:
        """Build a credential observation, deduping on (username, host, service)."""

        key = (username, host, service)
        if key in seen:
            return None
        seen.add(key)

        account_label = f"{domain}\\{username}" if domain else username
        return ParsedObservation(
            kind="credential",
            summary=f"Mimikatz recovered {kind} for {account_label}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "secret": secret,
                "kind": kind,
                "host": host,
                "service": service,
                "validated": False,
            },
            metadata={"domain": domain, "provider": service},
        )

    def _account(
        self,
        username: str,
        domain: str | None,
        host: str | None,
        seen: set[tuple[str | None, str]],
    ) -> ParsedObservation | None:
        """Build an account observation for the compromised account, once per user."""

        key = (domain, username)
        if key in seen:
            return None
        seen.add(key)

        return ParsedObservation(
            kind="account",
            summary=f"Mimikatz-recovered account {username}",
            source_tool=self.source_tool,
            data={
                "username": username,
                "domain": domain,
                "host": host,
                "source": "mimikatz",
                "enabled": True,
            },
        )

    @staticmethod
    def _clean(value: str) -> str | None:
        """Strip a captured field value, mapping blank/(null) markers to None."""

        cleaned = value.strip()
        if cleaned.lower() in _BLANK_MARKERS:
            return None
        return cleaned
