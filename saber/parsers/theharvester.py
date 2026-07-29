"""theHarvester output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)
_SECTION_RE = re.compile(r"^\[\*\]\s+(?P<label>[A-Za-z ]+?)\s+found", re.IGNORECASE)


class TheHarvesterParser(BaseParser):
    """Parse theHarvester output into canonical account/host/note observations.

    Emails become ``kind="account"`` (``username`` is the local part, the full
    address is kept in ``metadata``), harvested hosts become ``kind="host"``,
    and one summary ``kind="note"`` records the collection totals. Handles both
    the ``-f`` JSON form and the sectioned stdout form.
    """

    source_tool = "theharvester"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse theHarvester stdout (or JSON, when the output is JSON)."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["theHarvester output is empty."],
            )

        if stripped.startswith("{"):
            decoded = self.safe_json_loads(stripped)
            if decoded is not None:
                return self.parse_json(decoded, metadata=metadata)

        emails: list[str] = []
        hosts: list[str] = []
        section: str | None = None

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line or set(line) <= {"-", "="}:
                continue

            section_match = _SECTION_RE.match(line)
            if section_match is not None:
                section = section_match.group("label").strip().lower()
                continue
            if line.startswith("[") or line.startswith("*"):
                continue

            if _EMAIL_RE.match(line):
                emails.append(line)
            elif section in {"hosts", "interesting urls"} or (
                section is None and _HOSTNAME_RE.match(line.split(":", 1)[0])
            ):
                hosts.append(line)

        return self._result(emails, hosts, output_format="text")

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse theHarvester ``-f`` JSON output."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["theHarvester JSON output is not an object."],
            )

        emails = [str(item).strip() for item in (data.get("emails") or []) if str(item).strip()]
        hosts = [str(item).strip() for item in (data.get("hosts") or []) if str(item).strip()]
        return self._result(emails, hosts, output_format="json")

    def _result(
        self, emails: list[str], hosts: list[str], *, output_format: str
    ) -> ParserResult:
        """Build a ParserResult from harvested emails and hosts."""

        observations: list[ParsedObservation] = []
        seen_emails: set[str] = set()
        seen_hosts: set[str] = set()

        for email in emails:
            normalized = email.strip().lower()
            if not _EMAIL_RE.match(normalized) or normalized in seen_emails:
                continue
            seen_emails.add(normalized)
            username, _, domain = normalized.partition("@")
            observations.append(
                ParsedObservation(
                    kind="account",
                    summary=f"Harvested email {normalized}",
                    source_tool=self.source_tool,
                    data={
                        "username": username,
                        "domain": domain,
                        "source": "theharvester",
                        "metadata": {"email": normalized},
                    },
                )
            )

        for entry in hosts:
            name, _, address = entry.strip().lower().partition(":")
            name = name.strip()
            address = address.strip()
            if not name or not _HOSTNAME_RE.match(name):
                continue
            resolved = address if address else name
            if resolved in seen_hosts:
                continue
            seen_hosts.add(resolved)
            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=f"Harvested host {name}",
                    source_tool=self.source_tool,
                    data={"address": resolved, "hostnames": [name]},
                )
            )

        if observations:
            title = "theHarvester OSINT summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Harvested {len(seen_emails)} email address(es) and "
                            f"{len(seen_hosts)} host(s) via OSINT sources."
                        ),
                        "severity": "info",
                        "metadata": {
                            "email_count": len(seen_emails),
                            "host_count": len(seen_hosts),
                        },
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No theHarvester results could be parsed."],
            metadata={
                "format": output_format,
                "email_count": len(seen_emails),
                "host_count": len(seen_hosts),
            },
        )
