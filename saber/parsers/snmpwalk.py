"""snmpwalk output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_LINE_RE = re.compile(r"^(?P<oid>\S+)\s*=\s*(?P<type>[A-Za-z][\w-]*)\s*:\s*(?P<value>.*)$")

_SYS_TITLES: dict[str, str] = {
    "sysdescr": "SNMP sysDescr",
    "sysname": "SNMP sysName",
    "syscontact": "SNMP sysContact",
    "syslocation": "SNMP sysLocation",
}

# Windows LanManager "user accounts" MIB — a well-known SNMP misconfiguration
# that leaks local account names when community strings are left at defaults.
_USER_MIB_PREFIX = "enterprises.77.1.2.25"


def _clean_value(raw: str) -> str:
    """Strip surrounding quotes/whitespace from a walked SNMP value."""

    value = raw.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.strip()


class SnmpwalkParser(BaseParser):
    """Parse ``snmpwalk`` text output into canonical note/account observations.

    A full SNMP walk can return thousands of OIDs; this parser distills that
    into a small, meaningful set of notes (system description/name/contact/
    location, a running-processes summary, an installed-software summary)
    plus one ``account`` observation per enumerated local user, rather than
    emitting one note per OID line (which would flood ``MissionState``).
    """

    source_tool = "snmpwalk"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse raw ``snmpwalk`` stdout."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["snmpwalk output is empty."],
            )

        sys_values: dict[str, str] = {}
        processes: list[str] = []
        software: list[str] = []
        usernames: list[str] = []
        seen_usernames: set[str] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = _LINE_RE.match(line)
            if match is None:
                continue

            oid = match.group("oid")
            value = _clean_value(match.group("value"))
            if not value:
                continue

            lowered_oid = oid.lower()

            sys_key = next(
                (key for key in _SYS_TITLES if lowered_oid.split("::")[-1].startswith(key)),
                None,
            )
            if sys_key is not None:
                sys_values[sys_key] = value
                continue

            if "hrswrunname" in lowered_oid:
                processes.append(value)
                continue

            if "hrswinstalledname" in lowered_oid:
                software.append(value)
                continue

            if _USER_MIB_PREFIX in lowered_oid:
                if value not in seen_usernames:
                    seen_usernames.add(value)
                    usernames.append(value)
                continue

        observations: list[ParsedObservation] = []

        for key, title in _SYS_TITLES.items():
            sys_value = sys_values.get(key)
            if not sys_value:
                continue
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={"title": title, "detail": sys_value, "severity": "info"},
                )
            )

        if processes:
            title = "SNMP running processes summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"{len(processes)} running process(es) enumerated via SNMP: "
                            f"{', '.join(processes)}"
                        ),
                        "severity": "info",
                        "metadata": {"processes": processes, "count": len(processes)},
                    },
                )
            )

        if software:
            title = "SNMP installed software summary"
            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"{len(software)} installed software package(s) enumerated via "
                            f"SNMP: {', '.join(software)}"
                        ),
                        "severity": "info",
                        "metadata": {"software": software, "count": len(software)},
                    },
                )
            )

        for username in usernames:
            observations.append(
                ParsedObservation(
                    kind="account",
                    summary=f"SNMP-enumerated user {username}",
                    source_tool=self.source_tool,
                    data={"username": username, "source": "snmpwalk"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No snmpwalk results could be parsed."],
            metadata={
                "sys_field_count": len(sys_values),
                "process_count": len(processes),
                "software_count": len(software),
                "account_count": len(usernames),
            },
        )
