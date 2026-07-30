"""Enum4linux output parser for SABER."""

from __future__ import annotations

import re
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# "        ADMIN$          Disk      Remote Admin"  (Share Enumeration table row)
_SHARE_ROW_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<type>Disk|IPC|Printer)\s*(?P<comment>.*?)\s*$",
    re.IGNORECASE,
)
# "//192.168.56.10/NETLOGON\tMapping: OK, Listing: OK"
_MAPPING_RE = re.compile(
    r"^//(?P<host>\S+?)/(?P<share>\S+)\s+Mapping:\s*(?P<mapping>OK|DENIED|N/A)"
    r"(?:,\s*Listing:\s*(?P<listing>OK|DENIED|N/A))?",
    re.IGNORECASE,
)
# "index: 0x1 RID: 0x3e9 acb: 0x00000010 Account: jdoe	Name: John Doe	Desc: (null)"
_USER_RE = re.compile(
    r"index:\s*0x[0-9a-f]+\s+RID:\s*0x[0-9a-f]+\s+acb:\s*0x[0-9a-f]+\s+"
    r"Account:\s*(?P<account>\S+)(?:\s+Name:\s*(?P<name>.*?))?(?:\s+Desc:.*)?$",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(r"Got domain/workgroup name:\s*(?P<domain>\S+)", re.IGNORECASE)
_DOMAIN_SID_RE = re.compile(r"^Domain Sid:\s*(?P<sid>\S+)", re.IGNORECASE)


class Enum4LinuxParser(BaseParser):
    """Parse enum4linux/enum4linux-ng stdout output into canonical observations.

    Emits ``share`` observations from the "Share Enumeration" table (merging in
    access from the "Mapping: OK, Listing: OK" lines), ``account`` observations
    from RID-cycling ``index: ... Account: ...`` lines, and ``note`` observations
    for domain/workgroup and domain SID details worth reasoning over. ``host``
    prefers ``metadata["target"]`` since the RID-cycling user lines and the
    share table itself do not always repeat the target host.
    """

    source_tool = "enum4linux"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse enum4linux stdout output."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Enum4linux output is empty."],
            )

        metadata = metadata or {}
        host = str(metadata.get("target") or "").strip() or None

        observations: list[ParsedObservation] = []
        share_types: dict[str, str] = {}
        share_comments: dict[str, str] = {}
        share_access: dict[str, str] = {}
        seen_users: set[str] = set()
        seen_notes: set[str] = set()

        in_share_table = False
        for raw_line in stripped.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue

            if "Share Enumeration" in line:
                in_share_table = True
                continue
            if in_share_table and "Attempting to map shares" in line:
                in_share_table = False

            mapping_match = _MAPPING_RE.match(line.strip())
            if mapping_match is not None:
                in_share_table = False
                mapped_host = mapping_match.group("host")
                share_name = mapping_match.group("share")
                mapping = (mapping_match.group("mapping") or "").upper()
                listing = (mapping_match.group("listing") or "").upper()
                share_access[share_name] = "read" if mapping == "OK" and listing == "OK" else "none"
                if host is None:
                    host = mapped_host
                continue

            if in_share_table:
                stripped_line = line.strip()
                if stripped_line.lower().startswith("sharename") or set(
                    stripped_line.replace(" ", "")
                ) <= {"-"}:
                    continue
                share_match = _SHARE_ROW_RE.match(line)
                if share_match is not None:
                    name = share_match.group("name")
                    share_types[name] = share_match.group("type").lower()
                    share_comments[name] = share_match.group("comment").strip()
                    continue

            user_match = _USER_RE.search(line.strip())
            if user_match is not None:
                account = user_match.group("account").strip()
                if account and account not in seen_users:
                    seen_users.add(account)
                    display_name = (user_match.group("name") or "").strip() or None
                    observations.append(
                        ParsedObservation(
                            kind="account",
                            summary=f"SMB account discovered: {account}",
                            source_tool=self.source_tool,
                            data={
                                "username": account,
                                "host": host,
                                "source": "enum4linux",
                                "enabled": True,
                                "metadata": {"display_name": display_name} if display_name else {},
                            },
                        )
                    )
                continue

            domain_match = _DOMAIN_RE.search(line)
            if domain_match is not None:
                domain = domain_match.group("domain")
                title = f"SMB domain/workgroup: {domain}"
                if title not in seen_notes:
                    seen_notes.add(title)
                    observations.append(
                        ParsedObservation(
                            kind="note",
                            summary=title,
                            source_tool=self.source_tool,
                            data={
                                "title": title,
                                "detail": f"enum4linux reported domain/workgroup name '{domain}'.",
                                "severity": "info",
                                "metadata": {"host": host, "domain": domain},
                            },
                        )
                    )
                continue

            sid_match = _DOMAIN_SID_RE.match(line.strip())
            if sid_match is not None:
                sid = sid_match.group("sid")
                title = "SMB domain SID"
                if title not in seen_notes:
                    seen_notes.add(title)
                    observations.append(
                        ParsedObservation(
                            kind="note",
                            summary=title,
                            source_tool=self.source_tool,
                            data={
                                "title": title,
                                "detail": f"enum4linux reported domain SID {sid}.",
                                "severity": "info",
                                "metadata": {"host": host, "sid": sid},
                            },
                        )
                    )

        for name, share_type in share_types.items():
            comment = share_comments.get(name) or None
            observations.append(
                ParsedObservation(
                    kind="share",
                    summary=f"SMB share discovered: {name}",
                    source_tool=self.source_tool,
                    data={
                        "host": host,
                        "name": name,
                        "type": share_type,
                        "access": share_access.get(name, "none"),
                        "metadata": {"comment": comment} if comment else {},
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No enum4linux findings could be parsed."],
            metadata={
                "format": "stdout",
                "share_count": len(share_types),
                "account_count": len(seen_users),
            },
        )
