"""OpenVAS/GVM report parser for SABER."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# GVM reports emit informational "Log" threat entries (e.g. host-alive pings)
# that carry no vulnerability signal; they are not surfaced as findings.
_SKIP_THREATS = {"log", "none", ""}


class OpenVASParser(BaseParser):
    """Parse GVM/OpenVAS ``get_reports`` XML into canonical vuln observations."""

    source_tool = "openvas"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse GVM report XML."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["OpenVAS output is empty."],
            )

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as exc:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=[f"Invalid OpenVAS XML: {exc}"],
            )

        observations: list[ParsedObservation] = []
        for result in root.findall(".//result"):
            observation = self._result_observation(result)
            if observation is not None:
                observations.append(observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No OpenVAS vulnerability results could be parsed."],
            metadata={"format": "xml", "observation_count": len(observations)},
        )

    def _result_observation(self, result: ET.Element) -> ParsedObservation | None:
        """Build a vuln observation from a single GVM ``<result>`` element."""

        name_element = result.find("name")
        title = (name_element.text or "").strip() if name_element is not None else ""
        if not title:
            return None

        threat = self._text(result, "threat")
        if threat.strip().lower() in _SKIP_THREATS:
            return None

        host = self._text(result, "host") or None
        port = self._parse_port(self._text(result, "port"))
        severity = self._severity(result, threat)
        identifier = self._identifier(result)

        return ParsedObservation(
            kind="vuln",
            summary=f"{title} on {host or 'unknown host'} ({severity}).",
            source_tool=self.source_tool,
            data={
                "title": title,
                "host": host,
                "port": port,
                "severity": severity,
                "identifier": identifier,
                "confirmed": True,
            },
            metadata={
                "threat": threat or None,
                "description": self._text(result, "description") or None,
            },
        )

    def _severity(self, result: ET.Element, threat: str) -> str:
        """Derive canonical severity, preferring the GVM threat label."""

        normalized = self.severity_from_string(threat)
        if normalized.value != "unknown":
            return normalized.value

        cvss_text = self._text(result, "severity")
        return self._severity_from_cvss(cvss_text)

    @staticmethod
    def _severity_from_cvss(cvss_text: str) -> str:
        """Map a CVSS 0.0-10.0 float onto a canonical severity band."""

        try:
            score = float(cvss_text)
        except (TypeError, ValueError):
            return "unknown"
        if score <= 0.0:
            return "info"
        if score < 4.0:
            return "low"
        if score < 7.0:
            return "medium"
        if score < 9.0:
            return "high"
        return "critical"

    @staticmethod
    def _identifier(result: ET.Element) -> str | None:
        """Extract a CVE id from the nested ``<nvt><cve>`` element."""

        cve_element = result.find("./nvt/cve")
        if cve_element is None or not cve_element.text:
            return None
        cve = cve_element.text.strip()
        if not cve or cve.upper() == "NOCVE":
            return None
        return cve

    @staticmethod
    def _parse_port(port_text: str) -> int | None:
        """Parse a GVM ``443/tcp`` style port into an int, if numeric."""

        if not port_text:
            return None
        head = port_text.split("/", 1)[0].strip()
        return int(head) if head.isdigit() else None

    @staticmethod
    def _text(element: ET.Element, tag: str) -> str:
        """Read stripped text from a direct child tag, defaulting to ''."""

        child = element.find(tag)
        return (child.text or "").strip() if child is not None and child.text else ""
