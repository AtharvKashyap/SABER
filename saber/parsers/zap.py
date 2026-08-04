"""OWASP ZAP output parser for SABER."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class ZapParser(BaseParser):
    """Parse OWASP ZAP JSON alert reports into canonical vuln/note observations.

    Handles the standard ZAP JSON report shape produced by ``zap-baseline.py
    -J``, ``zap-full-scan.py -J``, and ``zap-cli report -f json``::

        {"site": [{"@name": "http://example.com", "alerts": [{...}]}]}

    Each alert becomes a ``vuln`` observation; a per-site summary becomes a
    ``note`` observation.
    """

    source_tool = "zap"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse ZAP JSON report text."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["ZAP output is empty."],
            )

        decoded = self.safe_json_loads(stripped)
        if decoded is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["ZAP output is not valid JSON."],
            )
        return self.parse_json(decoded, metadata=metadata)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse a ZAP JSON alert report into vuln/note observations."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["ZAP output is not a JSON object."],
            )

        sites = data.get("site")
        if not isinstance(sites, list) or not sites:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["ZAP output has no 'site' list."],
            )

        observations: list[ParsedObservation] = []

        for site in sites:
            if not isinstance(site, dict):
                continue
            site_name = str(site.get("@name") or "").strip()
            raw_alerts = site.get("alerts")
            alerts = raw_alerts if isinstance(raw_alerts, list) else []

            alert_count = 0
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                title = str(alert.get("name") or "").strip()
                if not title:
                    continue
                alert_count += 1
                observations.append(self._vuln_observation(alert, title, site_name))

            if site_name:
                observations.append(
                    ParsedObservation(
                        kind="note",
                        summary=f"ZAP scan summary for {site_name}",
                        source_tool=self.source_tool,
                        data={
                            "title": f"ZAP scan summary: {site_name}",
                            "detail": f"{alert_count} alert(s) reported for {site_name}.",
                        },
                    )
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No ZAP alerts could be parsed."],
            metadata={"site_count": len(sites)},
        )

    def _vuln_observation(
        self, alert: dict[str, Any], title: str, site_name: str
    ) -> ParsedObservation:
        """Build a canonical vuln observation from one ZAP alert record."""

        host, port = self._host_port(alert, site_name)
        severity = self.severity_from_string(self._risk_token(alert.get("riskdesc")))
        identifier = str(alert.get("cweid") or alert.get("alertRef") or "").strip() or None
        instances = alert.get("instances")
        confirmed = bool(isinstance(instances, list) and instances)

        return ParsedObservation(
            kind="vuln",
            summary=f"ZAP alert: {title}",
            source_tool=self.source_tool,
            data={
                "title": title,
                "host": host,
                "port": port,
                "severity": severity.value,
                "identifier": identifier,
                "confirmed": confirmed,
            },
        )

    @staticmethod
    def _risk_token(riskdesc: Any) -> str | None:
        """Extract the leading risk word from a ZAP 'riskdesc' string (e.g. 'High (Medium)')."""

        if not riskdesc:
            return None
        text = str(riskdesc).strip()
        return text.split(" ", 1)[0] if text else None

    @staticmethod
    def _host_port(alert: dict[str, Any], site_name: str) -> tuple[str | None, int | None]:
        """Derive host/port from the first alert instance URI, else the site name."""

        instances = alert.get("instances")
        uri = None
        if isinstance(instances, list) and instances:
            first = instances[0]
            if isinstance(first, dict):
                uri = first.get("uri")

        parsed = urlparse(str(uri or site_name or ""))
        return parsed.hostname, parsed.port
