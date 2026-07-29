"""Nmap output parser for SABER."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class NmapParser(BaseParser):
    """Parse Nmap XML/stdout into host and service observations."""

    source_tool = "nmap"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Nmap XML or stdout."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(source_tool=self.source_tool, success=False, errors=["Nmap output is empty."])

        if stripped.startswith("<"):
            return self.parse_xml(stripped)

        return self._parse_stdout(stripped)

    def parse_xml(self, text: str) -> ParserResult:
        """Parse Nmap XML output."""

        observations: list[ParsedObservation] = []
        errors: list[str] = []

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            return ParserResult(source_tool=self.source_tool, success=False, errors=[f"Invalid Nmap XML: {exc}"])

        for host in root.findall("host"):
            address = self._host_address(host)
            if not address:
                continue

            state = self._host_state(host)
            hostnames = self._hostnames(host)

            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=f"Host {address} is {state}.",
                    source_tool=self.source_tool,
                    data={
                        "host": address,
                        "state": state,
                        "hostnames": hostnames,
                    },
                )
            )

            for port in host.findall("./ports/port"):
                port_observation = self._port_observation(address, port)
                if port_observation:
                    observations.append(port_observation)

        return ParserResult(
            source_tool=self.source_tool,
            success=True,
            observations=observations,
            metadata={"format": "xml", "observation_count": len(observations)},
            errors=errors,
        )

    def _parse_stdout(self, text: str) -> ParserResult:
        """Parse common Nmap stdout fallback."""

        observations: list[ParsedObservation] = []
        current_host: str | None = None

        host_pattern = re.compile(r"Nmap scan report for (?P<host>.+)")
        port_pattern = re.compile(
            r"^(?P<port>\d+)/(?P<protocol>\w+)\s+(?P<state>\w+)\s+(?P<service>\S+)(?:\s+(?P<extra>.*))?$"
        )

        for line in text.splitlines():
            line = line.strip()
            host_match = host_pattern.search(line)
            if host_match:
                raw_host = host_match.group("host").strip()
                current_host = raw_host.split()[-1].strip("()")
                observations.append(
                    ParsedObservation(
                        kind="host",
                        summary=f"Host {current_host} was reported by Nmap.",
                        source_tool=self.source_tool,
                        data={"host": current_host, "state": "unknown", "raw": raw_host},
                        metadata={"format": "stdout"},
                    )
                )
                continue

            port_match = port_pattern.match(line)
            if port_match and current_host:
                port = int(port_match.group("port"))
                protocol = port_match.group("protocol")
                state = port_match.group("state")
                service = port_match.group("service")
                extra = port_match.group("extra") or ""

                observations.append(
                    ParsedObservation(
                        kind="service",
                        summary=f"{current_host}:{port}/{protocol} is {state} running {service}.",
                        source_tool=self.source_tool,
                        data={
                            "host": current_host,
                            "port": port,
                            "protocol": protocol,
                            "state": state,
                            "service": service,
                            "extra": extra,
                        },
                        metadata={"format": "stdout"},
                    )
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Nmap observations could be parsed."],
            metadata={"format": "stdout", "observation_count": len(observations)},
        )

    def _port_observation(self, host: str, port: ET.Element) -> ParsedObservation | None:
        """Build service observation from XML port element."""

        port_id = port.attrib.get("portid")
        protocol = port.attrib.get("protocol", "tcp")
        state_element = port.find("state")
        service_element = port.find("service")

        if not port_id:
            return None

        state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"
        service = service_element.attrib.get("name", "unknown") if service_element is not None else "unknown"
        product = service_element.attrib.get("product") if service_element is not None else None
        version = service_element.attrib.get("version") if service_element is not None else None
        extrainfo = service_element.attrib.get("extrainfo") if service_element is not None else None
        cpes = [cpe.text for cpe in port.findall("./service/cpe") if cpe.text]

        service_label = " ".join(part for part in [service, product, version] if part)

        return ParsedObservation(
            kind="service",
            summary=f"{host}:{port_id}/{protocol} is {state} running {service_label or service}.",
            source_tool=self.source_tool,
            data={
                "host": host,
                "port": int(port_id),
                "protocol": protocol,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpes": cpes,
            },
            metadata={"format": "xml"},
        )

    @staticmethod
    def _host_address(host: ET.Element) -> str | None:
        """Extract host address."""

        for address in host.findall("address"):
            if address.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                return address.attrib.get("addr")
        address = host.find("address")
        return address.attrib.get("addr") if address is not None else None

    @staticmethod
    def _host_state(host: ET.Element) -> str:
        """Extract host state."""

        state = host.find("status")
        return state.attrib.get("state", "unknown") if state is not None else "unknown"

    @staticmethod
    def _hostnames(host: ET.Element) -> list[str]:
        """Extract hostnames."""

        names: list[str] = []
        for hostname in host.findall("./hostnames/hostname"):
            name = hostname.attrib.get("name")
            if name:
                names.append(name)
        return names

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Nmap JSON is not first-class; accept already-normalized records."""

        records = data if isinstance(data, list) else data.get("hosts", [])
        observations: list[ParsedObservation] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            host = record.get("host") or record.get("ip") or record.get("address")
            if not host:
                continue
            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=f"Host {host} was reported by Nmap.",
                    source_tool=self.source_tool,
                    data=record,
                    metadata={"format": "json"},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No Nmap JSON observations could be parsed."],
            metadata={"format": "json", "observation_count": len(observations)},
        )
