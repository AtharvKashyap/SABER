"""WhatWeb output parser for SABER.

Emits canonical observations: one ``technology`` per detected technology
(each carrying a derived ``host``), plus a single ``service`` for the HTTP
port. The pre-canonical ``web_technology`` blob is retired.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Plugins that describe the response, not a technology stack component.
_IGNORED_PLUGINS = {
    "Title",
    "IP",
    "Country",
    "HTTPStatus",
    "HTTPServer",
    "RedirectLocation",
}


class WhatWebParser(BaseParser):
    """Parse WhatWeb JSON/stdout into canonical technology + service observations."""

    source_tool = "whatweb"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse WhatWeb JSON (preferred) or stdout, threading target metadata."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["WhatWeb output is empty."],
            )

        parsed = self.safe_json_loads(stripped)
        if parsed is not None:
            return self.parse_json(parsed, metadata=metadata)

        return self._parse_stdout(stripped, metadata=metadata)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse WhatWeb JSON output into canonical observations."""

        records = data if isinstance(data, list) else [data]
        observations: list[ParsedObservation] = []

        for record in records:
            if not isinstance(record, dict):
                continue

            url = record.get("target") or record.get("url") or record.get("uri")
            if not url and metadata:
                url = metadata.get("target") or metadata.get("url")

            host = self._host_from(url)
            plugins = record.get("plugins", {})
            if not isinstance(plugins, dict):
                plugins = {}

            if not host or not plugins:
                continue

            observations.extend(self._observations_from_plugins(host, url, plugins))

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No WhatWeb JSON observations could be parsed."],
            metadata={"format": "json", "observation_count": len(observations)},
        )

    def _parse_stdout(
        self, text: str, metadata: dict[str, Any] | None = None
    ) -> ParserResult:
        """Parse common WhatWeb stdout into per-tech technology observations."""

        observations: list[ParsedObservation] = []

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            url = line.split()[0]
            host = self._host_from(url) or self._host_from(
                (metadata or {}).get("target") or (metadata or {}).get("url")
            )
            if not host:
                continue

            server = self._extract_bracket_value(line, r"HTTPServer\[([^\]]+)\]")
            for name in self._stdout_technology_names(line):
                version = self._extract_bracket_value(line, rf"{re.escape(name)}\[([^\]]+)\]")
                observations.append(
                    self._technology(host, url, name, version)
                )

            observations.append(self._service(host, url, server))
            if server:
                product, product_version = self._split_product(server)
                observations.append(
                    self._technology(host, url, product, product_version)
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No WhatWeb stdout observations could be parsed."],
            metadata={"format": "stdout", "observation_count": len(observations)},
        )

    def _observations_from_plugins(
        self, host: str, url: str | None, plugins: dict[str, Any]
    ) -> list[ParsedObservation]:
        """Turn a record's plugin map into canonical observations."""

        observations: list[ParsedObservation] = []

        for name, value in plugins.items():
            if name in _IGNORED_PLUGINS:
                continue
            version = self._first_version(value)
            observations.append(self._technology(host, url, name, version))

        server = self._extract_plugin_string(plugins, "HTTPServer")
        observations.append(self._service(host, url, server))
        if server:
            product, product_version = self._split_product(server)
            observations.append(self._technology(host, url, product, product_version))

        return observations

    def _technology(
        self, host: str, url: str | None, name: str, version: str | None
    ) -> ParsedObservation:
        """Build a canonical `technology` observation."""

        label = f"{name} {version}".strip() if version else name
        return ParsedObservation(
            kind="technology",
            summary=f"{host} runs {label}.",
            source_tool=self.source_tool,
            data={"host": host, "name": name, "version": version},
            metadata={"url": url} if url else {},
        )

    def _service(
        self, host: str, url: str | None, server: str | None
    ) -> ParsedObservation:
        """Build a canonical `service` observation for the HTTP port."""

        port, scheme = self._port_from(url)
        product, product_version = self._split_product(server) if server else (None, None)
        return ParsedObservation(
            kind="service",
            summary=f"HTTP service on {host}:{port}"
            + (f" ({server})" if server else "")
            + ".",
            source_tool=self.source_tool,
            data={
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": scheme,
                "product": product or server,
                "version": product_version,
            },
            metadata={"url": url} if url else {},
        )

    @staticmethod
    def _host_from(url: str | None) -> str | None:
        """Derive a bare hostname from a target/URL, tolerating a missing scheme."""

        if not url:
            return None
        text = str(url).strip()
        if not text:
            return None
        parsed = urlparse(text if "//" in text else f"//{text}")
        return parsed.hostname

    @staticmethod
    def _port_from(url: str | None) -> tuple[int, str]:
        """Derive (port, scheme) from a URL, defaulting to HTTP/80 or HTTPS/443."""

        if not url:
            return 80, "http"
        text = str(url).strip()
        parsed = urlparse(text if "//" in text else f"//{text}")
        scheme = parsed.scheme or "http"
        if parsed.port:
            return parsed.port, ("https" if scheme == "https" else "http")
        if scheme == "https":
            return 443, "https"
        return 80, "http"

    @staticmethod
    def _first_version(value: Any) -> str | None:
        """Extract the first version string from a WhatWeb plugin value."""

        if isinstance(value, dict):
            raw = value.get("version")
            if isinstance(raw, list) and raw:
                return str(raw[0])
            if isinstance(raw, str) and raw:
                return raw
        return None

    @staticmethod
    def _split_product(server: str) -> tuple[str, str | None]:
        """Split an HTTPServer string like ``Apache/2.4.7 (Ubuntu)`` into (name, version)."""

        first = server.split()[0] if server.split() else server
        match = re.match(r"([^/]+)/([0-9][0-9A-Za-z.\-]*)", first)
        if match:
            return match.group(1), match.group(2)
        return first, None

    @staticmethod
    def _extract_plugin_string(plugins: dict[str, Any], key: str) -> str | None:
        """Extract a common WhatWeb plugin string."""

        value = plugins.get(key)
        if not value:
            return None

        if isinstance(value, dict):
            strings = value.get("string")
            if isinstance(strings, list) and strings:
                return str(strings[0])
            if isinstance(strings, str):
                return strings

        return str(value)

    @staticmethod
    def _extract_bracket_value(text: str, pattern: str) -> str | None:
        """Extract regex bracket value."""

        match = re.search(pattern, text)
        return match.group(1) if match else None

    @staticmethod
    def _stdout_technology_names(line: str) -> list[str]:
        """Extract technology plugin names from a stdout line."""

        names = re.findall(r"([A-Za-z0-9_\-]+)\[", line)
        return sorted({name for name in names if name not in _IGNORED_PLUGINS})
