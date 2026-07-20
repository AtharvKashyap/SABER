"""Normalize parsed tool observations into MissionState.

This is the deterministic 'update its understanding' step of the mission loop.
It dedupes hosts/services/technologies, promotes vulns, tracks credentials,
attaches evidence/finding refs, and records the attempted action.
"""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import (
    AttemptedAction,
    KnownCredential,
    KnownHost,
    KnownService,
    KnownTechnology,
    KnownVuln,
    MissionState,
)


class StateMerger:
    """Merge normalized parser observations into MissionState."""

    def merge(
        self,
        state: MissionState,
        parsed_observations: list[dict[str, Any]],
        attempt: AttemptedAction,
        evidence_refs: list[str] | None = None,
        finding_refs: list[str] | None = None,
    ) -> MissionState:
        """Return a new MissionState folding in the parsed observations."""

        hosts = {host.address: host for host in state.hosts}
        services = {svc.key: svc for svc in state.services}
        technologies = {(tech.host, tech.name): tech for tech in state.technologies}
        credentials = {(cred.username, cred.host, cred.service): cred for cred in state.credentials}
        vulns = {self._vuln_key(v.title, v.host, v.port): v for v in state.vulns}

        for observation in parsed_observations:
            kind = str(observation.get("kind") or "").lower()
            data = observation.get("data") or {}
            if not isinstance(data, dict):
                continue

            if kind == "host":
                self._merge_host(hosts, data)
            elif kind == "service":
                self._merge_service(services, hosts, data)
            elif kind == "technology":
                self._merge_technology(technologies, data)
            elif kind == "credential":
                self._merge_credential(credentials, data)
            elif kind == "vuln":
                self._merge_vuln(vulns, data, evidence_refs or [])

        updated = state.record_attempt(attempt)
        return updated.model_copy(
            update={
                "hosts": list(hosts.values()),
                "services": list(services.values()),
                "technologies": list(technologies.values()),
                "credentials": list(credentials.values()),
                "vulns": list(vulns.values()),
                "evidence_refs": self._extend_unique(state.evidence_refs, evidence_refs),
                "finding_refs": self._extend_unique(state.finding_refs, finding_refs),
            }
        )

    def _merge_host(self, hosts: dict[str, KnownHost], data: dict[str, Any]) -> None:
        address = str(data.get("address") or data.get("host") or "").strip()
        if not address:
            return
        existing = hosts.get(address)
        hosts[address] = KnownHost(
            address=address,
            hostnames=list(data.get("hostnames") or (existing.hostnames if existing else [])),
            os=data.get("os") or (existing.os if existing else None),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_service(
        self,
        services: dict[str, KnownService],
        hosts: dict[str, KnownHost],
        data: dict[str, Any],
    ) -> None:
        host = str(data.get("host") or "").strip()
        port = data.get("port")
        if not host or port is None:
            return
        candidate = KnownService(
            host=host,
            port=int(port),
            protocol=str(data.get("protocol") or "tcp"),
            service=data.get("service"),
            product=data.get("product"),
            version=data.get("version"),
            state=str(data.get("state") or "open"),
        )
        existing = services.get(candidate.key)
        if existing is None:
            services[candidate.key] = candidate
        else:
            services[candidate.key] = existing.model_copy(
                update={
                    "service": candidate.service or existing.service,
                    "product": candidate.product or existing.product,
                    "version": candidate.version or existing.version,
                    "state": candidate.state or existing.state,
                }
            )
        hosts.setdefault(host, KnownHost(address=host))

    def _merge_technology(
        self, technologies: dict[tuple, KnownTechnology], data: dict[str, Any]
    ) -> None:
        host = str(data.get("host") or "").strip()
        name = str(data.get("name") or "").strip()
        if not host or not name:
            return
        technologies[(host, name)] = KnownTechnology(
            host=host, name=name, version=data.get("version")
        )

    def _merge_credential(
        self, credentials: dict[tuple, KnownCredential], data: dict[str, Any]
    ) -> None:
        username = str(data.get("username") or "").strip()
        if not username:
            return
        key = (username, data.get("host"), data.get("service"))
        credentials[key] = KnownCredential(
            username=username,
            secret=data.get("secret"),
            kind=str(data.get("kind") or "password"),
            host=data.get("host"),
            service=data.get("service"),
            validated=bool(data.get("validated", False)),
        )

    def _merge_vuln(
        self, vulns: dict[str, KnownVuln], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        title = str(data.get("title") or "").strip()
        if not title:
            return
        key = self._vuln_key(title, data.get("host"), data.get("port"))
        vulns[key] = KnownVuln(
            title=title,
            host=data.get("host"),
            port=data.get("port"),
            severity=str(data.get("severity") or "info"),
            identifier=data.get("identifier"),
            confirmed=bool(data.get("confirmed", False)),
            evidence_refs=list(evidence_refs),
        )

    @staticmethod
    def _vuln_key(title: str, host: Any, port: Any) -> str:
        return f"{title}|{host}|{port}"

    @staticmethod
    def _extend_unique(base: list[str], extra: list[str] | None) -> list[str]:
        result = list(base)
        for item in extra or []:
            if item not in result:
                result.append(item)
        return result
