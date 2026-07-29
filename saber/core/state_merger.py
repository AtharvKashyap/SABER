"""Normalize parsed tool observations into MissionState.

This is the deterministic 'update its understanding' step of the mission loop.
It dedupes hosts/services/technologies, promotes vulns, tracks credentials,
attaches evidence/finding refs, and records the attempted action.
"""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import (
    AttemptedAction,
    KnownAccount,
    KnownCredential,
    KnownFlag,
    KnownHost,
    KnownLoot,
    KnownService,
    KnownSession,
    KnownShare,
    KnownTechnology,
    KnownVuln,
    MissionNote,
    MissionState,
)


class StateMerger:
    """Merge normalized parser observations into MissionState.

    Consumes the canonical observation vocabulary (single source of truth,
    mirrored in ``saber/parsers/base.py``). Each ``kind`` folds into exactly one
    ``MissionState`` list via one merger; required data fields are marked
    ``(req)``. ``kind -> MissionState list``:

    - host -> hosts (KnownHost):
        address (req), hostnames: list[str], os, metadata
    - service -> services (KnownService):
        host (req), port (req, int), protocol, service, product, version, state
    - technology -> technologies (KnownTechnology):
        host (req), name (req), version, metadata
    - credential -> credentials (KnownCredential):
        username (req), secret, kind (password|hash|key|token), host, service,
        validated: bool
    - vuln -> vulns (KnownVuln):
        title (req), host, port, severity, identifier, confirmed: bool
    - share -> shares (KnownShare):
        host (req), name (req), type, access (read|write|none), metadata
    - account -> accounts (KnownAccount):
        username (req), domain, host, source, enabled: bool, metadata
    - session -> sessions (KnownSession):
        host (req), kind (shell|meterpreter|winrm|ssh), user,
        privilege (user|root|system), ref, metadata
    - loot -> loot (KnownLoot):
        host, path, kind (file|hash|key|config), description (req), evidence_ref,
        metadata
    - flag -> flags (KnownFlag):
        value (req), host, location, metadata
    - note -> notes (list[MissionNote]):
        title (req), detail, severity, refs: list[str], metadata
    """

    def merge(
        self,
        state: MissionState,
        parsed_observations: list[dict[str, Any]],
        attempt: AttemptedAction,
        evidence_refs: list[str] | None = None,
        finding_refs: list[str] | None = None,
    ) -> MissionState:
        """Return a new MissionState folding in the parsed observations."""

        acc: dict[str, dict[Any, Any]] = {
            "host": {h.address: h for h in state.hosts},
            "service": {s.key: s for s in state.services},
            "technology": {(t.host, t.name): t for t in state.technologies},
            "credential": {(c.username, c.host, c.service): c for c in state.credentials},
            "vuln": {self._vuln_key(v.title, v.host, v.port): v for v in state.vulns},
            "share": {(s.host, s.name): s for s in state.shares},
            "account": {(a.domain, a.username): a for a in state.accounts},
            "session": {(s.host, s.kind, s.user): s for s in state.sessions},
            "loot": {(loot_.host, loot_.path, loot_.kind): loot_ for loot_ in state.loot},
            "flag": {f.value: f for f in state.flags},
            "note": {n.title: n for n in state.notes},
        }

        for observation in parsed_observations:
            kind = str(observation.get("kind") or "").lower()
            data = observation.get("data") or {}
            if not isinstance(data, dict):
                continue
            merger = self._MERGERS.get(kind)
            if merger is None:
                continue
            merger(self, acc, data, evidence_refs or [])

        updated = state.record_attempt(attempt)
        return updated.model_copy(
            update={
                "hosts": list(acc["host"].values()),
                "services": list(acc["service"].values()),
                "technologies": list(acc["technology"].values()),
                "credentials": list(acc["credential"].values()),
                "vulns": list(acc["vuln"].values()),
                "shares": list(acc["share"].values()),
                "accounts": list(acc["account"].values()),
                "sessions": list(acc["session"].values()),
                "loot": list(acc["loot"].values()),
                "flags": list(acc["flag"].values()),
                "notes": list(acc["note"].values()),
                "evidence_refs": self._extend_unique(state.evidence_refs, evidence_refs),
                "finding_refs": self._extend_unique(state.finding_refs, finding_refs),
            }
        )

    def _merge_host(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        hosts = acc["host"]
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
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        services = acc["service"]
        hosts = acc["host"]
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
                    "state": candidate.state if "state" in data else existing.state,
                }
            )
        hosts.setdefault(host, KnownHost(address=host))

    def _merge_technology(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        technologies = acc["technology"]
        host = str(data.get("host") or "").strip()
        name = str(data.get("name") or "").strip()
        if not host or not name:
            return
        existing = technologies.get((host, name))
        technologies[(host, name)] = KnownTechnology(
            host=host,
            name=name,
            version=data.get("version") or (existing.version if existing else None),
        )

    def _merge_credential(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        credentials = acc["credential"]
        username = str(data.get("username") or "").strip()
        if not username:
            return
        key = (username, data.get("host"), data.get("service"))
        existing = credentials.get(key)
        credentials[key] = KnownCredential(
            username=username,
            secret=data.get("secret") or (existing.secret if existing else None),
            kind=str(data.get("kind") or (existing.kind if existing else "password")),
            host=data.get("host") or (existing.host if existing else None),
            service=data.get("service") or (existing.service if existing else None),
            validated=bool(data.get("validated", existing.validated if existing else False)),
        )

    def _merge_vuln(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        vulns = acc["vuln"]
        title = str(data.get("title") or "").strip()
        if not title:
            return
        key = self._vuln_key(title, data.get("host"), data.get("port"))
        existing = vulns.get(key)
        vulns[key] = KnownVuln(
            title=title,
            host=data.get("host") or (existing.host if existing else None),
            port=data.get("port") or (existing.port if existing else None),
            severity=str(data.get("severity") or (existing.severity if existing else "info")),
            identifier=data.get("identifier") or (existing.identifier if existing else None),
            confirmed=bool(data.get("confirmed", existing.confirmed if existing else False)),
            evidence_refs=self._extend_unique(
                existing.evidence_refs if existing else [], evidence_refs
            ),
        )

    def _merge_share(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        shares = acc["share"]
        host = str(data.get("host") or "").strip()
        name = str(data.get("name") or "").strip()
        if not host or not name:
            return
        existing = shares.get((host, name))
        shares[(host, name)] = KnownShare(
            host=host,
            name=name,
            type=str(data.get("type") or (existing.type if existing else "smb")),
            access=str(data.get("access") or (existing.access if existing else "none")),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_account(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        accounts = acc["account"]
        username = str(data.get("username") or "").strip()
        if not username:
            return
        domain = data.get("domain")
        existing = accounts.get((domain, username))
        accounts[(domain, username)] = KnownAccount(
            username=username,
            domain=domain or (existing.domain if existing else None),
            host=data.get("host") or (existing.host if existing else None),
            source=data.get("source") or (existing.source if existing else None),
            enabled=bool(data.get("enabled", existing.enabled if existing else True)),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_session(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        sessions = acc["session"]
        host = str(data.get("host") or "").strip()
        if not host:
            return
        kind = str(data.get("kind") or "shell")
        user = data.get("user")
        existing = sessions.get((host, kind, user))
        sessions[(host, kind, user)] = KnownSession(
            host=host,
            kind=kind,
            user=user or (existing.user if existing else None),
            privilege=str(data.get("privilege") or (existing.privilege if existing else "user")),
            ref=data.get("ref") or (existing.ref if existing else None),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_loot(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        loot = acc["loot"]
        description = str(data.get("description") or "").strip()
        if not description:
            return
        host = data.get("host")
        path = data.get("path")
        kind = str(data.get("kind") or "file")
        existing = loot.get((host, path, kind))
        loot[(host, path, kind)] = KnownLoot(
            description=description,
            kind=kind,
            host=host or (existing.host if existing else None),
            path=path or (existing.path if existing else None),
            evidence_ref=data.get("evidence_ref") or (existing.evidence_ref if existing else None),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_flag(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        flags = acc["flag"]
        value = str(data.get("value") or "").strip()
        if not value:
            return
        existing = flags.get(value)
        flags[value] = KnownFlag(
            value=value,
            host=data.get("host") or (existing.host if existing else None),
            location=data.get("location") or (existing.location if existing else None),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_note(
        self, acc: dict[str, Any], data: dict[str, Any], evidence_refs: list[str]
    ) -> None:
        notes = acc["note"]
        title = str(data.get("title") or "").strip()
        if not title:
            return
        existing = notes.get(title)
        notes[title] = MissionNote(
            title=title,
            detail=str(data.get("detail") or (existing.detail if existing else "")),
            severity=str(data.get("severity") or (existing.severity if existing else "info")),
            refs=self._extend_unique(
                existing.refs if existing else [], list(data.get("refs") or [])
            ),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    _MERGERS = {
        "host": _merge_host,
        "service": _merge_service,
        "technology": _merge_technology,
        "credential": _merge_credential,
        "vuln": _merge_vuln,
        "share": _merge_share,
        "account": _merge_account,
        "session": _merge_session,
        "loot": _merge_loot,
        "flag": _merge_flag,
        "note": _merge_note,
    }

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
