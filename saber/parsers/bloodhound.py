"""BloodHound output parser for SABER.

Emits the canonical observation vocabulary (see ``saber/parsers/base.py``):
AD users become ``account``, computers become ``host``, and groups, domains,
relationships and attack paths become ``note``. Before F3 this parser emitted
``ad_entity``/``ad_relationship``/``ad_path``, none of which ``StateMerger``
knows, so every BloodHound collection was silently discarded and
``MissionState`` never grew — the same defect class as the original whatweb bug.
``ParsedFinding`` output is unchanged and still feeds the report path.
"""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedFinding, ParsedObservation, ParserResult, ParserSeverity

# SharpHound/bloodhound-python meta.type -> the singular entity name used below.
_SHARPHOUND_TYPES = {
    "users": "user",
    "computers": "computer",
    "groups": "group",
    "domains": "domain",
    "gpos": "gpo",
    "ous": "ou",
    "containers": "container",
}


class BloodHoundParser(BaseParser):
    """Parse BloodHound/SharpHound-like JSON into AD observations and findings."""

    source_tool = "bloodhound"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse BloodHound JSON text."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(source_tool=self.source_tool, success=False, errors=["BloodHound output is empty."])

        parsed = self.safe_json_loads(stripped)
        if parsed is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["BloodHound parser currently expects JSON-compatible output."],
            )

        return self.parse_json(parsed)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse BloodHound JSON-compatible data."""

        observations: list[ParsedObservation] = []
        findings: list[ParsedFinding] = []

        if isinstance(data, list):
            for record in data:
                self._consume_record(record, observations, findings)
        else:
            self._consume_collection(data, observations, findings)

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations or findings),
            observations=observations,
            findings=findings,
            errors=[] if observations or findings else ["No BloodHound relationships or paths could be parsed."],
            metadata={
                "format": "json",
                "observation_count": len(observations),
                "finding_count": len(findings),
            },
        )

    def _consume_collection(
        self,
        data: dict[str, Any],
        observations: list[ParsedObservation],
        findings: list[ParsedFinding],
    ) -> None:
        """Consume BloodHound-like collection object."""

        for key in ("relationships", "edges", "links"):
            records = data.get(key)
            if isinstance(records, list):
                for record in records:
                    self._consume_relationship(record, observations, findings)

        for key in ("paths", "attack_paths", "attackPaths"):
            paths = data.get(key)
            if isinstance(paths, list):
                for path in paths:
                    self._consume_path(path, observations, findings)

        for key in ("users", "groups", "computers", "domains"):
            records = data.get(key)
            if isinstance(records, list):
                for record in records:
                    self._consume_entity(key.rstrip("s"), record, observations)

        # Real SharpHound / bloodhound-python output: {"meta": {"type": "users"},
        # "data": [{"Properties": {...}}, ...]}.
        meta = data.get("meta")
        records = data.get("data")
        if isinstance(records, list):
            meta_type = ""
            if isinstance(meta, dict):
                meta_type = str(meta.get("type") or "").lower()
            entity_type = _SHARPHOUND_TYPES.get(meta_type, "entity")
            for record in records:
                if isinstance(record, dict) and isinstance(record.get("Properties"), dict):
                    self._consume_entity(entity_type, record["Properties"], observations)
                else:
                    self._consume_entity(entity_type, record, observations)

        if any(name in data for name in ("source", "target", "relationship", "edges")):
            self._consume_record(data, observations, findings)

    def _consume_record(
        self,
        record: Any,
        observations: list[ParsedObservation],
        findings: list[ParsedFinding],
    ) -> None:
        """Consume one unknown BloodHound record."""

        if not isinstance(record, dict):
            return

        if "edges" in record or "path" in record or record.get("kind") == "ad_path":
            self._consume_path(record, observations, findings)
            return

        if any(key in record for key in ("relationship", "edge_type", "rightname", "source", "target")):
            self._consume_relationship(record, observations, findings)
            return

        if any(key in record for key in ("name", "objectid", "object_id")):
            self._consume_entity(record.get("type", "entity"), record, observations)

    def _consume_relationship(
        self,
        record: Any,
        observations: list[ParsedObservation],
        findings: list[ParsedFinding],
    ) -> None:
        """Consume AD relationship record."""

        if not isinstance(record, dict):
            return

        source = record.get("source") or record.get("start") or record.get("principal") or record.get("from")
        target = record.get("target") or record.get("end") or record.get("object") or record.get("to")
        relationship = (
            record.get("relationship")
            or record.get("edge_type")
            or record.get("rightname")
            or record.get("label")
            or "Relationship"
        )

        if not source and isinstance(record.get("source_node"), dict):
            source = record["source_node"].get("name")
        if not target and isinstance(record.get("target_node"), dict):
            target = record["target_node"].get("name")

        if not source or not target:
            return

        summary = f"{source} has {relationship} relationship to {target}."
        title = f"AD relationship: {source} -{relationship}-> {target}"
        severity = "high" if self._is_high_value_target(target) else "info"
        observations.append(
            ParsedObservation(
                kind="note",
                summary=summary,
                source_tool=self.source_tool,
                data={
                    "title": title,
                    "detail": summary,
                    "severity": severity,
                    "metadata": {
                        "source": source,
                        "relationship": relationship,
                        "target": target,
                        "observation_type": "ad_relationship",
                    },
                },
                metadata={"relationship": relationship},
            )
        )

        finding = self._finding_for_relationship(source, relationship, target, record)
        if finding:
            findings.append(finding)

    def _consume_path(
        self,
        record: Any,
        observations: list[ParsedObservation],
        findings: list[ParsedFinding],
    ) -> None:
        """Consume AD attack path record."""

        if not isinstance(record, dict):
            return

        edges = record.get("edges") or record.get("path") or []
        source = record.get("source") or record.get("start") or self._path_endpoint(edges, first=True)
        target = record.get("target") or record.get("end") or self._path_endpoint(edges, first=False)
        path_length = record.get("path_length") or record.get("length") or (len(edges) if isinstance(edges, list) else None)

        if not source and not target and not edges:
            return

        summary = f"AD attack path found from {source or 'unknown source'} to {target or 'unknown target'}."
        title = f"AD attack path: {source or 'unknown'} -> {target or 'unknown'}"
        observations.append(
            ParsedObservation(
                kind="note",
                summary=summary,
                source_tool=self.source_tool,
                data={
                    "title": title,
                    "detail": summary,
                    "severity": "high" if self._is_high_value_target(target) else "medium",
                    "metadata": {
                        "source": source,
                        "target": target,
                        "path_length": path_length,
                        "observation_type": "ad_path",
                    },
                },
                metadata={"path_length": path_length},
            )
        )

        if self._is_high_value_target(target):
            findings.append(
                ParsedFinding(
                    title=f"Attack path to high-value AD target: {target}",
                    severity=ParserSeverity.HIGH,
                    description=summary,
                    source_tool=self.source_tool,
                    evidence={
                        "source": source,
                        "target": target,
                        "path_length": path_length,
                        "edges": edges,
                    },
                    metadata={"finding_type": "ad_attack_path"},
                )
            )

    def _consume_entity(
        self,
        entity_type: str,
        record: Any,
        observations: list[ParsedObservation],
    ) -> None:
        """Consume AD entity record."""

        if not isinstance(record, dict):
            return

        name = record.get("name") or record.get("Name") or record.get("objectid") or record.get("object_id")
        if not name:
            return

        name = str(name).strip()
        summary = f"BloodHound entity discovered: {entity_type} {name}."
        entity_metadata = {"entity_type": entity_type, "objectid": record.get("objectid")}

        if entity_type == "user":
            # SharpHound names are UPN-ish: "JDOE@LAB.LOCAL".
            account, _, domain = name.partition("@")
            observations.append(
                ParsedObservation(
                    kind="account",
                    summary=summary,
                    source_tool=self.source_tool,
                    data={
                        "username": account.lower() or name.lower(),
                        "domain": (domain or record.get("domain") or None) or None,
                        "source": "bloodhound",
                        "enabled": bool(record.get("enabled", True)),
                        "metadata": entity_metadata,
                    },
                    metadata={"entity_type": entity_type},
                )
            )
            return

        if entity_type == "computer":
            observations.append(
                ParsedObservation(
                    kind="host",
                    summary=summary,
                    source_tool=self.source_tool,
                    data={
                        "address": name.lower(),
                        "hostnames": [name.lower()],
                        "os": record.get("operatingsystem") or record.get("os"),
                        "metadata": entity_metadata,
                    },
                    metadata={"entity_type": entity_type},
                )
            )
            return

        # Groups, domains, OUs, GPOs: structural context, not a state primitive.
        observations.append(
            ParsedObservation(
                kind="note",
                summary=summary,
                source_tool=self.source_tool,
                data={
                    "title": f"AD {entity_type}: {name}",
                    "detail": summary,
                    "severity": "info",
                    "metadata": {**entity_metadata, "observation_type": "ad_entity"},
                },
                metadata={"entity_type": entity_type},
            )
        )

    def _finding_for_relationship(
        self,
        source: Any,
        relationship: Any,
        target: Any,
        raw: dict[str, Any],
    ) -> ParsedFinding | None:
        """Return finding for high-risk AD relationship."""

        relationship_text = str(relationship).lower()
        target_text = str(target).lower()

        high_risk_relationships = {
            "genericall",
            "genericwrite",
            "ownsdacl",
            "writeowner",
            "addmember",
            "adminips",
            "adminto",
            "canrdp",
            "hasession",
        }

        if relationship_text not in high_risk_relationships and not self._is_high_value_target(target_text):
            return None

        severity = ParserSeverity.HIGH if self._is_high_value_target(target_text) else ParserSeverity.MEDIUM

        return ParsedFinding(
            title=f"High-risk AD relationship: {source} -> {relationship} -> {target}",
            severity=severity,
            description=f"{source} has {relationship} relationship to {target}.",
            source_tool=self.source_tool,
            evidence={
                "source": source,
                "relationship": relationship,
                "target": target,
                "raw": raw,
            },
            metadata={"finding_type": "ad_relationship"},
        )

    @staticmethod
    def _is_high_value_target(target: Any) -> bool:
        """Return whether target appears high value."""

        if not target:
            return False

        text = str(target).lower()
        high_value_terms = [
            "domain admin",
            "domain admins",
            "enterprise admin",
            "enterprise admins",
            "administrator",
            "dc",
            "domain controller",
            "tier 0",
        ]
        return any(term in text for term in high_value_terms)

    @staticmethod
    def _path_endpoint(edges: Any, first: bool) -> Any:
        """Best-effort path endpoint extraction."""

        if not isinstance(edges, list) or not edges:
            return None

        edge = edges[0] if first else edges[-1]
        if not isinstance(edge, dict):
            return None

        if first:
            return edge.get("source") or edge.get("start") or edge.get("from")
        return edge.get("target") or edge.get("end") or edge.get("to")
