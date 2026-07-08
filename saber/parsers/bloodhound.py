"""BloodHound output parser for SABER."""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedFinding, ParsedObservation, ParserResult, ParserSeverity


class BloodHoundParser(BaseParser):
    """Parse BloodHound/SharpHound-like JSON into AD observations and findings."""

    source_tool = "bloodhound"

    def parse_text(self, text: str) -> ParserResult:
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

    def parse_json(self, data: dict[str, Any] | list[Any]) -> ParserResult:
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
        observations.append(
            ParsedObservation(
                kind="ad_relationship",
                summary=summary,
                source_tool=self.source_tool,
                data={
                    "source": source,
                    "relationship": relationship,
                    "target": target,
                    "raw": record,
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
        observations.append(
            ParsedObservation(
                kind="ad_path",
                summary=summary,
                source_tool=self.source_tool,
                data={
                    "source": source,
                    "target": target,
                    "path_length": path_length,
                    "edges": edges,
                    "raw": record,
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

        observations.append(
            ParsedObservation(
                kind="ad_entity",
                summary=f"BloodHound entity discovered: {entity_type} {name}.",
                source_tool=self.source_tool,
                data={
                    "entity_type": entity_type,
                    "name": name,
                    "raw": record,
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
