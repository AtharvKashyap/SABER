"""Nuclei output parser for SABER."""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedFinding, ParsedObservation, ParserResult, ParserSeverity


class NucleiParser(BaseParser):
    """Parse Nuclei JSON/JSONL output into vulnerability findings."""

    source_tool = "nuclei"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse Nuclei JSON, JSONL, or simple stdout."""

        stripped = text.strip()
        if not stripped:
            return ParserResult(source_tool=self.source_tool, success=False, errors=["Nuclei output is empty."])

        parsed = self.safe_json_loads(stripped)
        if parsed is not None:
            return self.parse_json(parsed)

        objects, errors = self.parse_json_lines(stripped)
        if objects:
            result = self.parse_json(objects)
            return ParserResult(
                source_tool=result.source_tool,
                success=result.success,
                observations=result.observations,
                findings=result.findings,
                errors=errors,
                metadata={**result.metadata, "format": "jsonl"},
            )

        return self._parse_stdout(stripped, errors)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse Nuclei JSON-compatible output."""

        records = data if isinstance(data, list) else [data]
        observations: list[ParsedObservation] = []
        findings: list[ParsedFinding] = []

        for record in records:
            if not isinstance(record, dict):
                continue

            finding = self._finding_from_record(record)
            if finding:
                findings.append(finding)
                observations.append(
                    ParsedObservation(
                        kind="vulnerability",
                        summary=f"{finding.title} matched with {finding.severity.value} severity.",
                        source_tool=self.source_tool,
                        data=finding.evidence,
                        metadata={"finding_title": finding.title, "severity": finding.severity.value},
                    )
                )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(findings or observations),
            observations=observations,
            findings=findings,
            errors=[] if findings else ["No Nuclei findings could be parsed."],
            metadata={"format": "json", "finding_count": len(findings)},
        )

    def _parse_stdout(self, text: str, errors: list[str] | None = None) -> ParserResult:
        """Parse simple Nuclei stdout fallback."""

        observations: list[ParsedObservation] = []
        findings: list[ParsedFinding] = []

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Common format:
            # [template-id] [protocol] [severity] target
            parts = line.split()
            if len(parts) < 3:
                continue

            template_id = parts[0].strip("[]")
            severity_raw = parts[2].strip("[]") if len(parts) > 2 else "unknown"
            matched_at = parts[-1]
            severity = self.severity_from_string(severity_raw)

            finding = ParsedFinding(
                title=template_id,
                severity=severity,
                description=f"Nuclei matched template {template_id} against {matched_at}.",
                source_tool=self.source_tool,
                evidence={
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "raw": line,
                },
                metadata={"format": "stdout"},
            )
            findings.append(finding)
            observations.append(
                ParsedObservation(
                    kind="vulnerability",
                    summary=f"Nuclei matched {template_id} against {matched_at}.",
                    source_tool=self.source_tool,
                    data=finding.evidence,
                    metadata={"severity": severity.value},
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(findings),
            observations=observations,
            findings=findings,
            errors=[] if findings else (errors or ["No Nuclei stdout findings could be parsed."]),
            metadata={"format": "stdout", "finding_count": len(findings)},
        )

    def _finding_from_record(self, record: dict[str, Any]) -> ParsedFinding | None:
        """Build finding from one Nuclei record."""

        info = record.get("info") or {}
        template_id = record.get("template-id") or record.get("template_id") or record.get("id")
        name = info.get("name") or record.get("name") or template_id
        severity = self.severity_from_string(info.get("severity") or record.get("severity"))
        matched_at = record.get("matched-at") or record.get("matched_at") or record.get("host") or record.get("url")
        description = info.get("description") or f"Nuclei matched template {template_id} against {matched_at}."
        references = self._references(info)

        if not name and not template_id:
            return None

        return ParsedFinding(
            title=str(name),
            severity=severity,
            description=str(description),
            source_tool=self.source_tool,
            evidence={
                "template_id": template_id,
                "matched_at": matched_at,
                "matcher_name": record.get("matcher-name") or record.get("matcher_name"),
                "type": record.get("type"),
                "host": record.get("host"),
                "ip": record.get("ip"),
                "port": record.get("port"),
                "raw": record,
            },
            references=references,
            metadata={
                "classification": info.get("classification", {}),
                "tags": info.get("tags"),
            },
        )

    @staticmethod
    def _references(info: dict[str, Any]) -> list[str]:
        """Extract references from Nuclei info."""

        references = info.get("reference") or info.get("references") or []
        if isinstance(references, str):
            return [references]
        if isinstance(references, list):
            return [str(reference) for reference in references]
        return []
