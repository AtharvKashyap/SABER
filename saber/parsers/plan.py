"""Lateral movement planner output parser for SABER.

The planner reasons over already-known state (hosts/services/credentials) and
never touches a remote host, so it never evidences a host/service/session --
it only records what was reasoned about. Every observation is therefore
``kind="note"`` (spec §4-Pillar-3: state must still grow even for pure local
reasoning steps).
"""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class PlanParser(BaseParser):
    """Parse lateral_movement.plan JSON output into canonical note observations."""

    source_tool = "plan"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse stdout, delegating to JSON parsing when the text is valid JSON."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Plan output is empty."],
            )

        data = self.safe_json_loads(stripped)
        if data is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Plan output is not valid JSON."],
            )
        return self.parse_json(data, metadata=metadata)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse a plan-paths/rank-paths/export-plan JSON payload."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Plan output is not a JSON object."],
            )

        observations: list[ParsedObservation] = []

        if isinstance(data.get("paths"), list):
            observations.extend(self._plan_paths_notes(data))
        elif isinstance(data.get("ranked"), list):
            observations.extend(self._rank_paths_notes(data))
        elif "exported_path" in data or "plan_id" in data:
            observations.extend(self._export_plan_notes(data))

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No lateral movement plan data could be parsed."],
            metadata={"note_count": len(observations)},
        )

    def _plan_paths_notes(self, data: dict[str, Any]) -> list[ParsedObservation]:
        source = str(data.get("source") or "").strip()
        destination = str(data.get("target") or "").strip()
        notes: list[ParsedObservation] = []
        for entry in data.get("paths") or []:
            if not isinstance(entry, dict):
                continue
            path_id = str(entry.get("path_id") or "").strip()
            hops = [str(hop) for hop in (entry.get("hops") or [])]
            if not path_id or not hops:
                continue
            technique = str(entry.get("technique") or "unknown")
            risk = str(entry.get("risk") or "info")
            title = f"Lateral movement path planned: {path_id} ({' -> '.join(hops)})"
            notes.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": (
                            f"Candidate path from {source or hops[0]} to "
                            f"{destination or hops[-1]} via {technique}."
                        ),
                        "severity": self.severity_from_string(risk).value,
                        "metadata": {
                            "path_id": path_id,
                            "hops": hops,
                            "technique": technique,
                            "risk": risk,
                        },
                    },
                )
            )
        return notes

    def _rank_paths_notes(self, data: dict[str, Any]) -> list[ParsedObservation]:
        criteria = str(data.get("criteria") or "unknown")
        notes: list[ParsedObservation] = []
        for entry in data.get("ranked") or []:
            if not isinstance(entry, dict):
                continue
            path_id = str(entry.get("path_id") or "").strip()
            rank = entry.get("rank")
            if not path_id or rank is None:
                continue
            score = entry.get("score")
            title = f"Path {path_id} ranked #{rank} by {criteria}"
            notes.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": f"Ranking score {score} using criteria '{criteria}'.",
                        "severity": "info",
                        "metadata": {
                            "path_id": path_id,
                            "rank": rank,
                            "score": score,
                            "criteria": criteria,
                        },
                    },
                )
            )
        return notes

    def _export_plan_notes(self, data: dict[str, Any]) -> list[ParsedObservation]:
        plan_id = str(data.get("plan_id") or "").strip()
        if not plan_id:
            return []
        output_format = str(data.get("format") or "json")
        exported_path = data.get("exported_path")
        path_count = data.get("path_count")
        title = f"Lateral movement plan exported: {plan_id}"
        return [
            ParsedObservation(
                kind="note",
                summary=title,
                source_tool=self.source_tool,
                data={
                    "title": title,
                    "detail": (
                        f"Plan {plan_id} exported as {output_format} "
                        f"({path_count if path_count is not None else 'unknown'} path(s))"
                        f"{f' to {exported_path}' if exported_path else ''}."
                    ),
                    "severity": "info",
                    "metadata": {
                        "plan_id": plan_id,
                        "output_format": output_format,
                        "exported_path": exported_path,
                        "path_count": path_count,
                    },
                },
            )
        ]
