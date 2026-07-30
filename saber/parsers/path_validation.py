"""Lateral movement path-validation output parser for SABER.

Every action here reasons over (or, for ``dry_run_path``, lightly probes) a
candidate path and reports whether it holds up. None of it evidences a new
host/service/session -- it only records a validation verdict, so every
observation is ``kind="note"`` (state must still grow per spec §4-Pillar-3).
"""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult


class PathValidationParser(BaseParser):
    """Parse lateral_movement.path_validation JSON output into note observations."""

    source_tool = "path_validation"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse stdout, delegating to JSON parsing when the text is valid JSON."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Path validation output is empty."],
            )

        data = self.safe_json_loads(stripped)
        if data is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Path validation output is not valid JSON."],
            )
        return self.parse_json(data, metadata=metadata)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse a validate-step/validate-path/dry-run-path JSON payload."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Path validation output is not a JSON object."],
            )

        observation: ParsedObservation | None = None
        action = str(data.get("action") or "")

        if action == "validate_step" or ("technique" in data and "path_id" not in data):
            observation = self._validate_step_note(data)
        elif action == "dry_run_path" or "reachable_hops" in data:
            observation = self._dry_run_note(data)
        elif action == "validate_path" or "hops" in data:
            observation = self._validate_path_note(data)

        observations = [observation] if observation is not None else []
        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No path validation result could be parsed."],
            metadata={"note_count": len(observations)},
        )

    def _validate_step_note(self, data: dict[str, Any]) -> ParsedObservation | None:
        source = str(data.get("source") or "").strip()
        destination = str(data.get("target") or "").strip()
        technique = str(data.get("technique") or "").strip()
        if not source or not destination or not technique:
            return None
        valid = bool(data.get("valid"))
        reason = str(data.get("reason") or "")
        title = (
            f"Path step validated: {source} -> {destination} via {technique}"
            if valid
            else f"Path step invalid: {source} -> {destination} via {technique}"
        )
        return ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": reason,
                "severity": "info" if valid else "medium",
                "metadata": {
                    "source": source,
                    "target": destination,
                    "technique": technique,
                    "valid": valid,
                },
            },
        )

    def _validate_path_note(self, data: dict[str, Any]) -> ParsedObservation | None:
        path_id = str(data.get("path_id") or "").strip()
        hops = [str(hop) for hop in (data.get("hops") or [])]
        if not path_id or not hops:
            return None
        valid = bool(data.get("valid"))
        invalid_hops = [str(hop) for hop in (data.get("invalid_hops") or [])]
        title = f"Path {path_id} validated" if valid else f"Path {path_id} failed validation"
        detail = (
            f"All {len(hops)} hop(s) check out against known state."
            if valid
            else f"Invalid hop(s): {', '.join(invalid_hops) or 'unspecified'}."
        )
        return ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": detail,
                "severity": "info" if valid else "medium",
                "metadata": {"path_id": path_id, "hops": hops, "invalid_hops": invalid_hops},
            },
        )

    def _dry_run_note(self, data: dict[str, Any]) -> ParsedObservation | None:
        path_id = str(data.get("path_id") or "").strip()
        hops = [str(hop) for hop in (data.get("hops") or [])]
        if not path_id or not hops:
            return None
        reachable_hops = [str(hop) for hop in (data.get("reachable_hops") or [])]
        blocked_at = data.get("blocked_at")
        fully_reachable = not blocked_at and len(reachable_hops) == len(hops)
        title = (
            f"Path {path_id} dry run succeeded"
            if fully_reachable
            else f"Path {path_id} dry run blocked at {blocked_at or 'unknown hop'}"
        )
        detail = str(data.get("reason") or "")
        return ParsedObservation(
            kind="note",
            summary=title,
            source_tool=self.source_tool,
            data={
                "title": title,
                "detail": detail,
                "severity": "info" if fully_reachable else "high",
                "metadata": {
                    "path_id": path_id,
                    "hops": hops,
                    "reachable_hops": reachable_hops,
                    "blocked_at": blocked_at,
                },
            },
        )
