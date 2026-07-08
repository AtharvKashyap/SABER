"""Tool result processing for SABER.

The result processor is the bridge between tool execution and persisted mission
state.

It saves raw evidence, dispatches parser output through ParserRegistry, persists
findings/observations, and stores graph data when parser observations contain AD
graph facts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.parsers.registry import ParserRegistry, build_default_parser_registry
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.graph_store import GraphStore


@dataclass(frozen=True)
class ProcessedToolResult:
    """Summary of persisted tool result processing."""

    session_id: str
    step_id: str | None
    tool_name: str
    parser_used: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    graph_updates: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible processing summary."""

        return {
            "session_id": self.session_id,
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "parser_used": self.parser_used,
            "evidence_ids": self.evidence_ids,
            "finding_ids": self.finding_ids,
            "observation_ids": self.observation_ids,
            "graph_updates": self.graph_updates,
            "errors": self.errors,
        }


class ResultProcessor:
    """Persist and parse tool results."""

    def __init__(
        self,
        evidence_index: EvidenceIndex,
        finding_store: FindingStore,
        graph_store: GraphStore,
        parser_registry: ParserRegistry | None = None,
        evidence_root: str | Path = "runs/evidence",
    ) -> None:
        """Initialize processor."""

        self.evidence_index = evidence_index
        self.finding_store = finding_store
        self.graph_store = graph_store
        self.parser_registry = parser_registry or build_default_parser_registry()
        self.evidence_root = Path(evidence_root)

    def process_tool_result(
        self,
        session_id: str,
        tool_result: Any,
        step_id: str | None = None,
        tool_name: str | None = None,
        action: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProcessedToolResult:
        """Process one tool result.

        This method is intentionally tolerant of different ToolResult shapes.
        It supports SABER ToolResult objects, dictionaries, and simple fake test
        objects.
        """

        metadata = dict(metadata or {})
        inferred_tool = tool_name or self._get(tool_result, "tool_name") or self._get(tool_result, "tool") or "unknown"
        inferred_action = action or self._get(tool_result, "action") or self._get(tool_result, "command") or "run"

        evidence_ids: list[str] = []
        finding_ids: list[str] = []
        observation_ids: list[str] = []
        errors: list[str] = []
        parser_used: str | None = None
        graph_updates = 0

        raw_outputs = self._extract_outputs(tool_result)
        evidence_metadata = {
            **metadata,
            "tool_result_status": self._stringify(self._get(tool_result, "status")),
            "command": self._stringify(self._get(tool_result, "command")),
        }

        for output_name, output_value in raw_outputs.items():
            if output_value is None or output_value == "":
                continue

            try:
                evidence_path = self._write_output_file(
                    session_id=session_id,
                    step_id=step_id,
                    tool_name=str(inferred_tool),
                    output_name=output_name,
                    output_value=output_value,
                )
                evidence_id = self.evidence_index.add_evidence(
                    session_id=session_id,
                    step_id=step_id,
                    tool_name=str(inferred_tool),
                    action=str(inferred_action),
                    title=f"{inferred_tool} {output_name}",
                    path=evidence_path,
                    metadata=evidence_metadata,
                )
                evidence_ids.append(evidence_id)
            except Exception as exc:
                errors.append(f"evidence:{output_name}:{type(exc).__name__}: {exc}")

        parse_metadata = {
            **metadata,
            "session_id": session_id,
            "step_id": step_id,
            "tool_name": str(inferred_tool),
            "action": str(inferred_action),
            "evidence_ids": evidence_ids,
        }

        dispatch = self._parse_outputs(
            tool_name=str(inferred_tool),
            tool_result=tool_result,
            raw_outputs=raw_outputs,
            metadata=parse_metadata,
        )

        parser_used = dispatch.get("parser_used")
        errors.extend(dispatch.get("errors", []))

        parser_result = dispatch.get("result")
        if parser_result is not None:
            for observation in getattr(parser_result, "observations", []) or []:
                try:
                    observation_id = self.finding_store.save_observation(
                        session_id=session_id,
                        observation=observation,
                        step_id=step_id,
                        evidence_id=evidence_ids[0] if evidence_ids else None,
                    )
                    observation_ids.append(observation_id)

                    if self.graph_store.save_from_observation(session_id, observation):
                        graph_updates += 1
                except Exception as exc:
                    errors.append(f"observation:{type(exc).__name__}: {exc}")

            for finding in getattr(parser_result, "findings", []) or []:
                try:
                    finding_id = self.finding_store.save_finding(
                        session_id=session_id,
                        finding=finding,
                        step_id=step_id,
                        evidence_id=evidence_ids[0] if evidence_ids else None,
                    )
                    finding_ids.append(finding_id)
                except Exception as exc:
                    errors.append(f"finding:{type(exc).__name__}: {exc}")

        return ProcessedToolResult(
            session_id=session_id,
            step_id=step_id,
            tool_name=str(inferred_tool),
            parser_used=parser_used,
            evidence_ids=evidence_ids,
            finding_ids=finding_ids,
            observation_ids=observation_ids,
            graph_updates=graph_updates,
            errors=errors,
        )

    def process_evidence_file(
        self,
        *,
        session_id: str,
        path: str | Path,
        tool_name: str,
        step_id: str | None = None,
        action: str | None = None,
        evidence_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProcessedToolResult:
        """Parse an already-indexed evidence file and persist parsed output.

        This is used when Sandbox/EvidenceStore already saved a file and
        Storage/EvidenceIndex already indexed it. Unlike process_tool_result(),
        this method does not write duplicate raw evidence files.
        """

        errors: list[str] = []
        finding_ids: list[str] = []
        observation_ids: list[str] = []
        graph_updates = 0

        parse_metadata = {
            **(metadata or {}),
            "session_id": session_id,
            "step_id": step_id,
            "tool_name": tool_name,
            "action": action,
            "evidence_id": evidence_id,
            "path": str(path),
        }

        dispatch = self.parser_registry.parse_file(
            tool_name=tool_name,
            path=path,
            metadata=parse_metadata,
        )

        parser_used = dispatch.parser_used
        errors.extend(dispatch.errors)

        parser_result = dispatch.result
        if parser_result is not None:
            for observation in getattr(parser_result, "observations", []) or []:
                try:
                    observation_id = self.finding_store.save_observation(
                        session_id=session_id,
                        observation=observation,
                        step_id=step_id,
                        evidence_id=evidence_id,
                    )
                    observation_ids.append(observation_id)

                    if self.graph_store.save_from_observation(session_id, observation):
                        graph_updates += 1
                except Exception as exc:
                    errors.append(f"observation:{type(exc).__name__}: {exc}")

            for finding in getattr(parser_result, "findings", []) or []:
                try:
                    finding_id = self.finding_store.save_finding(
                        session_id=session_id,
                        finding=finding,
                        step_id=step_id,
                        evidence_id=evidence_id,
                    )
                    finding_ids.append(finding_id)
                except Exception as exc:
                    errors.append(f"finding:{type(exc).__name__}: {exc}")

        return ProcessedToolResult(
            session_id=session_id,
            step_id=step_id,
            tool_name=tool_name,
            parser_used=parser_used,
            evidence_ids=[evidence_id] if evidence_id else [],
            finding_ids=finding_ids,
            observation_ids=observation_ids,
            graph_updates=graph_updates,
            errors=errors,
        )

    def process_many(
        self,
        session_id: str,
        tool_results: list[Any],
        step_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> list[ProcessedToolResult]:
        """Process multiple tool results."""

        return [
            self.process_tool_result(
                session_id=session_id,
                tool_result=tool_result,
                step_id=step_id,
                metadata=metadata,
            )
            for tool_result in tool_results
        ]

    def _parse_outputs(
        self,
        tool_name: str,
        tool_result: Any,
        raw_outputs: dict[str, Any],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Parse the best available output."""

        result_json = self._get(tool_result, "json")
        if result_json is None:
            result_json = self._get(tool_result, "json_output")
        if result_json is None:
            result_json = self._get(tool_result, "parsed_json")

        if result_json is not None:
            dispatch = self.parser_registry.parse_json(tool_name, result_json, metadata=metadata)
            return {
                "parser_used": dispatch.parser_used,
                "result": dispatch.result,
                "errors": dispatch.errors,
            }

        stdout = raw_outputs.get("stdout")
        if stdout:
            dispatch = self.parser_registry.parse_text(tool_name, str(stdout), metadata=metadata)
            return {
                "parser_used": dispatch.parser_used,
                "result": dispatch.result,
                "errors": dispatch.errors,
            }

        output = raw_outputs.get("output")
        if output:
            dispatch = self.parser_registry.parse_text(tool_name, str(output), metadata=metadata)
            return {
                "parser_used": dispatch.parser_used,
                "result": dispatch.result,
                "errors": dispatch.errors,
            }

        output_path = self._get(tool_result, "output_path") or self._get(tool_result, "path")
        if output_path:
            dispatch = self.parser_registry.parse_file(tool_name, output_path, metadata=metadata)
            return {
                "parser_used": dispatch.parser_used,
                "result": dispatch.result,
                "errors": dispatch.errors,
            }

        return {
            "parser_used": None,
            "result": None,
            "errors": [f"No parseable output found for tool: {tool_name}"],
        }

    def _extract_outputs(self, tool_result: Any) -> dict[str, Any]:
        """Extract raw outputs from flexible tool result shapes."""

        outputs: dict[str, Any] = {}

        for key in ("stdout", "stderr", "output"):
            value = self._get(tool_result, key)
            if value is not None:
                outputs[key] = value

        if "output" not in outputs:
            result = self._get(tool_result, "result")
            if result is not None:
                outputs["output"] = result

        json_payload = self._get(tool_result, "json") or self._get(tool_result, "json_output") or self._get(tool_result, "parsed_json")
        if json_payload is not None:
            outputs["json"] = json_payload

        if not outputs:
            outputs["tool_result"] = self._serialize(tool_result)

        return outputs

    def _write_output_file(
        self,
        session_id: str,
        step_id: str | None,
        tool_name: str,
        output_name: str,
        output_value: Any,
    ) -> Path:
        """Write raw output to an evidence file."""

        safe_tool = self._safe_name(tool_name)
        safe_step = self._safe_name(step_id or "no_step")
        safe_output = self._safe_name(output_name)

        session_dir = self.evidence_root / self._safe_name(session_id) / safe_step
        session_dir.mkdir(parents=True, exist_ok=True)

        suffix = "json" if isinstance(output_value, (dict, list)) or output_name == "json" else "txt"
        path = session_dir / f"{safe_tool}_{safe_output}.{suffix}"

        if isinstance(output_value, (dict, list)):
            path.write_text(json.dumps(output_value, indent=2, sort_keys=True, default=str), encoding="utf-8")
        else:
            path.write_text(str(output_value), encoding="utf-8")

        return path

    @staticmethod
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        """Get key/attribute from flexible object."""

        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _safe_name(value: Any) -> str:
        """Make filesystem-safe name."""

        text = str(value or "unknown")
        safe = "".join(character if character.isalnum() or character in {"_", "-"} else "_" for character in text)
        return safe.strip("_") or "unknown"

    @staticmethod
    def _serialize(value: Any) -> str:
        """Serialize arbitrary value safely for evidence."""

        if isinstance(value, str):
            return value

        if isinstance(value, (dict, list, tuple, int, float, bool)) or value is None:
            return json.dumps(value, indent=2, sort_keys=True, default=str)

        if hasattr(value, "to_dict"):
            return json.dumps(value.to_dict(), indent=2, sort_keys=True, default=str)

        if hasattr(value, "model_dump"):
            return json.dumps(value.model_dump(mode="json"), indent=2, sort_keys=True, default=str)

        return str(value)

    @staticmethod
    def _stringify(value: Any) -> str | None:
        """Stringify optional metadata value."""

        if value is None:
            return None
        return str(value)
