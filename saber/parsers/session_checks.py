"""Lateral movement session-check output parser for SABER.

``validate_session`` is the one action that may evidence a genuinely live
interactive foothold: it re-confirms an *already claimed* session/access
record is still usable, which is exactly what ``KnownSession`` models. It only
emits ``kind="session"`` when the record comes back valid; an invalid/stale
session is recorded as a note only, never fabricated as live.

``summarize_sessions`` and ``authenticated_reachability`` never emit
``kind="session"``: the former is a local summary of records that may already
be stale, and the latter only proves network+credential reachability, not an
interactive foothold. Both degrade to ``kind="note"``.
"""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

_PROTOCOL_TO_SESSION_KIND = {
    "ssh": "ssh",
    "winrm": "winrm",
    "meterpreter": "meterpreter",
    "shell": "shell",
}


class SessionChecksParser(BaseParser):
    """Parse lateral_movement.session_checks JSON output into canonical observations."""

    source_tool = "session_checks"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse stdout, delegating to JSON parsing when the text is valid JSON."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Session check output is empty."],
            )

        data = self.safe_json_loads(stripped)
        if data is None:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Session check output is not valid JSON."],
            )
        return self.parse_json(data, metadata=metadata)

    def parse_json(
        self,
        data: dict[str, Any] | list[Any],
        metadata: dict[str, Any] | None = None,
    ) -> ParserResult:
        """Parse a validate-session/summarize-sessions/authenticated-reachability payload."""

        if not isinstance(data, dict):
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["Session check output is not a JSON object."],
            )

        observations: list[ParsedObservation] = []
        action = str(data.get("action") or "")

        if action == "validate_session" or "session_id" in data:
            observations.extend(self._validate_session_observations(data))
        elif action == "summarize_sessions" or isinstance(data.get("sessions"), list):
            observations.extend(self._summarize_sessions_notes(data))
        elif action == "authenticated_reachability" or "reachable" in data:
            observations.extend(self._authenticated_reachability_notes(data))

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No session check result could be parsed."],
            metadata={"observation_count": len(observations)},
        )

    def _validate_session_observations(self, data: dict[str, Any]) -> list[ParsedObservation]:
        session_id = str(data.get("session_id") or "").strip()
        host = str(data.get("host") or "").strip()
        if not session_id:
            return []
        valid = bool(data.get("valid"))
        protocol = str(data.get("protocol") or "shell").strip().lower()
        user = data.get("user")
        privilege = str(data.get("privilege") or "user")

        title = (
            f"Session {session_id} validated as live"
            if valid
            else f"Session {session_id} is no longer valid"
        )
        observations: list[ParsedObservation] = [
            ParsedObservation(
                kind="note",
                summary=title,
                source_tool=self.source_tool,
                data={
                    "title": title,
                    "detail": f"Protocol {protocol}, host {host or 'unknown'}.",
                    "severity": "info" if valid else "medium",
                    "metadata": {
                        "session_id": session_id,
                        "host": host,
                        "protocol": protocol,
                        "valid": valid,
                    },
                },
            )
        ]

        # Only a *validated* session on a known host is real evidence of a live
        # interactive foothold. Do not fabricate a session for an invalid record
        # or when the host is missing (KnownSession.host is required).
        if valid and host:
            observations.append(
                ParsedObservation(
                    kind="session",
                    summary=f"Validated live session on {host}",
                    source_tool=self.source_tool,
                    data={
                        "host": host,
                        "kind": _PROTOCOL_TO_SESSION_KIND.get(protocol, "shell"),
                        "user": user,
                        "privilege": privilege,
                        "ref": session_id,
                    },
                )
            )
        return observations

    def _summarize_sessions_notes(self, data: dict[str, Any]) -> list[ParsedObservation]:
        notes: list[ParsedObservation] = []
        for entry in data.get("sessions") or []:
            if not isinstance(entry, dict):
                continue
            session_id = str(entry.get("session_id") or "").strip()
            host = str(entry.get("host") or "").strip()
            if not session_id:
                continue
            status = str(entry.get("status") or "unknown")
            protocol = str(entry.get("protocol") or "unknown")
            title = f"Known session {session_id} on {host or 'unknown host'} ({status})"
            notes.append(
                ParsedObservation(
                    kind="note",
                    summary=title,
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": f"Protocol {protocol}, status {status}.",
                        "severity": "info" if status == "active" else "low",
                        "metadata": {
                            "session_id": session_id,
                            "host": host,
                            "protocol": protocol,
                            "status": status,
                        },
                    },
                )
            )
        return notes

    def _authenticated_reachability_notes(self, data: dict[str, Any]) -> list[ParsedObservation]:
        source = str(data.get("source") or "").strip()
        destination = str(data.get("target") or "").strip()
        if not source or not destination:
            return []
        reachable = bool(data.get("reachable"))
        protocol = str(data.get("protocol") or "unknown")
        detail = str(data.get("detail") or "")
        title = (
            f"Authenticated reachability confirmed: {source} -> {destination} ({protocol})"
            if reachable
            else f"Authenticated reachability failed: {source} -> {destination} ({protocol})"
        )
        return [
            ParsedObservation(
                kind="note",
                summary=title,
                source_tool=self.source_tool,
                data={
                    "title": title,
                    "detail": detail,
                    "severity": "medium" if reachable else "info",
                    "metadata": {
                        "source": source,
                        "target": destination,
                        "protocol": protocol,
                        "reachable": reachable,
                        "credential_ref": data.get("credential_ref"),
                    },
                },
            )
        ]
