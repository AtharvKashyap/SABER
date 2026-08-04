"""`file` output parser for SABER.

Emits one ``kind="note"`` per identified file: ``title`` embeds the path (the
note merger dedupes on title) and ``detail`` is the type description. Severity is
raised for artifacts worth attacking next — ELF/PE executables and setuid
binaries — so the decider can tell a promising target from a text file.

Handles all three shapes the wrapper produces: ``file <path>`` ("path: desc"),
``file -b`` (bare description, path recovered from metadata), and the
directory walk (many "path: desc" lines).
"""

from __future__ import annotations

from typing import Any

from saber.parsers.base import BaseParser, ParsedObservation, ParserResult

# Type fragments that mean "this is worth looking at next".
_EXECUTABLE_HINTS = (
    "elf ",
    "pe32",
    "pe32+",
    "mach-o",
    "executable",
    "shared object",
)
_ARCHIVE_HINTS = ("archive", "compressed", "zip", "gzip", "tar")


class FileParser(BaseParser):
    """Parse `file` output into canonical note observations."""

    source_tool = "file"

    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse `file` stdout in any of its three shapes."""

        stripped = (text or "").strip()
        if not stripped:
            return ParserResult(
                source_tool=self.source_tool,
                success=False,
                errors=["file output is empty."],
            )

        fallback_path = str((metadata or {}).get("file_path") or "").strip()

        observations: list[ParsedObservation] = []
        seen: set[str] = set()

        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            path, description = self._split(line, fallback_path)
            if not description:
                continue
            title = f"File type: {path}"
            if title in seen:
                continue
            seen.add(title)

            observations.append(
                ParsedObservation(
                    kind="note",
                    summary=f"{path}: {description}",
                    source_tool=self.source_tool,
                    data={
                        "title": title,
                        "detail": description,
                        "severity": self._severity_for(description),
                        "metadata": {
                            "path": path,
                            "file_type": description,
                            "executable": self._matches(description, _EXECUTABLE_HINTS),
                            "archive": self._matches(description, _ARCHIVE_HINTS),
                        },
                    },
                )
            )

        return ParserResult(
            source_tool=self.source_tool,
            success=bool(observations),
            observations=observations,
            errors=[] if observations else ["No file identifications could be parsed."],
            metadata={"format": "stdout", "file_count": len(observations)},
        )

    @staticmethod
    def _split(line: str, fallback_path: str) -> tuple[str, str]:
        """Split a `file` line into (path, description).

        ``file -b`` prints only the description, so the path comes from the
        metadata the executor threaded through.
        """

        # A description can itself contain ": ", so split on the FIRST colon only,
        # and only treat it as a path when it looks like one.
        if ": " in line:
            candidate, _, description = line.partition(": ")
            if candidate and not candidate.endswith(","):
                return candidate.strip(), description.strip()
        return (fallback_path or "unknown file"), line

    @staticmethod
    def _matches(description: str, hints: tuple[str, ...]) -> bool:
        lowered = description.lower()
        return any(hint in lowered for hint in hints)

    def _severity_for(self, description: str) -> str:
        """Executables and setuid artifacts are the ones worth pursuing."""

        lowered = description.lower()
        if "setuid" in lowered:
            return "high"
        if self._matches(description, _EXECUTABLE_HINTS):
            return "medium"
        if self._matches(description, _ARCHIVE_HINTS):
            return "low"
        return "info"
