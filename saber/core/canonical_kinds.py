"""The fixed canonical observation-kind vocabulary (spec §3.2)."""

from __future__ import annotations

CANONICAL_KINDS: frozenset[str] = frozenset({
    "host", "service", "technology", "credential", "vuln",
    "share", "account", "session", "loot", "flag", "note",
})
