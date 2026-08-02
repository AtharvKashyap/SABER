"""Jinja environment and view-model helpers for the SABER operator console.

The console is server-rendered: FastAPI routes build a small, explicit view model
here and hand it to a template. HTML is never assembled in Python.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from saber.models.mission_state import MissionState, PtesPhase

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Statuses that mean the loop may still act, so the page keeps polling.
LIVE_STATUSES = frozenset({"running", "in_progress", "pending", "created", "started"})

_PHASE_LABELS: dict[PtesPhase, str] = {
    PtesPhase.PRE_ENGAGEMENT: "scope",
    PtesPhase.RECON: "recon",
    PtesPhase.VULN_ASSESSMENT: "assess",
    PtesPhase.EXPLOITATION: "exploit",
    PtesPhase.POST_EXPLOITATION: "post-ex",
    PtesPhase.LATERAL_MOVEMENT: "lateral",
    PtesPhase.PROOF_OF_CONCEPT: "proof",
    PtesPhase.POST_ENGAGEMENT: "wrap-up",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def badge(value: Any) -> Markup:
    """Render a status/severity pill.

    The CSS class is derived from the value so a new status degrades to the
    neutral pill rather than rendering unstyled.
    """

    text = str(value or "unknown").strip() or "unknown"
    slug = text.lower().replace(" ", "_").replace("-", "_")
    return Markup('<span class="badge badge-{}">{}</span>').format(slug, text)


def shortdate(value: Any) -> str:
    """Format a timestamp for a dense table cell."""

    if not value:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%d %b %H:%M")
    text = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).strftime("%d %b %H:%M")
        except ValueError:
            continue
    return text[:16]


def build_environment() -> Environment:
    """Return the console's Jinja environment."""

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["badge"] = badge
    env.filters["shortdate"] = shortdate
    return env


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Return severity counts in fixed severity order (zeros included)."""

    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        key = str(finding.get("severity") or "unknown").lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def phase_strip(state: MissionState | None) -> list[dict[str, Any]]:
    """Return the PTES phase strip with current/done flags."""

    ordered = PtesPhase.ordered()
    if state is None:
        return [{"label": _PHASE_LABELS[p], "current": False, "done": False} for p in ordered]

    try:
        index = ordered.index(state.current_phase)
    except ValueError:
        index = 0

    return [
        {"label": _PHASE_LABELS[phase], "current": position == index, "done": position < index}
        for position, phase in enumerate(ordered)
    ]


def state_ledger(state: MissionState | None) -> list[tuple[str, int]]:
    """Return the working-memory tally shown beside the mission timeline."""

    if state is None:
        return []
    return [
        ("Hosts", len(state.hosts)),
        ("Services", len(state.services)),
        ("Technologies", len(state.technologies)),
        ("Vulnerabilities", len(state.vulns)),
        ("Credentials", len(state.credentials)),
        ("Accounts", len(state.accounts)),
        ("Shares", len(state.shares)),
        ("Sessions", len(state.sessions)),
        ("Loot", len(state.loot)),
        ("Flags", len(state.flags)),
        ("Steps taken", state.step_count),
    ]


def _duration_text(seconds: float) -> str:
    """Render an elapsed time compactly."""

    if seconds < 1:
        return "<1s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def _gap_pixels(seconds: float) -> int:
    """Scale an elapsed time to spine rule length.

    Log-scaled and tightly bounded. A linear scale made a single slow scan
    dominate the timeline with dead space, which buried the thing the spine is
    for: reading many steps at a glance. This keeps the list dense while still
    making a long step visibly longer than a fast one.
    """

    if seconds <= 0:
        return 14
    return int(min(56, 14 + 12 * math.log10(1 + seconds)))


def build_spine(state: MissionState | None) -> list[dict[str, Any]]:
    """Return the loop timeline: one entry per action the loop took.

    Each entry carries the outcome, the arguments used, and how long the step
    took, so the operator can read the mission's rhythm top to bottom.
    """

    if state is None or not state.attempted_actions:
        return []

    actions = state.attempted_actions
    rows: list[dict[str, Any]] = []

    for position, action in enumerate(actions):
        reason = action.reason or ""
        refused = reason.startswith("refused:")

        if refused:
            outcome, css = "refused", "is-gated"
        elif action.success:
            outcome, css = "completed", ""
        else:
            outcome, css = "failed", "is-failed"

        seconds = 0.0
        if position + 1 < len(actions):
            later = actions[position + 1].at
            if later and action.at:
                seconds = max(0.0, (later - action.at).total_seconds())

        rows.append(
            {
                "index": position + 1,
                "tool": action.tool_name,
                "action": action.action,
                "outcome": outcome,
                "css": css,
                "reason": reason,
                "args": json.dumps(action.args, sort_keys=True, default=str) if action.args else "",
                "duration": _duration_text(seconds) if seconds else "",
                "gap_px": _gap_pixels(seconds),
            }
        )

    return rows


__all__ = [
    "LIVE_STATUSES",
    "STATIC_DIR",
    "TEMPLATE_DIR",
    "badge",
    "build_environment",
    "build_spine",
    "escape",
    "phase_strip",
    "severity_counts",
    "shortdate",
    "state_ledger",
]
