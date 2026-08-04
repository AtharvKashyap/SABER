"""Every action the rule ladder proposes must exist in the tool catalog.

The ladder proposed `searchsploit.lookup` with `{product, version}`. SearchSploit
declares `exploit_search` / `cve_search` / `copy_exploit` and takes `query`, so
that rung raised "Unsupported SearchSploit action: lookup" every single time it
was reached — a dead step, burned budget, and no exploit intel. Seen live on a
lab mission against DVWA.
"""

from __future__ import annotations

import ast
from pathlib import Path

from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry

DECIDER = Path("saber/agents/deciders/deterministic.py")


def _proposed_pairs() -> set[tuple[str, str]]:
    """Return every literal (tool_name, tool_action) the decider constructs."""

    tree = ast.parse(DECIDER.read_text(encoding="utf-8"))
    pairs: set[tuple[str, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", None) != "ProposedAction":
            continue
        found: dict[str, str] = {}
        for keyword in node.keywords:
            if keyword.arg in {"tool_name", "tool_action"} and isinstance(
                keyword.value, ast.Constant
            ):
                found[keyword.arg] = keyword.value.value
        if "tool_name" in found and "tool_action" in found:
            pairs.add((found["tool_name"], found["tool_action"]))

    return pairs


def test_every_ladder_action_exists_in_the_catalog() -> None:
    catalog = ToolCatalog.from_registry(build_default_registry())
    known = {
        (tool.name, action.action) for tool in catalog.tools for action in tool.actions
    }

    unknown = sorted(pair for pair in _proposed_pairs() if pair not in known)

    assert not unknown, f"deterministic decider proposes actions no tool declares: {unknown}"


def test_the_ladder_actually_proposes_something() -> None:
    """Guard the AST scrape itself: an empty set would make the test vacuous."""

    assert len(_proposed_pairs()) >= 4
