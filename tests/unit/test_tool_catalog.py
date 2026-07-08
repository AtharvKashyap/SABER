"""Tests for SABER tool catalog."""

from __future__ import annotations

from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry


def test_tool_catalog_builds_from_default_registry() -> None:
    registry = build_default_registry()
    catalog = ToolCatalog.from_registry(registry)

    data = catalog.to_dict()
    prompt_text = catalog.to_prompt_text()

    assert len(catalog.tools) >= 1
    assert "tools" in data
    assert "nmap" in prompt_text
    assert "service_scan" in prompt_text


def test_tool_catalog_has_approval_for_risky_actions() -> None:
    registry = build_default_registry()
    catalog = ToolCatalog.from_registry(registry)

    risky = [
        action
        for tool in catalog.tools
        for action in tool.actions
        if action.requires_approval
    ]

    assert risky
