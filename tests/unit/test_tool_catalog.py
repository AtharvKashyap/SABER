"""Tests for SABER tool catalog."""

from __future__ import annotations

from saber.core.tool_catalog import ToolCatalog
from saber.tools.registry import build_default_registry
from tests.support.catalog import build_test_catalog


def test_from_registry_skips_contractless_tools() -> None:
    # F0.4: the catalog is generated from wrapper CONTRACTs. Wrappers without a
    # CONTRACT are simply skipped rather than getting a fabricated "default"
    # action. As of F1.6, custom_cli, nmap, nuclei, nikto, whatweb, and
    # searchsploit are migrated, so they are the only entries in the catalog
    # (alphabetically sorted); every other (contractless) wrapper is absent.
    catalog = ToolCatalog.from_registry(build_default_registry())

    names = [tool.name for tool in catalog.tools]
    assert names == ["custom_cli", "nikto", "nmap", "nuclei", "searchsploit", "whatweb"]
    # No fabricated "default" action; only the real contract actions surface.
    actions = {action.action for tool in catalog.tools for action in tool.actions}
    assert "default" not in actions
    assert {"run_command", "run_script", "run_pipeline"}.issubset(actions)
    assert {"service_scan", "vuln_scan", "udp_scan", "script_scan"}.issubset(actions)
    assert "template_scan" in actions
    assert "web_scan" in actions


def test_tool_catalog_renders_contract_actions() -> None:
    catalog = build_test_catalog()

    data = catalog.to_dict()
    prompt_text = catalog.to_prompt_text()

    assert len(catalog.tools) >= 1
    assert "tools" in data
    assert "nmap" in prompt_text
    assert "service_scan" in prompt_text
    # per-action args are surfaced in the prompt text
    assert "arg target: str, required" in prompt_text


def test_tool_catalog_has_approval_for_risky_actions() -> None:
    catalog = build_test_catalog()

    risky = [
        action
        for tool in catalog.tools
        for action in tool.actions
        if action.requires_approval
    ]

    assert risky
