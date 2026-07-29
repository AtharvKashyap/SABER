"""Tests for ToolCatalog generation from tool contracts."""

from __future__ import annotations

import pytest
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog
from saber.models.scope import AssessmentPhase
from saber.tools.capability import RequestedActionCategory
from saber.tools.registry import ToolRegistry, ToolRegistryEntry


@pytest.mark.xfail(reason="nmap CONTRACT lands in F1", strict=False)
def test_catalog_generates_actions_from_contract(monkeypatch):
    # nmap module will carry a CONTRACT after F1; generation must surface its actions + args.
    reg = ToolRegistry(
        [
            ToolRegistryEntry(
                name="nmap",
                import_path="saber.tools.recon.nmap",
                class_name="NmapWrapper",
                category=RequestedActionCategory.RECON,
                phase=AssessmentPhase.RECON,
            ),
        ]
    )
    catalog = ToolCatalog.from_registry(reg)
    nmap = next(t for t in catalog.tools if t.name == "nmap")
    actions = {a.action for a in nmap.actions}
    assert "service_scan" in actions
    assert "default" not in actions
    svc = next(a for a in nmap.actions if a.action == "service_scan")
    assert any(arg.name == "target" and arg.required for arg in svc.args)


def test_action_spec_has_args_field():
    spec = ToolActionSpec(tool_name="x", action="y", description="d")
    assert spec.args == ()
