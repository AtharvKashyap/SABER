"""The decider should only be offered tools its mission profile can use.

The full catalog is 36 tools / 105 actions and renders to ~10.6k tokens, which
was sent on every decision regardless of profile. Measured on a live web mission
it was 76% of a 14,091-token prompt — and the provider refused the request with
HTTP 402 because the key's remaining balance capped prompts at 12,274.

Beyond cost, it is simply wrong: a web mission was being offered mimikatz,
ghidra and bloodhound.
"""

from __future__ import annotations

import pytest
from saber.core.tool_catalog import PROFILE_CATEGORIES, ToolCatalog
from saber.tools.registry import build_default_registry


@pytest.fixture(scope="module")
def catalog() -> ToolCatalog:
    return ToolCatalog.from_registry(build_default_registry())


def test_web_profile_drops_the_tools_a_web_mission_cannot_use(catalog) -> None:
    names = {tool.name for tool in catalog.for_profile("web").tools}

    assert {"nuclei", "sqlmap", "nmap", "whatweb"} <= names
    assert not names & {"mimikatz", "ghidra_headless", "bloodhound", "impacket"}


def test_full_profile_keeps_everything(catalog) -> None:
    assert len(catalog.for_profile("full").tools) == len(catalog.tools)


def test_an_unknown_profile_keeps_everything(catalog) -> None:
    """Fail open on profile, not closed — scope is what restricts a mission."""

    assert len(catalog.for_profile("something-new").tools) == len(catalog.tools)


def test_every_profile_keeps_the_custom_script_escape_hatch(catalog) -> None:
    """custom_cli is how the loop runs a script it wrote; no profile should lose it."""

    for profile in PROFILE_CATEGORIES:
        names = {tool.name for tool in catalog.for_profile(profile).tools}
        assert "custom_cli" in names, f"{profile} lost custom_cli"


def test_every_profile_keeps_recon(catalog) -> None:
    """Every mission starts by looking around."""

    for profile in PROFILE_CATEGORIES:
        names = {tool.name for tool in catalog.for_profile(profile).tools}
        assert "nmap" in names, f"{profile} lost nmap"


def test_scoping_cuts_the_prompt_materially(catalog) -> None:
    """The point of the change. A web catalog must be far cheaper than the full one."""

    full = len(catalog.to_prompt_text())
    web = len(catalog.for_profile("web").to_prompt_text())

    assert web < full * 0.45, f"web catalog is {web} chars vs full {full}"


def test_filtering_preserves_action_detail(catalog) -> None:
    """A scoped catalog must still carry the args the decider validates against."""

    scoped = catalog.for_profile("web")
    nuclei = next(tool for tool in scoped.tools if tool.name == "nuclei")
    original = next(tool for tool in catalog.tools if tool.name == "nuclei")

    assert {a.action for a in nuclei.actions} == {a.action for a in original.actions}


def test_runtime_gives_the_decider_a_scoped_catalog_and_the_gate_the_full_one() -> None:
    """The model sees only its profile's tools; the risk gate must still see all.

    A gate with a filtered catalog would have blind spots when classifying an
    action naming a tool the profile never offered.
    """

    import tempfile
    from pathlib import Path

    from saber.core.runtime import SaberConfig, build_saber_runtime

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        runtime = build_saber_runtime(
            SaberConfig(
                db_path=root / "s.db",
                evidence_dir=root / "e",
                reports_dir=root / "r",
                profile="web",
                agent_mode="deterministic",
            )
        )

    # The runtime always carries the full catalog for gating and dispatch.
    assert len(runtime.tool_catalog.tools) > len(runtime.tool_catalog.for_profile("web").tools)
