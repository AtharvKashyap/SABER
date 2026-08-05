"""Docs make checkable claims, so check them.

CLAUDE.md and README.md both told operators to use a published sandbox image that
was missing six contracted executables, and described a `Require approval` toggle
and a GUI that no longer existed. Stale docs on a security tool are worse than
absent ones: they get followed.

Only mechanically verifiable claims belong here — make targets, file paths,
defaults, and the absence of things that were deliberately removed. Prose is not
testable and is not tested.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MD = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
README_MD = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
MAKEFILE = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

DOCS = {"CLAUDE.md": CLAUDE_MD, "README.md": README_MD}


@pytest.mark.parametrize(
    "target",
    ["unit", "smoke", "e2e", "llm-e2e", "final", "sandbox-build", "sandbox-verify",
     "lab-up", "lab-down", "preflight"],
)
def test_every_make_target_the_docs_name_exists(target: str) -> None:
    named_in_docs = any(f"make {target}" in body for body in DOCS.values())
    if not named_in_docs:
        pytest.skip(f"docs do not mention make {target}")

    assert re.search(rf"^{re.escape(target)}:", MAKEFILE, re.M), (
        f"docs tell the reader to run `make {target}`, but the Makefile has no such target"
    )


@pytest.mark.parametrize(
    "path",
    [
        "saber/orchestration/mission_loop.py",
        "saber/models/mission_state.py",
        "saber/agents/deciders/base.py",
        "saber/agents/deciders/llm.py",
        "saber/agents/deciders/hybrid.py",
        "saber/agents/deciders/deterministic.py",
        "saber/core/state_merger.py",
        "saber/core/state_summary.py",
        "saber/orchestration/risk_gate.py",
        "saber/ui/web/templating.py",
        "saber/tools/image_manifest.py",
        "prompts/next_action.txt",
    ],
)
def test_every_source_path_the_docs_point_at_exists(path: str) -> None:
    """A doc that sends a reader to a file that moved wastes their time."""

    if not any(path in body for body in DOCS.values()):
        pytest.skip(f"docs do not reference {path}")

    assert (REPO_ROOT / path).exists(), f"docs reference {path}, which does not exist"


def test_the_documented_sandbox_image_is_the_real_default() -> None:
    from saber.core.docker_runner import DEFAULT_SHARED_IMAGE

    for name, body in DOCS.items():
        assert DEFAULT_SHARED_IMAGE in body, f"{name} does not name the real default image"


def test_no_doc_advertises_the_retired_published_image() -> None:
    """It was missing checksec/radare2/gdb/pwntools/chisel/enum4linux and is gone."""

    for name, body in {**DOCS, ".env.example": (REPO_ROOT / ".env.example").read_text()}.items():
        assert "ghcr.io/atharvkashyap/saber-sandbox" not in body, (
            f"{name} still points at the retired published image"
        )


def test_no_doc_advertises_the_deleted_publish_workflow() -> None:
    assert not (REPO_ROOT / ".github/workflows/publish-sandbox.yml").exists()
    for name, body in DOCS.items():
        assert "publish-sandbox" not in body, f"{name} references a deleted workflow"


def test_plan_first_is_documented_as_retired_and_chain_runner_is_gone() -> None:
    """An invariant in CLAUDE.md that a reader must be able to trust."""

    assert not (REPO_ROOT / "saber/orchestration/chain_runner.py").exists()
    assert "ChainRunner` has been deleted" in CLAUDE_MD


def test_the_cli_run_flag_the_docs_show_is_real() -> None:
    """CLAUDE.md warns that older docs showed a positional target. Keep that true."""

    cli = (REPO_ROOT / "saber/ui/cli/main.py").read_text(encoding="utf-8")

    assert '"--target"' in cli
    assert "--target" in README_MD


def test_documented_env_vars_are_read_by_the_code() -> None:
    """A documented variable that nothing reads is a trap."""

    runtime = (REPO_ROOT / "saber/core/runtime.py").read_text(encoding="utf-8")
    client = (REPO_ROOT / "saber/core/llm_client.py").read_text(encoding="utf-8")
    combined = runtime + client

    for variable in ("SABER_SANDBOX_IMAGE", "SABER_DOCKER_NETWORK", "SABER_MODEL",
                     "SABER_PROMPT_CACHE"):
        if variable not in CLAUDE_MD:
            continue
        assert variable in combined, f"CLAUDE.md documents {variable} but no code reads it"


def test_llm_mode_really_builds_the_hybrid_the_docs_describe() -> None:
    """Both docs now say LLM missions get a HybridDecider, not a bare LlmDecider."""

    runtime = (REPO_ROOT / "saber/core/runtime.py").read_text(encoding="utf-8")

    assert "HybridDecider(" in runtime
    assert "HybridDecider" in CLAUDE_MD
    assert "HybridDecider" in README_MD


def test_the_docs_disclose_that_a_paused_mission_cannot_resume() -> None:
    """The most important limitation for anyone running this autonomously."""

    for name, body in DOCS.items():
        assert "cannot resume" in body, f"{name} does not disclose the approval-resume gap"
