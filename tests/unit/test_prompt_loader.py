"""Tests for SABER PromptLoader."""

from __future__ import annotations

from saber.core.prompt_loader import PromptLoader


def test_prompt_loader_combines_common_and_agent_prompt(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "common_agent_policy.txt").write_text("COMMON", encoding="utf-8")
    (prompt_dir / "recon_agent.txt").write_text("RECON", encoding="utf-8")

    prompt = PromptLoader(prompt_dir).load_agent_prompt("recon_agent")

    assert prompt.common_policy == "COMMON"
    assert prompt.agent_prompt == "RECON"
    assert "COMMON" in prompt.system_prompt
    assert "RECON" in prompt.system_prompt


def test_prompt_loader_falls_back_to_short_agent_name(tmp_path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "recon.txt").write_text("RECON SHORT", encoding="utf-8")

    prompt = PromptLoader(prompt_dir).load_agent_prompt("recon_agent")

    assert prompt.agent_prompt == "RECON SHORT"
