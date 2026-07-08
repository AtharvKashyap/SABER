"""Prompt loading utilities for SABER agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_PROMPT_DIR = Path("prompts")


@dataclass(frozen=True)
class AgentPrompt:
    """Loaded prompt bundle for one agent."""

    agent_name: str
    common_policy: str
    agent_prompt: str

    @property
    def system_prompt(self) -> str:
        """Combined system prompt."""

        pieces = []

        if self.common_policy.strip():
            pieces.append(self.common_policy.strip())

        if self.agent_prompt.strip():
            pieces.append(self.agent_prompt.strip())

        return "\n\n".join(pieces)


class PromptLoader:
    """Loads common and per-agent prompts from disk."""

    def __init__(self, prompt_dir: str | Path = DEFAULT_PROMPT_DIR) -> None:
        self.prompt_dir = Path(prompt_dir)

    def load_agent_prompt(self, agent_name: str) -> AgentPrompt:
        """Load prompt for an agent.

        Looks for:
        - prompts/common_agent_policy.txt
        - prompts/<agent_name>.txt
        - prompts/<agent_name without _agent>.txt
        """

        common = self.load_optional("common_agent_policy.txt")

        candidates = [
            f"{agent_name}.txt",
            f"{agent_name.replace('_agent', '')}.txt",
        ]

        agent_prompt = ""
        for candidate in candidates:
            agent_prompt = self.load_optional(candidate)
            if agent_prompt:
                break

        return AgentPrompt(
            agent_name=agent_name,
            common_policy=common,
            agent_prompt=agent_prompt,
        )

    def load_required(self, name: str) -> str:
        """Load required prompt file."""

        path = self.prompt_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Prompt file not found: {path}")
        return path.read_text(encoding="utf-8")

    def load_optional(self, name: str) -> str:
        """Load optional prompt file."""

        path = self.prompt_dir / name
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")
