"""Declarative tool contracts — the single source generating catalog + validator + tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ArgType = Literal["str", "int", "float", "bool", "list[str]", "enum"]


@dataclass(frozen=True)
class ArgSpec:
    name: str
    type: ArgType
    required: bool = False
    default: Any = None
    description: str = ""
    choices: tuple[Any, ...] = ()
    example: Any = None


@dataclass(frozen=True)
class ActionContract:
    action: str
    description: str
    args: tuple[ArgSpec, ...] = ()
    risk: Literal["low", "medium", "high"] = "low"
    requires_approval: bool = False
    emits_kinds: tuple[str, ...] = ()
    example_args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolContract:
    tool_name: str
    category: str
    phase: str
    description: str
    actions: tuple[ActionContract, ...]
    parser: str | None = None
    aliases: tuple[str, ...] = ()
