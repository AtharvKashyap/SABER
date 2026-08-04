"""Tool catalog for LLM-aware SABER agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.tools.contract import ArgSpec
from saber.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ToolActionSpec:
    """One action an agent may request."""

    tool_name: str
    action: str
    description: str
    risk: str = "low"
    requires_approval: bool = False
    example_args: dict[str, Any] = field(default_factory=dict)
    args: tuple[ArgSpec, ...] = ()


@dataclass(frozen=True)
class ToolSpec:
    """LLM-readable tool description."""

    name: str
    category: str
    phase: str
    description: str
    image: str | None = None
    actions: list[ToolActionSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# Tool categories each mission profile can actually make use of, aligned with the
# agents PROFILE_AGENTS enables for that profile.
#
# "unknown" is custom_cli — the escape hatch the loop uses to run a script it
# wrote itself — and "recon" is how every mission starts, so both are in every
# profile. A profile not listed here is not filtered at all: an unrecognized
# profile should fail OPEN, because scope is what restricts a mission, not this.
PROFILE_CATEGORIES: dict[str, set[str]] = {
    "recon": {"recon", "unknown"},
    "web": {"recon", "web", "unknown"},
    "network": {"recon", "network", "unknown"},
    "ad": {
        "recon",
        "network",
        "active_directory",
        "post_exploitation",
        "password_cracking",
        "unknown",
    },
}


class ToolCatalog:
    """Catalog of exact tool capabilities available to agents."""

    def __init__(self, tools: list[ToolSpec]) -> None:
        self.tools = tools

    @classmethod
    def from_registry(cls, registry: ToolRegistry) -> "ToolCatalog":
        """Build a catalog by reading each registered wrapper's module-level CONTRACT."""

        specs: list[ToolSpec] = []
        for entry in registry.list_entries():
            try:
                contract = entry.load_contract()
            except (ImportError, ModuleNotFoundError):
                # Wrapper module not importable (e.g. the known impacket
                # import_path drift). Skip only for a genuinely missing module;
                # a malformed CONTRACT must fail loudly, not vanish.
                continue
            if contract is None:
                continue  # not yet migrated; do not fabricate a fake action
            actions = [
                ToolActionSpec(
                    tool_name=contract.tool_name,
                    action=ac.action,
                    description=ac.description,
                    risk=ac.risk,
                    requires_approval=ac.requires_approval,
                    example_args=dict(ac.example_args),
                    args=ac.args,
                )
                for ac in contract.actions
            ]
            specs.append(
                ToolSpec(
                    name=contract.tool_name,
                    category=contract.category,
                    phase=contract.phase,
                    image=None,
                    description=contract.description,
                    actions=actions,
                    metadata={"registry_name": entry.name, "aliases": list(contract.aliases)},
                )
            )

        deduped: dict[str, ToolSpec] = {}
        for spec in specs:
            deduped.setdefault(spec.name, spec)
        return cls(sorted(deduped.values(), key=lambda item: item.name))

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible catalog."""

        return {
            "tools": [
                {
                    "name": tool.name,
                    "category": tool.category,
                    "phase": tool.phase,
                    "description": tool.description,
                    "image": tool.image,
                    "actions": [
                        {
                            "tool_name": action.tool_name,
                            "action": action.action,
                            "description": action.description,
                            "risk": action.risk,
                            "requires_approval": action.requires_approval,
                            "example_args": action.example_args,
                            "args": [
                                {
                                    "name": a.name,
                                    "type": a.type,
                                    "required": a.required,
                                    "default": a.default,
                                    "description": a.description,
                                    "choices": list(a.choices),
                                    "example": a.example,
                                }
                                for a in action.args
                            ],
                        }
                        for action in tool.actions
                    ],
                    "metadata": tool.metadata,
                }
                for tool in self.tools
            ]
        }

    def to_prompt_text(self) -> str:
        """Return compact prompt-ready tool catalog text."""

        lines: list[str] = []

        for tool in self.tools:
            lines.append(f"- {tool.name} [{tool.phase}/{tool.category}]")
            lines.append(f"  Description: {tool.description}")
            if tool.image:
                lines.append(f"  Docker image: {tool.image}")
            for action in tool.actions:
                approval = "approval required" if action.requires_approval else "auto allowed"
                lines.append(
                    f"  - action={action.action}; risk={action.risk}; {approval}; "
                    f"{action.description}; example_args={action.example_args}"
                )
                for arg in action.args:
                    req = "required" if arg.required else "optional"
                    lines.append(f"    arg {arg.name}: {arg.type}, {req}; {arg.description}")

        return "\n".join(lines)

    def for_profile(self, profile: str) -> "ToolCatalog":
        """Return a catalog holding only the tools this profile can use.

        The LLM decider is handed this rather than the whole catalog. The full
        catalog renders to ~10.6k tokens and was sent on every decision whatever
        the profile — 76% of the prompt on a live web mission, which the provider
        then refused outright (HTTP 402) because the key's remaining balance
        capped prompts below that. It was also simply wrong: a web mission was
        being offered mimikatz, ghidra and bloodhound.

        An unrecognized profile returns the full catalog unchanged.
        """

        categories = PROFILE_CATEGORIES.get((profile or "").strip().lower())
        if not categories:
            return self

        return ToolCatalog(
            [tool for tool in self.tools if tool.category.lower() in categories]
        )

    def actions_for_phase(self, phase: str) -> list[ToolActionSpec]:
        """Return actions matching a phase."""

        normalized = phase.lower()
        actions: list[ToolActionSpec] = []

        for tool in self.tools:
            if tool.phase.lower() == normalized or tool.category.lower() == normalized:
                actions.extend(tool.actions)

        return actions
