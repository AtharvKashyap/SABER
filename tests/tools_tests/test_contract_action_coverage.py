"""Structural gates that keep tool CONTRACTs from drifting away from their wrappers.

Two failure modes this workstream exists to prevent, both proven live:

1. A wrapper implements a ``build_command`` branch the CONTRACT never declares.
   The action then exists but is invisible to the decider, so a real attack
   avenue (dnsrecon AXFR, sqlmap --schema, amass active enum) can never be
   chosen no matter what the mission needs.
2. A CONTRACT declares an arg the executor strips. ``BaseAgent`` removes
   ``target``/``session``/``action``/``metadata`` from decider args before
   calling ``run()``, so a *required* arg with one of those names can never be
   satisfied: ``LlmDecider._validate_args`` rejects the action and the decider
   returns STOP, killing the whole mission rather than one step.

Both are checked by reading the wrapper source, so they hold for every tool as
it is migrated rather than only for the ones someone remembered to test.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from saber.agents.base_agent import BaseAgent
from saber.tools.registry import build_default_registry

from tests.tools_tests.test_contract_consistency import _MIGRATED_TOOLS

# Aliases a wrapper accepts purely as a synonym for a declared action. These need
# no separate CONTRACT entry because they build an identical command.
_ALIAS_ACTIONS: dict[str, set[str]] = {
    "nuclei": {"scan"},
    "nikto": {"scan"},
    "searchsploit": {"search"},
    "sqlmap": {"test_url"},
    "whatweb": {"scan"},
    # Original dispatch name, still used by network_agent/tool_selection_agent;
    # the CONTRACT advertises the clearer "enumerate".
    "snmpwalk": {"walk"},
}


def _dispatch_actions(wrapper_class: type) -> set[str]:
    """Return every action string ``build_command`` dispatches on, via the AST.

    Picks up both ``action == "x"`` and ``action in {"x", "y"}`` forms.
    """

    source = inspect.getsource(inspect.getmodule(wrapper_class))
    tree = ast.parse(source)

    build_command = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "build_command":
            build_command = node
            break
    if build_command is None:
        return set()

    actions: set[str] = set()
    for node in ast.walk(build_command):
        if not isinstance(node, ast.Compare):
            continue
        if not (isinstance(node.left, ast.Name) and node.left.id == "action"):
            continue
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            if isinstance(op, ast.Eq) and isinstance(comparator, ast.Constant):
                if isinstance(comparator.value, str):
                    actions.add(comparator.value)
            elif isinstance(op, ast.In) and isinstance(
                comparator, ast.Set | ast.Tuple | ast.List
            ):
                for element in comparator.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        actions.add(element.value)
    return actions


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_every_wrapper_action_is_declared_in_the_contract(tool_name):
    """No wrapper action may be reachable in code but invisible to the decider."""

    entry = build_default_registry().get(tool_name)
    contract = entry.load_contract()
    wrapper_class = entry.load_class()

    declared = {action.action for action in contract.actions}
    dispatched = _dispatch_actions(wrapper_class)
    aliases = _ALIAS_ACTIONS.get(tool_name, set())

    undeclared = dispatched - declared - aliases
    assert not undeclared, (
        f"{tool_name} build_command dispatches {sorted(undeclared)} but its CONTRACT "
        f"declares only {sorted(declared)} — the decider can never choose them. "
        f"Declare them, or add pure synonyms to _ALIAS_ACTIONS."
    )


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_every_declared_action_is_buildable(tool_name):
    """Every declared action must survive build_command with its example_args."""

    from saber.models.target import Target, TargetType

    entry = build_default_registry().get(tool_name)
    contract = entry.load_contract()
    wrapper = entry.load_class()(sandbox=None)

    for action in contract.actions:
        args = dict(action.example_args)
        # Mirror production: the loop passes the Target, never an args entry.
        for reserved in BaseAgent._RESERVED_TOOL_KWARGS:
            args.pop(reserved, None)
        try:
            command = wrapper.build_command(
                Target(type=TargetType.IP, value="127.0.0.1"), action=action.action, **args
            )
        except ValueError as exc:
            pytest.fail(
                f"{tool_name}.{action.action} is declared but not buildable from its "
                f"example_args ({args}): {exc}"
            )
        assert command.command, f"{tool_name}.{action.action} built an empty command"


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_no_contract_declares_an_executor_reserved_arg(tool_name):
    """A reserved-name arg is stripped before run(), so declaring one is a trap."""

    contract = build_default_registry().get(tool_name).load_contract()

    for action in contract.actions:
        offenders = {
            spec.name for spec in action.args if spec.name in BaseAgent._RESERVED_TOOL_KWARGS
        }
        assert not offenders, (
            f"{tool_name}.{action.action} declares reserved arg(s) {sorted(offenders)}. "
            f"BaseAgent strips these before run(), so a required one can never be "
            f"satisfied and the decider will STOP the mission."
        )
        example_offenders = {
            key for key in action.example_args if key in BaseAgent._RESERVED_TOOL_KWARGS
        }
        assert not example_offenders, (
            f"{tool_name}.{action.action} example_args includes reserved key(s) "
            f"{sorted(example_offenders)}; the prompt would teach the model to send "
            f"an arg that is rejected as unknown."
        )


def test_migrated_tools_set_matches_contract_bearing_wrappers():
    """Any wrapper that has grown a CONTRACT must be in the consistency gate."""

    reg = build_default_registry()
    with_contract = set()
    for name in _all_registry_names(reg):
        try:
            contract = reg.get(name).load_contract()
        except Exception:  # noqa: BLE001 - unimportable wrappers are covered elsewhere
            continue
        if contract is None:
            continue
        # Key on the contract's own tool_name, not the registry key: a wrapper
        # reachable under an alias (openvas / openvas_api) must not be reported
        # twice, and _MIGRATED_TOOLS holds the canonical name that
        # test_contract_consistency asserts equals contract.tool_name.
        with_contract.add(contract.tool_name)

    missing = with_contract - set(_MIGRATED_TOOLS)
    assert not missing, (
        f"{sorted(missing)} declare a CONTRACT but are absent from _MIGRATED_TOOLS, "
        f"so none of the consistency gates run for them."
    )


def _all_registry_names(reg) -> list[str]:
    """Return every registered tool name, however the registry exposes them."""

    for attribute in ("names", "tool_names"):
        getter = getattr(reg, attribute, None)
        if callable(getter):
            return sorted(getter())
    entries = getattr(reg, "entries", None)
    if entries:
        return sorted(entry.tool_name for entry in entries)
    # Last resort: the wrapper modules on disk.
    return sorted(
        path.stem for path in Path("saber/tools").rglob("*.py") if not path.stem.startswith("_")
    )
