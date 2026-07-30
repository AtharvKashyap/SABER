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

# Actions a wrapper implements but which are DELIBERATELY not exposed to the decider,
# each with a recorded reason. Distinct from _ALIAS_ACTIONS (pure synonyms): these are
# real, distinct branches that must not be offered because they cannot succeed.
# Withholding is a conscious decision, so it is recorded here rather than by silently
# widening the alias set.
_WITHHELD_ACTIONS: dict[str, dict[str, str]] = {
    "bloodhound": {
        "ingest_existing_zip": (
            "Builds ['python', '-m', 'saber.parsers.bloodhound', ...]: Kali has no "
            "`python` alias, the saber package is not in the sandbox image, and that "
            "module has no __main__. Offering it would guarantee a failed step."
        )
    },
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
    withheld = set(_WITHHELD_ACTIONS.get(tool_name, {}))

    undeclared = dispatched - declared - aliases - withheld
    assert not undeclared, (
        f"{tool_name} build_command dispatches {sorted(undeclared)} but its CONTRACT "
        f"declares only {sorted(declared)} — the decider can never choose them. "
        f"Declare them, add pure synonyms to _ALIAS_ACTIONS, or record a deliberate "
        f"omission in _WITHHELD_ACTIONS with a reason."
    )


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_withheld_actions_are_really_absent_from_the_contract(tool_name):
    """A withheld action must not also be declared — that would defeat the point."""

    contract = build_default_registry().get(tool_name).load_contract()
    declared = {action.action for action in contract.actions}

    for action, reason in _WITHHELD_ACTIONS.get(tool_name, {}).items():
        assert action not in declared, (
            f"{tool_name}.{action} is listed as withheld but IS declared: {reason}"
        )
        assert reason.strip(), f"{tool_name}.{action} is withheld without a reason"


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
def test_example_args_only_use_declared_arg_names(tool_name):
    """example_args teaches the model what to send, so it must match the schema.

    A key in example_args that is not a declared ArgSpec trains the model to send an
    arg `LlmDecider._validate_args` then rejects as unknown — and per llm.py that
    returns STOP, killing the whole mission rather than one step.
    """

    contract = build_default_registry().get(tool_name).load_contract()

    for action in contract.actions:
        declared = {spec.name for spec in action.args}
        undeclared = set(action.example_args) - declared
        assert not undeclared, (
            f"{tool_name}.{action.action} example_args has undeclared key(s) "
            f"{sorted(undeclared)}; declared args are {sorted(declared)}"
        )


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_every_required_arg_appears_in_example_args(tool_name):
    """Otherwise the advertised example cannot actually be run."""

    contract = build_default_registry().get(tool_name).load_contract()

    for action in contract.actions:
        required = {spec.name for spec in action.args if spec.required}
        missing = required - set(action.example_args)
        assert not missing, (
            f"{tool_name}.{action.action} requires {sorted(missing)} but its "
            f"example_args omits them, so the example is not runnable"
        )


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
    """Return the canonical name of every registered tool.

    ``ToolRegistry`` keys ``_entries`` by name AND by every alias, so this
    de-duplicates on ``entry.name``. Reading the real registry matters: an
    earlier version of this helper fell back to globbing wrapper module stems,
    which discovers ``impacket_tools`` rather than the registry name
    ``impacket`` — so a genuinely unmigrated tool could slip past the gate while
    the test still passed.
    """

    entries = getattr(reg, "_entries", None)
    if not entries:
        raise AssertionError(
            "ToolRegistry exposed no _entries; the coverage gate cannot enumerate tools."
        )
    return sorted({entry.name for entry in entries.values()})
