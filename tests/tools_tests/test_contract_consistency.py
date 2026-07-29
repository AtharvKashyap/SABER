import pytest
from saber.core.canonical_kinds import CANONICAL_KINDS
from saber.tools.registry import build_default_registry

# Grows one entry per migrated tool. F1 adds the 11; F2-F6 append the rest.
_MIGRATED_TOOLS: set[str] = set()


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_migrated_tool_contract_is_consistent(tool_name):
    reg = build_default_registry()
    entry = reg.get(tool_name)
    contract = entry.load_contract()
    assert contract is not None, f"{tool_name} has no CONTRACT"
    assert contract.tool_name == tool_name
    # category/phase equality vs the wrapper config
    wrapper = entry.load_class()(sandbox=None)
    assert contract.category == wrapper.config.category.value
    assert contract.phase == wrapper.config.phase.value
    # every action is buildable and emits only canonical kinds
    for action in contract.actions:
        for kind in action.emits_kinds:
            assert (
                kind in CANONICAL_KINDS
            ), f"{tool_name}.{action.action} emits non-canonical {kind}"


def test_no_default_action_and_all_migrated_have_contracts():
    reg = build_default_registry()
    for tool_name in _MIGRATED_TOOLS:
        contract = reg.get(tool_name).load_contract()
        assert all(a.action != "default" for a in contract.actions)
