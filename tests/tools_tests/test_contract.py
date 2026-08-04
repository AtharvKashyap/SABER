from saber.tools.contract import ArgSpec, ActionContract, ToolContract


def test_contract_shapes_are_frozen_and_typed():
    arg = ArgSpec("target", "str", required=True, description="in scope")
    action = ActionContract(action="service_scan", description="scan",
                            args=(arg,), risk="low", emits_kinds=("host", "service"))
    contract = ToolContract(tool_name="nmap", category="recon", phase="recon",
                            description="d", actions=(action,), parser="nmap")
    assert contract.actions[0].args[0].name == "target"
    assert contract.actions[0].risk == "low"
    import dataclasses
    assert dataclasses.is_dataclass(arg)
    # frozen: mutation raises
    import pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        arg.name = "x"  # type: ignore[misc]
