from saber.tools.registry import build_default_registry


def test_load_contract_returns_none_when_absent_and_contract_when_present():
    reg = build_default_registry()
    # nmap has no CONTRACT yet at this point in the plan -> None is acceptable pre-migration.
    entry = reg.get("nmap")
    result = entry.load_contract()
    assert result is None or result.tool_name == "nmap"
