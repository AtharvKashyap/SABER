from saber.agents.deciders.llm import LlmDecider
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.tools.contract import ArgSpec


def _catalog():
    action = ToolActionSpec(
        tool_name="nmap", action="service_scan", description="d",
        args=(ArgSpec("target", "str", required=True),
              ArgSpec("ports", "str", required=False)),
    )
    return ToolCatalog([ToolSpec(name="nmap", category="recon", phase="recon",
                                 description="d", actions=[action])])


def test_validate_args_rejects_missing_required():
    d = LlmDecider(llm_client=None, tool_catalog=_catalog())
    errors = d._validate_args("nmap", "service_scan", {})
    assert any("target" in e for e in errors)


def test_validate_args_rejects_unknown_arg():
    d = LlmDecider(llm_client=None, tool_catalog=_catalog())
    errors = d._validate_args("nmap", "service_scan", {"target": "x", "bogus": 1})
    assert any("bogus" in e for e in errors)


def test_validate_args_accepts_valid():
    d = LlmDecider(llm_client=None, tool_catalog=_catalog())
    assert d._validate_args("nmap", "service_scan", {"target": "127.0.0.1"}) == []
