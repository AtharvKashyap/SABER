"""Keep `saber/tools/specs/*.yaml` honest about what actually drives behaviour.

`output_parsers:` entries in those YAML files are read by NO Python in the repo — the
parser for a tool comes from its CONTRACT's `parser=` field and the
`ParserRegistry`. So a spec naming `nmap_xml`/`nmap_text` or `john_show` describes
parsers that do not exist as separate units, and nothing flags the drift.

Rather than silently deleting operator-facing config, this test pins the real source
of truth: whatever a spec claims, the CONTRACT's declared parser must be registered
and resolvable. That is the property missions actually depend on.
"""

from __future__ import annotations

import pytest
from saber.parsers.registry import build_default_parser_registry
from saber.tools.registry import build_default_registry

from tests.tools_tests.test_contract_consistency import _MIGRATED_TOOLS


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_contract_declared_parser_resolves_in_the_parser_registry(tool_name):
    """A CONTRACT naming a parser that is not registered would silently drop output."""

    contract = build_default_registry().get(tool_name).load_contract()
    if contract.parser is None:
        # Legitimate: custom_cli produces free-form output with no fixed parser.
        return

    parser = build_default_parser_registry().get(contract.parser)
    assert parser is not None, (
        f"{tool_name} declares parser={contract.parser!r} but nothing is registered "
        f"under that name, so every successful run would be discarded"
    )


@pytest.mark.parametrize("tool_name", sorted(_MIGRATED_TOOLS))
def test_the_tool_name_itself_resolves_a_parser(tool_name):
    """ResultProcessor dispatches by TOOL name, so that lookup must work too."""

    contract = build_default_registry().get(tool_name).load_contract()
    if contract.parser is None:
        return

    assert build_default_parser_registry().get(tool_name) is not None, (
        f"no parser resolves for tool name {tool_name!r}; results would be dropped"
    )


def test_spec_output_parsers_field_is_documented_as_inert():
    """Guard against someone 'fixing' a spec's output_parsers and expecting an effect.

    If this ever becomes live config, delete this test and wire it properly — but do
    not leave a field that looks authoritative and is not.
    """

    from pathlib import Path

    specs = sorted(Path("saber/tools/specs").glob("*.yaml"))
    assert specs, "no tool specs found"

    readme = Path("saber/tools/specs/README.md")
    assert readme.exists(), (
        "saber/tools/specs/*.yaml contains an output_parsers field that no Python "
        "reads. Add saber/tools/specs/README.md recording that it is inert and that "
        "the CONTRACT's parser= field is authoritative."
    )
    text = readme.read_text().lower()
    assert "output_parsers" in text and "inert" in text
