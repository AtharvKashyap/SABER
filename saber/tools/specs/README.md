# Tool specs — what is live and what is not

These YAML files predate the declarative `CONTRACT` introduced in Workstream F. Not
every field in them still drives behaviour, and one in particular does not.

## `output_parsers:` is INERT

No Python in this repository reads `output_parsers`. Verified with
`grep -rn "output_parsers" --include=*.py saber/ tests/` → no hits.

Parser selection is decided by two things, both in code:

1. **The tool's `CONTRACT.parser` field** (`saber/tools/<category>/<tool>.py`) — the
   authoritative declaration of which parser handles that tool's output.
2. **`saber/parsers/registry.py::default_parser_entries()`** — maps tool names and
   aliases to parser instances, and is what `ResultProcessor` dispatches through.

So entries like `nmap.yaml`'s `nmap_xml` / `nmap_text`, or `john.yaml`'s `john_show`,
name parsers that do not exist as separate registered units. They are documentation of
intent at best, and misleading at worst: editing them changes nothing.

`tests/tools_tests/test_spec_yaml_is_not_dead_config.py` pins the property that
actually matters — every CONTRACT-declared parser resolves in the parser registry,
under both the parser name and the tool name — and asserts this README exists so the
inert field cannot be mistaken for live config.

**If you make `output_parsers` live**, wire it in code, delete the assertion in that
test, and update this file. Do not leave a field that looks authoritative and isn't.
