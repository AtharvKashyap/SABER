# Workstream F — Autonomous Full-Arsenal Pentester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SABER's three tool layers — catalog, wrappers, parsers→StateMerger — structurally consistent so that every selectable tool/action really runs, every successful run emits canonical `{kind, data}` observations, and `MissionState` grows across the full ~36-tool arsenal.

**Architecture:** Introduce one declarative `CONTRACT` per wrapper module (`saber/tools/contract.py`). `ToolCatalog` is *generated* from contracts (no more hand-maintained `_infer_actions`), `LlmDecider` validates proposed args against the contract before dispatch, and parsers emit a fixed canonical `kind` vocabulary that a `_MERGERS`-registry-driven `StateMerger` folds into an extended `MissionState`. The same contract feeds the catalog (what the LLM sees), the validator (what is accepted), and the tests (what is asserted), so the three layers cannot drift.

**Tech Stack:** Python >=3.11, pydantic v2 (`MissionState`), frozen dataclasses (contract/catalog/command), pytest (offline `make unit`), Docker/Kali sandbox (gated `SABER_RUN_DOCKER_E2E`), ruff + mypy (touched files only).

## Global Constraints

Copied verbatim from spec §6 invariants plus repo rules. Every task's requirements implicitly include this section.

- **Agents never run shell.** Execution only via `Sandbox` dispatched through `ActionExecutor`. New capabilities (tshark sniffing, pwntools/gdb, `custom_cli`) go through the same `build_command → ToolCommand → SandboxExecutionRequest → Sandbox` path. No subprocess anywhere in a wrapper/agent.
- **`MissionState` immutable-by-copy.** All new fields updated only via `model_copy(update=...)`; observations become state only through `StateMerger.merge`. No hand-editing of the new lists elsewhere.
- **Risk-gated autonomy; scope is a hard wall.** `RiskGate` still runs first and refuses out-of-scope/prohibited actions before any autonomy consideration. Contract `risk`/`requires_approval` feed the gate; sniffing, binary exploit, and `custom_cli` slot INTO the gate (high-risk/approval by default), never around it. Do not weaken `RiskGate`.
- **SQL parameterized; schema changes via static DDL migrations** under `saber/storage/migrations/*.sql`. New persisted `MissionState` fields that touch storage go through migrations, never string-built SQL. (Approved decision #4: in Workstream F the new kinds ride the JSON `MissionState` snapshot blob — NO new SQL tables; revisit at F9 only if reporting needs them.)
- **The loop decides; agents execute.** Contracts describe capabilities; the decider still chooses; `ActionExecutor` still dispatches. No wrapper gains decision logic.
- **Python >=3.11**, package `saber/`, main branch for PRs is `main`.
- **Lint scope is touched files only.** `ruff check <touched files>` and `mypy saber` on touched modules. The repo carries ~500 pre-existing ruff findings (mostly E501); do NOT attempt a repo-wide fix.
- **`make unit` must stay green and offline** (no Docker, no model): `tests/unit + tests/agent_tests + tests/orchestration_tests`. Integration tests are gated behind `SABER_RUN_DOCKER_E2E=1`.
- **NO `Co-Authored-By` trailer in any commit** authored under this plan.

---

## Executor-model tags

Every task is tagged `[opus]` or `[sonnet]`. This drives later subagent dispatch (spec §9).

- **`[opus]`** — foundation, brain, and cross-cutting judgment: **all of F0**, the `LlmDecider` arg-validation work, the binary-exploit loop (F5), and **all of F8**.
- **`[sonnet]`** — mechanical per-tool migrations, parser writing, and sandbox-image work: **F2–F7** per-tool tasks and **F9** report-adapter mechanics.

**Parallelizability:** the dependency spine is **F0 → F1 → {F2, F3, F4, F5, F6}**, with **F7 parallel from the start** and **F8/F9 after** the arsenal is consistent. Once F0 and F1 land, every per-tool task in F2–F6 is mutually independent (each touches its own wrapper module, its own parser module, its own test file, plus append-only edits to `default_parser_entries()` and the migrated-tools set) and can run on parallel `[sonnet]` subagents. The only shared files they append to are `saber/parsers/registry.py::default_parser_entries()` and the `_MIGRATED_TOOLS` set in the consistency test (see F0 Task 9) — resolve append-order conflicts at merge, never by editing another tool's block.

---

## Shared conventions (define once; referenced by later tasks)

### Canonical observation kinds (single source of truth)

The fixed `kind` vocabulary and per-kind `data` schema (spec §3.2). Every `ParsedObservation.kind` a wrapper's parser emits MUST be one of these, and `StateMerger._MERGERS` has exactly one entry per kind (F0 Task 8 asserts key-set equality).

| kind | data fields (canonical) | merges into |
|------|------------------------|-------------|
| `host` | `address` (req), `hostnames: list[str]`, `os`, `metadata` | `MissionState.hosts` (`KnownHost`) |
| `service` | `host` (req), `port` (req, int), `protocol`, `service`, `product`, `version`, `state` | `services` (`KnownService`) |
| `technology` | `host` (req), `name` (req), `version`, `metadata` | `technologies` (`KnownTechnology`) |
| `credential` | `username` (req), `secret`, `kind` (password\|hash\|key\|token), `host`, `service`, `validated: bool` | `credentials` (`KnownCredential`) |
| `vuln` | `title` (req), `host`, `port`, `severity`, `identifier` (CVE/template id), `confirmed: bool` | `vulns` (`KnownVuln`) |
| `share` | `host` (req), `name` (req), `type` (smb\|nfs\|...), `access` (read\|write\|none), `metadata` | `shares` (`KnownShare`) |
| `account` | `username` (req), `domain`, `host`, `source`, `enabled: bool`, `metadata` | `accounts` (`KnownAccount`) |
| `session` | `host` (req), `kind` (shell\|meterpreter\|winrm\|ssh), `user`, `privilege` (user\|root\|system), `ref`, `metadata` | `sessions` (`KnownSession`) |
| `loot` | `host`, `path`, `kind` (file\|hash\|key\|config), `description` (req), `evidence_ref`, `metadata` | `loot` (`KnownLoot`) |
| `flag` | `value` (req), `host`, `location`, `metadata` | `flags` (`KnownFlag`) |
| `note` | `title` (req), `detail`, `severity`, `refs: list[str]`, `metadata` | `notes` (`list[MissionNote]`) |

> **Note on `finding`/`note`:** the spec §3.2 row is labelled `finding` / `note`. This plan standardises on the single canonical kind **`note`** (title+detail+refs). A parser MAY set `data["kind"]` sub-fields but the observation-level `kind` string is always `"note"`.

### Risk taxonomy (approved decision #7 — one canonical mapping)

Contract `risk` strings map to the decider `RiskLevel` IntEnum (`saber/agents/deciders/base.py:15`) via the existing `RiskLevel.from_str`: `"low"→LOW(0)`, `"medium"→MEDIUM(1)`, `"high"→HIGH(2)`. `custom_cli`'s `risk_level` arg feeds the *same* `from_str`. `RiskGate` sees exactly one risk value per action (contract `risk` for contracted tools; for `custom_cli`, `max(contract risk="high", risk_level arg)`). No new risk enum is introduced.

### Contract vs config (approved decision #1)

`CONTRACT` and `ToolWrapperConfig` both persist. `CONTRACT.tool_name`/`category`/`phase` duplicate `ToolWrapperConfig`; a **consistency test** (F0 Task 9) enforces equality. Do NOT derive one from the other.

### `emits_kinds` enforcement (approved decision #6)

`emits_kinds` is **documentation + a soft warning**, NOT strict rejection. `StateMerger.merge` still folds any canonical kind it receives; a parser emitting a kind outside its action's `emits_kinds` logs a warning (via the module logger) but the observation is still merged. No task rejects an observation on `emits_kinds` grounds.

### `custom_cli` free-form output (approved decision #3)

`custom_cli` output has no schema. Its parser (if any) emits a generic `kind="note"` (`title`=action, `detail`=truncated stdout). There is **NO extra LLM parse call** in the parse path.

### Parser dispatch signature (approved decision #2)

Standardise ALL parsers to accept an optional `metadata` kwarg. `BaseParser.parse_text(self, text, metadata=None)` and `BaseParser.parse_json(self, data, metadata=None)` gain the kwarg (default `None`); `parse_file` already tolerates it. This makes all three `ParserRegistry` dispatch paths consistent (spec §2.3) and lets parsers derive `host` from `metadata["target"]` when output lacks it (the whatweb fix depends on this).

### Parser test fixture convention

- Fixtures live in `tests/fixtures/` as real tool output samples named `sample_<tool>_output.<ext>` (matches existing `sample_nmap_output.xml`, `sample_nuclei_output.json`).
- Parser tests live in `tests/parser_tests/test_<tool>.py`.
- A parser test (a) loads the fixture, (b) calls the parser, (c) asserts exact `{kind, data}` on selected observations, and (d) asserts `StateMerger.merge` grows the right `MissionState` list. Steps (c)/(d) use the shared helper below.

### Canonical-observation assertion helper

Defined once in F0 Task 10 at `tests/conftest.py` (project-root conftest, already present). All later parser tests import it.

```python
# tests/conftest.py  (append)
from saber.core.state_merger import StateMerger
from saber.models.mission_state import MissionState, AttemptedAction
from saber.models.target import Target


def assert_observation(obs: dict, *, kind: str, data_subset: dict) -> None:
    """Assert an observation has the given kind and its data is a superset of data_subset."""
    assert obs["kind"] == kind, f"expected kind={kind!r}, got {obs['kind']!r}"
    for key, value in data_subset.items():
        assert obs["data"].get(key) == value, (
            f"data[{key!r}]: expected {value!r}, got {obs['data'].get(key)!r}"
        )


def merge_observations(observations: list[dict], *, tool: str, action: str) -> MissionState:
    """Merge a list of {kind,data} observations into a fresh MissionState and return it."""
    state = MissionState(session_id="test", target=Target(host="127.0.0.1"))
    attempt = AttemptedAction(tool_name=tool, action=action, args={}, success=True)
    return StateMerger().merge(state, observations, attempt)
```

> Confirm `Target(host=...)` is the real constructor when implementing F0 Task 10 (read `saber/models/target.py`); if the field name differs, use the real one — this helper must instantiate a valid `Target`.

---

## Per-tool migration TEMPLATE (worked once with nmap)

**F2–F6 tasks reference this template.** A per-tool migration task is exactly these seven steps; the F2–F6 task bodies supply only the tool-specific specifics (actions, args, risk, `emits_kinds`, parser fixture → asserted observations). Do NOT re-paste boilerplate — follow the worked nmap example's shape.

Template steps (per tool `<T>`):
1. **(a) Declare `CONTRACT`** in the wrapper module `saber/tools/<cat>/<T>.py` — a module-level `CONTRACT: ToolContract` whose `actions` exactly match the wrapper's real `build_command` dispatch branches, with correct `args` (`ArgSpec` list), `risk`, `requires_approval`, `emits_kinds`, and `parser`.
2. **(b) Contract-consistency test** — add `<T>` to the migrated-tools set (F0 Task 9's `_MIGRATED_TOOLS`); the parametrized consistency test then asserts `CONTRACT.tool_name == config.tool_name`, category/phase equality, every `action` buildable by `build_command`, and every `emits_kinds` value canonical.
3. **(c) Golden `build_command` test per action** — assert the exact `ToolCommand.command` list per action (real flags).
4. **(d) Parser emits canonical observations** — write/fix `saber/parsers/<T>.py` so a fixture (`tests/fixtures/sample_<T>_output.*`) yields the asserted `{kind, data}` observations; register it in `default_parser_entries()`.
5. **(e) `StateMerger.merge` grows the right list** — assert `merge_observations(...)` grows the target `MissionState` list by the expected count.
6. **(f) Run offline tests** — `pytest tests/parser_tests/test_<T>.py tests/tools_tests/test_<T>_contract.py -q` → PASS; `ruff check` + `mypy` on touched files.
7. **(g) Commit** — one commit per tool, message `feat(tools): migrate <T> to CONTRACT + canonical parser`.

### Worked example — nmap (the concrete template)

Files: Modify `saber/tools/recon/nmap.py`; Modify `saber/parsers/nmap.py`; Modify `saber/parsers/registry.py`; Test `tests/tools_tests/test_nmap_contract.py`, `tests/parser_tests/test_nmap.py`.

**(a) `CONTRACT` in `saber/tools/recon/nmap.py`** (add after imports; matches the wrapper's real four actions and the `-Pn` fix from F1 Task 3):

```python
from saber.tools.contract import ActionContract, ArgSpec, ToolContract

CONTRACT = ToolContract(
    tool_name="nmap",
    category="recon",
    phase="recon",
    description="Network discovery and service/version enumeration.",
    parser="nmap",
    actions=(
        ActionContract(
            action="service_scan",
            description="TCP connect service/version scan (-sT -sV -sC -Pn).",
            args=(
                ArgSpec("target", "str", required=True, description="Host/CIDR/URL in scope."),
                ArgSpec("ports", "str", required=False, default=None, example="1-1000"),
            ),
            risk="low", requires_approval=False,
            emits_kinds=("host", "service"),
            example_args={"target": "127.0.0.1", "ports": "1-1000"},
        ),
        ActionContract(
            action="vuln_scan",
            description="NSE vuln category scan. Intrusive.",
            args=(ArgSpec("target", "str", required=True), ArgSpec("ports", "str")),
            risk="medium", requires_approval=True,
            emits_kinds=("vuln", "service"),
            example_args={"target": "127.0.0.1"},
        ),
        ActionContract(
            action="udp_scan",
            description="UDP service discovery. Slower and noisier than TCP.",
            args=(ArgSpec("target", "str", required=True), ArgSpec("ports", "str")),
            risk="medium", requires_approval=True,
            emits_kinds=("host", "service"),
            example_args={"target": "127.0.0.1", "ports": "53,161"},
        ),
        ActionContract(
            action="script_scan",
            description="Run a specific NSE script or category.",
            args=(
                ArgSpec("target", "str", required=True),
                ArgSpec("script", "str", required=True, description="NSE script or category"),
                ArgSpec("ports", "str"),
            ),
            risk="medium", requires_approval=True,
            emits_kinds=("host", "service", "vuln"),
            example_args={"target": "127.0.0.1", "script": "http-title"},
        ),
    ),
)
```

**(c) Golden command test** (`tests/tools_tests/test_nmap_contract.py`):

```python
from saber.tools.recon.nmap import NmapWrapper
from saber.models.target import Target


def test_service_scan_command_includes_pn():
    wrapper = NmapWrapper(sandbox=None)  # build_command does not touch sandbox
    cmd = wrapper.build_command(Target(host="127.0.0.1"), action="service_scan", ports="1-1000")
    assert cmd.command == ["nmap", "-sT", "-sV", "-sC", "-Pn", "-p", "1-1000", "127.0.0.1"]
    assert cmd.action == "service_scan"
```

**(d)+(e) Parser → canonical → merge test** (`tests/parser_tests/test_nmap.py`, uses `tests/fixtures/sample_nmap_output.xml`):

```python
from pathlib import Path
from saber.parsers.nmap import NmapParser
from tests.conftest import assert_observation, merge_observations


def test_nmap_xml_emits_host_and_service_and_grows_state():
    text = Path("tests/fixtures/sample_nmap_output.xml").read_text()
    result = NmapParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    hosts = [o for o in obs if o["kind"] == "host"]
    services = [o for o in obs if o["kind"] == "service"]
    assert hosts and services
    assert_observation(services[0], kind="service",
                       data_subset={"host": hosts[0]["data"]["address"]})
    state = merge_observations(obs, tool="nmap", action="service_scan")
    assert len(state.services) >= 1
    assert len(state.hosts) >= 1
```

> nmap's parser currently emits `host` data under key `"host"`, not `"address"` (`saber/parsers/nmap.py:53,96`). F1 Task 4 aligns the host `data` key to the canonical `address`. This test is written against the post-F1 canonical shape.

The remaining F2–F6 tool tasks are this exact shape with their own specifics.

---

## F0 — Foundation `[opus]`

Everything depends on F0. All tasks are failing-test-first. F0 is a single opus workstream (tasks are sequential; later F0 tasks consume earlier ones).

### Task F0.1: Create `saber/tools/contract.py` `[opus]`

**Files:** Create `saber/tools/contract.py`; Test `tests/tools_tests/test_contract.py`.

**Interfaces:**
- Produces: `ArgType`, `ArgSpec`, `ActionContract`, `ToolContract` (exact fields below). Consumed by every wrapper `CONTRACT`, `ToolCatalog.from_registry`, and `LlmDecider._validate_args`.

- [ ] **Step 1: Write the failing test**

```python
# tests/tools_tests/test_contract.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tools_tests/test_contract.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'saber.tools.contract'`

- [ ] **Step 3: Write minimal implementation**

```python
# saber/tools/contract.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tools_tests/test_contract.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add saber/tools/contract.py tests/tools_tests/test_contract.py
git commit -m "feat(tools): add declarative tool contract types"
```

### Task F0.2: `ToolRegistryEntry.load_contract()` `[opus]`

**Files:** Modify `saber/tools/registry.py`; Test `tests/tools_tests/test_registry_load_contract.py`.

**Interfaces:**
- Consumes: `ToolContract` (F0.1).
- Produces: `ToolRegistryEntry.load_contract() -> ToolContract | None` (imports `import_path`, returns module `CONTRACT`, or `None` if the module has none yet — needed so the catalog can be built while migration is in progress).

- [ ] **Step 1: Write the failing test**

```python
# tests/tools_tests/test_registry_load_contract.py
from saber.tools.registry import build_default_registry


def test_load_contract_returns_none_when_absent_and_contract_when_present():
    reg = build_default_registry()
    # nmap has no CONTRACT yet at this point in the plan -> None is acceptable pre-migration.
    entry = reg.get("nmap")
    result = entry.load_contract()
    assert result is None or result.tool_name == "nmap"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tools_tests/test_registry_load_contract.py -q`
Expected: FAIL with `AttributeError: 'ToolRegistryEntry' object has no attribute 'load_contract'`

- [ ] **Step 3: Write minimal implementation** — add to `ToolRegistryEntry` (after `load_class`, `saber/tools/registry.py:60`):

```python
    def load_contract(self) -> "ToolContract | None":
        """Import the wrapper module and return its module-level CONTRACT, if any."""

        from saber.tools.contract import ToolContract

        module = import_module(self.import_path)
        contract = getattr(module, "CONTRACT", None)
        if contract is not None and not isinstance(contract, ToolContract):
            raise TypeError(f"{self.import_path}.CONTRACT is not a ToolContract")
        return contract
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tools_tests/test_registry_load_contract.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add saber/tools/registry.py tests/tools_tests/test_registry_load_contract.py
git commit -m "feat(tools): ToolRegistryEntry.load_contract()"
```

### Task F0.3: Register `custom_cli` in the default registry `[opus]`

**Files:** Modify `saber/tools/registry.py:159` (`default_tool_entries`); Test `tests/tools_tests/test_custom_cli_registered.py`.

Rationale: `custom_cli` (and the legacy `hydra`) are advertised in the old `known` dict but never registered (spec §2.1). `custom_cli` is the LLM-authored-script escape hatch and must be a real registry entry. `hydra` has no wrapper module and stays unregistered.

- [ ] **Step 1: Write the failing test**

```python
# tests/tools_tests/test_custom_cli_registered.py
from saber.tools.registry import build_default_registry


def test_custom_cli_is_registered():
    reg = build_default_registry()
    assert reg.has("custom_cli")
    entry = reg.get("custom_cli")
    assert entry.class_name == "CustomCliWrapper"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tools_tests/test_custom_cli_registered.py -q`
Expected: FAIL — `assert reg.has("custom_cli")` is False.

- [ ] **Step 3: Write minimal implementation** — append to the `default_tool_entries()` list (before the closing `]`, `saber/tools/registry.py:460`):

```python
        ToolRegistryEntry(
            name="custom_cli",
            import_path="saber.tools.custom_cli",
            class_name="CustomCliWrapper",
            category=RequestedActionCategory.UNKNOWN,
            phase=AssessmentPhase.RECON,
            description="Authorized custom command/script/pipeline in the sandbox.",
        ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tools_tests/test_custom_cli_registered.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add saber/tools/registry.py tests/tools_tests/test_custom_cli_registered.py
git commit -m "feat(tools): register custom_cli escape hatch"
```

### Task F0.4: `ToolActionSpec.args` field + `ToolCatalog` generation from contracts `[opus]`

**Files:** Modify `saber/core/tool_catalog.py`; Test `tests/tools_tests/test_catalog_from_contracts.py`.

**Interfaces:**
- Consumes: `ToolRegistryEntry.load_contract()` (F0.2), `ArgSpec`/`ActionContract`/`ToolContract` (F0.1).
- Produces: `ToolActionSpec` gains `args: tuple[ArgSpec, ...] = ()`. `ToolCatalog.from_registry` generates `ToolSpec`/`ToolActionSpec` from each entry's `CONTRACT`; entries without a `CONTRACT` are skipped (not defaulted). `to_dict()`/`to_prompt_text()` include per-action `args`.

Depends on: F0.1, F0.2. This task keeps the tests green *before* wrappers have contracts by skipping contract-less entries, so `make unit` stays green during migration.

- [ ] **Step 1: Write the failing test**

```python
# tests/tools_tests/test_catalog_from_contracts.py
from saber.core.tool_catalog import ToolCatalog, ToolActionSpec
from saber.tools.registry import ToolRegistry, ToolRegistryEntry
from saber.models.scope import AssessmentPhase
from saber.tools.capability import RequestedActionCategory


def test_catalog_generates_actions_from_contract(monkeypatch):
    # nmap module will carry a CONTRACT after F1; generation must surface its actions + args.
    reg = ToolRegistry([
        ToolRegistryEntry(name="nmap", import_path="saber.tools.recon.nmap",
                          class_name="NmapWrapper",
                          category=RequestedActionCategory.RECON,
                          phase=AssessmentPhase.RECON),
    ])
    catalog = ToolCatalog.from_registry(reg)
    nmap = next(t for t in catalog.tools if t.name == "nmap")
    actions = {a.action for a in nmap.actions}
    assert "service_scan" in actions
    assert "default" not in actions
    svc = next(a for a in nmap.actions if a.action == "service_scan")
    assert any(arg.name == "target" and arg.required for arg in svc.args)


def test_action_spec_has_args_field():
    spec = ToolActionSpec(tool_name="x", action="y", description="d")
    assert spec.args == ()
```

> This test depends on nmap carrying a `CONTRACT`. Sequence F1 Task 1 (nmap CONTRACT) is a prerequisite for this test to pass; until then it is expected-fail. Mark it `@pytest.mark.xfail(reason="nmap CONTRACT lands in F1", strict=False)` in Step 3 and **remove the xfail in F1 Task 1 Step 6**. Record this in the plan's Self-Review type-consistency check.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tools_tests/test_catalog_from_contracts.py -q`
Expected: FAIL — `ToolActionSpec` has no `args`; `from_registry` still emits `action="default"`.

- [ ] **Step 3: Write minimal implementation**

Add `args` to `ToolActionSpec` (`saber/core/tool_catalog.py:11`):

```python
from saber.tools.contract import ArgSpec  # add import


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
```

Rewrite `from_registry` to generate from contracts (replace the body, `saber/core/tool_catalog.py:42-111`):

```python
    @classmethod
    def from_registry(cls, registry: ToolRegistry) -> "ToolCatalog":
        """Build a catalog by reading each registered wrapper's module-level CONTRACT."""

        specs: list[ToolSpec] = []
        for entry in registry.list_entries():
            contract = entry.load_contract()
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
```

Update `to_dict()` per-action block and `to_prompt_text()` to include args:

```python
        # in to_dict()'s action dict, add:
        "args": [
            {"name": a.name, "type": a.type, "required": a.required,
             "default": a.default, "description": a.description,
             "choices": list(a.choices), "example": a.example}
            for a in action.args
        ],
```

```python
        # in to_prompt_text(), after the action line, add for each action:
        for arg in action.args:
            req = "required" if arg.required else "optional"
            lines.append(f"    arg {arg.name}: {arg.type}, {req}; {arg.description}")
```

Delete `_infer_actions`, `_description_for_tool`, `_category_for_tool`, `_phase_for_tool` and the now-unused `_get`/`_to_dict`/`_stringify` helpers ONLY if no longer referenced (verify with `grep`); keep any still used by `to_dict`. Run `grep -n "_infer_actions\|_description_for_tool\|_category_for_tool\|_phase_for_tool" saber/` — expect zero hits after deletion.

- [ ] **Step 4: Run test to verify it passes** (with the xfail note)

Run: `pytest tests/tools_tests/test_catalog_from_contracts.py::test_action_spec_has_args_field -q`
Expected: PASS. (`test_catalog_generates_actions_from_contract` is xfail until F1 Task 1.)

- [ ] **Step 5: Verify no `action="default"` anywhere and offline suite still green**

Run: `grep -rn 'action="default"' saber/ ; make unit`
Expected: grep prints nothing; `make unit` green (contract-less tools are simply absent from the catalog for now).

- [ ] **Step 6: Commit**

```bash
git add saber/core/tool_catalog.py tests/tools_tests/test_catalog_from_contracts.py
git commit -m "feat(catalog): generate ToolCatalog from tool contracts; drop _infer_actions"
```

### Task F0.5: `LlmDecider._validate_args` + prompt update `[opus]`

**Files:** Modify `saber/agents/deciders/llm.py`; Modify `prompts/next_action.txt` (locate with `find . -name next_action.txt`); Test `tests/agent_tests/test_llm_decider_validate_args.py`.

**Interfaces:**
- Consumes: `ToolCatalog` with `ToolActionSpec.args` (F0.4).
- Produces: `LlmDecider._validate_args(tool_name, action, args) -> list[str]` (empty list = valid). Called in `decide()` before returning a TOOL action; a non-empty result returns a STOP/`_error` with the joined messages.

- [ ] **Step 1: Write the failing test**

```python
# tests/agent_tests/test_llm_decider_validate_args.py
from saber.agents.deciders.llm import LlmDecider
from saber.core.tool_catalog import ToolCatalog, ToolSpec, ToolActionSpec
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/agent_tests/test_llm_decider_validate_args.py -q`
Expected: FAIL — `_validate_args` does not exist.

- [ ] **Step 3: Write minimal implementation** — add to `LlmDecider` and wire into `_parse` (before returning the TOOL action, `saber/agents/deciders/llm.py:78`):

```python
    def _validate_args(self, tool_name: Any, action: Any, args: dict[str, Any]) -> list[str]:
        """Return a list of validation errors ([] = valid) for the proposed args."""

        spec = None
        for tool in self.tool_catalog.tools:
            if tool.name == tool_name:
                spec = next((a for a in tool.actions if a.action == action), None)
                break
        if spec is None:
            return [f"unknown tool/action: {tool_name}/{action}"]

        errors: list[str] = []
        known = {arg.name: arg for arg in spec.args}
        for name in args:
            if name not in known:
                errors.append(f"unknown arg: {name}")
        for arg in spec.args:
            if arg.required and args.get(arg.name) in (None, ""):
                errors.append(f"missing required arg: {arg.name}")
                continue
            if arg.name not in args or args[arg.name] is None:
                continue
            value = args[arg.name]
            if arg.type == "int" and not isinstance(value, int):
                errors.append(f"arg {arg.name} must be int")
            elif arg.type == "bool" and not isinstance(value, bool):
                errors.append(f"arg {arg.name} must be bool")
            elif arg.type == "list[str]" and not isinstance(value, list):
                errors.append(f"arg {arg.name} must be list[str]")
            elif arg.type == "enum" and arg.choices and value not in arg.choices:
                errors.append(f"arg {arg.name} must be one of {arg.choices}")
        return errors
```

In `_parse`, replace the `_catalog_has` gate with validation:

```python
        args = raw.get("args") if isinstance(raw.get("args"), dict) else {}
        errors = self._validate_args(tool_name, tool_action, args)
        if errors:
            return self._stop("; ".join(errors))
        # ...then build ProposedAction with args=args
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/agent_tests/test_llm_decider_validate_args.py -q`
Expected: PASS

- [ ] **Step 5: Update the prompt** — in `prompts/next_action.txt`: (1) add to the JSON schema block an `"args"` object described as "the exact args for the chosen action, matching the catalog's arg schema for that action"; (2) add to Hard rules: "Provide exactly the required args for the chosen action and no unknown args; types must match the arg schema." Verify with `grep -c args prompts/next_action.txt` ≥ 1.

- [ ] **Step 6: Commit**

```bash
git add saber/agents/deciders/llm.py prompts/next_action.txt tests/agent_tests/test_llm_decider_validate_args.py
git commit -m "feat(decider): validate proposed args against contract before dispatch"
```

### Task F0.6: New `MissionState` models + list fields `[opus]`

**Files:** Modify `saber/models/mission_state.py`; Test `tests/model_tests/test_mission_state_new_kinds.py`.

**Interfaces:**
- Produces: `KnownShare`, `KnownAccount`, `KnownSession`, `KnownLoot`, `KnownFlag`, `MissionNote` pydantic models; `MissionState` gains `shares/accounts/sessions/loot/flags/notes` list fields (default `[]`); `to_summary_dict()["counts"]` gains the six counts.

- [ ] **Step 1: Write the failing test**

```python
# tests/model_tests/test_mission_state_new_kinds.py
from saber.models.mission_state import (
    MissionState, KnownShare, KnownAccount, KnownSession, KnownLoot, KnownFlag, MissionNote,
)
from saber.models.target import Target


def test_new_lists_default_empty_and_counts_present():
    st = MissionState(session_id="s", target=Target(host="127.0.0.1"))
    assert st.shares == [] and st.accounts == [] and st.sessions == []
    assert st.loot == [] and st.flags == [] and st.notes == []
    counts = st.to_summary_dict()["counts"]
    for key in ("shares", "accounts", "sessions", "loot", "flags", "notes"):
        assert counts[key] == 0


def test_new_models_construct():
    KnownShare(host="10.0.0.1", name="ADMIN$", type="smb", access="read")
    KnownAccount(username="admin", domain="CORP")
    KnownSession(host="10.0.0.1", kind="shell", privilege="user")
    KnownLoot(description="id_rsa", kind="key", host="10.0.0.1", path="/root/.ssh/id_rsa")
    KnownFlag(value="FLAG{x}")
    MissionNote(title="note", detail="d")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/model_tests/test_mission_state_new_kinds.py -q`
Expected: FAIL — the new models/fields do not exist.

- [ ] **Step 3: Write minimal implementation** — add models after `KnownVuln` (`saber/models/mission_state.py:89`):

```python
class KnownShare(BaseModel):
    """A network share discovered on a host."""

    host: str
    name: str
    type: str = "smb"  # smb | nfs | ...
    access: str = "none"  # read | write | none
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownAccount(BaseModel):
    """A user/computer account discovered (distinct from a usable credential)."""

    username: str
    domain: str | None = None
    host: str | None = None
    source: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownSession(BaseModel):
    """An interactive foothold established on a host."""

    host: str
    kind: str = "shell"  # shell | meterpreter | winrm | ssh
    user: str | None = None
    privilege: str = "user"  # user | root | system
    ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownLoot(BaseModel):
    """A collected artifact of value (file/hash/key/config)."""

    description: str
    kind: str = "file"  # file | hash | key | config
    host: str | None = None
    path: str | None = None
    evidence_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownFlag(BaseModel):
    """A captured flag / proof token."""

    value: str
    host: str | None = None
    location: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MissionNote(BaseModel):
    """Free-form knowledge the decider should see (e.g. custom_cli output)."""

    title: str
    detail: str = ""
    severity: str = "info"
    refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
```

Add the list fields to `MissionState` (after `vulns`, `saber/models/mission_state.py:134`):

```python
    shares: list[KnownShare] = Field(default_factory=list)
    accounts: list[KnownAccount] = Field(default_factory=list)
    sessions: list[KnownSession] = Field(default_factory=list)
    loot: list[KnownLoot] = Field(default_factory=list)
    flags: list[KnownFlag] = Field(default_factory=list)
    notes: list[MissionNote] = Field(default_factory=list)
```

Add counts to `to_summary_dict()["counts"]`:

```python
                "shares": len(self.shares),
                "accounts": len(self.accounts),
                "sessions": len(self.sessions),
                "loot": len(self.loot),
                "flags": len(self.flags),
                "notes": len(self.notes),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/model_tests/test_mission_state_new_kinds.py -q`
Expected: PASS

- [ ] **Step 5: Back-compat check** — old snapshots must still load. Run: `pytest tests/storage_tests -q` Expected: PASS (new fields default to `[]`).

- [ ] **Step 6: Commit**

```bash
git add saber/models/mission_state.py tests/model_tests/test_mission_state_new_kinds.py
git commit -m "feat(state): add share/account/session/loot/flag/note models and lists"
```

### Task F0.7: `StateMerger._MERGERS` registry + new-kind branches `[opus]`

**Files:** Modify `saber/core/state_merger.py`; Test `tests/orchestration_tests/test_state_merger_new_kinds.py`.

**Interfaces:**
- Consumes: new models (F0.6).
- Produces: `StateMerger._MERGERS: dict[str, Callable]` keyed by canonical kind; `merge()` grows `shares/accounts/sessions/loot/flags/notes`. Dedupe keys (spec §3.3): `share`=`(host,name)`; `account`=`(domain,username)`; `session`=`(host,kind,user)`; `loot`=`(host,path,kind)`; `flag`=`value`; `note`=`title`.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_state_merger_new_kinds.py
from saber.core.state_merger import StateMerger
from saber.models.mission_state import MissionState, AttemptedAction
from saber.models.target import Target


def _merge(obs):
    st = MissionState(session_id="s", target=Target(host="127.0.0.1"))
    at = AttemptedAction(tool_name="t", action="a", args={}, success=True)
    return StateMerger().merge(st, obs, at)


def test_merges_share_account_session_loot_flag_note():
    obs = [
        {"kind": "share", "data": {"host": "10.0.0.1", "name": "ADMIN$", "access": "read"}},
        {"kind": "account", "data": {"username": "admin", "domain": "CORP"}},
        {"kind": "session", "data": {"host": "10.0.0.1", "kind": "shell", "user": "svc"}},
        {"kind": "loot", "data": {"description": "id_rsa", "kind": "key", "path": "/r/.ssh/id_rsa", "host": "10.0.0.1"}},
        {"kind": "flag", "data": {"value": "FLAG{x}"}},
        {"kind": "note", "data": {"title": "obs", "detail": "text"}},
    ]
    st = _merge(obs)
    assert len(st.shares) == 1 and len(st.accounts) == 1 and len(st.sessions) == 1
    assert len(st.loot) == 1 and len(st.flags) == 1 and len(st.notes) == 1


def test_dedupe_by_key():
    obs = [{"kind": "flag", "data": {"value": "FLAG{x}"}}] * 3
    assert len(_merge(obs).flags) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/orchestration_tests/test_state_merger_new_kinds.py -q`
Expected: FAIL — new kinds are silently dropped, lists stay empty.

- [ ] **Step 3: Write minimal implementation** — refactor `merge()` to a `_MERGERS` registry and add per-kind mergers. Add imports for the six new models. Introduce accumulator dicts and dispatch:

```python
    def merge(self, state, parsed_observations, attempt, evidence_refs=None, finding_refs=None):
        acc = {
            "host": {h.address: h for h in state.hosts},
            "service": {s.key: s for s in state.services},
            "technology": {(t.host, t.name): t for t in state.technologies},
            "credential": {(c.username, c.host, c.service): c for c in state.credentials},
            "vuln": {self._vuln_key(v.title, v.host, v.port): v for v in state.vulns},
            "share": {(s.host, s.name): s for s in state.shares},
            "account": {(a.domain, a.username): a for a in state.accounts},
            "session": {(s.host, s.kind, s.user): s for s in state.sessions},
            "loot": {(loot_.host, loot_.path, loot_.kind): loot_ for loot_ in state.loot},
            "flag": {f.value: f for f in state.flags},
            "note": {n.title: n for n in state.notes},
        }
        for observation in parsed_observations:
            kind = str(observation.get("kind") or "").lower()
            data = observation.get("data") or {}
            if not isinstance(data, dict):
                continue
            merger = self._MERGERS.get(kind)
            if merger is None:
                continue
            merger(self, acc, data, evidence_refs or [])

        updated = state.record_attempt(attempt)
        return updated.model_copy(update={
            "hosts": list(acc["host"].values()),
            "services": list(acc["service"].values()),
            "technologies": list(acc["technology"].values()),
            "credentials": list(acc["credential"].values()),
            "vulns": list(acc["vuln"].values()),
            "shares": list(acc["share"].values()),
            "accounts": list(acc["account"].values()),
            "sessions": list(acc["session"].values()),
            "loot": list(acc["loot"].values()),
            "flags": list(acc["flag"].values()),
            "notes": list(acc["note"].values()),
            "evidence_refs": self._extend_unique(state.evidence_refs, evidence_refs),
            "finding_refs": self._extend_unique(state.finding_refs, finding_refs),
        })
```

Keep the existing `_merge_host`/`_merge_service`/`_merge_technology`/`_merge_credential`/`_merge_vuln` bodies but re-sign them as `(self, acc, data, evidence_refs)` reading `acc["host"]` etc. Add new mergers `_merge_share`, `_merge_account`, `_merge_session`, `_merge_loot`, `_merge_flag`, `_merge_note` following the dedupe keys. Then declare the registry as a class attribute:

```python
    _MERGERS = {
        "host": _merge_host, "service": _merge_service, "technology": _merge_technology,
        "credential": _merge_credential, "vuln": _merge_vuln, "share": _merge_share,
        "account": _merge_account, "session": _merge_session, "loot": _merge_loot,
        "flag": _merge_flag, "note": _merge_note,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/orchestration_tests/test_state_merger_new_kinds.py -q`
Expected: PASS

- [ ] **Step 5: Regression** — Run: `pytest tests/orchestration_tests -q` Expected: PASS (existing five-kind behavior unchanged).

- [ ] **Step 6: Commit**

```bash
git add saber/core/state_merger.py tests/orchestration_tests/test_state_merger_new_kinds.py
git commit -m "feat(merger): _MERGERS registry + share/account/session/loot/flag/note kinds"
```

### Task F0.8: `_MERGERS` key set == canonical vocabulary test `[opus]`

**Files:** Create `saber/core/canonical_kinds.py`; Modify `saber/core/state_merger.py` (import the vocabulary); Test `tests/orchestration_tests/test_canonical_vocabulary.py`.

**Interfaces:**
- Produces: `CANONICAL_KINDS: frozenset[str]` — the single source of truth for "what kinds exist" (the 11 rows in the Shared conventions table). `StateMerger._MERGERS` key set MUST equal it.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_canonical_vocabulary.py
from saber.core.canonical_kinds import CANONICAL_KINDS
from saber.core.state_merger import StateMerger


def test_mergers_cover_exactly_the_canonical_vocabulary():
    assert set(StateMerger._MERGERS.keys()) == set(CANONICAL_KINDS)


def test_vocabulary_is_the_expected_eleven():
    assert CANONICAL_KINDS == frozenset({
        "host", "service", "technology", "credential", "vuln",
        "share", "account", "session", "loot", "flag", "note",
    })
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/orchestration_tests/test_canonical_vocabulary.py -q`
Expected: FAIL — `saber.core.canonical_kinds` does not exist.

- [ ] **Step 3: Write minimal implementation**

```python
# saber/core/canonical_kinds.py
"""The fixed canonical observation-kind vocabulary (spec §3.2)."""

from __future__ import annotations

CANONICAL_KINDS: frozenset[str] = frozenset({
    "host", "service", "technology", "credential", "vuln",
    "share", "account", "session", "loot", "flag", "note",
})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/orchestration_tests/test_canonical_vocabulary.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add saber/core/canonical_kinds.py tests/orchestration_tests/test_canonical_vocabulary.py
git commit -m "feat(merger): pin canonical-kind vocabulary and assert _MERGERS coverage"
```

### Task F0.9: Growing contract-consistency test `[opus]`

**Files:** Create `tests/tools_tests/test_contract_consistency.py`.

**Interfaces:**
- Consumes: `build_default_registry`, `ToolCatalog`, `CANONICAL_KINDS`, each wrapper's `CONTRACT`.
- Produces: `_MIGRATED_TOOLS: set[str]` — the set of tool names that must satisfy full consistency. **Every F1–F6 per-tool task appends its tool name here** as its migration lands. This is the "gate that grows per phase" the brief requires; contract-less tools are simply not yet in the set, so `make unit` stays green mid-migration.

- [ ] **Step 1: Write the failing test** (starts with an empty migrated set → trivially passes; the assertions bite as names are added)

```python
# tests/tools_tests/test_contract_consistency.py
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
            assert kind in CANONICAL_KINDS, f"{tool_name}.{action.action} emits non-canonical {kind}"


def test_no_default_action_and_all_migrated_have_contracts():
    reg = build_default_registry()
    for tool_name in _MIGRATED_TOOLS:
        contract = reg.get(tool_name).load_contract()
        assert all(a.action != "default" for a in contract.actions)
```

> **Buildability note:** the "every action is buildable by `build_command`" assertion (spec §8) requires constructing valid args per action, which is action-specific. Implement it in each per-tool golden-command test (template step c) rather than generically here — a generic call cannot supply each action's required args. This consistency test covers tool_name/category/phase/canonical-kinds; the golden-command tests cover buildability.

- [ ] **Step 2: Run test to verify it fails/passes** — with an empty set it PASSES vacuously.

Run: `pytest tests/tools_tests/test_contract_consistency.py -q`
Expected: PASS (0 parametrized cases). This is intentional: the gate grows as tools migrate.

- [ ] **Step 3: Commit**

```bash
git add tests/tools_tests/test_contract_consistency.py
git commit -m "test(tools): growing contract-consistency gate (_MIGRATED_TOOLS)"
```

### Task F0.10: Canonical schema docstrings + assertion helper `[opus]`

**Files:** Modify `saber/parsers/base.py` (docstring + `metadata` kwarg), `saber/core/state_merger.py` (docstring); Modify `tests/conftest.py` (append helpers from Shared conventions).

- [ ] **Step 1: Write the failing test**

```python
# tests/parser_tests/test_base_parser.py  (append)
from saber.parsers.base import BaseParser


class _P(BaseParser):
    source_tool = "x"
    def parse_text(self, text, metadata=None):
        from saber.parsers.base import ParserResult
        return ParserResult(source_tool="x", success=True)


def test_parse_text_accepts_metadata_kwarg():
    assert _P().parse_text("hi", metadata={"target": "127.0.0.1"}).success
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/parser_tests/test_base_parser.py::test_parse_text_accepts_metadata_kwarg -q`
Expected: FAIL — base `parse_text(self, text)` rejects `metadata`.

- [ ] **Step 3: Write minimal implementation** — change base signatures (`saber/parsers/base.py:132,137`):

```python
    def parse_text(self, text: str, metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse text output. `metadata` may carry target/url context for host derivation."""
        raise NotImplementedError(f"{type(self).__name__}.parse_text is not implemented.")

    def parse_json(self, data: dict[str, Any] | list[Any],
                   metadata: dict[str, Any] | None = None) -> ParserResult:
        """Parse JSON-compatible data. `metadata` may carry target/url context."""
        raise NotImplementedError(f"{type(self).__name__}.parse_json is not implemented.")
```

Update `parse_file` internal calls to pass `metadata` through (it already reads it via the registry TypeError fallback; make it explicit by threading a `metadata` param into `parse_file`). Add the canonical-schema docstring (the Shared-conventions table) to the module docstring of `saber/parsers/base.py` and to `StateMerger`'s class docstring. Append `assert_observation`/`merge_observations` to `tests/conftest.py` (code in Shared conventions).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/parser_tests/test_base_parser.py -q`
Expected: PASS

- [ ] **Step 5: Existing parsers still satisfy the base** — the 5 existing parsers override `parse_text(self, text)` without `metadata`. Add `metadata=None` to each of their signatures now (nmap, whatweb, nuclei, searchsploit, bloodhound) so the registry can always pass `metadata`. Run: `pytest tests/parser_tests -q` Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add saber/parsers/base.py saber/core/state_merger.py tests/conftest.py saber/parsers/*.py tests/parser_tests/test_base_parser.py
git commit -m "feat(parsers): standardize optional metadata kwarg; document canonical schema; add test helpers"
```

**F0 exit criteria:** `make unit` green; catalog generates only from contracts; decider validates args; new kinds merge; vocabulary pinned; consistency gate in place (empty). No tool is fully migrated yet.

---

## F1 — Prove the pattern + web normalization `[opus]` lead, `[sonnet]` per-tool

Migrate the 11 already-correct tools (nmap, masscan, subfinder, amass, dnsrecon, theharvester, whatweb, nuclei, nikto, searchsploit, sqlmap) to `CONTRACT` with **zero behavior regression** (golden-command tests assert the exact existing command first, then add `CONTRACT`). Fix web normalization so a dvwa mission grows state. Tasks F1.1 (nmap) and F1.5 (whatweb) are `[opus]` because they set the reference pattern and the load-bearing regression; the other nine are `[sonnet]`.

### Task F1.1: nmap — CONTRACT + `-Pn` + golden command `[opus]`

**Files:** Modify `saber/tools/recon/nmap.py`; Test `tests/tools_tests/test_nmap_contract.py`.

This task realises the worked template example above and fixes the raw-socket bug (spec §2.3).

- [ ] **Step 1: Write the failing golden-command test** — exactly the `test_service_scan_command_includes_pn` test from the worked template (asserts `-Pn` present).
- [ ] **Step 2: Run** `pytest tests/tools_tests/test_nmap_contract.py -q` → FAIL (current command has no `-Pn`).
- [ ] **Step 3: Add `-Pn`** to the `service_scan` branch (`saber/tools/recon/nmap.py:137`): `command = ["nmap", "-sT", "-sV", "-sC", "-Pn"]`. Add `-Pn` to `udp_scan` too (`command = ["nmap", "-sU", "-Pn"]`). Add the `CONTRACT` block from the worked template.
- [ ] **Step 4: Run** `pytest tests/tools_tests/test_nmap_contract.py -q` → PASS.
- [ ] **Step 5: Enable the catalog test** — remove the `@pytest.mark.xfail` on `test_catalog_generates_actions_from_contract` (F0.4). Run: `pytest tests/tools_tests/test_catalog_from_contracts.py -q` → PASS.
- [ ] **Step 6: Add `"nmap"` to `_MIGRATED_TOOLS`** (F0.9). Run: `pytest tests/tools_tests/test_contract_consistency.py -q` → PASS.
- [ ] **Step 7: Commit** `feat(tools): migrate nmap to CONTRACT; add -Pn (raw-socket fix)`.

### Task F1.2: nmap parser — canonical `host.address` alignment `[opus]`

**Files:** Modify `saber/parsers/nmap.py`; Test `tests/parser_tests/test_nmap.py`.

The parser emits host data under key `"host"` (`saber/parsers/nmap.py:53,96,210`) but the canonical `host` schema and `_merge_host` expect `address`. `_merge_host` already reads `data.get("address") or data.get("host")` so merge works, but tests and the canonical schema require `address`.

- [ ] **Step 1** Write the template's parser test `test_nmap_xml_emits_host_and_service_and_grows_state` (asserts `hosts[0]["data"]["address"]`).
- [ ] **Step 2** Run → FAIL (host obs uses `"host"` not `"address"`).
- [ ] **Step 3** In each host `ParsedObservation`, set `data={"address": address, ...}` (keep `"host"` too for back-compat if any test needs it). Service observations already carry `host` — leave them.
- [ ] **Step 4** Run → PASS.
- [ ] **Step 5** Commit `fix(parser): nmap host observations use canonical address key`.

### Task F1.3–F1.4: nuclei & nikto — CONTRACT + `vuln` kind alignment `[sonnet]`

**Files:** Modify `saber/tools/web/nuclei.py`, `saber/tools/web/nikto.py`; Modify `saber/parsers/nuclei.py` (verify emits `kind="vuln"` with `title`/`severity`/`identifier`); Create `saber/parsers/nikto.py`; Register nikto in `default_parser_entries()`; Tests `tests/tools_tests/test_nuclei_contract.py`, `test_nikto_contract.py`, `tests/parser_tests/test_nikto.py`.

Apply the migration template. Concrete specifics:
- **nuclei**: action `template_scan`; args `ArgSpec("target","str",required=True)`, `ArgSpec("severity","str",default="low,medium,high,critical")`; risk `medium`, `requires_approval=True`; `emits_kinds=("vuln",)`; parser `nuclei` (exists — verify each observation is `kind="vuln"` with `data={"title","host","severity","identifier","confirmed"}`; fix if it emits another kind).
- **nikto**: action `web_scan`; args `ArgSpec("url"|"target","str",required=True)` (read the wrapper for the real arg name), `ArgSpec("port","str")`; risk `medium`, `requires_approval=True`; `emits_kinds=("vuln",)`. New parser `NiktoParser` maps each Nikto finding line to `kind="vuln"` (`title`=finding text, `severity`=from `severity_from_string`, `host`=from `metadata["target"]`). Fixture `tests/fixtures/sample_nikto_output.txt` (a few real Nikto `+ OSVDB-...:` lines).
- Add `"nuclei"`, `"nikto"` to `_MIGRATED_TOOLS`. One commit per tool.

### Task F1.5: whatweb parser rewrite — one `technology` per tech with `host` `[opus]`

**Files:** Modify `saber/tools/recon/whatweb.py` (CONTRACT), `saber/parsers/whatweb.py` (rewrite); Modify `tests/fixtures/` (add `sample_whatweb_output.json`); Test `tests/parser_tests/test_whatweb.py`.

This is the load-bearing normalization fix (spec §2.3, §3.2): today whatweb emits `kind="web_technology"` (dropped by `StateMerger`) packing all techs into one list. It must emit one `kind="technology"` observation per tech, with `host` derived from the target/URL and a real `version`, plus a `kind="service"` for the HTTP port.

- [ ] **Step 1: Write the failing test** (the permanent dvwa regression test)

```python
# tests/parser_tests/test_whatweb.py  (replace web_technology assertions)
from pathlib import Path
from saber.parsers.whatweb import WhatWebParser
from tests.conftest import assert_observation, merge_observations


def test_whatweb_emits_one_technology_per_tech_with_host_and_grows_state():
    text = Path("tests/fixtures/sample_whatweb_output.json").read_text()
    result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})
    obs = [o.to_dict() for o in result.observations]
    techs = [o for o in obs if o["kind"] == "technology"]
    assert len(techs) >= 2  # e.g. Apache, PHP
    for t in techs:
        assert t["data"]["host"] == "127.0.0.1"
        assert t["data"]["name"]
    apache = next(t for t in techs if t["data"]["name"] == "Apache")
    assert_observation(apache, kind="technology", data_subset={"host": "127.0.0.1", "version": "2.4.7"})
    state = merge_observations(obs, tool="whatweb", action="fingerprint")
    assert len(state.technologies) >= 2
    assert len(state.services) >= 1  # HTTP service on port 80
```

Fixture `tests/fixtures/sample_whatweb_output.json` — a real whatweb `--log-json` record for `http://127.0.0.1` whose `plugins` include `Apache` (string `["Apache"]`, version `["2.4.7"]`), `PHP` (version `["5.5.9"]`), `HTTPServer`, `HTTPStatus 200`.

- [ ] **Step 2: Run** → FAIL (parser emits `web_technology`, no per-tech `host`).
- [ ] **Step 3: Rewrite `WhatWebParser`** — for each JSON record: derive `host` from `record.target`/`url` or `metadata["target"]` (strip scheme/path via `urllib.parse.urlparse(...).hostname`). For each plugin that is a real technology (skip `Title/IP/Country/HTTPStatus/HTTPServer/RedirectLocation`), emit `ParsedObservation(kind="technology", data={"host": host, "name": plugin_name, "version": <first version string or None>}, metadata={"url": url})`. Emit one `kind="service"` `data={"host": host, "port": <from url or 80/443>, "protocol":"tcp", "service":"http", "product": HTTPServer, "version": server_version}`. Emit a `kind="technology"` for the HTTPServer product too. Keep `parse_text` JSON-first with the stdout fallback also emitting per-tech `technology` observations (host from `metadata["target"]`). Add CONTRACT: actions `fingerprint`/`aggressive`/`list_scan` (match the wrapper — read it), args `ArgSpec("url"|"target","str",required=True)`, risk `low`, `emits_kinds=("technology","service")`, parser `whatweb`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5** Add `"whatweb"` to `_MIGRATED_TOOLS`; run consistency + `make unit` → PASS.
- [ ] **Step 6: Commit** `fix(parser): whatweb emits canonical technology+service observations`.

### Task F1.6: searchsploit & sqlmap — CONTRACT + parser verification `[sonnet]`

**Files:** Modify `saber/tools/exploitation/searchsploit.py`, `saber/tools/web/sqlmap.py`; verify `saber/parsers/searchsploit.py`; Tests `tests/tools_tests/test_searchsploit_contract.py`, `test_sqlmap_contract.py`.

Apply template. Specifics:
- **searchsploit**: action `exploit_search`; args `ArgSpec("query","str",required=True)`; risk `low`; `emits_kinds=("note",)` (exploit references become `kind="note"` — refs to EDB ids). Verify/adjust `SearchSploitParser` to emit `kind="note"` (title=exploit title, refs=[edb-id]) rather than a dropped kind.
- **sqlmap**: read the wrapper for real actions (`injection_test` etc.); args `ArgSpec("url","str",required=True)` + real optionals; risk `high`, `requires_approval=True`; `emits_kinds=("vuln","note")`. New parser `SqlmapParser` (F2 may extend) emitting `kind="vuln"` when injection confirmed; register it. Fixture `sample_sqlmap_output.txt`.
- Add both to `_MIGRATED_TOOLS`.

### Task F1.7: masscan, subfinder, amass, dnsrecon, theharvester — CONTRACT only (golden command, no behavior change) `[sonnet]`

**Files:** Modify each wrapper module under `saber/tools/recon/`; Tests `tests/tools_tests/test_<tool>_contract.py` each.

These five are among the "11 correct" for *catalog* purposes but currently have **no registered parser**. F1 migrates only their `CONTRACT` + golden command (zero behavior change); their **parsers are added in F2** (see F2). Specifics per tool (read each wrapper's `build_command` for exact actions/args; assert the current exact command in the golden test *before* adding CONTRACT):
- **masscan**: action `top_ports` (or wrapper's real name); args `target` (req), `ports`, `rate`; risk `medium`, `requires_approval=True`; `emits_kinds=("host","service")`; parser `masscan` (added F2).
- **subfinder**: action `passive`; args `domain` (req); risk `low`; `emits_kinds=("host",)`; parser `subfinder` (F2).
- **amass**: action `passive_enum`; args `domain` (req); risk `low`; `emits_kinds=("host",)`; parser `amass` (F2).
- **dnsrecon**: action `standard`; args `domain` (req); risk `low`; `emits_kinds=("host",)`; parser `dnsrecon` (F2).
- **theharvester**: action `search`; args `domain` (req), `source` (default `all`); risk `low`; `emits_kinds=("host","account","note")`; parser `theharvester` (F2).
- Add all five to `_MIGRATED_TOOLS`. One commit each.

### Task F1.8: F1 exit — dvwa web regression test `[opus]`

**Files:** Test `tests/orchestration_tests/test_dvwa_web_regression.py`.

Permanent regression proving the loop's central invariant. Uses the whatweb fixture through the full parse→merge path (offline; no Docker).

- [ ] **Step 1: Write the test**

```python
# tests/orchestration_tests/test_dvwa_web_regression.py
from pathlib import Path
from saber.parsers.whatweb import WhatWebParser
from tests.conftest import merge_observations


def test_dvwa_whatweb_grows_technologies_and_services():
    text = Path("tests/fixtures/sample_whatweb_output.json").read_text()
    result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})
    obs = [o.to_dict() for o in result.observations]
    state = merge_observations(obs, tool="whatweb", action="fingerprint")
    assert len(state.technologies) > 0  # was 0 pre-F1 (spec §2.3)
    assert len(state.services) > 0
```

- [ ] **Step 2: Run** → PASS (depends on F1.5). **Step 3: Commit** `test(loop): permanent dvwa web-normalization regression`.

**F1 exit criteria:** all 11 tools in `_MIGRATED_TOOLS`; `make unit` green; dvwa regression proves `technologies>0` and `services>0`.

---

## F2 — remaining recon/network `[sonnet]` (parallelizable)

Each task = apply the migration template. **Independent; dispatch in parallel** after F1. Two groups: (A) add parsers for the five F1 CONTRACT-only recon tools; (B) full migration of the never-contracted recon/network tools.

### Group A — parsers for masscan / subfinder / amass / dnsrecon / theharvester `[sonnet]`

Contracts already landed in F1.7; add the parser (template steps d–g) each:
- **masscan** → `saber/parsers/masscan.py`, `kind="host"`+`kind="service"` from masscan `-oL`/list output (`open tcp <port> <ip>` lines → `service` `data={host,port,protocol:"tcp",service,state:"open"}`). Fixture `sample_masscan_output.txt`.
- **subfinder** → `saber/parsers/subfinder.py`, `kind="host"` per discovered subdomain (`data={"address": <resolved-or-name>, "hostnames":[name]}`). Fixture `sample_subfinder_output.txt` (one host per line).
- **amass** → `saber/parsers/amass.py`, `kind="host"` per line (`name` + optional resolved IP). Fixture `sample_amass_output.txt`.
- **dnsrecon** → `saber/parsers/dnsrecon.py`, `kind="host"` per A/AAAA record (`address`=IP, `hostnames`=[name]); CNAME/MX → `kind="note"`. Fixture `sample_dnsrecon_output.json`.
- **theharvester** → `saber/parsers/theharvester.py`, emails → `kind="account"` (`username`=local part, `metadata={email}`); hosts → `kind="host"`; a summary `kind="note"`. Fixture `sample_theharvester_output.json`.

Register each in `default_parser_entries()`. `_MIGRATED_TOOLS` already contains these; add a parser→merge test per tool.

### Group B — full migration of feroxbuster / zap_api / snmpwalk / responder / bettercap / openvas `[sonnet]`

Apply the full template (a–g) each:
- **feroxbuster** (`saber/tools/web/feroxbuster.py`): action `content_discovery` (read wrapper); args `url` (req), `wordlist`; risk `medium`, `requires_approval=True`; `emits_kinds=("note",)` (discovered paths → `kind="note"` with `title=path`, `detail=status`). Parser `feroxbuster` over `--json` lines. Fixture `sample_feroxbuster_output.json`.
- **zap_api** (`saber/tools/web/zap_api.py`, alias `zap`): actions per wrapper (spider/active_scan); args `target` (req); risk `high`, `requires_approval=True`; `emits_kinds=("vuln","note")`. Parser maps ZAP alerts → `kind="vuln"`. Fixture `sample_zap_output.json`.
- **snmpwalk** (`saber/tools/network/snmpwalk.py`): action `enumerate`; args `target` (req), `community` (default `public`); risk `medium`, `requires_approval=True`; `emits_kinds=("note","account")`. Parser → OIDs to `kind="note"`, discovered users → `kind="account"`. Fixture `sample_snmpwalk_output.txt`.
- **responder** (`saber/tools/network/responder.py`): action `capture`; args `interface` (req); risk `high`, `requires_approval=True`; `emits_kinds=("credential","note")`. Parser → captured hashes → `kind="credential"` (`kind="hash"`). Fixture `sample_responder_output.txt`.
- **bettercap** (`saber/tools/network/bettercap.py`): action `recon` (read wrapper); args `interface`|`target`; risk `high`, `requires_approval=True`; `emits_kinds=("host","note")`. Parser → discovered hosts → `kind="host"`. Fixture `sample_bettercap_output.txt`.
- **openvas** (`saber/tools/network/openvas_api.py`, alias `openvas_api`): actions per wrapper (start_scan/get_results); args `target` (req); risk `high`, `requires_approval=True`; `emits_kinds=("vuln",)`. Parser → GVM results → `kind="vuln"`. Fixture `sample_openvas_output.xml`.
- Add each to `_MIGRATED_TOOLS`; one commit per tool.

---

## F3 — Active Directory tools `[sonnet]` (parallelizable)

Each task = template. Emits `share`/`account`/`session`/`credential`.
- **bloodhound** (`saber/tools/active_directory/bloodhound.py`): actions per wrapper (collect); args `domain` (req), `dc_ip`, `username`, `password`; risk `high`, `requires_approval=True`; `emits_kinds=("account","note")`. Parser `bloodhound` exists — verify/extend it to emit `kind="account"` per user node and `kind="note"` for attack paths (currently registered; read `saber/parsers/bloodhound.py`). Fixture already exists: `tests/fixtures/sample_bloodhound_output.json`.
- **netexec** (`saber/tools/active_directory/netexec.py`, alias `nxc`): actions per wrapper (smb_enum/shares/users); args `target` (req), `username`, `password`; risk `high`, `requires_approval=True`; `emits_kinds=("share","account","session","credential")`. Parser → shares (`kind="share"` `data={host,name,access}`), users (`kind="account"`), successful auth (`kind="credential"` validated + `kind="session"`). Fixture `sample_netexec_output.txt`.
- **impacket** (`saber/tools/active_directory/impacket.py`): actions per wrapper (secretsdump/psexec/GetUserSPNs); args `target` (req), `username`, `password`, `hashes`; risk `high`, `requires_approval=True`; `emits_kinds=("credential","account","session")`. Parser → dumped hashes → `kind="credential"` (`kind="hash"`); SPN roast → `kind="credential"`; psexec shell → `kind="session"`. Fixture `sample_impacket_secretsdump.txt`.
- **enum4linux** (`saber/tools/network/enum4linux.py`): action `enumerate`; args `target` (req); risk `medium`, `requires_approval=True`; `emits_kinds=("share","account","note")`. New parser → SMB shares → `kind="share"`, users → `kind="account"`. Fixture `sample_enum4linux_output.txt`.
- Add each to `_MIGRATED_TOOLS`; one commit per tool. **Dependency note:** integration (not unit) coverage for netexec/impacket needs the sandbox image (F7).

---

## F4 — exploitation / password / post-exploit / lateral `[sonnet]` (parallelizable)

Each task = template. (searchsploit + sqlmap already migrated in F1.6.)
- **metasploit** (`saber/tools/exploitation/metasploit.py`, alias `msfconsole`): actions per wrapper (run_module/exploit); args `module` (req), `rhosts` (req), `options`; risk `high`, `requires_approval=True`; `emits_kinds=("session","vuln","note")`. Parser → `Meterpreter session N opened` → `kind="session"` (`kind="meterpreter"`, `ref`=session id); `[+]` success → `kind="note"`. Fixture `sample_metasploit_output.txt`.
- **hashcat** (`saber/tools/password/hashcat.py`): action `crack`; args `hash_file` (req), `mode` (int, req), `wordlist`; risk `medium`, `requires_approval=True`; `emits_kinds=("credential",)`. Parser → cracked `hash:plain` lines → `kind="credential"` (`kind="password"`, `secret`=plain, `validated=False`). Fixture `sample_hashcat_output.txt` (potfile-style).
- **john** (`saber/tools/password/john.py`): action `crack`; args `hash_file` (req), `format`, `wordlist`; risk `medium`, `requires_approval=True`; `emits_kinds=("credential",)`. Parser → `--show` output (`user:plain:...`) → `kind="credential"`. Fixture `sample_john_output.txt`.
- **linpeas** (`saber/tools/post_exploit/linpeas.py`): action `run`; args `session_ref`|`target`; risk `high`, `requires_approval=True`; `emits_kinds=("note","loot")`. Parser → PE-vector highlights → `kind="note"` (severity from color/keyword); sensitive files → `kind="loot"`. Fixture `sample_linpeas_output.txt`.
- **winpeas** (`saber/tools/post_exploit/winpeas.py`): action `run`; args like linpeas; risk `high`, `requires_approval=True`; `emits_kinds=("note","loot")`. Parser analogous. Fixture `sample_winpeas_output.txt`.
- **mimikatz** (`saber/tools/post_exploit/mimikatz.py`): action `dump` (sekurlsa::logonpasswords); args `session_ref`|`dump_file`; risk `high`, `requires_approval=True`; `emits_kinds=("credential","account")`. Parser → NTLM/plaintext → `kind="credential"` (`kind="hash"`/`"password"`). Fixture `sample_mimikatz_output.txt`.
- **chisel** (`saber/tools/post_exploit/chisel.py`): actions per wrapper (server/client tunnel); args `server`|`remote`; risk `high`, `requires_approval=True`; `emits_kinds=("note","session")`. Parser → tunnel established → `kind="note"`. Fixture `sample_chisel_output.txt`.
- **plan** (`saber/tools/lateral_movement/plan.py`, alias `lateral_movement_planner`): action `plan`; args `objective`|`target`; risk `low`; `emits_kinds=("note",)`. Parser → planned path → `kind="note"`. Fixture `sample_plan_output.json`. (No meaningful structured output — `note` so state still grows, per spec §4-Pillar-3.)
- **path_validation** (`saber/tools/lateral_movement/path_validation.py`): action `validate`; args `path`|`target`; risk `medium`, `requires_approval=True`; `emits_kinds=("note",)`. Parser → reachability → `kind="note"`. Fixture `sample_path_validation_output.json`.
- **session_checks** (`saber/tools/lateral_movement/session_checks.py`): action `check`; args `target`; risk `low`; `emits_kinds=("session","note")`. Parser → reachable sessions → `kind="session"`. Fixture `sample_session_checks_output.json`.
- Add each to `_MIGRATED_TOOLS`; one commit per tool. **Dependency note:** most F4 tools need real footholds/binaries; unit coverage is fixture-based; live behavior needs F7 + lab targets.

---

## F5 — Reverse engineering + binary exploit `[sonnet]` + one `[opus]` task

### F5 RE tools (template each, `[sonnet]`, parallelizable)
- **file** (`saber/tools/reverse_engineering/file.py`): action `identify`; args `path` (req); risk `low`; `emits_kinds=("note",)`. Parser → file-type line → `kind="note"` (`title`=path, `detail`=type). Fixture `sample_file_output.txt`.
- **strings** (`saber/tools/reverse_engineering/strings.py`): action `extract`; args `path` (req), `min_len` (int); risk `low`; `emits_kinds=("note","loot")`. Parser → interesting strings (URLs, `flag{`, creds) → `kind="loot"`/`kind="note"`. Fixture `sample_strings_output.txt`.
- **checksec** (`saber/tools/reverse_engineering/checksec.py`): action `check`; args `path` (req); risk `low`; `emits_kinds=("note",)`. Parser → NX/PIE/RELRO/Canary → one `kind="note"` (`detail`=protections, `metadata`=flags dict — the binary-exploit loop reads this). Fixture `sample_checksec_output.json`.
- **radare2** (`saber/tools/reverse_engineering/radare2.py`, alias `r2`): actions per wrapper (analyze/disasm); args `path` (req), `command`; risk `medium`, `requires_approval=True`; `emits_kinds=("note",)`. Parser → function list / notable gadgets → `kind="note"`. Fixture `sample_radare2_output.txt`.
- **ghidra_headless** (`saber/tools/reverse_engineering/ghidra_headless.py`, alias `ghidra`): action `analyze`; args `path` (req), `script`; risk `medium`, `requires_approval=True`; `emits_kinds=("note",)`. Parser → decompiled-summary → `kind="note"`. Fixture `sample_ghidra_output.txt`.
- Add each to `_MIGRATED_TOOLS`; one commit per tool.

### Task F5.X: pwntools/gdb binary-exploit iterative loop `[opus]`

**Files:** Create `saber/tools/reverse_engineering/pwntools.py` + `CONTRACT`; register in `default_tool_entries()`; Create `saber/parsers/pwntools.py`; Tests `tests/tools_tests/test_pwntools_contract.py`, `tests/parser_tests/test_pwntools.py`; integration `tests/e2e_tests/test_vulnbin_exploit.py` (gated). Reference lab binary `docker/lab/vulnbin` (a `read()`-overflow C binary with `flag.txt`).

This is `[opus]` because it is the one iterative-reasoning capability, not a stateless wrapper. Design:
- **Contract**: tool `pwntools`, category `reverse_engineering`, phase `exploitation`. Actions: `run_exploit` (args `binary_path` (req), `script_path` (req, a pwntools script authored by the decider), `argv` (list[str])); `debug` (args `binary_path` (req), `gdb_script`). risk `high`, `requires_approval=True`. `emits_kinds=("flag","note")`.
- **Execution stays in-sandbox**: the wrapper builds `["python3", script_path, binary_path]` (pwntools installed in the image, F7) — NO subprocess in the wrapper (invariant). The decider authors the pwntools script via `custom_cli`/an evidence file; the wrapper only runs it in the sandbox.
- **Iterative loop is the DECIDER's job** (F8), not the wrapper: the wrapper is stateless; the loop feeds program output/errors back into `MissionState` as `kind="note"` and the decider revises the script. Frame as *structured iteration, not a solver* (spec §10).
- **Parser** `PwntoolsParser`: scans stdout for `flag{...}`/`FLAG{...}` → `kind="flag"` (`value`, `location`=binary_path); crashes/leaks → `kind="note"`. Fixture `sample_pwntools_output.txt` containing a `flag{...}` line.
- Bite-sized steps: (1) write contract test; (2) golden command `["python3", script_path, binary_path]`; (3) parser flag-extraction test with fixture; (4) merge test asserts `state.flags` grows; (5) add `"pwntools"` to `_MIGRATED_TOOLS`; (6) gated e2e against `docker/lab/vulnbin` asserting a flag is captured (skipped unless `SABER_RUN_DOCKER_E2E=1` AND F7 provides pwntools/gdb); (7) commit.
- **Honest caveat in the plan (spec §10):** proven against the known `vulnbin` overflow only; "attempt general binaries" is best-effort.

---

## F6 — Wireshark / passive capture `[sonnet]`

### Task F6.1: tshark passive capture `[sonnet]`

**Files:** Create `saber/tools/network/tshark.py` + `CONTRACT`; register in `default_tool_entries()` (name `tshark`, alias `wireshark`, category `network`, phase `recon`); Create `saber/parsers/tshark.py`; Tests `tests/tools_tests/test_tshark_contract.py`, `tests/parser_tests/test_tshark.py`.

Apply template. Specifics: action `capture`; args `interface` (req), `duration` (int, default 30), `filter` (BPF); risk `high`, `requires_approval=True` (passive capture slots INTO `RiskGate`, spec §6); `emits_kinds=("note","loot")`. Parser over tshark `-T json`/summary: observed hosts/protocols → `kind="note"`; captured file / credential-bearing packets → `kind="loot"` (`kind="file"`, `path`=pcap). Fixture `sample_tshark_output.json`. Add `"tshark"` to `_MIGRATED_TOOLS`. Commit `feat(tools): add tshark passive-capture wrapper + parser`.

---

## F7 — Sandbox image audit / rebuild `[sonnet]` (parallel from the start)

`docker/Dockerfile.sandbox` already installs: nmap, masscan, amass, subfinder, theharvester, dnsrecon, whatweb, feroxbuster, nuclei, sqlmap, nikto, zaproxy, enum4linux-ng, snmp, responder, bettercap, metasploit-framework, exploitdb, hashcat, john, bloodhound.py, crackmapexec, netexec, impacket-scripts. **Missing** for the contracted arsenal: `radare2`, `ghidra` (headless), `gdb`, `python3-pwntools`, `tshark`/`wireshark-common`, `checksec`, `chisel`, `openvas`/`gvm`, `linpeas`/`winpeas` (download scripts), `mimikatz` (Windows/wine — document as N/A in the Linux sandbox).

### Task F7.1: image-manifest test (gated) `[sonnet]`

**Files:** Create `tests/e2e_tests/test_image_manifest.py`.

- [ ] **Step 1:** Write a gated test that, for every tool in `_MIGRATED_TOOLS` with an expected binary, runs `which <binary>` inside the sandbox image and asserts exit 0. Skip unless `SABER_RUN_DOCKER_E2E=1`. Map tool→binary (e.g. `nmap→nmap`, `netexec→nxc`, `radare2→r2`, `ghidra_headless→ghidra`  or `analyzeHeadless`, `tshark→tshark`, `pwntools→python3 -c "import pwn"`). Tools with no binary (`plan`, `path_validation`, `session_checks`, `custom_cli`) are excluded.
- [ ] **Step 2:** Run (gated) → initially FAIL for the missing tools above.
- [ ] **Step 3:** Commit the test.

### Task F7.2: add missing tool groups to the Dockerfile `[sonnet]`

**Files:** Modify `docker/Dockerfile.sandbox`; Modify `scripts/install_kali_deps.sh` (keep in sync per the Dockerfile comment).

- [ ] Add an apt layer: `radare2 gdb tshark checksec` (and `wireshark-common`; set `DEBIAN_FRONTEND` so tshark installs non-interactively). Add `python3-pwntools` (or `pip install --break-system-packages pwntools`). Add a download layer for `linpeas.sh`/`winpeas` into `/opt/peass`. Add `chisel` (download release binary). Document `ghidra` headless install (download + `analyzeHeadless` on PATH) and mark `mimikatz` N/A on Linux (wrapper still contracts it; image note only).
- [ ] Rebuild locally: `docker build -f docker/Dockerfile.sandbox -t saber-sandbox:f7 docker/` → success.
- [ ] Run the gated manifest test against the new tag → PASS.
- [ ] Commit `chore(sandbox): add radare2/gdb/tshark/pwntools/checksec/chisel/peass to image`. Publishing `ghcr.io/atharvkashyap/saber-sandbox:kali-*` is a release step outside unit CI.

**Honest dependency note (spec §10):** F7 must land before the integration tests for the tools it provides (radare2, ghidra, gdb, pwntools, tshark, checksec, chisel, openvas); until then those tools' unit (fixture) tests pass but their gated e2e tests are skipped/red.

---

## F8 — PTES reasoning brain `[opus]` (LATER — outline only)

> **Detailed bite-sized tasks to be expanded when F0–F7 land.** F8 depends on the arsenal being consistent and on trial runs against lab targets; its judgment quality is not deterministically testable (spec §10, §11). The outline below is sufficient to plan sequencing, not to implement yet.

Outline:
1. **Phase enum** — add `PtesPhase(StrEnum)` to `saber/models/mission_state.py`: `pre_engagement → recon → vuln_assessment → exploitation → post_exploitation → lateral_movement → proof_of_concept → post_engagement`. Add `MissionState.current_phase: PtesPhase = PtesPhase.RECON` (default; back-compat).
2. **Deterministic phase-goal checker** (approved decision #5) — new `saber/orchestration/phase_gate.py::PhaseGoalChecker` mirroring `StopEvaluator`'s shape: given `MissionState`, returns whether the current phase's goal is met (e.g. recon done when `hosts>0` and `services>0`; vuln_assessment done when `vulns>0`). Phase transitions are **gated by this deterministic checker**, not by decider free-choice — this is what makes phase transitions unit-testable.
3. **Decider reasoning upgrade** — `LlmDecider` reasons over accumulated state: chain attacks off discovered `services`/`credentials`/`sessions`; replan on failure (do not repeat a `failed_actions` signature when state is unchanged — the loop already computes `AttemptedAction.signature`; choose an alternative); reach for `custom_cli` when no contracted tool fits.
4. **Prompt work** — `prompts/next_action.txt`: per-phase guidance, chaining hints, the new state fields (shares/accounts/sessions/loot/flags/notes) and `current_phase`.
5. **Tests** — phase-transition tests (state satisfying a phase goal → checker advances phase); replanning tests (unchanged state → signature not repeated, alternative chosen). Judgment quality → trial runs, not unit assertions (spec §10).

---

## F9 — PTES reporting `[sonnet]` (LATER — outline only)

> **Detailed bite-sized tasks to be expanded when F0–F7 land.** Depends on the extended `MissionState` and (possibly) new storage tables for reporting (open question #4 — revisit whether JSON-blob snapshotting suffices or dedicated DDL migrations are needed).

Outline:
1. **Extend `saber/reporting/state_report_adapter.py`** (already the report-from-final-state path) into a standard phased pentest report: methodology, per-phase findings, attack-chain/kill-chain narrative, proof-of-concept, remediation.
2. **Consume the extended state** — sections for `sessions`, `loot`, `flags`, `notes`, `shares`, `accounts`, and `current_phase`, so the report reflects the full arsenal, not just vulns.
3. **Back-compat** — tolerate absence of the new lists in old snapshots (default `[]`) until this lands.
4. **Storage revisit** — if reporting needs queryable per-kind tables, add static DDL migrations under `saber/storage/migrations/*.sql` (parameterized SQL only). Decide during expansion.

---

## Self-Review

Run this checklist with fresh eyes against the spec.

### 1. Spec coverage (every pillar → tasks)

| Spec pillar / section | Task(s) |
|---|---|
| §3.1 Contract types (`ArgSpec`/`ActionContract`/`ToolContract`) | F0.1 |
| §3.1 `load_contract()` | F0.2 |
| §3.1 catalog generated from contracts; `_infer_actions` deleted; `ToolActionSpec.args` | F0.4 |
| §3.1 `LlmDecider._validate_args` + prompt | F0.5 |
| §3.1 `custom_cli` catalog==wrapper (registered, string args + reason) | F0.3 (register); custom_cli CONTRACT declared in F4-adjacent step — **see gap note below** |
| §3.2 canonical observation schema documented | F0.10 (docstrings) + Shared conventions table |
| §3.3 `StateMerger` new kinds + models + `_MERGERS` | F0.6, F0.7 |
| §3.3 `_MERGERS` key set == vocabulary | F0.8 |
| §4 Pillar-2 whatweb/nmap/nuclei/nikto/enum4linux normalization | F1.1–F1.5, F3 (enum4linux) |
| §4 Pillar-2 parser dispatch-signature fix | F0.10 |
| §4 Pillar-3 full arsenal (all 36 + 2 new) | F1–F6 (every tool enumerated) |
| §4 Pillar-4 sandbox image + manifest test | F7 |
| §4 Pillar-5 PTES brain | F8 (outline) |
| §4 Pillar-6 PTES reporting | F9 (outline) |
| §8 per-tool testing bar | migration template steps c/d/e |
| §8 cross-cutting consistency + no `action="default"` | F0.4 Step 5, F0.9 |
| §10 caveats (custom_cli risk, binary-exploit bounded, F7 dependency) | called out in F0.3, F5.X, F7 |

### 2. Placeholder scan

No "TBD/handle edge cases/similar to Task N". Where F2–F6 say "read the wrapper for exact actions/args", that is a **deliberate, bounded instruction** (the wrapper is the ground truth for its own dispatch branches) — not a placeholder; the emits_kinds/risk/parser-fixture specifics are concrete per tool. F8/F9 are explicitly marked outline-only per the brief.

### 3. Type consistency

- `ToolContract`/`ActionContract`/`ArgSpec` field names identical across F0.1, F0.4, F0.5, and every tool CONTRACT.
- Canonical `kind` strings identical everywhere: the 11 in the Shared-conventions table == `CANONICAL_KINDS` (F0.8) == `StateMerger._MERGERS` keys (F0.7) == every parser's emitted kind.
- `_MIGRATED_TOOLS` (F0.9) is the single growing gate every F1–F6 task appends to.
- Merger dedupe keys (F0.7) match spec §3.3 exactly.
- xfail handshake: F0.4 marks `test_catalog_generates_actions_from_contract` xfail; **F1.1 Step 5 removes it** — a deliberate cross-task dependency, recorded here.

### 4. Gaps found and resolved / flagged

- **custom_cli CONTRACT declaration:** F0.3 registers `custom_cli` but the plan does not give it a dedicated numbered migration task. **Resolution:** declare its `CONTRACT` (the spec §3.1 corrected custom_cli contract — string `command`/`pipeline`/`script_path` args + required `reason`, actions `run_command`/`run_script`/`run_pipeline`, risk `high`, `requires_approval=True`, `parser=None`, `emits_kinds=("note",)`) as part of F0.3, and add `"custom_cli"` to `_MIGRATED_TOOLS` there. Its optional note-parser is covered by approved decision #3 (generic `kind="note"`, no LLM call). Implementers should treat F0.3 as also declaring the custom_cli CONTRACT.
- **F1 vs F2 recon overlap:** masscan/subfinder/amass/dnsrecon/theharvester get CONTRACT in F1.7 (no behavior change) and their PARSERS in F2 Group A. Explicitly reconciled so no tool is double-migrated.
- **`hydra`:** advertised in the old `known` dict but has no wrapper module and is not registered; intentionally NOT migrated (no code exists). Flagged, not a gap.
- **Buildability assertion:** the spec §8 "every action buildable by build_command" is realised in per-tool golden-command tests (template step c), not the generic consistency test, because valid args are action-specific. Documented in F0.9.
- **mimikatz on Linux sandbox:** contracted but its binary is Windows-only; F7 marks it N/A in the Kali image. Its unit test is fixture-based; no gated e2e. Flagged.
