# CTF/Lab Slice (A+B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give SABER a reproducible Docker lab of vulnerable targets and the CLI/GUI wiring to run CTF/lab missions against them, with flag detection so `CtfStrategy` actually completes.

**Architecture:** Extend `select_strategy` with an explicit override carried in mission metadata; thread `--strategy`/`--lab`/`--scope` from CLI and a Strategy dropdown / Lab checkbox from the GUI into `run_mission`. Add a pure flag-detector called from the mission loop after each merge. Ship a `docker/lab/` compose (DVWA, Juice Shop, Metasploitable2, a custom `vulnbin`) on a `saber-lab` bridge network, with `make lab-up`/`lab-down` and an auto-generated scope file.

**Tech Stack:** Python 3.11+, pydantic v2, FastAPI, argparse, pytest, Docker Compose.

## Global Constraints

- Python >=3.11; package is `saber/`; PRs target `main`. (verbatim from CLAUDE.md)
- Agents never run shell; all tool execution goes through `Sandbox` via `ActionExecutor`. Do not add subprocess/shell to any agent or tool wrapper. (Tests may use subprocess.)
- `MissionState` is immutable-by-copy: update only via `model_copy(update=...)`. Never mutate in place.
- State mutations from observations go through `StateMerger.merge` only.
- Risk-gated autonomy: do not weaken `RiskGate`. Scope is a hard wall, checked before autonomy.
- SQL is parameterized only; schema changes are static DDL under `saber/storage/migrations/*.sql`.
- Lint scope: `ruff check` only the files you touch (repo carries pre-existing debt). Line length 100.
- Run offline tests with `make unit`; single test `pytest <path>::<name> -q`.

## Parallelization (for subagent-driven execution)

Independent tasks may be dispatched to concurrent subagents in waves. Within a wave, tasks touch disjoint files.

- **Wave A (parallel):** Task 1, Task 2, Task 3
- **Wave B (parallel):** Task 4 (needs 1), Task 7 (needs 2)
- **Wave C (parallel):** Task 5 (needs 4), Task 6 (needs 4)
- **Wave D:** Task 8 (needs 3 + 5), then Task 9 (docs, last)

---

## Task 1: `select_strategy` explicit override

**Wave A.** Add an explicit strategy override, carried in mission metadata under `strategy_override`, that wins over auto-detection. Existing `ctf`/`lab` metadata keys keep working.

**Files:**
- Modify: `saber/orchestration/strategies/base.py:40-51` (the `select_strategy` function)
- Test: `tests/orchestration_tests/test_select_strategy.py` (create)

**Interfaces:**
- Consumes: `Target`, `TargetType` (existing); `NetworkStrategy`, `WebStrategy`, `CtfStrategy` (existing).
- Produces: `select_strategy(target: Target, metadata: dict[str, Any] | None = None) -> TargetStrategy` — unchanged signature; new behavior: `metadata["strategy_override"]` in `{"network","web","ctf"}` selects that strategy first.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_select_strategy.py
from saber.models.target import Target, TargetType
from saber.orchestration.strategies.base import select_strategy
from saber.orchestration.strategies.ctf import CtfStrategy
from saber.orchestration.strategies.network import NetworkStrategy
from saber.orchestration.strategies.web import WebStrategy


def _host(value: str = "10.0.0.5") -> Target:
    return Target(type=TargetType.HOST, value=value)


def _url(value: str = "http://10.0.0.5") -> Target:
    return Target(type=TargetType.URL, value=value)


def test_override_ctf_wins_over_host_autodetect():
    strat = select_strategy(_host(), {"strategy_override": "ctf"})
    assert isinstance(strat, CtfStrategy)


def test_override_network_wins_over_url_autodetect():
    strat = select_strategy(_url(), {"strategy_override": "network"})
    assert isinstance(strat, NetworkStrategy)


def test_override_web_selected():
    strat = select_strategy(_host(), {"strategy_override": "web"})
    assert isinstance(strat, WebStrategy)


def test_no_override_keeps_autodetect_url_is_web():
    strat = select_strategy(_url(), {})
    assert isinstance(strat, WebStrategy)


def test_lab_metadata_still_selects_ctf():
    strat = select_strategy(_host(), {"lab": True})
    assert isinstance(strat, CtfStrategy)


def test_unknown_override_falls_through_to_autodetect():
    strat = select_strategy(_host(), {"strategy_override": "bogus"})
    assert isinstance(strat, NetworkStrategy)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/orchestration_tests/test_select_strategy.py -q`
Expected: FAIL (override branch not implemented; `test_override_ctf_wins_over_host_autodetect` returns NetworkStrategy).

- [ ] **Step 3: Implement the override**

Replace the body of `select_strategy` in `saber/orchestration/strategies/base.py` with:

```python
def select_strategy(target: Target, metadata: dict[str, Any] | None = None) -> TargetStrategy:
    """Pick the right strategy for a target.

    Precedence: an explicit ``metadata["strategy_override"]`` in
    {"network","web","ctf"} wins; then ``ctf``/``lab`` metadata selects CTF;
    then the target type is auto-detected.
    """

    from saber.orchestration.strategies.ctf import CtfStrategy
    from saber.orchestration.strategies.network import NetworkStrategy
    from saber.orchestration.strategies.web import WebStrategy

    metadata = metadata or {}

    override = str(metadata.get("strategy_override") or "").strip().lower()
    if override == "ctf":
        return CtfStrategy()
    if override == "web":
        return WebStrategy()
    if override == "network":
        return NetworkStrategy()

    if metadata.get("ctf") or metadata.get("lab"):
        return CtfStrategy()
    if target.type == TargetType.URL or target.is_web_target:
        return WebStrategy()
    return NetworkStrategy()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/orchestration_tests/test_select_strategy.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add saber/orchestration/strategies/base.py tests/orchestration_tests/test_select_strategy.py
git commit -m "feat(orchestration): explicit strategy override in select_strategy"
```

---

## Task 2: Flag detector (pure function)

**Wave A.** A dependency-free function that finds a CTF flag in text.

**Files:**
- Create: `saber/core/flag_detector.py`
- Test: `tests/unit/test_flag_detector.py`

**Interfaces:**
- Produces: `detect_flag(texts: Iterable[str], extra_patterns: list[str] | None = None) -> str | None` — returns the first flag found scanning `texts` in order, or `None`. Default formats: `picoCTF{...}`, `flag{...}`, `FLAG{...}`, `CTF{...}` (case-insensitive on the `flag`/`ctf` word, `{...}` non-greedy, no nested braces). `extra_patterns` are additional regex strings tried after the defaults.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_flag_detector.py
from saber.core.flag_detector import detect_flag


def test_detects_picoctf():
    assert detect_flag(["got picoCTF{s0me_fl4g} here"]) == "picoCTF{s0me_fl4g}"


def test_detects_lowercase_flag():
    assert detect_flag(["flag{abc_123}"]) == "flag{abc_123}"


def test_detects_uppercase_flag():
    assert detect_flag(["FLAG{ABC}"]) == "FLAG{ABC}"


def test_detects_ctf():
    assert detect_flag(["CTF{x}"]) == "CTF{x}"


def test_returns_first_match_across_texts():
    assert detect_flag(["nothing", "flag{first}", "flag{second}"]) == "flag{first}"


def test_no_match_returns_none():
    assert detect_flag(["no flags here", "flagpole", "{}"]) is None


def test_extra_pattern_matches_custom_format():
    assert detect_flag(["KEY-abc-999"], extra_patterns=[r"KEY-[a-z]+-\d+"]) == "KEY-abc-999"


def test_ignores_empty_and_non_string():
    assert detect_flag(["", None, "flag{ok}"]) == "flag{ok}"  # type: ignore[list-item]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_flag_detector.py -q`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement**

```python
# saber/core/flag_detector.py
"""Detect CTF flags in tool output text.

Pure and dependency-free so it is trivially unit-testable and safe to call from
the mission loop. Returns the first flag found; never raises.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Non-greedy brace body, no nested braces. The flag word is matched
# case-insensitively via the IGNORECASE flag applied at compile time.
_DEFAULT_PATTERNS = (
    r"picoCTF\{[^{}]{1,256}\}",
    r"flag\{[^{}]{1,256}\}",
    r"CTF\{[^{}]{1,256}\}",
)


def detect_flag(texts: Iterable[str], extra_patterns: list[str] | None = None) -> str | None:
    """Return the first flag found scanning ``texts`` in order, else None."""

    patterns = [re.compile(p, re.IGNORECASE) for p in _DEFAULT_PATTERNS]
    patterns.extend(re.compile(p) for p in (extra_patterns or []))

    for text in texts:
        if not isinstance(text, str) or not text:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_flag_detector.py -q`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add saber/core/flag_detector.py tests/unit/test_flag_detector.py
git commit -m "feat(core): add CTF flag detector"
```

---

## Task 3: Lab — compose + `vulnbin` image

**Wave A.** The vulnerable-target lab. No SABER code changes here; pure infra.

**Files:**
- Create: `docker/lab/docker-compose.yml`
- Create: `docker/lab/vulnbin/Dockerfile`
- Create: `docker/lab/vulnbin/vuln.c`
- Create: `docker/lab/vulnbin/flag.txt`
- Create: `docker/lab/vulnbin/entrypoint.sh`
- Create: `docker/lab/README.md`

**Networking contract (concrete mechanism):** the lab defines a bridge network named `saber-lab`. SABER's Docker runner launches each tool container with `--network $SABER_DOCKER_NETWORK`; to reach lab targets by service name, the operator sets `SABER_DOCKER_NETWORK=saber-lab` in `.env` before launching SABER. (This refines the design doc's "attach the sandbox" wording — the real hook is the per-exec network, since tool containers are ephemeral.) Nuclei template auto-update needs egress; document running the lab web missions with template updates disabled or pre-baked.

- [ ] **Step 1: Write `vulnbin/vuln.c`** (deliberately vulnerable; a later RE/pwn target)

```c
/* docker/lab/vulnbin/vuln.c
 * Intentionally vulnerable demo binary for the SABER lab. NOT for production.
 * Classic unbounded gets() stack overflow; reads the flag file on request.
 */
#include <stdio.h>
#include <string.h>

void print_flag(void) {
    FILE *f = fopen("/flag.txt", "r");
    char buf[128];
    if (!f) { puts("no flag"); return; }
    while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
    fclose(f);
}

int main(void) {
    char name[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("vulnbin: enter your name:");
    gets(name);                 /* overflow: no bounds check */
    printf("hello, %s\n", name);
    if (strcmp(name, "sesame") == 0) print_flag();
    return 0;
}
```

- [ ] **Step 2: Write `vulnbin/flag.txt`**

```text
flag{saber_vulnbin_pwned}
```

- [ ] **Step 3: Write `vulnbin/entrypoint.sh`**

```bash
#!/bin/sh
# Expose the vulnerable binary over TCP so lab missions can reach it.
set -e
exec socat TCP-LISTEN:9001,reuseaddr,fork EXEC:/opt/vuln
```

- [ ] **Step 4: Write `vulnbin/Dockerfile`**

```dockerfile
# docker/lab/vulnbin/Dockerfile
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat \
    && rm -rf /var/lib/apt/lists/*

COPY vuln.c /tmp/vuln.c
COPY flag.txt /flag.txt
COPY entrypoint.sh /entrypoint.sh

# -fno-stack-protector / -no-pie keep the classic overflow exploitable for the RE/pwn workstream.
RUN gcc -fno-stack-protector -no-pie -o /opt/vuln /tmp/vuln.c \
    && rm /tmp/vuln.c \
    && chmod 0644 /flag.txt \
    && chmod +x /entrypoint.sh

EXPOSE 9001
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 5: Write `docker/lab/docker-compose.yml`**

Pin exact image digests at implementation time; the tags below are the starting point.

```yaml
# docker/lab/docker-compose.yml
# SABER vulnerable-target lab. Authorized local testing only.
name: saber-lab

services:
  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: saber-lab-dvwa
    networks: [saber-lab]
    restart: unless-stopped

  juiceshop:
    image: bkimminich/juice-shop:latest
    container_name: saber-lab-juiceshop
    networks: [saber-lab]
    restart: unless-stopped

  metasploitable:
    image: tleemcjr/metasploitable2:latest
    container_name: saber-lab-metasploitable
    networks: [saber-lab]
    restart: unless-stopped

  vulnbin:
    build: ./vulnbin
    image: saber/lab-vulnbin:latest
    container_name: saber-lab-vulnbin
    networks: [saber-lab]
    restart: unless-stopped

networks:
  saber-lab:
    name: saber-lab
    driver: bridge
```

- [ ] **Step 6: Write `docker/lab/README.md`**

```markdown
# SABER Vulnerable Lab

Authorized local testing only. These targets are intentionally insecure — never
expose them to an untrusted network.

## Targets (on the `saber-lab` bridge network)

| Service | Reach as | Notes |
|---------|----------|-------|
| DVWA | `dvwa` | Classic vulnerable web app |
| Juice Shop | `juiceshop` (port 3000) | Modern SPA |
| Metasploitable2 | `metasploitable` | Multi-service box (SSH/SMB/FTP/web) |
| vulnbin | `vulnbin` (port 9001) | Custom overflow binary + `/flag.txt` |

## Use

```bash
make lab-up      # build vulnbin, create the saber-lab network, start targets, write runs/lab_scope.yaml
make lab-down    # stop and remove everything
```

Set `SABER_DOCKER_NETWORK=saber-lab` in `.env` before launching SABER so tool
containers can resolve the target names above. Run missions with the generated
scope: `--scope runs/lab_scope.yaml`.
```

- [ ] **Step 7: Verify the vulnbin image builds**

Run: `docker build -t saber/lab-vulnbin:latest docker/lab/vulnbin`
Expected: build succeeds (a `gets()` warning from gcc is expected and fine).

- [ ] **Step 8: Commit**

```bash
git add docker/lab
git commit -m "feat(lab): vulnerable-target compose (DVWA, Juice Shop, Metasploitable2, vulnbin)"
```

---

## Task 4: `run_cli_mission` — thread strategy/lab/scope into `run_mission`

**Wave B (needs Task 1).** Add params and a scope-file loader; set `session.scope` and mission metadata.

**Files:**
- Create: `saber/core/scope_loader.py`
- Modify: `saber/ui/cli/run_command.py` (signature + metadata + scope wiring)
- Test: `tests/unit/test_run_command_strategy.py`
- Test: `tests/unit/test_scope_loader.py`

**Interfaces:**
- Produces: `load_scope(path: str | Path) -> MissionScope` — parse a YAML file `{mission_name: str, targets: [str, ...]}` into a `MissionScope` with host `Target`s.
- Produces: `run_cli_mission(..., strategy: str = "auto", lab: bool = False, scope_path: str | None = None)` — `strategy != "auto"` adds `metadata["strategy_override"]`; `lab` adds `metadata["lab"]=True`; `scope_path` loads a scope and sets it on the session.

- [ ] **Step 1: Write the failing test for the scope loader**

```python
# tests/unit/test_scope_loader.py
from saber.core.scope_loader import load_scope


def test_load_scope_reads_targets(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("mission_name: Lab\ntargets:\n  - dvwa\n  - metasploitable\n")
    scope = load_scope(p)
    assert scope.mission_name == "Lab"
    assert set(scope.target_values()) == {"dvwa", "metasploitable"}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_scope_loader.py -q`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the scope loader**

```python
# saber/core/scope_loader.py
"""Load a mission scope from a simple YAML file."""

from __future__ import annotations

from pathlib import Path

import yaml

from saber.models.scope import MissionScope
from saber.models.target import Target, TargetType


def load_scope(path: str | Path) -> MissionScope:
    """Parse ``{mission_name, targets: [...]}`` YAML into a MissionScope."""

    data = yaml.safe_load(Path(path).read_text()) or {}
    targets = [
        Target(type=TargetType.HOST, value=str(value).strip())
        for value in (data.get("targets") or [])
        if str(value).strip()
    ]
    return MissionScope(
        mission_name=str(data.get("mission_name") or "SABER lab"),
        targets=targets,
    )
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/unit/test_scope_loader.py -q`
Expected: PASS.

Note: if `MissionScope.target_values()` does not exist, use `[t.value for t in scope.targets]` in the test instead — verify the method name against `saber/models/scope.py` before finalizing.

- [ ] **Step 5: Write the failing test for run_cli_mission threading**

```python
# tests/unit/test_run_command_strategy.py
from unittest.mock import MagicMock, patch

from saber.ui.cli import run_command


def _run(**overrides):
    """Call run_cli_mission with build_saber_runtime fully mocked."""
    with patch.object(run_command, "build_saber_runtime") as build:
        runtime = MagicMock()
        runtime.llm_client.enabled = False
        # run_mission returns an object persist_mission_result can consume.
        result = MagicMock()
        result.records = []
        result.observations = []
        result.status.value = "completed"
        runtime.orchestrator.run_mission.return_value = result
        build.return_value = runtime
        with patch.object(run_command, "persist_mission_result"):
            run_command.run_cli_mission(
                target_value="dvwa",
                profile="web",
                agent_mode="deterministic",
                **overrides,
            )
        return runtime.orchestrator.run_mission


def test_strategy_override_reaches_run_mission_metadata():
    run_mission = _run(strategy="ctf")
    _, kwargs = run_mission.call_args
    assert kwargs["metadata"].get("strategy_override") == "ctf"


def test_auto_strategy_sets_no_override():
    run_mission = _run(strategy="auto")
    _, kwargs = run_mission.call_args
    assert "strategy_override" not in kwargs["metadata"]


def test_lab_flag_reaches_metadata():
    run_mission = _run(lab=True)
    _, kwargs = run_mission.call_args
    assert kwargs["metadata"].get("lab") is True
```

- [ ] **Step 6: Run it to verify it fails**

Run: `pytest tests/unit/test_run_command_strategy.py -q`
Expected: FAIL (`run_cli_mission` has no `strategy`/`lab` params → TypeError).

- [ ] **Step 7: Implement in `run_command.py`**

Add to the `run_cli_mission` signature (after `agent_mode: str = "deterministic",`):

```python
    strategy: str = "auto",
    lab: bool = False,
    scope_path: str | None = None,
```

Replace the `metadata={...}` dict passed to `runtime.orchestrator.run_mission(...)` (currently `{"source": "cli_run", "profile": ..., "dry_run": ...}`) with a built dict:

```python
        mission_metadata: dict[str, Any] = {
            "source": "cli_run",
            "profile": normalized_profile,
            "dry_run": dry_run,
        }
        if strategy and strategy.strip().lower() != "auto":
            mission_metadata["strategy_override"] = strategy.strip().lower()
        if lab:
            mission_metadata["lab"] = True
```

Then pass `metadata=mission_metadata` in the `run_mission(...)` call.

Wire the scope onto the session — after `session = _make_session(...)` add:

```python
        if scope_path:
            from saber.core.scope_loader import load_scope

            session = session.model_copy(update={"scope": load_scope(scope_path)})
```

(`Any` is already imported in this module.)

- [ ] **Step 8: Run both tests to verify they pass**

Run: `pytest tests/unit/test_run_command_strategy.py tests/unit/test_scope_loader.py -q`
Expected: PASS.

- [ ] **Step 9: Run the existing run-command regression**

Run: `pytest tests/unit/test_run_command.py -q`
Expected: PASS (the single-run behavior is unchanged).

- [ ] **Step 10: Commit**

```bash
git add saber/core/scope_loader.py saber/ui/cli/run_command.py tests/unit/test_run_command_strategy.py tests/unit/test_scope_loader.py
git commit -m "feat(cli): thread strategy/lab/scope through run_cli_mission"
```

---

## Task 5: CLI flags `--strategy` / `--lab` / `--scope`

**Wave C (needs Task 4).**

**Files:**
- Modify: `saber/ui/cli/main.py` (`run` subparser + `dispatch`)
- Test: `tests/unit/test_cli_run_flags.py`

**Interfaces:**
- Consumes: `run_cli_mission(strategy=, lab=, scope_path=)` from Task 4.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_cli_run_flags.py
from unittest.mock import patch

from saber.ui.cli import main as cli_main


def _dispatch(argv):
    parser = cli_main.build_parser()
    args = parser.parse_args(argv)
    with patch.object(cli_main, "run_cli_mission", return_value={}) as run:
        cli_main.dispatch(args, None, None, None)
    return run


def test_strategy_and_lab_and_scope_flags_are_passed():
    run = _dispatch(
        ["run", "--target", "dvwa", "--profile", "web",
         "--strategy", "ctf", "--lab", "--scope", "runs/lab_scope.yaml"]
    )
    _, kwargs = run.call_args
    assert kwargs["strategy"] == "ctf"
    assert kwargs["lab"] is True
    assert kwargs["scope_path"] == "runs/lab_scope.yaml"


def test_defaults_when_flags_absent():
    run = _dispatch(["run", "--target", "127.0.0.1"])
    _, kwargs = run.call_args
    assert kwargs["strategy"] == "auto"
    assert kwargs["lab"] is False
    assert kwargs["scope_path"] is None
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_cli_run_flags.py -q`
Expected: FAIL (`--strategy` is not a recognized argument → SystemExit).

- [ ] **Step 3: Implement — add arguments**

In `saber/ui/cli/main.py`, in `build_parser`, after the existing `run.add_argument("--dry-run", ...)` line, add:

```python
    run.add_argument("--strategy", choices=["auto", "network", "web", "ctf"], default="auto")
    run.add_argument("--lab", action="store_true", help="Mark the target as an owned lab (relaxes ownership assumptions).")
    run.add_argument("--scope", dest="scope_path", default=None, help="Path to a scope YAML file to enforce.")
```

- [ ] **Step 4: Implement — pass them through**

In `dispatch`, in the `args.command == "run"` block, add these to the `run_cli_mission(...)` call:

```python
            strategy=args.strategy,
            lab=args.lab,
            scope_path=args.scope_path,
```

- [ ] **Step 5: Run it to verify it passes**

Run: `pytest tests/unit/test_cli_run_flags.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add saber/ui/cli/main.py tests/unit/test_cli_run_flags.py
git commit -m "feat(cli): add --strategy/--lab/--scope flags to run"
```

---

## Task 6: GUI — Strategy dropdown + Lab checkbox

**Wave C (needs Task 4).**

**Files:**
- Modify: `saber/ui/web/routers/sessions.py` (`MissionRunRequest` + `kwargs`)
- Modify: `saber/ui/web/app.py` (form HTML + submit JS, around lines 590-635)
- Test: `tests/unit/test_web_run_strategy.py`

**Interfaces:**
- Consumes: `run_cli_mission(strategy=, lab=)` from Task 4.
- Produces: `MissionRunRequest` gains `strategy: str` (pattern `^(auto|network|web|ctf)$`, default `auto`) and `lab: bool = False`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_web_run_strategy.py
from unittest.mock import patch

from fastapi.testclient import TestClient

from saber.ui.web import app as web_app


def _client():
    application = web_app.create_app(require_auth=False)
    return TestClient(application)


def test_run_passes_strategy_and_lab_to_run_cli_mission():
    with patch("saber.ui.web.routers.sessions.run_cli_mission", return_value={}) as run:
        # Thread target is started but we only assert the kwargs it was built with.
        with patch("saber.ui.web.routers.sessions.Thread") as thread:
            client = _client()
            resp = client.post(
                "/sessions/run",
                json={"target": "dvwa", "profile": "web", "strategy": "ctf", "lab": True},
            )
    assert resp.status_code == 200
    kwargs = thread.call_args.kwargs["kwargs"]
    assert kwargs["strategy"] == "ctf"
    assert kwargs["lab"] is True
    assert run is not None
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_web_run_strategy.py -q`
Expected: FAIL (`kwargs` has no `strategy`/`lab`).

- [ ] **Step 3: Implement — request model + kwargs**

In `saber/ui/web/routers/sessions.py`, add to `MissionRunRequest` (after `agent_mode`):

```python
    strategy: str = Field(default="auto", pattern="^(auto|network|web|ctf)$")
    lab: bool = False
```

In `run_mission_from_web`, add to the `kwargs` dict (after `"agent_mode": run_request.agent_mode,`):

```python
        "strategy": run_request.strategy,
        "lab": run_request.lab,
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/unit/test_web_run_strategy.py -q`
Expected: PASS.

- [ ] **Step 5: Add the form controls (manual UI)**

In `saber/ui/web/app.py`, after the Mode `<label>` block (ends at line ~595) add:

```html
        <label>Strategy
          <select id="mission-strategy" name="strategy">
            <option value="auto">auto</option>
            <option value="network">network</option>
            <option value="web">web</option>
            <option value="ctf">ctf</option>
          </select>
        </label>
```

And after the Dry-run checkbox `<label>` (ends at line ~609) add:

```html
        <label class="checkbox-row">
          <input id="mission-lab" name="lab" type="checkbox" />
          Lab target (owned)
        </label>
```

In the `startMission` JS `payload` object (around line 634), add:

```javascript
          strategy: document.getElementById("mission-strategy").value,
          lab: document.getElementById("mission-lab").checked,
```

- [ ] **Step 6: Verify the page renders**

Run: `python -c "from saber.ui.web.app import create_app; from fastapi.testclient import TestClient; c=TestClient(create_app(require_auth=False)); r=c.get('/ui'); assert 'mission-strategy' in r.text and 'mission-lab' in r.text; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 7: Commit**

```bash
git add saber/ui/web/routers/sessions.py saber/ui/web/app.py tests/unit/test_web_run_strategy.py
git commit -m "feat(ui): Strategy dropdown + Lab checkbox on Start Mission"
```

---

## Task 7: Wire flag detection into the mission loop

**Wave B (needs Task 2).** After each merge, scan the just-observed text for a flag and record it on `state.metadata["flag"]` (immutable copy), before the strategy objective check so `CtfStrategy.objective_met` fires the same iteration.

**Files:**
- Modify: `saber/orchestration/mission_loop.py` (add a helper + call it after the ALLOW-path merge, ~line 194)
- Test: `tests/orchestration_tests/test_mission_loop_flag_detection.py`

**Interfaces:**
- Consumes: `detect_flag` (Task 2); `MissionState.metadata`; `CtfStrategy.objective_met`.
- Produces: after an ALLOW iteration, if a flag is found and `metadata["flag"]` is unset, `state.metadata["flag"]` is set. An optional per-mission `state.metadata["flag_regex"]` (str) is passed as an extra pattern.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_mission_loop_flag_detection.py
from saber.agents.base_agent import AgentObservation
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.core.state_merger import StateMerger
from saber.models.mission_state import MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.risk_gate import GateDecision, GateResult
from saber.orchestration.stop_conditions import StopDecision
from saber.orchestration.strategies.ctf import CtfStrategy


class _Summarizer:
    def summarize(self, state):
        return type("S", (), {"to_dict": lambda self: {}})()


class _Decider:
    """One TOOL action, then STOP."""
    def __init__(self):
        self.calls = 0

    def decide(self, state, summary):
        self.calls += 1
        if self.calls == 1:
            return ProposedAction(
                kind=ActionKind.TOOL, tool_name="custom_cli", tool_action="run_command",
                args={}, objective="grab flag", risk=RiskLevel.LOW,
            )
        return ProposedAction(kind=ActionKind.STOP, objective="done", rationale="done")


class _Gate:
    def evaluate(self, state, action):
        return GateResult(GateDecision.ALLOW, "ok")


class _Executor:
    def execute(self, state, session, action):
        obs = AgentObservation(
            summary="output was: flag{saber_vulnbin_pwned}",
            tool_name=action.tool_name, action=action.tool_action, success=True,
        )
        return ActionExecutionRecord(sandbox_result=None, observation=obs, error=None)


class _ResultProcessor:
    def process_tool_result(self, **kwargs):
        return type("P", (), {"parsed_observations": [], "evidence_ids": [], "finding_ids": []})()


class _Stop:
    def evaluate(self, state, action):
        return StopDecision(should_stop=state.objective_met, reason="objective met")


class _Store:
    def __init__(self):
        self.snapshots = []

    def snapshot(self, state):
        self.snapshots.append(state)


def _state():
    target = Target(type=TargetType.HOST, value="vulnbin")
    return MissionState(session_id="s1", target=target, objective="capture the flag")


def test_flag_detected_sets_metadata_and_meets_objective():
    store = _Store()
    loop = MissionLoop(
        decider=_Decider(), summarizer=_Summarizer(), risk_gate=_Gate(),
        stop_evaluator=_Stop(), executor=_Executor(), merger=StateMerger(),
        state_store=store, result_processor=_ResultProcessor(),
        max_steps=5, strategy=CtfStrategy(),
    )
    session = MissionSession(session_id="s1", mission_name="ctf")
    result = loop.run(_state(), session, strategy=CtfStrategy())
    final = store.snapshots[-1]
    assert final.metadata.get("flag") == "flag{saber_vulnbin_pwned}"
    assert final.objective_met is True
```

Verify constructor names before running: `StopDecision`/`GateResult`/`GateDecision` field names against `saber/orchestration/stop_conditions.py` and `risk_gate.py`; adjust the fakes if the real dataclasses differ.

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_mission_loop_flag_detection.py -q`
Expected: FAIL (`final.metadata["flag"]` is absent; objective not met).

- [ ] **Step 3: Implement the helper**

In `saber/orchestration/mission_loop.py`, add the import near the top:

```python
from saber.core.flag_detector import detect_flag
```

Add a method to `MissionLoop`:

```python
    def _detect_and_record_flag(
        self,
        state: MissionState,
        record: "ActionExecutionRecord",
        parsed_observations: list[dict],
    ) -> MissionState:
        """Record a captured flag on state.metadata['flag'] if one appears."""

        if state.metadata.get("flag"):
            return state

        texts: list[str] = [record.observation.summary or ""]
        for obs in parsed_observations:
            texts.append(str(obs))
        result = getattr(record, "sandbox_result", None)
        for attr in ("stdout", "output", "reason"):
            value = getattr(result, attr, None)
            if isinstance(value, str):
                texts.append(value)

        extra = state.metadata.get("flag_regex")
        flag = detect_flag(texts, extra_patterns=[extra] if isinstance(extra, str) else None)
        if not flag:
            return state
        return state.model_copy(update={"metadata": {**state.metadata, "flag": flag}})
```

- [ ] **Step 4: Call the helper in the ALLOW path**

In `run`, in the ALLOW branch, insert the call between the merge and `_apply_strategy_objective` (currently lines 187-194):

```python
            state = self.merger.merge(
                state,
                parsed_observations,
                attempt,
                evidence_refs=evidence_refs,
                finding_refs=finding_refs,
            )
            state = self._detect_and_record_flag(state, record, parsed_observations)
            state = self._apply_strategy_objective(state, active_strategy)
            self.state_store.snapshot(state)
```

- [ ] **Step 5: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_mission_loop_flag_detection.py -q`
Expected: PASS.

- [ ] **Step 6: Regression + commit**

Run: `make unit`
Expected: PASS (no regressions).

```bash
git add saber/orchestration/mission_loop.py tests/orchestration_tests/test_mission_loop_flag_detection.py
git commit -m "feat(orchestration): detect and record captured flags in the loop"
```

---

## Task 8: Lab make targets + scope-gen + Docker-gated integration test

**Wave D (needs Task 3 + Task 5).**

**Files:**
- Create: `scripts/lab_scope.py` (writes `runs/lab_scope.yaml`)
- Modify: `Makefile` (add `lab-up`, `lab-down`)
- Create: `tests/e2e_tests/test_lab_missions_e2e.py`

**Interfaces:**
- Consumes: `docker/lab/docker-compose.yml` (Task 3); `run_cli_mission(scope_path=, strategy=)` (Tasks 4-5).

- [ ] **Step 1: Write `scripts/lab_scope.py`**

```python
# scripts/lab_scope.py
"""Write the lab scope file listing the saber-lab targets."""

from __future__ import annotations

from pathlib import Path

LAB_TARGETS = ["dvwa", "juiceshop", "metasploitable", "vulnbin"]


def main() -> None:
    out = Path("runs/lab_scope.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["mission_name: SABER lab", "targets:"]
    lines += [f"  - {t}" for t in LAB_TARGETS]
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Add Makefile targets**

Add to `.PHONY` line: `lab-up lab-down`. Append:

```makefile
lab-up:
	docker network inspect saber-lab >/dev/null 2>&1 || docker network create saber-lab
	docker compose -f docker/lab/docker-compose.yml up -d --build
	python scripts/lab_scope.py
	@echo "Lab up. Set SABER_DOCKER_NETWORK=saber-lab in .env, then run missions with --scope runs/lab_scope.yaml"

lab-down:
	docker compose -f docker/lab/docker-compose.yml down -v
	-docker network rm saber-lab
```

- [ ] **Step 3: Verify scope-gen runs**

Run: `python scripts/lab_scope.py && cat runs/lab_scope.yaml`
Expected: file lists the four targets.

- [ ] **Step 4: Write the Docker-gated integration test**

```python
# tests/e2e_tests/test_lab_missions_e2e.py
"""Docker-gated lab missions. Requires `make lab-up` first.

Gated by SABER_RUN_DOCKER_E2E; skips cleanly when the lab is not reachable.
"""

import os
import socket

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("SABER_RUN_DOCKER_E2E", "0") not in {"1", "true", "True"},
    reason="Docker E2E gated behind SABER_RUN_DOCKER_E2E=1",
)


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def test_web_mission_against_dvwa(tmp_path):
    from saber.ui.cli.run_command import run_cli_mission

    if not _reachable("dvwa", 80) and not _reachable("127.0.0.1", 80):
        pytest.skip("DVWA not reachable; run `make lab-up` and set SABER_DOCKER_NETWORK=saber-lab")

    scope = tmp_path / "scope.yaml"
    scope.write_text("mission_name: Lab\ntargets:\n  - dvwa\n")
    result = run_cli_mission(
        target_value="dvwa",
        profile="web",
        agent_mode="deterministic",
        strategy="web",
        scope_path=str(scope),
        db_path=str(tmp_path / "saber.db"),
        evidence_dir=str(tmp_path / "evidence"),
        reports_dir=str(tmp_path / "reports"),
        max_steps=6,
    )
    assert result["status"] in {"completed", "stopped"}
    assert result["steps"] >= 1
```

- [ ] **Step 5: Run it (gated)**

Run: `make lab-up` then `SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_lab_missions_e2e.py -q`
Expected: PASS, or SKIP with the reachability message when the lab is down.

- [ ] **Step 6: Commit**

```bash
git add scripts/lab_scope.py Makefile tests/e2e_tests/test_lab_missions_e2e.py
git commit -m "feat(lab): make lab-up/lab-down + scope-gen + gated lab mission test"
```

---

## Task 9: Documentation

**Wave D (last).**

**Files:**
- Modify: `README.md` (add a "Test against the lab" section; document `--strategy`/`--lab`/`--scope` and the GUI fields)

- [ ] **Step 1: Add a lab section to the README**

Under the GUI/CLI usage area, add:

```markdown
## Test against the lab

SABER ships a reproducible lab of intentionally vulnerable targets for
authorized local testing.

```bash
make lab-up      # build vulnbin, create saber-lab network, start targets, write runs/lab_scope.yaml
# set SABER_DOCKER_NETWORK=saber-lab in .env, then:
python -m saber.ui.cli.main run --target dvwa --profile web --strategy web --scope runs/lab_scope.yaml
python -m saber.ui.cli.main run --target vulnbin --strategy ctf --lab --scope runs/lab_scope.yaml
make lab-down
```

The mission loop is LLM-driven in production (`--mode llm`); deterministic mode
is used for reproducible offline/CI runs. Targets: `dvwa`, `juiceshop`,
`metasploitable`, `vulnbin`. See `docker/lab/README.md`.
```

Also add `--strategy {auto,network,web,ctf}`, `--lab`, and `--scope <file>` to the CLI flags list, and note the GUI Start Mission form now has a Strategy dropdown and Lab checkbox.

- [ ] **Step 2: Verify referenced commands are accurate**

Run: `python -m saber.ui.cli.main run --help`
Expected: shows `--strategy`, `--lab`, `--scope`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document the vulnerable lab and CTF/lab mission flags"
```

---

## Self-Review

**Spec coverage** (against `2026-07-23-ctf-lab-slice-design.md`):
- Lab (DVWA/Juice Shop/Metasploitable2/vulnbin, saber-lab net, lab-up/down, scope file) → Tasks 3, 8. ✔
- `select_strategy` override + `--lab` → Tasks 1, 4, 5. ✔
- CLI `--strategy`/`--lab` → Task 5; GUI dropdown/checkbox → Task 6. ✔
- Flag detection (defaults + configurable regex) + `CtfStrategy.objective_met` fires → Tasks 2, 7. ✔
- Testing split (offline unit / Docker-gated integration / LLM acceptance) → unit throughout; integration Task 8; LLM acceptance noted in design (not new code this slice). ✔
- Invariants (sandbox-only, immutable state, scope hard wall) → preserved; scope wiring (Task 4) strengthens the wall rather than weakening it. ✔

**Placeholder scan:** no TBD/TODO; every code step shows full code. Two explicit "verify the real name" notes (Task 4 `target_values`, Task 7 dataclass fields) are grounding checks, not placeholders.

**Type consistency:** `strategy_override` / `lab` / `flag` / `flag_regex` metadata keys, `detect_flag(texts, extra_patterns=)`, `load_scope(path)`, and the `run_cli_mission(strategy=, lab=, scope_path=)` signature are used identically across Tasks 1, 4, 5, 6, 7, 8.

**Grounding caveats to confirm while implementing:**
- `MissionScope.target_values()` method name (Task 4 Step 4 note).
- `StopDecision` / `GateResult` / `GateDecision` field names for the Task 7 fakes.
- Exact public image tags/digests for DVWA/Juice Shop/Metasploitable2 (pin at implementation).
- `pyyaml` is importable (used by `scope_loader`); add to `requirements.txt` if absent.
