# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What SABER is

SABER (Scoped Automated Breach, Exploitation & Reporting) is a self-hosted, evidence-first penetration-testing operator platform for **authorized assessments only**. A mission does not run a pre-built plan; it runs as a **state-first agentic loop** that keeps a live picture of what it knows (`MissionState`) and, each iteration, decides the single highest-value next action from that state, risk-gates it, runs it in a Docker/Kali sandbox, folds the parsed result back into state, and repeats until the objective is met or a stop condition fires. Python package is `saber/` (requires Python >=3.11); main branch for PRs is `main`.

## Core architecture — the loop

The mission driver is `saber/orchestration/mission_loop.py` (`MissionLoop`). **This is the entry point to understand; start here.** `MissionOrchestrator.run_mission()` builds state + session and drives every mission exclusively through `MissionLoop.run()`.

**The five files to read first:**
1. `saber/orchestration/mission_loop.py` — the loop itself (`MissionLoop.run`).
2. `saber/models/mission_state.py` — `MissionState`, the accumulating working memory the loop reasons over.
3. `saber/agents/deciders/base.py` + `saber/agents/deciders/llm.py` + `saber/agents/deciders/hybrid.py` — the `NextActionDecider` interface (`ProposedAction`, `ActionKind`, `RiskLevel`), the LLM decider, and the hybrid wrapper that LLM missions actually get.
4. `saber/core/state_merger.py` — `StateMerger`, how parsed observations fold into `MissionState`.
5. `saber/orchestration/risk_gate.py` — `RiskGate`, the autonomy/scope gate.

### Data flow (one iteration)

```
summarize (StateSummarizer)                     saber/core/state_summary.py
  -> decide (NextActionDecider)                 deciders/hybrid.py -> llm.py | deterministic.py
  -> risk-gate (RiskGate: allow/confirm/refuse) orchestration/risk_gate.py
  -> execute (ActionExecutor -> capability agent -> Sandbox)  orchestration/action_executor.py
  -> parse (ParserRegistry) + persist (ResultProcessor -> stores)  core/result_processor.py
  -> merge (StateMerger) into MissionState      core/state_merger.py
  -> snapshot (MissionStateStore)               storage/mission_state_store.py
  -> stop-check (StopEvaluator)                 orchestration/stop_conditions.py
  -> repeat
```

State is snapshotted after every step, so the GUI and the final report always read real persisted state. On a terminal COMPLETED/STOPPED outcome the loop finalizes reports **from the final `MissionState`** via `saber/reporting/state_report_adapter.py` (feeding the existing exporters). The loop terminates when: the strategy reports the objective met, the decider returns STOP/REPORT, `max_steps` is reached, or the repeated-failure guard trips.

## Invariants (do not break these)

- **Agents never run shell.** All execution goes through `Sandbox` (Docker), dispatched only via `ActionExecutor`. Never add subprocess/shell execution to an agent or tool wrapper.
- **The loop decides; agents execute.** `MissionLoop` calls `decider.decide()`; agents are capability lenses the executor dispatches to. The loop never calls `agent.decide()`, and agents no longer drive the mission's direction.
- **`MissionState` is immutable-by-copy.** It is a pydantic model updated only via `model_copy(update=...)` (see `record_attempt`, `touch`). Never mutate a `MissionState` in place.
- **State mutations go through `StateMerger`.** Parsed observations become hosts/services/technologies/credentials/vulns only via `StateMerger.merge`, which dedupes. Do not hand-edit these lists elsewhere.
- **Risk-gated autonomy.** Autonomous by default; only high-risk or explicitly confirmation-flagged actions pause for a one-click confirmation. Do not weaken `RiskGate`.
- **Scope is a hard wall.** Out-of-scope targets or prohibited tool/actions are **refused** (never offered for confirmation), and scope is checked before any autonomy consideration.
- **SQL is parameterized only; schema changes are static DDL migrations** under `saber/storage/migrations/*.sql`. Never build SQL by string interpolation.

## Plan-first is retired

The old plan-first driver (`ExecutionPlan` + `ChainRunner`) no longer drives missions. **`ChainRunner` has been deleted** (no references remain). `ExecutionPlan`/`step_runner.py` survive only as execution helpers, and `MissionOrchestrator.create_plan()` is now only an **optional seed** — it does not orchestrate. Treat any doc or comment implying a pre-computed plan runs the mission as stale.

## Deciders

The decision mode is chosen **per mission** via `agent_mode`, not a persistent env toggle:

- **`--mode llm`** builds a **`HybridDecider`** (`deciders/hybrid.py`) wrapping `LlmDecider`. Note this: LLM missions do **not** get a bare `LlmDecider`, so `runtime.orchestrator.mission_loop.decider` is the hybrid and the model decider is at `.llm_decider`.
- **`--mode deterministic`** (the default) builds `DeterministicDecider` (`deciders/deterministic.py`) — a fixed rule ladder over normalized state (recon -> fingerprint web -> vuln-scan -> exploit intel -> report). No model; used for offline runs and CI.

If LLM mode is requested with no enabled `SABER_MODEL`, it falls back to deterministic.

### How the hybrid splits work

`HybridDecider` answers **forced** moves from the rule ladder and sends everything else to the model. A forced state is one where only one action is defensible, so paying ~8k prompt tokens for a model to restate it buys nothing:

- no services known at all -> scan
- an open web port whose host has no recorded technology -> fingerprint it

Everything else — which vulnerability scanner, which exploit query, whether to pivot — is genuine judgement and goes to the model. **The delegation is one-directional: the ladder must never override the model on a step with more than one reasonable answer.** `_is_forced` is therefore an allow-list of *states*, not "whatever the ladder happens to suggest". If you widen it, you are trading reasoning for tokens; there are tests pinning the boundary in both directions.

Every action carries `metadata["decided_by"]` (`"deterministic"` or `"llm"`) so the operator can see which steps were reasoned.

### Prompt economy (do not regress these)

Roughly 85% of the original per-decision token cost has been removed *without* reducing what the model sees. Three things are load-bearing:

- **The tool catalog lives in the system prompt, not the per-call payload.** It never changes during a mission, so it belongs in the cacheable prefix. `prompts/next_action.txt` refers to it as the `AVAILABLE TOOLS` section.
- **The payload is compact JSON with `sort_keys=True`.** `indent=2` cost ~1,350 tokens per call in whitespace. `sort_keys` is not cosmetic — a byte-stable payload is what makes provider-side caching possible.
- **The catalog is scoped by profile** via `ToolCatalog.for_profile()`, so a web mission is not offered mimikatz or ghidra. `RiskGate` deliberately keeps the **full** catalog, because it must classify anything proposed, including a tool the profile never offered.

`LlmClient` marks the system message cacheable only for model families that understand `cache_control` (Anthropic/Claude) and only above a size threshold. Sending it to a provider that rejects unknown fields is a 400, which fails the decision and with it the mission — so the fallback to a plain string is deliberate, not laziness.

## The operator console

`saber/ui/web/` is server-rendered FastAPI + Jinja + HTMX. No Node, no build step, and
every asset is self-hosted so it works air-gapped next to the sandbox.

- **HTML is never assembled in Python.** Routes build a small view model and hand it to a
  template. `app.py` used to be ~700 lines of concatenated HTML with an inline `<style>`;
  do not reintroduce that.
- `saber/ui/web/templating.py` — Jinja environment plus the view-model helpers
  (`build_spine`, `state_ledger`, `phase_strip`, `severity_counts`, `badge`).
- `templates/` and `static/` — pages, partials, `saber.css`, `saber.js`, vendored
  `htmx.min.js`. CSP is `script-src 'self'`, so nothing may come from a CDN.
- Live regions are HTMX partials that poll and **stop at terminal states**
  (`partials/state_panel.html.j2`, `partials/mission_status.html.j2`). Both own their
  wrapper element because they are swapped with `outerHTML`.
- A mission launched from the console is scoped to its target. The form promises this in
  its help text, and `RiskGate` treats `scope=None` as "allow every host", so the promise
  has to be kept in code.

`app` is a **module-level attribute** in `saber/ui/web/app.py` because `./run_saber` runs
`uvicorn saber.ui.web.app:app`. Tests that only call `create_app()` cannot catch its
removal, so a test pins it directly.

## The sandbox runs as root, deliberately

`docker/Dockerfile.sandbox` sets no `USER`. This is not an oversight, and
`tests/tools_tests/test_sandbox_runs_as_root.py` fails if someone "fixes" it:

- A non-root user does not inherit the container's capabilities, so the
  `NET_RAW`/`NET_ADMIN` that `DockerSubprocessRunner` grants become dead code.
- The Dockerfile removes nmap's file capabilities on purpose (Docker Desktop refuses to
  exec binaries carrying them), so file caps are not a fallback either.
- Consequence when `USER saber` was set: `nmap -sU`, masscan, responder and bettercap
  could not function at all, and on Linux the bind-mounted workspace was not writable.
  Nothing failed loudly; tools just returned permission errors.

The container is the isolation boundary: `--rm`, non-privileged, holding only the two
capabilities SABER asks for, running tooling designed to run as root.

## Known limitations

State these rather than implying otherwise:

- **A paused mission cannot resume.** `MissionLoop` returns `PAUSED_FOR_APPROVAL` and
  hands control back; the console can record approve/deny, but there is no path back into
  the loop. Autonomous runs should leave approval off.
- **Tool success is judged by exit code.** Some tools exit 0 while failing (whatweb
  returns 0 when it cannot resolve a host), so a step can be recorded as successful with
  no observations.
- **Lateral movement, attack chaining and LLM-authored custom scripts are implemented and
  unit-tested but not demonstrated** against a live multi-host target. The longest live
  LLM run so far was 2 steps.

## Commands

Tests run via the Makefile (they encode the right groupings and gate env vars):

```bash
make unit        # ALL offline suites (no Docker, no model). Covers unit, agent_tests,
                 # orchestration_tests, parser_tests, tools_tests, reporting_tests,
                 # model_tests, storage_tests, integration. Only tests/e2e_tests is
                 # excluded (gated). Do NOT hand-pick a subset of these directories:
                 # `unit` used to run only the first three, and a breaking change to
                 # the report adapter shipped green because reporting_tests never ran.
make smoke       # py_compile core files + a few high-value unit tests
make e2e         # Docker-gated E2E (sets SABER_RUN_DOCKER_E2E=1; needs Docker + real tools)
make llm-e2e     # live-model mission-loop acceptance (sets SABER_RUN_LLM_E2E=1 + SABER_RUN_DOCKER_E2E=1; real API calls; not in CI)
make final       # smoke + unit + e2e + preflight
pytest tests/unit/test_approval_gates.py::test_name -q   # single test
```

Sandbox and lab (both need Docker):

```bash
make sandbox-build   # build saber-sandbox:local from docker/Dockerfile.sandbox
make sandbox-verify  # ask the BUILT image whether every executable a tool CONTRACT
                     # invokes is on PATH. tests/tools_tests/test_sandbox_image_manifest.py
                     # is only a static proxy — it reads the Dockerfile, it cannot run it.
make lab-up          # DVWA, Juice Shop, Metasploitable, vulnbin on the saber-lab network,
                     # and writes runs/lab_scope.yaml
make lab-down        # tear the lab down
```

There is **no published sandbox image**. The default is the locally built
`saber-sandbox:local`, defined once as `DEFAULT_SHARED_IMAGE` in
`saber/core/docker_runner.py`; everything else imports it and a test pins the Makefile,
`.env.example` and `scripts/launch_saber.py` in step. A registry copy silently drifted
from the Dockerfile once — missing six contracted executables and running as the wrong
user for a month — and only a locally built image is one `make sandbox-verify` can vouch
for.

Lint/types are **not** run by any `make` target: `ruff check <files>` and `mypy saber` (config in `pyproject.toml`: ruff selects E,F,I,B,UP,SIM, line-length 100). NOTE: the repo carries **substantial pre-existing ruff debt** (~500 findings repo-wide, mostly E501). `ruff check saber tests` is not clean — scope lint to the files you touch; do not attempt a repo-wide fix.

## Key environment variables

Full list with defaults in `.env.example`. Key ones:

- `SABER_AGENT_MODE` — documented in `.env.example`, but the actual decider mode is read from the CLI `--mode` flag / the web form's `agent_mode` field, **not** from the environment (it is not read by `SaberConfig.from_env()` in `saber/core/runtime.py`). Setting only the env var does not change the mode.
- `SABER_MODEL`, `SABER_MODEL_API_KEY`, `SABER_LOCAL_MODEL_URL` — model config (used only in LLM mode).
- `SABER_SANDBOX_BACKEND` (docker), `SABER_SANDBOX_IMAGE` (`saber-sandbox:local`, built by `make sandbox-build`), `SABER_DOCKER_NETWORK` (host).
- `SABER_PROMPT_CACHE` — default `1`. Asks the provider to cache the static prompt prefix. Set `0` to disable if a provider misbehaves.
- `SABER_RUN_DOCKER_E2E`, `SABER_RUN_LLM_E2E` — default `0`; gate the E2E and live-model tests (see `make e2e` / `make llm-e2e`).

`autonomy_level` (`recon_only` / `assisted` / `autonomous`, default `autonomous`) tightens or relaxes the risk gate. It is carried in the mission constraints and `MissionState.autonomy_level` — **not yet exposed as a CLI or GUI flag**.

## Doc-accuracy note

The CLI `run` command uses a **required `--target` flag** (`python -m saber.ui.cli.main run --target 127.0.0.1 --profile recon`). Any older doc showing a positional target argument is wrong. Verify make targets against the `Makefile` and CLI flags against `saber/ui/cli/main.py` before quoting them.
