# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What SABER is

SABER (Scoped Automated Breach, Exploitation & Reporting) is a self-hosted, evidence-first penetration-testing operator platform for **authorized assessments only**. A mission does not run a pre-built plan; it runs as a **state-first agentic loop** that keeps a live picture of what it knows (`MissionState`) and, each iteration, decides the single highest-value next action from that state, risk-gates it, runs it in a Docker/Kali sandbox, folds the parsed result back into state, and repeats until the objective is met or a stop condition fires. Python package is `saber/` (requires Python >=3.11); main branch for PRs is `main`.

## Core architecture — the loop

The mission driver is `saber/orchestration/mission_loop.py` (`MissionLoop`). **This is the entry point to understand; start here.** `MissionOrchestrator.run_mission()` builds state + session and drives every mission exclusively through `MissionLoop.run()`.

**The five files to read first:**
1. `saber/orchestration/mission_loop.py` — the loop itself (`MissionLoop.run`).
2. `saber/models/mission_state.py` — `MissionState`, the accumulating working memory the loop reasons over.
3. `saber/agents/deciders/base.py` + `saber/agents/deciders/llm.py` — the `NextActionDecider` interface (`ProposedAction`, `ActionKind`, `RiskLevel`) and the LLM decider.
4. `saber/core/state_merger.py` — `StateMerger`, how parsed observations fold into `MissionState`.
5. `saber/orchestration/risk_gate.py` — `RiskGate`, the autonomy/scope gate.

### Data flow (one iteration)

```
summarize (StateSummarizer)                     saber/core/state_summary.py
  -> decide (NextActionDecider)                 deciders/llm.py | deciders/deterministic.py
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

## Deterministic vs LLM decider

The decision mode is chosen **per mission** via `agent_mode`, not a persistent env toggle:

- **`LlmDecider`** (`deciders/llm.py`) — `--mode llm` on the CLI or the Mode field in the GUI form. Asks the configured model using the `prompts/next_action.txt` system prompt and validates every proposed `tool_name`/`tool_action` against `ToolCatalog` and scope before it can run. Requires an enabled `SABER_MODEL`; if no model is enabled it falls back to deterministic.
- **`DeterministicDecider`** (`deciders/deterministic.py`, the default) — a fixed rule ladder over normalized state (recon -> fingerprint web -> vuln-scan -> exploit intel -> report). No model; used for offline runs and CI.

## Commands

Tests run via the Makefile (they encode the right groupings and gate env vars):

```bash
make unit        # offline: tests/unit + tests/agent_tests + tests/orchestration_tests (no Docker, no model)
make smoke       # py_compile core files + a few high-value unit tests
make e2e         # Docker-gated E2E (sets SABER_RUN_DOCKER_E2E=1; needs Docker + real tools)
make llm-e2e     # live-model mission-loop acceptance (sets SABER_RUN_LLM_E2E=1 + SABER_RUN_DOCKER_E2E=1; real API calls; not in CI)
make final       # smoke + unit + e2e + preflight
pytest tests/unit/test_approval_gates.py::test_name -q   # single test
```

Lint/types are **not** run by any `make` target: `ruff check <files>` and `mypy saber` (config in `pyproject.toml`: ruff selects E,F,I,B,UP,SIM, line-length 100). NOTE: the repo carries **substantial pre-existing ruff debt** (~500 findings repo-wide, mostly E501). `ruff check saber tests` is not clean — scope lint to the files you touch; do not attempt a repo-wide fix.

## Key environment variables

Full list with defaults in `.env.example`. Key ones:

- `SABER_AGENT_MODE` — documented in `.env.example`, but the actual decider mode is read from the CLI `--mode` flag / the web form's `agent_mode` field, **not** from the environment (it is not read by `SaberConfig.from_env()` in `saber/core/runtime.py`). Setting only the env var does not change the mode.
- `SABER_MODEL`, `SABER_MODEL_API_KEY`, `SABER_LOCAL_MODEL_URL` — model config (used only in LLM mode).
- `SABER_SANDBOX_BACKEND` (docker), `SABER_SANDBOX_IMAGE` (`ghcr.io/atharvkashyap/saber-sandbox:kali-last-release`), `SABER_DOCKER_NETWORK` (host).
- `SABER_RUN_DOCKER_E2E`, `SABER_RUN_LLM_E2E` — default `0`; gate the E2E and live-model tests (see `make e2e` / `make llm-e2e`).

`autonomy_level` (`recon_only` / `assisted` / `autonomous`, default `autonomous`) tightens or relaxes the risk gate. It is carried in the mission constraints and `MissionState.autonomy_level` — **not yet exposed as a CLI or GUI flag**.

## Doc-accuracy note

The CLI `run` command uses a **required `--target` flag** (`python -m saber.ui.cli.main run --target 127.0.0.1 --profile recon`). Any older doc showing a positional target argument is wrong. Verify make targets against the `Makefile` and CLI flags against `saber/ui/cli/main.py` before quoting them.
