# SABER

## Scoped Automated Breach, Exploitation & Reporting

**SABER** is a self-hosted, evidence-first penetration testing operator platform. It runs real security tools through a Docker/Kali sandbox, parses the results into accumulating mission state, reasons about the next best action, and exports reports from a local browser GUI.

Unlike a fixed playbook runner, SABER drives each mission as an **agentic closed loop**. It does not build a static plan up front and then execute it. Instead it keeps a live picture of what it knows (`MissionState`) and, on every iteration, decides the single highest-value next action from that state, gates it for risk, runs it, folds the result back into state, and repeats until the objective is met or a stop condition fires.

```text
./run_saber
  ↓
Docker sandbox starts
  ↓
Browser GUI opens
  ↓
Operator enters target, scope, profile, objective
  ↓
Mission loop starts from a seeded MissionState
  ↓
    ┌────────────────────────────────────────────────────────┐
    │  observe → reason → decide → risk-gate → execute →       │
    │  normalize into MissionState → snapshot → stop-check     │
    │                        ↑                                 │
    └────────────────────────┘  repeat until done             │
  ↓
Evidence captured, parsed, and merged into state each step
  ↓
Report finalized from the final MissionState
  ↓
Deliverables listed and downloadable in the GUI
```

SABER is built for **authorized assessments, internal security teams, labs, training ranges, and controlled research environments**.

---

## The Mission Loop

The mission driver is a state-first agentic loop (`saber/orchestration/mission_loop.py`, `MissionLoop`). Each iteration does exactly this:

```text
                 ┌──────────────────────────────────────────────┐
   MissionState  │  1. summarize state        (StateSummarizer)  │
   (working  ───▶│  2. decide next action     (a Decider)        │
    memory)      │  3. risk-gate the action   (RiskGate)         │
                 │  4. execute via an agent    (ActionExecutor)   │
                 │  5. parse + normalize       (ResultProcessor + │
                 │        into MissionState     StateMerger)      │
                 │  6. snapshot                (MissionStateStore)│
                 │  7. check stop conditions   (StopEvaluator)    │
                 └──────────────────────────────────────────────┘
                          ▲                          │
                          └────── repeat ────────────┘
```

- The **decider** chooses one next action from the current state. There is no precomputed step list; the next move is always a function of what is known right now.
- The **risk gate** decides whether that action may auto-run, must pause for a one-click confirmation, or is refused outright (see [Autonomy & Safety](#autonomy--safety)).
- The **executor** dispatches the action to the capability agent that owns it and runs it in the sandbox. The loop decides; the agent executes.
- Tool output is parsed and **merged into `MissionState`** (new hosts, services, technologies, credentials, vulns, hypotheses, and the attempted/failed-action trace).
- The state is snapshotted after every step, so the GUI and the final report always read from real, persisted state.
- The loop terminates when the objective is met, the decider asks to stop/report, `max_steps` is reached, or an action keeps failing.

The plan-first driver (`ExecutionPlan` + `ChainRunner`) that older versions used to pre-plan and route missions has been retired. `ChainRunner` is deleted, and `MissionOrchestrator.run_mission()` now drives every mission exclusively through the loop.

---

## What SABER Does

SABER turns a pentest workflow into one repeatable, state-driven mission:

```text
Target + Objective + Scope (Rules of Engagement)
   ↓
Target strategy seeds MissionState + first move
   ↓
Mission loop:  decide → risk-gate → execute → normalize → repeat
   ↓
Capability agents run scoped tools in the Docker sandbox
   ↓
Parsers + ResultProcessor turn raw output into observations/findings
   ↓
StateMerger folds results into MissionState (hosts, services, vulns, ...)
   ↓
Report finalized from the final MissionState
   ↓
GUI dashboard + downloadable deliverables
```

Instead of scattered terminals, notes, screenshots, and manual report writing, SABER gives the operator one cockpit for:

- Launching scoped missions.
- Letting the loop pick and run the next best tool action.
- Watching mission state accumulate live.
- Capturing and parsing evidence.
- Pausing only genuinely risky actions for a one-click confirmation.
- Exporting evidence-backed reports.

---

## Current Capabilities

SABER currently supports the full local operator path:

- `./run_saber` starts the platform and opens the GUI.
- Docker sandbox execution is wired and validated.
- The browser mission form and the CLI both start real missions through the same loop.
- The mission is driven by a **state-first agentic loop** over `MissionState`, not a static plan.
- `MissionState` accumulates hosts, services, technologies, credentials, vulns, hypotheses, and the attempted/failed-action trace; it is persisted and snapshotted every step.
- Two deciders are available: an **LLM-primary decider** and a **deterministic rule-based decider** for offline/CI runs.
- **Risk-gated autonomy**: SABER runs autonomously by default and pauses only for high-risk/destructive actions; out-of-scope targets are always refused.
- The mission detail page shows a **live Mission State panel** in addition to steps, findings, evidence, and reports.
- Reports (JSON, XLSX, Markdown, PDF) are finalized from the final `MissionState` and are downloadable from the GUI.
- Local-first storage: SQLite database, evidence files, and reports all live under `runs/`.
- CI runs on Linux, macOS, and Windows. Docker-backed and live-model tests are gated and opt-in.

The unit, agent, and orchestration suites run fully offline (no Docker, no model). Docker-backed end-to-end tests are gated behind `SABER_RUN_DOCKER_E2E`, and live-model acceptance tests behind `SABER_RUN_LLM_E2E` (see [Development](#development)).

---

## Autonomy & Safety

Autonomy is enforced by the risk gate (`saber/orchestration/risk_gate.py`), which classifies every proposed action as **allow**, **confirm**, or **refuse** before it can run.

### Scope is a hard wall

If an action targets something outside the mission scope, or invokes a prohibited tool/action, it is **refused** — never offered for confirmation and never run. Scope is checked first, ahead of any autonomy consideration.

### The high-risk confirmation gate

By default SABER runs autonomously. Low- and medium-risk enumeration proceeds without interruption. Only **high-risk / destructive** actions (or actions the decider flags as requiring confirmation) pause the mission for a **one-click confirmation** before proceeding. When paused, the mission records an approval request and surfaces it in the GUI.

### Per-mission autonomy level

Every mission runs at an `autonomy_level` (default `autonomous`) that tightens or relaxes the gate:

| Level          | Behavior                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `recon_only`   | Exploit-class actions (exploitation, post-exploit, lateral movement) are **refused**. Recon and enumeration proceed. |
| `assisted`     | Exploit-class actions **and** any medium-or-higher-risk action pause for confirmation.            |
| `autonomous`   | Runs automatically; pauses only for high-risk actions or actions explicitly marked as needing confirmation. This is the default. |

Regardless of level, out-of-scope targets are always refused.

### Stop conditions

The loop terminates (`saber/orchestration/stop_conditions.py`) when any of these hold:

- The objective is met (the active target strategy reports success).
- The decider asks to stop or to write the final report.
- `max_steps` is reached.
- The same action keeps failing (repeated-failure guard).

---

## Quickstart

### 1. Clone and enter the repo

```bash
git clone https://github.com/AtharvKashyap/SABER.git
cd SABER
```

### 2. Create a Python environment

SABER requires Python 3.11+.

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
```

Installing the package in editable mode (`python -m pip install -e .`) also works.

### 3. Configure environment

```bash
cp .env.example .env
```

`.env` configures the model and the sandbox. Key variables (see `.env.example` for the full list):

```text
# Model (used only when a mission runs in LLM mode)
SABER_MODEL=openrouter:anthropic/claude-3.5-sonnet   # or "disabled", or local:<model>
SABER_MODEL_API_KEY=                                  # required for hosted models

# Sandbox
SABER_SANDBOX_BACKEND=docker
SABER_SANDBOX_IMAGE=saber-sandbox:local
SABER_DOCKER_NETWORK=host
```

The **decision mode** (deterministic vs. LLM) is chosen **per mission** — with `--mode` on the CLI or the Mode field in the GUI — not by an environment toggle. LLM mode also needs a configured, enabled `SABER_MODEL`; if no model is enabled, SABER falls back to the deterministic decider.

Never commit `.env`.

### 4. Run SABER

```bash
./run_saber
```

This will:

1. Activate `.venv` and load `.env`.
2. Check Docker (and start Docker Desktop on macOS if needed).
3. Pull/use the sandbox image.
4. Start the SABER web server and open the GUI.

Default GUI:

```text
http://127.0.0.1:8000/ui
```

Launch without opening a browser:

```bash
./run_saber --no-browser
```

---

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

---

## GUI Workflow

From `/ui`, use **Start Mission**.

Mission fields:

- Target
- Profile
- Strategy (`auto`, `network`, `web`, or `ctf`)
- Lab (marks the target as an owned lab and selects the CTF strategy; does not currently change risk-gating)
- Mode (deterministic or LLM)
- Max steps
- Require approval
- Dry run
- Objective

> Note: Pausing for approval is governed by the risk gate and the mission's autonomy level, not the **Require approval** toggle — the mission loop's `RiskGate` does not currently consume it.

Profiles select which capability agents the loop may dispatch to:

```text
recon     recon + reporter
web       recon + web + reporter
network   recon + network + reporter
ad        recon + network + lateral-movement + reporter
full      recon + web + network + exploit + post-exploit + lateral-movement + reverse-engineer + reporter
```

(All profiles also include the planner agent, used as an optional recon-seed helper.)

After a mission starts, the mission detail page shows:

- Session status
- A **live Mission State panel** (hosts, services, technologies, vulns, hypotheses, and the attempted-action timeline), polled from `GET /api/sessions/{session_id}/state`
- Steps and records
- Findings and observations
- Evidence
- Pending approvals (one-click confirmation for gated actions)
- Report links

---

## Agents

The nine agents are **capability lenses** the loop dispatches execution through — not mission drivers. The decider picks the next action; `ActionExecutor` hands it to the agent that owns that capability, which runs the tool in the sandbox. Agents no longer decide the mission's direction.

- **ReconAgent** — service and technology discovery.
- **WebAgent** — web fingerprinting and safe web checks.
- **NetworkAgent** — network enumeration for matching services.
- **ExploitAgent** — exploit-intelligence and gated validation paths.
- **PostExploitAgent** — controlled post-exploit validation paths.
- **LateralMovementAgent** — AD / lateral-movement reasoning.
- **ReverseEngineerAgent** — file and binary analysis workflows.
- **ReporterAgent** — reporting context.
- **PlannerAgent** — optional recon-seed helper (no longer drives missions).

---

## Deciders & Modes

The decider is the loop's brain. SABER ships two, selected per mission by mode:

- **`LlmDecider`** (`--mode llm`, or the GUI Mode field): asks the configured model for the next action, using the `prompts/next_action.txt` system prompt. Every proposed action is validated against the tool catalog and the scope before it can run. Requires an enabled `SABER_MODEL`.
- **`DeterministicDecider`** (`--mode deterministic`, the default): a rule ladder over normalized state (recon first, then fingerprint web services, then vuln-scan, then exploit intel, then report). It needs no model and is used for offline runs and CI.

If LLM mode is requested but no model is enabled, SABER uses the deterministic decider.

---

## Target Strategies

A target strategy (`saber/orchestration/strategies/`) seeds the mission: it sets the default objective and first move, and defines what "objective met" means. The loop itself is identical across target types.

- **Network / IP** (`NetworkStrategy`): enumerate the host, identify services and known vulnerabilities. Objective met once vulns are known and exploit intel is gathered.
- **Web / URL** (`WebStrategy`): fingerprint the target and run safe web vulnerability checks. Objective met once technologies are fingerprinted and a web scan has run.
- **CTF / SSH box** (`CtfStrategy`): recon → foothold → credentials/sessions → post-exploit/lateral → capture the flag. Objective met once a flag or credentials are captured.

The strategy is chosen automatically from the target type (and CTF/lab metadata).

---

## Tool Execution

Actions select structured tool operations. They do **not** run arbitrary shell commands.

Example tool actions:

```python
nmap.service_scan(target)
whatweb.fingerprint(url)
nuclei.template_scan(url)
searchsploit.lookup(product="Apache", version="2.4.49")
enum4linux.safe_enum(target)
snmpwalk.public_check(target)
```

Execution flow for one loop step:

```text
Decider chooses an action
  ↓
RiskGate  (allow / confirm / refuse)
  ↓
Capability agent + tool wrapper
  ↓
DockerSubprocessRunner (sandbox)
  ↓
Raw evidence
  ↓
ParserRegistry
  ↓
ResultProcessor
  ↓
FindingStore / EvidenceIndex / GraphStore
  ↓
StateMerger folds results into MissionState
```

Docker maps the repo into the container at `/workspace`. Nmap service scans use TCP connect mode (`-sT`) for Docker Desktop compatibility.

---

## Tool Coverage

Current and planned tool categories:

```text
tools/
  recon/                 # nmap, masscan, amass, subfinder, whatweb, dnsrecon
  web/                   # nuclei, nikto, feroxbuster, ZAP, sqlmap
  network/               # enum4linux, snmpwalk, OpenVAS/GVM, Responder/Bettercap stubs
  active_directory/      # BloodHound-style, Impacket, NetExec workflows
  exploitation/          # SearchSploit, controlled Metasploit paths
  password/              # hashcat, john
  post_exploit/          # linPEAS, winPEAS, chisel, controlled impact checks
  lateral_movement/      # Path planning and session validation
  reverse_engineering/   # file, strings, checksec, radare2, Ghidra headless
```

---

## Evidence and Reports

Default local storage:

```text
runs/saber.db
runs/evidence/
runs/reports/
```

SABER stores:

- Sessions
- MissionState snapshots (working memory, per step)
- Steps and step records
- Evidence metadata
- Parsed observations
- Findings
- Pending approvals
- Report artifacts
- Graph nodes and edges where applicable

On completion, the loop finalizes reports from the final `MissionState` (via `saber/reporting/state_report_adapter.py` and the existing exporters):

- Findings JSON
- Findings workbook (XLSX)
- Technical Markdown report
- Executive Markdown report
- Technical PDF report (when supported)
- Executive PDF report (when supported)
- Mission result JSON

Reports are linked in the GUI and downloadable from the session page.

---

## Architecture

```text
saber/
  agents/              # Capability agents (recon, web, network, exploit,
                       #   post_exploit, lateral_movement, reverse_engineering,
                       #   reporter, planner) + deciders/ (llm, deterministic)
  core/                # Runtime, Docker runner, sandbox, result processing,
                       #   state summarizer/merger, LLM client, tool catalog
  models/              # Targets, findings, sessions, scope, credentials,
                       #   and mission_state (working memory)
  orchestration/       # mission_loop, mission_orchestrator, action_executor,
                       #   risk_gate, stop_conditions, strategies/,
                       #   execution_plan + step_runner (seed/exec helpers)
  tools/               # Python wrappers around real security tools
  parsers/             # Tool output parsers
  storage/             # SQLite, sessions, evidence, findings, graph,
                       #   mission_state_store, migrations/
  reporting/           # JSON/XLSX/PDF/Markdown exporters, finalizer,
                       #   state_report_adapter, templates
  ui/                  # CLI and FastAPI web UI

prompts/               # Decider prompts (next_action.txt)
scripts/               # Launcher and preflight utilities
docker/                # Kali sandbox image
tests/                 # unit, agent, orchestration, parser, storage,
                       #   model, reporting, tools, integration, e2e suites
```

---

## CLI Usage

The GUI is the main path, but the CLI runs the same mission loop.

Run a mission:

```bash
python -m saber.ui.cli.main run --target 127.0.0.1 --profile recon --max-steps 8
```

Choose the decider with `--mode {deterministic,llm}` (default `deterministic`). `--profile` accepts `recon`, `web`, `network`, `ad`, or `full`. `--strategy {auto,network,web,ctf}` overrides which target strategy seeds the mission (default `auto`, chosen from the target type). `--lab` marks the target as an owned lab and selects the CTF strategy; it does not currently change risk-gating. `--scope <file>` enforces a scope YAML file (for example the `runs/lab_scope.yaml` written by `make lab-up`). Other useful flags: `--objective`, `--mission-name`, `--no-approval`, `--dry-run`. Note that `--no-approval` only records a mission constraint; pausing is governed by the risk gate and autonomy level (the loop's `RiskGate` does not currently consume it).

Show live status:

```bash
python -m saber.ui.cli.main live <session_id>
```

List findings:

```bash
python -m saber.ui.cli.main findings list <session_id>
```

Export a report manually:

```bash
python -m saber.ui.cli.main reports export <session_id> --format json --output runs/reports/report.json
```

Other subcommands: `doctor`, `sessions`, `approvals`, `evidence`, and `sandbox check`.

---

## Development

Run fast checks:

```bash
make smoke       # compile core files + run high-value smoke tests
make unit        # unit, agent, and orchestration suites (offline; no Docker/model)
make e2e         # Docker-backed E2E (sets SABER_RUN_DOCKER_E2E=1; needs Docker)
make preflight   # whitespace, git status, and secret-string checks
```

Run final validation:

```bash
make final       # smoke + unit + e2e + preflight
```

Run the live-model acceptance tests (gated, opt-in):

```bash
make llm-e2e     # sets SABER_RUN_LLM_E2E=1 and SABER_RUN_DOCKER_E2E=1
```

`make llm-e2e` exercises the mission loop end to end against a live model. It requires a configured model (`SABER_MODEL` / `SABER_MODEL_API_KEY`) **and** Docker, makes real API calls, and is skipped in CI. It is not part of `make final`.

Run the full test suite directly:

```bash
pytest tests/ -q --tb=short -x
```

Makefile targets:

```text
test       Run all tests
unit       Run unit, agent, and orchestration tests (offline)
e2e        Run Docker-backed E2E tests (SABER_RUN_DOCKER_E2E=1)
e2e-one    Run the planner/orchestrator/report E2E slice
llm-e2e    Run the gated live-model mission-loop acceptance test
smoke      Compile core files and run high-value smoke tests
preflight  Check whitespace, git status, and secret strings
launch     Run ./run_saber
final      Run smoke, unit, e2e, and preflight
lab-up     Build vulnbin, create the saber-lab network, start lab targets,
           and write runs/lab_scope.yaml
lab-down   Stop and remove the lab targets and network
```

The `SABER_RUN_DOCKER_E2E` and `SABER_RUN_LLM_E2E` flags default to `0`; the tests they gate are skipped unless the flag is set (see `.env.example`).

---

## CI

CI includes:

- Linux tests
- macOS tests
- Windows tests
- Linux full non-Docker test suite
- Optional Linux Docker E2E workflow
- Sandbox image publishing workflow

Live-model acceptance tests (`SABER_RUN_LLM_E2E`) are never run in CI; they are for local acceptance only.

Sandbox image:

```text
saber-sandbox:local
```

---

## Safety and Ethics

SABER is for authorized testing only.

Use it only against:

- Systems you own
- Systems you have explicit permission to test
- Internal security environments
- Training ranges
- Lab targets

Safety controls include:

- Docker sandbox execution
- Structured tool wrappers (no arbitrary shell)
- Scope enforced as a hard wall (out-of-scope actions refused)
- Risk-gated autonomy with a high-risk confirmation gate
- Per-mission autonomy levels
- Evidence-first reporting
- Local-first storage

Before pushing code, run:

```bash
python scripts/preflight_secrets.py
```

---

## License

MIT
