# SABER

## Scoped Automated Breach, Exploitation & Reporting

**SABER** is a self-hosted, evidence-first penetration testing operator platform. It runs real security tools through a Docker/Kali sandbox, parses the results, stores evidence, chains agent decisions, and exports reports from a local browser GUI.

The vision is simple:

```text
./run_saber
  ↓
Docker sandbox starts
  ↓
Browser GUI opens
  ↓
Operator enters target, scope, profile, and objective
  ↓
PlannerAgent builds the mission plan
  ↓
Agents run scoped tools safely
  ↓
Evidence is captured and parsed
  ↓
Findings are stored
  ↓
Reports are generated and linked in the GUI
```

SABER is built for **authorized assessments, internal security teams, labs, training ranges, and controlled research environments**.

---

## What SABER Does

SABER turns a pentest workflow into a repeatable mission pipeline:

```text
Target + Rules of Engagement
   ↓
PlannerAgent
   ↓
Recon / Web / Network / Exploit-Intel / Post-Exploit / Reporter agents
   ↓
Docker sandbox tool execution
   ↓
Evidence capture
   ↓
Parsers + ResultProcessor
   ↓
Findings, observations, evidence, reports
   ↓
GUI dashboard + downloadable deliverables
```

Instead of scattered terminals, notes, screenshots, and manual report writing, SABER gives the operator one cockpit for:

- Launching scoped missions
- Running real tools
- Watching agent progress
- Capturing evidence
- Parsing tool output
- Routing to the next correct agent
- Pausing risky actions for approval
- Exporting reports

---

## Current Capabilities

SABER currently supports the full local operator path:

- `./run_saber` starts the platform and opens the GUI.
- Docker sandbox execution is wired and validated.
- Browser mission form starts real missions.
- Mission detail page shows progress and status.
- PlannerAgent creates mission plans.
- StepRunner executes agent-selected tool actions.
- ResultProcessor parses evidence into observations and findings.
- ChainAgent routes based on discovered services.
- Approval gates pause risky actions.
- ReportFinalizer exports JSON, XLSX, Markdown, and PDF artifacts when supported.
- Reports are listed and downloadable from the GUI.
- CI runs on Linux, macOS, and Windows.
- Docker E2E validation is available on Linux.

Validated locally:

```text
pytest tests/ -q --tb=short -x
1046 passed, 9 skipped

make final
smoke: passed
unit: passed
e2e: passed
preflight: passed
```

---

## Quickstart

### 1. Clone and enter the repo

```bash
git clone https://github.com/AtharvKashyap/SABER.git
cd SABER
```

### 2. Create a Python environment

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

### 3. Configure environment

```bash
cp .env.example .env
```

Important defaults:

```text
SABER_SANDBOX_BACKEND=docker
SABER_SANDBOX_IMAGE=ghcr.io/atharvkashyap/saber-sandbox:kali-last-release
SABER_DOCKER_NETWORK=host
SABER_REQUIRE_APPROVAL=true
SABER_MAX_STEPS=50
```

For LLM mode:

```text
SABER_AGENT_MODE=llm
SABER_MODEL=openrouter:anthropic/claude-3.5-sonnet
SABER_MODEL_API_KEY=
```

For deterministic mode, use:

```text
SABER_AGENT_MODE=deterministic
```

Never commit `.env`.

### 4. Run SABER

```bash
./run_saber
```

This will:

1. Load `.env`.
2. Check Docker.
3. Start Docker Desktop on macOS if needed.
4. Pull/use the sandbox image.
5. Start the SABER web server.
6. Open the browser GUI.

Default GUI:

```text
http://127.0.0.1:8000/ui
```

Launch without opening a browser:

```bash
./run_saber --no-browser
```

---

## GUI Workflow

From `/ui`, use **Start Mission**.

Mission fields:

- Target
- Profile
- Mode
- Max steps
- Require approval
- Dry run
- Objective

Supported profiles:

```text
recon     PlannerAgent + ReconAgent + ReporterAgent
web       PlannerAgent + ReconAgent + WebAgent + ReporterAgent
network   PlannerAgent + ReconAgent + NetworkAgent + ReporterAgent
ad        PlannerAgent + ReconAgent + NetworkAgent + LateralMovementAgent + ReporterAgent
full      PlannerAgent + ReconAgent + WebAgent + NetworkAgent + ExploitAgent + PostExploitAgent + LateralMovementAgent + ReverseEngineerAgent + ReporterAgent
```

After a mission starts, the GUI shows:

- Session status
- Agent timeline
- Steps
- Records
- Findings
- Observations
- Evidence
- Pending approvals
- Report links

---

## Agents

SABER is agent-driven:

- **PlannerAgent** builds mission plans.
- **ReconAgent** discovers services and technologies.
- **ChainAgent** routes based on parsed observations.
- **WebAgent** runs web fingerprinting and safe web checks.
- **NetworkAgent** runs network enumeration when matching services exist.
- **ExploitAgent** handles exploit-intelligence and approval-gated validation paths.
- **PostExploitAgent** handles controlled post-exploit validation paths.
- **LateralMovementAgent** supports AD/lateral-movement path reasoning.
- **ReverseEngineerAgent** supports file and binary analysis workflows.
- **ReporterAgent** prepares final reporting context.

Agents can run deterministically or with an LLM decision engine.

---

## Tool Execution

Agents select structured tool actions. They do **not** run arbitrary shell commands.

Example capabilities:

```python
nmap.service_scan(target)
whatweb.fingerprint(url)
nuclei.template_scan(url)
searchsploit.lookup(product="Apache", version="2.4.49")
enum4linux.safe_enum(target)
snmpwalk.public_check(target)
```

Execution flow:

```text
Agent decision
  ↓
Tool wrapper
  ↓
Scope / approval checks
  ↓
DockerSubprocessRunner
  ↓
Raw evidence
  ↓
ParserRegistry
  ↓
ResultProcessor
  ↓
FindingStore / EvidenceIndex / GraphStore
```

Docker maps the repo into the container at:

```text
/workspace
```

Nmap service scans use TCP connect mode:

```text
-sT
```

This improves Docker Desktop compatibility.

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

Validated E2E slices include:

- Docker tool execution
- Real nmap execution
- Real nmap XML parsing
- Finding storage
- StepRunner integration
- ReconAgent mission execution
- ChainAgent routing
- WebAgent slice
- NetworkAgent slice
- Approval gates
- PlannerAgent mission planning
- Report export
- GUI mission start
- GUI mission progress polling

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
- Execution plans
- Steps
- Step records
- Evidence metadata
- Parsed observations
- Findings
- Pending approvals
- Report artifacts
- Graph nodes and edges where applicable

Report outputs:

- Findings JSON
- Findings workbook XLSX
- Technical Markdown report
- Executive Markdown report
- Technical PDF report when supported
- Executive PDF report when supported
- Mission result JSON

Reports are linked in the GUI and downloadable from the session page.

---

## Architecture

```text
saber/
  agents/              # Planner, recon, web, network, exploit, chain, reporter agents
  core/                # Runtime, Docker runner, evidence/result processing
  models/              # Targets, findings, sessions, credentials, AD, chains
  tools/               # Python wrappers around real security tools
  parsers/             # Tool output parsers
  orchestration/       # ExecutionPlan, StepRunner, ChainRunner, MissionOrchestrator
  storage/             # SQLite, sessions, evidence, findings, graph storage
  reporting/           # JSON, XLSX, Markdown, PDF exporters
  ui/                  # CLI and FastAPI web UI
  scripts/             # Launcher and preflight utilities
  docker/              # Kali sandbox image
  tests/               # Unit, agent, orchestration, parser, storage, E2E tests
```

---

## CLI Usage

The GUI is the main path, but the CLI is still available.

Run a mission:

```bash
python -m saber.ui.cli.main run 127.0.0.1 --profile recon --max-steps 8
```

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

---

## Development

Run fast checks:

```bash
make smoke
make unit
make e2e
make preflight
```

Run final validation:

```bash
make final
```

Run the full test suite:

```bash
pytest tests/ -q --tb=short -x
```

Makefile targets:

```text
test       Run all tests
unit       Run unit, agent, and orchestration tests
e2e        Run Docker E2E tests
e2e-one    Run planner/orchestrator/report E2E
smoke      Compile core files and run high-value smoke tests
preflight  Check whitespace, git status, and secret strings
launch     Run ./run_saber
final      Run smoke, unit, e2e, and preflight
```

---

## CI

CI includes:

- Linux tests
- macOS tests
- Windows tests
- Linux full non-Docker test suite
- Optional Linux Docker E2E workflow
- Sandbox image publishing workflow

Sandbox image:

```text
ghcr.io/atharvkashyap/saber-sandbox:kali-last-release
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
- Structured tool wrappers
- Scope-aware target handling
- Profile-based agent filtering
- Risk metadata
- Approval gates
- Evidence-first reporting
- Local-first storage

Before pushing code, run:

```bash
python scripts/preflight_secrets.py
```

---

## License

MIT