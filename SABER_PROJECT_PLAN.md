# SABER

## Scoped Automated Breach, Exploitation & Reporting

> A self-hosted, evidence-first internal-network and web/app penetration testing platform. Accepts a target scope and rules of engagement. Returns a full kill-chain execution, evidence bundle, and multi-format report — without the infrastructure weight of enterprise competitors.

---

## Table of Contents

1. [Philosophy & Design Decisions](#1-philosophy--design-decisions)
   - [Core Principles](#core-principles)
   - [What This Is Not](#what-this-is-not)
2. [System Architecture Overview](#2-system-architecture-overview)
   - [Technology Assignments](#technology-assignments-updated)
3. [Full Project Structure](#3-full-project-structure)
4. [Layer-by-Layer Component Specs](#4-layer-by-layer-component-specs)
   - [4.1 Operator Interface](#41-operator-interface)
   - [4.2 Mission Planner Agent](#42-mission-planner-agent)
   - [4.3 Sub-Agents](#43-sub-agents)
   - [4.4 Tool Execution Layer — Now Sandbox-Aware](#44-tool-execution-layer--now-sandbox-aware)
   - [4.5 Approval Gate — New Component](#45-approval-gate--new-component)
   - [4.6 Output Normalizer & Evidence Store](#46-output-normalizer--evidence-store)
   - [4.7 Phase Graph — Upgraded Hierarchy](#47-phase-graph--upgraded-hierarchy)
   - [4.8 Reporting Agent](#48-reporting-agent)
5. [Core Data Schemas](#5-core-data-schemas)
   - [ADPrincipal — New](#adprincipal--new)
   - [ApprovalRecord — New](#approvalrecord--new)
6. [Agent System Prompt Designs](#6-agent-system-prompt-designs)
7. [Tool Wrapper Inventory](#7-tool-wrapper-inventory)
   - [Phase 4 — Active Directory](#phase-4--active-directory-new--formerly-listed-as-a-deferred-future-module)
   - [Updated Phase Ordering](#updated-phase-ordering)
8. [Storage & Database Design](#8-storage--database-design)
9. [Configuration System](#9-configuration-system)
10. [Build Phases (Chip-by-Chip)](#10-build-phases-chip-by-chip)
11. [Testing Strategy](#11-testing-strategy)
12. [Security & Operational Safeguards](#12-security--operational-safeguards)
13. [Future Modules](#13-future-modules)
14. [Technology Decision Log](#14-technology-decision-log)
15. [Requirements](#requirements-updated)
   - [requirements.txt](#requirementstxt)
   - [requirements-dev.txt](#requirements-devtxt)
   - [Kali / Host Setup](#kali--host-setup)

---

## 1. Philosophy & Design Decisions

### Core Principles

**Separation of concerns over monolithic chains.** The AI never directly invokes tools. It reads normalized data, makes decisions, and issues structured commands. A deterministic Python execution layer handles all subprocess work inside sandboxed containers. A crashed tool never crashes the AI orchestrator, and a misbehaving tool never escapes its container.

**Schema-first design.** The `Finding` dataclass is the contract between every component. Tools produce it. Agents read it. The reporter synthesizes it. Nothing communicates via raw tool output strings.

**Every run is reproducible.** A complete session is saved to SQLite at every step, structured as flow → task → subtask → action. Any phase can be re-run or resumed without re-running prior phases. Raw tool output is always preserved alongside normalized findings.

**Scope enforcement is non-negotiable.** A `ScopeGuard` class wraps every tool invocation. No IP, domain, or port outside the declared scope can be touched — at the Python level, not just by agent instruction.

**Containment is non-negotiable.** Every tool runs inside an ephemeral, per-session Docker container, not on the host. This is a hard architectural requirement, not a configurable convenience — it's the difference between "an AI agent that can theoretically be told to stay in scope" and "an AI agent that is physically unable to touch anything outside its sandbox and declared targets."

**Evidence-first reporting.** Every finding must have attached evidence before it's reportable: a raw command, its output, a screenshot where applicable, and a timestamp. Unattested findings are flagged `UNVERIFIED` and excluded from the executive summary.

**Human authority is preserved, not assumed away.** Full autonomy is the default operating mode, but the operator can require explicit approval before any exploitation or post-exploitation action fires, without losing the rest of the automation.

### What This Is Not

- Not a single Claude agent calling `subprocess.run()` in a loop
- Not an n8n workflow — n8n is a webhook/SaaS glue layer; this needs real subprocess and container control
- Not a tool that covers every Kali tool — it covers the kill chain with best-of-breed tools per phase
- Not a heavyweight multi-service platform requiring Postgres, Neo4j, Redis, ClickHouse, and MinIO just to run one engagement
- Not a web-app-only scanner — internal network and Active Directory attack chains are first-class, not bolted on
- Not a replacement for a human pentester — it generates verified, reproducible evidence that a human reviews and attests

---

## 2. System Architecture Overview

```text
┌─────────────────────────────────────────────────────────┐
│                    OPERATOR INTERFACE                   │
│   scope.yaml · roe.yaml · --interactive flag (optional) │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│              MISSION PLANNER AGENT (Claude)             │
│   Reads scope → builds flow/task/subtask graph          │
│   dispatches agents → gates phase progression           │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┘
   │          │          │          │          │
┌──▼──┐  ┌────▼───┐  ┌───▼──────┐  ┌▼──────┐  ┌──▼─────┐
│Recon│  │  Web   │  │Network/AD│  │Exploit│  │  Post  │
│Agent│  │ Agent  │  │  Agent   │  │Agent  │  │ Exploit│
└──┬──┘  └────┬───┘  └────┬─────┘  └───┬───┘  └──┬─────┘
   │          │           │            │          │
┌──▼──────────▼───────────▼────────────▼──────────▼────────┐
│         APPROVAL GATE (optional, --interactive only)     │
│   allow-once / allow-session / deny per sensitive action │
└───────────────────────┬──────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│      EPHEMERAL DOCKER SANDBOX (per-session container)   │
│   ScopeGuard validates target → tool runs in container  │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│         TOOL EXECUTION LAYER (Python wrappers)          │
│  nmap · amass · nuclei · feroxbuster · sqlmap · msf     │
│  bloodhound · impacket · crackmapexec · hashcat · ...   │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│              OUTPUT NORMALIZER                          │
│   Raw output → Finding schema → Evidence store          │
└───────────────────────┬─────────────────────────────────┘
                        │
                        │ findings JSON fed back up
                        │
┌───────────────────────▼─────────────────────────────────┐
│              REPORTING AGENT (Claude)                   │
│  Reads all Finding JSON → CVSS scoring → narrative      │
└──┬─────────┬──────────┬─────────────────────────────────┘
   │         │          │
┌──▼──┐  ┌───▼──┐  ┌────▼──┐
│ PDF │  │ XLSX │  │ JSON  │
└─────┘  └──────┘  └───────┘
```

### Technology Assignments (Updated)

| Layer | Technology | Rationale |
|---|---|---|
| Agent orchestration | Anthropic API (Claude) with tool use | Direct control, no framework magic to debug |
| Multi-agent coordination | Python async + queue | Transparent, no hidden abstraction layers |
| Tool execution | Python `asyncio.subprocess` **inside Docker container** | Timeout/kill/stderr control + host isolation |
| Container runtime | Docker (Kali rolling base image) | Industry-standard isolation; matches every serious competitor |
| Finding storage | SQLite via `aiosqlite` | Zero-config, file-portable, queryable — kept deliberately lightweight |
| Evidence storage | Local filesystem, structured paths | Never goes to cloud; reproducible |
| CLI interface | `click` + `rich` | Rich gives live progress panels |
| Web UI (optional phase) | FastAPI + Jinja2 | Lightweight, no framework overhead |
| Report PDF | `reportlab` | Programmatic, no LaTeX dependency |
| Report XLSX | `openpyxl` | Industry standard for analyst handoff |
| Config | YAML via `pyyaml` + Pydantic validation | Human-readable, machine-validated |
| Metasploit interface | `pymetasploit3` (MSFRPC) | Real API instead of fragile msfconsole subprocess |
| ZAP interface | `python-owasp-zap-v2.4` official client | Avoid hand-rolling REST calls |
| CVSS scoring | `cvss` pip package | Avoid writing your own vector parser/calculator |
| AD attack tooling | `bloodhound-python`, `impacket`, `crackmapexec` / `netexec` | Industry-standard, reused not rebuilt |
| Approval gating | Custom `ApprovalGate` state machine | PentesterFlow-inspired allow-once/allow-session/deny |

---

## 3. Full Project Structure

```text
saber/
│
├── README.md
├── SABER_PROJECT_PLAN.md                 ← this document
├── MARKET_RESEARCH.md                    ← competitive research reference
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
├── pyproject.toml
│
├── saber/                                # main package
│   │
│   ├── __init__.py
│   │
│   ├── core/                             # mission control, not AI-specific
│   │   ├── __init__.py
│   │   ├── mission.py                    # MissionController: top-level run loop
│   │   ├── session.py                    # SessionManager: load/save/resume state
│   │   ├── scope_guard.py                # ScopeGuard: enforce IP/domain/port limits
│   │   ├── phase_graph.py                # PhaseGraph: flow → task → subtask → action DAG
│   │   ├── sandbox.py                    # SandboxManager: future per-session container lifecycle
│   │   ├── docker_runner.py              # cross-platform Docker CLI helpers for sandbox commands
│   │   ├── approval_gate.py              # ApprovalGate: allow-once/allow-session/deny gating
│   │   └── evidence_store.py             # EvidenceStore: screenshot + file management
│   │
│   ├── agents/                           # Claude-powered decision layers
│   │   ├── __init__.py
│   │   ├── base_agent.py                 # BaseAgent: Anthropic API wrapper + retry logic
│   │   ├── planner.py                    # MissionPlannerAgent
│   │   ├── recon.py                      # ReconAgent
│   │   ├── web.py                        # WebAgent
│   │   ├── network.py                    # NetworkAgent (now includes AD attack logic)
│   │   ├── exploit.py                    # ExploitAgent
│   │   ├── post_exploit.py               # PostExploitAgent
│   │   └── reporter.py                   # ReportingAgent
│   │
│   ├── tools/                            # deterministic subprocess wrappers
│   │   ├── __init__.py
│   │   ├── base_wrapper.py               # ToolWrapper base class (now sandbox-aware)
│   │   │
│   │   ├── recon/
│   │   │   ├── __init__.py
│   │   │   ├── nmap.py
│   │   │   ├── masscan.py
│   │   │   ├── amass.py
│   │   │   ├── subfinder.py
│   │   │   ├── theharvester.py
│   │   │   ├── dnsrecon.py
│   │   │   └── whatweb.py
│   │   │
│   │   ├── web/
│   │   │   ├── __init__.py
│   │   │   ├── feroxbuster.py
│   │   │   ├── nuclei.py
│   │   │   ├── sqlmap.py
│   │   │   ├── nikto.py
│   │   │   └── zap_api.py                # via python-owasp-zap-v2.4
│   │   │
│   │   ├── network/
│   │   │   ├── __init__.py
│   │   │   ├── openvas_api.py            # via python-gvm
│   │   │   ├── responder.py
│   │   │   ├── bettercap.py
│   │   │   ├── enum4linux.py
│   │   │   └── snmpwalk.py
│   │   │
│   │   ├── active_directory/             # NEW — promoted from future module to core
│   │   │   ├── __init__.py
│   │   │   ├── bloodhound.py             # bloodhound-python ingestor wrapper
│   │   │   ├── impacket_tools.py         # secretsdump, GetUserSPNs, wmiexec wrappers
│   │   │   └── netexec.py                # crackmapexec/netexec wrapper
│   │   │
│   │   ├── exploitation/
│   │   │   ├── __init__.py
│   │   │   ├── metasploit.py             # via pymetasploit3 (MSFRPC)
│   │   │   └── searchsploit.py
│   │   │
│   │   ├── post_exploit/
│   │   │   ├── __init__.py
│   │   │   ├── mimikatz.py
│   │   │   ├── linpeas.py
│   │   │   ├── winpeas.py
│   │   │   └── chisel.py
│   │   │
│   │   └── password/
│   │       ├── __init__.py
│   │       ├── hashcat.py
│   │       └── john.py
│   │
│   ├── models/                           # Pydantic dataclasses: the schema contract
│   │   ├── __init__.py
│   │   ├── finding.py                    # Finding (the central model)
│   │   ├── evidence.py                   # Evidence (attached proof)
│   │   ├── scope.py                      # Scope + RulesOfEngagement
│   │   ├── session.py                    # SessionState
│   │   ├── target.py                     # Target (host/service/url)
│   │   ├── credential.py                 # Credential (captured creds vault)
│   │   └── ad_principal.py               # NEW — AD user/group/computer/ACL relationship model
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py                   # async SQLite via aiosqlite
│   │   └── migrations/
│   │       ├── 001_initial.sql
│   │       └── 002_ad_and_approvals.sql  # NEW — AD principals + approval log tables
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── pdf_exporter.py               # reportlab PDF builder
│   │   ├── xlsx_exporter.py              # openpyxl workbook builder
│   │   ├── json_exporter.py              # raw JSON dump
│   │   └── templates/
│   │       ├── executive_summary.md.j2
│   │       └── technical_report.md.j2
│   │
│   └── ui/
│       ├── __init__.py
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py                   # click entry point
│       │   ├── doctor.py                 # environment and sandbox readiness checks
│       │   ├── sandbox_commands.py       # build/status/shell commands for Docker sandbox
│       │   ├── approval_prompt.py        # interactive approval UI
│       │   └── live_panel.py             # rich live dashboard
│       └── web/                          # optional, phase 4+
│           ├── __init__.py
│           ├── app.py
│           └── routers/
│               ├── sessions.py
│               ├── findings.py
│               └── reports.py
│
├── prompts/                              # externalized agent system prompts
│   ├── planner.txt
│   ├── recon_agent.txt
│   ├── web_agent.txt
│   ├── network_agent.txt                 # now includes AD attack methodology
│   ├── exploit_agent.txt
│   ├── post_exploit_agent.txt
│   └── reporter.txt
│
├── docker/                               # NEW
│   ├── Dockerfile.sandbox                # Kali rolling base + tool installs
│   └── docker-compose.sandbox.yml        # optional multi-container setup
│
├── config/
│   ├── scope.yaml.example
│   ├── roe.yaml.example
│   └── tools.yaml
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_scope_guard.py
│   │   ├── test_finding_schema.py
│   │   ├── test_phase_graph.py
│   │   ├── test_sandbox.py               # NEW — mocked Docker lifecycle
│   │   ├── test_approval_gate.py         # NEW
│   │   └── test_tool_wrappers.py
│   ├── integration/
│   │   ├── test_recon_agent.py
│   │   ├── test_ad_attack_chain.py       # NEW — against a lab AD environment
│   │   └── test_full_pipeline.py
│   └── fixtures/
│       ├── sample_nmap_output.xml
│       ├── sample_nuclei_output.json
│       ├── sample_bloodhound_output.json # NEW
│       └── sample_scope.yaml
│
├── examples/
│   ├── sample_executive_summary.pdf
│   ├── sample_technical_report.pdf
│   ├── sample_findings.json
│   └── sample_scope.yaml
│
├── output/
│   └── .gitkeep
│
└── sessions/
    └── .gitkeep
```

---

## 4. Layer-by-Layer Component Specs

### 4.1 Operator Interface

**Files:** `saber/ui/cli/main.py`, `config/scope.yaml`

Unchanged in spirit from the original plan, with one addition: an `--interactive` flag.

```bash
# Fully autonomous run (default — matches original vision)
saber run --scope config/scope.yaml --roe config/roe.yaml

# Interactive mode — exploitation/post-exploitation pause for approval
saber run --scope config/scope.yaml --interactive

# Resume an interrupted mission
saber resume --session sessions/q3-web-tier/

# Run a single phase only
saber run --scope config/scope.yaml --phase recon

# Generate report from existing session (no re-scanning)
saber report --session sessions/q3-web-tier/ --format pdf,xlsx

# Live dashboard view
saber status --session sessions/q3-web-tier/
```

`scope.yaml` is unchanged in structure from the original plan. `allowed_ttps` now additionally supports AD-specific values:

- `kerberoasting`
- `asreproasting`
- `smb_relay`
- `bloodhound_collection`
- `dcsync`

### 4.2 Mission Planner Agent

**File:** `saber/agents/planner.py`  
**Prompt:** `prompts/planner.txt`

Unchanged role from the original plan — reads scope, dispatches phases, gates progression — but now operates over a flow → task → subtask → action hierarchy instead of a flat phase list, and is aware of the `--interactive` flag when deciding whether to pause before dispatching exploitation actions.

See [4.7 Phase Graph — Upgraded Hierarchy](#47-phase-graph--upgraded-hierarchy).

### 4.3 Sub-Agents

Unchanged in role split from the original plan, with one update:

**NetworkAgent (`agents/network.py`)** now explicitly owns the AD attack chain as part of its responsibility, not a separate future agent. Decision logic: passive enum first using enum4linux and SMB share listing, then BloodHound collection if `bloodhound_collection` is in `allowed_ttps`, then Kerberoasting/ASREPRoasting against accounts BloodHound flags as high-value, then NetExec for credential validation/spraying across discovered hosts.

This keeps the agent count the same as originally planned — five sub-agents — while expanding NetworkAgent's tool set significantly.

### 4.4 Tool Execution Layer — Now Sandbox-Aware

**Files:** `saber/tools/base_wrapper.py`, `saber/core/sandbox.py`

This is the most significant architectural change in this revision. The original `ToolWrapper.run()` spawned subprocesses directly on the host. It now executes inside a per-session ephemeral Docker container.

```python
# saber/core/sandbox.py  (spec, not final code)

class SandboxManager:
    """
    Manages the lifecycle of the per-session Docker sandbox container.
    
    One container per session, created at session start, destroyed at
    session end (or kept paused for resume). The container has network
    access to the declared scope targets only — enforced via Docker
    network policy as a second layer behind ScopeGuard, not a replacement
    for it.
    """
    
    image: str = "saber/sandbox:kali-last-release"
    
    async def start_session_container(self, session_id: str) -> ContainerHandle:
        # docker run -d --name saber-{session_id}
        #   --network saber-session-net-{session_id}
        #   saber/sandbox:kali-last-release
        ...
    
    async def exec_in_container(
        self,
        container: ContainerHandle,
        command: List[str],
        timeout: int
    ) -> ToolResult:
        # docker exec {container} {command}
        # capture stdout/stderr, enforce timeout, never shell=True
        ...
    
    async def stop_session_container(self, container: ContainerHandle) -> None:
        ...
```

```python
# saber/tools/base_wrapper.py  (spec, updated)

class ToolWrapper:
    """
    Base class for all tool wrappers. Now requires a SandboxManager
    and executes inside the session container rather than on the host.
    """
    
    async def run(
        self,
        target: Target,
        flags: dict,
        scope_guard: ScopeGuard,
        sandbox: SandboxManager,
        evidence_store: EvidenceStore
    ) -> ToolResult:
        # 1. scope_guard.validate(target) — raises ScopeViolation if out of scope
        # 2. build_command(target, flags) — returns List[str]
        # 3. sandbox.exec_in_container(container, cmd, timeout=self.timeout_seconds)
        # 4. evidence_store.save_raw(tool_name, target, stdout, stderr, cmd)
        # 5. parse_output(stdout) → List[Finding]
        # 6. return ToolResult(findings, raw_output_path, exit_code, duration)
```

The `docker/Dockerfile.sandbox` builds a Kali rolling base image with all tools from [Section 7](#7-tool-wrapper-inventory) pre-installed, so container startup doesn't require per-tool installation at runtime — matching the pattern PentAGI and PentestAgent both use.

### 4.5 Approval Gate — New Component

**Files:** `saber/core/approval_gate.py`, `saber/ui/cli/approval_prompt.py`

Only active when `--interactive` is passed. Wraps the ExploitAgent and PostExploitAgent's dispatch calls.

```python
# saber/core/approval_gate.py  (spec)

class ApprovalDecision(str, Enum):
    ALLOW_ONCE = "allow_once"
    ALLOW_SESSION = "allow_session"
    DENY = "deny"

class ApprovalGate:
    """
    Before a sensitive action (exploitation attempt, post-exploitation
    command) fires, prompts the operator for approval if --interactive
    is set. ALLOW_SESSION caches approval for the rest of the session
    for that specific (tool, target) pair — not a blanket approval for
    all future actions.
    """
    
    async def request_approval(
        self,
        action_description: str,
        tool: str,
        target: Target,
        command: List[str]
    ) -> ApprovalDecision:
        # Check session cache for prior ALLOW_SESSION on (tool, target)
        # If not cached, prompt operator via CLI, block until response
        # Log decision to approvals table regardless of outcome
        ...
```

This directly mirrors PentesterFlow's gating model: permission-gated tools require allow-once, allow-session, or deny, and scoped session caching never licenses a second host or command. An `ALLOW_SESSION` on one target's Metasploit module does not silently authorize the same module against a different target.

### 4.6 Output Normalizer & Evidence Store

Unchanged from the original plan — this part of the design held up against all competitive research.

### 4.7 Phase Graph — Upgraded Hierarchy

**File:** `saber/core/phase_graph.py`

The original flat phase list:

```text
recon → web → network → exploit → post_exploit → report
```

is upgraded to a four-level hierarchy modeled on PentAGI's flow/task/subtask/action structure, without adopting PentAGI's infrastructure:

```text
Flow: "Q3 Internal Pentest - Web Tier"
├── Task: Reconnaissance
│   ├── Subtask: Port/service discovery
│   │   ├── Action: nmap -sV --open 10.10.10.0/24
│   │   └── Action: masscan -p1-65535 10.10.10.0/24
│   └── Subtask: Subdomain enumeration
│       └── Action: amass enum -passive -d internal.corp.example
├── Task: Web Assessment
│   └── ...
├── Task: Network & Active Directory
│   ├── Subtask: SMB enumeration
│   ├── Subtask: BloodHound collection
│   └── Subtask: Kerberoasting
├── Task: Exploitation
└── Task: Post-Exploitation
```

This is a pure data-modeling change — same SQLite backend, no Neo4j — but gives the Mission Planner finer-grained resumability and gives the live CLI dashboard a meaningful progress tree to render.

### 4.8 Reporting Agent

Unchanged from the original plan.

---

## 5. Core Data Schemas

The `Finding`, `Evidence`, `Credential`, `Scope`, and `ToolResult` schemas are unchanged from the original plan — they held up against the competitive research without modification.

Two additions:

### ADPrincipal — New

```python
# saber/models/ad_principal.py

class PrincipalType(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    GPO = "gpo"
    OU = "ou"

class ADPrincipal(BaseModel):
    id: str
    session_id: str
    sam_account_name: str
    principal_type: PrincipalType
    domain: str
    distinguished_name: Optional[str]
    member_of: List[str] = []        # group SIDs
    admin_on: List[str] = []         # computer hostnames this principal has admin on
    high_value: bool = False         # flagged by BloodHound as high-value target
    kerberoastable: bool = False
    asreproastable: bool = False
    source_tool: str                 # bloodhound | netexec | manual
    discovered_at: datetime
```

### ApprovalRecord — New

```python
class ApprovalRecord(BaseModel):
    id: str
    session_id: str
    action_description: str
    tool: str
    target: str
    command: List[str]
    decision: ApprovalDecision
    decided_at: datetime
```

---

## 6. Agent System Prompt Designs

The prompts are now externalized into `prompts/` and use a stricter JSON-first format. Agents do not generate raw shell commands. They return structured plans, observations, evidence requirements, stop conditions, approval requirements, and handoff targets for the Python orchestrator.

Current prompt files:

- `planner.txt` — builds the mission flow/task/subtask/action graph and enforces scope/ROE interpretation.
- `recon_agent.txt` — plans host discovery, port/service detection, DNS/subdomain enumeration, and technology fingerprinting.
- `web_agent.txt` — plans safe web assessment using WhatWeb, nuclei, feroxbuster, nikto, ZAP, and sqlmap when allowed.
- `network_agent.txt` — plans SMB, SNMP, OpenVAS/GVM, NetExec, BloodHound, and AD-related assessment with strict approval gating.
- `exploit_agent.txt` — plans only controlled proof-of-exploitability when explicitly authorized.
- `post_exploit_agent.txt` — plans only minimal authorized impact evidence collection.
- `reporter.txt` — planned next; converts verified evidence into executive, technical, XLSX, and JSON reports.

All prompts follow the same pattern:

```text
1. State the agent role.
2. Define allowed responsibilities.
3. Define hard safety boundaries.
4. Define tool families the agent may request.
5. Require structured JSON only.
6. Require expected evidence for every action.
7. Require stop conditions for risky actions.
8. Separate verified findings from candidate observations.
9. Mark high-impact actions for ApprovalGate.
10. Return operator_review_items when authorization is missing or unclear.
```

---

## 7. Tool Wrapper Inventory

Phases 1–3 — Recon, Web, Network — and Phases 5–6 — Post-Exploitation, Password — are unchanged from the original plan.

The Active Directory module is new.

### Phase 4 — Active Directory (NEW — Formerly Listed as a Deferred Future Module)

| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| bloodhound-python | `tools/active_directory/bloodhound.py` | JSON (BloodHound ingest format) | Users/groups/computers/ACLs/sessions graph data |
| Impacket — secretsdump | `tools/active_directory/impacket_tools.py` | text parse | NTLM hashes, Kerberos keys |
| Impacket — GetUserSPNs | `tools/active_directory/impacket_tools.py` | text parse | Kerberoastable account tickets |
| Impacket — wmiexec | `tools/active_directory/impacket_tools.py` | interactive shell capture | Remote command execution evidence |
| CrackMapExec / NetExec | `tools/active_directory/netexec.py` | JSON (`--log` parse) | Credential validation across host ranges, share enumeration |

**Note on BloodHound:** the wrapper runs `bloodhound-python` as the collector, with no GUI dependency, and stores the raw JSON output in the evidence store. Graph analysis of the output — finding shortest paths to Domain Admin — is done in Python using the `bloodhound-python` library's own graph utilities, or in a lightweight in-memory graph such as `networkx`, rather than standing up Neo4j.

This is the specific point where SABER deliberately stays lighter than PentAGI.

### Updated Phase Ordering

```text
1. Recon
2. Web
3. Network (general enumeration)
4. Active Directory (if domain environment detected)
5. Exploitation
6. Post-Exploitation
7. Password Cracking (can run in parallel with Post-Exploitation)
8. Reporting
```

---

## 8. Storage & Database Design

The original `sessions`, `findings`, `credentials`, and `tool_runs` tables are unchanged.

Two new tables:

```sql
-- ad_principals
CREATE TABLE ad_principals (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    sam_account_name    TEXT NOT NULL,
    principal_type      TEXT NOT NULL,
    domain              TEXT NOT NULL,
    distinguished_name  TEXT,
    member_of_json      TEXT,       -- JSON array of group SIDs
    admin_on_json       TEXT,       -- JSON array of hostnames
    high_value          BOOLEAN DEFAULT FALSE,
    kerberoastable      BOOLEAN DEFAULT FALSE,
    asreproastable      BOOLEAN DEFAULT FALSE,
    source_tool         TEXT,
    discovered_at       TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- approvals
CREATE TABLE approvals (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    action_description  TEXT NOT NULL,
    tool                TEXT NOT NULL,
    target              TEXT NOT NULL,
    command_json        TEXT NOT NULL,
    decision            TEXT NOT NULL,   -- allow_once | allow_session | deny
    decided_at          TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
```

The flow/task/subtask/action hierarchy from [Section 4.7](#47-phase-graph--upgraded-hierarchy) is represented as a self-referencing `phase_nodes` table rather than a separate graph database:

```sql
-- phase_nodes (flow/task/subtask/action hierarchy)
CREATE TABLE phase_nodes (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    parent_id    TEXT,             -- NULL for top-level flow node
    node_type    TEXT NOT NULL,    -- flow | task | subtask | action
    name         TEXT NOT NULL,
    status       TEXT NOT NULL,    -- pending | running | complete | skipped | failed
    started_at   TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (parent_id) REFERENCES phase_nodes(id)
);
```

---

## 9. Configuration System

`tools.yaml` gains entries for the new AD tools and the Docker sandbox config:

```yaml
sandbox:
  image: saber/sandbox:kali-last-release
  network_mode: scoped
  memory_limit: 4g
  cpu_limit: 2
  container_timeout: 7200

tools:
  # ... (nmap, masscan, amass, nuclei, feroxbuster, sqlmap, metasploit,
  #      hashcat, responder — all unchanged from original plan) ...

  bloodhound:
    binary: bloodhound-python
    default_flags: ["-c", "All", "--zip"]
    timeout: 900

  impacket-secretsdump:
    binary: secretsdump.py
    timeout: 300

  impacket-getuserspns:
    binary: GetUserSPNs.py
    default_flags: ["-request"]
    timeout: 300

  netexec:
    binary: netexec
    default_flags: ["smb"]
    timeout: 300

  zap:
    client: python-owasp-zap-v2.4
    api_host: 127.0.0.1
    api_port: 8080
    api_key_env: ZAP_API_KEY
```

`.env.example` gains:

```bash
# Docker sandbox
SABER_SANDBOX_IMAGE=saber/sandbox:kali-last-release
SABER_INTERACTIVE_DEFAULT=false

# Active Directory
AD_DOMAIN_CONTROLLER=
AD_TEST_CREDENTIALS=
```

---

## 10. Build Phases (Chip-by-Chip)

Build order is updated to front-load the Docker sandbox, since every later phase depends on it, and to insert the AD module where it now belongs.

### Phase 1 — Foundation + Sandbox (Weeks 1–3, Expanded)

**Goal:** schema + storage + scope enforcement + Docker sandbox working. No AI yet.

- [ ] Define and test all Pydantic models in `models/`, including `ADPrincipal` and `ApprovalRecord`
- [ ] Implement `ScopeGuard` with full test coverage
- [ ] Build `docker/Dockerfile.sandbox` — Kali rolling + all Phase 1–6 tools
- [ ] Implement `SandboxManager` — container start/exec/stop lifecycle, mocked Docker tests
- [ ] Implement `EvidenceStore`
- [ ] Implement SQLite schema, including new `ad_principals`, `approvals`, and `phase_nodes` tables
- [ ] Implement `DatabaseManager`
- [ ] Implement `ToolWrapper` base class, sandbox-aware, with mock subclass
- [ ] Write unit tests for all of the above

**Milestone:** `saber/` package imports cleanly. Can create a session, spin up a sandbox container, save a mock finding inside it, query it back, and tear the container down.

### Phase 2 — Recon Layer (Weeks 4–5)

Unchanged from the original plan, except tool execution now runs through the sandbox.

**Milestone:** `saber run --scope examples/sample_scope.yaml --phase recon` runs inside the sandbox container against a test host, produces findings in SQLite, and saves raw output to the evidence directory.

### Phase 3 — Recon Agent (Week 6)

Unchanged from the original plan.

### Phase 4 — Web Layer (Weeks 7–8)

Unchanged from the original plan, with the ZAP wrapper now using `python-owasp-zap-v2.4` instead of hand-rolled REST calls.

### Phase 5 — Network & Active Directory Layer (Weeks 9–11, Expanded)

**Goal:** internal network enumeration and AD attack chain working — this phase grew the most in this revision.

- [ ] Implement `Enum4linuxWrapper`, `ResponderWrapper`, and `SnmpwalkWrapper`
- [ ] Implement `BloodhoundWrapper` — collection + JSON evidence storage
- [ ] Implement lightweight graph analysis over BloodHound JSON output using `networkx`, not Neo4j, to identify shortest paths to high-value targets
- [ ] Implement `ImpacketWrapper` — secretsdump, GetUserSPNs, wmiexec
- [ ] Implement `NetexecWrapper`
- [ ] Implement `NetworkAgent` with the expanded AD methodology from [Section 6](#6-agent-system-prompt-designs)
- [ ] Implement `ApprovalGate` and wire it as a pass-through no-op when `--interactive` is not set

**Milestone:** network agent runs against a lab AD environment, captures SMB info, runs BloodHound collection, identifies a Kerberoastable account, requests the ticket, and — if `--interactive` is set — pauses for approval before doing so.

### Phase 6 — Exploitation Layer (Weeks 12–13)

**Goal:** Metasploit integration and exploit dispatch working, now approval-gate-aware.

- [ ] Start MSFRPC and implement `MetasploitWrapper` via `pymetasploit3`
- [ ] Implement `SearchsploitWrapper`
- [ ] Implement `ExploitAgent` with conservative gating logic
- [ ] Wire `ApprovalGate` into the ExploitAgent's dispatch path
- [ ] Implement screenshot capture post-exploitation

**Milestone:** exploit agent matches a nuclei finding to a Metasploit module, prompts for approval in `--interactive` mode, launches it against a test target inside the sandbox after approval, gets shell, and screenshots the session.

### Phase 7 — Post-Exploitation Layer (Week 14)

Unchanged from the original plan, with `ApprovalGate` wired into PostExploitAgent the same way as ExploitAgent.

### Phase 8 — Reporting (Week 15)

Unchanged from the original plan. Technical report now includes an AD attack path section when applicable — shortest path to Domain Admin, rendered as a simple text-based path list, not a graph visualization in v1.

### Phase 9 — Full Integration (Week 16)

**Goal:** end-to-end run on a controlled lab including a domain-joined Windows environment, such as GOAD — Game of Active Directory — or a small custom AD lab, in addition to Metasploitable.

- [ ] Full pipeline test: recon → web → network/AD → exploit → post-exploit → report
- [ ] Sandbox container resume/cleanup testing
- [ ] Approval gate testing in both autonomous and interactive modes
- [ ] Scope guard stress testing — verify the Docker network policy actually blocks out-of-scope traffic, not just that ScopeGuard rejects the call in Python
- [ ] Fix all integration bugs

**Milestone:** complete run on a mixed Metasploitable + small AD lab produces a full report including an AD attack path section.

### Phase 10 — Hardening & Polish (Week 17+)

Unchanged from the original plan, with one addition: sandbox image size/startup time optimization, since a 17-tool Kali image can be slow to pull/start. Layer the Dockerfile so common tools are in early layers and rarely-used ones — wireless, reverse engineering, if added later — are in optional extension layers.

---

## 11. Testing Strategy

Unchanged structure from the original plan.

Two additions:

- `tests/unit/test_sandbox.py` — mocks the Docker SDK, verifies container lifecycle calls happen in the right order, and verifies that `exec_in_container` never uses `shell=True`
- `tests/unit/test_approval_gate.py` — verifies allow-once doesn't cache, allow-session caches per `(tool, target)` pair only, deny blocks the action and logs it
- `tests/integration/test_ad_attack_chain.py` — requires a lab AD environment such as GOAD or similar, marked to not run in CI by default

---

## 12. Security & Operational Safeguards

The original `ScopeGuard`, command injection prevention, and credential vault protections are unchanged and still apply — now as the first layer of defense, with the Docker sandbox as a second, independent layer.

### Defense in Depth (Updated)

1. **ScopeGuard** — Python-level. Rejects any tool call against an out-of-scope target before the command is even built.
2. **Docker network policy** — container-level. The session container's network is restricted to the declared scope's IP ranges, so even a ScopeGuard bug or a successfully-injected command can't reach anything outside scope.
3. **ApprovalGate** — operator-level, optional. In interactive mode, a human confirms exploitation/post-exploitation actions before they fire, independent of whether the AI's reasoning was sound.

This is a meaningful upgrade from the original single-layer ScopeGuard design. It now matches the isolation model used by every serious competitor in the space rather than relying on a single Python-level check.

---

## 13. Future Modules

Updated list — Active Directory has been promoted out of this section into the core build.

| Module | Description | Why Deferred |
|---|---|---|
| Wireless | Aircrack-ng, Wifite, Airgeddon | Requires physical hardware; hard to automate reliably |
| Mobile | MobSF, apktool | Separate toolchain entirely |
| Cloud | Pacu, ScoutSuite, Prowler | Requires separate credential model — AWS/Azure/GCP keys |
| Cross-engagement memory | Vector storage / knowledge graph for learning across engagements | This is PentAGI's strongest feature but genuinely requires the heavier infra you're deliberately avoiding in v1 — revisit only if running many engagements becomes the actual use case |
| CI/CD integration | GitHub Actions, GitLab pipelines, diff-scoped scanning (Strix-style) | Lower priority than internal-network depth given your stated goals; revisit if web/app scope grows |
| Web UI | FastAPI + React | Phase 10+ after core is stable |
| Collaborative / multi-operator | Session sharing, role-based access | Needs proper auth system |

---

## 14. Technology Decision Log

Original entries are unchanged and still apply.

New entries from this revision:

| Decision | Chosen | Rejected | Reason |
|---|---|---|---|
| Tool execution isolation | Ephemeral Docker container per session | Direct host subprocess — original plan | Every serious competitor — PentAGI, Strix, autopentest-ai, PentestAgent — sandboxes execution. A single Python-level ScopeGuard is not defense in depth on its own. |
| AD attack tooling | `bloodhound-python` + Impacket + NetExec, core in Phase 5 | Treating AD as a deferred future module | Every full-kill-chain competitor treats this as core; it's the actual differentiator versus web-focused competitors like Strix/XBOW. |
| BloodHound graph analysis | `networkx` in-process | Neo4j — PentAGI's approach | Avoids standing up a graph database for a single-operator, single-engagement tool. Revisit only if cross-engagement analysis becomes a real requirement. |
| Phase modeling | flow → task → subtask → action hierarchy | Flat phase list — original plan | Borrowed from PentAGI's cleanest idea without its infrastructure. Enables finer-grained resume and a meaningful progress tree in the CLI. |
| Human oversight | Optional `--interactive` approval gate — allow-once/allow-session/deny | Scope-yaml-only enforcement — original plan | PentesterFlow's gating model is a stronger trust-building pattern than static scope enforcement alone, without sacrificing the default of full autonomy. |
| ZAP client | `python-owasp-zap-v2.4` official client | Hand-rolled REST calls — original plan | Use the maintained official client instead of rebuilding it. |
| Metasploit client | `pymetasploit3` — unchanged, confirmed | msfconsole subprocess | Confirmed correct after competitive research — every credible competitor uses an RPC/API approach, not subprocess parsing. |
| CVSS scoring | `cvss` pip package | Custom vector parser | No reason to hand-roll a CVSS calculator when a maintained library exists. |
| Cross-engagement memory / knowledge graph | Deferred to future module | Building it into v1 — tempting after seeing PentAGI's Graphiti/Neo4j integration | This is the single biggest infrastructure trap in this space. It's genuinely valuable at scale but is exactly the weight that makes PentAGI unsuitable for a solo operator running one engagement at a time. |

---

## Requirements (Updated)

### requirements.txt

```text
anthropic>=0.28.0
pydantic>=2.0.0
aiosqlite>=0.19.0
pyyaml>=6.0
click>=8.0
rich>=13.0
docker>=7.0.0
python-libnmap>=0.7.2
pymetasploit3>=1.0.3
python-gvm>=22.0.0
python-owasp-zap-v2.4>=0.0.21
cvss>=3.1
bloodhound-python>=1.7.0
impacket>=0.11.0
networkx>=3.0
reportlab>=4.0.0
openpyxl>=3.1.0
Pillow>=10.0.0
requests>=2.31.0
aiohttp>=3.9.0
python-dotenv>=1.0.0
jinja2>=3.1.0
```

### requirements-dev.txt

```text
pytest>=7.0
pytest-asyncio>=0.21
pytest-mock>=3.11
coverage>=7.0
ruff>=0.1.0
mypy>=1.0
```

### Kali / Host Setup

SABER no longer uses host install scripts for the assessment tools. Tooling is installed inside the Docker sandbox image and managed through the Python CLI.

```bash
# Check local setup
python -m saber doctor

# Build sandbox image
python -m saber sandbox build

# Verify image exists
python -m saber sandbox status

# Enter sandbox shell
python -m saber sandbox shell
```

The Docker image is named:

```text
saber/sandbox:kali-last-release
```

The Kali package `bloodhound.py` is installed in the sandbox image. `bloodhound-python` is intentionally not listed in `requirements.txt` because it is not installed as a normal PyPI runtime dependency for this project.
