## Table of Contents
 
1. [Philosophy & Design Decisions](#1-philosophy--design-decisions)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Full Project Structure](#3-full-project-structure)
4. [Layer-by-Layer Component Specs](#4-layer-by-layer-component-specs)
   - 4.1 [Operator Interface](#41-operator-interface)
   - 4.2 [Mission Planner Agent](#42-mission-planner-agent)
   - 4.3 [Sub-Agents](#43-sub-agents)
   - 4.4 [Tool Execution Layer](#44-tool-execution-layer)
   - 4.5 [Output Normalizer & Evidence Store](#45-output-normalizer--evidence-store)
   - 4.6 [Reporting Agent](#46-reporting-agent)
5. [Core Data Schemas](#5-core-data-schemas)
6. [Agent System Prompt Designs](#6-agent-system-prompt-designs)
7. [Tool Wrapper Inventory](#7-tool-wrapper-inventory)
8. [Storage & Database Design](#8-storage--database-design)
9. [Configuration System](#9-configuration-system)
10. [Build Phases (Chip-by-Chip)](#10-build-phases-chip-by-chip)
11. [Testing Strategy](#11-testing-strategy)
12. [Security & Operational Safeguards](#12-security--operational-safeguards)
13. [Future Modules](#13-future-modules)
14. [Technology Decision Log](#14-technology-decision-log)
---
 
## 1. Philosophy & Design Decisions
 
### Core Principles
 
**Separation of concerns over monolithic chains.** The AI never directly invokes tools. It reads normalized data, makes decisions, and issues structured commands. A deterministic Python execution layer handles all subprocess work. This means a crashed tool never crashes the AI orchestrator.
 
**Schema-first design.** The `Finding` dataclass is the contract between every component. Tools produce it. Agents read it. The reporter synthesizes it. Nothing communicates via raw tool output strings.
 
**Every run is reproducible.** A complete session is saved to SQLite at every step. Any phase can be re-run or resumed without re-running prior phases. Raw tool output is always preserved alongside normalized findings.
 
**Scope enforcement is non-negotiable.** A `ScopeGuard` class wraps every tool invocation. No IP, domain, or port outside the declared scope can be touched — at the Python level, not just by agent instruction.
 
**Evidence-first reporting.** Every finding must have attached evidence before it's reportable: a raw command, its output, a screenshot where applicable, and a timestamp. Unattested findings are flagged `UNVERIFIED` and excluded from the executive summary.
 
### What This Is Not
 
- Not a single Claude agent calling `subprocess.run()` in a loop
- Not an n8n workflow (n8n is a webhook/SaaS glue layer; this needs real subprocess control)
- Not a tool that covers every Kali tool (it covers the kill chain with best-of-breed per phase)
- Not a replacement for a human pentester — it generates verified, reproducible evidence that a human reviews and attests
---
 
## 2. System Architecture Overview
 
```
┌─────────────────────────────────────────────────────────┐
│                    OPERATOR INTERFACE                    │
│         scope.yaml  ·  targets.txt  ·  roe.yaml         │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│              MISSION PLANNER AGENT (Claude)              │
│   Reads scope → builds phase graph → dispatches agents   │
│              gates phase progression                     │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┘
   │          │          │          │          │
┌──▼──┐  ┌───▼──┐  ┌────▼──┐  ┌───▼───┐  ┌──▼─────┐
│Recon│  │ Web  │  │ Net   │  │Exploit│  │  Post  │
│Agent│  │Agent │  │Agent  │  │Agent  │  │ Exploit│
└──┬──┘  └───┬──┘  └────┬──┘  └───┬───┘  └──┬─────┘
   │          │          │          │          │
┌──▼──────────▼──────────▼──────────▼──────────▼─────────┐
│              OUTPUT NORMALIZER                          │
│   Raw output → Finding schema → Evidence store         │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│         TOOL EXECUTION LAYER (Python wrappers)          │
│  nmap · amass · nuclei · feroxbuster · sqlmap · msf     │
│  hashcat · responder · bettercap · mimikatz · ...       │
└───────────────────────┬─────────────────────────────────┘
                        │ (findings JSON fed back up)
┌───────────────────────▼─────────────────────────────────┐
│              REPORTING AGENT (Claude)                   │
│  Reads all Finding JSON → CVSS scoring → narrative      │
└──┬──────────┬──────────┬──────────────────────────────┘
   │          │          │
┌──▼──┐  ┌───▼──┐  ┌────▼──┐
│ PDF │  │XLSX  │  │ JSON  │
└─────┘  └──────┘  └───────┘
```
 
### Technology Assignments (final decisions)
 
| Layer | Technology | Rationale |
|---|---|---|
| Agent orchestration | Anthropic API (claude-opus-4) with tool use | Direct control, no framework magic to debug |
| Multi-agent coordination | Python async + queue | LangGraph adds complexity; async queues are transparent |
| Tool execution | Python `asyncio.subprocess` | Full timeout/kill/stderr control |
| Finding storage | SQLite (via `aiosqlite`) | Zero-config, file-portable, queryable |
| Evidence storage | Local filesystem, structured paths | Never goes to cloud; reproducible |
| CLI interface | `click` + `rich` | Rich gives live progress panels |
| Web UI (optional phase) | FastAPI + Jinja2 | Lightweight, no framework overhead |
| Report PDF | `reportlab` | Programmatic, no LaTeX dependency |
| Report XLSX | `openpyxl` | Industry standard for analyst handoff |
| Config | YAML via `pyyaml` + Pydantic validation | Human-editable, machine-validated |
 
---
 
## 3. Full Project Structure
 
```
phantom/
│
├── README.md
├── PHANTOM_PROJECT_PLAN.md          ← this document
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
├── pyproject.toml                   # project metadata + tool config
│
├── phantom/                         # main package
│   │
│   ├── __init__.py
│   │
│   ├── core/                        # mission control, not AI-specific
│   │   ├── __init__.py
│   │   ├── mission.py               # MissionController: top-level run loop
│   │   ├── session.py               # SessionManager: load/save/resume state
│   │   ├── scope_guard.py           # ScopeGuard: enforce IP/domain/port limits
│   │   ├── phase_graph.py           # PhaseGraph: DAG of phases + dependencies
│   │   └── evidence_store.py        # EvidenceStore: screenshot + file management
│   │
│   ├── agents/                      # Claude-powered decision layers
│   │   ├── __init__.py
│   │   ├── base_agent.py            # BaseAgent: Anthropic API wrapper + retry logic
│   │   ├── planner.py               # MissionPlannerAgent
│   │   ├── recon.py                 # ReconAgent
│   │   ├── web.py                   # WebAgent
│   │   ├── network.py               # NetworkAgent
│   │   ├── exploit.py               # ExploitAgent
│   │   ├── post_exploit.py          # PostExploitAgent
│   │   └── reporter.py              # ReportingAgent
│   │
│   ├── tools/                       # deterministic subprocess wrappers
│   │   ├── __init__.py
│   │   ├── base_wrapper.py          # ToolWrapper base class
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
│   │   │   └── zap_api.py           # ZAP via REST API, not subprocess
│   │   │
│   │   ├── network/
│   │   │   ├── __init__.py
│   │   │   ├── openvas_api.py       # OpenVAS/GVM via python-gvm
│   │   │   ├── responder.py
│   │   │   ├── bettercap.py
│   │   │   ├── enum4linux.py
│   │   │   └── snmpwalk.py
│   │   │
│   │   ├── exploitation/
│   │   │   ├── __init__.py
│   │   │   ├── metasploit.py        # via pymetasploit3 (MSFRPC)
│   │   │   └── searchsploit.py
│   │   │
│   │   ├── post_exploit/
│   │   │   ├── __init__.py
│   │   │   ├── mimikatz.py
│   │   │   ├── linpeas.py
│   │   │   ├── winpeas.py
│   │   │   └── chisel.py            # tunneling/pivoting
│   │   │
│   │   └── password/
│   │       ├── __init__.py
│   │       ├── hashcat.py
│   │       └── john.py
│   │
│   ├── models/                      # Pydantic dataclasses: the schema contract
│   │   ├── __init__.py
│   │   ├── finding.py               # Finding (the central model)
│   │   ├── evidence.py              # Evidence (attached proof)
│   │   ├── scope.py                 # Scope + RulesOfEngagement
│   │   ├── session.py               # SessionState
│   │   ├── target.py                # Target (host/service/url)
│   │   └── credential.py            # Credential (captured creds vault)
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py              # async SQLite via aiosqlite
│   │   └── migrations/
│   │       └── 001_initial.sql
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── pdf_exporter.py          # reportlab PDF builder
│   │   ├── xlsx_exporter.py         # openpyxl workbook builder
│   │   ├── json_exporter.py         # raw JSON dump
│   │   └── templates/
│   │       ├── executive_summary.md.j2
│   │       └── technical_report.md.j2
│   │
│   └── ui/
│       ├── __init__.py
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py              # click entry point
│       │   └── live_panel.py        # rich live dashboard
│       └── web/                     # optional, phase 4+
│           ├── __init__.py
│           ├── app.py               # FastAPI application
│           └── routers/
│               ├── sessions.py
│               ├── findings.py
│               └── reports.py
│
├── prompts/                         # externalized agent system prompts
│   ├── planner.txt
│   ├── recon_agent.txt
│   ├── web_agent.txt
│   ├── network_agent.txt
│   ├── exploit_agent.txt
│   ├── post_exploit_agent.txt
│   └── reporter.txt
│
├── config/
│   ├── scope.yaml.example
│   ├── roe.yaml.example             # rules of engagement
│   └── tools.yaml                   # tool paths + default flags
│
├── scripts/
│   ├── install_kali_deps.sh         # apt + pip setup on Kali
│   ├── start_msfrpc.sh              # launch Metasploit RPC daemon
│   └── start_zap.sh                 # launch ZAP in daemon mode
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_scope_guard.py
│   │   ├── test_finding_schema.py
│   │   ├── test_phase_graph.py
│   │   └── test_tool_wrappers.py    # mocked subprocess
│   ├── integration/
│   │   ├── test_recon_agent.py      # against local test target
│   │   └── test_full_pipeline.py    # end-to-end on DVWA
│   └── fixtures/
│       ├── sample_nmap_output.xml
│       ├── sample_nuclei_output.json
│       └── sample_scope.yaml
│
├── examples/
│   ├── sample_executive_summary.pdf
│   ├── sample_technical_report.pdf
│   ├── sample_findings.json
│   └── sample_scope.yaml
│
├── output/                          # generated reports (gitignored)
│   └── .gitkeep
│
└── sessions/                        # saved session state (gitignored)
    └── .gitkeep
```
 
---
 
## 4. Layer-by-Layer Component Specs
 
### 4.1 Operator Interface
 
**File:** `phantom/ui/cli/main.py`, `config/scope.yaml`
 
The entry point. The operator never interacts with agents directly — they define a scope document and fire the mission.
 
#### scope.yaml structure
 
```yaml
mission_name: "Q3 Internal Pentest - Web Tier"
operator: "j.smith"
date: "2026-06-04"
 
targets:
  - type: ip_range
    value: "10.10.10.0/24"
  - type: domain
    value: "internal.corp.example"
  - type: url
    value: "https://app.internal.corp.example"
 
out_of_scope:
  - "10.10.10.1"           # firewall — do not touch
  - "*.prod.example.com"   # production — out of scope
 
allowed_phases:
  - recon
  - web
  - network
  - exploitation
  - post_exploitation
 
allowed_ttps:
  - port_scan
  - subdomain_enum
  - web_directory_brute
  - sqli_detection
  - sqli_exploitation
  - smb_enum
  - hash_capture
  - hash_crack
  - metasploit_public_exploits
 
prohibited:
  - dos_attacks
  - destructive_payloads
  - lateral_movement_outside_scope
 
evidence_path: "./sessions/q3-web-tier/"
max_concurrent_tools: 3
```
 
#### CLI commands
 
```bash
# Start a new mission
phantom run --scope config/scope.yaml --roe config/roe.yaml
 
# Resume an interrupted mission
phantom resume --session sessions/q3-web-tier/
 
# Run a single phase only
phantom run --scope config/scope.yaml --phase recon
 
# Generate report from existing session (no re-scanning)
phantom report --session sessions/q3-web-tier/ --format pdf,xlsx
 
# Live dashboard view
phantom status --session sessions/q3-web-tier/
```
 
---
 
### 4.2 Mission Planner Agent
 
**File:** `phantom/agents/planner.py`
**Prompt:** `prompts/planner.txt`
 
This is the top-level Claude agent. It is NOT a general-purpose agent — it has a narrow, structured job:
 
1. Read the scope YAML and all prior-phase findings (if resuming)
2. Output a `MissionPlan` (structured JSON): ordered phase list, per-phase targets, per-phase tool selection
3. After each phase completes, read the findings and decide: proceed / re-run phase with different tools / escalate to exploit phase early / abort
**What it does NOT do:**
- Does not call tools
- Does not parse raw tool output
- Does not write reports
- Does not make decisions about CVE severity (that's the reporting agent)
**Key design:** the planner communicates via structured `tool_use` calls, not free text. It calls a `dispatch_phase(phase_name, targets, tools, flags)` tool, which is handled by the Python orchestrator.
 
**Phase gating logic:** The planner won't dispatch the exploit agent until the recon and web/network agents have returned findings. It uses a simple decision tree defined in its system prompt:
 
```
IF recon_complete AND (web_findings OR network_findings):
  → dispatch exploit agent with high-confidence findings only
IF exploit_successful:
  → dispatch post_exploit agent
IF phase_returns_empty_findings AND retries_exhausted:
  → mark phase SKIPPED and continue
```
 
---
 
### 4.3 Sub-Agents
 
Each sub-agent inherits from `BaseAgent`. They receive:
- Their phase scope (subset of full scope)
- Prior-phase findings relevant to them
- A list of permitted tools (from scope YAML)
They output structured `ToolCall` commands, which the Python executor runs. They never see raw subprocess output — only normalized `Finding` objects returned by the executor.
 
#### ReconAgent (`agents/recon.py`)
- Responsible for: port/service discovery, subdomain enum, DNS analysis, OSINT
- Tools it can call: `nmap`, `masscan`, `amass`, `subfinder`, `theharvester`, `dnsrecon`, `whatweb`
- Decision logic: run masscan first for speed, then targeted nmap on discovered ports for version/script data. Run subdomain enum in parallel.
- Output: list of `Target` objects (host + port + service + banner) fed to web/network agents
#### WebAgent (`agents/web.py`)
- Responsible for: directory brute, tech fingerprint, vuln scanning, injection testing
- Tools it can call: `feroxbuster`, `nuclei`, `sqlmap`, `nikto`, `zap_api`
- Decision logic: feroxbuster first for map, then nuclei templates against discovered paths, then targeted sqlmap only on parameterized endpoints
- Output: `Finding` objects for each confirmed vulnerability
#### NetworkAgent (`agents/network.py`)
- Responsible for: SMB/LDAP enum, SNMP, hash capture, service vulns
- Tools it can call: `enum4linux`, `snmpwalk`, `responder`, `bettercap`, `openvas_api`
- Decision logic: passive enum first, then Responder only if hash_capture is in allowed_ttps
- Output: `Finding` objects + `Credential` objects for captured hashes
#### ExploitAgent (`agents/exploit.py`)
- Responsible for: matching findings to exploits, executing with Metasploit or manual PoC
- Tools it can call: `searchsploit`, `metasploit` (via MSFRPC)
- Decision logic: only act on findings with `confidence >= 0.85` and matching CVE or named vuln. Rank by CVSS. Try highest-scoring first. Record success/fail for each attempt.
- **Critical:** always checks scope_guard before launching any exploit
- Output: `Finding` with `exploited: True`, shell session ID if successful
#### PostExploitAgent (`agents/post_exploit.py`)
- Responsible for: privilege escalation, credential dumping, pivot setup, data exfil simulation
- Tools it can call: `mimikatz`, `linpeas`, `winpeas`, `chisel`
- Decision logic: enumerate then escalate. Never runs destructive commands. Screenshots every privilege escalation proof.
- Output: `Finding` objects, `Credential` objects, screenshot evidence
---
 
### 4.4 Tool Execution Layer
 
**File:** `phantom/tools/base_wrapper.py`
 
The most important non-AI file in the project. Every tool wrapper inherits from this.
 
```python
# phantom/tools/base_wrapper.py  (spec, not final code)
 
class ToolWrapper:
    """
    Base class for all tool wrappers.
    
    Responsibilities:
    - Build the command from structured args (never string interpolation)
    - Enforce timeout and kill
    - Capture stdout, stderr, exit code
    - Pass raw output to the tool's own parser
    - Return a list of Finding objects
    - Save raw output to evidence store
    - Never raise on non-zero exit — always return findings (possibly empty)
    """
    
    tool_name: str           # e.g. "nmap"
    binary_path: str         # from tools.yaml
    default_flags: list      # safe defaults
    timeout_seconds: int     # hard kill timeout
    
    async def run(
        self,
        target: Target,
        flags: dict,
        scope_guard: ScopeGuard,
        evidence_store: EvidenceStore
    ) -> ToolResult:
        # 1. scope_guard.validate(target) — raises ScopeViolation if out of scope
        # 2. build_command(target, flags) — returns List[str], never shell=True
        # 3. asyncio.create_subprocess_exec(*cmd)
        # 4. communicate(timeout=self.timeout_seconds)
        # 5. evidence_store.save_raw(tool_name, target, stdout, stderr, cmd)
        # 6. parse_output(stdout) → List[Finding]
        # 7. return ToolResult(findings, raw_output_path, exit_code, duration)
    
    def build_command(self, target: Target, flags: dict) -> List[str]:
        # MUST return a list, never a string
        # NEVER use shell=True or f-string command building
        raise NotImplementedError
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        # Tool-specific parsing into Finding objects
        raise NotImplementedError
```
 
**Key principle:** `shell=False` always. Command arguments are always a `List[str]`. This prevents shell injection from AI-generated parameters.
 
#### NmapWrapper example spec
 
```
binary: nmap
default_flags: ["-sV", "-sC", "--open", "-oX", "-"]  # XML to stdout
parse_output: uses python-libnmap to parse XML → extract hosts/ports/services
Finding fields populated:
  - target.host, target.port, target.service, target.banner
  - finding.phase = "recon"
  - finding.title = "Open port: {port}/{service}"
  - finding.severity = "info"
  - finding.evidence.raw_command = full nmap command string
  - finding.evidence.raw_output_path = path to saved XML
```
 
---
 
### 4.5 Output Normalizer & Evidence Store
 
**Files:** `phantom/core/evidence_store.py`, `phantom/models/finding.py`
 
The normalizer is not a separate service — it's the `parse_output()` method of each tool wrapper, which always returns the same `Finding` schema regardless of which tool produced it.
 
#### Evidence directory structure
 
```
sessions/
└── q3-web-tier-2026-06-04/
    ├── session.db                   # SQLite — all findings, targets, creds
    ├── session.json                 # human-readable session summary
    ├── evidence/
    │   ├── recon/
    │   │   ├── nmap_10.10.10.5_raw.xml
    │   │   ├── nmap_10.10.10.5_cmd.txt
    │   │   ├── amass_corp_raw.txt
    │   │   └── ...
    │   ├── web/
    │   │   ├── feroxbuster_app_raw.txt
    │   │   ├── nuclei_app_raw.json
    │   │   ├── sqlmap_login_raw.txt
    │   │   ├── screenshots/
    │   │   │   ├── sqli_proof_001.png
    │   │   │   └── xss_proof_001.png
    │   │   └── ...
    │   ├── network/
    │   ├── exploitation/
    │   │   ├── msf_session_001.txt
    │   │   └── screenshots/
    │   │       └── shell_access_001.png
    │   └── post_exploit/
    │       ├── privesc_proof.png
    │       └── creds_dump.txt
    └── reports/
        ├── executive_summary.pdf
        ├── technical_report.pdf
        ├── findings.json
        └── findings.xlsx
```
 
---
 
### 4.6 Reporting Agent
 
**File:** `phantom/agents/reporter.py`
**Prompt:** `prompts/reporter.txt`
 
Runs after all phases are complete (or on demand via `phantom report`). Reads the SQLite findings database and all evidence metadata. Produces a structured report.
 
**Two output narratives:**
 
1. **Executive summary** (for management/clients): risk summary, top 5 critical findings, business impact, recommended priorities. No technical jargon. Includes key screenshots.
2. **Technical report** (for remediation teams): full finding-by-finding walkthrough, exact reproduction steps, tool commands used, raw evidence references, CVSS scores, CVE references, fix recommendations.
**What the reporter does NOT do:**
- Does not re-run any tools
- Does not make new vulnerability discoveries
- Does not assign severity without a CVSS base score or known CVE reference
- Does not include unverified findings (missing evidence) in executive output
---
 
## 5. Core Data Schemas
 
### Finding (the central contract)
 
```python
# phantom/models/finding.py
 
from enum import Enum
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
 
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
 
class FindingStatus(str, Enum):
    CONFIRMED    = "confirmed"    # tool confirmed + evidence attached
    UNVERIFIED   = "unverified"   # detected but not exploited/proven
    FALSE_POSITIVE = "false_positive"
    EXPLOITED    = "exploited"    # full PoC achieved
 
class Evidence(BaseModel):
    raw_command:     str                    # exact command that produced this
    raw_output_path: str                    # path to saved raw output file
    screenshots:     List[str] = []         # paths to screenshot files
    timestamp:       datetime
 
class Finding(BaseModel):
    id:              str                    # uuid4
    session_id:      str
    phase:           str                    # recon | web | network | exploit | post_exploit
    tool:            str                    # nmap | nuclei | sqlmap | etc.
    
    # Target
    host:            str                    # IP or hostname
    port:            Optional[int]
    service:         Optional[str]          # http | smb | ssh | etc.
    url:             Optional[str]          # full URL if web finding
    
    # Finding
    title:           str                    # short, human-readable
    description:     str                    # what was found
    severity:        Severity
    status:          FindingStatus
    confidence:      float                  # 0.0–1.0 (tool-assigned)
    
    # CVE / Reference
    cve:             Optional[str]          # CVE-YYYY-NNNNN
    cvss_score:      Optional[float]        # 0.0–10.0
    cvss_vector:     Optional[str]
    references:      List[str] = []
    
    # Exploitation result (if applicable)
    exploited:       bool = False
    exploit_module:  Optional[str]          # e.g. "exploit/multi/handler"
    shell_session:   Optional[str]          # msf session ID or description
    
    # Credentials obtained
    credentials:     List["Credential"] = []
    
    # Evidence
    evidence:        Evidence
    
    # Reporting
    reporter_notes:  Optional[str]          # Claude-generated analyst note
    remediation:     Optional[str]          # Claude-generated fix recommendation
    
    created_at:      datetime
    updated_at:      datetime
```
 
### Credential
 
```python
class CredentialType(str, Enum):
    PLAINTEXT   = "plaintext"
    NTLM_HASH   = "ntlm_hash"
    NET_NTLMv2  = "net_ntlmv2"
    KERBEROS    = "kerberos"
    SSH_KEY     = "ssh_key"
    API_KEY     = "api_key"
 
class Credential(BaseModel):
    id:           str
    session_id:   str
    finding_id:   str              # which finding produced this
    host:         str
    service:      str
    username:     Optional[str]
    secret:       str              # hash or plaintext
    type:         CredentialType
    cracked:      bool = False
    plaintext:    Optional[str]    # populated if cracked
    evidence_path: str
    timestamp:    datetime
```
 
### Scope & RulesOfEngagement
 
```python
class ScopeTarget(BaseModel):
    type:  str                     # ip | ip_range | domain | url
    value: str
 
class RulesOfEngagement(BaseModel):
    allowed_phases:   List[str]
    allowed_ttps:     List[str]
    prohibited:       List[str]
    max_concurrent_tools: int = 3
    rate_limit_rps:   float = 10.0  # requests per second cap
    
class Scope(BaseModel):
    mission_name:  str
    operator:      str
    date:          str
    targets:       List[ScopeTarget]
    out_of_scope:  List[str]        # IPs, domains, CIDR ranges
    roe:           RulesOfEngagement
    evidence_path: str
```
 
### ToolResult
 
```python
class ToolResult(BaseModel):
    tool:           str
    target:         str
    command:        List[str]       # exact command executed
    exit_code:      int
    duration_seconds: float
    findings:       List[Finding]
    raw_output_path: str
    error:          Optional[str]   # stderr if non-zero exit
```
 
---
 
## 6. Agent System Prompt Designs
 
### planner.txt (structure)
 
```
You are the Mission Planner for PHANTOM, an automated penetration testing platform.
 
ROLE: You read scope definitions and finding summaries. You issue structured 
dispatch commands for sub-agents. You never call tools directly. You never 
interpret raw tool output — only normalized Finding JSON.
 
INPUT FORMAT: You receive a JSON object containing:
  - scope: the full scope definition
  - completed_phases: list of phase names already run
  - findings_summary: aggregated findings from completed phases
  - session_id: current session identifier
 
OUTPUT FORMAT: You must respond ONLY with a JSON object using the dispatch_phase 
tool. Never respond with free text.
 
PHASE ORDERING RULES:
  1. recon always runs first
  2. web and network run in parallel after recon
  3. exploitation runs only after web OR network returns confirmed findings
  4. post_exploitation runs only after a successful exploit
  5. reporting always runs last
 
DECISION GATES:
  - Do not dispatch exploitation if recon_findings is empty
  - Do not dispatch exploitation against targets outside scope
  - Mark a phase SKIPPED if: it has run twice and returned zero findings
  - Escalate to exploitation early if a finding has cvss_score >= 9.0
 
SCOPE ENFORCEMENT: You may only dispatch phases and tools that appear in 
scope.allowed_phases and scope.roe.allowed_ttps.
```
 
### exploit_agent.txt (structure, most critical to get right)
 
```
You are the Exploitation Agent for PHANTOM.
 
ROLE: You receive a list of confirmed, high-confidence findings from the recon, 
web, and network phases. You decide which findings to attempt exploitation on, 
in what order, and with which tools/modules.
 
CONSTRAINTS (non-negotiable):
  - You only attempt exploitation on findings with confidence >= 0.85
  - You only use exploit modules that appear in scope.roe.allowed_ttps
  - You do not attempt destructive payloads (format, delete, encrypt)
  - You attempt at most 3 exploit modules per finding before marking it FAILED
  - You record the exact command used for every attempt, success or fail
 
ORDERING:
  Rank findings by: (cvss_score * confidence) DESC
  Attempt highest-ranked first.
 
OUTPUT FORMAT: structured ToolCall JSON only. No free text.
```
 
---
 
## 7. Tool Wrapper Inventory
 
### Phase 1 — Recon
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| nmap | `tools/recon/nmap.py` | XML via python-libnmap | host/port/service/banner |
| masscan | `tools/recon/masscan.py` | JSON (`-oJ`) | open ports (fast sweep) |
| amass | `tools/recon/amass.py` | JSON (`-json`) | subdomains + IPs |
| subfinder | `tools/recon/subfinder.py` | JSON (`-json`) | subdomains |
| theHarvester | `tools/recon/theharvester.py` | JSON (`-f -b all`) | emails, hosts, IPs |
| dnsrecon | `tools/recon/dnsrecon.py` | JSON (`-j`) | DNS records, zone transfer |
| whatweb | `tools/recon/whatweb.py` | JSON (`--log-json`) | tech fingerprint |
 
### Phase 2 — Web
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| feroxbuster | `tools/web/feroxbuster.py` | JSON (`--json`) | discovered paths |
| nuclei | `tools/web/nuclei.py` | JSON (`-json`) | template-matched vulns |
| sqlmap | `tools/web/sqlmap.py` | text + JSON (`--batch --json-out`) | SQLi findings + data |
| nikto | `tools/web/nikto.py` | XML (`-Format xml`) | web misconfigs |
| ZAP | `tools/web/zap_api.py` | REST API JSON | active scan findings |
 
**Note on ZAP:** ZAP runs as a daemon (`start_zap.sh`). The wrapper calls its REST API rather than spawning it as a subprocess. This is intentional — ZAP needs to run persistently and cannot be respawned per scan.
 
### Phase 3 — Network
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| enum4linux-ng | `tools/network/enum4linux.py` | JSON (`-oJ`) | SMB users/shares/policies |
| snmpwalk | `tools/network/snmpwalk.py` | text | SNMP OID dump |
| Responder | `tools/network/responder.py` | log file parse | captured NTLMv2 hashes |
| Bettercap | `tools/network/bettercap.py` | REST API + events log | MITM, ARP poison data |
| OpenVAS | `tools/network/openvas_api.py` | python-gvm XML | network vulns |
 
**Note on Responder:** Responder writes to `/usr/share/responder/logs/`. The wrapper starts it, monitors the log directory for new hash files, captures them, then kills the process. It does not parse Responder's stdout.
 
### Phase 4 — Exploitation
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| Metasploit | `tools/exploitation/metasploit.py` | MSFRPC / pymetasploit3 | session IDs, shell output |
| searchsploit | `tools/exploitation/searchsploit.py` | JSON (`--json`) | matching exploit paths/titles |
 
**Note on Metasploit:** Uses `pymetasploit3` to communicate with the MSFRPC daemon (started via `start_msfrpc.sh`). Never spawns `msfconsole` as a subprocess — MSFRPC provides a structured API for module loading, option setting, and session management.
 
### Phase 5 — Post-Exploitation
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| Mimikatz | `tools/post_exploit/mimikatz.py` | text parse | NTLM hashes, plaintext creds |
| LinPEAS | `tools/post_exploit/linpeas.py` | text parse + ANSI strip | privesc vectors |
| WinPEAS | `tools/post_exploit/winpeas.py` | text parse | privesc vectors |
| Chisel | `tools/post_exploit/chisel.py` | subprocess + log | pivot tunnel setup |
 
### Phase 6 — Password
 
| Tool | Wrapper File | Parse Format | Key Output |
|---|---|---|---|
| Hashcat | `tools/password/hashcat.py` | `--outfile` parse + `--status-json` | cracked plaintext |
| John the Ripper | `tools/password/john.py` | `--show` output parse | cracked plaintext |
 
---
 
## 8. Storage & Database Design
 
**File:** `phantom/storage/database.py`
**Engine:** SQLite via `aiosqlite`
**Schema file:** `phantom/storage/migrations/001_initial.sql`
 
### Tables
 
```sql
-- sessions
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    operator     TEXT,
    scope_json   TEXT NOT NULL,       -- full scope YAML serialized
    status       TEXT NOT NULL,       -- running | paused | complete | failed
    started_at   TIMESTAMP,
    updated_at   TIMESTAMP,
    completed_at TIMESTAMP
);
 
-- findings
CREATE TABLE findings (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    phase         TEXT NOT NULL,
    tool          TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER,
    service       TEXT,
    url           TEXT,
    title         TEXT NOT NULL,
    description   TEXT,
    severity      TEXT NOT NULL,
    status        TEXT NOT NULL,
    confidence    REAL,
    cve           TEXT,
    cvss_score    REAL,
    cvss_vector   TEXT,
    exploited     BOOLEAN DEFAULT FALSE,
    exploit_module TEXT,
    reporter_notes TEXT,
    remediation   TEXT,
    evidence_json TEXT NOT NULL,      -- serialized Evidence object
    created_at    TIMESTAMP,
    updated_at    TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
 
-- credentials
CREATE TABLE credentials (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    finding_id    TEXT NOT NULL,
    host          TEXT NOT NULL,
    service       TEXT,
    username      TEXT,
    secret        TEXT NOT NULL,
    type          TEXT NOT NULL,
    cracked       BOOLEAN DEFAULT FALSE,
    plaintext     TEXT,
    evidence_path TEXT,
    timestamp     TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
 
-- tool_runs (raw execution log)
CREATE TABLE tool_runs (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    phase           TEXT NOT NULL,
    tool            TEXT NOT NULL,
    target          TEXT,
    command_json    TEXT NOT NULL,   -- List[str] as JSON
    exit_code       INTEGER,
    duration_secs   REAL,
    raw_output_path TEXT,
    error           TEXT,
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP
);
```
 
---
 
## 9. Configuration System
 
### tools.yaml — tool paths and default flags
 
```yaml
tools:
  nmap:
    binary: /usr/bin/nmap
    default_flags: ["-sV", "-sC", "--open", "-oX", "-"]
    timeout: 300
 
  masscan:
    binary: /usr/bin/masscan
    default_flags: ["--rate", "1000", "-p", "1-65535"]
    timeout: 120
    requires_root: true
 
  amass:
    binary: /usr/bin/amass
    default_flags: ["enum", "-passive"]
    timeout: 600
 
  nuclei:
    binary: /usr/bin/nuclei
    default_flags: ["-json", "-silent", "-severity", "medium,high,critical"]
    timeout: 600
    templates_path: /root/nuclei-templates
 
  feroxbuster:
    binary: /usr/bin/feroxbuster
    default_flags: ["--json", "--silent", "-t", "30"]
    timeout: 300
    wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 
  sqlmap:
    binary: /usr/bin/sqlmap
    default_flags: ["--batch", "--level", "3", "--risk", "2", "--json-out"]
    timeout: 300
 
  metasploit:
    rpc_host: 127.0.0.1
    rpc_port: 55553
    rpc_password: phantom_msfrpc_password   # set in .env
    timeout: 120
 
  hashcat:
    binary: /usr/bin/hashcat
    wordlist: /usr/share/wordlists/rockyou.txt
    timeout: 3600
 
  responder:
    binary: /usr/bin/responder
    log_dir: /usr/share/responder/logs
    timeout: 300
```
 
### .env.example
 
```bash
# Anthropic API
ANTHROPIC_API_KEY=your_key_here
 
# Metasploit RPC
MSF_RPC_PASSWORD=phantom_msfrpc_password
 
# ZAP API key
ZAP_API_KEY=your_zap_key_here
 
# Optional: OpenVAS
OPENVAS_HOST=127.0.0.1
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASSWORD=your_openvas_password
 
# Session defaults
DEFAULT_SESSION_DIR=./sessions
DEFAULT_OUTPUT_DIR=./output
LOG_LEVEL=INFO
```
 
---
 
## 10. Build Phases (Chip-by-Chip)
 
Build order is designed so every phase produces something testable before moving to the next.
 
### Phase 1 — Foundation (weeks 1–2)
**Goal:** schema + storage + scope enforcement working. No AI yet.
 
- [ ] Define and test all Pydantic models (`models/`)
- [ ] Implement `ScopeGuard` with full test coverage
- [ ] Implement `EvidenceStore` (directory creation, file saving)
- [ ] Implement SQLite schema and `DatabaseManager` (CRUD for all tables)
- [ ] Implement `ToolWrapper` base class with mock subclass
- [ ] Write unit tests for all of the above
**Milestone:** `phantom/` package imports cleanly. Can create a session, save a mock finding, query it back.
 
### Phase 2 — Recon Layer (weeks 3–4)
**Goal:** nmap + amass wrappers working end-to-end on a test target.
 
- [ ] Implement `NmapWrapper` with XML parsing via python-libnmap
- [ ] Implement `AmassWrapper` with JSON parsing
- [ ] Implement `SubfinderWrapper`
- [ ] Implement basic CLI (`phantom run --scope ... --phase recon`)
- [ ] Implement `rich` live panel for scan progress
- [ ] Add MasscanWrapper
**Milestone:** `phantom run --scope examples/sample_scope.yaml --phase recon` runs against a test host, produces findings in SQLite, saves raw output to evidence dir.
 
### Phase 3 — Recon Agent (week 5)
**Goal:** Claude orchestrates the recon phase using tool wrappers.
 
- [ ] Implement `BaseAgent` with Anthropic API client + retry logic
- [ ] Implement `ReconAgent` with system prompt
- [ ] Implement `MissionPlannerAgent` (recon dispatch only for now)
- [ ] Wire agent → tool wrapper → storage
**Milestone:** Agent decides to run nmap + amass, dispatches both, findings appear in DB.
 
### Phase 4 — Web Layer (weeks 6–7)
**Goal:** web scanning pipeline working.
 
- [ ] Implement `FeroxbusterWrapper`
- [ ] Implement `NucleiWrapper`
- [ ] Implement `SqlmapWrapper`
- [ ] Implement `WebAgent`
- [ ] Start ZAP daemon via `start_zap.sh`, implement `ZapApiWrapper`
**Milestone:** web agent runs against DVWA (local), finds SQLi, saves finding + screenshot evidence.
 
### Phase 5 — Network Layer (week 8)
**Goal:** internal network enumeration working.
 
- [ ] Implement `Enum4linuxWrapper`
- [ ] Implement `ResponderWrapper` (log-watching pattern)
- [ ] Implement `NetworkAgent`
- [ ] Implement `SnmpwalkWrapper`
**Milestone:** network agent runs against local test environment, captures SMB info + NTLMv2 hash.
 
### Phase 6 — Exploitation Layer (weeks 9–10)
**Goal:** Metasploit integration and exploit dispatch working.
 
- [ ] Start MSFRPC via `start_msfrpc.sh`
- [ ] Implement `MetasploitWrapper` via pymetasploit3
- [ ] Implement `SearchsploitWrapper`
- [ ] Implement `ExploitAgent` with conservative gating logic
- [ ] Implement screenshot capture post-exploitation
**Milestone:** exploit agent matches a nuclei finding to a Metasploit module, launches it against test target, gets shell, screenshots session.
 
### Phase 7 — Post-Exploitation Layer (week 11)
**Goal:** post-exploit chain working.
 
- [ ] Implement `LinPEASWrapper` / `WinPEASWrapper`
- [ ] Implement `MimikatzWrapper`
- [ ] Implement `PostExploitAgent`
- [ ] Implement `CredentialModel` vault
- [ ] Implement `HashcatWrapper`
**Milestone:** post-exploit agent runs linpeas on shell session, finds privesc vector, escalates, dumps creds, cracks hashes.
 
### Phase 8 — Reporting (week 12)
**Goal:** full report generation working.
 
- [ ] Implement `ReportingAgent` with system prompt
- [ ] Implement `PdfExporter` with reportlab
- [ ] Implement `XlsxExporter` with openpyxl
- [ ] Implement `JsonExporter`
- [ ] Wire to `phantom report` CLI command
**Milestone:** `phantom report --session sessions/test/` produces executive PDF, technical PDF, and findings XLSX.
 
### Phase 9 — Full Integration (week 13)
**Goal:** end-to-end run on a controlled lab (Metasploitable, HackTheBox, or internal VM).
 
- [ ] Full pipeline test: recon → web → network → exploit → post-exploit → report
- [ ] Session resume testing (interrupt mid-phase, resume)
- [ ] Scope guard stress testing (verify no out-of-scope calls)
- [ ] Fix all integration bugs
**Milestone:** complete run on Metasploitable produces full report with all phases.
 
### Phase 10 — Hardening & Polish (week 14+)
- [ ] Rate limiting on all tool wrappers
- [ ] Parallel phase execution (web + network simultaneously)
- [ ] Retry logic tuning on all agents
- [ ] Optional FastAPI web UI for session management
- [ ] Full test suite to 80%+ coverage
- [ ] README and documentation pass
---
 
## 11. Testing Strategy
 
### Unit tests (`tests/unit/`)
No real tools. No Anthropic API calls. No network.
 
- `test_scope_guard.py` — verify IPs/domains in/out of scope, CIDR ranges
- `test_finding_schema.py` — Pydantic validation, required fields, enum values
- `test_phase_graph.py` — ordering logic, gate conditions
- `test_tool_wrappers.py` — mock `asyncio.subprocess`, verify command building, output parsing against fixture files
### Integration tests (`tests/integration/`)
Require a controlled lab environment. Defined with pytest marks so they don't run in CI unless explicitly triggered.
 
- `test_recon_pipeline.py` — real nmap + amass against `scanme.nmap.org` or local target
- `test_web_pipeline.py` — real feroxbuster + nuclei against DVWA
- `test_full_pipeline.py` — full run against Metasploitable
### Fixtures (`tests/fixtures/`)
Real tool output saved as files for unit test parsing:
- `sample_nmap_output.xml`
- `sample_nuclei_output.json`
- `sample_feroxbuster_output.json`
- `sample_amass_output.json`
- `sample_sqlmap_output.json`
- `sample_scope.yaml`
---
 
## 12. Security & Operational Safeguards
 
### ScopeGuard (mandatory, not optional)
`ScopeGuard.validate(target)` is called by every `ToolWrapper.run()` call before the subprocess is spawned. It raises `ScopeViolationError` — not a soft return — so it can never be silently ignored. This is the last defense against an AI agent drifting outside declared scope.
 
```python
class ScopeGuard:
    def validate(self, target: Target) -> None:
        # Check IP against all allowed networks (ipaddress module)
        # Check domain against allowed domain list + wildcard rules
        # Check port against any port restrictions
        # Raises ScopeViolationError with full context if out of scope
```
 
### Command injection prevention
- `shell=False` on all subprocess calls
- Command arguments built as `List[str]` with no f-string interpolation of user/AI-supplied values
- All AI-supplied tool parameters are validated against a whitelist schema before being passed to `build_command()`
### Credential vault protection
- Credentials table in SQLite is encrypted at rest (using `sqlcipher` or an AES-encrypted JSON file)
- Cracked plaintext values are stored separately from hashes
- Evidence directory containing credential files is `.gitignore`d
### Session isolation
- Each session gets its own subdirectory and SQLite file
- No shared state between sessions
- All paths validated to be within the declared `evidence_path` (no directory traversal)
---
 
## 13. Future Modules
 
Intentionally excluded from the initial build. Design slots exist but are not implemented.
 
| Module | Description | Why Deferred |
|---|---|---|
| Wireless | Aircrack-ng, Wifite, Airgeddon | Requires physical hardware; hard to automate reliably |
| Active Directory | BloodHound, Kerbrute, Impacket | Full AD attack surface is a platform in itself |
| Mobile | MobSF, apktool | Separate toolchain entirely |
| Cloud | Pacu, ScoutSuite | Requires separate credential model (AWS/Azure keys) |
| Web UI | FastAPI + React | Phase 10+ after core is stable |
| Collaborative | Multi-operator session sharing | Needs proper auth system |
| CI/CD integration | GitHub Actions, Gitlab | Regression pentest automation |
 
---
 
## 14. Technology Decision Log
 
Decisions documented here so they don't get relitigated.
 
| Decision | Chosen | Rejected | Reason |
|---|---|---|---|
| Agent framework | Anthropic API direct + `tool_use` | LangGraph, CrewAI, AutoGen | Fewer abstraction layers = easier debugging. Direct API = full control over prompts and retry logic. |
| Workflow automation | Python asyncio | n8n | n8n is SaaS glue. Need real subprocess control, process trees, stdin/stdout. |
| Tool invocation | `asyncio.create_subprocess_exec` | `subprocess.run`, `shell=True` | Async for parallel phases. `exec` (not shell) for injection safety. |
| Finding storage | SQLite + aiosqlite | PostgreSQL, MongoDB, flat JSON | Zero-config. File-portable. Queryable. No server to manage. |
| Metasploit interface | pymetasploit3 (MSFRPC) | msfconsole subprocess | MSFRPC provides a real API. msfconsole subprocess is fragile and unparseable. |
| ZAP interface | ZAP REST API daemon | sqlmap subprocess | ZAP needs to run persistently for proxy/crawler functionality. |
| Report PDF | reportlab | WeasyPrint, pdfkit, LaTeX | reportlab = pure Python, no system dependencies, fully programmable. |
| Config format | YAML + Pydantic | TOML, JSON, INI | YAML is human-readable for scope files. Pydantic catches mistakes at load time. |
| Nuclei over OpenVAS (primary) | Nuclei | OpenVAS as primary | Nuclei is scripted, template-based, JSON output, fast. OpenVAS is slow and requires setup — use for compliance/deep scans as secondary. |
| feroxbuster over gobuster | feroxbuster | gobuster, dirbuster | feroxbuster is actively maintained, recursive, JSON output, faster. Gobuster is fine but single-depth. Dirbuster is dead. |
 
---
 
## Requirements
 
### requirements.txt
 
```
anthropic>=0.28.0
pydantic>=2.0.0
aiosqlite>=0.19.0
pyyaml>=6.0
click>=8.0
rich>=13.0
python-libnmap>=0.7.2
pymetasploit3>=1.0.3
python-gvm>=22.0.0
reportlab>=4.0.0
openpyxl>=3.1.0
Pillow>=10.0.0
requests>=2.31.0
aiohttp>=3.9.0
python-dotenv>=1.0.0
jinja2>=3.1.0
```
 
### requirements-dev.txt
 
```
pytest>=7.0
pytest-asyncio>=0.21
pytest-mock>=3.11
coverage>=7.0
ruff>=0.1.0
mypy>=1.0
```
 
### Kali setup
 
```bash
# scripts/install_kali_deps.sh
apt-get update
apt-get install -y nmap masscan amass subfinder nuclei feroxbuster \
  sqlmap nikto whatweb dnsrecon enum4linux-ng responder bettercap \
  metasploit-framework hashcat john mimikatz chisel
pip install -r requirements.txt --break-system-packages
```
 
---
