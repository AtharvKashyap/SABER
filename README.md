# SABER

## Scoped Automated Breach, Exploitation & Reporting

**SABER** is a self-hosted AI penetration testing platform that runs real security tools, analyzes results, chains findings across the stack, stores evidence, and exports clean reports.

Give it a target, define the engagement, choose the tools or let agents plan the workflow, and SABER handles execution, parsing, analysis, storage, and reporting from one local-first platform.

> Built for authorized assessments, labs, training ranges, and internal security teams.

---

## What SABER Does

SABER turns a pentest workflow into a repeatable tool-running and analysis pipeline:

```text
Target + Rules of Engagement
   ↓
AI Planner / Operator Tool Selection
   ↓
Recon, Web, Network, AD, Exploit-Intel, Password, RE, Post-Exploit Tools
   ↓
Sandboxed Execution
   ↓
Parsers + Evidence + Findings
   ↓
Database + Reports + Dashboards
```

It can support work across multiple layers of the stack:

- **Recon:** nmap, masscan, amass, subfinder, theHarvester, dnsrecon, whatweb
- **Web:** nuclei, nikto, feroxbuster, ZAP, sqlmap
- **Network:** enum4linux-ng, snmpwalk, OpenVAS/GVM, NetExec, Impacket
- **Active Directory:** BloodHound-style collection, LDAP/SMB enumeration, Kerberos checks
- **Exploitation intelligence:** SearchSploit, CVE correlation, Metasploit RPC integration later
- **Password analysis:** hashcat, john, offline cracking workflows
- **Reverse engineering:** file, strings, checksec, radare2, Ghidra headless workflows
- **Post-exploitation validation:** PEAS-style checks, tunneling/pivot tooling, impact evidence collection
- **Reporting:** JSON, XLSX, PDF, evidence bundles, executive and technical reports

The goal is simple: **run the tools, understand the output, chain the next step, and produce the report.**

---

## Why SABER

Most pentest workflows are scattered across terminals, screenshots, notes, scripts, databases, and manual report writing. SABER brings those pieces together:

- **Run real tools** from Python wrappers instead of loose terminal history.
- **Feed outputs to agents** for analysis, next-step planning, and reporting.
- **Parse raw results** into structured services, technologies, vulnerabilities, credentials, AD objects, and attack-chain steps.
- **Store everything** in sessions, evidence indexes, finding stores, and graph stores.
- **Export deliverables** as JSON, XLSX, PDF, and evidence bundles.
- **Cover the full stack** from recon and web testing to AD, password analysis, reverse engineering, exploitation intelligence, and post-exploit validation.

SABER is meant to feel like an operator cockpit: run tools, collect evidence, ask the AI what matters, chain the next move, and generate the report.

---

## Core Principles

- **Real tool execution:** SABER wraps tools like nmap, nuclei, BloodHound, Impacket, NetExec, SearchSploit, hashcat, radare2, and more.
- **Agent-callable functions:** agents call Python methods such as `nmap.service_scan()`, `whatweb.fingerprint()`, and `searchsploit.lookup()` instead of raw shell strings.
- **Structured data:** parsers turn messy stdout, XML, JSON, and tool logs into typed models.
- **Evidence by default:** every command can be tied to output, timestamps, metadata, and report-ready evidence.
- **Chainable workflows:** recon results can feed web testing, version checks can feed CVE lookup, AD data can feed attack-path planning, and findings can feed reports.
- **Local-first operation:** the platform is designed to run on your machine or lab infrastructure.

---

## Platform Architecture

```text
saber/
  agents/              # Planner, recon, web, network, exploit, chain, reporter agents
  core/                # ScopeGuard, ApprovalGate, Sandbox, sessions, evidence, mission control
  models/              # Typed models for scope, targets, evidence, findings, credentials, AD, chains
  tools/               # Python wrappers around real security tools
  parsers/             # Convert raw tool output into structured results
  orchestration/       # Execution plans, step runner, chain runner, mission orchestrator
  storage/             # Database, session store, evidence index, finding store, graph store
  reporting/           # JSON, XLSX, PDF exporters and report templates
  ui/                  # CLI and web UI
```

### Execution Flow

```text
Agent or operator chooses a capability
        ↓
Tool wrapper builds the command and expected output contract
        ↓
Sandbox/Docker runner executes the tool
        ↓
EvidenceStore saves stdout, stderr, files, metadata, and timestamps
        ↓
Parser extracts structured results
        ↓
Agents analyze results and choose next steps
        ↓
Storage records sessions, evidence, findings, credentials, and graphs
        ↓
Reports are generated
```

Agents call tools as Python functions, not arbitrary shell commands. For example:

```python
nmap.service_scan(target)
whatweb.fingerprint(url)
searchsploit.lookup(product="Apache", version="2.4.49")
bloodhound.collect_safe_defaults(domain, credentials_ref)
```

Internally, those wrappers build real tool commands, execute them through the runner, save raw evidence, parse outputs, and return data the agents can reason over.

---

## Tool Coverage

SABER is organized by assessment phase:

```text
tools/
  active_directory/      # BloodHound, Impacket, NetExec
  exploitation/          # SearchSploit, Metasploit integration
  lateral_movement/      # Path planning and session validation
  network/               # enum4linux, snmpwalk, OpenVAS, Responder/Bettercap stubs
  password/              # hashcat, john
  post_exploit/          # linPEAS, winPEAS, chisel, controlled impact checks
  recon/                 # nmap, masscan, amass, subfinder, whatweb, dnsrecon
  reverse_engineering/   # file, strings, checksec, radare2, Ghidra headless
  web/                   # nuclei, nikto, feroxbuster, ZAP, sqlmap
```

Each tool category is designed to expose clean Python functions for agents and operators. Some tools are simple recon wrappers, some parse structured output, and some eventually support deeper chains such as old-version detection, CVE lookup, exploit intelligence, AD path analysis, password workflows, reverse engineering, and post-exploit validation.

---

## Current Status

SABER is in active development. Current foundations include:

- Python package and CLI scaffold
- Docker/Kali sandbox structure
- Scope and ROE configuration examples
- Core models for targets, scope, evidence, findings, credentials, sessions, AD principals, and attack chains
- Sandbox, DockerRunner, EvidenceStore, PhaseGraph, SessionManager, MissionController, and optional policy/approval foundations
- Tool wrapper architecture and multiple tool categories
- Parser, storage, orchestration, reporting, and UI package structure
- Unit, model, tool, parser, storage, orchestration, agent, and integration test layout

The next major milestone is a real end-to-end tool path: run nmap, save evidence, parse services, store results, let an agent analyze them, and export a report.

---

## Requirements

- Python 3.11+
- Docker Desktop or Docker Engine
- Docker Compose plugin
- macOS, Linux, or Windows

Optional integrations:

- Anthropic/OpenAI-compatible LLM API for planning and analysis
- Metasploit RPC for controlled exploit validation
- ZAP API for web assessment
- GVM/OpenVAS for vulnerability scanning

---

## Setup

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Copy environment defaults:

```bash
cp .env.example .env
```

---

## CLI Usage

Run a health check:

```bash
python -m saber doctor
```

Build the sandbox image:

```bash
python -m saber sandbox build
```

Check sandbox status:

```bash
python -m saber sandbox status
```

Open an interactive sandbox shell:

```bash
python -m saber sandbox shell
```

After editable install:

```bash
saber doctor
saber sandbox status
```

---

## Configuration

Primary configuration lives in `config/`:

- `scope.yaml.example` — mission scope, allowed targets, excluded targets, allowed phases, and safety limits
- `roe.yaml.example` — rules of engagement, testing windows, approval rules, contacts, and prohibited actions
- `tools.yaml` — tool metadata, categories, risk levels, and wrapper defaults

Before a real assessment, copy the examples and create mission-specific configs.

---

## Outputs

SABER is designed to produce:

- Executive summary PDF
- Technical report PDF
- Findings workbook XLSX
- Findings JSON
- Raw evidence bundle
- Session metadata
- Attack chain summaries
- AD/network graph artifacts

Findings are intended to include severity, CVSS, affected assets, evidence references, business impact, technical impact, remediation guidance, reproduction notes, and verification status.

---

## Development

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
python -m pytest tests/
```

---

## Roadmap

Near-term:

1. Stabilize shared ToolRunResult and tool result models.
2. Build the tool registry so agents can discover available capabilities.
3. Implement real nmap execution, evidence capture, and parser output.
4. Add WhatWeb, Nuclei, SearchSploit, BloodHound, NetExec, and Impacket flows.
5. Connect parsed output to findings, storage, graphs, and reports.
6. Build end-to-end agent loops: recon → analysis → next tool → findings → report.

Later:

- Live mission dashboard
- Approval workflow UI
- AD graph ingestion and attack path summaries
- CVE and exploit-intelligence correlation
- Reverse engineering workflows
- Controlled exploit validation in lab mode
- Multi-mission history and evidence bundle export

---

## Legal and Ethical Use

SABER is intended for authorized penetration testing, internal security assessments, lab environments, and training ranges. Only run it against systems you own or have explicit permission to test.

---

## License

MIT