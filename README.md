# SABER

## Scoped Automated Breach, Exploitation & Reporting
---

## What SABER Is

SABER is a local-first security assessment platform for authorized internal-network, web, and lab penetration testing. It combines strict scope enforcement, sandboxed tool execution, LLM-assisted planning, structured evidence collection, and automated reporting.

The goal is not to be an uncontrolled “AI hacker.” The goal is to make authorized assessments more repeatable, safer, easier to review, and easier to report.

## Core Principles

- **Scope first:** every action must pass scope and rules-of-engagement checks.
- **Evidence first:** findings are not reportable unless backed by raw tool output, metadata, timestamps, and affected assets.
- **Sandboxed execution:** security tools run inside a controlled Docker/Kali sandbox.
- **Human approval for risk:** exploitation, post-exploitation, credential access, relay, poisoning, and other high-impact actions require explicit approval.
- **Structured outputs:** plans, actions, findings, evidence, and reports are machine-readable.
- **No stealth or persistence:** SABER is for authorized validation and reporting, not covert access.

## Current Status

SABER is in early development. The current implementation focuses on project structure, configuration, prompts, sandbox setup, and CLI foundations.

Implemented so far:

- Python package scaffold
- Cross-platform CLI entrypoint
- Docker sandbox build/status/shell commands
- Environment health check command
- Scope and ROE example configs
- Tool registry config
- Agent prompt files for planning and assessment phases
- Kali-based sandbox image

## Architecture

```text
scope.yaml + roe.yaml
        |
        v
Mission Planner Agent
        |
        v
ScopeGuard + ApprovalGate
        |
        v
Specialized Agents
        |
        v
Tool Wrappers inside Docker Sandbox
        |
        v
EvidenceStore + Finding Models
        |
        v
PDF / XLSX / JSON Reports
```

Main agent roles:

- **PlannerAgent:** builds the mission phase graph.
- **ReconAgent:** host, port, DNS, subdomain, and technology discovery.
- **WebAgent:** web scanning, content discovery, and web finding validation.
- **NetworkAgent:** SMB, SNMP, network service, and Active Directory assessment.
- **ExploitAgent:** controlled proof-of-exploitability when explicitly allowed.
- **PostExploitAgent:** minimal authorized impact evidence collection.
- **ReporterAgent:** turns verified evidence into final reports.

## Project Structure

```text
SABER/
├── config/                  # Scope, ROE, and tool configuration
├── docker/                  # Kali sandbox Dockerfile and Compose file
├── examples/                # Example scope, findings, and report artifacts
├── output/                  # Generated reports and exports
├── prompts/                 # LLM prompts for planner and agents
├── saber/                   # Main Python package
│   ├── agents/              # Agent classes
│   ├── core/                # ScopeGuard, sandbox, sessions, evidence, approvals
│   ├── models/              # Typed data models
│   ├── reporting/           # PDF, XLSX, JSON, and Markdown exporters
│   ├── storage/             # Database and persistence layer
│   ├── tools/               # Safe wrappers around security tools
│   └── ui/                  # CLI and future web UI
├── sessions/                # Local mission/session state
├── tests/                   # Unit and integration tests
├── .env.example             # Environment variable template
├── requirements.txt         # Runtime dependencies
├── requirements-dev.txt     # Development dependencies
└── pyproject.toml           # Python package metadata and tooling config
```

## Requirements

- Python 3.11+
- Docker Desktop or Docker Engine
- Docker Compose plugin
- macOS, Linux, or Windows

Optional, depending on features used:

- Anthropic API key for LLM planning/analysis
- Metasploit RPC service for controlled exploit validation
- ZAP service for web assessment
- GVM/OpenVAS service for vulnerability scanning

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

## Environment Configuration

Copy the example environment file and fill in values as needed:

```bash
cp .env.example .env
```

At minimum, SABER can run local CLI and sandbox checks without an LLM key. LLM-backed planning requires an API key configured in `.env`.

## CLI Usage

Run the health check:

```bash
python -m saber doctor
```

Build the sandbox image:

```bash
python -m saber sandbox build
```

Check sandbox image status:

```bash
python -m saber sandbox status
```

Open an interactive sandbox shell:

```bash
python -m saber sandbox shell
```

After editable install, the console command is also available:

```bash
saber doctor
saber sandbox status
```

## Docker Sandbox

SABER uses a Kali-based Docker sandbox to keep security tooling isolated from the host system.

The sandbox includes common assessment tools such as:

- nmap
- masscan
- amass
- subfinder
- theHarvester
- dnsrecon
- whatweb
- nuclei
- feroxbuster
- nikto
- ZAP
- sqlmap
- enum4linux-ng
- NetExec
- Impacket tools
- Metasploit Framework
- BloodHound collector tooling
- hashcat
- john

The sandbox is intentionally constrained with limited CPU, memory, dropped Linux capabilities, and no-new-privileges where possible.

## Configuration Files

Primary configuration files live in `config/`:

- `scope.yaml.example` defines mission scope, allowed targets, excluded targets, allowed phases, and safety limits.
- `roe.yaml.example` defines rules of engagement, testing windows, approval rules, contacts, and prohibited actions.
- `tools.yaml` defines tool metadata, categories, risk levels, and wrapper defaults.

Before a real assessment, copy the example files and create mission-specific configs.

## Safety Model

SABER is designed around hard safety boundaries:

- ScopeGuard validates targets before actions run.
- ApprovalGate blocks high-impact actions until explicitly approved.
- EvidenceStore records raw outputs and metadata.
- Agents return structured JSON instead of free-form commands.
- ToolWrappers construct safe commands instead of trusting model-generated shell text.
- Reports distinguish verified findings from unverified observations.

High-impact actions include exploitation, post-exploitation, credential dumping, password cracking, password spraying, SMB relay, poisoning, tunneling, and remote command execution.

## Outputs

Planned report outputs:

- Executive summary PDF
- Technical report PDF
- Findings workbook XLSX
- Findings JSON
- Raw evidence bundle
- Session metadata

Findings should include:

- Title
- Severity
- CVSS score
- Affected assets
- Evidence references
- Business impact
- Reproduction notes
- Remediation guidance
- Verification status

## Development

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check saber tests
```

Run formatting:

```bash
ruff format saber tests
```

## Roadmap

Near-term priorities:

1. Implement core data models.
2. Implement ScopeGuard target validation.
3. Implement EvidenceStore.
4. Implement base ToolWrapper.
5. Implement safe nmap wrapper.
6. Implement session database.
7. Connect planner JSON to phase execution.
8. Generate basic JSON and Markdown reports.
9. Add PDF/XLSX exporters.
10. Add integration tests using lab targets only.

Later priorities:

- Web UI
- Live mission dashboard
- Approval workflow UI
- GVM/OpenVAS integration
- ZAP integration
- Metasploit RPC integration
- Active Directory lab workflows
- Evidence bundle export
- Multi-mission history

## Legal and Ethical Use

SABER must only be used on systems where the operator has explicit authorization to test. The project is designed for internal security assessments, lab environments, training ranges, and approved penetration tests.

Do not use SABER against third-party systems without written permission.

## License

MIT