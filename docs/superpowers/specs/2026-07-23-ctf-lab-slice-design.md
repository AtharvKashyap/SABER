# Slice 1 Design — CTF/Lab wiring (A) + Vulnerable-app lab (B)

**Date:** 2026-07-23
**Status:** Approved — ready for implementation planning
**Roadmap:** see `2026-07-23-automated-pentest-roadmap.md`

## Goal

Give SABER a reproducible, self-contained lab of intentionally vulnerable
targets and the wiring to point the mission loop at them as CTF/lab missions —
so the **LLM-driven** pentesting path can be exercised against real targets, and
`CtfStrategy` can actually complete on a captured flag. Deterministic mode is
used only to make the integration tests reproducible.

## Non-goals (deferred to later workstreams)

Tool-contract/drift fix (F), Wireshark (C), chain/lateral/AD/RE wiring (D),
binary-exploit tooling (E), exposing `autonomy_level` as a flag. The custom
`vulnbin` target is built now as a *target*, but the RE/exploit tooling that
attacks it is out of scope here.

## Component 1 — The lab (`docker/lab/`)

A `docker-compose.yml` defining four targets on a dedicated `saber-lab` bridge
network:

| Service | Image / build | Purpose |
|---------|---------------|---------|
| `dvwa` | public `vulnerables/web-dvwa` | WebStrategy: whatweb → nikto/nuclei → sqlmap |
| `juiceshop` | public `bkimminich/juice-shop` | WebStrategy against a modern SPA |
| `metasploitable` | public Metasploitable2 image | NetworkStrategy + CtfStrategy foothold (SSH/SMB/FTP/etc.) |
| `vulnbin` | custom `Dockerfile` | A deliberately vulnerable C binary + `/flag.txt` + a listening service; a flag-capture target now, an RE/pwn target for D/E later |

### Networking (resolves the host-network caveat)

The Kali sandbox defaults to `SABER_DOCKER_NETWORK=host`, which cannot reach an
isolated bridge, and host networking is unreliable on Docker Desktop/macOS.
Resolution:

- The lab runs on its own `saber-lab` bridge with **no internet egress**
  (`internal: true` where the image allows it) so targets can't call home.
- `make lab-up` starts the compose **and ensures the SABER sandbox container is
  attached to `saber-lab`**, so in-sandbox tools resolve targets by service name
  (`dvwa`, `metasploitable`, `vulnbin`) and by the bridge subnet.
- Reachability and isolation are both satisfied: SABER reaches the lab; the lab
  cannot reach the internet.

### Lifecycle + scope

- `make lab-up` — start compose, attach sandbox, and **auto-write a scope file**
  (`runs/lab_scope.yaml`) listing the lab service names / subnet so missions
  against the lab pass the scope hard-wall with no hand-editing.
- `make lab-down` — stop and remove the compose project and generated scope.
- Documented in the README (a "Test against the lab" section).

## Component 2 — CTF/Lab wiring (A)

### `select_strategy` explicit override

`select_strategy(target, metadata)` gains an explicit-override path: a caller can
force a strategy kind, which wins over target-type auto-detection. The existing
`ctf`/`lab` metadata keys keep working. Precedence:

1. explicit strategy override (from `--strategy`/GUI dropdown), else
2. `metadata["ctf"] or metadata["lab"]` → `CtfStrategy`, else
3. target-type auto-detection (URL/web → Web, else Network).

`--lab` sets `metadata["lab"]=True` (marks the target owned) independently of the
chosen strategy.

### CLI

`run` subcommand gains:

- `--strategy {auto,network,web,ctf}` (default `auto`)
- `--lab` (store_true)

Threaded through `run_cli_mission(..., strategy=..., lab=...)` into the
`run_mission` metadata. `auto` preserves today's behavior exactly.

### GUI

The Start Mission form gains a **Strategy** dropdown (`auto`/`network`/`web`/`ctf`)
and a **Lab** checkbox, passed through the sessions router into the same
`run_mission` path as the CLI.

## Component 3 — Flag detection

`CtfStrategy.objective_met` already reads `state.metadata["flag"]`, but nothing
sets it. Add a small **flag detector** invoked in the merge path (where parsed
observations/evidence text is folded into `MissionState`):

- Scans observation summaries / parsed text for common flag formats:
  `picoCTF{…}`, `flag{…}`, `FLAG{…}`, `CTF{…}`.
- Supports a **per-mission configurable regex** (via mission metadata) that adds
  to the defaults.
- On a match, records `state.metadata["flag"]` (first match wins; recorded via
  the immutable `model_copy` path, never in-place mutation).
- Redacts nothing here — a captured flag is the objective, not a secret.

This makes `CtfStrategy.objective_met` fire correctly and is fully unit-testable
offline.

## Testing

### Offline unit tests (no Docker, no model)
- `select_strategy` override precedence (all three branches + `--lab`).
- CLI arg threading: `--strategy`/`--lab` reach `run_mission` metadata.
- GUI form → sessions router → run path threading.
- Flag detector: each default format, the configurable regex, and no-false-match
  cases; `CtfStrategy.objective_met` returns `True` once `metadata["flag"]` is set.

### Docker-gated integration (`SABER_RUN_DOCKER_E2E`)
- `make lab-up`, then a **deterministic** web mission against `dvwa` and a network
  mission against `metasploitable`: assert the loop terminates, `MissionState`
  grows (hosts/services/technologies), no scope violation, and a report artifact
  is produced. Deterministic here = reproducible CI, not the product path.
- `vulnbin` reachability: assert the sandbox can reach `vulnbin` on the
  `saber-lab` network. (Actually *capturing* the flag through the loop needs the
  LLM path — the deterministic ladder does not read flag files — so flag capture
  is an LLM acceptance check, below. The flag *detector* is proven in the offline
  unit tests by feeding it known output.)

### LLM acceptance (manual / gated, `SABER_RUN_LLM_E2E`)
- The real product path: an LLM-decider mission against `dvwa` and
  `metasploitable`, asserting loop invariants (terminates, no scope violation,
  state grows, report emitted). Not run in CI.
- Flag capture: an LLM-decider CTF mission against `vulnbin` that reaches the
  flag (e.g. via `custom_cli`) and completes through `CtfStrategy` with
  `metadata["flag"]` set. Gated/manual.

## Invariants preserved

- Execution only via the Docker sandbox through `ActionExecutor`; no agent-run
  shell.
- `MissionState` updated only via `model_copy` / `StateMerger`.
- Scope checked as a hard wall before autonomy; the lab scope file is additive,
  never a scope bypass.
- `RiskGate` unchanged.

## Open decisions (none blocking)

- Exact public image tags for DVWA/Juice Shop/Metasploitable2 pinned at
  implementation time for reproducibility.
- Whether `vulnbin` exposes SSH or a raw TCP service — decided when the RE/pwn
  workstream (D/E) firms up its needs; for slice 1 a simple readable-flag path
  is sufficient.
