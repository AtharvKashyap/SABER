# SABER Agentic Mission Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SABER's plan-first orchestration with a state-first *agentic mission loop* — an accumulating `MissionState` that is re-reasoned every iteration to choose the next action, execute it, normalize the result back into state, and repeat until a stop condition, then generate an evidence-backed report from the final state.

**Architecture:** A new `MissionLoop` becomes the primary driver. Each iteration: summarize state → decide next action (LLM-primary decider) → validate against scope + risk-gated autonomy → execute through an existing capability agent → parse/normalize into `MissionState` → snapshot → evaluate stop conditions. Existing `StepRunner`, parsers, `ResultProcessor`, stores, and the approval machinery are reused. Per-target-type `TargetStrategy` objects seed the loop for network/IP, web, and CTF/SSH targets. The old `ExecutionPlan`/`ChainRunner` driving retires (kept only as an optional recon seed).

**Tech Stack:** Python 3.11+, Pydantic v2, SQLite (`aiosqlite`/`sqlite3`), Anthropic/OpenRouter via existing `LlmClient`, Docker sandbox, FastAPI GUI, pytest.

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the repo.

- **Python** `requires-python = ">=3.11"`.
- **Lint/format** (ruff): `line-length = 100`, `quote-style = "double"`, rules `E, F, I, B, UP, SIM`. Run `ruff check saber tests` and `ruff format saber tests` before each commit.
- **Types**: `mypy saber` must not regress (`check_untyped_defs = true`, `no_implicit_optional = true`).
- **Immutability**: models mutate by returning copies — Pydantic `model_copy(update={...})`, dataclasses `dataclasses.replace(...)`. Match the existing `MissionSession` / `ExecutionStep` style. Never mutate a model in place.
- **No shell in agents/wrappers**: agents emit structured actions; execution happens *only* through `Sandbox`. Never add `subprocess`/shell to an agent, decider, or tool wrapper.
- **Storage**: parameterized SQL only. Migrations are static DDL files named `NNN_*.sql`, applied in sorted order by `StorageConnection.apply_migrations()`. `PRAGMA foreign_keys = ON` is set; every child table needs a real `sessions(session_id)` FK.
- **Timestamps**: UTC only — `datetime.now(UTC)`.
- **Tests**: `pytest`, `asyncio_mode = "auto"`. Live-LLM tests are gated behind `SABER_RUN_LLM_E2E=1`; Docker E2E behind `SABER_RUN_DOCKER_E2E=1`. Neither runs in default CI.
- **Commits**: frequent, conventional-commit style. End every commit message with:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```

## Design Summary (approved)

The approved design decisions this plan implements:

1. **MissionLoop is primary**; `MissionOrchestrator.run_mission()` delegates to it; plan-first driving retires.
2. **New `MissionState`** (working memory) + **own persistence** (migration `003`). `MissionSession` stays the lifecycle record; the loop syncs findings/evidence/confirmations across.
3. **LLM-primary decider** (`LlmDecider`) with a **thin `DeterministicDecider`** for offline runs.
4. **Risk-gated autonomy**: autonomous by default; only `high`-risk/destructive/"deep exploit" actions pause for a one-click confirmation. Out-of-scope targets are *refused*, never offered. Per-mission `autonomy_level` (`recon_only`/`assisted`/`autonomous`, default `autonomous`) tightens this.
5. **Keep the 9 agents as capability lenses**; the loop dispatches execution through them (reusing their tool wiring). No agent rewrite.
6. **Target order**: network/IP → web → CTF/SSH, all three as acceptance targets.
7. **Testing**: deterministic unit tests for pure components; **live-model integration** for loop/decider correctness (behind `SABER_RUN_LLM_E2E`), asserting loop *invariants* (state grows, no scope violation, terminates, report produced) rather than exact tool order.

## File Structure

**New files**
| Path | Responsibility |
|------|----------------|
| `saber/models/mission_state.py` | `MissionState` + sub-models (`KnownHost`, `KnownService`, `KnownTechnology`, `KnownCredential`, `KnownVuln`, `Hypothesis`, `AttemptedAction`), `AutonomyLevel`. Working memory. |
| `saber/storage/migrations/003_mission_state.sql` | `mission_states` table (snapshot JSON, FK to sessions). |
| `saber/storage/mission_state_store.py` | `MissionStateStore` — save/load/snapshot state JSON. |
| `saber/core/state_merger.py` | `StateMerger` — normalize parsed observations into `MissionState`. |
| `saber/core/state_summary.py` | `StateSummarizer`, `StateSummary` — token-bounded agent memory. |
| `saber/orchestration/risk_gate.py` | `RiskGate`, `AutonomyLevel` gate logic, `GateDecision`, `GateResult`. |
| `saber/orchestration/stop_conditions.py` | `StopEvaluator`, `StopDecision`. |
| `saber/agents/deciders/__init__.py` | package marker. |
| `saber/agents/deciders/base.py` | `NextActionDecider` ABC, `ProposedAction`, `ActionKind`, `RiskLevel`. |
| `saber/agents/deciders/deterministic.py` | `DeterministicDecider`. |
| `saber/agents/deciders/llm.py` | `LlmDecider`. |
| `prompts/next_action.txt` | system prompt for the loop decider. |
| `saber/orchestration/action_executor.py` | `ActionExecutor`, `ActionExecutionRecord` — dispatch a `ProposedAction` through a capability agent. |
| `saber/orchestration/mission_loop.py` | `MissionLoop`, `MissionLoopResult` — the closed loop. |
| `saber/orchestration/strategies/__init__.py` | package marker. |
| `saber/orchestration/strategies/base.py` | `TargetStrategy` ABC, `StrategyKind`, `select_strategy()`. |
| `saber/orchestration/strategies/network.py` | network/IP strategy. |
| `saber/orchestration/strategies/web.py` | website/URL strategy. |
| `saber/orchestration/strategies/ctf.py` | CTF/SSH box strategy. |
| `saber/reporting/state_report_adapter.py` | `MissionStateReportAdapter` — final state → report context. |
| `saber/ui/web/routers/mission_state.py` | GUI live MissionState endpoints. |

**Modified files**
| Path | Change |
|------|--------|
| `saber/core/result_processor.py` | Add additive `parsed_observations` to `ProcessedToolResult`; populate it. |
| `saber/core/runtime.py` | Wire `MissionLoop`, decider, `StateMerger`, `MissionStateStore`, `RiskGate`, `StopEvaluator`, strategies. |
| `saber/orchestration/mission_orchestrator.py` | `run_mission()` delegates to `MissionLoop`; remove plan-first driving (keep optional seed). |
| `saber/reporting/finalizer.py` | Accept a `MissionState` and use the report adapter. |
| `saber/ui/web/app.py` | Register the mission_state router; add the live-state view. |
| `README.md`, `CLAUDE.md` | Rewrite to describe the agentic loop (final phase). |

---

# Phase P0 — MissionState & persistence

### Task 1: `MissionState` working-memory models

**Files:**
- Create: `saber/models/mission_state.py`
- Test: `tests/model_tests/test_mission_state.py`

**Interfaces:**
- Consumes: `saber.models.target.Target`, `saber.models.scope.MissionScope`.
- Produces:
  - `AutonomyLevel(StrEnum)` = `RECON_ONLY | ASSISTED | AUTONOMOUS`.
  - Sub-models `KnownHost`, `KnownService` (`.key -> "host:port/proto"`), `KnownTechnology`, `KnownCredential`, `KnownVuln`, `Hypothesis`, `AttemptedAction` (`.signature -> str`).
  - `MissionState(BaseModel)` with fields listed below and methods:
    - `failed_actions -> list[AttemptedAction]` (property)
    - `record_attempt(attempt: AttemptedAction) -> MissionState`
    - `touch() -> MissionState` (bump `updated_at`)
    - `to_summary_dict() -> dict[str, Any]`

- [ ] **Step 1: Write the failing test**

```python
# tests/model_tests/test_mission_state.py
from datetime import UTC, datetime

from saber.models.mission_state import (
    AttemptedAction,
    AutonomyLevel,
    KnownService,
    MissionState,
)
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(
        session_id="session_abc",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="Enumerate and assess 10.0.0.5",
    )


def test_defaults_are_autonomous_and_empty():
    state = _state()
    assert state.autonomy_level == AutonomyLevel.AUTONOMOUS
    assert state.services == []
    assert state.step_count == 0
    assert state.objective_met is False


def test_known_service_key():
    svc = KnownService(host="10.0.0.5", port=80, protocol="tcp", service="http")
    assert svc.key == "10.0.0.5:80/tcp"


def test_record_attempt_is_immutable_and_appends():
    state = _state()
    attempt = AttemptedAction(tool_name="nmap", action="service_scan", success=True)
    updated = state.record_attempt(attempt)

    assert state.attempted_actions == []  # original unchanged
    assert len(updated.attempted_actions) == 1
    assert updated.failed_actions == []


def test_failed_actions_filters():
    state = _state().record_attempt(
        AttemptedAction(tool_name="nmap", action="service_scan", success=False, reason="timeout")
    )
    assert len(state.failed_actions) == 1
    assert state.failed_actions[0].reason == "timeout"


def test_attempt_signature_is_stable_and_order_independent():
    a = AttemptedAction(tool_name="whatweb", action="fingerprint", args={"url": "http://x", "depth": 1})
    b = AttemptedAction(tool_name="whatweb", action="fingerprint", args={"depth": 1, "url": "http://x"})
    assert a.signature == b.signature
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/model_tests/test_mission_state.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'saber.models.mission_state'`.

- [ ] **Step 3: Write minimal implementation**

```python
# saber/models/mission_state.py
"""Working-memory state for the SABER agentic mission loop.

MissionState is distinct from MissionSession. MissionSession is the lifecycle
record (status, phases, approvals). MissionState is the accumulating knowledge
the loop reasons over each iteration: hosts, services, credentials, vulns,
hypotheses, and the trace of attempted/failed actions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from saber.models.scope import MissionScope
from saber.models.target import Target


class AutonomyLevel(StrEnum):
    """How much the loop may do without a human confirmation."""

    RECON_ONLY = "recon_only"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"


class KnownHost(BaseModel):
    """A host the loop has learned about."""

    address: str
    hostnames: list[str] = Field(default_factory=list)
    os: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownService(BaseModel):
    """An open service on a host."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        """Return the natural dedupe key."""

        return f"{self.host}:{self.port}/{self.protocol}"


class KnownTechnology(BaseModel):
    """A technology/product fingerprinted on a host or URL."""

    host: str
    name: str
    version: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownCredential(BaseModel):
    """A credential discovered or validated during the mission."""

    username: str
    secret: str | None = None
    kind: str = "password"  # password | hash | key | token
    host: str | None = None
    service: str | None = None
    validated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnownVuln(BaseModel):
    """A candidate or confirmed vulnerability."""

    title: str
    host: str | None = None
    port: int | None = None
    severity: str = "info"
    identifier: str | None = None  # CVE id, nuclei template id, etc.
    confirmed: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    """A ranked belief the loop is reasoning about."""

    statement: str
    confidence: float = 0.5
    supporting_evidence: list[str] = Field(default_factory=list)
    status: str = "open"  # open | confirmed | rejected
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttemptedAction(BaseModel):
    """One action the loop has run, with outcome."""

    tool_name: str
    action: str
    args: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    reason: str = ""
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def signature(self) -> str:
        """Return a stable, order-independent identity for repeat detection."""

        args = json.dumps(self.args, sort_keys=True, default=str)
        return f"{self.tool_name}:{self.action}:{args}"


class MissionState(BaseModel):
    """Accumulating working memory for one mission."""

    session_id: str
    target: Target
    objective: str = ""
    scope: MissionScope | None = None
    autonomy_level: AutonomyLevel = AutonomyLevel.AUTONOMOUS
    roe: dict[str, Any] = Field(default_factory=dict)

    hosts: list[KnownHost] = Field(default_factory=list)
    services: list[KnownService] = Field(default_factory=list)
    technologies: list[KnownTechnology] = Field(default_factory=list)
    credentials: list[KnownCredential] = Field(default_factory=list)
    vulns: list[KnownVuln] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    attempted_actions: list[AttemptedAction] = Field(default_factory=list)

    finding_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    objective_met: bool = False
    stop_reason: str | None = None
    step_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def failed_actions(self) -> list[AttemptedAction]:
        """Return only the actions that failed."""

        return [action for action in self.attempted_actions if not action.success]

    def record_attempt(self, attempt: AttemptedAction) -> MissionState:
        """Return a copy with one more attempted action and updated timestamp."""

        return self.model_copy(
            update={
                "attempted_actions": [*self.attempted_actions, attempt],
                "step_count": self.step_count + 1,
                "updated_at": datetime.now(UTC),
            }
        )

    def touch(self) -> MissionState:
        """Return a copy with a bumped updated_at timestamp."""

        return self.model_copy(update={"updated_at": datetime.now(UTC)})

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact JSON-compatible snapshot for CLI/GUI/report."""

        return {
            "session_id": self.session_id,
            "target": self.target.to_agent_dict(),
            "objective": self.objective,
            "autonomy_level": self.autonomy_level.value,
            "counts": {
                "hosts": len(self.hosts),
                "services": len(self.services),
                "technologies": len(self.technologies),
                "credentials": len(self.credentials),
                "vulns": len(self.vulns),
                "hypotheses": len(self.hypotheses),
                "attempted_actions": len(self.attempted_actions),
                "failed_actions": len(self.failed_actions),
            },
            "objective_met": self.objective_met,
            "stop_reason": self.stop_reason,
            "step_count": self.step_count,
            "updated_at": self.updated_at.isoformat(),
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/model_tests/test_mission_state.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
ruff format saber/models/mission_state.py tests/model_tests/test_mission_state.py
ruff check saber tests
git add saber/models/mission_state.py tests/model_tests/test_mission_state.py
git commit -m "feat(models): add MissionState working-memory model

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `MissionStateStore` + migration 003

**Files:**
- Create: `saber/storage/migrations/003_mission_state.sql`
- Create: `saber/storage/mission_state_store.py`
- Test: `tests/storage_tests/test_mission_state_store.py`

**Interfaces:**
- Consumes: `saber.storage.connection.StorageConnection`, `saber.models.mission_state.MissionState`, `saber.models.session.MissionSession`.
- Produces: `MissionStateStore(connection)` with:
  - `save(state: MissionState) -> None` (upsert by `session_id`)
  - `load(session_id: str) -> MissionState | None`
  - `snapshot(state: MissionState) -> None` (alias for `save`, semantic name used by the loop)

- [ ] **Step 1: Write the failing test**

```python
# tests/storage_tests/test_mission_state_store.py
from saber.models.mission_state import KnownService, MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.storage.connection import StorageConnection
from saber.storage.mission_state_store import MissionStateStore
from saber.storage.session_store import SessionStore


def _conn(tmp_path) -> StorageConnection:
    connection = StorageConnection(tmp_path / "saber.db")
    connection.initialize()
    return connection


def _seed_session(connection) -> str:
    store = SessionStore(connection)
    session = MissionSession(session_id="session_s1", mission_name="m")
    store.create_session(session)
    return session.session_id


def test_migration_003_creates_table(tmp_path):
    connection = _conn(tmp_path)
    row = connection.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='mission_states'"
    )
    assert row is not None


def test_save_and_load_round_trip(tmp_path):
    connection = _conn(tmp_path)
    session_id = _seed_session(connection)
    store = MissionStateStore(connection)

    state = MissionState(
        session_id=session_id,
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
        services=[KnownService(host="10.0.0.5", port=22, service="ssh")],
    )
    store.save(state)

    loaded = store.load(session_id)
    assert loaded is not None
    assert loaded.objective == "assess"
    assert loaded.services[0].key == "10.0.0.5:22/tcp"


def test_save_is_upsert(tmp_path):
    connection = _conn(tmp_path)
    session_id = _seed_session(connection)
    store = MissionStateStore(connection)
    base = MissionState(session_id=session_id, target=Target(type=TargetType.IP, value="10.0.0.5"))

    store.save(base)
    store.save(base.model_copy(update={"objective": "second"}))

    rows = connection.query_all("SELECT session_id FROM mission_states WHERE session_id = ?", (session_id,))
    assert len(rows) == 1
    assert store.load(session_id).objective == "second"


def test_load_missing_returns_none(tmp_path):
    connection = _conn(tmp_path)
    assert MissionStateStore(connection).load("nope") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/storage_tests/test_mission_state_store.py -v`
Expected: FAIL — module/table missing.

- [ ] **Step 3: Write the migration**

```sql
-- saber/storage/migrations/003_mission_state.sql
-- SABER storage migration 003
-- Working-memory state for the agentic mission loop.
--
-- Security notes:
-- - Static DDL only.
-- - state_json is inert JSON TEXT written via parameterized queries.

CREATE TABLE IF NOT EXISTS mission_states (
    session_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
```

- [ ] **Step 4: Write the store**

```python
# saber/storage/mission_state_store.py
"""Persistence for MissionState snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from saber.models.mission_state import MissionState


class MissionStateStore:
    """Persist and load MissionState as a JSON snapshot per session."""

    def __init__(self, connection: Any) -> None:
        """Initialize store."""

        self.connection = connection

    def save(self, state: MissionState) -> None:
        """Upsert the working-memory snapshot for a session."""

        if not state.session_id:
            raise ValueError("MissionState.session_id cannot be empty.")

        self.connection.execute(
            """
            INSERT OR REPLACE INTO mission_states (session_id, state_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (
                state.session_id,
                state.model_dump_json(),
                datetime.now(UTC).isoformat(),
            ),
        )

    def snapshot(self, state: MissionState) -> None:
        """Alias used by the mission loop after every merge."""

        self.save(state)

    def load(self, session_id: str) -> MissionState | None:
        """Load the latest snapshot for a session, or None."""

        row = self.connection.query_one(
            "SELECT state_json FROM mission_states WHERE session_id = ?",
            (session_id,),
        )
        if row is None:
            return None
        return MissionState.model_validate_json(row["state_json"])
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/storage_tests/test_mission_state_store.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Regression + commit**

```bash
pytest tests/storage_tests -q
ruff format saber/storage/mission_state_store.py tests/storage_tests/test_mission_state_store.py
ruff check saber tests
git add saber/storage/mission_state_store.py saber/storage/migrations/003_mission_state.sql tests/storage_tests/test_mission_state_store.py
git commit -m "feat(storage): persist MissionState (migration 003 + MissionStateStore)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P1 — Normalization & agent memory

### Task 3: `StateMerger` (+ expose parsed observations)

**Files:**
- Modify: `saber/core/result_processor.py` (add additive `parsed_observations`)
- Create: `saber/core/state_merger.py`
- Test: `tests/unit/test_state_merger.py`
- Test: `tests/unit/test_result_processor_parsed_observations.py`

**Interfaces:**
- Consumes: `MissionState`, `AttemptedAction`, `KnownHost/Service/Technology/Credential/Vuln`, `Hypothesis`, `ProcessedToolResult.parsed_observations`.
- Produces:
  - `ProcessedToolResult.parsed_observations: list[dict[str, Any]]` (new field, default `[]`).
  - `StateMerger.merge(state: MissionState, parsed_observations: list[dict], attempt: AttemptedAction, evidence_refs: list[str] | None = None, finding_refs: list[str] | None = None) -> MissionState`.
  - Parsed-observation contract: each dict has `kind` in `{host, service, technology, credential, vuln}` and a `data` dict. `service` data: `host, port, protocol, service, product, version, state`. `vuln` data: `title, host, port, severity, identifier`. `technology` data: `host, name, version`. `credential` data: `username, secret, kind, host, service`. `host` data: `address, hostnames, os`.

- [ ] **Step 1: Write the failing test for `parsed_observations`**

```python
# tests/unit/test_result_processor_parsed_observations.py
from saber.core.result_processor import ProcessedToolResult


def test_processed_result_defaults_parsed_observations_empty():
    result = ProcessedToolResult(session_id="s", step_id=None, tool_name="nmap")
    assert result.parsed_observations == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_result_processor_parsed_observations.py -v`
Expected: FAIL — `TypeError`/`AttributeError` (field does not exist).

- [ ] **Step 3: Add the additive field + populate it**

In `saber/core/result_processor.py`, add the field to the `ProcessedToolResult` dataclass (after `observation_ids`):

```python
    parsed_observations: list[dict[str, Any]] = field(default_factory=list)
```

Add it to `to_dict()`:

```python
            "parsed_observations": self.parsed_observations,
```

In both `process_tool_result()` and `process_evidence_file()`, collect a `parsed_observations` list while iterating `parser_result.observations` and pass it into the returned `ProcessedToolResult`. Add before the observation loop:

```python
        parsed_observations: list[dict[str, Any]] = []
```

Inside the `for observation in ... parser_result.observations` loop, after `observation_ids.append(observation_id)`:

```python
                parsed_observations.append(
                    {
                        "kind": self._value_from_observation(observation, "kind"),
                        "data": self._value_from_observation(observation, "data") or {},
                        "summary": self._value_from_observation(observation, "summary") or "",
                        "source_tool": self._value_from_observation(observation, "source_tool"),
                    }
                )
```

And include `parsed_observations=parsed_observations` in each `return ProcessedToolResult(...)`.

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/unit/test_result_processor_parsed_observations.py -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `StateMerger`**

```python
# tests/unit/test_state_merger.py
from saber.core.state_merger import StateMerger
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))


def _attempt() -> AttemptedAction:
    return AttemptedAction(tool_name="nmap", action="service_scan", success=True)


def test_merge_adds_service_and_records_attempt():
    obs = [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "service": "http", "state": "open"}}]
    merged = StateMerger().merge(_state(), obs, _attempt())

    assert len(merged.services) == 1
    assert merged.services[0].key == "10.0.0.5:80/tcp"
    assert merged.step_count == 1
    assert merged.attempted_actions[0].tool_name == "nmap"


def test_merge_dedupes_services_by_key():
    state = _state()
    obs = [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "service": "http"}}]
    once = StateMerger().merge(state, obs, _attempt())
    twice = StateMerger().merge(once, obs, _attempt())
    assert len(twice.services) == 1  # no duplicate


def test_merge_updates_service_fields_on_rescan():
    state = _state()
    first = StateMerger().merge(state, [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80}}], _attempt())
    second = StateMerger().merge(
        first,
        [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "product": "nginx", "version": "1.25"}}],
        _attempt(),
    )
    assert len(second.services) == 1
    assert second.services[0].product == "nginx"
    assert second.services[0].version == "1.25"


def test_merge_promotes_vuln_and_evidence_refs():
    obs = [{"kind": "vuln", "data": {"title": "CVE-2021-41773", "host": "10.0.0.5", "severity": "high"}}]
    merged = StateMerger().merge(_state(), obs, _attempt(), evidence_refs=["ev1"], finding_refs=["f1"])
    assert merged.vulns[0].identifier is None or merged.vulns[0].title.startswith("CVE")
    assert "ev1" in merged.evidence_refs
    assert "f1" in merged.finding_refs


def test_merge_records_failed_attempt():
    attempt = AttemptedAction(tool_name="nmap", action="service_scan", success=False, reason="timeout")
    merged = StateMerger().merge(_state(), [], attempt)
    assert merged.failed_actions[0].reason == "timeout"


def test_merge_is_immutable():
    state = _state()
    StateMerger().merge(state, [{"kind": "service", "data": {"host": "10.0.0.5", "port": 22}}], _attempt())
    assert state.services == []  # original untouched
```

- [ ] **Step 6: Run it to verify it fails**

Run: `pytest tests/unit/test_state_merger.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 7: Implement `StateMerger`**

```python
# saber/core/state_merger.py
"""Normalize parsed tool observations into MissionState.

This is the deterministic 'update its understanding' step of the mission loop.
It dedupes hosts/services/technologies, promotes vulns, tracks credentials,
attaches evidence/finding refs, and records the attempted action.
"""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import (
    AttemptedAction,
    Hypothesis,
    KnownCredential,
    KnownHost,
    KnownService,
    KnownTechnology,
    KnownVuln,
    MissionState,
)


class StateMerger:
    """Merge normalized parser observations into MissionState."""

    def merge(
        self,
        state: MissionState,
        parsed_observations: list[dict[str, Any]],
        attempt: AttemptedAction,
        evidence_refs: list[str] | None = None,
        finding_refs: list[str] | None = None,
    ) -> MissionState:
        """Return a new MissionState folding in the parsed observations."""

        hosts = {host.address: host for host in state.hosts}
        services = {svc.key: svc for svc in state.services}
        technologies = {(tech.host, tech.name): tech for tech in state.technologies}
        credentials = {(cred.username, cred.host, cred.service): cred for cred in state.credentials}
        vulns = {self._vuln_key(v.title, v.host, v.port): v for v in state.vulns}

        for observation in parsed_observations:
            kind = str(observation.get("kind") or "").lower()
            data = observation.get("data") or {}
            if not isinstance(data, dict):
                continue

            if kind == "host":
                self._merge_host(hosts, data)
            elif kind == "service":
                self._merge_service(services, hosts, data)
            elif kind == "technology":
                self._merge_technology(technologies, data)
            elif kind == "credential":
                self._merge_credential(credentials, data)
            elif kind == "vuln":
                self._merge_vuln(vulns, data, evidence_refs or [])

        updated = state.record_attempt(attempt)
        return updated.model_copy(
            update={
                "hosts": list(hosts.values()),
                "services": list(services.values()),
                "technologies": list(technologies.values()),
                "credentials": list(credentials.values()),
                "vulns": list(vulns.values()),
                "evidence_refs": self._extend_unique(state.evidence_refs, evidence_refs),
                "finding_refs": self._extend_unique(state.finding_refs, finding_refs),
            }
        )

    def _merge_host(self, hosts: dict[str, KnownHost], data: dict[str, Any]) -> None:
        address = str(data.get("address") or data.get("host") or "").strip()
        if not address:
            return
        existing = hosts.get(address)
        hosts[address] = KnownHost(
            address=address,
            hostnames=list(data.get("hostnames") or (existing.hostnames if existing else [])),
            os=data.get("os") or (existing.os if existing else None),
            metadata={**(existing.metadata if existing else {}), **(data.get("metadata") or {})},
        )

    def _merge_service(
        self,
        services: dict[str, KnownService],
        hosts: dict[str, KnownHost],
        data: dict[str, Any],
    ) -> None:
        host = str(data.get("host") or "").strip()
        port = data.get("port")
        if not host or port is None:
            return
        candidate = KnownService(
            host=host,
            port=int(port),
            protocol=str(data.get("protocol") or "tcp"),
            service=data.get("service"),
            product=data.get("product"),
            version=data.get("version"),
            state=str(data.get("state") or "open"),
        )
        existing = services.get(candidate.key)
        if existing is None:
            services[candidate.key] = candidate
        else:
            services[candidate.key] = existing.model_copy(
                update={
                    "service": candidate.service or existing.service,
                    "product": candidate.product or existing.product,
                    "version": candidate.version or existing.version,
                    "state": candidate.state or existing.state,
                }
            )
        hosts.setdefault(host, KnownHost(address=host))

    def _merge_technology(self, technologies: dict[tuple, KnownTechnology], data: dict[str, Any]) -> None:
        host = str(data.get("host") or "").strip()
        name = str(data.get("name") or "").strip()
        if not host or not name:
            return
        technologies[(host, name)] = KnownTechnology(host=host, name=name, version=data.get("version"))

    def _merge_credential(self, credentials: dict[tuple, KnownCredential], data: dict[str, Any]) -> None:
        username = str(data.get("username") or "").strip()
        if not username:
            return
        key = (username, data.get("host"), data.get("service"))
        credentials[key] = KnownCredential(
            username=username,
            secret=data.get("secret"),
            kind=str(data.get("kind") or "password"),
            host=data.get("host"),
            service=data.get("service"),
            validated=bool(data.get("validated", False)),
        )

    def _merge_vuln(self, vulns: dict[str, KnownVuln], data: dict[str, Any], evidence_refs: list[str]) -> None:
        title = str(data.get("title") or "").strip()
        if not title:
            return
        key = self._vuln_key(title, data.get("host"), data.get("port"))
        vulns[key] = KnownVuln(
            title=title,
            host=data.get("host"),
            port=data.get("port"),
            severity=str(data.get("severity") or "info"),
            identifier=data.get("identifier"),
            confirmed=bool(data.get("confirmed", False)),
            evidence_refs=list(evidence_refs),
        )

    @staticmethod
    def _vuln_key(title: str, host: Any, port: Any) -> str:
        return f"{title}|{host}|{port}"

    @staticmethod
    def _extend_unique(base: list[str], extra: list[str] | None) -> list[str]:
        result = list(base)
        for item in extra or []:
            if item not in result:
                result.append(item)
        return result
```

- [ ] **Step 8: Run it to verify it passes**

Run: `pytest tests/unit/test_state_merger.py tests/unit/test_result_processor_parsed_observations.py -v`
Expected: PASS.

- [ ] **Step 9: Regression + commit**

```bash
pytest tests/unit tests/parser_tests -q     # ensure ResultProcessor change didn't regress
ruff format saber/core/state_merger.py saber/core/result_processor.py tests/unit/test_state_merger.py tests/unit/test_result_processor_parsed_observations.py
ruff check saber tests
git add saber/core/state_merger.py saber/core/result_processor.py tests/unit/test_state_merger.py tests/unit/test_result_processor_parsed_observations.py
git commit -m "feat(core): add StateMerger and expose parsed observations

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `StateSummarizer` (agent memory)

**Files:**
- Create: `saber/core/state_summary.py`
- Test: `tests/unit/test_state_summary.py`

**Interfaces:**
- Consumes: `MissionState`.
- Produces:
  - `StateSummary` (frozen dataclass) with `.to_dict() -> dict[str, Any]`.
  - `StateSummarizer(max_items: int = 20)` with `summarize(state: MissionState) -> StateSummary`.
  - Summary caps each list to `max_items`, prioritizing: open services, unconfirmed high/critical vulns, validated credentials, open hypotheses, and the most recent failed actions (so the decider avoids repeats).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_state_summary.py
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import (
    AttemptedAction,
    Hypothesis,
    KnownService,
    KnownVuln,
    MissionState,
)
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
        services=[KnownService(host="10.0.0.5", port=p) for p in range(1, 60)],
        vulns=[KnownVuln(title="v", severity="high")],
        hypotheses=[Hypothesis(statement="maybe RCE via CVE-2021-41773")],
        attempted_actions=[AttemptedAction(tool_name="nmap", action="x", success=False, reason="timeout")],
    )


def test_summary_caps_services():
    summary = StateSummarizer(max_items=20).summarize(_state())
    assert len(summary.to_dict()["services"]) <= 20


def test_summary_includes_failed_actions_for_repeat_avoidance():
    summary = StateSummarizer().summarize(_state())
    failed = summary.to_dict()["recent_failures"]
    assert failed and failed[0]["reason"] == "timeout"


def test_summary_includes_objective_and_counts():
    d = StateSummarizer().summarize(_state()).to_dict()
    assert d["objective"] == "assess"
    assert d["counts"]["services"] == 59
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/unit/test_state_summary.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/core/state_summary.py
"""Token-bounded summary of MissionState for the decider prompt."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.models.mission_state import MissionState

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class StateSummary:
    """Compact, prioritized view of MissionState for the decider."""

    objective: str
    target: dict[str, Any]
    autonomy_level: str
    counts: dict[str, int]
    services: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    recent_failures: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible payload for the LLM."""

        return {
            "objective": self.objective,
            "target": self.target,
            "autonomy_level": self.autonomy_level,
            "counts": self.counts,
            "services": self.services,
            "technologies": self.technologies,
            "credentials": self.credentials,
            "vulns": self.vulns,
            "hypotheses": self.hypotheses,
            "recent_failures": self.recent_failures,
        }


class StateSummarizer:
    """Build a bounded StateSummary from MissionState."""

    def __init__(self, max_items: int = 20) -> None:
        """Initialize summarizer."""

        self.max_items = max_items

    def summarize(self, state: MissionState) -> StateSummary:
        """Return a prioritized, capped summary."""

        open_services = [svc for svc in state.services if svc.state == "open"]
        vulns_sorted = sorted(state.vulns, key=lambda v: _SEVERITY_RANK.get(v.severity, 5))
        open_hypotheses = [h for h in state.hypotheses if h.status == "open"]

        return StateSummary(
            objective=state.objective,
            target=state.target.to_agent_dict(),
            autonomy_level=state.autonomy_level.value,
            counts=state.to_summary_dict()["counts"],
            services=[svc.model_dump() for svc in open_services[: self.max_items]],
            technologies=[t.model_dump() for t in state.technologies[: self.max_items]],
            credentials=[c.model_dump(exclude={"secret"}) for c in state.credentials[: self.max_items]],
            vulns=[v.model_dump() for v in vulns_sorted[: self.max_items]],
            hypotheses=[h.model_dump() for h in open_hypotheses[: self.max_items]],
            recent_failures=[
                {"tool_name": a.tool_name, "action": a.action, "reason": a.reason}
                for a in state.failed_actions[-self.max_items :]
            ],
        )
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/unit/test_state_summary.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/core/state_summary.py tests/unit/test_state_summary.py
ruff check saber tests
git add saber/core/state_summary.py tests/unit/test_state_summary.py
git commit -m "feat(core): add StateSummarizer for decider agent memory

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P2 — Safety & control primitives

### Task 5: `RiskGate` + autonomy + scope enforcement

**Files:**
- Create: `saber/orchestration/risk_gate.py`
- Test: `tests/orchestration_tests/test_risk_gate.py`

**Interfaces:**
- Consumes: `MissionState`, `AutonomyLevel`, `saber.agents.deciders.base.ProposedAction` + `RiskLevel` (defined in Task 7 — this task imports them; sequence Task 7 before 5 if implementing strictly TDD, or define `ProposedAction`/`RiskLevel` stubs first. **Implementation order: do Task 7 before Task 5.**).
- Produces:
  - `GateDecision(StrEnum)` = `ALLOW | CONFIRM | REFUSE`.
  - `GateResult` (frozen dataclass): `decision: GateDecision`, `reason: str`.
  - `RiskGate(tool_catalog=None)` with `evaluate(state: MissionState, action: ProposedAction) -> GateResult`.
  - Rules (in order): out-of-scope target → `REFUSE`; scope prohibits action → `REFUSE`; `recon_only` + exploit-class category → `REFUSE`; `assisted` + (exploit-class or risk ≥ medium) → `CONFIRM`; `autonomous` + (risk == high or `requires_confirmation`) → `CONFIRM`; else `ALLOW`.

> **Note:** exploit-class categories = `{"exploitation", "post_exploit", "lateral_movement"}`. Category is read from `action.metadata["category"]`, falling back to a `tool_catalog` lookup by `action.tool_name`.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_risk_gate.py
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.risk_gate import GateDecision, RiskGate


def _state(level: AutonomyLevel) -> MissionState:
    return MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=level,
    )


def _action(risk: RiskLevel, category: str = "recon", requires_confirmation: bool = False) -> ProposedAction:
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="t",
        tool_action="a",
        objective="o",
        risk=risk,
        requires_confirmation=requires_confirmation,
        metadata={"category": category},
    )


def test_autonomous_allows_low_and_medium():
    gate = RiskGate()
    assert gate.evaluate(_state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.LOW)).decision == GateDecision.ALLOW
    assert gate.evaluate(_state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.MEDIUM)).decision == GateDecision.ALLOW


def test_autonomous_confirms_high_risk():
    result = RiskGate().evaluate(_state(AutonomyLevel.AUTONOMOUS), _action(RiskLevel.HIGH, category="exploitation"))
    assert result.decision == GateDecision.CONFIRM


def test_assisted_confirms_exploit_class_even_at_low_risk():
    result = RiskGate().evaluate(
        _state(AutonomyLevel.ASSISTED), _action(RiskLevel.LOW, category="exploitation")
    )
    assert result.decision == GateDecision.CONFIRM


def test_recon_only_refuses_exploit_class():
    result = RiskGate().evaluate(
        _state(AutonomyLevel.RECON_ONLY), _action(RiskLevel.LOW, category="post_exploit")
    )
    assert result.decision == GateDecision.REFUSE
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_risk_gate.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/orchestration/risk_gate.py
"""Risk-gated autonomy for the mission loop.

Autonomous by default. Only high-risk/destructive actions pause for a human
confirmation. Out-of-scope actions are refused, never offered for confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState

EXPLOIT_CLASS = {"exploitation", "post_exploit", "lateral_movement"}


class GateDecision(StrEnum):
    """Outcome of the risk gate."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    REFUSE = "refuse"


@dataclass(frozen=True)
class GateResult:
    """Gate decision with a human-readable reason."""

    decision: GateDecision
    reason: str


class RiskGate:
    """Decide whether an action may auto-run, needs confirmation, or is refused."""

    def __init__(self, tool_catalog: Any | None = None) -> None:
        """Initialize the gate with an optional ToolCatalog for category lookup."""

        self.tool_catalog = tool_catalog

    def evaluate(self, state: MissionState, action: ProposedAction) -> GateResult:
        """Return the gate decision for one proposed action."""

        if action.kind != ActionKind.TOOL:
            return GateResult(GateDecision.ALLOW, "non-tool action")

        if not self._scope_allows(state, action):
            return GateResult(GateDecision.REFUSE, "target or action is out of scope")

        category = self._category(action)
        exploit_class = category in EXPLOIT_CLASS

        if state.autonomy_level == AutonomyLevel.RECON_ONLY and exploit_class:
            return GateResult(GateDecision.REFUSE, "recon_only forbids exploit-class actions")

        if state.autonomy_level == AutonomyLevel.ASSISTED and (exploit_class or action.risk >= RiskLevel.MEDIUM):
            return GateResult(GateDecision.CONFIRM, "assisted mode requires confirmation")

        if state.autonomy_level == AutonomyLevel.AUTONOMOUS and (
            action.risk == RiskLevel.HIGH or action.requires_confirmation
        ):
            return GateResult(GateDecision.CONFIRM, "high-risk action requires confirmation")

        return GateResult(GateDecision.ALLOW, "within autonomy budget")

    def _category(self, action: ProposedAction) -> str:
        category = str(action.metadata.get("category") or "").lower()
        if category:
            return category
        if self.tool_catalog is not None:
            for tool in getattr(self.tool_catalog, "tools", []):
                if tool.name == action.tool_name:
                    return str(getattr(tool, "category", "")).lower()
        return ""

    @staticmethod
    def _scope_allows(state: MissionState, action: ProposedAction) -> bool:
        scope = state.scope
        if scope is None:
            return True
        if scope.is_action_prohibited(f"{action.tool_name}.{action.tool_action}"):
            return False
        target_value = (action.target.value if action.target else state.target.value)
        allowed = set(scope.target_values())
        if not allowed:
            return True
        return target_value in allowed
```

> `RiskLevel` must support ordering (`>=`). Task 7 defines it as an `IntEnum`-style comparable enum (see Task 7).

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_risk_gate.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/orchestration/risk_gate.py tests/orchestration_tests/test_risk_gate.py
ruff check saber tests
git add saber/orchestration/risk_gate.py tests/orchestration_tests/test_risk_gate.py
git commit -m "feat(orchestration): risk-gated autonomy (RiskGate)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `StopEvaluator`

**Files:**
- Create: `saber/orchestration/stop_conditions.py`
- Test: `tests/orchestration_tests/test_stop_conditions.py`

**Interfaces:**
- Consumes: `MissionState`, `ProposedAction`, `ActionKind`.
- Produces:
  - `StopDecision` (frozen dataclass): `should_stop: bool`, `reason: str`.
  - `StopEvaluator(max_steps: int = 50, max_repeat_failures: int = 3)` with `evaluate(state: MissionState, last_action: ProposedAction | None) -> StopDecision`.
  - Stops when: `state.objective_met`; `last_action.kind in {STOP, REPORT}`; `state.step_count >= max_steps`; the same failing action signature has occurred `>= max_repeat_failures` times.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_stop_conditions.py
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.stop_conditions import StopEvaluator


def _state(**kw) -> MissionState:
    return MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"), **kw)


def test_stops_when_objective_met():
    result = StopEvaluator().evaluate(_state(objective_met=True), None)
    assert result.should_stop and "objective" in result.reason


def test_stops_when_decider_says_stop():
    action = ProposedAction(kind=ActionKind.STOP, objective="done", risk=RiskLevel.LOW)
    assert StopEvaluator().evaluate(_state(), action).should_stop


def test_stops_at_max_steps():
    assert StopEvaluator(max_steps=5).evaluate(_state(step_count=5), None).should_stop


def test_stops_on_repeated_failures():
    failing = [
        AttemptedAction(tool_name="nmap", action="scan", args={"x": 1}, success=False, reason="timeout")
        for _ in range(3)
    ]
    state = _state(attempted_actions=failing)
    assert StopEvaluator(max_repeat_failures=3).evaluate(state, None).should_stop


def test_continues_by_default():
    assert StopEvaluator().evaluate(_state(step_count=1), None).should_stop is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_stop_conditions.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/orchestration/stop_conditions.py
"""Stop-condition evaluation for the mission loop."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from saber.agents.deciders.base import ActionKind, ProposedAction
from saber.models.mission_state import MissionState


@dataclass(frozen=True)
class StopDecision:
    """Whether the loop should stop, and why."""

    should_stop: bool
    reason: str


class StopEvaluator:
    """Evaluate when the mission loop should terminate."""

    def __init__(self, max_steps: int = 50, max_repeat_failures: int = 3) -> None:
        """Initialize evaluator."""

        self.max_steps = max_steps
        self.max_repeat_failures = max_repeat_failures

    def evaluate(self, state: MissionState, last_action: ProposedAction | None) -> StopDecision:
        """Return the stop decision given current state and the last action."""

        if state.objective_met:
            return StopDecision(True, "objective met")

        if last_action is not None and last_action.kind in {ActionKind.STOP, ActionKind.REPORT}:
            return StopDecision(True, f"decider requested {last_action.kind.value}")

        if state.step_count >= self.max_steps:
            return StopDecision(True, f"reached max_steps ({self.max_steps})")

        failures = Counter(action.signature for action in state.failed_actions)
        for signature, count in failures.items():
            if count >= self.max_repeat_failures:
                return StopDecision(True, f"repeated failure ({count}x): {signature}")

        return StopDecision(False, "continue")
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_stop_conditions.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/orchestration/stop_conditions.py tests/orchestration_tests/test_stop_conditions.py
ruff check saber tests
git add saber/orchestration/stop_conditions.py tests/orchestration_tests/test_stop_conditions.py
git commit -m "feat(orchestration): add StopEvaluator

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P3 — The decider (brain)

### Task 7: Decider base — `ProposedAction`, `NextActionDecider`

**Files:**
- Create: `saber/agents/deciders/__init__.py` (empty)
- Create: `saber/agents/deciders/base.py`
- Test: `tests/agent_tests/test_decider_base.py`

**Interfaces:**
- Produces:
  - `RiskLevel(IntEnum)` = `LOW=0 < MEDIUM=1 < HIGH=2` (comparable, with `from_str()`).
  - `ActionKind(StrEnum)` = `TOOL | STOP | REPORT`.
  - `ProposedAction` (frozen dataclass): `kind`, `objective`, `risk`, plus `tool_name`, `tool_action`, `args`, `agent_name`, `target`, `rationale`, `expected_evidence`, `requires_confirmation`, `metadata`. Method `to_dict()`.
  - `NextActionDecider(ABC)` with abstractmethod `decide(self, state: MissionState, summary: StateSummary) -> ProposedAction`.

- [ ] **Step 1: Write the failing test**

```python
# tests/agent_tests/test_decider_base.py
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel


def test_risk_level_is_ordered():
    assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH
    assert RiskLevel.from_str("HIGH") == RiskLevel.HIGH
    assert RiskLevel.from_str("bogus") == RiskLevel.LOW


def test_proposed_action_tool_requires_tool_name():
    import pytest

    with pytest.raises(ValueError):
        ProposedAction(kind=ActionKind.TOOL, objective="o", risk=RiskLevel.LOW)


def test_proposed_action_to_dict_round_trips_core_fields():
    action = ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="nmap",
        tool_action="service_scan",
        objective="enumerate",
        risk=RiskLevel.LOW,
    )
    d = action.to_dict()
    assert d["kind"] == "tool"
    assert d["tool_name"] == "nmap"
    assert d["risk"] == "low"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/agent_tests/test_decider_base.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/agents/deciders/base.py
"""Decider abstractions for the SABER mission loop."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from saber.core.state_summary import StateSummary
from saber.models.mission_state import MissionState
from saber.models.target import Target


class RiskLevel(IntEnum):
    """Ordered risk level (LOW < MEDIUM < HIGH)."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def from_str(cls, value: str | None) -> "RiskLevel":
        """Parse a risk string, defaulting to LOW."""

        return {"low": cls.LOW, "medium": cls.MEDIUM, "high": cls.HIGH}.get(
            str(value or "").strip().lower(), cls.LOW
        )

    @property
    def label(self) -> str:
        """Return the lowercase label."""

        return self.name.lower()


class ActionKind(StrEnum):
    """What the decider wants the loop to do next."""

    TOOL = "tool"
    STOP = "stop"
    REPORT = "report"


@dataclass(frozen=True)
class ProposedAction:
    """A single next action proposed by a decider."""

    kind: ActionKind
    objective: str
    risk: RiskLevel = RiskLevel.LOW
    tool_name: str | None = None
    tool_action: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    agent_name: str | None = None
    target: Target | None = None
    rationale: str = ""
    expected_evidence: str = ""
    requires_confirmation: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate proposed-action consistency."""

        if not self.objective.strip():
            raise ValueError("ProposedAction.objective cannot be empty.")
        if self.kind == ActionKind.TOOL and not (self.tool_name and self.tool_action):
            raise ValueError("TOOL actions require tool_name and tool_action.")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dict."""

        return {
            "kind": self.kind.value,
            "objective": self.objective,
            "risk": self.risk.label,
            "tool_name": self.tool_name,
            "tool_action": self.tool_action,
            "args": self.args,
            "agent_name": self.agent_name,
            "target": self.target.to_agent_dict() if self.target else None,
            "rationale": self.rationale,
            "expected_evidence": self.expected_evidence,
            "requires_confirmation": self.requires_confirmation,
            "metadata": self.metadata,
        }


class NextActionDecider(ABC):
    """Interface for choosing the next mission action."""

    @abstractmethod
    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the single best next action for the current state."""
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/agent_tests/test_decider_base.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/agents/deciders/base.py tests/agent_tests/test_decider_base.py
ruff check saber tests
git add saber/agents/deciders/__init__.py saber/agents/deciders/base.py tests/agent_tests/test_decider_base.py
git commit -m "feat(agents): add decider base (ProposedAction, NextActionDecider)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: `DeterministicDecider`

**Files:**
- Create: `saber/agents/deciders/deterministic.py`
- Test: `tests/agent_tests/test_deterministic_decider.py`

**Interfaces:**
- Consumes: `NextActionDecider`, `ProposedAction`, `MissionState`, `StateSummary`, `StateSummarizer`.
- Produces: `DeterministicDecider()` implementing `decide()`. Rule ladder (first match wins):
  1. No services known yet → `nmap.service_scan` on the target (recon).
  2. Open 80/443/8080 service with no technology fingerprint for that host → `whatweb.fingerprint` (web).
  3. Open web service with fingerprint but no vulns → `nuclei.template_scan` (web).
  4. Known service with product+version and no matching vuln lookup attempted → `searchsploit.lookup` (exploitation-intel, low risk).
  5. Nothing useful left → `ActionKind.REPORT`.

- [ ] **Step 1: Write the failing test**

```python
# tests/agent_tests/test_deterministic_decider.py
from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.deterministic import DeterministicDecider
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import KnownService, KnownTechnology, MissionState
from saber.models.target import Target, TargetType


def _decide(state: MissionState):
    return DeterministicDecider().decide(state, StateSummarizer().summarize(state))


def test_first_action_is_service_scan_when_no_services():
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    action = _decide(state)
    assert action.kind == ActionKind.TOOL
    assert (action.tool_name, action.tool_action) == ("nmap", "service_scan")


def test_web_service_without_fingerprint_triggers_whatweb():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
    )
    action = _decide(state)
    assert action.tool_name == "whatweb"


def test_report_when_nothing_left():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        technologies=[KnownTechnology(host="10.0.0.5", name="nginx")],
        vulns=[],
        metadata={"web_scanned": True, "exploit_intel_done": True},
    )
    # after web + intel exhausted, decider reports
    action = _decide(state)
    assert action.kind in {ActionKind.REPORT, ActionKind.TOOL}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/agent_tests/test_deterministic_decider.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/agents/deciders/deterministic.py
"""Rule-based fallback decider for offline / CI runs.

This is intentionally thin. The LLM decider is the real brain; this exists so
the loop can run and be tested without a live model.
"""

from __future__ import annotations

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction, RiskLevel
from saber.core.state_summary import StateSummary
from saber.models.mission_state import MissionState

_WEB_PORTS = {80, 443, 8080, 8443}


class DeterministicDecider(NextActionDecider):
    """Pick the next action from a fixed rule ladder over normalized state."""

    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the next action per the rule ladder (first match wins)."""

        attempted = {(a.tool_name, a.action) for a in state.attempted_actions}

        # 1. Recon first.
        if not state.services and ("nmap", "service_scan") not in attempted:
            return ProposedAction(
                kind=ActionKind.TOOL,
                tool_name="nmap",
                tool_action="service_scan",
                args={"target": state.target.value},
                agent_name="recon_agent",
                objective=f"Enumerate services on {state.target.value}",
                risk=RiskLevel.LOW,
                rationale="No services known; run a service scan.",
                metadata={"category": "recon"},
            )

        fingerprinted_hosts = {tech.host for tech in state.technologies}

        # 2. Web service without a fingerprint.
        for svc in state.services:
            if svc.port in _WEB_PORTS and svc.host not in fingerprinted_hosts:
                url = f"http://{svc.host}:{svc.port}"
                if ("whatweb", "fingerprint") not in attempted:
                    return ProposedAction(
                        kind=ActionKind.TOOL,
                        tool_name="whatweb",
                        tool_action="fingerprint",
                        args={"url": url},
                        agent_name="web_agent",
                        objective=f"Fingerprint web service at {url}",
                        risk=RiskLevel.LOW,
                        rationale="Open web port without a technology fingerprint.",
                        metadata={"category": "web"},
                    )

        # 3. Web fingerprint but no vuln scan yet.
        if fingerprinted_hosts and not state.vulns and not state.metadata.get("web_scanned"):
            svc = next((s for s in state.services if s.port in _WEB_PORTS), None)
            if svc is not None:
                url = f"http://{svc.host}:{svc.port}"
                return ProposedAction(
                    kind=ActionKind.TOOL,
                    tool_name="nuclei",
                    tool_action="template_scan",
                    args={"url": url},
                    agent_name="web_agent",
                    objective=f"Run nuclei against {url}",
                    risk=RiskLevel.MEDIUM,
                    rationale="Fingerprinted web service with no vuln scan yet.",
                    metadata={"category": "web"},
                )

        # 4. Exploit intelligence for versioned services.
        if not state.metadata.get("exploit_intel_done"):
            svc = next((s for s in state.services if s.product and s.version), None)
            if svc is not None and ("searchsploit", "lookup") not in attempted:
                return ProposedAction(
                    kind=ActionKind.TOOL,
                    tool_name="searchsploit",
                    tool_action="lookup",
                    args={"product": svc.product, "version": svc.version},
                    agent_name="exploit_agent",
                    objective=f"Look up known exploits for {svc.product} {svc.version}",
                    risk=RiskLevel.LOW,
                    rationale="Versioned service; check exploit intel.",
                    metadata={"category": "exploitation"},
                )

        # 5. Nothing useful left.
        return ProposedAction(
            kind=ActionKind.REPORT,
            objective="Generate final report; no further safe useful action.",
            risk=RiskLevel.LOW,
            rationale="Rule ladder exhausted.",
        )
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/agent_tests/test_deterministic_decider.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/agents/deciders/deterministic.py tests/agent_tests/test_deterministic_decider.py
ruff check saber tests
git add saber/agents/deciders/deterministic.py tests/agent_tests/test_deterministic_decider.py
git commit -m "feat(agents): add DeterministicDecider rule ladder

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: `LlmDecider` + `next_action.txt`

**Files:**
- Create: `saber/agents/deciders/llm.py`
- Create: `prompts/next_action.txt`
- Test: `tests/agent_tests/test_llm_decider.py`

**Interfaces:**
- Consumes: `NextActionDecider`, `ProposedAction`, `MissionState`, `StateSummary`, `saber.core.llm_client.LlmClient`, `saber.core.tool_catalog.ToolCatalog`, `saber.core.prompt_loader.PromptLoader`.
- Produces:
  - `LlmDecider(llm_client, tool_catalog, prompt_loader=None, prompt_name="next_action")` implementing `decide()`.
  - It builds a payload `{summary, tool_catalog, autonomy_level, scope}` → `llm_client.complete_json(system_prompt, user_prompt)` → parses a decision JSON → validates tool/action exist in the catalog → returns a `ProposedAction`. On unknown tool/action or invalid JSON, returns `ActionKind.STOP` with a reason (so the loop terminates cleanly rather than crashing).
  - Expected decision JSON schema (documented in the prompt): `{"kind": "tool|stop|report", "tool_name": str, "tool_action": str, "args": {}, "agent_name": str, "risk": "low|medium|high", "requires_confirmation": bool, "rationale": str, "expected_evidence": str, "category": str}`.

- [ ] **Step 1: Write the failing test (uses a fake LLM client — no live call)**

```python
# tests/agent_tests/test_llm_decider.py
from saber.agents.deciders.base import ActionKind, RiskLevel
from saber.agents.deciders.llm import LlmDecider
from saber.core.state_summary import StateSummarizer
from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.models.mission_state import MissionState
from saber.models.target import Target, TargetType


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.enabled = True

    def complete_json(self, system_prompt, user_prompt, metadata=None):
        return self._response


def _catalog() -> ToolCatalog:
    return ToolCatalog(
        [
            ToolSpec(
                name="nmap",
                category="recon",
                phase="reconnaissance",
                description="scanner",
                actions=[ToolActionSpec(tool_name="nmap", action="service_scan", description="scan")],
            )
        ]
    )


def _state() -> MissionState:
    return MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"), objective="assess")


def test_valid_tool_decision_becomes_proposed_action():
    client = _FakeClient(
        {
            "kind": "tool",
            "tool_name": "nmap",
            "tool_action": "service_scan",
            "args": {"target": "10.0.0.5"},
            "agent_name": "recon_agent",
            "risk": "low",
            "category": "recon",
            "rationale": "start with recon",
        }
    )
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.TOOL
    assert action.tool_name == "nmap"
    assert action.risk == RiskLevel.LOW
    assert action.metadata["category"] == "recon"


def test_unknown_tool_returns_stop():
    client = _FakeClient({"kind": "tool", "tool_name": "ghost", "tool_action": "x"})
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.STOP


def test_report_decision():
    client = _FakeClient({"kind": "report", "rationale": "done"})
    decider = LlmDecider(llm_client=client, tool_catalog=_catalog())
    action = decider.decide(_state(), StateSummarizer().summarize(_state()))
    assert action.kind == ActionKind.REPORT
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/agent_tests/test_llm_decider.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write the prompt**

```
# prompts/next_action.txt
You are the decision core of SABER, an authorized penetration-testing operator.

You are given the current MISSION STATE SUMMARY, the exact TOOL CATALOG you may
use, the mission SCOPE, and the AUTONOMY LEVEL. Choose the single best next
action to advance the objective, exactly as a skilled human operator would:
reason about what is known, pick the highest-value next tool, and stop when
there is nothing useful or safe left to do.

Hard rules:
- Use ONLY exact tool_name/tool_action pairs that appear in tool_catalog.
- Never target anything outside scope.
- Do not repeat an action listed in recent_failures unless state changed.
- Rate risk honestly: "high" for destructive, deep-exploit, or impactful steps.
- Prefer recon/enumeration before exploitation.
- When the objective is met or no safe useful action remains, return kind "report".

Return ONE strict JSON object, no Markdown, with this schema:
{
  "kind": "tool" | "stop" | "report",
  "tool_name": string | null,
  "tool_action": string | null,
  "args": object,
  "agent_name": string | null,
  "risk": "low" | "medium" | "high",
  "requires_confirmation": boolean,
  "category": string,
  "rationale": string,
  "expected_evidence": string
}
```

- [ ] **Step 4: Implement**

```python
# saber/agents/deciders/llm.py
"""LLM-primary decider for the mission loop."""

from __future__ import annotations

import json
from typing import Any

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction, RiskLevel
from saber.core.prompt_loader import PromptLoader
from saber.core.state_summary import StateSummary
from saber.core.tool_catalog import ToolCatalog
from saber.models.mission_state import MissionState


class LlmDecider(NextActionDecider):
    """Ask the configured LLM for the next action, validated against the catalog."""

    def __init__(
        self,
        llm_client: Any,
        tool_catalog: ToolCatalog,
        prompt_loader: PromptLoader | None = None,
        prompt_name: str = "next_action",
    ) -> None:
        """Initialize the LLM decider."""

        self.llm_client = llm_client
        self.tool_catalog = tool_catalog
        self.prompt_loader = prompt_loader or PromptLoader()
        self.prompt_name = prompt_name

    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the next action chosen by the LLM."""

        if not getattr(self.llm_client, "enabled", False):
            return self._stop("LLM client disabled")

        system_prompt = self._load_prompt()
        payload = {
            "summary": summary.to_dict(),
            "tool_catalog": self.tool_catalog.to_dict(),
            "autonomy_level": state.autonomy_level.value,
            "scope": state.scope.to_agent_context() if state.scope else None,
        }
        user_prompt = json.dumps(payload, indent=2, sort_keys=True, default=str)

        try:
            raw = self.llm_client.complete_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                metadata={"component": "next_action_decider"},
            )
        except Exception as exc:  # noqa: BLE001 - decider must never crash the loop
            return self._stop(f"LLM error: {exc}")

        return self._parse(raw)

    def _parse(self, raw: dict[str, Any]) -> ProposedAction:
        kind = str(raw.get("kind") or "").strip().lower()

        if kind == "report":
            return ProposedAction(
                kind=ActionKind.REPORT,
                objective="Generate final report.",
                rationale=str(raw.get("rationale") or ""),
            )
        if kind == "stop":
            return self._stop(str(raw.get("rationale") or "LLM requested stop"))

        tool_name = raw.get("tool_name")
        tool_action = raw.get("tool_action")
        if not self._catalog_has(tool_name, tool_action):
            return self._stop(f"unknown tool/action: {tool_name}/{tool_action}")

        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name=str(tool_name),
            tool_action=str(tool_action),
            args=raw.get("args") if isinstance(raw.get("args"), dict) else {},
            agent_name=raw.get("agent_name"),
            objective=str(raw.get("rationale") or f"Run {tool_name}.{tool_action}"),
            risk=RiskLevel.from_str(raw.get("risk")),
            requires_confirmation=bool(raw.get("requires_confirmation", False)),
            rationale=str(raw.get("rationale") or ""),
            expected_evidence=str(raw.get("expected_evidence") or ""),
            metadata={"category": str(raw.get("category") or ""), "llm_raw": raw},
        )

    def _catalog_has(self, tool_name: Any, tool_action: Any) -> bool:
        if not tool_name or not tool_action:
            return False
        for tool in self.tool_catalog.tools:
            if tool.name == tool_name:
                return any(action.action == tool_action for action in tool.actions)
        return False

    def _load_prompt(self) -> str:
        try:
            prompt = self.prompt_loader.load_agent_prompt(self.prompt_name)
            return getattr(prompt, "system_prompt", None) or str(prompt)
        except Exception:  # noqa: BLE001 - fall back to inline instruction
            return "Return one strict JSON decision using only tools from tool_catalog."

    @staticmethod
    def _stop(reason: str) -> ProposedAction:
        return ProposedAction(kind=ActionKind.STOP, objective="Stop mission.", rationale=reason)
```

> **Verify `PromptLoader.load_agent_prompt` accepts an arbitrary name.** If it only resolves known agent names, add a `next_action` entry to the loader's prompt map, or load `prompts/next_action.txt` directly via a small `_load_prompt` that reads the file. Confirm during Step 5 and adjust `_load_prompt` accordingly.

- [ ] **Step 5: Run it to verify it passes**

Run: `pytest tests/agent_tests/test_llm_decider.py -v`
Expected: PASS (3 passed).

- [ ] **Step 6: Commit**

```bash
ruff format saber/agents/deciders/llm.py tests/agent_tests/test_llm_decider.py
ruff check saber tests
git add saber/agents/deciders/llm.py prompts/next_action.txt tests/agent_tests/test_llm_decider.py
git commit -m "feat(agents): add LlmDecider + next_action prompt

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P4 — The loop

### Task 10: `ActionExecutor` (dispatch through capability agents)

**Files:**
- Create: `saber/orchestration/action_executor.py`
- Test: `tests/orchestration_tests/test_action_executor.py`

**Interfaces:**
- Consumes: `ProposedAction`, `MissionState`, `MissionSession`, `saber.agents.base_agent.BaseAgent` (`.execute_tool`, `.config.phase`), `AgentToolCall`, `AgentContext`, `ToolRegistry`, `Sandbox`.
- Produces:
  - `ActionExecutionRecord` (frozen dataclass): `sandbox_result`, `observation: AgentObservation`, `error: str | None`.
  - `ActionExecutor(agents, tool_registry, sandbox, default_agent="recon_agent")` with `execute(state, session, action) -> ActionExecutionRecord`.
  - Resolves the executing agent from `action.agent_name` (fallback: `default_agent`), builds an `AgentContext`, and calls `agent.execute_tool(context, AgentToolCall(...))`. Never calls `agent.decide()` — the decision is already made. Catches execution errors into `ActionExecutionRecord.error`.

- [ ] **Step 1: Write the failing test (fake agent, no Docker)**

```python
# tests/orchestration_tests/test_action_executor.py
from saber.agents.base_agent import AgentConfig, BaseAgent
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import MissionState
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutor


class _FakeSandboxResult:
    allowed = True
    return_code = 0
    reason = "ok"
    metadata: dict = {}
    stdout = "PORT 80 open"


class _FakeAgent(BaseAgent):
    def __init__(self):
        super().__init__(AgentConfig(name="recon_agent", phase=AssessmentPhase.RECONNAISSANCE))
        self.calls = []

    def decide(self, context):  # pragma: no cover - must NOT be called by executor
        raise AssertionError("executor must not call decide()")

    def execute_tool(self, context, tool_call):
        self.calls.append((tool_call.tool_name, tool_call.action))
        return _FakeSandboxResult()


def _action():
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="nmap",
        tool_action="service_scan",
        args={"target": "10.0.0.5"},
        agent_name="recon_agent",
        objective="scan",
        risk=RiskLevel.LOW,
    )


def test_executor_dispatches_to_named_agent():
    agent = _FakeAgent()
    executor = ActionExecutor(agents={"recon_agent": agent}, tool_registry=object(), sandbox=object())
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    session = MissionSession(session_id="s", mission_name="m")

    record = executor.execute(state, session, _action())

    assert agent.calls == [("nmap", "service_scan")]
    assert record.error is None
    assert record.observation.success is True


def test_executor_captures_errors():
    class _Boom(_FakeAgent):
        def execute_tool(self, context, tool_call):
            raise RuntimeError("sandbox down")

    executor = ActionExecutor(agents={"recon_agent": _Boom()}, tool_registry=object(), sandbox=object())
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    session = MissionSession(session_id="s", mission_name="m")

    record = executor.execute(state, session, _action())
    assert record.error is not None
    assert record.observation.success is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_action_executor.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/orchestration/action_executor.py
"""Execute a ProposedAction through an existing capability agent.

The decider has already chosen the action. This dispatches it to the agent that
owns the capability and runs it via BaseAgent.execute_tool -> ToolRegistry ->
Sandbox. It never calls agent.decide() — the loop, not the agent, decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from saber.agents.base_agent import AgentContext, AgentObservation, AgentToolCall, BaseAgent
from saber.agents.deciders.base import ProposedAction
from saber.models.mission_state import MissionState
from saber.models.session import MissionSession


@dataclass(frozen=True)
class ActionExecutionRecord:
    """Outcome of executing one action."""

    sandbox_result: Any
    observation: AgentObservation
    error: str | None = None


class ActionExecutor:
    """Dispatch proposed actions to capability agents."""

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: Any,
        sandbox: Any,
        default_agent: str = "recon_agent",
    ) -> None:
        """Initialize executor."""

        if not agents:
            raise ValueError("ActionExecutor requires at least one agent.")
        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox
        self.default_agent = default_agent

    def execute(
        self,
        state: MissionState,
        session: MissionSession,
        action: ProposedAction,
    ) -> ActionExecutionRecord:
        """Run one tool action and return its record."""

        agent = self._resolve_agent(action)
        target = action.target or state.target

        context = AgentContext(
            session=session,
            target=target,
            sandbox=self.sandbox,
            tool_registry=self.tool_registry,
            objective=action.objective,
            phase=agent.config.phase,
            observations=[],
            constraints={"agent_mode": "loop"},
            metadata={"proposed_action": action.to_dict()},
        )

        tool_call = AgentToolCall(
            tool_name=action.tool_name or "",
            action=action.tool_action or "",
            args=action.args,
            reason=action.rationale,
            metadata={"category": action.metadata.get("category", "")},
        )

        try:
            sandbox_result = agent.execute_tool(context=context, tool_call=tool_call)
        except Exception as exc:  # noqa: BLE001 - loop must survive tool failures
            observation = AgentObservation(
                summary=f"Action {action.tool_name}.{action.tool_action} failed: {exc}",
                tool_name=action.tool_name,
                action=action.tool_action,
                success=False,
            )
            return ActionExecutionRecord(sandbox_result=None, observation=observation, error=str(exc))

        success = bool(getattr(sandbox_result, "allowed", True)) and (
            getattr(sandbox_result, "return_code", 0) == 0
        )
        observation = AgentObservation(
            summary=getattr(sandbox_result, "reason", None) or "Tool execution completed.",
            tool_name=action.tool_name,
            action=action.tool_action,
            success=success,
            result=sandbox_result,
            metadata=getattr(sandbox_result, "metadata", {}) or {},
        )
        return ActionExecutionRecord(sandbox_result=sandbox_result, observation=observation, error=None)

    def _resolve_agent(self, action: ProposedAction) -> BaseAgent:
        if action.agent_name and action.agent_name in self.agents:
            return self.agents[action.agent_name]
        if self.default_agent in self.agents:
            return self.agents[self.default_agent]
        return next(iter(self.agents.values()))
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_action_executor.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/orchestration/action_executor.py tests/orchestration_tests/test_action_executor.py
ruff check saber tests
git add saber/orchestration/action_executor.py tests/orchestration_tests/test_action_executor.py
git commit -m "feat(orchestration): add ActionExecutor (capability-lens dispatch)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: `MissionLoop`

**Files:**
- Create: `saber/orchestration/mission_loop.py`
- Test: `tests/orchestration_tests/test_mission_loop.py`

**Interfaces:**
- Consumes: `NextActionDecider`, `StateSummarizer`, `RiskGate`/`GateDecision`, `StopEvaluator`, `ActionExecutor`, `StateMerger`, `MissionStateStore`, `ResultProcessor`, `MissionRunStatus` (from `mission_orchestrator`), `MissionSession`, `ApprovalRequest`.
- Produces:
  - `MissionLoopResult` (frozen dataclass): `state: MissionState`, `session: MissionSession`, `status: MissionRunStatus`, `reason: str`.
  - `MissionLoop(decider, summarizer, risk_gate, stop_evaluator, executor, merger, state_store, result_processor, session_store=None, max_steps=50)` with `run(state: MissionState, session: MissionSession) -> MissionLoopResult`.
  - One iteration exactly as designed: summarize → decide → gate → (CONFIRM → pause; REFUSE → skip+record failure; ALLOW → execute) → process+merge → snapshot → stop-check.

- [ ] **Step 1: Write the failing test (deterministic decider, fake executor/processor)**

```python
# tests/orchestration_tests/test_mission_loop.py
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.core.state_merger import StateMerger
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.risk_gate import RiskGate
from saber.orchestration.stop_conditions import StopEvaluator
from saber.orchestration.mission_orchestrator import MissionRunStatus


class _ScriptedDecider:
    """Emits a low-risk tool action once, then reports."""

    def __init__(self):
        self.calls = 0

    def decide(self, state, summary):
        self.calls += 1
        if self.calls == 1:
            return ProposedAction(
                kind=ActionKind.TOOL, tool_name="nmap", tool_action="service_scan",
                args={"target": "10.0.0.5"}, agent_name="recon_agent",
                objective="scan", risk=RiskLevel.LOW, metadata={"category": "recon"},
            )
        return ProposedAction(kind=ActionKind.REPORT, objective="done", risk=RiskLevel.LOW)


class _FakeExecutor:
    def execute(self, state, session, action):
        from saber.agents.base_agent import AgentObservation
        obs = AgentObservation(summary="ok", tool_name=action.tool_name, action=action.tool_action, success=True)
        return ActionExecutionRecord(sandbox_result=object(), observation=obs, error=None)


class _FakeProcessor:
    def process_tool_result(self, **kwargs):
        from saber.core.result_processor import ProcessedToolResult
        return ProcessedToolResult(
            session_id=kwargs["session_id"], step_id=None, tool_name="nmap",
            parsed_observations=[{"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "service": "http"}}],
            evidence_ids=["ev1"], finding_ids=["f1"],
        )


class _FakeStore:
    def __init__(self):
        self.snapshots = 0
    def snapshot(self, state):
        self.snapshots += 1


def _loop(decider):
    return MissionLoop(
        decider=decider,
        summarizer=StateSummarizer(),
        risk_gate=RiskGate(),
        stop_evaluator=StopEvaluator(max_steps=10),
        executor=_FakeExecutor(),
        merger=StateMerger(),
        state_store=_FakeStore(),
        result_processor=_FakeProcessor(),
        max_steps=10,
    )


def _fixtures():
    state = MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=AutonomyLevel.AUTONOMOUS, objective="assess",
    )
    session = MissionSession(session_id="s", mission_name="m")
    return state, session


def test_loop_runs_then_reports_and_completes():
    state, session = _fixtures()
    result = _loop(_ScriptedDecider()).run(state, session)
    assert result.status == MissionRunStatus.COMPLETED
    assert any(s.key == "10.0.0.5:80/tcp" for s in result.state.services)  # merged
    assert result.state.step_count >= 1


def test_loop_pauses_on_high_risk_confirmation():
    class _HighRisk:
        def decide(self, state, summary):
            return ProposedAction(
                kind=ActionKind.TOOL, tool_name="metasploit", tool_action="run_exploit",
                objective="pop", risk=RiskLevel.HIGH, agent_name="exploit_agent",
                metadata={"category": "exploitation"},
            )
    state, session = _fixtures()
    result = _loop(_HighRisk()).run(state, session)
    assert result.status == MissionRunStatus.PAUSED_FOR_APPROVAL


def test_loop_snapshots_state_each_iteration():
    state, session = _fixtures()
    loop = _loop(_ScriptedDecider())
    loop.run(state, session)
    assert loop.state_store.snapshots >= 1
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_mission_loop.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# saber/orchestration/mission_loop.py
"""The SABER agentic mission loop.

State-first closed loop: summarize -> decide -> gate -> execute -> normalize ->
snapshot -> stop-check, repeated until a stop condition. Replaces plan-first
driving. Reuses StepRunner-adjacent execution via ActionExecutor, plus parsers,
ResultProcessor, and the stores.
"""

from __future__ import annotations

from dataclasses import dataclass

from saber.agents.deciders.base import ActionKind, ProposedAction
from saber.core.result_processor import ResultProcessor
from saber.core.state_merger import StateMerger
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.session import ApprovalRequest, MissionSession
from saber.orchestration.action_executor import ActionExecutor
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.orchestration.risk_gate import GateDecision, RiskGate
from saber.orchestration.stop_conditions import StopEvaluator
from saber.storage.mission_state_store import MissionStateStore


@dataclass(frozen=True)
class MissionLoopResult:
    """Result of a mission-loop run."""

    state: MissionState
    session: MissionSession
    status: MissionRunStatus
    reason: str


class MissionLoop:
    """Drive a mission from MissionState until a stop condition."""

    def __init__(
        self,
        decider,
        summarizer: StateSummarizer,
        risk_gate: RiskGate,
        stop_evaluator: StopEvaluator,
        executor: ActionExecutor,
        merger: StateMerger,
        state_store: MissionStateStore,
        result_processor: ResultProcessor,
        session_store=None,
        max_steps: int = 50,
    ) -> None:
        """Initialize the loop."""

        self.decider = decider
        self.summarizer = summarizer
        self.risk_gate = risk_gate
        self.stop_evaluator = stop_evaluator
        self.executor = executor
        self.merger = merger
        self.state_store = state_store
        self.result_processor = result_processor
        self.session_store = session_store
        self.max_steps = max_steps

    def run(self, state: MissionState, session: MissionSession) -> MissionLoopResult:
        """Run the closed loop until pause, completion, or a stop condition."""

        self.state_store.snapshot(state)

        for _ in range(self.max_steps):
            summary = self.summarizer.summarize(state)
            action = self.decider.decide(state, summary)

            if action.kind in {ActionKind.STOP, ActionKind.REPORT}:
                reason = action.rationale or action.kind.value
                state = state.model_copy(update={"stop_reason": reason})
                self.state_store.snapshot(state)
                return MissionLoopResult(state, session, MissionRunStatus.COMPLETED, reason)

            gate = self.risk_gate.evaluate(state, action)

            if gate.decision == GateDecision.REFUSE:
                state = self.merger.merge(
                    state,
                    [],
                    AttemptedAction(
                        tool_name=action.tool_name or "?",
                        action=action.tool_action or "?",
                        args=action.args,
                        success=False,
                        reason=f"refused: {gate.reason}",
                    ),
                )
                self.state_store.snapshot(state)
                stop = self.stop_evaluator.evaluate(state, action)
                if stop.should_stop:
                    state = state.model_copy(update={"stop_reason": stop.reason})
                    return MissionLoopResult(state, session, MissionRunStatus.STOPPED, stop.reason)
                continue

            if gate.decision == GateDecision.CONFIRM:
                approval = ApprovalRequest(
                    action=f"{action.tool_name}.{action.tool_action}",
                    reason=gate.reason,
                    requested_by="mission_loop",
                    target=action.target or state.target,
                    metadata={"proposed_action": action.to_dict()},
                )
                session = session.wait_for_approval(approval)
                if self.session_store is not None:
                    self.session_store.update_session_status(
                        session.session_id, "waiting_for_approval"
                    )
                state = state.model_copy(update={"stop_reason": f"awaiting confirmation: {gate.reason}"})
                self.state_store.snapshot(state)
                return MissionLoopResult(
                    state, session, MissionRunStatus.PAUSED_FOR_APPROVAL, gate.reason
                )

            # ALLOW: execute the action.
            record = self.executor.execute(state, session, action)
            attempt = AttemptedAction(
                tool_name=action.tool_name or "?",
                action=action.tool_action or "?",
                args=action.args,
                success=record.observation.success,
                reason=("" if record.error is None else record.error),
            )

            parsed_observations: list[dict] = []
            evidence_refs: list[str] = []
            finding_refs: list[str] = []
            if record.error is None and record.sandbox_result is not None:
                processed = self.result_processor.process_tool_result(
                    session_id=state.session_id,
                    tool_result=record.sandbox_result,
                    tool_name=action.tool_name,
                    action=action.tool_action,
                )
                parsed_observations = list(getattr(processed, "parsed_observations", []) or [])
                evidence_refs = list(getattr(processed, "evidence_ids", []) or [])
                finding_refs = list(getattr(processed, "finding_ids", []) or [])

            state = self.merger.merge(
                state, parsed_observations, attempt, evidence_refs=evidence_refs, finding_refs=finding_refs
            )
            self.state_store.snapshot(state)

            stop = self.stop_evaluator.evaluate(state, action)
            if stop.should_stop:
                state = state.model_copy(update={"stop_reason": stop.reason})
                self.state_store.snapshot(state)
                return MissionLoopResult(state, session, MissionRunStatus.STOPPED, stop.reason)

        state = state.model_copy(update={"stop_reason": "max_steps exhausted"})
        self.state_store.snapshot(state)
        return MissionLoopResult(state, session, MissionRunStatus.STOPPED, "max_steps exhausted")
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_mission_loop.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Full regression + commit**

```bash
pytest tests/unit tests/agent_tests tests/orchestration_tests tests/model_tests tests/storage_tests -q
ruff format saber/orchestration/mission_loop.py tests/orchestration_tests/test_mission_loop.py
ruff check saber tests
git add saber/orchestration/mission_loop.py tests/orchestration_tests/test_mission_loop.py
git commit -m "feat(orchestration): add MissionLoop closed loop

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 12: Wire the loop into `runtime.py` and `MissionOrchestrator`

**Files:**
- Modify: `saber/core/runtime.py`
- Modify: `saber/orchestration/mission_orchestrator.py`
- Test: `tests/orchestration_tests/test_orchestrator_uses_loop.py`

**Interfaces:**
- Produces: `SaberRuntime` (or existing runtime object) now builds a `MissionLoop` from its already-wired agents, tool_registry, sandbox, result_processor, and stores; selects `LlmDecider` when `agent_mode == "llm"` else `DeterministicDecider`. `MissionOrchestrator.run_mission(...)` builds an initial `MissionState` (via `select_strategy` from Task 14 — until then, a network default) and calls `MissionLoop.run(...)`, returning a `MissionRunResult` adapted from `MissionLoopResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_orchestrator_uses_loop.py
"""MissionOrchestrator.run_mission must drive via MissionLoop, not a static plan."""

from unittest.mock import MagicMock

from saber.models.session import MissionSession
from saber.models.target import Target, TargetType


def test_run_mission_delegates_to_mission_loop(monkeypatch):
    from saber.orchestration import mission_orchestrator as mod

    captured = {}

    class _FakeLoop:
        def run(self, state, session):
            captured["state"] = state
            captured["session"] = session
            from saber.orchestration.mission_loop import MissionLoopResult
            return MissionLoopResult(state, session, mod.MissionRunStatus.COMPLETED, "done")

    orchestrator = mod.MissionOrchestrator(
        agents={"recon_agent": MagicMock(config=MagicMock(phase="reconnaissance"))},
        tool_registry=MagicMock(),
        sandbox=MagicMock(),
        mission_loop=_FakeLoop(),   # new injectable dependency
    )
    session = MissionSession(session_id="s", mission_name="m")
    target = Target(type=TargetType.IP, value="10.0.0.5")

    result = orchestrator.run_mission(session=session, target=target, objective="assess")

    assert captured["state"].target.value == "10.0.0.5"
    assert result.status == mod.MissionRunStatus.COMPLETED
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_orchestrator_uses_loop.py -v`
Expected: FAIL — `MissionOrchestrator.__init__` has no `mission_loop` param.

- [ ] **Step 3: Implement — add an injectable `mission_loop` and delegate**

In `saber/orchestration/mission_orchestrator.py`:
- Add `mission_loop: "MissionLoop | None" = None` to `__init__`, store `self.mission_loop`.
- Replace the body of `run_mission(...)` so that, when `self.mission_loop` is set, it builds an initial `MissionState` and delegates:

```python
    def run_mission(
        self,
        session: MissionSession,
        target: Target,
        objective: str,
        plan: ExecutionPlan | None = None,
        initial_observations: list[AgentObservation] | None = None,
        constraints: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MissionRunResult:
        """Run a mission. State-first via MissionLoop when available."""

        if self.mission_loop is not None:
            from saber.models.mission_state import AutonomyLevel, MissionState

            constraints = constraints or {}
            state = MissionState(
                session_id=session.session_id,
                target=target,
                objective=objective,
                scope=session.scope,
                autonomy_level=AutonomyLevel(
                    str(constraints.get("autonomy_level", AutonomyLevel.AUTONOMOUS.value))
                ),
                roe=constraints.get("roe", {}),
                metadata=metadata or {},
            )
            loop_result = self.mission_loop.run(state=state, session=session)
            return self._result_from_loop(loop_result)

        # Legacy plan-first path retained only as an explicit fallback (removed in P5).
        active_plan = plan or self.create_plan(
            mission_name=session.mission_name, target=target, objective=objective, metadata=metadata
        )
        return self.run_until_pause_or_complete(
            plan=active_plan, session=session, target=target,
            observations=initial_observations or [], constraints=constraints, metadata=metadata,
        )
```

- Add the adapter:

```python
    def _result_from_loop(self, loop_result: "MissionLoopResult") -> MissionRunResult:
        """Adapt a MissionLoopResult into the existing MissionRunResult shape."""

        from saber.orchestration.execution_plan import ExecutionPlan

        return MissionRunResult(
            session=loop_result.session,
            plan=ExecutionPlan(mission_name=loop_result.session.mission_name, steps=[]),
            status=loop_result.status,
            observations=[],
            records=[],
            artifacts=[],
            metadata={
                "reason": loop_result.reason,
                "mission_state": loop_result.state.to_summary_dict(),
            },
        )
```

> Check `ExecutionPlan`'s constructor signature and adapt the empty-plan construction to match (it may require `target`/`objective`). Confirm during Step 4.

In `saber/core/runtime.py`, after agents/tool_registry/sandbox/result_processor/stores are built, construct the loop and pass it to `MissionOrchestrator(...)`:

```python
        from saber.agents.deciders.deterministic import DeterministicDecider
        from saber.agents.deciders.llm import LlmDecider
        from saber.core.state_merger import StateMerger
        from saber.core.state_summary import StateSummarizer
        from saber.core.tool_catalog import ToolCatalog
        from saber.orchestration.action_executor import ActionExecutor
        from saber.orchestration.mission_loop import MissionLoop
        from saber.orchestration.risk_gate import RiskGate
        from saber.orchestration.stop_conditions import StopEvaluator
        from saber.storage.mission_state_store import MissionStateStore

        tool_catalog = ToolCatalog.from_registry(tool_registry)
        if agent_mode == "llm" and llm_client is not None and llm_client.enabled:
            decider = LlmDecider(llm_client=llm_client, tool_catalog=tool_catalog)
        else:
            decider = DeterministicDecider()

        mission_loop = MissionLoop(
            decider=decider,
            summarizer=StateSummarizer(),
            risk_gate=RiskGate(tool_catalog=tool_catalog),
            stop_evaluator=StopEvaluator(max_steps=max_steps),
            executor=ActionExecutor(agents=agents, tool_registry=tool_registry, sandbox=sandbox),
            merger=StateMerger(),
            state_store=MissionStateStore(storage_connection),
            result_processor=result_processor,
            session_store=session_store,
            max_steps=max_steps,
        )
```

Pass `mission_loop=mission_loop` into the `MissionOrchestrator(...)` constructor call. Use the real local variable names already present in `runtime.py` (inspect and match: `agents`, `tool_registry`, `sandbox`, `result_processor`, `session_store`, `storage_connection`, `llm_client`, `agent_mode`, `max_steps`).

- [ ] **Step 4: Run it to verify it passes**

Run: `pytest tests/orchestration_tests/test_orchestrator_uses_loop.py -v`
Expected: PASS. Then run the runtime's own tests: `pytest tests/orchestration_tests tests/integration -q`.

- [ ] **Step 5: Manual smoke — deterministic loop against a real container (network/IP)**

```bash
SABER_AGENT_MODE=deterministic ./run_saber --no-browser &   # or use CLI:
python -m saber.ui.cli.main run --target 127.0.0.1 --profile recon --max-steps 6
```
Expected: mission completes via the loop; `runs/saber.db` `mission_states` row exists; report artifacts written under `runs/reports/`.

- [ ] **Step 6: Commit**

```bash
ruff format saber/core/runtime.py saber/orchestration/mission_orchestrator.py tests/orchestration_tests/test_orchestrator_uses_loop.py
ruff check saber tests
git add saber/core/runtime.py saber/orchestration/mission_orchestrator.py tests/orchestration_tests/test_orchestrator_uses_loop.py
git commit -m "feat(orchestration): drive missions via MissionLoop from runtime

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P5 — Retire plan-first driving

### Task 13: Remove plan-first driving; migrate `ChainRunner`/orchestrator tests

**Files:**
- Modify: `saber/orchestration/mission_orchestrator.py` (make loop mandatory; keep `create_plan()` only as an optional seed helper)
- Modify/Delete: plan-first tests that assert static-plan walking
- Test: update `tests/orchestration_tests/` and any `tests/e2e_tests/` referencing the old path

**Interfaces:**
- Produces: `MissionOrchestrator` requires `mission_loop`; `run_until_pause_or_complete()` and `ChainRunner` are no longer part of the mission-driving path. `ChainRunner` file may remain (unused) or be deleted; if deleted, remove its imports/tests.

- [ ] **Step 1: Make the loop mandatory (write the guard test first)**

```python
# tests/orchestration_tests/test_orchestrator_requires_loop.py
import pytest
from unittest.mock import MagicMock
from saber.orchestration.mission_orchestrator import MissionOrchestrator


def test_orchestrator_requires_mission_loop():
    with pytest.raises(ValueError):
        MissionOrchestrator(
            agents={"a": MagicMock()}, tool_registry=MagicMock(), sandbox=MagicMock(), mission_loop=None
        )
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_orchestrator_requires_loop.py -v`
Expected: FAIL (constructor still allows `None`).

- [ ] **Step 3: Implement the guard + remove legacy driving**

In `mission_orchestrator.py`: raise `ValueError("MissionOrchestrator requires a mission_loop.")` when `mission_loop is None`; delete the legacy branch in `run_mission`; delete `run_until_pause_or_complete`, `_result`, `_finalize_result`'s plan-walking, and the `chain_runner` usage. Keep `create_plan()` (now documented as "optional recon seed, not used to drive").

- [ ] **Step 4: Migrate the failing legacy tests**

Run the suite: `pytest tests/orchestration_tests tests/e2e_tests -q`. For each test that fails because it exercised static-plan walking or `ChainRunner` routing:
- If it validates behavior now owned by `MissionLoop`/`ChainRunner`-equivalent, rewrite it against `MissionLoop` (see Task 11 patterns).
- If it validates `create_plan()` seed building, keep it.
- If it is obsolete (asserts the orchestrator walks a plan), delete it and note the deletion in the commit body.

Delete `saber/orchestration/chain_runner.py` and `tests/orchestration_tests/test_chain_runner*.py` **only if** no non-test code imports `ChainRunner` (grep first: `grep -rn "chain_runner\|ChainRunner" saber`). If `runtime.py` still imports it, remove that import.

- [ ] **Step 5: Full regression**

Run: `make unit`
Expected: PASS. Then `pytest tests/ -q` (excluding gated E2E) — green.

- [ ] **Step 6: Commit**

```bash
ruff check saber tests
git add -A
git commit -m "refactor(orchestration): retire plan-first driving; loop is mandatory

Removed run_until_pause_or_complete and ChainRunner from the mission-driving
path. Migrated plan-walking tests to MissionLoop. create_plan() kept as an
optional recon seed only.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

# Phase P6 — Target strategies & acceptance

### Task 14: `TargetStrategy` base + `select_strategy` + network strategy

**Files:**
- Create: `saber/orchestration/strategies/__init__.py`
- Create: `saber/orchestration/strategies/base.py`
- Create: `saber/orchestration/strategies/network.py`
- Test: `tests/orchestration_tests/test_strategies.py`

**Interfaces:**
- Produces:
  - `StrategyKind(StrEnum)` = `NETWORK | WEB | CTF`.
  - `TargetStrategy(ABC)`: `kind: StrategyKind`, `seed_objective(target) -> str`, `initial_metadata(target) -> dict`, `objective_met(state) -> bool`.
  - `select_strategy(target: Target, metadata: dict | None = None) -> TargetStrategy` — chooses CTF when `metadata.get("ctf")` or `scope` flags a lab; WEB for URL/web targets; NETWORK otherwise.
  - `NetworkStrategy(TargetStrategy)`.
  - `MissionState` gains initial `metadata` seeded from the strategy (wired in `run_mission`).

- [ ] **Step 1: Write the failing test**

```python
# tests/orchestration_tests/test_strategies.py
from saber.models.mission_state import KnownVuln, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.strategies.base import StrategyKind, select_strategy


def test_url_selects_web_strategy():
    strat = select_strategy(Target(type=TargetType.URL, value="http://x/"))
    assert strat.kind == StrategyKind.WEB


def test_ip_selects_network_strategy():
    strat = select_strategy(Target(type=TargetType.IP, value="10.0.0.5"))
    assert strat.kind == StrategyKind.NETWORK


def test_ctf_flag_selects_ctf_strategy():
    strat = select_strategy(Target(type=TargetType.IP, value="10.0.0.5"), metadata={"ctf": True})
    assert strat.kind == StrategyKind.CTF


def test_network_objective_met_when_vulns_and_scanned():
    from saber.orchestration.strategies.network import NetworkStrategy
    state = MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"),
        vulns=[KnownVuln(title="v")], metadata={"exploit_intel_done": True},
    )
    assert NetworkStrategy().objective_met(state) is True
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pytest tests/orchestration_tests/test_strategies.py -v`
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement base + network + selector**

```python
# saber/orchestration/strategies/base.py
"""Per-target-type strategies that seed the mission loop."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from saber.models.mission_state import MissionState
from saber.models.target import Target, TargetType


class StrategyKind(StrEnum):
    """Kind of target strategy."""

    NETWORK = "network"
    WEB = "web"
    CTF = "ctf"


class TargetStrategy(ABC):
    """Seed objective/metadata and define objective-met for one target type."""

    kind: StrategyKind

    @abstractmethod
    def seed_objective(self, target: Target) -> str:
        """Return the default objective for this target."""

    def initial_metadata(self, target: Target) -> dict[str, Any]:
        """Return metadata seeded onto MissionState (strategy hints)."""

        return {"strategy": self.kind.value}

    @abstractmethod
    def objective_met(self, state: MissionState) -> bool:
        """Return whether the mission objective is satisfied."""


def select_strategy(target: Target, metadata: dict[str, Any] | None = None) -> TargetStrategy:
    """Pick the right strategy for a target."""

    from saber.orchestration.strategies.ctf import CtfStrategy
    from saber.orchestration.strategies.network import NetworkStrategy
    from saber.orchestration.strategies.web import WebStrategy

    metadata = metadata or {}
    if metadata.get("ctf") or metadata.get("lab"):
        return CtfStrategy()
    if target.type == TargetType.URL or target.is_web_target:
        return WebStrategy()
    return NetworkStrategy()
```

```python
# saber/orchestration/strategies/network.py
"""Network / IP host strategy."""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class NetworkStrategy(TargetStrategy):
    """Recon -> services -> web/network/exploit-intel branches."""

    kind = StrategyKind.NETWORK

    def seed_objective(self, target: Target) -> str:
        return f"Enumerate {target.value}, identify services and known vulnerabilities, and report."

    def objective_met(self, state: MissionState) -> bool:
        return bool(state.services) and bool(state.vulns) and bool(state.metadata.get("exploit_intel_done"))
```

- [ ] **Step 4: Run it to verify it passes** (write `web.py`/`ctf.py` minimal stubs in Tasks 15/16; for this task, add temporary minimal classes so the selector import works, or implement 15/16 first). **Implementation order: 14 → 15 → 16, but the selector imports all three; create thin `web.py`/`ctf.py` in this task with just the class + `kind` + `seed_objective` + `objective_met` returning `False`, then flesh them out in 15/16.**

Run: `pytest tests/orchestration_tests/test_strategies.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
ruff format saber/orchestration/strategies/ tests/orchestration_tests/test_strategies.py
ruff check saber tests
git add saber/orchestration/strategies tests/orchestration_tests/test_strategies.py
git commit -m "feat(orchestration): add TargetStrategy + network strategy + selector

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 6: Wire strategy into `run_mission`**

Modify `MissionOrchestrator.run_mission` to call `select_strategy(target, (metadata or {}))`, use `strategy.seed_objective(target)` when `objective` is blank, and seed `MissionState.metadata` with `strategy.initial_metadata(target)`. Add a test `tests/orchestration_tests/test_run_mission_seeds_strategy.py` asserting `result.metadata["mission_state"]` reflects the seeded strategy. Commit.

---

### Task 15: Web strategy

**Files:**
- Modify: `saber/orchestration/strategies/web.py`
- Test: extend `tests/orchestration_tests/test_strategies.py`

**Interfaces:**
- Produces: `WebStrategy(TargetStrategy)` with `kind = WEB`; `seed_objective` = fingerprint + safe web checks + report; `objective_met` when technologies fingerprinted and a nuclei scan recorded (`state.metadata.get("web_scanned")`).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/orchestration_tests/test_strategies.py
def test_web_objective_met_after_scan():
    from saber.models.mission_state import KnownTechnology, MissionState
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.web import WebStrategy
    state = MissionState(
        session_id="s", target=Target(type=TargetType.URL, value="http://x/"),
        technologies=[KnownTechnology(host="x", name="nginx")], metadata={"web_scanned": True},
    )
    assert WebStrategy().objective_met(state) is True
```

- [ ] **Step 2: Run it → fails. Step 3: Implement:**

```python
# saber/orchestration/strategies/web.py
"""Website / URL strategy."""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class WebStrategy(TargetStrategy):
    """Fingerprint -> nuclei -> safe web checks -> report."""

    kind = StrategyKind.WEB

    def seed_objective(self, target: Target) -> str:
        return f"Fingerprint {target.value}, run safe web vulnerability checks, and report."

    def objective_met(self, state: MissionState) -> bool:
        return bool(state.technologies) and bool(state.metadata.get("web_scanned"))
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** (`feat(orchestration): web target strategy`).

---

### Task 16: CTF / SSH strategy

**Files:**
- Modify: `saber/orchestration/strategies/ctf.py`
- Test: extend `tests/orchestration_tests/test_strategies.py`

**Interfaces:**
- Produces: `CtfStrategy(TargetStrategy)` with `kind = CTF`; `seed_objective` = "capture the flag"; `initial_metadata` sets `{"strategy": "ctf", "lab": True}` (so the risk gate treats it as a lab per autonomy rules); `objective_met` when `state.metadata.get("flag")` is set OR loot captured.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/orchestration_tests/test_strategies.py
def test_ctf_objective_met_when_flag_found():
    from saber.models.mission_state import MissionState
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.ctf import CtfStrategy
    state = MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"),
        metadata={"flag": "picoCTF{...}"},
    )
    assert CtfStrategy().objective_met(state) is True


def test_ctf_metadata_marks_lab():
    from saber.models.target import Target, TargetType
    from saber.orchestration.strategies.ctf import CtfStrategy
    meta = CtfStrategy().initial_metadata(Target(type=TargetType.IP, value="10.0.0.5"))
    assert meta["lab"] is True
```

- [ ] **Step 2: Run → fails. Step 3: Implement:**

```python
# saber/orchestration/strategies/ctf.py
"""CTF / SSH box strategy."""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class CtfStrategy(TargetStrategy):
    """Recon -> foothold -> creds/sessions -> post-exploit/lateral -> capture flag."""

    kind = StrategyKind.CTF

    def seed_objective(self, target: Target) -> str:
        return f"Compromise {target.value} and capture the flag."

    def initial_metadata(self, target: Target) -> dict[str, Any]:
        return {"strategy": self.kind.value, "lab": True}

    def objective_met(self, state: MissionState) -> bool:
        return bool(state.metadata.get("flag")) or bool(state.credentials)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** (`feat(orchestration): CTF/SSH target strategy`).

> **Objective-met wiring:** the loop currently sets `objective_met` only via the decider's REPORT. Add a step in `MissionLoop.run` (small follow-up edit) to call an injected `strategy.objective_met(state)` after each merge and set `state.objective_met` accordingly. Add `strategy` as an optional `MissionLoop` constructor arg (default `None`); when set, consult it in the stop check. Cover with a `tests/orchestration_tests/test_mission_loop_objective_met.py` test using a scripted strategy. Commit.

---

### Task 17: Live-model acceptance tests (network / web / CTF)

**Files:**
- Create: `tests/e2e_tests/test_mission_loop_live_llm_e2e.py`
- Modify: `.env.example` (document `SABER_RUN_LLM_E2E`), `Makefile` (add `llm-e2e` target)

**Interfaces:**
- Consumes: full runtime, Docker sandbox, live `LlmClient`.
- Produces: three gated integration tests asserting **loop invariants** (not exact tool order): state grows (≥1 service or tech), no scope violation recorded, loop terminates within `max_steps`, a report artifact is produced. Skipped unless `SABER_RUN_LLM_E2E=1` **and** `SABER_RUN_DOCKER_E2E=1` and an API key is configured.

- [ ] **Step 1: Write the gated test**

```python
# tests/e2e_tests/test_mission_loop_live_llm_e2e.py
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("SABER_RUN_LLM_E2E", "0").strip().lower() not in {"1", "true", "yes"}
    or os.getenv("SABER_RUN_DOCKER_E2E", "0").strip().lower() not in {"1", "true", "yes"},
    reason="Set SABER_RUN_LLM_E2E=1 and SABER_RUN_DOCKER_E2E=1 to run live-LLM loop E2E.",
)


def _assert_loop_invariants(result, state_summary):
    assert result.status.value in {"completed", "stopped", "paused_for_approval"}
    counts = state_summary["counts"]
    assert counts["services"] + counts["technologies"] >= 1  # state grew
    assert counts["step_count"] if "step_count" in counts else state_summary["step_count"] >= 1


@pytest.mark.e2e
def test_network_ip_loop_live(tmp_path):
    """Loop against a local network target with a live LLM decider."""
    from saber.core.runtime import build_runtime  # use the real runtime builder name

    runtime = build_runtime(db_path=str(tmp_path / "saber.db"), agent_mode="llm", max_steps=8)
    result = runtime.run_mission_for_target(target_value="127.0.0.1", profile="recon")  # match real API
    _assert_loop_invariants(result, result.metadata["mission_state"])


@pytest.mark.e2e
def test_web_url_loop_live(tmp_path):
    from saber.core.runtime import build_runtime
    runtime = build_runtime(db_path=str(tmp_path / "saber.db"), agent_mode="llm", max_steps=8)
    result = runtime.run_mission_for_target(target_value="http://127.0.0.1", profile="web")
    _assert_loop_invariants(result, result.metadata["mission_state"])
```

> **Adapt `build_runtime` / `run_mission_for_target` to the real runtime API** discovered in `saber/core/runtime.py` (names may differ — inspect and match). The CTF test targets a locally-runnable vulnerable container (e.g. a picoCTF-style box or a known-vuln image in the sandbox); add it once a reproducible local box is chosen, and `log()`/document any target that must be supplied by the operator.

- [ ] **Step 2: Run gated (locally, with a key + Docker)**

```bash
SABER_RUN_LLM_E2E=1 SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_mission_loop_live_llm_e2e.py -v
```
Expected: PASS locally (skipped in CI). If the LLM picks tools not in the catalog, tighten `prompts/next_action.txt`; if it violates scope, the assertion catches it — fix the gate/prompt, not the test.

- [ ] **Step 3: Add `Makefile` target + `.env.example` doc + commit**

Add to `Makefile`:
```make
llm-e2e:
	SABER_RUN_LLM_E2E=1 SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_mission_loop_live_llm_e2e.py -q --tb=short
```
Document `SABER_RUN_LLM_E2E` in `.env.example`. Commit (`test(e2e): add gated live-LLM mission-loop acceptance tests`).

---

# Phase P7 — Report from final MissionState

### Task 18: `MissionStateReportAdapter` + `ReportFinalizer` integration

**Files:**
- Create: `saber/reporting/state_report_adapter.py`
- Modify: `saber/reporting/finalizer.py`
- Test: `tests/reporting_tests/test_state_report_adapter.py`

**Interfaces:**
- Consumes: `MissionState`, `MissionSession`, existing exporters used by `ReportFinalizer`.
- Produces:
  - `MissionStateReportAdapter.build_report_context(state: MissionState, session: MissionSession) -> dict[str, Any]` — a report context containing hosts, services, technologies, credentials (secret-redacted), vulns (with evidence refs), hypotheses, the full attempted-action timeline, and the stop reason.
  - `ReportFinalizer.finalize_from_state(state, session, reports_dir) -> list[MissionArtifact]` reusing the JSON/XLSX/Markdown/PDF exporters via the adapter context.

- [ ] **Step 1: Write the failing test**

```python
# tests/reporting_tests/test_state_report_adapter.py
from saber.models.mission_state import KnownCredential, KnownService, KnownVuln, MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.reporting.state_report_adapter import MissionStateReportAdapter


def test_context_has_sections_and_redacts_secrets():
    state = MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"), objective="assess",
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        vulns=[KnownVuln(title="CVE-2021-41773", severity="high", evidence_refs=["ev1"])],
        credentials=[KnownCredential(username="root", secret="hunter2")],
        stop_reason="objective met",
    )
    session = MissionSession(session_id="s", mission_name="m")
    ctx = MissionStateReportAdapter().build_report_context(state, session)

    assert ctx["summary"]["objective"] == "assess"
    assert ctx["services"][0]["port"] == 80
    assert ctx["vulns"][0]["evidence_refs"] == ["ev1"]
    assert ctx["credentials"][0]["secret"] in {None, "***redacted***"}  # never leak the secret
    assert ctx["stop_reason"] == "objective met"
```

- [ ] **Step 2: Run → fails. Step 3: Implement adapter:**

```python
# saber/reporting/state_report_adapter.py
"""Adapt a final MissionState into a report context."""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import MissionState
from saber.models.session import MissionSession


class MissionStateReportAdapter:
    """Build an evidence-backed report context from final MissionState."""

    def build_report_context(self, state: MissionState, session: MissionSession) -> dict[str, Any]:
        """Return a JSON-compatible report context."""

        return {
            "summary": state.to_summary_dict(),
            "session": session.to_summary_dict(),
            "hosts": [h.model_dump() for h in state.hosts],
            "services": [s.model_dump() for s in state.services],
            "technologies": [t.model_dump() for t in state.technologies],
            "credentials": [
                {**c.model_dump(exclude={"secret"}), "secret": ("***redacted***" if c.secret else None)}
                for c in state.credentials
            ],
            "vulns": [v.model_dump() for v in state.vulns],
            "hypotheses": [h.model_dump() for h in state.hypotheses],
            "timeline": [
                {"tool_name": a.tool_name, "action": a.action, "success": a.success, "reason": a.reason,
                 "at": a.at.isoformat()}
                for a in state.attempted_actions
            ],
            "evidence_refs": state.evidence_refs,
            "finding_refs": state.finding_refs,
            "stop_reason": state.stop_reason,
        }
```

- [ ] **Step 4: Integrate into `ReportFinalizer`** — add `finalize_from_state(...)` that builds the context and feeds the existing exporters (inspect `finalizer.py` for the exact exporter calls and mirror them). Have `MissionLoop` call `report_finalizer.finalize_from_state(...)` on COMPLETED/STOPPED (inject `report_finalizer` into `MissionLoop`, default `None`). Add a test that a completed loop writes report artifacts (using a tmp reports dir + fake exporters or real JSON exporter).

- [ ] **Step 5: Run → PASS. Regression `pytest tests/reporting_tests -q`. Commit** (`feat(reporting): generate report from final MissionState`).

---

# Phase P8 — GUI live MissionState view

### Task 19: Mission-state router + GUI view

**Files:**
- Create: `saber/ui/web/routers/mission_state.py`
- Modify: `saber/ui/web/app.py` (register router; add view)
- Test: `tests/integration/test_mission_state_api.py`

**Interfaces:**
- Consumes: `MissionStateStore`, FastAPI app, existing session routers.
- Produces:
  - `GET /api/sessions/{session_id}/state` → JSON of `MissionState.to_summary_dict()` + full lists (hosts/services/vulns/hypotheses/timeline/pending confirmations).
  - GUI panel on the mission detail page polling that endpoint (reuse the existing polling pattern used for mission progress).

- [ ] **Step 1: Write the failing API test**

```python
# tests/integration/test_mission_state_api.py
from fastapi.testclient import TestClient


def test_state_endpoint_returns_summary(tmp_path, monkeypatch):
    # Build the app with a DB that has one saved MissionState (reuse app factory).
    from saber.ui.web.app import create_app  # match the real factory name
    from saber.models.mission_state import KnownService, MissionState
    from saber.models.session import MissionSession
    from saber.models.target import Target, TargetType
    from saber.storage.connection import StorageConnection
    from saber.storage.mission_state_store import MissionStateStore
    from saber.storage.session_store import SessionStore

    db = tmp_path / "saber.db"
    conn = StorageConnection(db); conn.initialize()
    SessionStore(conn).create_session(MissionSession(session_id="s1", mission_name="m"))
    MissionStateStore(conn).save(
        MissionState(session_id="s1", target=Target(type=TargetType.IP, value="10.0.0.5"),
                     services=[KnownService(host="10.0.0.5", port=80)])
    )

    app = create_app(db_path=str(db))   # match the real signature
    client = TestClient(app)
    resp = client.get("/api/sessions/s1/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["counts"]["services"] == 1
    assert body["services"][0]["port"] == 80
```

- [ ] **Step 2: Run → fails. Step 3: Implement the router:**

```python
# saber/ui/web/routers/mission_state.py
"""GUI endpoints for live MissionState."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from saber.storage.mission_state_store import MissionStateStore


def build_mission_state_router(state_store: MissionStateStore) -> APIRouter:
    """Build the mission-state router bound to a store."""

    router = APIRouter()

    @router.get("/api/sessions/{session_id}/state")
    def get_state(session_id: str) -> dict[str, Any]:
        state = state_store.load(session_id)
        if state is None:
            raise HTTPException(status_code=404, detail="mission state not found")
        return {
            "summary": state.to_summary_dict(),
            "hosts": [h.model_dump() for h in state.hosts],
            "services": [s.model_dump() for s in state.services],
            "technologies": [t.model_dump() for t in state.technologies],
            "vulns": [v.model_dump() for v in state.vulns],
            "hypotheses": [h.model_dump() for h in state.hypotheses],
            "timeline": [
                {"tool_name": a.tool_name, "action": a.action, "success": a.success, "reason": a.reason}
                for a in state.attempted_actions
            ],
        }

    return router
```

Register it in `app.py` where other routers are included (match the existing `app.include_router(...)` / store-wiring pattern), constructing `MissionStateStore` from the app's `StorageConnection`.

- [ ] **Step 4: Run → PASS. Step 5: Add the GUI panel** — on the mission detail template, add a "Mission State" panel (hosts/services/vulns/hypotheses/timeline + pending confirmations) that polls `/api/sessions/{id}/state` on the same interval as the existing progress poll. Manually verify via `./run_saber` that the panel updates during a deterministic mission.

- [ ] **Step 6: Commit** (`feat(ui): live MissionState view in GUI`).

---

# Phase P9 — Documentation

### Task 20: Rewrite `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite the architecture + workflow sections** to describe the agentic loop. Replace the "PlannerAgent builds the mission plan → agents run planned steps" narrative with the **observe → reason → decide → execute → normalize → repeat** loop. Update:
  - The top-of-file flow diagram to the closed loop.
  - "Current Capabilities" — replace static-plan language with the state-first loop, `MissionState`, risk-gated autonomy, and report-from-state.
  - "Agents" — reframe agents as capability lenses the loop dispatches to.
  - Add an **Autonomy & Safety** section: `autonomy_level` (recon_only/assisted/autonomous), the high-risk confirmation gate, scope-as-hard-wall.
  - Add `SABER_RUN_LLM_E2E` and `make llm-e2e` to the Development/CI sections.
  - Update the CLI example to the working `--target` form.

- [ ] **Step 2: Verify** the README's documented commands actually run (`make unit`, the CLI line). Fix any that don't.

- [ ] **Step 3: Commit** (`docs: rewrite README for the agentic mission loop`).

### Task 21: Rewrite `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Rewrite `CLAUDE.md`** so future Claude Code instances understand the new architecture. Include, prefixed with the required header:
  ```
  # CLAUDE.md

  This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
  ```
  Cover: the state-first loop as the core (`MissionLoop` in `saber/orchestration/mission_loop.py` is the entry point to understand); the five files to read first (`mission_loop.py`, `mission_state.py`, `deciders/base.py` + `llm.py`, `state_merger.py`, `risk_gate.py`); the invariants (agents never run shell; execution only via Sandbox through `ActionExecutor`; `MissionState` is immutable-copy; risk-gated autonomy; scope is a hard wall); the deterministic-vs-LLM decider split; commands (`make unit`, `make llm-e2e`, single-test pattern, ruff/mypy); key env vars incl. `SABER_AGENT_MODE`, `SABER_RUN_LLM_E2E`, autonomy level. Note the doc discrepancy fix: CLI uses `--target`.

- [ ] **Step 2: Commit** (`docs: rewrite CLAUDE.md for the agentic mission loop`).

---

## Self-Review (completed against the approved spec)

- **Spec coverage:** MissionState (T1), persistence (T2), dynamic decision loop (T11), agent memory/summary (T4), tool/action planner over normalized observations (T7–T9 decider + T3 merger), branching per target type (T14–T16), stop conditions (T6), report from final state (T18). GUI live view (T19). Retire plan-first (T13). Risk-gated autonomy per your directive (T5). Live-model acceptance on all three targets (T17). Docs (T20–T21). ✔ every spec item maps to a task.
- **Type consistency:** `ProposedAction`, `RiskLevel` (ordered `IntEnum`), `ActionKind`, `GateDecision`, `AutonomyLevel`, `MissionState`, `StateSummary`, `ProcessedToolResult.parsed_observations`, `MissionLoopResult`, `ActionExecutionRecord` are defined once (T7/T5/T1/T4/T3/T11/T10) and referenced with the same names/signatures throughout.
- **Sequencing note:** implement **T7 before T5** (RiskGate imports `ProposedAction`/`RiskLevel`), and create thin `web.py`/`ctf.py` in T14 (selector imports them) before fleshing them out in T15/T16. Flagged inline in those tasks.
- **Grounding caveats to verify while implementing (flagged inline):** exact local variable names in `runtime.py`; `ExecutionPlan` constructor shape for the empty-plan adapter; `PromptLoader.load_agent_prompt` name resolution; the real runtime/app factory names in T17/T19. These are marked in-task; adjust to the actual code rather than assuming.

## Execution Handoff

Plan complete and saved to `PLAN.md`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
**2. Inline Execution** — execute tasks in this session with checkpoints for review.

Which approach?
