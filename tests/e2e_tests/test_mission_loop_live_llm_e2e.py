"""Gated live-model acceptance tests for the SABER mission loop.

These are ACCEPTANCE tests. They drive a full mission through the real runtime
(``build_saber_runtime`` -> ``MissionOrchestrator.run_mission`` -> ``MissionLoop``)
with the LIVE ``LlmDecider`` and a real Docker sandbox, then assert loop
INVARIANTS rather than an exact tool sequence.

They are GATED and skip by default. To run them you need ALL of:

  * ``SABER_RUN_LLM_E2E=1``
  * ``SABER_RUN_DOCKER_E2E=1``
  * a configured model + key (``SABER_MODEL`` / ``SABER_MODEL_API_KEY``)
  * a working Docker daemon and the SABER sandbox image

Run them with::

    make llm-e2e
    # or
    SABER_RUN_LLM_E2E=1 SABER_RUN_DOCKER_E2E=1 \
        pytest tests/e2e_tests/test_mission_loop_live_llm_e2e.py -v

Invariants asserted (see ``_assert_loop_invariants``):

  1. The mission TERMINATES with a terminal status
     (``completed`` / ``stopped`` / ``paused_for_approval``) within ``max_steps``.
  2. NO scope violation was recorded in the final ``MissionState``.
  3. On a terminal ``completed``/``stopped`` run the ``MissionState`` GREW
     (>= 1 service or technology) AND a report artifact was produced.
     A ``paused_for_approval`` run produces neither by design (the loop returns
     before finalizing a report), so those two checks are skipped for it.

These tests mirror how the CLI launches a mission (SaberConfig with
``agent_mode="llm"`` -> ``build_saber_runtime`` -> ``run_mission``) but drive
``run_mission`` directly so the returned ``MissionRunResult`` and the persisted
``MissionState`` can be inspected for the invariants above.

CTF acceptance target: this repository bundles no locally-reproducible
vulnerable box (the sandbox image is an attacker toolkit, not a victim), so the
CTF acceptance test uses an OPERATOR-SUPPLIED target read from
``SABER_CTF_TARGET`` (with optional ``SABER_CTF_PROFILE``). It skips with a clear
reason when that variable is unset, even when the gates above are on.
"""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from saber.core.runtime import SaberConfig, build_saber_runtime
from saber.models.scope import MissionScope
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.storage.mission_state_store import MissionStateStore
from saber.ui.cli.run_command import _configure_llm_agents


def _truthy(name: str) -> bool:
    """Return whether an env flag is set to a truthy value."""

    return os.getenv(name, "0").strip().lower() in {"1", "true", "yes", "y", "on"}


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not (_truthy("SABER_RUN_LLM_E2E") and _truthy("SABER_RUN_DOCKER_E2E")),
        reason=(
            "Set SABER_RUN_LLM_E2E=1 and SABER_RUN_DOCKER_E2E=1 (plus a live model "
            "and Docker) to run the live-LLM mission-loop acceptance tests."
        ),
    ),
]

# Keep live runs bounded and affordable; overridable for local tuning.
MAX_STEPS = int(os.getenv("SABER_E2E_MAX_STEPS", "8"))

_TERMINAL = {"completed", "stopped", "paused_for_approval"}
_FINALIZED = {"completed", "stopped"}


def _build_target(value: str) -> Target:
    """Build a Target from an operator/test string, choosing the type by shape."""

    normalized = value.strip()
    if normalized.lower().startswith(("http://", "https://")):
        return Target(type=TargetType.URL, value=normalized)
    try:
        return Target(type=TargetType.IP, value=normalized)
    except Exception:
        return Target(type=TargetType.HOST, value=normalized)


def _build_live_runtime(tmp_path, *, profile: str, agent_mode: str = "llm"):
    """Build a fully wired runtime with tmp storage, mirroring the CLI config."""

    config = SaberConfig(
        db_path=tmp_path / "saber.db",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        profile=profile,
        require_approval=False,
        max_steps=MAX_STEPS,
        agent_mode=agent_mode,
        metadata={"source": "llm_e2e"},
    )
    return build_saber_runtime(config)


def _run_live_mission(runtime, *, target: Target, profile: str):
    """Launch one mission via the real orchestrator loop and return the result.

    An explicit ``MissionScope`` containing the target is attached to the session
    so the RiskGate's scope enforcement is actually ACTIVE (rather than the
    scope-less always-allow path), making the "no scope violation" invariant a
    real check. The mission target is always in scope, so a correct run records
    no scope refusal.
    """

    session_id = f"llm_e2e_{uuid4().hex[:12]}"
    scope = MissionScope(mission_name=f"LLM E2E {profile}", targets=[target])
    session = MissionSession(
        session_id=session_id,
        mission_name=f"LLM E2E {profile} mission",
        scope=scope,
    )

    runtime.session_store.create_session(
        {
            "session_id": session_id,
            "mission_name": session.mission_name,
            "status": "running",
            "metadata": {"target": target.value, "profile": profile, "source": "llm_e2e"},
        }
    )
    _configure_llm_agents(runtime, agent_mode="llm")

    result = runtime.orchestrator.run_mission(
        session=session,
        target=target,
        objective="",  # let the target strategy seed the objective, as run_mission intends
        constraints={"autonomy_level": "autonomous", "agent_mode": "llm", "profile": profile},
        metadata={"source": "llm_e2e", "profile": profile},
    )
    return session_id, result


def _assert_loop_invariants(runtime, session_id: str, result) -> None:
    """Assert the mission-loop invariants on a completed run."""

    # 1. The mission terminates with a terminal status within max_steps.
    assert result.status.value in _TERMINAL, f"non-terminal mission status: {result.status}"

    # Reload the full MissionState for the action trace + growth counts. The loop
    # snapshots after every merge, so a run always leaves a state behind.
    state = MissionStateStore(runtime.storage_connection).load(session_id)
    assert state is not None, "mission loop must persist a MissionState snapshot"

    # 2. No scope violation recorded. A RiskGate scope REFUSE is merged into the
    # state as a failed attempt whose reason carries the gate reason
    # ("... out of scope"). None of those may be present.
    scope_violations = [
        attempt for attempt in state.attempted_actions
        if "out of scope" in (attempt.reason or "").lower()
    ]
    assert not scope_violations, (
        f"scope violations recorded: {[a.reason for a in scope_violations]}"
    )

    # 3. On a finalized (completed/stopped) run: state grew and a report exists.
    # A paused-for-approval run produces neither by design, so skip those checks.
    if result.status.value in _FINALIZED:
        grew = len(state.services) + len(state.technologies) >= 1
        assert grew, (
            "MissionState did not grow: expected >=1 service or technology "
            f"(services={len(state.services)}, technologies={len(state.technologies)})"
        )

        assert result.artifacts, "expected at least one report artifact on a finalized run"
        assert any(
            Path(artifact.path).is_file() and Path(artifact.path).stat().st_size > 0
            for artifact in result.artifacts
        ), "expected a non-empty report artifact file on disk"


def _skip_if_model_disabled(runtime) -> None:
    """Skip (and close the runtime) when no live model is configured."""

    if not runtime.llm_client.enabled:
        runtime.close()
        pytest.skip(
            "Live model not configured (set SABER_MODEL and SABER_MODEL_API_KEY) "
            "for the live-LLM acceptance tests."
        )


def test_network_ip_loop_live(tmp_path) -> None:
    """Recon/network mission against a local IP with a live LLM decider."""

    runtime = _build_live_runtime(tmp_path, profile="network")
    _skip_if_model_disabled(runtime)
    try:
        session_id, result = _run_live_mission(
            runtime, target=_build_target("127.0.0.1"), profile="network"
        )
        _assert_loop_invariants(runtime, session_id, result)
    finally:
        runtime.close()


def test_web_url_loop_live(tmp_path) -> None:
    """Web mission against a local URL with a live LLM decider."""

    runtime = _build_live_runtime(tmp_path, profile="web")
    _skip_if_model_disabled(runtime)
    try:
        session_id, result = _run_live_mission(
            runtime, target=_build_target("http://127.0.0.1"), profile="web"
        )
        _assert_loop_invariants(runtime, session_id, result)
    finally:
        runtime.close()


def test_ctf_box_loop_live(tmp_path) -> None:
    """CTF-style acceptance against an OPERATOR-SUPPLIED target.

    No reproducible local CTF box is bundled with SABER, so the acceptance
    target must be supplied by the operator via ``SABER_CTF_TARGET`` (an IP,
    host, or URL of an authorized, locally-runnable vulnerable box). Set
    ``SABER_CTF_PROFILE`` to steer the profile (default ``network``). The test
    skips cleanly when no target is supplied.
    """

    ctf_target = os.getenv("SABER_CTF_TARGET", "").strip()
    if not ctf_target:
        pytest.skip(
            "Set SABER_CTF_TARGET=<ip|host|url> (and optionally SABER_CTF_PROFILE) "
            "to run the CTF acceptance test. No reproducible local CTF box is "
            "bundled with SABER, so the CTF target must be operator-supplied."
        )

    profile = os.getenv("SABER_CTF_PROFILE", "network").strip() or "network"
    runtime = _build_live_runtime(tmp_path, profile=profile)
    _skip_if_model_disabled(runtime)
    try:
        session_id, result = _run_live_mission(
            runtime, target=_build_target(ctf_target), profile=profile
        )
        _assert_loop_invariants(runtime, session_id, result)
    finally:
        runtime.close()
