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
from saber.core.docker_runner import DEFAULT_SHARED_IMAGE


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
        # Honour the sandbox env vars. Constructing SaberConfig explicitly bypasses
        # SaberConfig.from_env(), so these previously fell back to their DEFAULTS: a
        # stale published image that lacked radare2/pwntools/tshark, and network
        # "host", where a lab hostname like "dvwa" does not resolve at all.
        # The mission therefore executed tools that could not reach the target, and the
        # "MissionState grew" assertion failed for an environmental reason that looked
        # exactly like a product defect.
        sandbox_backend=os.environ.get("SABER_SANDBOX_BACKEND", "docker"),
        sandbox_image=os.environ.get(
            "SABER_SANDBOX_IMAGE", DEFAULT_SHARED_IMAGE
        ),
        docker_network=os.environ.get("SABER_DOCKER_NETWORK", "host"),
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

    # 3a. A paused run must still be a REAL pause, not merely a status string.
    # Previously both substantive checks below were simply skipped for a pause, so a
    # mission that paused on its very first decision passed this test having proven
    # nothing at all. A pause is legitimate (a high-risk first action), but it must be
    # evidenced: the loop records the gate reason as the stop_reason.
    if result.status.value == "paused_for_approval":
        assert state.stop_reason and "confirmation" in state.stop_reason.lower(), (
            "a paused run must record the awaiting-confirmation stop_reason, got "
            f"{state.stop_reason!r}"
        )
        # Say so loudly: this run did NOT exercise execute -> parse -> merge.
        if not state.attempted_actions:
            pytest.skip(
                "mission paused on its first decision with no executed action: this "
                "run proves nothing about the execute/parse/merge path. Re-run with a "
                "target whose first useful action is low-risk, or set "
                "autonomy_level=autonomous."
            )

    # 3b. On a finalized (completed/stopped) run: state grew and a report exists.
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


def _reachable_from_sandbox(host: str, port: int) -> bool:
    """Probe a host from INSIDE the sandbox network, as the tools will see it.

    This matters more than it looks. These tests used to target ``127.0.0.1`` /
    ``http://127.0.0.1``, but tools run inside a container, where loopback is the
    CONTAINER's own loopback — nothing is served there. Verified against the built
    image: 127.0.0.1:80 is closed, dvwa:80 is open. So the web acceptance test
    asserted "MissionState grew" against a target the sandbox cannot reach, and could
    never legitimately pass; it only ever reported a product failure that was really a
    test-targeting bug.
    """

    import subprocess

    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, test-only Docker probe
            [
                "docker",
                "run",
                "--rm",
                "--network",
                os.getenv("SABER_DOCKER_NETWORK", "saber-lab"),
                "--entrypoint",
                "sh",
                os.getenv("SABER_SANDBOX_IMAGE", DEFAULT_SHARED_IMAGE),
                "-lc",
                f"nc -z -w 3 {host} {port}",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _require_lab_target(candidates: list[tuple[str, int]], env_var: str) -> str:
    """Return an operator-supplied target, else the first reachable lab host, else skip.

    Takes a candidate LIST because lab containers are not equally reliable:
    metasploitable is a heavy image that crash-loops on some hosts, so depending on it
    alone made the test skip for an unrelated reason. dvwa/juiceshop come up reliably
    and are perfectly good network-scan targets.
    """

    override = os.getenv(env_var, "").strip()
    if override:
        return override
    for host, port in candidates:
        if _reachable_from_sandbox(host, port):
            return host
    tried = ", ".join(f"{host}:{port}" for host, port in candidates)
    pytest.skip(
        f"no lab target reachable from inside the sandbox network (tried {tried}). Run "
        f"`make lab-up`, build the image (`make sandbox-build`), and set "
        f"SABER_DOCKER_NETWORK=saber-lab — or point {env_var} at your own target."
    )


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
    # metasploitable is the lab's network target; loopback inside the sandbox serves
    # nothing, so a scan of 127.0.0.1 could not grow state.
    host = _require_lab_target(
        [("metasploitable", 80), ("dvwa", 80), ("juiceshop", 3000)],
        "SABER_LAB_NETWORK_TARGET",
    )
    try:
        session_id, result = _run_live_mission(
            runtime, target=_build_target(host), profile="network"
        )
        _assert_loop_invariants(runtime, session_id, result)
    finally:
        runtime.close()


def test_web_url_loop_live(tmp_path) -> None:
    """Web mission against a local URL with a live LLM decider."""

    runtime = _build_live_runtime(tmp_path, profile="web")
    _skip_if_model_disabled(runtime)
    host = _require_lab_target([("dvwa", 80), ("juiceshop", 3000)], "SABER_LAB_WEB_TARGET")
    url = host if "://" in host else f"http://{host}"
    try:
        session_id, result = _run_live_mission(
            runtime, target=_build_target(url), profile="web"
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
