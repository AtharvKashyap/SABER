"""Tests for MissionStateReportAdapter and ReportFinalizer.finalize_from_state."""

from __future__ import annotations

import json

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
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.reporting.finalizer import ReportFinalizer
from saber.reporting.state_report_adapter import MissionStateReportAdapter


def _state() -> MissionState:
    return MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
        hosts=[KnownHost(address="10.0.0.5", hostnames=["web"])],
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        technologies=[KnownTechnology(host="10.0.0.5", name="nginx", version="1.20")],
        vulns=[KnownVuln(title="CVE-2021-41773", severity="high", evidence_refs=["ev1"])],
        credentials=[KnownCredential(username="root", secret="hunter2")],
        hypotheses=[Hypothesis(statement="path traversal likely", confidence=0.7)],
        attempted_actions=[
            AttemptedAction(tool_name="nmap", action="service_scan", success=True, reason="")
        ],
        evidence_refs=["ev1"],
        finding_refs=["f1"],
        stop_reason="objective met",
    )


def test_context_has_sections_and_redacts_secrets():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
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


def test_context_covers_all_state_sections():
    state = _state()
    session = MissionSession(session_id="s", mission_name="m")
    ctx = MissionStateReportAdapter().build_report_context(state, session)

    assert {
        "summary",
        "session",
        "hosts",
        "services",
        "technologies",
        "credentials",
        "vulns",
        "hypotheses",
        "timeline",
        "evidence_refs",
        "finding_refs",
        "stop_reason",
    } <= set(ctx)
    assert ctx["hosts"][0]["address"] == "10.0.0.5"
    assert ctx["technologies"][0]["name"] == "nginx"
    assert ctx["hypotheses"][0]["statement"] == "path traversal likely"
    assert ctx["timeline"][0]["tool_name"] == "nmap"
    assert ctx["timeline"][0]["success"] is True
    assert "at" in ctx["timeline"][0]
    assert ctx["evidence_refs"] == ["ev1"]
    assert ctx["finding_refs"] == ["f1"]
    # The raw secret must never appear anywhere in the serialized context.
    assert "hunter2" not in json.dumps(ctx)


def test_finalize_from_state_emits_json_report(tmp_path):
    state = _state()
    session = MissionSession(session_id="s", mission_name="m")
    finalizer = ReportFinalizer(
        finding_store=None,
        output_dir=tmp_path,
        export_pdf=False,
        export_markdown=False,
    )

    artifacts = finalizer.finalize_from_state(state, session, tmp_path)

    report_types = {artifact.report_type for artifact in artifacts}
    assert "json" in report_types

    json_path = tmp_path / "s" / "findings.json"
    assert json_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    # The state context is embedded in the report metadata.
    mission_state = payload["metadata"]["mission_state"]
    assert mission_state["stop_reason"] == "objective met"
    assert mission_state["services"][0]["port"] == 80
    assert "hunter2" not in json_path.read_text(encoding="utf-8")
