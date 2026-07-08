"""Fake end-to-end tests for SABER result processing.

These tests do not run real tools or touch the network.
They validate the product path:

evidence file -> EvidenceIndex -> ResultProcessor -> ParserRegistry -> FindingStore
"""

from __future__ import annotations

from pathlib import Path

from saber.core.runtime import SaberConfig, build_saber_runtime


def test_fake_nmap_evidence_is_indexed_parsed_and_persisted(tmp_path: Path) -> None:
    """Fake nmap output should become stored evidence and observations."""

    db_path = tmp_path / "saber.db"
    evidence_dir = tmp_path / "evidence"
    reports_dir = tmp_path / "reports"

    runtime = build_saber_runtime(
        SaberConfig(
            db_path=db_path,
            evidence_dir=evidence_dir,
            reports_dir=reports_dir,
            profile="recon",
        )
    )

    try:
        session_id = "e2e_fake_session"

        runtime.session_store.create_session(
            {
                "session_id": session_id,
                "mission_name": "Fake E2E Nmap Mission",
                "status": "running",
                "metadata": {"target": "127.0.0.1", "test": True},
            }
        )

        nmap_output = """Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-08 00:00 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
"""

        evidence_file = evidence_dir / "fake" / "nmap" / "service_scan" / "nmap.txt"
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        evidence_file.write_text(nmap_output, encoding="utf-8")

        evidence_id = runtime.evidence_index.add_evidence(
            session_id=session_id,
            step_id="recon",
            tool_name="nmap",
            action="service_scan",
            title="Fake nmap stdout",
            path=evidence_file,
            metadata={"test": True},
        )

        processed = runtime.result_processor.process_evidence_file(
            session_id=session_id,
            path=evidence_file,
            tool_name="nmap",
            step_id="recon",
            action="service_scan",
            evidence_id=evidence_id,
            metadata={"test": True},
        )

        evidence = runtime.evidence_index.list_evidence(session_id)
        observations = runtime.finding_store.list_observations(session_id)

        assert processed.tool_name == "nmap"
        assert processed.parser_used == "NmapParser"
        assert processed.evidence_ids == [evidence_id]
        assert processed.errors == []
        assert len(evidence) == 1
        assert len(observations) >= 1

        summaries = " ".join(str(observation.get("summary", "")) for observation in observations).lower()
        assert "127.0.0.1" in summaries or "localhost" in summaries
        assert "22" in summaries or "ssh" in summaries
        assert "80" in summaries or "http" in summaries
    finally:
        runtime.close()
