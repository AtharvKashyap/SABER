"""SABER command-line entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from saber.reporting.json_exporter import JsonExporter
from saber.reporting.pdf_exporter import PdfExporter
from saber.reporting.xlsx_exporter import XlsxExporter
from saber.storage.connection import StorageConnection
from saber.storage.evidence_index import EvidenceIndex
from saber.storage.finding_store import FindingStore
from saber.storage.session_store import SessionStore
from saber.ui.cli.approval_prompt import ApprovalPrompt, format_approval_list
from saber.ui.cli.doctor import SaberDoctor, format_doctor_report
from saber.ui.cli.live_panel import LivePanel
from saber.ui.cli.sandbox_commands import SandboxCommands


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""

    parser = argparse.ArgumentParser(prog="saber", description="SABER operator CLI.")
    parser.add_argument("--db", default="runs/saber.db", help="Path to SABER SQLite database.")

    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser("doctor", help="Run environment checks.")
    doctor.add_argument("--json", action="store_true", help="Output JSON.")

    sessions = subcommands.add_parser("sessions", help="Session commands.")
    sessions_sub = sessions.add_subparsers(dest="sessions_command", required=True)

    sessions_list = sessions_sub.add_parser("list", help="List sessions.")
    sessions_list.add_argument("--limit", type=int, default=100)

    sessions_show = sessions_sub.add_parser("show", help="Show one session.")
    sessions_show.add_argument("session_id")

    approvals = subcommands.add_parser("approvals", help="Approval commands.")
    approvals_sub = approvals.add_subparsers(dest="approvals_command", required=True)

    approvals_list = approvals_sub.add_parser("list", help="List pending approvals.")
    approvals_list.add_argument("--session-id")

    approvals_approve = approvals_sub.add_parser("approve", help="Approve an approval request.")
    approvals_approve.add_argument("approval_id")
    approvals_approve.add_argument("--by", dest="resolved_by")

    approvals_deny = approvals_sub.add_parser("deny", help="Deny an approval request.")
    approvals_deny.add_argument("approval_id")
    approvals_deny.add_argument("--by", dest="resolved_by")
    approvals_deny.add_argument("--reason")

    approvals_prompt = approvals_sub.add_parser("prompt", help="Interactively prompt pending approvals.")
    approvals_prompt.add_argument("--session-id")
    approvals_prompt.add_argument("--by", dest="resolved_by")

    findings = subcommands.add_parser("findings", help="Finding commands.")
    findings_sub = findings.add_subparsers(dest="findings_command", required=True)

    findings_list = findings_sub.add_parser("list", help="List findings.")
    findings_list.add_argument("session_id")
    findings_list.add_argument("--severity")
    findings_list.add_argument("--status")
    findings_list.add_argument("--json", action="store_true")

    evidence = subcommands.add_parser("evidence", help="Evidence commands.")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)

    evidence_list = evidence_sub.add_parser("list", help="List evidence.")
    evidence_list.add_argument("session_id")
    evidence_list.add_argument("--json", action="store_true")

    evidence_verify = evidence_sub.add_parser("verify", help="Verify evidence integrity.")
    evidence_verify.add_argument("evidence_id")

    reports = subcommands.add_parser("reports", help="Report commands.")
    reports_sub = reports.add_subparsers(dest="reports_command", required=True)

    reports_export = reports_sub.add_parser("export", help="Export report from stored findings/observations.")
    reports_export.add_argument("session_id")
    reports_export.add_argument("--format", choices=["json", "xlsx", "pdf", "markdown"], required=True)
    reports_export.add_argument("--output", required=True)
    reports_export.add_argument("--mission-name")
    reports_export.add_argument("--target", default="unknown")

    live = subcommands.add_parser("live", help="Show live mission status.")
    live.add_argument("session_id")
    live.add_argument("--interval", type=float, default=2.0)
    live.add_argument("--once", action="store_true")

    sandbox = subcommands.add_parser("sandbox", help="Sandbox inspection commands.")
    sandbox_sub = sandbox.add_subparsers(dest="sandbox_command", required=True)
    sandbox_sub.add_parser("check", help="Check sandbox and tools.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run SABER CLI."""

    args = build_parser().parse_args(argv)
    connection = StorageConnection(args.db)
    connection.initialize()

    session_store = SessionStore(connection)
    finding_store = FindingStore(connection)
    evidence_index = EvidenceIndex(connection)

    try:
        return dispatch(args, session_store, finding_store, evidence_index)
    finally:
        connection.close()


def dispatch(
    args: argparse.Namespace,
    session_store: SessionStore,
    finding_store: FindingStore,
    evidence_index: EvidenceIndex,
) -> int:
    """Dispatch parsed CLI args."""

    if args.command == "doctor":
        report = SaberDoctor(db_path=args.db).run()
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True, default=str))
        else:
            print(format_doctor_report(report))
        return 0 if report.ok() else 1

    if args.command == "sessions":
        return handle_sessions(args, session_store)

    if args.command == "approvals":
        return handle_approvals(args, session_store)

    if args.command == "findings":
        return handle_findings(args, finding_store)

    if args.command == "evidence":
        return handle_evidence(args, evidence_index)

    if args.command == "reports":
        return handle_reports(args, session_store, finding_store, evidence_index)

    if args.command == "live":
        panel = LivePanel(session_store, finding_store, evidence_index)
        if args.once:
            print(panel.render(args.session_id))
        else:
            panel.watch(args.session_id, interval_seconds=args.interval)
        return 0

    if args.command == "sandbox":
        return handle_sandbox(args, evidence_index)

    raise ValueError(f"Unsupported command: {args.command}")


def handle_sessions(args: argparse.Namespace, session_store: SessionStore) -> int:
    """Handle sessions commands."""

    if args.sessions_command == "list":
        sessions = session_store.list_sessions(limit=args.limit)
        print(json.dumps(sessions, indent=2, sort_keys=True, default=str))
        return 0

    if args.sessions_command == "show":
        session = session_store.get_session(args.session_id)
        if not session:
            print(f"Session not found: {args.session_id}", file=sys.stderr)
            return 1

        payload = {
            "session": session,
            "steps": session_store.list_steps(args.session_id),
            "records": session_store.list_step_records(args.session_id),
            "pending_approvals": session_store.list_pending_approvals(args.session_id),
            "report_artifacts": session_store.list_report_artifacts(args.session_id),
        }
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    raise ValueError(f"Unsupported sessions command: {args.sessions_command}")


def handle_approvals(args: argparse.Namespace, session_store: SessionStore) -> int:
    """Handle approval commands."""

    prompt = ApprovalPrompt(session_store)

    if args.approvals_command == "list":
        approvals = prompt.list_pending(session_id=args.session_id)
        print(format_approval_list(approvals))
        return 0

    if args.approvals_command == "approve":
        decision = prompt.approve(args.approval_id, resolved_by=args.resolved_by)
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.approvals_command == "deny":
        decision = prompt.deny(
            args.approval_id,
            resolved_by=args.resolved_by,
            reason=args.reason,
        )
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.approvals_command == "prompt":
        decisions = prompt.prompt_all(session_id=args.session_id, resolved_by=args.resolved_by)
        print(json.dumps([decision.to_dict() for decision in decisions], indent=2, sort_keys=True))
        return 0

    raise ValueError(f"Unsupported approvals command: {args.approvals_command}")


def handle_findings(args: argparse.Namespace, finding_store: FindingStore) -> int:
    """Handle finding commands."""

    findings = finding_store.list_findings(
        args.session_id,
        severity=args.severity,
        status=args.status,
    )

    if args.json:
        print(json.dumps(findings, indent=2, sort_keys=True, default=str))
        return 0

    if not findings:
        print("No findings.")
        return 0

    for finding in findings:
        print(
            f"{finding.get('finding_id')} | {finding.get('severity')} | "
            f"{finding.get('status')} | {finding.get('title')}"
        )

    return 0


def handle_evidence(args: argparse.Namespace, evidence_index: EvidenceIndex) -> int:
    """Handle evidence commands."""

    if args.evidence_command == "list":
        evidence = evidence_index.list_evidence(args.session_id)
        if args.json:
            print(json.dumps(evidence, indent=2, sort_keys=True, default=str))
            return 0

        if not evidence:
            print("No evidence.")
            return 0

        for item in evidence:
            print(
                f"{item.get('evidence_id')} | {item.get('tool_name') or '-'} | "
                f"{item.get('title')} | {item.get('path')}"
            )
        return 0

    if args.evidence_command == "verify":
        ok = evidence_index.verify_evidence(args.evidence_id)
        print("OK" if ok else "FAILED")
        return 0 if ok else 1

    raise ValueError(f"Unsupported evidence command: {args.evidence_command}")


def handle_reports(
    args: argparse.Namespace,
    session_store: SessionStore,
    finding_store: FindingStore,
    evidence_index: EvidenceIndex,
) -> int:
    """Handle report commands."""

    session = session_store.get_session(args.session_id) or {}
    mission_name = args.mission_name or session.get("mission_name") or args.session_id
    findings = finding_store.list_findings(args.session_id)
    observations = finding_store.list_observations(args.session_id)

    document = JsonExporter().build_document(
        mission_name=mission_name,
        target=args.target,
        observations=observations,
        findings=findings,
        metadata={
            "session": session,
            "evidence": evidence_index.list_evidence(args.session_id),
        },
    )

    output = Path(args.output)

    if args.format == "json":
        path = JsonExporter().export(document, output)
    elif args.format == "xlsx":
        path = XlsxExporter().export(document, output)
    elif args.format == "pdf":
        path = PdfExporter().export_pdf(document, output)
    elif args.format == "markdown":
        path = PdfExporter().export_markdown(document, output)
    else:
        raise ValueError(f"Unsupported report format: {args.format}")

    session_store.save_report_artifact(
        session_id=args.session_id,
        report_type=args.format,
        path=path,
        metadata={"generated_by": "saber-cli"},
    )

    print(str(path))
    return 0


def handle_sandbox(args: argparse.Namespace, evidence_index: EvidenceIndex) -> int:
    """Handle sandbox commands."""

    commands = SandboxCommands(evidence_index=evidence_index)

    if args.sandbox_command == "check":
        print(commands.format_check(commands.check()))
        return 0

    raise ValueError(f"Unsupported sandbox command: {args.sandbox_command}")


if __name__ == "__main__":
    raise SystemExit(main())
