"""Interactive approval helpers for SABER CLI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from saber.storage.session_store import SessionStore


@dataclass(frozen=True)
class ApprovalDecision:
    """Approval decision result."""

    approval_id: str
    decision: str
    resolved_by: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible decision."""

        return {
            "approval_id": self.approval_id,
            "decision": self.decision,
            "resolved_by": self.resolved_by,
            "reason": self.reason,
        }


def format_approval(approval: dict[str, Any]) -> str:
    """Format one approval request."""

    requested_action = approval.get("requested_action", {})
    metadata = approval.get("metadata", {})

    return "\n".join(
        [
            f"Approval ID: {approval.get('approval_id')}",
            f"Session: {approval.get('session_id')}",
            f"Step: {approval.get('step_id')}",
            f"Status: {approval.get('status')}",
            f"Reason: {approval.get('reason')}",
            "",
            "Requested action:",
            json.dumps(requested_action, indent=2, sort_keys=True, default=str),
            "",
            "Metadata:",
            json.dumps(metadata, indent=2, sort_keys=True, default=str),
        ]
    )


def format_approval_list(approvals: list[dict[str, Any]]) -> str:
    """Format approval list."""

    if not approvals:
        return "No pending approvals."

    blocks = []
    for approval in approvals:
        blocks.append(
            f"{approval.get('approval_id')} | session={approval.get('session_id')} "
            f"| step={approval.get('step_id')} | reason={approval.get('reason')}"
        )
    return "\n".join(blocks)


class ApprovalPrompt:
    """CLI approval workflow helper."""

    def __init__(self, session_store: SessionStore) -> None:
        """Initialize approval prompt."""

        self.session_store = session_store

    def list_pending(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """List pending approvals."""

        return self.session_store.list_pending_approvals(session_id=session_id)

    def approve(
        self,
        approval_id: str,
        resolved_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalDecision:
        """Approve a pending request."""

        self.session_store.resolve_approval(
            approval_id=approval_id,
            decision="approved",
            resolved_by=resolved_by,
            metadata=metadata,
        )
        return ApprovalDecision(
            approval_id=approval_id,
            decision="approved",
            resolved_by=resolved_by,
        )

    def deny(
        self,
        approval_id: str,
        resolved_by: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalDecision:
        """Deny a pending request."""

        merged_metadata = dict(metadata or {})
        if reason:
            merged_metadata["deny_reason"] = reason

        self.session_store.resolve_approval(
            approval_id=approval_id,
            decision="denied",
            resolved_by=resolved_by,
            metadata=merged_metadata,
        )
        return ApprovalDecision(
            approval_id=approval_id,
            decision="denied",
            resolved_by=resolved_by,
            reason=reason,
        )

    def prompt_once(
        self,
        approval: dict[str, Any],
        resolved_by: str | None = None,
        input_func: Any = input,
        print_func: Any = print,
    ) -> ApprovalDecision:
        """Prompt for one approval. Default is deny."""

        print_func(format_approval(approval))
        answer = input_func("\nApprove? [y/N]: ").strip().lower()

        approval_id = str(approval["approval_id"])

        if answer in {"y", "yes"}:
            return self.approve(approval_id, resolved_by=resolved_by)

        return self.deny(
            approval_id,
            resolved_by=resolved_by,
            reason="Denied by default or operator input.",
        )

    def prompt_all(
        self,
        session_id: str | None = None,
        resolved_by: str | None = None,
        input_func: Any = input,
        print_func: Any = print,
    ) -> list[ApprovalDecision]:
        """Prompt through all pending approvals."""

        decisions: list[ApprovalDecision] = []
        approvals = self.list_pending(session_id=session_id)

        if not approvals:
            print_func("No pending approvals.")
            return decisions

        for approval in approvals:
            decisions.append(
                self.prompt_once(
                    approval,
                    resolved_by=resolved_by,
                    input_func=input_func,
                    print_func=print_func,
                )
            )

        return decisions
