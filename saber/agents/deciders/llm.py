"""LLM-primary decider for the mission loop."""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import replace
from typing import Any

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction, RiskLevel
from saber.core.prompt_loader import PromptLoader
from saber.core.state_summary import StateSummary
from saber.core.tool_catalog import ToolCatalog
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType

# Substrings that mark a model failure as worth retrying. Deliberately conservative:
# a malformed-request or auth failure will not fix itself, so retrying it just burns
# mission time.
_TRANSIENT_MARKERS = (
    "429",
    "rate limit",
    "rate_limit",
    "too many requests",
    "overloaded",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "service unavailable",
    "502",
    "503",
    "504",
    "connection reset",
    "connection aborted",
    "remote end closed",
)


def _is_transient(error: Exception) -> bool:
    """Return whether a model error is worth retrying."""

    text = f"{type(error).__name__}: {error}".lower()
    return any(marker in text for marker in _TRANSIENT_MARKERS)


def _infer_target_type(value: str) -> TargetType:
    """Infer a TargetType from a bare string the model supplied."""

    if "://" in value:
        return TargetType.URL
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    else:
        return TargetType.CIDR if "/" in value else TargetType.IP
    if "-" in value and value.count(".") >= 3:
        return TargetType.IP_RANGE
    return TargetType.DOMAIN if "." in value else TargetType.HOST


class LlmDecider(NextActionDecider):
    """Ask the configured LLM for the next action, validated against the catalog."""

    def __init__(
        self,
        llm_client: Any,
        tool_catalog: ToolCatalog,
        prompt_loader: PromptLoader | None = None,
        prompt_name: str = "next_action",
        max_attempts: int = 3,
        retry_backoff_seconds: float = 2.0,
    ) -> None:
        """Initialize the LLM decider.

        ``max_attempts``/``retry_backoff_seconds`` bound the retry of TRANSIENT model
        failures (rate limits, 5xx, timeouts). Tests set the backoff to 0 to stay fast.
        """

        self.llm_client = llm_client
        self.tool_catalog = tool_catalog
        self.prompt_loader = prompt_loader or PromptLoader()
        self.prompt_name = prompt_name
        self.max_attempts = max(1, int(max_attempts))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))

    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the next action chosen by the LLM.

        Re-proposing an action that already failed wastes a step and, after
        ``StopEvaluator.max_repeat_failures``, ends the mission. So a repeat is
        rejected once and the model is re-asked with the failed signature called
        out explicitly. If it insists, the action is returned anyway (flagged in
        metadata) rather than stopping the mission on the decider's behalf — the
        repeat guard is the loop's job, not the decider's.
        """

        if not getattr(self.llm_client, "enabled", False):
            return self._error("LLM client disabled")

        failed = state.failed_signatures

        action = self._ask(state, summary)
        if not self._repeats_failure(action, failed):
            return action

        retry = self._ask(state, summary, avoid=action)
        if self._repeats_failure(retry, failed):
            return replace(
                retry,
                metadata={**retry.metadata, "repeated_failed_signature": True},
            )
        return retry

    def _ask(
        self,
        state: MissionState,
        summary: StateSummary,
        avoid: ProposedAction | None = None,
    ) -> ProposedAction:
        """Ask the model once, optionally forbidding a specific repeat."""

        # The catalog goes in the SYSTEM prompt, not the per-call payload. It is
        # reference material that never changes during a mission, so putting it in the
        # cacheable prefix means it bills at cache-read rates after the first decision
        # instead of full input rate on all ~3k tokens every step.
        #
        # Still the COMPACT prompt text, not the full JSON dump: the JSON form of 36
        # tools / 105 actions is ~30.6k tokens and once blew a provider limit outright
        # ("Prompt tokens limit exceeded: 37223 > 30000").
        #
        # This only changes what the MODEL sees. `_validate_args` still checks against
        # the full ToolCatalog objects, so arg validation is unaffected.
        system_prompt = (
            f"{self._load_prompt()}\n\nAVAILABLE TOOLS\n{self.tool_catalog.to_prompt_text()}"
        )

        payload: dict[str, Any] = {
            "summary": summary.to_dict(),
            "autonomy_level": state.autonomy_level.value,
            "scope": state.scope.to_agent_context() if state.scope else None,
        }
        if avoid is not None:
            payload["rejected_action"] = {
                "tool_name": avoid.tool_name,
                "tool_action": avoid.tool_action,
                "args": avoid.args,
                "why_rejected": (
                    "This exact action already failed earlier in the mission and state "
                    "has not changed since. Choose a DIFFERENT tool, a different action, "
                    "or materially different args."
                ),
            }
        # Compact separators, not indent=2. Pretty-printing this payload cost ~1,350
        # tokens per decision in pure whitespace — measured on a 20-step mission state,
        # 14% of the whole prompt — and the model does not need the indentation to read
        # JSON. sort_keys stays so the payload is byte-stable for a given state, which
        # is what makes provider-side prompt caching possible at all.
        user_prompt = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)

        # Retry TRANSIENT model failures before giving up. A decider ERROR fails the
        # WHOLE mission (MissionLoop turns it into MissionRunStatus.FAILED), so a
        # single 429 mid-run used to destroy an otherwise-healthy engagement. Observed
        # live: two missions that passed individually both failed when the suite ran
        # them back-to-back and the provider rate-limited one call.
        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                raw = self.llm_client.complete_json(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    metadata={"component": "next_action_decider", "attempt": attempt + 1},
                )
            except Exception as exc:  # noqa: BLE001 - decider must never crash the loop
                last_error = exc
                if attempt + 1 >= self.max_attempts or not _is_transient(exc):
                    return self._error(f"LLM error: {exc}")
                time.sleep(self.retry_backoff_seconds * (2**attempt))
                continue
            break
        else:  # pragma: no cover - loop always breaks or returns above
            return self._error(f"LLM error: {last_error}")

        return self._parse(raw)

    @staticmethod
    def _repeats_failure(action: ProposedAction, failed_signatures: set[str]) -> bool:
        """Return whether this action is a known-failed action proposed again."""

        if action.kind != ActionKind.TOOL or not failed_signatures:
            return False
        signature = AttemptedAction(
            tool_name=action.tool_name or "",
            action=action.tool_action or "",
            args=action.args,
        ).signature
        return signature in failed_signatures

    def _parse(self, raw: dict[str, Any]) -> ProposedAction:
        if not isinstance(raw, dict):
            return self._stop("non-object LLM response")

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
        args = raw.get("args") if isinstance(raw.get("args"), dict) else {}
        errors = self._validate_args(tool_name, tool_action, args)
        if errors:
            return self._stop("; ".join(errors))

        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name=str(tool_name),
            tool_action=str(tool_action),
            args=args,
            agent_name=raw.get("agent_name"),
            target=self._parse_target(raw.get("target")),
            objective=str(raw.get("rationale") or f"Run {tool_name}.{tool_action}"),
            risk=RiskLevel.from_str(raw.get("risk")),
            requires_confirmation=bool(raw.get("requires_confirmation", False)),
            rationale=str(raw.get("rationale") or ""),
            expected_evidence=str(raw.get("expected_evidence") or ""),
            metadata={"category": str(raw.get("category") or ""), "llm_raw": raw},
        )

    @staticmethod
    def _parse_target(value: Any) -> Target | None:
        """Build the per-action Target the model wants to act on, or None.

        The loop's ``ActionExecutor`` falls back to ``state.target`` when this is
        None, so a model that says nothing keeps today's behaviour. Naming a
        host lets the mission pivot onto something recon discovered (a second
        box, a specific web service) instead of re-hitting the seed target
        forever. Safety is unchanged: ``RiskGate`` scope-checks
        ``action.target`` before anything runs, and refuses out-of-scope values.

        Returns None on anything unparseable rather than raising — a malformed
        target must not crash the loop, and falling back to the seed target is
        always in scope.
        """

        if not isinstance(value, str) or not value.strip():
            return None
        try:
            text = value.strip()
            return Target(type=_infer_target_type(text), value=text)
        except Exception:  # noqa: BLE001 - unparseable target falls back to state.target
            return None

    def _validate_args(self, tool_name: Any, action: Any, args: dict[str, Any]) -> list[str]:
        """Return a list of validation errors ([] = valid) for the proposed args."""

        spec = None
        for tool in self.tool_catalog.tools:
            if tool.name == tool_name:
                spec = next((a for a in tool.actions if a.action == action), None)
                break
        if spec is None:
            return [f"unknown tool/action: {tool_name}/{action}"]

        errors: list[str] = []
        known = {arg.name: arg for arg in spec.args}
        for name in args:
            if name not in known:
                errors.append(f"unknown arg: {name}")
        for arg in spec.args:
            if arg.required and args.get(arg.name) in (None, ""):
                errors.append(f"missing required arg: {arg.name}")
                continue
            if arg.name not in args or args[arg.name] is None:
                continue
            value = args[arg.name]
            if arg.type == "int" and not isinstance(value, int):
                errors.append(f"arg {arg.name} must be int")
            elif arg.type == "bool" and not isinstance(value, bool):
                errors.append(f"arg {arg.name} must be bool")
            elif arg.type == "list[str]" and not isinstance(value, list):
                errors.append(f"arg {arg.name} must be list[str]")
            elif arg.type == "enum" and arg.choices and value not in arg.choices:
                errors.append(f"arg {arg.name} must be one of {arg.choices}")
        return errors

    def _load_prompt(self) -> str:
        try:
            prompt = self.prompt_loader.load_agent_prompt(self.prompt_name)
            return getattr(prompt, "system_prompt", None) or str(prompt)
        except Exception:  # noqa: BLE001 - fall back to inline instruction
            return "Return one strict JSON decision using only tools from tool_catalog."

    @staticmethod
    def _stop(reason: str) -> ProposedAction:
        return ProposedAction(kind=ActionKind.STOP, objective="Stop mission.", rationale=reason)

    @staticmethod
    def _error(reason: str) -> ProposedAction:
        """Signal an unrecoverable decision error (LLM unreachable/misconfigured).

        Distinct from STOP: the loop maps this to a FAILED mission rather than a
        COMPLETED one, so a transient LLM/transport error never masquerades as a
        successful, empty mission.
        """

        return ProposedAction(kind=ActionKind.ERROR, objective="Decision failed.", rationale=reason)
