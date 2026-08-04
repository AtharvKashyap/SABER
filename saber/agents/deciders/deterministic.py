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
        if (
            fingerprinted_hosts
            and not state.vulns
            and not state.metadata.get("web_scanned")
            and ("nuclei", "template_scan") not in attempted
        ):
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
            if svc is not None and ("searchsploit", "exploit_search") not in attempted:
                # SearchSploit declares exploit_search/cve_search/copy_exploit and takes
                # a free-form `query`. This rung used to propose `lookup` with
                # product/version, so it raised "Unsupported SearchSploit action" every
                # time it was reached and the mission never got exploit intel.
                return ProposedAction(
                    kind=ActionKind.TOOL,
                    tool_name="searchsploit",
                    tool_action="exploit_search",
                    args={"query": f"{svc.product} {svc.version}".strip()},
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
