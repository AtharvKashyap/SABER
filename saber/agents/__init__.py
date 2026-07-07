"""Agent package for SABER.

Agents are orchestration components. They decide what should happen next, but
they do not execute shell commands directly. Tool execution flows through:

    Agent -> ToolRegistry -> ToolWrapper -> Sandbox -> Evidence/Result pipeline

Agent modules can be imported directly, for example:

    from saber.agents.base_agent import BaseAgent, AgentContext

This package intentionally avoids eager imports to reduce circular import risk.
"""

__all__: list[str] = []
