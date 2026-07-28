"""Decider-supplied args must not collide with explicit run() kwargs.

Regression: the LLM decider returned args like {"target": "dvwa", "ports": ...};
execute_tool passed target= explicitly AND again via **args, raising
'multiple values for keyword argument target' and failing every nmap scan.
Reserved keys the loop supplies explicitly (and scope-gates) must be stripped.
"""

from __future__ import annotations

from saber.agents.base_agent import BaseAgent


def test_safe_tool_args_strips_reserved_keys():
    got = BaseAgent._safe_tool_args(
        {"target": "dvwa", "session": 1, "action": "x", "metadata": {}, "ports": "1-1000"}
    )
    assert got == {"ports": "1-1000"}


def test_safe_tool_args_none_is_empty():
    assert BaseAgent._safe_tool_args(None) == {}


def test_safe_tool_args_keeps_non_reserved():
    got = BaseAgent._safe_tool_args({"url": "http://dvwa", "severity": "high"})
    assert got == {"url": "http://dvwa", "severity": "high"}
