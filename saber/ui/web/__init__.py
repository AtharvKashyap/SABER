"""SABER web UI package.

The web UI exposes read-heavy mission visibility, finding review, report
generation, approval visibility, and graph/session APIs.

Web modules should not run tools directly, parse raw tool output, or make agent
decisions. They read from storage and call reporting/export helpers.
"""

__all__: list[str] = []
