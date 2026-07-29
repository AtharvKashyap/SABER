"""Shared test catalog builder.

Since F0.4, ``ToolCatalog.from_registry`` generates entries only from wrapper
``CONTRACT``s. Until the wrappers carry contracts (F1+), the default registry
yields an empty catalog, so tests that need known tool/actions build an
explicit catalog here that mirrors the shape contracts will produce.
"""

from __future__ import annotations

from saber.core.tool_catalog import ToolActionSpec, ToolCatalog, ToolSpec
from saber.tools.contract import ArgSpec


def build_test_catalog() -> ToolCatalog:
    """Return a representative catalog covering the tools exercised by tests."""

    return ToolCatalog(
        [
            ToolSpec(
                name="nmap",
                category="recon",
                phase="recon",
                description="Network discovery and service enumeration.",
                actions=[
                    ToolActionSpec(
                        tool_name="nmap",
                        action="service_scan",
                        description="TCP service discovery and version detection.",
                        risk="low",
                        requires_approval=False,
                        example_args={"target": "127.0.0.1", "ports": "1-1000"},
                        args=(
                            ArgSpec(name="target", type="str", required=True),
                            ArgSpec(name="ports", type="str", required=False),
                        ),
                    ),
                    ToolActionSpec(
                        tool_name="nmap",
                        action="udp_scan",
                        description="UDP service discovery.",
                        risk="medium",
                        requires_approval=True,
                        example_args={"target": "127.0.0.1", "ports": "top-100"},
                    ),
                ],
            ),
            ToolSpec(
                name="nuclei",
                category="web",
                phase="recon",
                description="Template-based vulnerability scanning.",
                actions=[
                    ToolActionSpec(
                        tool_name="nuclei",
                        action="template_scan",
                        description="Template-based vulnerability scanning.",
                        risk="medium",
                        requires_approval=True,
                        example_args={"target": "http://127.0.0.1"},
                    ),
                ],
            ),
            ToolSpec(
                name="sqlmap",
                category="web",
                phase="exploitation",
                description="SQL injection testing.",
                actions=[
                    ToolActionSpec(
                        tool_name="sqlmap",
                        action="injection_test",
                        description="SQL injection validation.",
                        risk="high",
                        requires_approval=True,
                        example_args={"url": "http://127.0.0.1/item?id=1"},
                    ),
                ],
            ),
            ToolSpec(
                name="mimikatz",
                category="post_exploitation",
                phase="exploitation",
                description="Credential material inspection workflow.",
                actions=[
                    ToolActionSpec(
                        tool_name="mimikatz",
                        action="credential_dump",
                        description="Dump credential material from an approved host.",
                        risk="high",
                        requires_approval=True,
                    ),
                ],
            ),
            ToolSpec(
                name="impacket",
                category="active_directory",
                phase="exploitation",
                description="Impacket AD and Windows protocol utilities.",
                actions=[
                    ToolActionSpec(
                        tool_name="impacket",
                        action="secretsdump",
                        description="Remote secrets extraction.",
                        risk="high",
                        requires_approval=True,
                    ),
                ],
            ),
            ToolSpec(
                name="hashcat",
                category="password_cracking",
                phase="exploitation",
                description="Hashcat password hash auditing.",
                actions=[
                    ToolActionSpec(
                        tool_name="hashcat",
                        action="crack",
                        description="Crack captured password hashes.",
                        risk="high",
                        requires_approval=True,
                    ),
                ],
            ),
        ]
    )
