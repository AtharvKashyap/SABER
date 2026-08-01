"""The human-readable report must show what the mission actually learned.

Found by reading a real generated report: a mission that discovered 2 hosts, 2
services and 1 technology produced a technical report saying "No reportable findings"
with an all-zero severity table, and an "Observations" section that was just a dump of
tool calls. The F9 adapter's methodology / attack_chain / access / collected data was
present in document.metadata but the renderer never passed it to the template.
"""

from saber.reporting.json_exporter import JsonExporter
from saber.reporting.pdf_exporter import PdfExporter


def _document():
    return JsonExporter().build_document(
        report_id="report_test",
        mission_name="Lab web mission",
        target="dvwa",
        findings=[],
        observations=[],
        metadata={
            "mission_state": {
                "methodology": [
                    {
                        "phase": "recon",
                        "reached": True,
                        "completed": True,
                        "evidence": "1 host(s), 1 service(s) discovered",
                    },
                    {"phase": "exploitation", "reached": False, "completed": False,
                     "evidence": None},
                ],
                "attack_chain": [
                    {"step": "reconnaissance", "detail": "Identified 1 host(s)."},
                    {"step": "foothold_established", "detail": "Access on 10.0.0.5."},
                ],
                "hosts": [{"address": "172.21.0.2", "hostnames": ["dvwa"], "os": None}],
                "services": [
                    {
                        "host": "172.21.0.2",
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "product": "Apache httpd",
                        "version": "2.4.25",
                    }
                ],
                "technologies": [{"host": "dvwa", "name": "PHP", "version": "5.6"}],
                "access": {
                    "sessions": [
                        {"host": "10.0.0.5", "kind": "shell", "user": "www",
                         "privilege": "user"}
                    ],
                    "credentials": [
                        {"username": "svc", "kind": "password", "host": "10.0.0.5",
                         "service": "smb", "validated": True, "secret": "***redacted***"}
                    ],
                    "accounts": [],
                    "shares": [],
                },
                "collected": {
                    "flags": [{"value": "flag{owned}", "location": "/root/flag.txt"}],
                    "loot": [],
                },
            }
        },
    )


def _markdown() -> str:
    return PdfExporter().render_markdown(_document())


def test_methodology_table_is_rendered_with_its_evidence():
    text = _markdown()
    assert "## Methodology (PTES)" in text
    assert "recon" in text
    assert "1 host(s), 1 service(s) discovered" in text


def test_attack_chain_is_rendered_in_order():
    text = _markdown()
    assert "## Attack Chain" in text
    assert text.index("reconnaissance") < text.index("foothold_established")


def test_recon_results_include_product_and_version():
    """Proves the nmap -oX fix reaches the deliverable, not just state."""

    text = _markdown()
    assert "## Reconnaissance Results" in text
    assert "172.21.0.2" in text
    assert "Apache httpd" in text and "2.4.25" in text
    assert "PHP" in text


def test_access_obtained_section_is_rendered():
    text = _markdown()
    assert "## Access Obtained" in text
    assert "shell" in text
    assert "svc" in text


def test_credential_secrets_stay_redacted_in_the_rendered_report():
    text = _markdown()
    assert "***redacted***" in text or "redacted" in text


def test_flags_are_rendered_as_the_deliverable():
    text = _markdown()
    assert "## Material Collected" in text
    assert "flag{owned}" in text


def test_an_empty_mission_state_renders_without_those_sections():
    """Back-compat: old snapshots have none of these keys and must not break."""

    document = JsonExporter().build_document(
        report_id="r", mission_name="m", target="t",
        findings=[], observations=[], metadata={},
    )
    text = PdfExporter().render_markdown(document)

    assert "## Methodology (PTES)" not in text
    assert "## Attack Chain" not in text
    assert "SABER Technical Report" in text
