"""Nuclei colours its stdout, and the colouring hides the severity.

Captured live against the lab. Nuclei wrote
``[\x1b[92mcookies-without-httponly\x1b[0m] [\x1b[94mjavascript\x1b[0m]
[\x1b[34minfo\x1b[0m] 172.21.0.4:80`` and the parser, which strips nothing,
produced a finding titled ``[92mcookies-without-httponly [0m`` with severity
``unknown``. Twenty-one findings landed in the report that way: unreadable
titles, and every severity lost even though nuclei had reported it.
"""

from __future__ import annotations

from saber.parsers.nuclei import NucleiParser

LIVE_STDOUT = (
    "[\x1b[92mcookies-without-httponly\x1b[0m] [\x1b[94mjavascript\x1b[0m] "
    "[\x1b[34minfo\x1b[0m] 172.21.0.4:80\n"
    "[\x1b[92mapache-detect\x1b[0m] [\x1b[94mhttp\x1b[0m] "
    "[\x1b[34mlow\x1b[0m] http://172.21.0.4:80\n"
)


def _observations():
    return NucleiParser().parse_text(LIVE_STDOUT, {"target": "172.21.0.4"}).observations


def test_no_observation_carries_an_escape_or_its_residue() -> None:
    for observation in _observations():
        blob = repr((observation.summary, observation.data, observation.metadata))
        assert "\\x1b" not in blob, f"escape survived: {blob}"
        # The ESC byte is sometimes lost in transit, leaving a bare "[92m".
        assert "[92m" not in blob and "[0m" not in blob, f"colour residue survived: {blob}"


def test_template_ids_are_clean() -> None:
    names = {observation.data.get("title") for observation in _observations()}

    assert "cookies-without-httponly" in names
    assert "apache-detect" in names


def test_severity_survives_the_colouring() -> None:
    """Severity is the whole point of a nuclei finding; it must not be lost."""

    severities = {
        observation.data.get("title"): observation.data.get("severity")
        for observation in _observations()
    }

    assert severities.get("cookies-without-httponly") == "info"
    assert severities.get("apache-detect") == "low"


def test_uncoloured_output_still_parses() -> None:
    plain = "[apache-detect] [http] [low] http://172.21.0.4:80"
    observations = NucleiParser().parse_text(plain, {}).observations

    assert observations
    assert observations[0].data.get("severity") == "low"
