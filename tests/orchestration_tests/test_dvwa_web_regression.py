"""Permanent guard for the original whatweb/dvwa normalization defect.

The live failure this commemorates: a real dvwa run had whatweb SUCCEED 13 times and
emit 78 observations, yet ``MissionState.technologies`` stayed at 0 — the parser did
not really parse whatweb output, and ``StateMerger`` silently dropped its
non-canonical ``web_technology`` kind.

This file used to assert only ``len(...) > 0``, which any garbage satisfies: mutating
the parser to emit ``name="MUTANT"``, ``port=9999`` left this test green while three
tests in test_whatweb.py failed. The file named after the incident guarded nothing.
It now asserts the actual VALUES, so a parser that emits the wrong content fails here.
"""

from pathlib import Path

from saber.parsers.whatweb import WhatWebParser

from tests.conftest import merge_observations


def _state():
    text = Path("tests/fixtures/sample_whatweb_output.json").read_text()
    result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})
    observations = [o.to_dict() for o in result.observations]
    return merge_observations(observations, tool="whatweb", action="fingerprint")


def test_dvwa_whatweb_grows_technologies_with_real_names():
    state = _state()

    assert len(state.technologies) > 0, "was 0 pre-F1 (spec §2.3)"
    names = {technology.name for technology in state.technologies}
    # The fingerprint must be the real stack, not merely non-empty.
    assert {"Apache", "PHP"} <= names, f"expected Apache and PHP, got {sorted(names)}"


def test_dvwa_whatweb_technologies_are_attributed_to_the_host():
    state = _state()

    for technology in state.technologies:
        assert technology.host, f"{technology.name} has no host; it cannot be correlated"


def test_dvwa_whatweb_grows_a_service_on_the_real_port():
    state = _state()

    assert len(state.services) > 0
    ports = {(service.port, service.service) for service in state.services}
    assert (80, "http") in ports, f"expected 80/http, got {sorted(ports)}"


def test_dvwa_whatweb_reports_a_version_for_at_least_one_technology():
    """Version data is what feeds searchsploit/CVE correlation downstream."""

    state = _state()

    versioned = [t for t in state.technologies if t.version]
    assert versioned, "no technology carried a version; CVE correlation has no input"
