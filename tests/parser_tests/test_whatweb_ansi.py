"""WhatWeb colours its stdout, and none of it belongs in mission state.

Captured live against the lab: whatweb wrote
``\x1b[1mApache\x1b[0m[\x1b[1m\x1b[32m2.4.25\x1b[0m]`` and the parser, which strips
nothing, recorded a technology literally named ``0m`` with version
``\x1b[1m\x1b[32m2.4.25\x1b[0m``. That lands in MissionState, the console, and the
client report.
"""

from __future__ import annotations

from saber.parsers.whatweb import WhatWebParser

# One real line of whatweb output, escapes and all.
LIVE_LINE = (
    "\x1b[1m\x1b[34mhttp://172.21.0.4:80\x1b[0m [302 Found] "
    "\x1b[1mApache\x1b[0m[\x1b[1m\x1b[32m2.4.25\x1b[0m], "
    "\x1b[1mHTTPServer\x1b[0m[\x1b[1m\x1b[31mDebian Linux\x1b[0m]"
    "[\x1b[1m\x1b[36mApache/2.4.25 (Debian)\x1b[0m], "
    "\x1b[1mPHP\x1b[0m, "
    "\x1b[1mIP\x1b[0m[\x1b[0m\x1b[22m172.21.0.4\x1b[0m]"
)


def _observations():
    return WhatWebParser().parse_text(LIVE_LINE, {"target": "172.21.0.4"}).observations


def test_no_observation_carries_an_escape_sequence() -> None:
    for observation in _observations():
        blob = repr((observation.summary, observation.data, observation.metadata))
        assert "\\x1b" not in blob, f"ANSI escape survived into {observation.kind}: {blob}"


def test_technology_names_are_real_names_not_colour_codes() -> None:
    names = {
        observation.data.get("name")
        for observation in _observations()
        if observation.kind == "technology"
    }

    assert "Apache" in names
    assert "PHP" in names
    # "0m" is the tail of an escape sequence, never a technology.
    assert "0m" not in names
    assert not any(name and name.startswith("[") for name in names)


def test_version_is_extracted_cleanly() -> None:
    versions = {
        observation.data.get("name"): observation.data.get("version")
        for observation in _observations()
        if observation.kind == "technology"
    }

    assert versions.get("Apache") == "2.4.25"


def test_plain_output_without_colour_still_parses() -> None:
    """The strip must not disturb output that was never coloured."""

    plain = "http://172.21.0.4:80 [302 Found] Apache[2.4.25], PHP"
    names = {
        observation.data.get("name")
        for observation in WhatWebParser().parse_text(plain, {}).observations
        if observation.kind == "technology"
    }

    assert "Apache" in names
    assert "PHP" in names


def test_response_attributes_are_not_recorded_as_technologies() -> None:
    """Cookies and password fields describe the response, not the stack."""

    line = (
        "http://172.21.0.4:80 [200 OK] Apache[2.4.25], "
        "Cookies[PHPSESSID,security], PasswordField[password], DVWA"
    )
    names = {
        observation.data.get("name")
        for observation in WhatWebParser().parse_text(line, {}).observations
        if observation.kind == "technology"
    }

    assert {"Apache", "DVWA"} <= names
    assert "Cookies" not in names
    assert "PasswordField" not in names
