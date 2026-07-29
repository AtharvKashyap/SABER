from pathlib import Path

from saber.parsers.whatweb import WhatWebParser

from tests.conftest import merge_observations


def test_dvwa_whatweb_grows_technologies_and_services():
    text = Path("tests/fixtures/sample_whatweb_output.json").read_text()
    result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})
    obs = [o.to_dict() for o in result.observations]
    state = merge_observations(obs, tool="whatweb", action="fingerprint")
    assert len(state.technologies) > 0  # was 0 pre-F1 (spec §2.3)
    assert len(state.services) > 0
