"""Tests for WhatWebParser."""

from __future__ import annotations

from pathlib import Path

from saber.parsers.whatweb import WhatWebParser

from tests.conftest import assert_observation, merge_observations


def test_whatweb_emits_one_technology_per_tech_with_host_and_grows_state():
    """Permanent regression: one canonical `technology` per tech + a `service`."""

    text = Path("tests/fixtures/sample_whatweb_output.json").read_text()
    result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})
    obs = [o.to_dict() for o in result.observations]
    techs = [o for o in obs if o["kind"] == "technology"]
    assert len(techs) >= 2  # e.g. Apache, PHP
    for t in techs:
        assert t["data"]["host"] == "127.0.0.1"
        assert t["data"]["name"]
    apache = next(t for t in techs if t["data"]["name"] == "Apache")
    assert_observation(
        apache, kind="technology", data_subset={"host": "127.0.0.1", "version": "2.4.7"}
    )
    state = merge_observations(obs, tool="whatweb", action="fingerprint")
    assert len(state.technologies) >= 2
    assert len(state.services) >= 1  # HTTP service on port 80


class TestWhatWebParser:
    """Validate WhatWeb parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = WhatWebParser().parse_text("")

        assert result.success is False
        assert result.errors == ["WhatWeb output is empty."]

    def test_parse_json_emits_per_tech_technologies(self) -> None:
        """WhatWeb JSON yields one `technology` per tech (was one `web_technology` blob)."""

        data = [
            {
                "target": "https://example.com",
                "plugins": {
                    "HTTPStatus": {"string": ["200"]},
                    "Title": {"string": ["Example"]},
                    "HTTPServer": {"string": ["nginx/1.18.0"]},
                    "nginx": {"version": ["1.18.0"]},
                    "WordPress": {"version": ["6.0"]},
                },
            }
        ]

        result = WhatWebParser().parse_json(data)

        assert result.success is True
        techs = [o for o in result.observations if o.kind == "technology"]
        names = {t.data["name"] for t in techs}
        assert "nginx" in names
        assert "WordPress" in names
        nginx = next(t for t in techs if t.data["name"] == "nginx")
        assert nginx.data["host"] == "example.com"
        assert nginx.data["version"] == "1.18.0"
        # Ignored plugins must not become technologies.
        assert "Title" not in names
        assert "HTTPStatus" not in names

    def test_parse_json_text(self) -> None:
        """JSON text should route to parse_json and emit a service on the HTTP port."""

        text = """
[
  {
    "target": "https://example.com",
    "plugins": {
      "HTTPStatus": {"string": ["200"]},
      "HTTPServer": {"string": ["Apache"]}
    }
  }
]
"""

        result = WhatWebParser().parse_text(text)

        assert result.success is True
        services = [o for o in result.observations if o.kind == "service"]
        assert services
        assert services[0].data["host"] == "example.com"
        assert services[0].data["port"] == 443
        assert services[0].data["product"] == "Apache"

    def test_parse_stdout_emits_per_tech_technologies(self) -> None:
        """Stdout fallback should emit per-tech `technology` observations (host from metadata)."""

        text = "http://127.0.0.1 [200 OK] HTTPServer[nginx] Title[Example] WordPress[6.0]"

        result = WhatWebParser().parse_text(text, metadata={"target": "http://127.0.0.1"})

        assert result.success is True
        assert result.metadata["format"] == "stdout"
        techs = [o for o in result.observations if o.kind == "technology"]
        names = {t.data["name"] for t in techs}
        assert "WordPress" in names
        for t in techs:
            assert t.data["host"] == "127.0.0.1"

    def test_parse_json_without_useful_records_fails(self) -> None:
        """JSON without target/tech should fail."""

        result = WhatWebParser().parse_json([{"plugins": {}}])

        assert result.success is False
        assert result.errors == ["No WhatWeb JSON observations could be parsed."]
