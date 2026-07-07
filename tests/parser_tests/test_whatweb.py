"""Tests for WhatWebParser."""

from __future__ import annotations

from saber.parsers.whatweb import WhatWebParser


class TestWhatWebParser:
    """Validate WhatWeb parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = WhatWebParser().parse_text("")

        assert result.success is False
        assert result.errors == ["WhatWeb output is empty."]

    def test_parse_json(self) -> None:
        """WhatWeb JSON should produce web technology observation."""

        data = [
            {
                "target": "https://example.com",
                "plugins": {
                    "HTTPStatus": {"string": ["200"]},
                    "Title": {"string": ["Example"]},
                    "HTTPServer": {"string": ["nginx"]},
                    "nginx": {"version": ["1.18.0"]},
                    "WordPress": {"version": ["6.0"]},
                },
            }
        ]

        result = WhatWebParser().parse_json(data)

        assert result.success is True
        assert len(result.observations) == 1

        observation = result.observations[0]
        assert observation.kind == "web_technology"
        assert observation.data["url"] == "https://example.com"
        assert observation.data["status"] == 200
        assert observation.data["title"] == "Example"
        assert observation.data["server"] == "nginx"
        assert "nginx" in observation.data["technologies"]
        assert "WordPress" in observation.data["technologies"]
        assert "1.18.0" in observation.data["technologies"]

    def test_parse_json_text(self) -> None:
        """JSON text should route to parse_json."""

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
        assert result.observations[0].data["server"] == "Apache"

    def test_parse_stdout(self) -> None:
        """Stdout should produce observation."""

        text = "https://example.com [200 OK] HTTPServer[nginx] Title[Example] WordPress[6.0]"

        result = WhatWebParser().parse_text(text)

        assert result.success is True
        assert result.metadata["format"] == "stdout"
        assert result.observations[0].data["url"] == "https://example.com"
        assert result.observations[0].data["status"] == 200
        assert result.observations[0].data["title"] == "Example"
        assert result.observations[0].data["server"] == "nginx"
        assert "HTTPServer" in result.observations[0].data["technologies"]
        assert "WordPress" in result.observations[0].data["technologies"]

    def test_parse_json_without_useful_records_fails(self) -> None:
        """JSON without target/tech should fail."""

        result = WhatWebParser().parse_json([{"plugins": {}}])

        assert result.success is False
        assert result.errors == ["No WhatWeb JSON observations could be parsed."]
