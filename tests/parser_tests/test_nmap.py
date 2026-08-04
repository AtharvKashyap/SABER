"""Tests for NmapParser."""

from __future__ import annotations

from pathlib import Path

from saber.parsers.nmap import NmapParser

from tests.conftest import assert_observation, merge_observations

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web01.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapParser:
    """Validate Nmap parser."""

    def test_empty_output_fails(self) -> None:
        """Empty output should fail."""

        result = NmapParser().parse_text("")

        assert result.success is False
        assert result.errors == ["Nmap output is empty."]

    def test_parse_xml_host_and_services(self) -> None:
        """XML should produce host and service observations."""

        result = NmapParser().parse_text(NMAP_XML)

        assert result.success is True
        assert result.metadata["format"] == "xml"
        assert len(result.observations) == 3

        host = result.observations[0]
        service = result.observations[1]

        assert host.kind == "host"
        assert host.data["host"] == "10.0.0.5"
        assert host.data["state"] == "up"
        assert host.data["hostnames"] == ["web01.local"]

        assert service.kind == "service"
        assert service.data["host"] == "10.0.0.5"
        assert service.data["port"] == 80
        assert service.data["protocol"] == "tcp"
        assert service.data["state"] == "open"
        assert service.data["service"] == "http"
        assert service.data["product"] == "nginx"
        assert service.data["version"] == "1.18.0"
        assert service.data["cpes"] == ["cpe:/a:nginx:nginx:1.18.0"]

    def test_invalid_xml_fails(self) -> None:
        """Invalid XML should fail."""

        result = NmapParser().parse_text("<nmaprun>")

        assert result.success is False
        assert "Invalid Nmap XML" in result.errors[0]

    def test_parse_stdout(self) -> None:
        """Stdout should produce host and service observations."""

        text = """
Nmap scan report for example.com (10.0.0.5)
Host is up.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9
80/tcp open  http    nginx
"""
        result = NmapParser().parse_text(text)

        assert result.success is True
        assert result.metadata["format"] == "stdout"
        assert result.observations[0].kind == "host"
        assert result.observations[0].data["host"] == "10.0.0.5"
        assert result.observations[1].kind == "service"
        assert result.observations[1].data["port"] == 22
        assert result.observations[1].data["service"] == "ssh"
        assert result.observations[2].data["port"] == 80

    def test_parse_unrecognized_stdout_fails(self) -> None:
        """Unrecognized stdout should fail."""

        result = NmapParser().parse_text("no useful content")

        assert result.success is False
        assert result.errors == ["No Nmap observations could be parsed."]

    def test_parse_json_records(self) -> None:
        """JSON records should produce host observations."""

        result = NmapParser().parse_json(
            [
                {"host": "10.0.0.5", "state": "up"},
                {"ip": "10.0.0.6", "state": "up"},
            ]
        )

        assert result.success is True
        assert len(result.observations) == 2
        assert result.observations[0].data["host"] == "10.0.0.5"
        assert result.observations[1].data["ip"] == "10.0.0.6"

    def test_parse_json_without_hosts_fails(self) -> None:
        """JSON without host records should fail."""

        result = NmapParser().parse_json({"not_hosts": []})

        assert result.success is False
        assert result.errors == ["No Nmap JSON observations could be parsed."]


def test_nmap_xml_emits_host_and_service_and_grows_state() -> None:
    """Fixture XML yields canonical host/service observations that grow state."""

    text = Path("tests/fixtures/sample_nmap_output.xml").read_text()
    result = NmapParser().parse_text(text)
    obs = [o.to_dict() for o in result.observations]
    hosts = [o for o in obs if o["kind"] == "host"]
    services = [o for o in obs if o["kind"] == "service"]
    assert hosts and services
    assert_observation(
        services[0], kind="service", data_subset={"host": hosts[0]["data"]["address"]}
    )
    state = merge_observations(obs, tool="nmap", action="service_scan")
    assert len(state.services) >= 1
    assert len(state.hosts) >= 1
