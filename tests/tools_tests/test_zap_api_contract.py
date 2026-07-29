"""Golden build_command tests for the ZAP API CONTRACT."""

from __future__ import annotations

from saber.models.target import Target, TargetType
from saber.tools.web.zap_api import ZAPApiWrapper


def test_baseline_scan_command():
    wrapper = ZAPApiWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="baseline_scan")
    assert cmd.command == ["zap-baseline.py", "-t", "127.0.0.1"]
    assert cmd.action == "baseline_scan"


def test_spider_command():
    wrapper = ZAPApiWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="spider", zap_url="http://127.0.0.1:8080")
    assert cmd.command == [
        "zap-cli",
        "--zap-url",
        "http://127.0.0.1:8080",
        "spider",
        "127.0.0.1",
    ]
    assert cmd.action == "spider"


def test_active_scan_command():
    wrapper = ZAPApiWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(target, action="active_scan", zap_url="http://127.0.0.1:8080")
    assert cmd.command == [
        "zap-cli",
        "--zap-url",
        "http://127.0.0.1:8080",
        "active-scan",
        "127.0.0.1",
    ]
    assert cmd.action == "active_scan"
    assert cmd.requires_explicit_authorization is True


def test_export_report_command():
    wrapper = ZAPApiWrapper(sandbox=None)
    target = Target(type=TargetType.IP, value="127.0.0.1")
    cmd = wrapper.build_command(
        target,
        action="export_report",
        report_file="/evidence/zap_report.html",
        zap_url="http://127.0.0.1:8080",
    )
    assert cmd.command == [
        "zap-cli",
        "--zap-url",
        "http://127.0.0.1:8080",
        "report",
        "-f",
        "html",
        "-o",
        "/evidence/zap_report.html",
    ]
    assert cmd.action == "export_report"
