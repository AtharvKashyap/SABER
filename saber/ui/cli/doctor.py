"""SABER CLI doctor checks."""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from saber.storage.connection import StorageConnection


@dataclass(frozen=True)
class DoctorCheck:
    """One doctor check result."""

    name: str
    status: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible check."""

        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class DoctorReport:
    """Doctor check report."""

    checks: list[DoctorCheck]

    def ok(self) -> bool:
        """Return whether all checks are OK or WARN."""

        return all(check.status in {"ok", "warn"} for check in self.checks)

    def has_failures(self) -> bool:
        """Return whether any check failed."""

        return any(check.status == "fail" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible report."""

        return {
            "ok": self.ok(),
            "has_failures": self.has_failures(),
            "checks": [check.to_dict() for check in self.checks],
        }


class SaberDoctor:
    """Run local SABER readiness checks."""

    DEFAULT_TOOLS = (
        "docker",
        "nmap",
        "nuclei",
        "whatweb",
        "searchsploit",
        "subfinder",
        "amass",
    )

    DEFAULT_PACKAGES = (
        "pydantic",
        "openpyxl",
        "jinja2",
        "reportlab",
        "fastapi",
        "uvicorn",
    )

    def __init__(
        self,
        db_path: str | Path = "runs/saber.db",
        evidence_dir: str | Path = "runs/evidence",
        reports_dir: str | Path = "runs/reports",
        tools: tuple[str, ...] | None = None,
        packages: tuple[str, ...] | None = None,
    ) -> None:
        """Initialize doctor."""

        self.db_path = Path(db_path)
        self.evidence_dir = Path(evidence_dir)
        self.reports_dir = Path(reports_dir)
        self.tools = tools if tools is not None else self.DEFAULT_TOOLS
        self.packages = packages if packages is not None else self.DEFAULT_PACKAGES

    def run(self) -> DoctorReport:
        """Run all doctor checks."""

        checks: list[DoctorCheck] = []
        checks.append(self.check_python_version())
        checks.append(self.check_storage())
        checks.append(self.check_writable_directory("Evidence directory", self.evidence_dir))
        checks.append(self.check_writable_directory("Reports directory", self.reports_dir))

        for package_name in self.packages:
            checks.append(self.check_python_package(package_name))

        for tool_name in self.tools:
            checks.append(self.check_executable(tool_name))

        return DoctorReport(checks=checks)

    def check_python_version(self) -> DoctorCheck:
        """Check Python version."""

        version = sys.version_info
        version_text = platform.python_version()

        if version >= (3, 11):
            return DoctorCheck(
                name="Python version",
                status="ok",
                message=f"Python {version_text}",
                metadata={"version": version_text},
            )

        return DoctorCheck(
            name="Python version",
            status="fail",
            message=f"Python {version_text}; SABER expects Python 3.11+.",
            metadata={"version": version_text},
        )

    def check_storage(self) -> DoctorCheck:
        """Check SQLite storage initialization."""

        try:
            connection = StorageConnection(self.db_path)
            connection.initialize()
            connection.close()
            return DoctorCheck(
                name="SQLite storage",
                status="ok",
                message=f"Storage initialized at {self.db_path}.",
                metadata={"db_path": str(self.db_path)},
            )
        except Exception as exc:
            return DoctorCheck(
                name="SQLite storage",
                status="fail",
                message=f"Storage initialization failed: {exc}",
                metadata={"db_path": str(self.db_path), "error_type": type(exc).__name__},
            )

    def check_writable_directory(self, name: str, directory: Path) -> DoctorCheck:
        """Check directory can be created and written."""

        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".saber_write_check"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return DoctorCheck(
                name=name,
                status="ok",
                message=f"{directory} is writable.",
                metadata={"path": str(directory)},
            )
        except Exception as exc:
            return DoctorCheck(
                name=name,
                status="fail",
                message=f"{directory} is not writable: {exc}",
                metadata={"path": str(directory), "error_type": type(exc).__name__},
            )

    def check_python_package(self, package_name: str) -> DoctorCheck:
        """Check Python package availability."""

        spec = importlib.util.find_spec(package_name)
        if spec:
            return DoctorCheck(
                name=f"Python package: {package_name}",
                status="ok",
                message=f"{package_name} is installed.",
                metadata={"package": package_name},
            )

        status = "warn" if package_name in {"fastapi", "uvicorn"} else "fail"
        return DoctorCheck(
            name=f"Python package: {package_name}",
            status=status,
            message=f"{package_name} is not installed.",
            metadata={"package": package_name},
        )

    def check_executable(self, executable: str) -> DoctorCheck:
        """Check executable availability."""

        path = shutil.which(executable)
        if path:
            return DoctorCheck(
                name=f"Executable: {executable}",
                status="ok",
                message=f"{executable} found at {path}.",
                metadata={"executable": executable, "path": path},
            )

        status = "warn"
        return DoctorCheck(
            name=f"Executable: {executable}",
            status=status,
            message=f"{executable} was not found on PATH.",
            metadata={"executable": executable, "path": os.environ.get("PATH", "")},
        )


def format_doctor_report(report: DoctorReport) -> str:
    """Format doctor report for terminal output."""

    lines = ["SABER Doctor", ""]

    for check in report.checks:
        label = {
            "ok": "OK",
            "warn": "WARN",
            "fail": "FAIL",
        }.get(check.status, check.status.upper())
        lines.append(f"[{label}] {check.name}: {check.message}")

    lines.append("")
    lines.append("Result: PASS" if report.ok() else "Result: FAIL")
    return "\n".join(lines)


def run_doctor(
    db_path: str | Path = "runs/saber.db",
    evidence_dir: str | Path = "runs/evidence",
    reports_dir: str | Path = "runs/reports",
) -> DoctorReport:
    """Run doctor checks."""

    return SaberDoctor(
        db_path=db_path,
        evidence_dir=evidence_dir,
        reports_dir=reports_dir,
    ).run()
