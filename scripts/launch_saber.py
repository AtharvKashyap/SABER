"""SABER operator launcher.

This is the user-facing launcher behind ./run_saber.

Responsibilities:
- load .env
- check Docker when docker sandbox mode is enabled
- optionally install Docker Desktop on macOS
- start Docker Desktop when installed but stopped
- pull or build the sandbox image
- start the web UI
- open the browser automatically
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_UI_PATH = "/ui"
# Kept as a literal, not imported from saber.core: this launcher runs before the
# package is guaranteed importable (it is what checks the venv). Must stay in step
# with DEFAULT_SHARED_IMAGE in saber/core/docker_runner.py — a test pins that.
DEFAULT_IMAGE = "saber-sandbox:local"
LOCAL_BUILD_IMAGE = "saber/sandbox:kali-last-release"


@dataclass(frozen=True)
class LaunchConfig:
    """Resolved launch config."""

    host: str
    port: int
    open_browser: bool
    build_image: bool
    install_docker: bool
    no_pull: bool
    backend: str
    image: str

    @property
    def ui_url(self) -> str:
        """Return UI URL."""

        return f"http://{self.host}:{self.port}{DEFAULT_UI_PATH}"


def main(argv: list[str] | None = None) -> int:
    """Run launcher."""

    args = parse_args(argv)
    load_dotenv(REPO_ROOT / ".env")

    config = LaunchConfig(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        build_image=args.build_image,
        install_docker=args.install_docker,
        no_pull=args.no_pull,
        backend=os.getenv("SABER_SANDBOX_BACKEND", "docker").strip().lower(),
        image=os.getenv("SABER_SANDBOX_IMAGE", DEFAULT_IMAGE).strip() or DEFAULT_IMAGE,
    )

    print_banner()
    print(f"[+] Repository: {REPO_ROOT}")
    print(f"[+] UI: {config.ui_url}")
    print(f"[+] Sandbox backend: {config.backend}")

    if config.backend == "docker":
        prepare_docker(config)

    ensure_uvicorn_available()

    return start_ui(config)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse launcher args."""

    parser = argparse.ArgumentParser(description="Launch SABER UI.")
    parser.add_argument("--host", default=os.getenv("SABER_UI_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("SABER_UI_PORT", str(DEFAULT_PORT))))
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically.")
    parser.add_argument(
        "--build-image",
        action="store_true",
        help="Build the sandbox image locally if it is missing.",
    )
    parser.add_argument(
        "--install-docker",
        action="store_true",
        help="Install Docker Desktop on macOS using Homebrew, then start it.",
    )
    parser.add_argument(
        "--no-pull",
        action="store_true",
        help="Do not pull the shared sandbox image if missing.",
    )
    return parser.parse_args(argv)


def print_banner() -> None:
    """Print startup banner."""

    print("")
    print("SABER")
    print("Scoped Automated Breach, Exploitation & Reporting")
    print("")


def load_dotenv(path: Path) -> dict[str, str]:
    """Load simple KEY=VALUE entries from .env without overriding existing environment."""

    loaded: dict[str, str] = {}

    if not path.exists():
        print("[!] .env not found. Using environment/defaults.")
        print("    Tip: cp .env.example .env")
        return loaded

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = clean_env_value(value.strip())

        if not key:
            continue

        loaded[key] = value
        os.environ.setdefault(key, value)

    print(f"[+] Loaded .env: {path}")
    return loaded


def clean_env_value(value: str) -> str:
    """Clean quoted env value."""

    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        return value[1:-1]
    return value


def prepare_docker(config: LaunchConfig) -> None:
    """Prepare Docker for SABER."""

    if shutil.which("docker") is None:
        if config.install_docker:
            install_docker_desktop()
        else:
            raise SystemExit(docker_missing_message())

    if not docker_daemon_running():
        start_docker_daemon()

    wait_for_docker_daemon()

    print("[+] Docker available")
    ensure_sandbox_image(
        config.image,
        build=config.build_image,
        pull=not config.no_pull,
    )


def docker_missing_message() -> str:
    """Return Docker missing help text."""

    return """[-] Docker CLI was not found.

Install Docker Desktop, then retry:

  macOS:
    brew install --cask docker
    open -a Docker

Or let SABER try on macOS:

  ./run_saber --install-docker

Temporary fallback without Docker:

  Set SABER_SANDBOX_BACKEND=local in .env
"""


def install_docker_desktop() -> None:
    """Install Docker Desktop on macOS using Homebrew."""

    if platform.system() != "Darwin":
        raise SystemExit(
            "[-] --install-docker is currently supported only on macOS with Homebrew."
        )

    if shutil.which("brew") is None:
        raise SystemExit(
            "[-] Homebrew was not found. Install Homebrew or Docker Desktop manually."
        )

    print("[+] Installing Docker Desktop with Homebrew")
    result = subprocess.run(
        ["brew", "install", "--cask", "docker"],
        cwd=REPO_ROOT,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise SystemExit("[-] Docker Desktop installation failed.")

    print("[+] Docker Desktop installed")


def docker_daemon_running() -> bool:
    """Return whether Docker daemon is reachable."""

    result = subprocess.run(
        ["docker", "info"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode == 0


def start_docker_daemon() -> None:
    """Try to start Docker daemon/Desktop."""

    if platform.system() == "Darwin":
        print("[+] Docker daemon is not running. Starting Docker Desktop...")
        subprocess.run(
            ["open", "-a", "Docker"],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return

    raise SystemExit(
        "[-] Docker is installed but the daemon is not running. Start Docker and retry."
    )


def wait_for_docker_daemon(timeout_seconds: int = 90) -> None:
    """Wait for Docker daemon to become available."""

    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        if docker_daemon_running():
            return

        print("[+] Waiting for Docker daemon...")
        time.sleep(3)

    raise SystemExit("[-] Timed out waiting for Docker daemon.")


def ensure_sandbox_image(image: str, *, build: bool, pull: bool) -> None:
    """Ensure sandbox image exists, pulling or building when requested."""

    if docker_image_exists(image):
        print(f"[+] Sandbox image found: {image}")
        return

    print(f"[!] Sandbox image missing: {image}")

    if pull:
        if pull_sandbox_image(image):
            print(f"[+] Pulled sandbox image: {image}")
            return

        print("[!] Could not pull shared sandbox image.")

    if build:
        build_sandbox_image(image)
        return

    print("")
    print("Options:")
    print("  Pull shared image:")
    print(f"    docker pull {image}")
    print("")
    print("  Build local image:")
    print("    ./run_saber --build-image")
    print("")
    print("  Use local backend temporarily:")
    print("    Set SABER_SANDBOX_BACKEND=local in .env")
    raise SystemExit(2)


def docker_image_exists(image: str) -> bool:
    """Return whether Docker image exists locally."""

    result = subprocess.run(
        ["docker", "image", "inspect", image],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode == 0


def pull_sandbox_image(image: str) -> bool:
    """Pull sandbox image."""

    print(f"[+] Pulling sandbox image: {image}")
    result = subprocess.run(
        ["docker", "pull", image],
        cwd=REPO_ROOT,
        text=True,
        check=False,
    )
    return result.returncode == 0


def build_sandbox_image(image: str) -> None:
    """Build sandbox image locally."""

    dockerfile = REPO_ROOT / "docker" / "Dockerfile.sandbox"

    if not dockerfile.exists():
        raise SystemExit(f"[-] Dockerfile not found: {dockerfile}")

    build_tag = image

    if image.startswith("ghcr.io/") or image.startswith("docker.io/"):
        build_tag = LOCAL_BUILD_IMAGE
        print(f"[+] Shared image name detected. Building local developer image instead: {build_tag}")
        os.environ["SABER_SANDBOX_IMAGE"] = build_tag

    print(f"[+] Building sandbox image: {build_tag}")
    result = subprocess.run(
        ["docker", "build", "-f", str(dockerfile), "-t", build_tag, "."],
        cwd=REPO_ROOT,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise SystemExit(f"[-] Failed to build sandbox image: {build_tag}")

    print(f"[+] Built sandbox image: {build_tag}")


def ensure_uvicorn_available() -> None:
    """Ensure uvicorn is importable."""

    result = subprocess.run(
        [sys.executable, "-c", "import uvicorn"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise SystemExit(
            "[-] uvicorn is not installed in this environment. Run: pip install -r requirements.txt"
        )


def start_ui(config: LaunchConfig) -> int:
    """Start web UI and optionally open browser."""

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "saber.ui.web.app:app",
        "--host",
        config.host,
        "--port",
        str(config.port),
    ]

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(REPO_ROOT))

    print("[+] Starting SABER UI")
    print(f"    {config.ui_url}")
    print("    Press Ctrl+C to stop.")
    print("")

    process = subprocess.Popen(cmd, cwd=REPO_ROOT, env=env)

    try:
        time.sleep(1.2)

        if config.open_browser:
            print("[+] Opening browser")
            webbrowser.open(config.ui_url)

        return process.wait()

    except KeyboardInterrupt:
        print("")
        print("[+] Stopping SABER UI")
        terminate_process(process)
        return 130


def terminate_process(process: subprocess.Popen) -> None:
    """Terminate child process cleanly."""

    if process.poll() is not None:
        return

    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
