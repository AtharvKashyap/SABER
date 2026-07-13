"""Small .env loader for SABER.

No external dependency. Loads KEY=VALUE lines into os.environ without
overwriting already-exported environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path = ".env", *, override: bool = False) -> dict[str, str]:
    """Load a .env file into os.environ.

    Supports:
    - KEY=value
    - KEY="value"
    - KEY='value'
    - comments and blank lines

    Returns loaded values.
    """

    env_path = Path(path)
    loaded: dict[str, str] = {}

    if not env_path.exists() or not env_path.is_file():
        return loaded

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = _clean_value(value.strip())

        if not key:
            continue

        loaded[key] = value

        if override or key not in os.environ:
            os.environ[key] = value

    return loaded


def _clean_value(value: str) -> str:
    """Clean .env value quotes/comments."""

    if not value:
        return ""

    if value[0] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]

    # Allow inline comments only after whitespace.
    for marker in (" #", "\t#"):
        if marker in value:
            value = value.split(marker, 1)[0].rstrip()

    return value
