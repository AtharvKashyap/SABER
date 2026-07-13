"""Simple preflight secret scanner with low false positives."""

from __future__ import annotations

import re
from pathlib import Path

SKIP_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "sessions",
    "output",
    "runs",
}

SKIP_NAMES = {
    ".env",
}

SKIP_SUFFIXES = {
    ".pyc",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".xlsx",
    ".sqlite",
    ".db",
}

PATTERNS = {
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    "ghp": re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    "api_sk": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
}

bad: list[str] = []

for path in Path(".").rglob("*"):
    if path.is_dir():
        continue
    if path.name in SKIP_NAMES:
        continue
    if any(part in SKIP_PARTS for part in path.parts):
        continue
    if path.suffix.lower() in SKIP_SUFFIXES:
        continue

    text = path.read_text(errors="ignore")
    matches = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    if matches:
        bad.append(f"{path} ({', '.join(matches)})")

if bad:
    raise SystemExit("Possible secret/token strings found in: " + ", ".join(bad))

print("secret string check passed")
