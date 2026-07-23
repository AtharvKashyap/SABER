"""Detect CTF flags in tool output text.

Pure and dependency-free so it is trivially unit-testable and safe to call from
the mission loop. Returns the first flag found. Does not raise for any input in
``texts``, but will raise ``re.error`` if ``extra_patterns`` contains an invalid
regex; callers that accept untrusted patterns should validate/guard them before
passing them in here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Non-greedy brace body, no nested braces. The flag word is matched
# case-insensitively via the IGNORECASE flag applied at compile time.
_DEFAULT_PATTERNS = (
    r"picoCTF\{[^{}]{1,256}\}",
    r"flag\{[^{}]{1,256}\}",
    r"CTF\{[^{}]{1,256}\}",
)


def detect_flag(texts: Iterable[str], extra_patterns: list[str] | None = None) -> str | None:
    """Return the first flag found scanning ``texts`` in order, else None.

    Raises ``re.error`` if ``extra_patterns`` contains an invalid regex.
    """

    patterns = [re.compile(p, re.IGNORECASE) for p in _DEFAULT_PATTERNS]
    patterns.extend(re.compile(p) for p in (extra_patterns or []))

    for text in texts:
        if not isinstance(text, str) or not text:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
    return None
