"""Guards on the test layout itself.

tests/unit and tests/e2e_tests have no __init__.py, so pytest imports their
modules by bare basename. Two files sharing a basename across those directories
makes collection fail with "import file mismatch" — which is what happened when
tests/unit/test_image_manifest.py was added alongside the e2e file of the same
name. It passed locally (the directories were run separately) and broke CI.
"""

from __future__ import annotations

import collections
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[1]


def test_no_two_test_modules_share_a_basename() -> None:
    by_name: dict[str, list[str]] = collections.defaultdict(list)
    for path in TESTS_ROOT.rglob("test_*.py"):
        by_name[path.name].append(str(path.relative_to(TESTS_ROOT)))

    collisions = {name: paths for name, paths in by_name.items() if len(paths) > 1}

    assert not collisions, "test modules sharing a basename break pytest collection:\n" + "\n".join(
        f"  {name}: {', '.join(sorted(paths))}" for name, paths in sorted(collisions.items())
    )
