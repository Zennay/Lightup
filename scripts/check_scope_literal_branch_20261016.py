#!/usr/bin/env python3
"""Own-branch-only additivity fence; never grants scope or releases LightUp.

Reads exact Git tree differences only. No network, no repo writes, no scan.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OWNED_EXACT = frozenset({
    ".github/workflows/scope-literal-controls-20261016.yml",
    "docs/scope-literal-control-review-20261016.md",
    "scripts/review_scope_literal_controls_20261016.py",
    "scripts/check_scope_literal_suite_20261016.py",
    "scripts/check_scope_literal_branch_20261016.py",
    "src/lightup/scope_literal_control_review_20261016.py",
})
OWNED_TEST = re.compile(r"tests/test_scope_literal_[a-z0-9_]+_20261016[.]py\Z")


def safe_change(status: str, path: str) -> bool:
    return (
        status == "A"
        and type(path) is str
        and (path in OWNED_EXACT or OWNED_TEST.fullmatch(path) is not None)
    )


def safe_diff(raw: bytes) -> bool:
    """Only exact NUL-delimited, added, exclusively own paths are acceptable."""
    if type(raw) is not bytes or not raw or len(raw) > 16384:
        return False
    try:
        segments = raw.decode("ascii").split("\0")
    except UnicodeError:
        return False
    if segments[-1] != "":
        return False
    segments.pop()
    if not segments or len(segments) % 2:
        return False
    names = set()
    for status, path in zip(segments[::2], segments[1::2]):
        if not safe_change(status, path) or path in names:
            return False
        names.add(path)
    return OWNED_EXACT <= names


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True,
        check=False, timeout=20,
    )


def main() -> int:
    try:
        # A remote main move must never silently change the held base.
        base = _git("merge-base", "--is-ancestor", "origin/main", "HEAD")
        head = _git("rev-parse", "HEAD")
        diff = _git(
            "diff", "--name-status", "-z", "--no-renames",
            "origin/main", "HEAD",
        )
        ok = (
            base.returncode == 0 and head.returncode == 0
            and len(head.stdout.strip()) == 40
            and diff.returncode == 0 and safe_diff(diff.stdout)
        )
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        ok = False
    print("scope_owned_additive_branch=" + ("PASS" if ok else "HOLD"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
