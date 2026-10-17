#!/usr/bin/env python3
"""Own-branch-only additivity fence; never grants scope or releases LightUp.

Reads exact Git tree differences only. No network, no repo writes, no scan.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import os
from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BRANCH = "chatgpt/scope-control-char-literal-review-20261016-2327"
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


def _owned_additions(raw: bytes) -> set[str] | None:
    """Return a valid diff's exact owned paths, or None for malformed bytes."""
    if type(raw) is not bytes or not raw or len(raw) > 16384:
        return None
    try:
        segments = raw.decode("ascii").split("\0")
    except UnicodeError:
        return None
    if segments[-1] != "":
        return None
    segments.pop()
    if not segments or len(segments) % 2:
        return None
    names = set()
    for status, path in zip(segments[::2], segments[1::2]):
        if not safe_change(status, path) or path in names:
            return None
        names.add(path)
    return names if OWNED_EXACT <= names else None


def safe_diff(raw: bytes) -> bool:
    """Only own exact paths may be newly added, never changed or deleted."""
    return _owned_additions(raw) is not None


def safe_tree(tree: bytes, delta: bytes) -> bool:
    """Demand regular Git blobs at every added path; no links/gitlinks."""
    paths = _owned_additions(delta)
    if paths is None or type(tree) is not bytes or not tree or len(tree) > 32768:
        return False
    entries = tree.split(b"\0")
    if entries[-1] != b"":
        return False
    entries.pop()
    if len(entries) != len(paths):
        return False
    found: set[str] = set()
    for entry in entries:
        try:
            header, path_raw = entry.split(b"\t", 1)
            mode, kind, oid = header.split(b" ")
            name = path_raw.decode("ascii")
        except (ValueError, UnicodeError):
            return False
        if (
            mode != b"100644" or kind != b"blob"
            or re.fullmatch(rb"[0-9a-f]{40}", oid) is None
            or name not in paths or name in found
        ):
            return False
        found.add(name)
    return found == paths


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True,
        check=False, timeout=20,
    )


def clean_worktree_status(result: object) -> bool:
    """Only exact zero-byte Git porcelain output proves the tested tree clean."""
    return (
        isinstance(result, subprocess.CompletedProcess)
        and type(result.returncode) is int
        and result.returncode == 0
        and type(result.stdout) is bytes
        and result.stdout == b""
    )


def branch_identity(
    symbolic: subprocess.CompletedProcess[bytes],
    head: subprocess.CompletedProcess[bytes],
    environment: Mapping[str, str],
) -> bool:
    """Never certify another worker's branch or an unpinned PR merge-ref."""
    if (
        not isinstance(symbolic, subprocess.CompletedProcess)
        or not isinstance(head, subprocess.CompletedProcess)
        or head.returncode != 0
        or type(head.stdout) is not bytes
        or re.fullmatch(rb"[0-9a-f]{40}", head.stdout.strip()) is None
    ):
        return False
    if environment.get("GITHUB_ACTIONS") == "true":
        return (
            symbolic.returncode in (0, 1)
            and environment.get("GITHUB_EVENT_NAME") == "push"
            and environment.get("GITHUB_REF") == "refs/heads/" + EXPECTED_BRANCH
            and environment.get("GITHUB_SHA") == head.stdout.strip().decode("ascii")
        )
    return (
        environment.get("GITHUB_ACTIONS") is None
        and symbolic.returncode == 0
        and type(symbolic.stdout) is bytes
        and symbolic.stdout == EXPECTED_BRANCH.encode("ascii") + b"\n"
    )


def main() -> int:
    try:
        # A remote main move must never silently change the held base.
        base = _git("merge-base", "--is-ancestor", "origin/main", "HEAD")
        head = _git("rev-parse", "HEAD")
        symbolic = _git("symbolic-ref", "--quiet", "--short", "HEAD")
        diff = _git(
            "diff", "--name-status", "-z", "--no-renames",
            "origin/main", "HEAD",
        )
        owned = _owned_additions(diff.stdout) if diff.returncode == 0 else None
        tree = _git("ls-tree", "-r", "-z", "HEAD", "--", *sorted(owned)) if owned else None
        # Never report branch proof for a dirty checkout: source/tests might
        # not match the actual committed Git tree. Includes untracked files.
        status = _git("status", "--porcelain=v1", "--untracked-files=all", "-z")
        ok = (
            clean_worktree_status(status) and
            branch_identity(symbolic, head, os.environ) and
            base.returncode == 0 and head.returncode == 0
            and re.fullmatch(rb"[0-9a-f]{40}", head.stdout.strip()) is not None
            and tree is not None and tree.returncode == 0
            and safe_tree(tree.stdout, diff.stdout)
        )
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        ok = False
    print("scope_owned_additive_branch=" + ("PASS" if ok else "HOLD"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
