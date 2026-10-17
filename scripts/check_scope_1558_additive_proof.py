"""Exact-base, add-only Git ownership gate for held scope issue #1558.

Read-only. Never executes Git status, filters, hooks or untrusted externals.
This proves a proposed commit changes only the explicitly owned new paths;
it does NOT attest real authorization, trusted runners, consent or release.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ORIGINAL_MAIN = "e73b7445c87ad239bdb03c50a99078ef93163b02"
OWNED_FILES = frozenset({
    ".github/workflows/lightup-scope-anchor-auth.yml",
    "docs/scope-audit-anchor-auth-offline.md",
    "src/lightup/scope_audit_anchor_auth_offline.py",
    "src/lightup/scope_audit_anchor_batch_offline.py",
    "tests/test_scope_audit_anchor_auth_offline.py",
    "tests/test_scope_audit_anchor_batch_offline.py",
    "scripts/check_scope_1558_additive_proof.py",
    "tests/test_scope_1558_additive_proof.py",
})


class InvalidOwnership(ValueError):
    """The proposed branch is not a strictly additive owned change."""


def _git(root: Path, *args: str) -> bytes:
    environment = dict(os.environ)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    # No shell, Git status, filesystem monitor, external diffs or textconv.
    command = [
        "git", "-C", str(root), "-c", "core.fsmonitor=false",
        *args,
    ]
    completed = subprocess.run(
        command, capture_output=True, check=False,
        env=environment, timeout=15,
    )
    if completed.returncode:
        raise InvalidOwnership("Git proof invocation failed")
    return completed.stdout


def validate_owned_changes(
    root: Path, expected_base: str, owned_files: frozenset[str]
) -> frozenset[str]:
    """Fail closed when any added path is foreign or base/history changed."""
    if not isinstance(root, Path) or not root.is_dir():
        raise InvalidOwnership("repository path")
    if type(expected_base) is not str or len(expected_base) != 40 or any(
        char not in "0123456789abcdef" for char in expected_base
    ):
        raise InvalidOwnership("immutable base SHA")
    if (
        type(owned_files) is not frozenset
        or not owned_files
        or any(type(item) is not str or not item for item in owned_files)
    ):
        raise InvalidOwnership("owned file list")
    _git(root, "merge-base", "--is-ancestor", expected_base, "HEAD")
    raw = _git(
        root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
        "--name-status", "-z", expected_base, "HEAD",
    )
    items = raw.split(b"\x00")
    if not items or items[-1] != b"":
        raise InvalidOwnership("incomplete Git name/status stream")
    fields = items[:-1]
    if len(fields) != 2 * len(owned_files):
        raise InvalidOwnership("unexpected path or partial coverage")
    changes: set[str] = set()
    for idx in range(0, len(fields), 2):
        if fields[idx] != b"A":
            raise InvalidOwnership("non-additive file change")
        try:
            path = fields[idx + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise InvalidOwnership("invalid path identity") from exc
        if path not in owned_files or path in changes:
            raise InvalidOwnership("foreign or duplicate owned path")
        changes.add(path)
    if changes != owned_files:
        raise InvalidOwnership("incomplete exact owned path coverage")
    return frozenset(changes)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        changed = validate_owned_changes(root, ORIGINAL_MAIN, OWNED_FILES)
    except (InvalidOwnership, OSError, subprocess.TimeoutExpired, ValueError):
        print("SCOPE_1558_ADD_ONLY_HOLD")
        return 2
    print(f"SCOPE_1558_ADD_ONLY_REVIEW_ONLY paths={len(changed)}")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
