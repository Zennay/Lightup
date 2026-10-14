"""Opt-in offline, negative-only add-only branch review; never an authorization."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
OWNED = re.compile(
    r"(?:tests/test_scope_[a-z0-9_]+\.py|"
    r"docs/scope-[a-z0-9-]+\.md|"
    r"scripts/check_scope_[a-z0-9_]+\.py)\Z"
)
MAX_FILES = 16


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(("git", *args), cwd=repo, capture_output=True, check=False)


def inspect(repo: Path, base: str, head: str, expected: tuple[str, ...]) -> tuple[str, int]:
    """Return a fixed reason code and count; never print private file contents."""
    if not SHA.fullmatch(base) or not SHA.fullmatch(head) or base == head:
        return "INVALID_IMMUTABLE_REFS", 0
    if (not 1 <= len(expected) <= MAX_FILES or len(set(expected)) != len(expected)
            or any(not OWNED.fullmatch(path) for path in expected)):
        return "INVALID_OWNERSHIP_MANIFEST", 0
    if not repo.is_dir():
        return "INVALID_REPOSITORY", 0
    for sha in (base, head):
        if _git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode:
            return "MISSING_COMMIT", 0
    if _git(repo, "merge-base", "--is-ancestor", base, head).returncode:
        return "NON_DESCENDANT_HEAD", 0
    diff = _git(repo, "diff", "--name-status", "--no-renames", "-z", base, head, "--")
    if diff.returncode:
        return "DIFF_UNAVAILABLE", 0
    fields = diff.stdout.split(b"\x00")
    if not fields or fields[-1] != b"":
        return "MALFORMED_DIFF", 0
    fields.pop()
    if not fields or len(fields) % 2:
        return "MALFORMED_DIFF", 0
    if len(fields) // 2 > MAX_FILES:
        return "UNBOUNDED_CHANGESET", len(fields) // 2
    changed: set[str] = set()
    for i in range(0, len(fields), 2):
        status, raw = fields[i:i + 2]
        try:
            path = raw.decode("ascii", "strict")
        except UnicodeError:
            return "NONCANONICAL_PATH", len(fields) // 2
        if status != b"A":
            return "PREEXISTING_PATH_CHANGED", len(fields) // 2
        if not OWNED.fullmatch(path) or path in changed:
            return "UNOWNED_OR_DUPLICATE_PATH", len(fields) // 2
        changed.add(path)
        tree = _git(repo, "ls-tree", "-z", head, "--", path)
        if tree.returncode or not tree.stdout.endswith(b"\x00"):
            return "INVALID_TREE_ENTRY", len(fields) // 2
        if tree.stdout != tree.stdout.rstrip(b"\x00") + b"\x00" or not tree.stdout.startswith(b"100644 blob "):
            return "UNSAFE_TREE_MODE", len(fields) // 2
        metadata, sep, actual = tree.stdout[:-1].partition(b"\t")
        if not sep or actual != raw or not re.fullmatch(rb"100644 blob [0-9a-f]{40}", metadata):
            return "INVALID_TREE_ENTRY", len(fields) // 2
    if changed != set(expected):
        return "OWNERSHIP_MANIFEST_MISMATCH", len(fields) // 2
    if _git(repo, "diff", "--check", base, head, "--").returncode:
        return "PATCH_CHECK_FAILED", len(fields) // 2
    return "ADDITIVE_PATHS_MATCH", len(fields) // 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--allow", action="append", required=True)
    args = parser.parse_args(argv)
    reason, count = inspect(args.repo, args.base, args.head, tuple(args.allow))
    print(json.dumps({
        "status": "REVIEW_ONLY" if reason == "ADDITIVE_PATHS_MATCH" else "HOLD",
        "reason": reason,
        "changed_files": count,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }, sort_keys=True))
    return 0 if reason == "ADDITIVE_PATHS_MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
