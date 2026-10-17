"""Offline immutable-base path/mode/ancestry gate for the #1563 draft.

Never grants execution authority. Uses Git object inspection only; no shell,
hooks, working-tree status, target interaction, network or credentials.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ORIGINAL_BASE = "e73b7445c87ad239bdb03c50a99078ef93163b02"
ALLOWED_ADDED = frozenset({
    ".github/workflows/scope-1563-membership-offline.yml",
    ".github/workflows/scope-1563-owner301-compat-offline.yml",
    "docs/scope-1563-membership-metamorphic-20261017.md",
    "scripts/scope_1563_membership_mutation_proof_20261017.py",
    "scripts/scope_1563_exact_tree_boundary_20261017.py",
    "tests/test_scope_membership_metamorphic_20261017.py",
    "tests/test_scope_1563_exact_tree_boundary_20261017.py",
})
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
PERMITTED_MODES = {"100644"}
MAX_GIT_BYTES = 32 * 1024


class Hold(ValueError):
    """Unsafe or unprovable exact-tree change: no merge or release."""


def _git(root: Path, *args: str) -> bytes:
    # Ignore caller-supplied Git object/repository/config redirection, including
    # GIT_DIR, GIT_WORK_TREE, GIT_CONFIG_COUNT and replace-object toggles. The
    # review must inspect the repository at 'root', not an attacker-selected one.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    command = [
        "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        *args,
    ]
    try:
        result = subprocess.run(
            command, cwd=root, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("git evidence unavailable") from exc
    if result.returncode:
        raise Hold("git evidence rejected or incomplete")
    if len(result.stdout) > MAX_GIT_BYTES:
        raise Hold("git evidence exceeds strict byte limit")
    return result.stdout


def _sha(raw: bytes) -> str:
    try:
        decoded = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise Hold("noncanonical Git SHA encoding") from exc
    if not SHA_PATTERN.fullmatch(decoded):
        raise Hold("noncanonical Git SHA")
    return decoded


def parse_changes(data: bytes) -> frozenset[str]:
    if not data or not data.endswith(b"\0"):
        raise Hold("missing/unterminated Git changed-file records")
    parts = data.split(b"\0")
    if parts[-1] != b"":
        raise Hold("unterminated Git record")
    parts.pop()
    if len(parts) % 2:
        raise Hold("truncated Git name-status pair")
    changed: set[str] = set()
    for index in range(0, len(parts), 2):
        raw_status, raw_path = parts[index:index + 2]
        if raw_status != b"A":
            raise Hold("non-additive change or rename/copy")
        try:
            name = raw_path.decode("ascii")
        except UnicodeDecodeError as exc:
            raise Hold("non-ASCII path may alias another worker") from exc
        if not name or name.startswith("/") or ".." in name.split("/"):
            raise Hold("unsafe changed path")
        if name not in ALLOWED_ADDED or name in changed:
            raise Hold("unowned/duplicate path")
        changed.add(name)
    if changed != ALLOWED_ADDED:
        raise Hold("incomplete expected owner path manifest")
    return frozenset(changed)



def _verify_history(root: Path, head: str) -> int:
    """Review every original-base-to-head transition, not just final tree."""
    entries = _git(root, "rev-list", "--reverse", "--parents", ORIGINAL_BASE + ".." + head)
    try:
        lines = entries.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise Hold("invalid ancestry bytes") from exc
    if not 1 <= len(lines) <= 128:
        raise Hold("missing or excessive commit history")
    parent = ORIGINAL_BASE
    for line in lines:
        words = line.split(" ")
        if len(words) != 2 or words[1] != parent or any(not SHA_PATTERN.fullmatch(x) for x in words):
            raise Hold("nonlinear/ambiguous commit history")
        commit = words[0]
        raw = _git(root, "diff-tree", "-r", "--no-ext-diff", "--no-renames",
                   "--no-commit-id", "--name-status", "-z", parent, commit)
        if not raw or not raw.endswith(b"\0"):
            raise Hold("empty or incomplete committed diff")
        pairs = raw.split(b"\0")[:-1]
        if len(pairs) % 2:
            raise Hold("truncated committed records")
        seen = set()
        for index in range(0, len(pairs), 2):
            operation, raw_path = pairs[index:index+2]
            try:
                name = raw_path.decode("ascii")
            except UnicodeDecodeError as exc:
                raise Hold("non-ASCII intermediate path") from exc
            if operation not in (b"A", b"M") or name not in ALLOWED_ADDED or name in seen:
                raise Hold("forbidden transient source, rename, delete or duplicate")
            seen.add(name)
            info = _git(root, "ls-tree", "-z", commit, "--", name)
            if not info.endswith(b"\0") or info.count(b"\0") != 1:
                raise Hold("missing committed file")
            try:
                metadata, observed = info[:-1].split(b"\t", 1)
                mode, kind, blob = metadata.decode("ascii").split(" ")
                observed = observed.decode("ascii")
            except (ValueError, UnicodeDecodeError) as exc:
                raise Hold("malformed intermediate Git tree") from exc
            if mode != "100644" or kind != "blob" or observed != name or not SHA_PATTERN.fullmatch(blob):
                raise Hold("nonregular intermediate Git object")
        parent = commit
    if parent != head:
        raise Hold("ancestry does not finish at exact head")
    return len(lines)

def inspect_exact_head(root: Path, expected_head: str) -> dict[str, str | int | bool]:
    if not SHA_PATTERN.fullmatch(expected_head):
        raise Hold("expected head must be an exact 40-byte hex SHA")
    head = _sha(_git(root, "rev-parse", "--verify", "HEAD"))
    if head != expected_head:
        raise Hold("current head no longer matches caller-pinned SHA")
    _sha(_git(root, "rev-parse", "--verify", ORIGINAL_BASE + "^{commit}"))
    _git(root, "merge-base", "--is-ancestor", ORIGINAL_BASE, head)
    changed = parse_changes(_git(
        root, "diff-tree", "-r", "--no-ext-diff", "--no-commit-id",
        "--name-status", "-z", ORIGINAL_BASE, head,
    ))
    for name in sorted(changed):
        raw = _git(root, "ls-tree", "-z", head, "--", name)
        if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
            raise Hold("noncanonical owned path Git tree entry")
        raw_record = raw[:-1]
        try:
            metadata, observed_path = raw_record.split(b"\t", 1)
            mode, kind, blob_sha = metadata.decode("ascii").split(" ")
            observed = observed_path.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise Hold("malformed Git tree record") from exc
        if mode not in PERMITTED_MODES or kind != "blob" or observed != name:
            raise Hold("owned file is not a canonical regular file")
        if not SHA_PATTERN.fullmatch(blob_sha):
            raise Hold("bad object identity in Git tree")
    return {
        "decision": "REVIEW_ONLY",
        "base": ORIGINAL_BASE,
        "head": head,
        "added_paths": len(changed),
        "checked_commits": _verify_history(root, head),
        "authorization_granted": False,
        "release_approved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Issue 1563 immutable Git tree review")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    try:
        result = inspect_exact_head(args.root, args.expected_head)
    except Hold as exc:
        print("HOLD:", str(exc), file=sys.stderr)
        return 2
    print("REVIEW_ONLY", result["head"], "added_paths", result["added_paths"])
    return 3  # non-authorizing by construction: never exit 0


if __name__ == "__main__":
    raise SystemExit(main())
