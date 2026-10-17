#!/usr/bin/env python3
"""Isolated immutable Git tree shape check. No authorization or scans."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = "7b9142bb9e9d5403d7a3e41914edddef4511c8a8"
BRANCH = "chatgpt/scope-auth-git-env-fence-20261017-0115"
OWNED = frozenset({
    ".github/workflows/scope-git-env-attestation-20261017.yml",
    "docs/scope-git-env-attestation-20261017.md",
    "scripts/scope_git_env_attestation_20261017.py",
    "scripts/check_scope_git_env_tree_20261017.py",
    "tests/test_scope_git_env_attestation_20261017.py",
    "tests/test_scope_git_env_tree_20261017.py",
})
SHA1 = re.compile(rb"[0-9a-f]{40}\Z")


def parse_additions(raw: object) -> set[str] | None:
    if type(raw) is not bytes or len(raw) > 8192 or not raw.endswith(b"\0"):
        return None
    try:
        fields = raw[:-1].decode("ascii").split("\0")
    except UnicodeError:
        return None
    if len(fields) != 2 * len(OWNED):
        return None
    names: set[str] = set()
    for status, path in zip(fields[::2], fields[1::2]):
        if status != "A" or path not in OWNED or path in names:
            return None
        names.add(path)
    return names if names == OWNED else None


def safe_tree(raw: object, delta: object) -> bool:
    names = parse_additions(delta)
    if names is None or type(raw) is not bytes or len(raw) > 16384 or not raw.endswith(b"\0"):
        return False
    try:
        records = raw[:-1].split(b"\0")
        if len(records) != len(OWNED):
            return False
        found = set()
        for record in records:
            meta, path = record.split(b"\t", 1)
            mode, kind, object_id = meta.split(b" ")
            name = path.decode("ascii")
            if (
                mode != b"100644" or kind != b"blob"
                or SHA1.fullmatch(object_id) is None
                or name not in names or name in found
            ):
                return False
            found.add(name)
        return found == names
    except (UnicodeError, ValueError):
        return False


# Hosted CI and the independent VPS checkout both use this absolute Git
# executable. Never resolve an attacker-supplied basename through PATH.
GIT_BINARY = "/usr/bin/git"


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([GIT_BINARY, *args], cwd=ROOT, capture_output=True, timeout=15)


def main() -> int:
    # Never attest git commands after environment-controlled redirection.
    if any(name.startswith("GIT_") for name in os.environ):
        print("scope_env_owned_tree=HOLD")
        return 3
    try:
        status = git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        branch = os.environ.get("GITHUB_REF", "")
        sha = os.environ.get("GITHUB_SHA", "")
        head = git("rev-parse", "HEAD")
        ancestor = git("merge-base", "--is-ancestor", BASE, "HEAD")
        diff = git("diff", "--name-status", "-z", "--no-renames", BASE, "HEAD")
        tree = git("ls-tree", "-r", "-z", "HEAD", "--", *sorted(OWNED))
        good = (
            os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and branch == "refs/heads/" + BRANCH
            and SHA1.fullmatch(sha.encode("ascii")) is not None
            and status.returncode == 0 and status.stdout == b""
            and head.returncode == 0 and head.stdout.strip() == sha.encode("ascii")
            and ancestor.returncode == 0 and diff.returncode == 0
            and tree.returncode == 0 and safe_tree(tree.stdout, diff.stdout)
        )
    except (OSError, UnicodeError, ValueError, TypeError, subprocess.TimeoutExpired):
        good = False
    print("scope_env_owned_tree=" + ("PASS" if good else "HOLD"))
    return 0 if good else 3


if __name__ == "__main__":
    raise SystemExit(main())
