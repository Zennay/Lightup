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


def _git_raw(*args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    # Never consult PATH for Git. Disable repository-provided fsmonitor hooks.
    return subprocess.run(
        [GIT_BINARY, "-c", "core.fsmonitor=false", *args],
        cwd=ROOT, input=data, capture_output=True, timeout=15,
    )


def _tracked_files_have_no_filters() -> bool:
    """Fail closed BEFORE Git status can execute a configured clean filter.

    Even read-only `git status` can execute filter.<name>.clean or .process
    from local/global Git config when .gitattributes selects that filter.
    Neither reading ls-files nor check-attr calls the filter executable.
    This offline proof conservatively rejects ALL selected filter drivers.
    """
    files = _git_raw("ls-files", "--cached", "-z")
    if (
        files.returncode != 0 or type(files.stdout) is not bytes
        or type(files.stderr) is not bytes or files.stderr
        or not files.stdout or len(files.stdout) > 262144
        or not files.stdout.endswith(b"\0")
    ):
        return False
    names = files.stdout[:-1].split(b"\0")
    if len(names) > 8192 or len(set(names)) != len(names):
        return False
    attrs = _git_raw("check-attr", "-z", "--stdin", "filter", data=files.stdout)
    if (
        attrs.returncode != 0 or type(attrs.stdout) is not bytes
        or type(attrs.stderr) is not bytes or attrs.stderr
        or not attrs.stdout or len(attrs.stdout) > 786432
        or not attrs.stdout.endswith(b"\0")
    ):
        return False
    fields = attrs.stdout[:-1].split(b"\0")
    if len(fields) != 3 * len(names):
        return False
    for index, path in enumerate(names):
        original, attr, value = fields[3 * index:3 * index + 3]
        if original != path or attr != b"filter" or value != b"unspecified":
            return False
    return True


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    if args and args[0] == "status" and not _tracked_files_have_no_filters():
        # Do not invoke status if an external filter may execute.
        return subprocess.CompletedProcess(args, 3, b"", b"")
    return _git_raw(*args)

def main() -> int:
    # Never attest git commands after environment-controlled redirection.
    if any(name.startswith("GIT_") for name in os.environ):
        print("scope_env_owned_tree=HOLD")
        return 3
    try:
        status = git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all")
        branch = os.environ.get("GITHUB_REF", "")
        sha = os.environ.get("GITHUB_SHA", "")
        head = git("rev-parse", "HEAD")
        top = git("rev-parse", "--show-toplevel")
        ancestor = git("merge-base", "--is-ancestor", BASE, "HEAD")
        diff = git("diff", "--name-status", "-z", "--no-renames", BASE, "HEAD")
        tree = git("ls-tree", "-r", "-z", "HEAD", "--", *sorted(OWNED))
        # Even successful Git commands can report config, object or worktree
        # warnings. Such diagnostics do not constitute clean evidence.
        git_results = (status, head, top, ancestor, diff, tree)
        silent_git = all(
            result.returncode == 0
            and type(result.stdout) is bytes
            and type(result.stderr) is bytes
            and result.stderr == b""
            for result in git_results
        )
        good = (
            silent_git
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and branch == "refs/heads/" + BRANCH
            and SHA1.fullmatch(sha.encode("ascii")) is not None
            and status.returncode == 0 and status.stdout == b""
            and head.returncode == 0 and head.stdout.strip() == sha.encode("ascii")
            and top.returncode == 0
            and top.stdout == os.fsencode(str(ROOT.resolve())) + b"\n"
            and ancestor.returncode == 0 and diff.returncode == 0
            and tree.returncode == 0 and safe_tree(tree.stdout, diff.stdout)
        )
    except (OSError, UnicodeError, ValueError, TypeError, subprocess.TimeoutExpired):
        good = False
    print("scope_env_owned_tree=" + ("PASS" if good else "HOLD"))
    return 0 if good else 3


if __name__ == "__main__":
    raise SystemExit(main())
