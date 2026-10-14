"""Opt-in offline, negative-only add-only branch review; never an authorization."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
OWNED = re.compile(
    r"(?:tests/test_scope_[a-z0-9_]+\.py|"
    r"docs/scope-[a-z0-9-]+\.md|"
    r"scripts/check_scope_[a-z0-9_]+\.py)\Z"
)
MAX_FILES = 16
MAX_TEXT_BYTES = 256 * 1024


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Read repository metadata without inherited Git redirection/config injection."""
    clean_env = {key: value for key, value in os.environ.items()
                 if not key.startswith("GIT_")}
    clean_env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    })
    command = ("git", "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab", *args)
    try:
        return subprocess.run(command, cwd=repo, env=clean_env, capture_output=True,
                              check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        # Missing Git, blocked invocations or timeouts yield an opaque HOLD.
        return subprocess.CompletedProcess(command, 126, b"", b"")


def inspect(repo: Path, base: str, head: str, expected: tuple[str, ...],
            peers: tuple[str, ...] = (), require_current_head: bool = False
            ) -> tuple[str, int]:
    """Return a fixed reason code and count; never print private file contents."""
    if not SHA.fullmatch(base) or not SHA.fullmatch(head) or base == head:
        return "INVALID_IMMUTABLE_REFS", 0
    if (not 1 <= len(expected) <= MAX_FILES or len(set(expected)) != len(expected)
            or any(not OWNED.fullmatch(path) for path in expected)):
        return "INVALID_OWNERSHIP_MANIFEST", 0
    if (len(peers) > MAX_FILES or len(set(peers)) != len(peers)
            or any(not SHA.fullmatch(peer) or peer in (base, head) for peer in peers)):
        return "INVALID_PEER_REFS", 0
    if not repo.is_dir():
        return "INVALID_REPOSITORY", 0
    # Git's inherited environment or a nested working directory must not select
    # an unrelated checkout while presenting otherwise valid commit identifiers.
    root = _git(repo, "rev-parse", "--show-toplevel")
    if root.returncode or not root.stdout.strip():
        return "INVALID_REPOSITORY_ROOT", 0
    try:
        canonical_repo = repo.resolve(strict=True)
        canonical_root = Path(os.fsdecode(root.stdout.strip())).resolve(strict=True)
    except (OSError, ValueError):
        return "INVALID_REPOSITORY_ROOT", 0
    if canonical_repo != canonical_root:
        return "INVALID_REPOSITORY_ROOT", 0
    if type(require_current_head) is not bool:
        return "INVALID_CURRENT_HEAD_POLICY", 0
    if require_current_head:
        current = _git(repo, "rev-parse", "--verify", "HEAD^{commit}")
        if current.returncode or current.stdout.strip() != head.encode("ascii"):
            return "STALE_CURRENT_HEAD", 0
    for sha in (base, head):
        if _git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode:
            return "MISSING_COMMIT", 0
    if _git(repo, "merge-base", "--is-ancestor", base, head).returncode:
        return "NON_DESCENDANT_HEAD", 0
    diff = _git(repo, "diff", "--name-status", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", base, head, "--")
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
        # A new .py/.md file must be a bounded ordinary text blob, never a
        # giant/binary fixture hidden behind an otherwise innocuous path.
        object_id = metadata.rsplit(b" ", 1)[-1].decode("ascii")
        blob_size = _git(repo, "cat-file", "-s", object_id)
        raw_size = blob_size.stdout.strip()
        if blob_size.returncode or not raw_size.isdigit() or len(raw_size) > 10:
            return "INVALID_BLOB_SIZE", len(fields) // 2
        size = int(raw_size)
        if size > MAX_TEXT_BYTES:
            return "ADDED_FILE_TOO_LARGE", len(fields) // 2
        content = _git(repo, "cat-file", "blob", object_id)
        if content.returncode or len(content.stdout) != size:
            return "INVALID_BLOB_DATA", len(fields) // 2
        try:
            decoded = content.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return "NONCANONICAL_TEXT", len(fields) // 2
        # Text can be syntactically valid UTF-8 but render differently from what
        # the reviewer sees. Reject invisible formatting and terminal controls.
        if decoded.startswith("\ufeff") or any(
                (unicodedata.category(char) == "Cf")
                or (unicodedata.category(char) == "Cc" and char not in "\t\n")
                for char in decoded):
            return "NONCANONICAL_TEXT", len(fields) // 2
    if changed != set(expected):
        return "OWNERSHIP_MANIFEST_MISMATCH", len(fields) // 2
    if _git(repo, "diff", "--check", "--no-ext-diff", "--no-textconv", base, head, "--").returncode:
        return "PATCH_CHECK_FAILED", len(fields) // 2
    for peer in peers:
        if _git(repo, "cat-file", "-e", f"{peer}^{{commit}}").returncode:
            return "MISSING_PEER_COMMIT", len(fields) // 2
        if _git(repo, "merge-base", "--is-ancestor", base, peer).returncode:
            return "NON_DESCENDANT_PEER", len(fields) // 2
        other = _git(repo, "diff", "--name-only", "--no-renames", "--no-ext-diff",
                     "--no-textconv", "-z", base, peer, "--")
        if other.returncode or (other.stdout and not other.stdout.endswith(b"\x00")):
            return "PEER_DIFF_UNAVAILABLE", len(fields) // 2
        raw_peers = other.stdout.split(b"\x00") if other.stdout else []
        if raw_peers:
            raw_peers.pop()
        if len(raw_peers) > 2048:
            return "UNBOUNDED_PEER_DIFF", len(fields) // 2
        try:
            peer_paths = {name.decode("ascii", "strict") for name in raw_peers}
        except UnicodeError:
            return "NONCANONICAL_PEER_PATH", len(fields) // 2
        # Exact Git paths may collide on a case-insensitive checkout even if
        # their stored tree spelling differs (e.g. Linux vs. macOS/Windows).
        if {path.casefold() for path in changed}.intersection(
                path.casefold() for path in peer_paths):
            return "PEER_PATH_COLLISION", len(fields) // 2
    return "ADDITIVE_PATHS_MATCH", len(fields) // 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--allow", action="append", required=True)
    parser.add_argument("--peer", action="append", default=[],
                        help="immutable other worker HEAD SHA (repeat; only supplied peers are checked)")
    parser.add_argument("--require-current-head", action="store_true",
                        help="deny an older SHA than the checkout's actual current HEAD")
    args = parser.parse_args(argv)
    reason, count = inspect(args.repo, args.base, args.head, tuple(args.allow),
                            tuple(args.peer), args.require_current_head)
    print(json.dumps({
        "status": "REVIEW_ONLY" if reason == "ADDITIVE_PATHS_MATCH" else "HOLD",
        "reason": reason,
        "changed_files": count,
        "peer_heads_submitted": len(args.peer),
        "peer_heads_checked": len(args.peer) if reason == "ADDITIVE_PATHS_MATCH" else 0,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }, sort_keys=True))
    return 0 if reason == "ADDITIVE_PATHS_MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
