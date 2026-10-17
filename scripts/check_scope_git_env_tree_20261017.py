#!/usr/bin/env python3
"""Isolated immutable Git tree shape check. No authorization or scans."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = "e73b7445c87ad239bdb03c50a99078ef93163b02"
BRANCH = "chatgpt/scope-git-env-main-isolated-1528-20261017"
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
GIT_TIMEOUT_SECONDS = 15


def _git_raw(*args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """Bound Git stdout/stderr while reading; never capture unlimited bytes.

    Git input is limited before spawning. Selector-driven pipe reads reject
    excessive output immediately without reading it fully into memory.
    """
    if data is not None and (type(data) is not bytes or len(data) > 262144):
        raise ValueError("invalid bounded Git stdin")
    command = [GIT_BINARY, "-c", "core.fsmonitor=false", *args]
    process = subprocess.Popen(
        command, cwd=ROOT,
        stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    out = bytearray()
    err = bytearray()
    offset = 0
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        with selectors.DefaultSelector() as streams:
            assert process.stdout is not None and process.stderr is not None
            streams.register(process.stdout, selectors.EVENT_READ, "out")
            streams.register(process.stderr, selectors.EVENT_READ, "err")
            if data is not None:
                assert process.stdin is not None
                streams.register(process.stdin, selectors.EVENT_WRITE, "in")
            while streams.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, GIT_TIMEOUT_SECONDS)
                ready = streams.select(remaining)
                if not ready:
                    raise subprocess.TimeoutExpired(command, GIT_TIMEOUT_SECONDS)
                for key, _ in ready:
                    channel = key.data
                    stream = key.fileobj
                    if channel == "in":
                        assert data is not None
                        try:
                            count = os.write(stream.fileno(), data[offset:offset + 16384])
                        except BrokenPipeError:
                            count = 0
                            offset = len(data)
                        offset += count
                        if offset >= len(data):
                            streams.unregister(stream)
                            stream.close()
                    else:
                        block = os.read(stream.fileno(), 16384)
                        if not block:
                            streams.unregister(stream)
                            stream.close()
                        else:
                            buffer = out if channel == "out" else err
                            limit = 786432 if channel == "out" else 16384
                            if len(buffer) + len(block) > limit:
                                raise ValueError("Git output exceeds bounded review cap")
                            buffer.extend(block)
        result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, result, bytes(out), bytes(err))
    except BaseException:
        # The Git process may exit before a malicious descendant closes the
        # inherited pipes. Kill the entire dedicated session on any failure,
        # not just its original (possibly already exited) leader.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

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
    # Ordinary check-attr filter reports "unspecified" BOTH for an absent
    # filter and for an explicit filter=unspecified declaration. That
    # declaration selects a real clean/process driver named "unspecified".
    # --all emits only explicitly active attributes and disambiguates this
    # without attempting to parse untrusted attributes-file syntax ourselves.
    attrs = _git_raw("check-attr", "--all", "-z", "--stdin", data=files.stdout)
    if (
        attrs.returncode != 0 or type(attrs.stdout) is not bytes
        or type(attrs.stderr) is not bytes or attrs.stderr
        or len(attrs.stdout) > 786432
    ):
        return False
    if not attrs.stdout:
        return True  # No selected attributes on any tracked path.
    if not attrs.stdout.endswith(b"\0"):
        return False
    fields = attrs.stdout[:-1].split(b"\0")
    if len(fields) % 3:
        return False
    allowed_paths = set(names)
    seen: set[tuple[bytes, bytes]] = set()
    for path, attribute, value in zip(fields[::3], fields[1::3], fields[2::3]):
        identity = (path, attribute)
        if (
            path not in allowed_paths or not value or len(value) > 8192
            or re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", attribute) is None
            or attribute.lower() == b"filter" or identity in seen
        ):
            return False
        seen.add(identity)
    return True


def _worktree_blobs_match_head(raw: object) -> bool:
    """Check actual owned source bytes, not merely index/status Git metadata.

    An assume-unchanged/skip-worktree index can hide modified source even
    when git status is empty and HEAD's Git tree still looks correct.
    """
    if type(raw) is not bytes or len(raw) > 16384 or not raw.endswith(b"\0"):
        return False
    try:
        root = ROOT.resolve(strict=True)
        found: set[str] = set()
        for record in raw[:-1].split(b"\0"):
            meta, path = record.split(b"\t", 1)
            mode, kind, oid = meta.split(b" ")
            name = path.decode("ascii")
            if (
                mode != b"100644" or kind != b"blob" or
                SHA1.fullmatch(oid) is None or name not in OWNED or
                name in found
            ):
                return False
            found.add(name)
            target = root
            components = name.split("/")
            # Reject even intermediate symlinks, not just file symlinks.
            for part in components:
                if part in ("", ".", ".."):
                    return False
                target = target / part
                if target.is_symlink():
                    return False
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1048576:
                return False
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(target, flags)
            with os.fdopen(fd, "rb") as handle:
                current = os.fstat(handle.fileno())
                if not stat.S_ISREG(current.st_mode) or current.st_size > 1048576:
                    return False
                payload = handle.read(1048577)
            if len(payload) > 1048576 or len(payload) != current.st_size:
                return False
            blob = b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
            if hashlib.sha1(blob).hexdigest().encode("ascii") != oid:
                return False
        return found == OWNED
    except (OSError, ValueError, UnicodeError, TypeError):
        return False


def _ignored_worktree_is_empty() -> bool:
    """Ignored files cannot count as a clean source checkout.

    Git status intentionally omits paths hidden by .gitignore,
    .git/info/exclude, or global excludes. A hidden Python module or
    startup hook could affect this evidence run while status says clean.
    No ignored cache, script, bytecode, or executable is trusted here.
    """
    result = _git_raw(
        "ls-files", "--others", "--ignored", "--exclude-standard", "-z"
    )
    return (
        result.returncode == 0
        and type(result.stdout) is bytes and result.stdout == b""
        and type(result.stderr) is bytes and result.stderr == b""
    )


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    if args and args[0] == "status" and (
        not _tracked_files_have_no_filters() or not _ignored_worktree_is_empty()
    ):
        # No status if an external filter or invisible ignored file exists.
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
        diff = git("diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "--no-renames", BASE, "HEAD")
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
            and _worktree_blobs_match_head(tree.stdout)
        )
    except (OSError, UnicodeError, ValueError, TypeError, subprocess.TimeoutExpired):
        good = False
    print("scope_env_owned_tree=" + ("PASS" if good else "HOLD"))
    return 0 if good else 3


if __name__ == "__main__":
    raise SystemExit(main())
