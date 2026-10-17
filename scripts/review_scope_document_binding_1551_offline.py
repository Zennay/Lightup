"""Read-only exact-byte synthetic scope-document binding. NEVER authority.

Only an explicitly supplied regular local file is read; no network, no targets,
no client secrets in stdout. Scope hash equality proves *byte consistency* only.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

PARENT = Path(__file__).resolve().with_name("review_scope_consent_timeline_1551_offline.py")
SPEC = importlib.util.spec_from_file_location("scope1551_timeline_core", PARENT)
timeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timeline)


def _hold() -> dict[str, object]:
    return {"schema_version": 1, "status": "HOLD",
            "reason": "UNTRUSTED_OR_DISCONTINUOUS", **timeline.claim.AUTHORITY_FLAGS}


def _read_regular_document(path: str) -> bytes:
    if type(path) is not str or not path or len(path) > 4096 or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("invalid path")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        details = os.fstat(fd)
        if (not stat.S_ISREG(details.st_mode) or details.st_size < 1
                or details.st_size > timeline.MAX_SCOPE_DOCUMENT_BYTES):
            raise ValueError("not a bounded regular file")
        fragments = []
        length = 0
        while True:
            piece = os.read(fd, min(4096, timeline.MAX_SCOPE_DOCUMENT_BYTES + 1 - length))
            if not piece:
                break
            length += len(piece)
            if length > timeline.MAX_SCOPE_DOCUMENT_BYTES:
                raise ValueError("document grew during read")
            fragments.append(piece)
        if length < 1:
            raise ValueError("empty document")
        after = os.fstat(fd)
        stable_before = (details.st_dev, details.st_ino, details.st_mode,
                         details.st_size, details.st_mtime_ns, details.st_ctime_ns)
        stable_after = (after.st_dev, after.st_ino, after.st_mode,
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if stable_before != stable_after or length != after.st_size:
            raise ValueError("scope document changed during read")
        return b"".join(fragments)
    finally:
        os.close(fd)


def _parse_args(argv: list[str]) -> tuple[str, str | None, int | None, str | None]:
    if type(argv) is not list or any(type(arg) is not str for arg in argv):
        raise ValueError("invalid arguments")
    if len(argv) not in (2, 4, 6) or argv[0] != "--scope-document":
        raise ValueError("invalid arguments")
    path = argv[1]
    head = None
    index = None
    checkpoint = None
    if len(argv) == 4:
        if argv[2] == "--expected-head":
            head = argv[3]
        elif argv[2] == "--checkpoint":
            index, checkpoint = _parse_checkpoint(argv[3])
        else:
            raise ValueError("invalid arguments")
    if len(argv) == 6:
        if argv[2] != "--checkpoint" or argv[4] != "--expected-head":
            raise ValueError("invalid arguments")
        index, checkpoint = _parse_checkpoint(argv[3])
        head = argv[5]
    return path, head, index, checkpoint


def _parse_checkpoint(value: str) -> tuple[int, str]:
    match = re.fullmatch(r"(0|[1-9][0-9]?):([0-9a-f]{64})", value, re.ASCII)
    if match is None:
        raise ValueError("noncanonical checkpoint")
    return int(match.group(1)), match.group(2)


def _read_stdin() -> bytes:
    chunks = []
    length = 0
    while True:
        chunk = sys.stdin.buffer.read(min(4096, timeline.MAX_TIMELINE_BYTES + 1 - length))
        if type(chunk) is not bytes:
            raise ValueError("invalid stdin")
        if not chunk:
            break
        length += len(chunk)
        if length > timeline.MAX_TIMELINE_BYTES:
            raise ValueError("timeline too large")
        chunks.append(chunk)
    return b"".join(chunks)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        path, head, index, checkpoint = _parse_args(argv)
        document = _read_regular_document(path)
        raw = _read_stdin()
        output = timeline.review(raw, scope_document_bytes=document,
                                 expected_head_sha256=head,
                                 checkpoint_index=index,
                                 expected_checkpoint_sha256=checkpoint)
    except (OSError, ValueError, OverflowError, MemoryError, TypeError):
        output = _hold()
    try:
        wire = json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
        amount = sys.stdout.write(wire)
        sys.stdout.flush()
        if type(amount) is not int or amount != len(wire):
            return 2
    except (OSError, ValueError, UnicodeError):
        return 2
    return 3 if output["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
