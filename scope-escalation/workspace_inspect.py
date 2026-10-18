"""Read-only recipient inspection of a PRIVATE human escalation room.

Compares every delivered byte with a separately supplied original Casebook
snapshot and the current local source code. Never authenticates a sender or
evaluates client consent, authorization or live revocation.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


class Hold(Exception):
    pass


def _read_private(path: Path, *, limit: int) -> bytes:
    if path.is_symlink():
        raise Hold("symlink refused")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        st1 = os.fstat(fd)
        if (not stat.S_ISREG(st1.st_mode) or st1.st_mode & 0o077
                or st1.st_size > limit):
            raise Hold("unsafe recipient file")
        body = os.read(fd, limit + 1)
        st2 = os.fstat(fd)
        if (len(body) > limit or len(body) != st1.st_size
                or st1.st_dev != st2.st_dev or st1.st_ino != st2.st_ino
                or st1.st_mtime_ns != st2.st_mtime_ns):
            raise Hold("changing recipient file")
        return body
    finally:
        os.close(fd)


def _original_builder():
    spec = importlib.util.spec_from_file_location(
        "scope_escalation_board", Path(__file__).with_name("board.py"))
    if spec is None or spec.loader is None:
        raise Hold("local owner source unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(source: Path, workspace: Path) -> dict:
    owner = _original_builder()
    if workspace.is_symlink() or not workspace.is_dir():
        raise Hold("invalid room directory")
    mode = workspace.stat().st_mode
    if not stat.S_ISDIR(mode) or mode & 0o077:
        raise Hold("room is not private")
    original, data = owner._read_source(source)
    expected = owner.compose_private_outputs(original, data)
    wanted = set(expected) | {"manifest.json"}
    if {p.name for p in workspace.iterdir()} != wanted:
        raise Hold("unexpected or missing recipient files")
    manifest_raw = _read_private(workspace / "manifest.json", limit=65536)
    manifest = json.loads(manifest_raw.decode("utf-8", "strict"),
                          object_pairs_hook=owner._unique_pairs,
                          parse_constant=owner._reject_constant)
    if (type(manifest) is not dict
            or set(manifest) != {"schema", "status", "authority", "files"}
            or manifest["schema"] != "lightup.scope_escalation_manifest.v1"
            or manifest["status"] != "REVIEW_ONLY"
            or manifest["authority"] is not False
            or type(manifest["files"]) is not dict
            or set(manifest["files"]) != set(expected)):
        raise Hold("manifest unsupported or contradictory")
    max_bytes = max(2 * 1024 * 1024, owner.MAX_BYTES * 4)
    for name, expected_bytes in expected.items():
        details = manifest["files"][name]
        if (type(details) is not dict or set(details) != {"sha256", "bytes"}
                or type(details["bytes"]) is not int):
            raise Hold("invalid recipient digest record")
        actual = _read_private(workspace / name, limit=max_bytes)
        if (details["bytes"] != len(expected_bytes)
                or details["sha256"] != sha256(expected_bytes).hexdigest()
                or actual != expected_bytes):
            raise Hold("recipient bytes differ from selected original source")
    return {"status": "REVIEW_ONLY", "authority": False,
            "human_followups": len(owner._queue(data)),
            "source_families": 5}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True,
                        help="separately held exact original private Casebook source")
    parser.add_argument("--workspace", required=True,
                        help="received private scope escalation room")
    args = parser.parse_args(argv)
    try:
        aggregate = inspect(Path(args.source), Path(args.workspace))
        print(json.dumps(aggregate, sort_keys=True))
        return 2
    except (Hold, OSError, ValueError, UnicodeError, KeyError, TypeError, Exception):
        print('{"status":"HOLD","authority":false}', file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
