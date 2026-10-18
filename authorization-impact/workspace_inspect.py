#!/usr/bin/env python3
"""Read-only recipient-side integrity inspection of a private Impact Map packet.

Checks consistency of a PRIVATE local artifact bundle relative to the
bundle's own untrusted manifest. Never authenticates issuer/consent.
Always return REVIEW_ONLY (2) or HOLD (3), not an approval code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from prepare import FALSE_FLAGS, Refused, _constant, _pairs, _validate_source

EXPECTED = {
    "casebook.json": 524288,
    "standalone.html": 524288,
    "START-HERE.txt": 32768,
}
MANIFEST_LIMIT = 32768


def _private_dir(directory: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise Refused("no safe directory support")
    fd = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        os.close(fd)
        raise Refused("unsafe recipient directory")
    return fd


def _private_file(fd: int, name: str, limit: int) -> bytes:
    child = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=fd,
    )
    try:
        first = os.fstat(child)
        if (
            not stat.S_ISREG(first.st_mode)
            or first.st_uid != os.geteuid()
            or first.st_mode & 0o077
            or not 2 <= first.st_size <= limit
        ):
            raise Refused("unsafe recipient file")
        parts: list[bytes] = []
        remain = limit + 1
        while remain:
            data = os.read(child, min(65536, remain))
            if not data:
                break
            parts.append(data)
            remain -= len(data)
        raw = b"".join(parts)
        final = os.fstat(child)
        if len(raw) != first.st_size or len(raw) > limit:
            raise Refused("incomplete recipient file")
        if (
            (first.st_dev, first.st_ino, first.st_mtime_ns, first.st_ctime_ns)
            != (final.st_dev, final.st_ino, final.st_mtime_ns, final.st_ctime_ns)
        ):
            raise Refused("unstable source revision")
        return raw
    finally:
        os.close(child)


def inspect(directory: Path) -> None:
    dirfd = _private_dir(directory)
    try:
        raw_manifest = _private_file(dirfd, "manifest.json", MANIFEST_LIMIT)
        try:
            manifest = json.loads(
                raw_manifest.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=_constant,
            )
        except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
            raise Refused("invalid manifest") from exc
        if (
            type(manifest) is not dict
            or manifest.get("schema") != "lightup.scope_impact_workspace.v1"
            or manifest.get("status") != "REVIEW_ONLY"
            or manifest.get("source_authenticated") is not False
        ):
            raise Refused("unsupported private workspace")
        authority = manifest.get("authority")
        if (
            type(authority) is not dict
            or set(authority) != set(FALSE_FLAGS)
            or not all(authority[field] is False for field in FALSE_FLAGS)
        ):
            raise Refused("authority flags cannot be inferred")
        references = manifest.get("files")
        if type(references) is not dict:
            raise Refused("incomplete recipient manifest")
        requested = set(references)
        base = set(EXPECTED)
        if requested not in (
            base, base | {"PRIVATE-review.json"},
            base | {"PRIVATE-ready.html"},
            base | {"PRIVATE-ready.html", "PRIVATE-review.json"},
        ):
            raise Refused("unexpected recipient files")
        expected_all = requested | {"manifest.json"}
        names = os.listdir(dirfd)
        if len(names) != len(expected_all) or set(names) != expected_all:
            raise Refused("incomplete or unexpected workspace entry")
        limits = dict(EXPECTED)
        if "PRIVATE-review.json" in requested:
            limits["PRIVATE-review.json"] = 262144
        if "PRIVATE-ready.html" in requested:
            limits["PRIVATE-ready.html"] = 1300000
        original_source = None
        review_source = None
        original_app = None
        ready_source = None
        for filename, max_size in limits.items():
            reference = references[filename]
            if type(reference) is not dict or set(reference) != {"sha256", "bytes"}:
                raise Refused("invalid file metadata")
            sha = reference["sha256"]
            if (
                type(sha) is not str
                or len(sha) != 64
                or any(c not in "0123456789abcdef" for c in sha)
                or type(reference["bytes"]) is not int
                or not 2 <= reference["bytes"] <= max_size
            ):
                raise Refused("invalid manifest digest")
            raw = _private_file(dirfd, filename, max_size)
            if len(raw) != reference["bytes"] or hashlib.sha256(raw).hexdigest() != sha:
                raise Refused("manifest / private file mismatch")
            if filename == "casebook.json":
                _validate_source(raw)
                original_source = raw
            elif filename == "PRIVATE-review.json":
                review_source = raw
            elif filename == "PRIVATE-ready.html":
                ready_source = raw
            elif filename == "standalone.html":
                from app_integrity import InvalidApp, admit_standalone
                try:
                    admit_standalone(raw)
                    original_app = raw
                except InvalidApp as exc:
                    raise Refused("private application CSP mismatch") from exc
        if ready_source is not None:
            from ready_room import admit_ready
            admit_ready(original_app, original_source, ready_source)
        if review_source is not None:
            from review_binding import admit_private_review
            admit_private_review(original_source, review_source)
    finally:
        os.close(dirfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a private Scope Impact Map handoff, never grant release or permission."
    )
    parser.add_argument("workspace", type=Path, help="Existing owner-private workspace")
    args = parser.parse_args()
    try:
        inspect(args.workspace)
    except (Refused, OSError, ValueError, TypeError):
        print("HOLD: private packet could not be reconciled.", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: private files match their local UNTRUSTED manifest; no consent or authority proof.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
