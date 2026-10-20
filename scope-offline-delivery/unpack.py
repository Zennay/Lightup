#!/usr/bin/env python3
"""Unpack a validated offline DRAFT/HOLD scope delivery into a new PRIVATE directory.

No grant, network, active assessment, auth, scanner, background service or deployment.
"""
from __future__ import annotations

import argparse
import ctypes
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import zipfile
from package import inspect, FILES, PRIVACY_FILES

def publish_directory_no_replace(staged: Path, destination: Path) -> None:
    # Linux RENAME_NOREPLACE is atomic even if another actor creates the path
    # after our preflight. Refuse platforms without the primitive.
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ValueError("Atomic NO_REPLACE folder publication is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(staged), -100,
                 os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))

MAX_ORIGINAL_MEMBERS = 256
MAX_UNPACK_BYTES = 16_000_000
MAX_MEMBER_BYTES = 2_000_000


def _safe_path(name: str) -> bool:
    return (type(name) is str and bool(name) and not name.startswith("/")
            and "\\" not in name and not name.endswith("/")
            and all(x not in ("", ".", "..") for x in name.split("/"))
            and all(ord(ch) >= 32 for ch in name))


def publish(archive: Path, destination: Path, expected_sha256: str | None = None) -> dict:
    evidence = inspect(archive, expected_sha256)
    parent = destination.absolute().parent
    if (not parent.is_dir() or parent.is_symlink()
            or (parent.stat().st_mode & 0o077)
            or parent.stat().st_uid != os.getuid()):
        raise ValueError("Output parent must be an existing operator-owned PRIVATE (0700) folder")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Destination exists; never overwrite")

    with zipfile.ZipFile(archive) as outside:
        original_zip = outside.read("workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip")
        with zipfile.ZipFile(io.BytesIO(original_zip)) as inside:
            entries = inside.infolist()
            if not 60 <= len(entries) <= MAX_ORIGINAL_MEMBERS:
                raise ValueError("Original archive membership changed")
            total_bytes = 0
            seen = set()
            for entry in entries:
                name = entry.filename
                if entry.is_dir():
                    # Explicit folder records carry no bytes and are never materialized.
                    name = name.rstrip("/")
                if not _safe_path(name) or entry.filename in seen:
                    raise ValueError("Unsafe or ambiguous original entry")
                seen.add(entry.filename)
                mode = entry.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("Links/devices in original workspace are forbidden")
                if (entry.flag_bits & 1 or entry.file_size > MAX_MEMBER_BYTES
                        or (entry.is_dir() and entry.file_size)):
                    raise ValueError("Unsafe original entry bytes or encryption")
                total_bytes += entry.file_size
            if total_bytes > MAX_UNPACK_BYTES:
                raise ValueError("Original expanded files exceed PRIVATE intake limit")

            stage = Path(tempfile.mkdtemp(prefix=".lightup-priv-", dir=parent))
            try:
                def put(name: str, payload: bytes) -> None:
                    if not _safe_path(name):
                        raise ValueError("Unsafe output path")
                    target = stage.joinpath(*PurePosixPath(name).parts)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(fd, "wb") as output:
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())

                for name in sorted(set(FILES) | set(PRIVACY_FILES) | {
                    "tools/package.py", "tools/unpack.py", "README.txt",
                    "START-HERE.html", "manifest.json",
                    "PRIVATE-receive.html", "tools/recipient.js",
                    "tools/recipient.css", "tools/recipient_zip.js", "tools/role_builder.js", "tools/handoff_review.js", "tools/ack_return.js", "tools/role_pack.py", "tools/recipient.template.html"}):
                    put(name, outside.read(name))
                for entry in entries:
                    if not entry.is_dir():
                        put("original-workspace/" + entry.filename, inside.read(entry))
                put("REVIEW-ONLY.txt", (
                    "LightUp · ORIGINAL offline scope workspace, source-byte reviewed.\n"
                    "Original HUMAN choices do not grant scope or verify consent.\n"
                    "INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.\n").encode())
                if destination.exists() or destination.is_symlink():
                    raise ValueError("Destination appeared concurrently; no overwrite")
                # Parent is operator-owned, private and non-symlinked.
                publish_directory_no_replace(stage, destination)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)
    return {**evidence, "status": "REVIEW_ONLY",
            "private_destination": str(destination), "original_entries": len(entries)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Unpack ONLY fully admitted original offline scope files")
    parser.add_argument("outer_zip", type=Path)
    parser.add_argument("new_private_destination", type=Path)
    parser.add_argument("--expected-sha256", help="Optional independently authenticated outer ZIP SHA-256")
    args = parser.parse_args()
    try:
        print(json.dumps(publish(args.outer_zip, args.new_private_destination, args.expected_sha256), sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, UnicodeError) as error:
        print("HOLD: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
