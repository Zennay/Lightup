#!/usr/bin/env python3
"""Deterministic source-only offline distribution builder and inventory inspector.

No private source data, scanning, model, permissions, authentication or network.
The manifest SHA256 is an unsigned local software identity inventory only.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

from ledger import Hold, canonical, object_unique, private_parent, reject

ROOT = Path(__file__).resolve().parent
PREFIX = "LightUp-Workspace-Ledger/"
NAMES = (
    "README.md", "ledger.py", "browser_studio.py", "compare.py", "continuity.py",
    "console.py", "human_revisions.py", "browser_intake.py", "package.py", "standalone.html",
)
SCHEMA = "lightup.private.workspace-ledger-software.v10"
FLAGS = {
    "authorization": False, "consent": False,
    "verified_finding": False, "release_approval": False,
}
MAX_FILE = 1_048_576
MAX_TOTAL = 6_291_456


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_source(name):
    if name not in NAMES:
        reject("PRIVATE HOLD: software source not allowlisted")
    fd = os.open(ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_FILE:
            reject("PRIVATE HOLD: unsupported or nonregular software source")
        payload = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > MAX_FILE:
                reject("PRIVATE HOLD: software size changed during read")
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(payload) != info.st_size:
            reject("PRIVATE HOLD: software source changed while packaging")
        return bytes(payload)
    finally:
        os.close(fd)


def bundle():
    entries = [(name, read_source(name)) for name in NAMES]
    manifest = {
        "schema": SCHEMA,
        "authority": FLAGS,
        "includes_customer_data": False,
        "files": [{"path": name, "bytes": len(data), "sha256": sha256(data)}
                  for name, data in entries],
    }
    entries.append(("manifest.json", json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8") + b"\n"))
    result = io.BytesIO()
    with zipfile.ZipFile(result, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as dst:
        for name, data in entries:
            info = zipfile.ZipInfo(PREFIX + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            dst.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return result.getvalue()


def build(args):
    dest = Path(args.output)
    if not dest.is_absolute() or dest.suffix.lower() != ".zip":
        reject("PRIVATE HOLD: output requires an absolute .zip filename")
    private_parent(str(dest.parent))
    if dest.is_relative_to(ROOT):
        reject("PRIVATE HOLD: output must be outside source checkout")
    contents = bundle()
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        count = 0
        while count < len(contents):
            count += os.write(fd, contents[count:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE REVIEW_ONLY: offline software-only archive produced (unsigned inventory)")
    print("Archive: " + str(dest))
    print("SHA256: " + sha256(contents))
    return 2


def unique_object(pairs):
    return object_unique(pairs)


def inspect(args):
    path = Path(args.archive)
    if not path.is_absolute():
        reject("PRIVATE HOLD: absolute source-only ZIP path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_TOTAL:
            reject("PRIVATE HOLD: archive size/type")
        raw = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_TOTAL:
                reject("PRIVATE HOLD: archive byte limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: archive changed during inspection")
    finally:
        os.close(fd)
    with zipfile.ZipFile(io.BytesIO(raw), "r") as src:
        entries = src.infolist()
        expected = [PREFIX + name for name in NAMES] + [PREFIX + "manifest.json"]
        if len(entries) != len(expected) or [entry.filename for entry in entries] != expected:
            reject("PRIVATE HOLD: ZIP entries are missing/reordered/extra/duplicate")
        content = {}
        total = 0
        for entry, name in zip(entries, list(NAMES) + ["manifest.json"]):
            if entry.flag_bits & 1 or entry.file_size <= 0 or entry.file_size > MAX_FILE or (
                entry.external_attr >> 16
            ) & 0o170000 not in (0, 0o100000):
                reject("PRIVATE HOLD: encrypted/symlink/unsupported ZIP entry")
            if entry.compress_type != zipfile.ZIP_DEFLATED:
                reject("PRIVATE HOLD: unexpected ZIP encoding")
            total += entry.file_size
            if total > MAX_TOTAL:
                reject("PRIVATE HOLD: uncompressed software size")
            data = src.read(entry)
            if len(data) != entry.file_size:
                reject("PRIVATE HOLD: ZIP data length")
            content[name] = data
    try:
        manifest = json.loads(content["manifest.json"].decode("utf-8"),
                              object_pairs_hook=unique_object,
                              parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite manifest"))
    except (ValueError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: invalid manifest") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "authority", "includes_customer_data", "files"
    } or manifest["schema"] != SCHEMA or manifest["authority"] != FLAGS or (
        manifest["includes_customer_data"] is not False
    ):
        reject("PRIVATE HOLD: source-only manifest schema/authority")
    rows = manifest["files"]
    if not isinstance(rows, list) or len(rows) != len(NAMES):
        reject("PRIVATE HOLD: wrong manifest source count")
    for row, name in zip(rows, NAMES):
        data = content[name]
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"} or (
            row["path"] != name or type(row["bytes"]) is not int or row["bytes"] != len(data)
            or row["sha256"] != sha256(data)
        ):
            reject("PRIVATE HOLD: ZIP bytes disagree with manifest")
    print("PRIVATE REVIEW_ONLY: software archive internal file hashes and schema match")
    print("UNSIGNED SHA256: " + sha256(raw))
    print("This is NOT software publisher authentication, approval, verified security, or consent.")
    return 2


def main():
    parser = argparse.ArgumentParser(description="Offline fixed-file software ZIP build or unsigned inventory inspection")
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("build", help="Build a new source-only ZIP outside checkout")
    make.add_argument("--output", required=True)
    check = sub.add_parser("inspect", help="Read a source-only ZIP and verify bounded unsigned internal SHA manifest")
    check.add_argument("--archive", required=True)
    args = parser.parse_args()
    try:
        return build(args) if args.action == "build" else inspect(args)
    except (Hold, OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError):
        print("PRIVATE HOLD: software archive operation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
