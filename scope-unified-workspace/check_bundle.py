#!/usr/bin/env python3
"""Read-only PRIVATE transport inventory checker. NEVER grants authorization.

Checks the packaged file inventory against a pinned source-head list, but an
unsigned inventory cannot prove authorship, client consent or safe behavior.
Success is deliberately REVIEW_ONLY (exit 3), not 0 / deploy permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

FORMAT = "lightup.scope_offline_bundle.v1"
POSTURE = "INCUBATE_M3_M7_DRAFT_HOLD"
MANIFEST = "scope-unified-workspace/SOURCE-MANIFEST.json"
SOURCES = {
    "scope-intake-matrix": "480e4c5e0ff6ffbf020719f0ab3c03c9d1162538",
    "scope-casebook-history": "2e10197061fe7876dcd6458ae4fc70d9674af9d3",
    "scope-casebook-transfer": "f40b0d2cf626e49bbd8f764968df132ba9d4365a",
    "scope-casebook-reconcile": "7de3f5a5549c738eeb90f81c687c9a7d9c7cab3a",
    "authorization-portfolio": "2ac15c5b24bf5646c3749c26fed577209b1b1221",
    "withdrawal-desk": "0235d93fe285edc0cc49ea3aec3580b7dc4e1338",
    "scope-vault": "49a569b2125a80dcaac21655febc07861afa0df2",
    "studio": "71d9e5f760ef2bff46a72b979173bb3181179afb",
}
AUTHORITY_KEYS = {"client_consent", "operator_consent", "grant", "scan", "deploy", "release"}
MANDATORY = {
    "scope-unified-workspace/index.html",
    "scope-unified-workspace/verify.html",
    "scope-unified-workspace/handoff.html",
    "scope-unified-workspace/source_pins.py",
    "scope-unified-workspace/PINNED-ORIGINALS.json",
    "scope-unified-workspace/README.md",
    "scope-unified-workspace/check_bundle.py",
    "scope-intake-matrix/standalone.html",
    "scope-casebook-transfer/standalone.html",
    "scope-casebook-reconcile/standalone.html",
    "authorization-portfolio/standalone.html",
    "withdrawal-desk/standalone.html",
    "scope-vault/standalone.html",
    "studio/index.html",
    "studio/scope-proposal.html",
    "scope-casebook-history/README.md",
}
MAX_FILES = 100
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 30 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")


class Hold(Exception):
    pass


def no_duplicate_keys(items):
    result = {}
    for k, value in items:
        if k in result:
            raise Hold("duplicate JSON property")
        result[k] = value
    return result


def invalid_constant(value):
    raise Hold("invalid numeric constant")


def safe_name(name):
    if type(name) is not str or not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise Hold("unsafe archive member")
    path = PurePosixPath(name)
    if path.as_posix() != name or any(part in (".", "..") for part in name.split("/")):
        raise Hold("noncanonical archive member")
    if ":" in name or path.parts[0] not in (*SOURCES.keys(), "scope-unified-workspace"):
        raise Hold("unexpected archive member prefix")
    if len(name.encode("utf-8")) > 300:
        raise Hold("unbounded member path")
    return name


def parse_manifest(data):
    if len(data) > 128 * 1024:
        raise Hold("oversized inventory")
    try:
        m = json.loads(data.decode("utf-8", "strict"),
                       object_pairs_hook=no_duplicate_keys, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Hold("invalid inventory JSON") from exc
    if type(m) is not dict or set(m) != {
        "format", "posture", "authority", "pinned_original_branch_heads",
        "file_entries", "note",
    }:
        raise Hold("invalid inventory shape")
    if m["format"] != FORMAT or m["posture"] != POSTURE:
        raise Hold("unsupported inventory posture")
    a = m["authority"]
    if type(a) is not dict or set(a) != AUTHORITY_KEYS or any(type(a[k]) is not bool or a[k] is not False for k in AUTHORITY_KEYS):
        raise Hold("authority claim in untrusted inventory")
    if m["pinned_original_branch_heads"] != SOURCES:
        raise Hold("original source-head mismatch")
    if type(m["note"]) is not str or not m["note"].startswith("Unsigned transport inventory"):
        raise Hold("unsigned inventory disclaimer missing")
    entries = m["file_entries"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_FILES:
        raise Hold("invalid file count")
    expected = {}
    size_total = 0
    for row in entries:
        if type(row) is not dict or set(row) != {"path", "size", "sha256"}:
            raise Hold("malformed file entry")
        name = safe_name(row["path"])
        length = row["size"]
        digest = row["sha256"]
        if name == MANIFEST or name in expected:
            raise Hold("recursive/duplicate file inventory")
        if type(length) is not int or not 0 <= length <= MAX_FILE:
            raise Hold("invalid member size")
        if type(digest) is not str or not HASH.fullmatch(digest):
            raise Hold("invalid digest")
        size_total += length
        if size_total > MAX_TOTAL:
            raise Hold("inventory size bound exceeded")
        expected[name] = (length, digest)
    if not MANDATORY.issubset(expected):
        raise Hold("missing required original offline apps or launcher")
    return expected


def check_contents(file_data):
    # file_data is an iterator of canonical member names and complete bounded bytes.
    contents = {}
    total = 0
    for name, data in file_data:
        name = safe_name(name)
        if name in contents:
            raise Hold("duplicate archive member")
        if len(data) > MAX_FILE:
            raise Hold("oversized member")
        contents[name] = (len(data), hashlib.sha256(data).hexdigest())
        total += len(data)
        if len(contents) > MAX_FILES + 1 or total > MAX_TOTAL:
            raise Hold("archive budget exceeded")
    if MANIFEST not in contents:
        raise Hold("missing inventory")
    return contents


def inspect_zip(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_TOTAL:
        raise Hold("missing, symlinked or oversized ZIP")
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if not 2 <= len(infos) <= MAX_FILES + 1:
            raise Hold("unexpected ZIP entry count")
        seen = set()
        total_size = 0
        data = []
        manifest_bytes = None
        for info in infos:
            name = safe_name(info.filename)
            if name in seen or info.is_dir():
                raise Hold("duplicate member or directory ZIP entry")
            seen.add(name)
            mode = info.external_attr >> 16
            if mode and not stat.S_ISREG(mode):
                raise Hold("unsafe ZIP member kind")
            if not 0 <= info.file_size <= MAX_FILE or info.flag_bits & 0x1:
                raise Hold("oversized/encrypted ZIP member")
            total_size += info.file_size
            if total_size > MAX_TOTAL:
                raise Hold("ZIP expanded size bound exceeded")
            with archive.open(info) as handle:
                blob = handle.read(MAX_FILE + 1)
            if len(blob) != info.file_size:
                raise Hold("short or oversized ZIP member")
            if name == MANIFEST:
                manifest_bytes = blob
            data.append((name, blob))
        expected = parse_manifest(manifest_bytes or b"")
        actual = check_contents(data)
    return expected, actual


def inspect_dir(path):
    if not path.is_dir() or path.is_symlink():
        raise Hold("missing or unsafe extracted directory")
    files = []
    for top in (*SOURCES, "scope-unified-workspace"):
        d = path / top
        if not d.is_dir() or d.is_symlink():
            raise Hold("missing extracted source directory")
        for p in d.rglob("*"):
            if p.is_symlink():
                raise Hold("symbolic links not allowed in extracted bundle")
            if p.is_dir():
                continue
            if not p.is_file() or p.stat().st_size > MAX_FILE:
                raise Hold("unexpected or oversized extracted member")
            name = safe_name(p.relative_to(path).as_posix())
            with p.open("rb") as handle:
                blob = handle.read(MAX_FILE + 1)
            files.append((name, blob))
    manifest_data = next((d for n, d in files if n == MANIFEST), b"")
    expected = parse_manifest(manifest_data)
    actual = check_contents(files)
    return expected, actual


def main():
    parser = argparse.ArgumentParser(description="Strict offline scope-package transport comparison; never authorizes")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--zip", type=Path, help="PRIVATE bundle ZIP path (no extraction)")
    group.add_argument("--directory", type=Path, help="Freshly extracted bundle root")
    args = parser.parse_args()
    try:
        expected, actual = inspect_zip(args.zip) if args.zip else inspect_dir(args.directory)
        if set(actual) != set(expected) | {MANIFEST}:
            raise Hold("missing or unexpected package files")
        for name, pair in expected.items():
            if actual.get(name) != pair:
                raise Hold("private package member differs from unsigned inventory")
    except (Hold, OSError, ValueError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        print("HOLD: offline package inventory could not be admitted (" + type(exc).__name__ + ").", file=sys.stderr)
        return 2
    print("REVIEW_ONLY: local package bytes match their unsigned source inventory.")
    print("Original branch identities, security, consent, grant and deployment remain UNVERIFIED / FALSE.")
    print("No scan, grant, client data, database, network, deployment or source authentication was performed.")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
