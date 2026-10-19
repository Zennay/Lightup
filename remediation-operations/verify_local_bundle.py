#!/usr/bin/env python3
"""PRIVATE offline integrity inventory verifier for a LightUp evidence workspace.

This is a user-facing package integrity utility, NOT QA, source authentication,
CI, evidence verification, security approval, consent, or authority to scan.
Never extracts archive entries, runs apps, connects to networks or changes source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

MAX_SOURCE_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
APP_DIRECTORIES = {
    "remediation-artifact-ledger", "remediation-response-reconciliation",
    "remediation-handoff-inbox", "remediation-human-runbooks", "remediation-operations",
    "remediation-vault", "remediation-change-windows",
}
REQUIRED_HEADS = {"1642", "1643", "1644", "1645", "1640", "1631"}
FALSE_FLAGS = (
    "authentication", "client_consent", "operator_consent", "active_execution",
    "security_fix_verified", "production_release_approved",
)


class Refused(Exception):
    """Non-authorizing offline package refused; no source bytes are executed."""


def pairwise_unique(items: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in items:
        if key in result:
            raise Refused("Duplicate JSON property")
        result[key] = value
    return result


def safe_name(name: str) -> bool:
    if not isinstance(name, str) or not name.isascii() or len(name) > 240:
        return False
    parts = PurePosixPath(name).parts
    if not parts or parts[0] not in APP_DIRECTORIES or len(parts) < 2:
        return False
    if name.startswith("/") or "\\" in name or name.endswith("/") or "//" in name:
        return False
    if any(part in (".", "..") or part.startswith(".") for part in parts):
        return False
    return all(part.replace("-", "").replace("_", "").replace(".", "").isalnum() for part in parts)


def manifest_from(data: bytes) -> dict:
    if len(data) > MAX_MANIFEST:
        raise Refused("Manifest too large")
    try:
        doc = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairwise_unique)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Refused("Invalid or ambiguous UTF-8 JSON manifest") from exc
    if not isinstance(doc, dict):
        raise Refused("Manifest must be an object")
    if doc.get("schema") != "lightup-private-human-evidence-integration-v1":
        raise Refused("Unknown original integration schema")
    if doc.get("start") != "remediation-operations/index.html":
        raise Refused("Unexpected workspace entrypoint")
    if doc.get("release") != "INCUBATE M3/M7 - PLAN/LAB ONLY - DRAFT/HOLD":
        raise Refused("Unexpected or overclaimed release phase")
    if any(doc.get(flag) is not False for flag in FALSE_FLAGS):
        raise Refused("An authority assertion is not literally false")
    heads = doc.get("original_source_pr_heads")
    if not isinstance(heads, dict) or set(heads) != REQUIRED_HEADS:
        raise Refused("Incomplete original source-owner inventory")
    if any(not isinstance(value, str) or len(value) != 40 or
           any(c not in "0123456789abcdef" for c in value) for value in heads.values()):
        raise Refused("Malformed declared original source-owner commit")
    rows = doc.get("files")
    if not isinstance(rows, list) or not 44 <= len(rows) <= 1000:
        raise Refused("Incomplete or excessive source file inventory")
    source = {}
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise Refused("Malformed source file identity")
        name, length, digest = row["path"], row["bytes"], row["sha256"]
        if not safe_name(name) or name in source:
            raise Refused("Duplicate or unsafe source file path")
        if type(length) is not int or length < 0 or length > MAX_SOURCE_FILE:
            raise Refused("Invalid source byte length")
        if (not isinstance(digest, str) or len(digest) != 64 or
                any(c not in "0123456789abcdef" for c in digest)):
            raise Refused("Malformed source SHA-256")
        source[name] = (length, digest)
        total += length
        if total > MAX_TOTAL:
            raise Refused("Source inventory exceeds 32 MiB")
    if {name.split("/", 1)[0] for name in source} != APP_DIRECTORIES:
        raise Refused("Missing original application directory")
    doc["_verified_inventory"] = source
    return doc


def integrity_bytes(source: dict[str, tuple[int, str]], read_file) -> None:
    for name, (expected_len, expected_digest) in source.items():
        content = read_file(name, expected_len)
        if len(content) != expected_len:
            raise Refused(f"Content length mismatch: {name}")
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise Refused(f"Content SHA mismatch: {name}")


def inspect_zip(path: Path) -> int:
    if not path.is_file() or path.is_symlink():
        raise Refused("Expected regular ZIP file")
    if path.stat().st_size > 40 * 1024 * 1024:
        raise Refused("ZIP file exceeds package size bound")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 1100:
                raise Refused("Excessive archive entries")
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise Refused("Duplicate ZIP entry")
            if any(not safe_name(name) for name in names):
                raise Refused("Unexpected ZIP entry path")
            if any((item.external_attr >> 16) & 0o170000 == stat.S_IFLNK for item in infos):
                raise Refused("ZIP contains a symbolic link")
            if any(item.file_size > MAX_SOURCE_FILE for item in infos):
                raise Refused("ZIP member exceeds 8 MiB")
            if "remediation-operations/MANIFEST.json" not in names:
                raise Refused("Missing manifest")
            manifest_info = archive.getinfo("remediation-operations/MANIFEST.json")
            if manifest_info.file_size > MAX_MANIFEST:
                raise Refused("Manifest too large")
            doc = manifest_from(archive.read(manifest_info))
            source = doc["_verified_inventory"]
            if set(names) != set(source) | {"remediation-operations/MANIFEST.json"}:
                raise Refused("Archive contains unexpected or missing entries")
            def read_exact(name: str, length: int) -> bytes:
                entry = archive.getinfo(name)
                if entry.file_size != length:
                    raise Refused("ZIP size mismatch")
                return archive.read(entry)
            integrity_bytes(source, read_exact)
            return len(source)
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError) as exc:
        raise Refused("Invalid PRIVATE ZIP archive") from exc


def inspect_directory(root: Path) -> int:
    if not root.is_dir() or root.is_symlink():
        raise Refused("Missing extracted workspace root")
    manifest_path = root / "remediation-operations" / "MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise Refused("Missing regular manifest file")
    doc = manifest_from(manifest_path.read_bytes())
    source = doc["_verified_inventory"]
    def read_exact(name: str, length: int) -> bytes:
        path = root.joinpath(*PurePosixPath(name).parts)
        if path.is_symlink() or not path.is_file():
            raise Refused("Missing regular source file")
        if path.stat().st_size != length:
            raise Refused("Source byte count changed")
        return path.read_bytes()
    integrity_bytes(source, read_exact)
    return len(source)


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE LightUp source content inventory verification (NOT authorization)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--zip", type=Path, help="Read packaged ZIP in-place, without extracting")
    group.add_argument("--directory", type=Path, help="Read extracted workspace directory")
    args = parser.parse_args()
    try:
        checked = (inspect_zip(args.zip) if args.zip else
                   inspect_directory(args.directory or Path(__file__).resolve().parent.parent))
    except (Refused, OSError) as exc:
        print(f"INTEGRITY HOLD: {exc}; no authority or source authenticity claimed.", file=sys.stderr)
        return 2
    print(f"LOCAL CONTENT INTEGRITY MATCH: {checked} files; NOT source authentication, CI, customer consent or release approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
