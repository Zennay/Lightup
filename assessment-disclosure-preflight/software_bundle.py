"""Deterministic software-only offline assessment kit builder (NO CLIENT DATA).

This static package never runs a scanner, imports customer evidence,
authenticates a sender, changes grants, claims review or confers release.
It only copies allowlisted bounded Git source assets into an unsigned ZIP.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

SOFTWARE_FILES = (
    "README.md", "preflight.py", "human_review.py", "vault_native.py",
    "reconcile.py", "requirements-native.txt", "review-studio.html",
    "review-studio.css", "review-studio.js", "review-vault.js", "package.py",
    "standalone.html", "reconcile-studio.html", "reconcile-studio.css",
    "reconcile-studio.js", "reconcile_package.py", "reconcile-standalone.html",
    "software_bundle.py",
)
MAX_ASSET = 512 * 1024
ARCHIVE_NAME = "LightUp-PRIVATE-Assessment-Offline-Kit.zip"
PREFIX = "assessment-disclosure-preflight/"
TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def admit_asset(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ASSET:
            raise ValueError("source-only asset not admitted")
        with os.fdopen(fd, "rb", closefd=False) as reader:
            raw = reader.read(MAX_ASSET + 1)
        after = os.fstat(fd)
        if not 0 < len(raw) <= MAX_ASSET or before.st_size != len(raw):
            raise ValueError("source asset changed or exceeds limit")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("source asset changed during read")
        raw.decode("utf-8", "strict")
        if b"\x00" in raw:
            raise ValueError("binary customer material refused")
        return raw
    finally:
        os.close(fd)


def compose(assets: dict[str, bytes]) -> bytes:
    if set(assets) != set(SOFTWARE_FILES):
        raise ValueError("only the fixed source-only software inventory is accepted")
    for name, data in assets.items():
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_ASSET:
            raise ValueError("unsafe source-only software entry")
        if b"\x00" in data:
            raise ValueError("binary/unexpected content refused")
        data.decode("utf-8", "strict")
    manifest = {
        "schema": "lightup.private_assessment_offline_software.v1",
        "status": "REVIEW_ONLY",
        "software_only": True,
        "source_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "release_allowed": False,
        "signed": False,
        "original_lab_inspector_included": False,
        "files": [
            {"path": PREFIX + name, "size": len(assets[name]),
             "sha256": hashlib.sha256(assets[name]).hexdigest()}
            for name in sorted(SOFTWARE_FILES)
        ],
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, strict_timestamps=True) as archive:
        for name, data in sorted(
            [(PREFIX + n, assets[n]) for n in SOFTWARE_FILES] +
            [(PREFIX + "MANIFEST.json", manifest_bytes)]
        ):
            entry = zipfile.ZipInfo(name, date_time=TIMESTAMP)
            entry.create_system = 3
            entry.external_attr = (0o100644 << 16)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    result = output.getvalue()
    if not 0 < len(result) <= 1024 * 1024:
        raise ValueError("static software-only package outside limit")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic unsigned PRIVATE offline software kit")
    parser.add_argument("--output", default=ARCHIVE_NAME)
    args = parser.parse_args()
    if args.output != ARCHIVE_NAME:
        parser.error("only the fixed software kit filename is admitted")
    root = Path(__file__).resolve().parent
    archive = compose({name: admit_asset(root / name) for name in SOFTWARE_FILES})
    fd, staging = tempfile.mkstemp(prefix=".lightup-software-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(archive)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, root / ARCHIVE_NAME)
        dirfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(staging)
        except FileNotFoundError:
            pass
    print("REVIEW_ONLY: unsigned source-only offline software package published exclusively")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
