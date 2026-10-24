#!/usr/bin/env python3
"""Offline fail-closed receipt of the LightUp PRIVATE scheduler software-only ZIP.

Requires an independently obtained locally trusted bundle receipt and
preinstalled source-only code. Checks original pinned source bytes, never
treats unsigned hashes as genuine sender or release approval. NO execution.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import zipfile

import bundle
import schedule
sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import install

MAX_ARCHIVE = 5_000_000
MAX_MEMBERS = 180
ORIGINAL_RUNTIME = frozenset((
    "remediation-integrated-workspace/install.py",
    "remediation-integrated-workspace/receiver.py",
    "remediation-integrated-workspace/workflow.py",
    "remediation-integrated-workspace/portable_cockpit.py",
    "remediation-integrated-workspace/single_review.py",
    "remediation-integrated-workspace/single_review.js",
    "remediation-integrated-workspace/single_brief.py",
    "remediation-integrated-workspace/SINGLE_REVIEW.md",
    "remediation-integrated-workspace/archive_workflow.py",
    "remediation-integrated-workspace/encrypted_cockpit.py",
    "remediation-integrated-workspace/journal_vault.py",
    "remediation-integrated-workspace/journal_encrypt.js",
    "remediation-integrated-workspace/journal_open.js",
    "remediation-integrated-workspace/review_package.py",
    "remediation-integrated-workspace/REVIEW_PACKAGE.md",
    "remediation-integrated-workspace/JOURNAL_VAULT.md",
    "remediation-integrated-workspace/README.md",
))


def require(condition: bool, explanation: str) -> None:
    install.require(condition, explanation)


def read_private(path: Path, bound: int) -> bytes:
    require(path.is_absolute() and
            path.parent == path.parent.resolve(strict=True) and
            not path.is_symlink(), "PRIVATE input needs an absolute literal path")
    install.owner_dir(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_mode & 0o077 == 0
            and 1 <= before.st_size <= bound,
            "PRIVATE input must be a bounded owner-only one-link regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require(opened.st_ino == before.st_ino and opened.st_dev == before.st_dev
                and opened.st_size == before.st_size,
                "PRIVATE input identity changed before read")
        value = os.read(fd, bound + 1)
        after = os.fstat(fd)
        require(len(value) == opened.st_size == after.st_size
                and opened.st_mtime_ns == after.st_mtime_ns,
                "PRIVATE input changed during read")
        return value
    finally:
        os.close(fd)


def admission(receipt: bytes, archive: bytes) -> dict[str, bytes]:
    metadata = install.parse(receipt)
    require(set(metadata) == {
        "kind", "version", "disposition", "authority_granted",
        "consent_verified", "remediation_verified", "scan_authorized",
        "original_native_manifest_sha256", "source_heads",
        "software_files", "portable_zip_sha256", "portable_zip_bytes", "warning",
    } and metadata["kind"] == bundle.KIND
            and type(metadata["version"]) is int and metadata["version"] == 1
            and metadata["disposition"] == bundle.DISPOSITION
            and metadata["warning"] == bundle.WARNING
            and all(metadata[k] is False for k in (
                "authority_granted", "consent_verified", "remediation_verified",
                "scan_authorized")),
            "Unknown recipient software bundle or authority assertion")
    native = install.catalog()[1]
    require(metadata["source_heads"] == native["source_heads"],
            "Source owner pins changed or private bundle compiled against different sources")
    table = metadata["software_files"]
    require(type(table) is dict and 80 <= len(table) <= MAX_MEMBERS
            and len(archive) == metadata["portable_zip_bytes"]
            and hashlib.sha256(archive).hexdigest() == metadata["portable_zip_sha256"],
            "Incomplete or modified offline HUMAN software ZIP")
    native_files = set(native["files"])
    companion = {"remediation-recipient-scheduler/" + p for p in bundle.SCHEDULER_FILES}
    expected_names = native_files | companion | ORIGINAL_RUNTIME | {
        "index.html", "original-home.html", "source-lock.json"
    }
    require(set(table) == expected_names,
            "Native original or additive HUMAN recipient source inventory changed")
    admitted: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        infos = z.infolist()
        require(len(infos) == len(table) <= MAX_MEMBERS
                and [i.filename for i in infos] == sorted(table),
                "Unsafe duplicated/reordered/private software ZIP inventory")
        for info in infos:
            name = info.filename
            descriptor = table[name]
            require(type(name) is str and
                    name in expected_names
                    and not info.is_dir() and not name.startswith("/")
                    and ".." not in name.split("/")
                    and (info.external_attr >> 16) == 0o100600
                    and type(descriptor) is dict and
                    set(descriptor) == {"sha256","bytes"} and
                    type(descriptor["bytes"]) is int and
                    0 <= descriptor["bytes"] <= bundle.MAX_MEMBER
                    and info.file_size == descriptor["bytes"]
                    and info.compress_size <= MAX_ARCHIVE,
                    "Private software ZIP entry unsafe or violates its own inventory")
            total += info.file_size
            require(total <= bundle.MAX_TOTAL, "Inflated private software bundle exceeds size bound")
            raw = z.read(info)
            require(len(raw) == info.file_size and
                    hashlib.sha256(raw).hexdigest() == descriptor["sha256"],
                    "Private software byte differs from original manifest")
            if name in native_files:
                pinned = native["files"][name]
                require(len(raw) == pinned["bytes"] and
                        hashlib.sha256(raw).hexdigest() == pinned["sha256"],
                        "Original owner source SHA-256 pin changed")
            admitted[name] = raw
    require(admitted["source-lock.json"] == install.LOCK.read_bytes()
            and admitted["index.html"] == bundle.page()
            and admitted["original-home.html"] == install.home(),
            "Original source lock or scriptless source-only portal changed")
    for name in companion | ORIGINAL_RUNTIME:
        require(admitted[name] == (schedule.PARENT / name).read_bytes(),
                "Received original native or scheduler companion differs from trusted local source")
    return admitted


def receive(archive: Path, manifest: Path, output: Path) -> None:
    require(archive != manifest and
            output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose a distinct new absolute PRIVATE recipient output folder")
    install.owner_dir(output.parent)
    for source in (archive,manifest):
        require(source != output and source.parent != output
                and output not in source.parents and source not in output.parents,
                "PRIVATE input cannot overlap receiver publication")
    original_zip = read_private(archive, MAX_ARCHIVE)
    original_manifest = read_private(manifest, 350_000)
    files = admission(original_manifest, original_zip)
    stage = output.parent / (".lightup-recipient-software-receive-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        for name, content in files.items():
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            install.write_file(target, content)
        # Independent receipt bytes remain next to runnable software but
        # are not included in the original source-only ZIP inventory.
        install.write_file(stage / "private-receipt.json", original_manifest)
        require(admission(read_private(stage / "private-receipt.json", 350_000),
                          original_zip).keys() == files.keys(),
                "Generated private receiver source identity changed")
        require(read_private(archive, MAX_ARCHIVE) == original_zip
                and read_private(manifest, 350_000) == original_manifest,
                "External recipient software or source receipt changed during intake")
        require(not output.exists(), "Recipient appeared before exclusive publication")
        install.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: PRIVATE original pinned recipient software admitted:", output)
    print("Open local offline launcher:", output / "index.html")
    print("No network, grant, scan, verified remediation, sender identity or release authority.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True,
                        help="Private 0600 owner-only portable merged software ZIP")
    parser.add_argument("--manifest", type=Path, required=True,
                        help="Separately obtained trusted bundle-manifest.json, 0600")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New absolute private software destination under 0700 parent")
    args = parser.parse_args()
    try:
        receive(args.archive, args.manifest, args.output_dir)
        return 2
    except (install.Hold, ValueError, OSError, TypeError, KeyError,
            RuntimeError, zipfile.BadZipFile) as exc:
        print("HOLD: source-only HUMAN software receipt:", exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
