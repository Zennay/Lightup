#!/usr/bin/env python3
"""Fail-closed, software-only offline LightUp recipient. Never authenticates sender."""
from __future__ import annotations
import io
import os
from pathlib import Path
import secrets
import shutil
import zipfile

import install as suite

# One exact source of truth for builder and receiver file inventory.
TOOLS = frozenset(suite.INTEGRATED_TOOLS)

def receive(archive: Path, destination: Path) -> None:
    suite.owner_dir(archive.parent)
    raw = suite.read_owner_file(archive)
    suite.require(0 < len(raw) <= suite.MAX_TOTAL, "Oversized incoming software ZIP")
    lock_bytes, lock = suite.catalog()
    expected = set(lock["files"]) | set(TOOLS) | {"source-lock.json", "index.html", "operator.html"}
    suite.require(destination.is_absolute() and not destination.exists()
                  and not destination.is_symlink()
                  and destination.parent == destination.parent.resolve(strict=True),
                  "Recipient destination must be fresh, literal and absolute")
    suite.owner_dir(destination.parent)
    suite.require(destination != suite.ROOT and suite.ROOT not in destination.parents
                  and destination not in suite.ROOT.parents
                  and archive != destination and destination not in archive.parents,
                  "Source, recipient or package paths overlap")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        members = z.infolist()
        names = z.namelist()
        suite.require(len(names) == len(expected) and set(names) == expected,
                      "Complete original software inventory required")
        suite.require(all((suite.safe_name(f.filename) or f.filename in expected - set(lock["files"]))
                          and not f.is_dir() and f.file_size <= suite.MAX_SOURCE
                          and f.compress_size <= suite.MAX_SOURCE
                          and (f.external_attr >> 16) in (0, 0o100600)
                          for f in members)
                      and sum(f.file_size for f in members) <= suite.MAX_TOTAL,
                      "Unsafe ZIP path, mode or size")
        files = {member.filename: z.read(member) for member in members}
    import operator_console
    suite.require(files["source-lock.json"] == lock_bytes
                  and files["index.html"] == suite.home()
                  and files["operator.html"] == operator_console.render(),
                  "Incoming source/portal/operator studio mismatch")
    for name, desc in lock["files"].items():
        suite.require(len(files[name]) == desc["bytes"]
                      and suite.digest(files[name]) == desc["sha256"],
                      "Unpinned source content in offline software")
    for name in TOOLS:
        suite.require(files[name] == suite.read_checkout_source(suite.ROOT / name),
                      "Installer or receiver version differs from source release")
    stage = destination.parent / (".lightup-receiver-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        entries = {}
        for name, data in sorted(files.items()):
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            suite.write_file(target, data)
            entries[name] = {"sha256": suite.digest(data), "bytes": len(data)}
        suite.write_file(stage / "software-only.zip", raw)
        entries["software-only.zip"] = {"sha256": suite.digest(raw), "bytes": len(raw)}
        receipt = {"kind": suite.KIND, "version": 1, "disposition": "HUMAN_ONLY_DRAFT_HOLD",
                   "authority_granted": False, "scan_authorized": False,
                   "verified_remediation": False, "client_consent": False,
                   "source_heads": lock["source_heads"], "files": entries,
                   "warning": suite.WARNING}
        suite.write_file(stage / "manifest.json", suite.canonical(receipt))
        suite.require(suite.read_checkout_source(suite.LOCK, 350_000) == lock_bytes,
                      "Pinned original source inventory changed during receiving")
        suite.require(suite.digest(suite.read_owner_file(archive)) == suite.digest(raw),
                      "Received ZIP changed during admission")
        # Validate the complete original staged suite and the stable received
        # ZIP against the same local checkout before any publication.
        suite.verify(stage, compare_checkout=True)
        suite.require(not destination.exists(), "Recipient destination unexpectedly appeared")
        suite.exclusive_publish(stage, destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: received original software to PRIVATE directory:", destination)
    print("Open offline:", destination / "index.html")
    print("Unsigned local digests NEVER establish authenticated source, consent or HUMAN GO.")
