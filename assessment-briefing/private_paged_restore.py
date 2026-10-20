#!/usr/bin/env python3
"""Restore only an existing, unsigned PRIVATE LightUp paged ZIP to NEW local files.

This never interprets archive contents as authorization, scan results or
independent authenticity. No target/model/network/browser interaction.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile

from briefing import Hold, json_bytes, publish_new, require, strict_pairs
from human_return import read_limited_file
from private_paged_zip import (
    START_HERE_PRIVATE, MAX_MANIFEST, MAX_MEMBER, MAX_SOURCE_BYTES,
    MAX_ZIP_BYTES, admit_inventory,
)

ZIP_EXTRA = "START-HERE-PRIVATE.txt"


def unpack_exact(archive_bytes: bytes) -> tuple[dict[str, bytes], dict]:
    require(0 < len(archive_bytes) <= MAX_ZIP_BYTES)
    # Canonical no-comment EOCD must be at the final byte. Do not accept
    # appended extra data, a disguised polyglot or forged trailing records.
    require(len(archive_bytes) >= 22 and
            archive_bytes[-22:-18] == b"PK\x05\x06" and
            archive_bytes[-2:] == b"\x00\x00")
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), mode="r",
                             allowZip64=False) as source:
            entries = source.infolist()
            require(len(entries) <= 56)
            require(len(entries) == len(set(item.filename for item in entries)))
            files = {entry.filename: entry for entry in entries}
            require("manifest.json" in files)
            man = files["manifest.json"]
            require(man.file_size <= MAX_MANIFEST and man.file_size > 0)
            require(man.compress_type == zipfile.ZIP_DEFLATED and
                    man.filename == "manifest.json" and
                    not man.is_dir() and not (man.flag_bits & 1))
            raw_manifest = source.read(man, pwd=None)
            require(len(raw_manifest) <= MAX_MANIFEST)
            manifest = json.loads(
                raw_manifest.decode("utf-8"),
                object_pairs_hook=strict_pairs,
                parse_constant=lambda _: require(False))
            expected = admit_inventory(manifest)
            expected_names = set(expected) | {"manifest.json", ZIP_EXTRA}
            require(set(files) == expected_names)
            total = 0
            for name in sorted(expected_names):
                entry = files[name]
                require(entry.compress_type == zipfile.ZIP_DEFLATED and
                        not entry.is_dir() and not (entry.flag_bits & 1) and
                        entry.file_size <= MAX_MEMBER and entry.file_size > 0)
                # Reject symlink/exec or surprising extraction semantics.
                require(entry.create_system == 3 and
                        (entry.external_attr >> 16) == 0o100600)
                total += entry.file_size
                require(total <= MAX_SOURCE_BYTES)
                raw = source.read(entry)
                require(len(raw) == entry.file_size)
                if name in expected:
                    require(hashlib.sha256(raw).hexdigest() == expected[name])
                elif name == ZIP_EXTRA:
                    require(raw == START_HERE_PRIVATE)
                elif name == "manifest.json":
                    require(raw == raw_manifest)
                members[name] = raw
            require(source.comment == b"")
    except (OSError, KeyError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError, RuntimeError, EOFError, zipfile.BadZipFile):
        raise Hold("PRIVATE ZIP package rejected (HOLD)") from None
    receipt = {
        "schema": "lightup.private_paged_restore_receipt.v1",
        "status": "REVIEW_ONLY",
        "archive_sha256_unsigned": hashlib.sha256(archive_bytes).hexdigest(),
        "original_source_sha256_unsigned":
            manifest["original_source_sha256_unsigned"],
        "restored_original_artifact_count": len(members),
        "source_authenticated": False,
        "ground_truth_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    return members, receipt


def restore(archive_path: str, output_dir: str) -> None:
    archived = read_limited_file(archive_path, MAX_ZIP_BYTES)
    files, receipt = unpack_exact(archived)
    # Restore the known exact local paths, never arbitrary archive paths.
    # The private directory is new-only; no clobber of downloaded originals.
    files["PRIVATE-restore-receipt.json"] = json_bytes(receipt)
    publish_new(output_dir, files)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore already-generated PRIVATE paged report ZIP, NO execution")
    parser.add_argument("--private-zip", required=True, help="existing local PRIVATE ZIP")
    parser.add_argument("--output-dir", required=True, help="NEW private output directory")
    args = parser.parse_args()
    try:
        restore(args.private_zip, args.output_dir)
    except Hold:
        print("HOLD: invalid PRIVATE archive or destination; no original files replaced",
              file=sys.stderr)
        return 3
    print("PRIVATE original paged briefing restored to NEW folder; HUMAN REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
