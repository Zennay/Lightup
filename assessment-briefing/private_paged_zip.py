#!/usr/bin/env python3
"""Bundle an EXISTING PRIVATE paged LightUp briefing into one offline ZIP.

Nothing here reads original lab source or contacts targets. A ZIP is PLAINTEXT:
only move it through an independently approved confidential channel.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import zipfile

from briefing import DENIAL_FLAGS, Hold, json_bytes, publish_new, require, strict_pairs

START_HERE_PRIVATE = (
                "LIGHTUP PRIVATE OFFLINE PAGED BRIEFING — REVIEW ONLY\n\n"
                "This ZIP is UNENCRYPTED and includes sensitive ORIGINAL lab "
                "target literals, finding descriptions, summaries and evidence "
                "references. Store privately; only transport via independently "
                "approved confidential means.\n"
                "Open index.html LOCALLY after extracting into a private folder. "
                "Do not publish via a website.\n"
                "The included unsigned manifest checks exact original source "
                "declarations; it NEVER proves authenticated source producer, "
                "consent, current revocation, valid findings, remediation, "
                "grants, authorization, scan permission or production release.\n"
                "INCUBATE M3/M7 PLAN/LAB ONLY — DRAFT/HOLD.\n"
).encode("utf-8")

MAX_MEMBERS = 55
MAX_MANIFEST = 64 * 1024
MAX_MEMBER = 24 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_ZIP_BYTES = 23 * 1024 * 1024
EXPECTED_FLAGS = ("source_authenticated", "ground_truth_verified",
                  "client_consent_verified", "operator_consent_verified",
                  *DENIAL_FLAGS)
METADATA = {"schema", "status", "layout", "original_source_sha256_unsigned",
            "declared_endpoint_count", "declared_finding_count",
            "original_report_pages", "private_artifact_sha256", *EXPECTED_FLAGS}


def sha_ok(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def admit_inventory(manifest: dict) -> dict[str, str]:
    """An UNSIGNED manifest describes only exact expected local output bytes."""
    require(type(manifest) is dict and set(manifest) == METADATA)
    require(manifest["schema"] == "lightup.private_lab_briefing.v1" and
            manifest["status"] == "REVIEW_ONLY" and
            manifest["layout"] == "paged_private_source_report")
    require(all(manifest[name] is False for name in EXPECTED_FLAGS))
    require(sha_ok(manifest["original_source_sha256_unsigned"]))
    require(type(manifest["declared_endpoint_count"]) is int and
            1 <= manifest["declared_endpoint_count"] <= 16)
    count = manifest["declared_finding_count"]
    require(type(count) is int and 0 <= count <= 2048)
    parts = manifest["original_report_pages"]
    require(type(parts) is dict and len(parts) == max(1, (count + 39) // 40))
    require(1 <= len(parts) <= 52)
    files = manifest["private_artifact_sha256"]
    require(type(files) is dict and set(files) == {"index.html", "human-followup.csv"} and
            all(sha_ok(sha) for sha in files.values()))
    expected = dict(files)
    for position in range(len(parts)):
        name = f"page-{position+1:04d}.html"
        require(name in parts and type(parts[name]) is dict)
        page = parts[name]
        require(set(page) == {"original_first_ordinal", "original_last_ordinal",
                              "source_declaration_count", "sha256_unsigned"})
        start = position * 40
        end = min(start + 40, count)
        require(page["original_first_ordinal"] == (start+1 if end > start else None) and
                page["original_last_ordinal"] == (end if end > start else None) and
                type(page["source_declaration_count"]) is int and
                page["source_declaration_count"] == end - start and
                sha_ok(page["sha256_unsigned"]))
        expected[name] = page["sha256_unsigned"]
    require(len(expected) + 1 <= MAX_MEMBERS)
    return expected


def read_private_file(directory_fd: int, name: str, limit: int) -> bytes:
    """Use directory-fd relative nofollow reads, not arbitrary paths or links."""
    require(name and "/" not in name and "\\" not in name and name not in (".", ".."))
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(name, flags, dir_fd=directory_fd)
        status = os.fstat(fd)
        require(stat.S_ISREG(status.st_mode) and status.st_nlink == 1)
        require(stat.S_IMODE(status.st_mode) & 0o077 == 0)
        require(0 < status.st_size <= limit)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(limit+1)
        require(0 < len(data) <= limit)
        return data
    except OSError:
        raise Hold("PRIVATE report source not admitted (HOLD)") from None
    finally:
        if fd >= 0:
            os.close(fd)


def assemble_from_existing(private_dir: str) -> tuple[bytes, dict]:
    dir_fd = -1
    try:
        dir_fd = os.open(private_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0))
        folder_status = os.fstat(dir_fd)
        require(stat.S_ISDIR(folder_status.st_mode) and
                (stat.S_IMODE(folder_status.st_mode) & 0o077) == 0)
        manifest_bytes = read_private_file(dir_fd, "manifest.json", MAX_MANIFEST)
        manifest = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=strict_pairs,
            parse_constant=lambda _: require(False))
        paths = admit_inventory(manifest)
        actual = set(os.listdir(dir_fd))
        original_files = set(paths) | {"manifest.json"}
        restored_files = original_files | {
            "START-HERE-PRIVATE.txt", "PRIVATE-restore-receipt.json"
        }
        require(actual in (original_files, restored_files))
        if actual == restored_files:
            # Round-trip a locally restored PRIVATE report without treating an
            # unsigned receipt as authority or copying the old receipt onward.
            notice = read_private_file(dir_fd, "START-HERE-PRIVATE.txt", 4096)
            require(notice == START_HERE_PRIVATE)
            old_receipt = json.loads(
                read_private_file(dir_fd, "PRIVATE-restore-receipt.json", 8192)
                    .decode("utf-8"),
                object_pairs_hook=strict_pairs,
                parse_constant=lambda _: require(False))
            require(type(old_receipt) is dict and
                    set(old_receipt) == {
                        "schema", "status", "archive_sha256_unsigned",
                        "original_source_sha256_unsigned",
                        "restored_original_artifact_count",
                        "source_authenticated", "ground_truth_verified",
                        "client_consent_verified", "operator_consent_verified",
                        "authorization_granted", "dispatch_allowed",
                        "release_allowed"
                    })
            require(old_receipt["schema"] ==
                    "lightup.private_paged_restore_receipt.v1" and
                    old_receipt["status"] == "REVIEW_ONLY" and
                    sha_ok(old_receipt["archive_sha256_unsigned"]) and
                    old_receipt["original_source_sha256_unsigned"] ==
                    manifest["original_source_sha256_unsigned"] and
                    type(old_receipt["restored_original_artifact_count"]) is int and
                    old_receipt["restored_original_artifact_count"] == len(paths)+2)
            require(all(old_receipt[flag] is False for flag in (
                "source_authenticated", "ground_truth_verified",
                "client_consent_verified", "operator_consent_verified",
                "authorization_granted", "dispatch_allowed", "release_allowed"
            )))

        total = len(manifest_bytes)
        payload = {"manifest.json": manifest_bytes}
        for name in sorted(paths):
            file_bytes = read_private_file(dir_fd, name, MAX_MEMBER)
            require(hashlib.sha256(file_bytes).hexdigest() == paths[name])
            total += len(file_bytes)
            require(total <= MAX_SOURCE_BYTES)
            payload[name] = file_bytes

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=False) as archive:
            for name, content in sorted(payload.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                info.create_system = 3
                archive.writestr(info, content)
            instructions = START_HERE_PRIVATE
            extra = zipfile.ZipInfo("START-HERE-PRIVATE.txt", date_time=(1980,1,1,0,0,0))
            extra.compress_type = zipfile.ZIP_DEFLATED
            extra.external_attr = 0o100600 << 16
            extra.create_system = 3
            archive.writestr(extra, instructions)
        compressed = output.getvalue()
        require(0 < len(compressed) <= MAX_ZIP_BYTES)
        receipt = {
            "schema": "lightup.private_paged_zip_receipt.v1",
            "status": "REVIEW_ONLY",
            "original_source_sha256_unsigned":
                manifest["original_source_sha256_unsigned"],
            "private_archive_sha256_unsigned": hashlib.sha256(compressed).hexdigest(),
            "packed_original_artifact_count": len(payload),
            "private_archive_bytes": len(compressed),
            "archive_is_encrypted": False,
            "source_authenticated": False,
            "client_consent_verified": False,
            "operator_consent_verified": False,
            "ground_truth_verified": False,
            **DENIAL_FLAGS,
        }
        return compressed, receipt
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, MemoryError,
            RecursionError, OverflowError, zipfile.BadZipFile):
        raise Hold("PRIVATE source bundle rejected (HOLD)") from None
    finally:
        if dir_fd >= 0:
            os.close(dir_fd)


def create(private_dir: str, output_dir: str) -> None:
    archive, receipt = assemble_from_existing(private_dir)
    publish_new(output_dir, {
        "LightUp-PRIVATE-Paged-Review.zip": archive,
        "PRIVATE-archive-receipt.json": json_bytes(receipt),
    })


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bundle PREVIOUSLY generated PRIVATE paged reports; NO scanner")
    parser.add_argument("--private-paged-dir", required=True,
                        help="unchanged PRIVATE original paged output directory")
    parser.add_argument("--output-dir", required=True,
                        help="new PRIVATE ZIP destination directory")
    arguments = parser.parse_args()
    try:
        create(arguments.private_paged_dir, arguments.output_dir)
    except Hold:
        print("HOLD: PRIVATE paged report not admitted; no ZIP produced", file=sys.stderr)
        return 3
    print("Created PRIVATE UNENCRYPTED portable review ZIP; HUMAN REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
