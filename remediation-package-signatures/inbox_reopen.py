#!/usr/bin/env python3
"""Reopen an already-published PRIVATE LightUp software inbox, fail closed.

Check original immutable software members AND currently non-revoked local keys.
Old static HTML files cannot revoke themselves; always use this foreground
reopen command for a fresh trust decision before consulting the local suite.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile

from offline_signatures import Hold, MAX_ARCHIVE_BYTES, _regular_file_bytes, _write_new_private, verify
from inbox import KIND, MAX_PACKAGES, _admit_signers, _html, _import_original_install
from portable_handoff import (
    ARCHIVE_NAME, PUBLIC_NAME, RECEIPT_NAME, SECOND_PUBLIC_NAME,
    SECOND_RECEIPT_NAME, _unpack_bytes,
)
from trust_registry import _json_file, _owner_private, minimum_signers, trusted

SHA = re.compile(r"^[0-9a-f]{64}$")
RECORD_FIELDS = frozenset({
    "ordinal", "slot", "original_zip_sha256", "original_zip_bytes", "signers",
})
SIGNER_FIELDS = frozenset({"fingerprint", "label"})
ROOT_FIELDS = frozenset({
    "format", "disposition", "source_owner_authenticated", "client_consent",
    "remediation_verified", "scan_authorized", "deployment_authorized",
    "human_go", "entries",
})


def inspect(keyring: Path, workspace: Path, require_two: bool) -> None:
    _owner_private(workspace)
    install = _import_original_install()
    manifest = _json_file(workspace / "inbox.json")
    fields = set(manifest)
    if fields not in (ROOT_FIELDS, ROOT_FIELDS | {"local_minimum_signers"}) or manifest["format"] != KIND or manifest["disposition"] != "PRIVATE_HUMAN_REVIEW_ONLY":
        raise Hold("private software inbox manifest format or authority differs")
    original_floor = manifest.get("local_minimum_signers", 1)
    if type(original_floor) is not int or original_floor not in (1, 2):
        raise Hold("invalid original recorded signer floor")
    require_two = require_two or original_floor == 2 or minimum_signers(keyring) == 2
    if any(manifest[key] is not False for key in (
        "source_owner_authenticated", "client_consent", "remediation_verified",
        "scan_authorized", "deployment_authorized", "human_go",
    )):
        raise Hold("inbox receipt contains an authority claim")
    records = manifest["entries"]
    if type(records) is not list or not 1 <= len(records) <= MAX_PACKAGES:
        raise Hold("inbox must contain 1–12 original review-only entries")
    observed = set()
    for ordinal, record in enumerate(records, 1):
        if type(record) is not dict or set(record) != RECORD_FIELDS:
            raise Hold("inbox record is not the original exact schema")
        slot = f"slot-{ordinal:02d}"
        if (
            type(record["ordinal"]) is not int or record["ordinal"] != ordinal
            or record["slot"] != slot
            or type(record["original_zip_sha256"]) is not str
            or SHA.fullmatch(record["original_zip_sha256"]) is None
            or type(record["original_zip_bytes"]) is not int
            or not 1 <= record["original_zip_bytes"] <= MAX_ARCHIVE_BYTES
            or type(record["signers"]) is not list
            or len(record["signers"]) not in (1, 2)
        ):
            raise Hold("malformed or non-canonical inbox ordinal, hash or signers")
        for signer in record["signers"]:
            if (
                type(signer) is not dict or set(signer) != SIGNER_FIELDS
                or any(type(signer[k]) is not str for k in SIGNER_FIELDS)
            ):
                raise Hold("invalid signer record")
        bundle = workspace / f"bundle-{ordinal:02d}.portable.zip"
        members = _unpack_bytes(bundle)
        sha = hashlib.sha256(members[ARCHIVE_NAME]).hexdigest()
        if sha != record["original_zip_sha256"] or len(members[ARCHIVE_NAME]) != record["original_zip_bytes"]:
            raise Hold("saved signed original software bytes no longer match source receipt")
        if sha in observed:
            raise Hold("duplicate archive identity inside private inbox")
        observed.add(sha)
        admitted = _admit_signers(keyring, members, require_two)
        if admitted != record["signers"]:
            raise Hold("local trusted signer set or label differs from saved custody receipt")
        with tempfile.TemporaryDirectory(prefix=".lightup-verify-at-open-", dir=str(workspace)) as scratch:
            parent = Path(scratch)
            _write_new_private(parent / ARCHIVE_NAME, members[ARCHIVE_NAME])
            _write_new_private(parent / RECEIPT_NAME, members[RECEIPT_NAME])
            _write_new_private(parent / PUBLIC_NAME, members[PUBLIC_NAME])
            original_bytes = verify(
                parent / ARCHIVE_NAME, parent / RECEIPT_NAME, parent / PUBLIC_NAME,
                admitted[0]["fingerprint"],
            )
            if len(admitted) == 2:
                _write_new_private(parent / SECOND_RECEIPT_NAME, members[SECOND_RECEIPT_NAME])
                _write_new_private(parent / SECOND_PUBLIC_NAME, members[SECOND_PUBLIC_NAME])
                second_bytes = verify(
                    parent / ARCHIVE_NAME, parent / SECOND_RECEIPT_NAME,
                    parent / SECOND_PUBLIC_NAME, admitted[1]["fingerprint"],
                )
                if second_bytes != original_bytes:
                    raise Hold("co-signer original ZIP byte images no longer match")
            slot_path = workspace / slot
            if not slot_path.is_dir() or slot_path.is_symlink():
                raise Hold("original native offline suite no longer present")
            install.verify(slot_path)
            installed_archive = _regular_file_bytes(slot_path / ARCHIVE_NAME, MAX_ARCHIVE_BYTES)
            if installed_archive != original_bytes:
                raise Hold("native received suite software ZIP differs from signed original")
        for signer in admitted:
            trusted(keyring, signer["fingerprint"])
        print(f"PRIVATE custody #{ordinal:02d} CURRENT KEY + ORIGINAL SOURCE ACCEPTED — REVIEW_ONLY")
    html_file = _regular_file_bytes(workspace / "index.html", 32768)
    if html_file != _html(records):
        raise Hold("local dashboard differs from exact original scriptless view of signed receipt")
    # Static HTML does not enforce current keyring checks by itself. This command
    # is the explicit local fresh re-admission before manually opening the file.
    print("CURRENT LOCAL CUSTODY REVIEW_ONLY:", workspace / "index.html")
    print("NO AUTHORIZATION: this does not approve code, consent, scans or deployment.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--require-two-signers", action="store_true")
    args = parser.parse_args()
    try:
        inspect(args.keyring, args.workspace, args.require_two_signers)
    except (ValueError, OSError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
