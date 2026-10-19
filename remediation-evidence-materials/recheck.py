#!/usr/bin/env python3
"""Reopen a PRIVATE received LightUp material folder against CURRENT source.

A human-only local evidence continuity operation; no testsuite, network,
authenticated client consent, grant, verified security finding, or retest.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys

import transfer

MAX_RECEIPT = 32768
RECEIPT_KEYS = {"kind", "schema_version", "disposition", "source_sha256",
                "files", "warning", *transfer.human.FLAGS}
RECORD_KEYS = {"stored_as", "finding_id", "original_file_name", "sha256", "byte_length"}


def review(args, vault) -> int:
    envelope, packet, indexed = transfer.current_human(args, vault)
    directory = args.folder.expanduser().absolute()
    dir_status = os.lstat(directory)
    if (not stat.S_ISDIR(dir_status.st_mode)
            or dir_status.st_uid != os.getuid()
            or dir_status.st_mode & 0o077):
        raise ValueError("Existing receipt folder must be real owner-private 0700.")
    receipt = vault._private_input(directory / "PRIVATE-receipt.json", MAX_RECEIPT)
    data = transfer.human._json(receipt, MAX_RECEIPT)
    if (set(data) != RECEIPT_KEYS or transfer.canonical(data) != receipt
            or data.get("kind") != "lightup.private_local_material_receipt"
            or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1
            or data.get("disposition") != "PRIVATE_HUMAN_UNVERIFIED_ONLY"
            or data.get("source_sha256") != packet["source_sha256"]
            or data.get("warning") != transfer.WARNING
            or any(data[flag] is not False for flag in transfer.human.FLAGS)):
        raise ValueError("Private original source-bound receipt is malformed or stale.")
    rows = data["files"]
    if type(rows) is not list or not 1 <= len(rows) <= transfer.MAX_FILES:
        raise ValueError("Invalid original private material receipt membership.")
    seen = set()
    expected = {"PRIVATE-receipt.json"}
    total = 0
    for ordinal, record in enumerate(rows, 1):
        if type(record) is not dict or set(record) != RECORD_KEYS:
            raise ValueError("Invalid original private material receipt fields.")
        filename = f"material-{ordinal:02d}.bin"
        if record.get("stored_as") != filename or not re.fullmatch(
                r"material-[0-9]{2}\.bin", filename):
            raise ValueError("Material identity/order differs from original private receipt.")
        if any(type(record.get(k)) is not str for k in
               ("stored_as","finding_id","original_file_name","sha256")) or (
                type(record.get("byte_length")) is not int):
            raise ValueError("Invalid original file identity.")
        key = (record["finding_id"], record["sha256"])
        original = indexed.get(key)
        if key in seen or original is None or any(
                record[k] != original[k if k!="original_file_name" else "file_name"]
                for k in ("finding_id", "sha256", "byte_length", "original_file_name")):
            raise ValueError("Receipt does not match current ORIGINAL HUMAN file inventory.")
        seen.add(key)
        data_bytes = vault._private_input(directory / filename, transfer.MAX_MATERIAL)
        if not data_bytes or len(data_bytes) != record["byte_length"] or (
                transfer.digest(data_bytes) != record["sha256"]):
            raise ValueError("PRIVATE local evidence bytes changed or disappeared.")
        total += len(data_bytes)
        if total > transfer.MAX_TOTAL:
            raise ValueError("Received evidence material exceeds original transport limit.")
        expected.add(filename)
    if set(os.listdir(directory)) != expected:
        raise ValueError("Unindexed files found in original PRIVATE material folder.")
    print("CURRENT ORIGINAL SOURCE-BOUND LOCAL MATERIAL CONTINUITY MATCH")
    print("Owner-private received material files:", len(rows))
    print("Currently matching original indexed local bytes:", total)
    print("Matching hashes do NOT verify collection provenance, repairs, retests, vulnerability or consent.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--human", type=Path, required=True,
                        help="CURRENT original encrypted HUMAN workspace .ltv")
    parser.add_argument("--folder", type=Path, required=True,
                        help="Existing owner-private folder created by transfer.py unpack")
    parser.add_argument("--ack-private-review", action="store_true",
                        help="Confirm deliberate read of real PRIVATE local material")
    opts = parser.parse_args(argv)
    try:
        if not opts.ack_private_review or not sys.stdin.isatty():
            raise ValueError("Real private terminal and human private-material acknowledgement required.")
        return review(opts, transfer.ORIGINAL._vault())
    except Exception:
        print("HUMAN HOLD: PRIVATE material is not a current exact local/original match. "
              "No security, remediation or authorization verdict issued.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
