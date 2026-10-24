#!/usr/bin/env python3
"""PRIVATE native counterpart for browser SHA-256 source-free packet receipt.

Strict original owner-only local-file admission, no packet opening/unpacking,
no provider, network, tenant access, authorization, signer or scan.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import install
import single_review

KIND = "lightup.private_unsigned_local_byte_fingerprints"
DISPOSITION = "HUMAN_REVIEW_ONLY_DRAFT_HOLD"
WARNING = ("Unkeyed SHA-256 is local byte consistency only, not original provenance, "
           "client consent, verified fix, scan, grant, security clearance or HUMAN GO.")
MAX_FILES = 8
MAX_ITEM = 20 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_RECEIPT = 16_384
SUFFIXES = frozenset((".luhx", ".luhz", ".luhp"))

class Hold(ValueError):
    pass

def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Hold(reason)

def receipt_bytes(path: Path) -> bytes:
    require(path.is_absolute() and path.suffix == ".json", "Expected original PRIVATE JSON receipt")
    install.owner_dir(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_mode & 0o077 == 0
            and 1 <= before.st_size <= MAX_RECEIPT,
            "Unsigned fingerprint receipt must be owner-private 0600")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(first.st_ino == before.st_ino and first.st_dev == before.st_dev
                and first.st_size == before.st_size,
                "PRIVATE receipt file changed before reading")
        raw = os.read(fd, MAX_RECEIPT + 1)
        last = os.fstat(fd)
        require(len(raw) == first.st_size == last.st_size
                and first.st_mtime_ns == last.st_mtime_ns,
                "PRIVATE receipt changed during read")
        return raw
    finally:
        os.close(fd)

def fingerprint(path: Path) -> dict:
    require(path.is_absolute() and path.suffix in SUFFIXES and not path.is_symlink(),
            "Require original PRIVATE local .luhx/.luhz/.luhp packet")
    require(path.parent == path.parent.resolve(strict=True),
            "PRIVATE packet parent must be literal path")
    install.owner_dir(path.parent)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_mode & 0o077 == 0
            and 1 <= before.st_size <= MAX_ITEM,
            "Packet must be owner-private regular file <=20 MiB")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(first.st_dev == before.st_dev and first.st_ino == before.st_ino
                and first.st_size == before.st_size and first.st_nlink == 1
                and stat.S_ISREG(first.st_mode),
                "PRIVATE packet changed before hashing")
        h = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_ITEM + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= MAX_ITEM, "Packet grew beyond local bound")
            h.update(chunk)
        after = os.fstat(fd)
        require(count == before.st_size == first.st_size == after.st_size
                and first.st_dev == after.st_dev and first.st_ino == after.st_ino
                and first.st_mtime_ns == after.st_mtime_ns
                and first.st_ctime_ns == after.st_ctime_ns,
                "PRIVATE packet changed while hashing")
        return {"bytes": count, "sha256": h.hexdigest()}
    finally:
        os.close(fd)

def fresh(packets: list[Path]) -> list[dict]:
    require(1 <= len(packets) <= MAX_FILES and len(set(packets)) == len(packets),
            "Choose 1 to 8 distinct literal PRIVATE packet paths")
    # Recheck before any read to avoid opening oversized total selections.
    total = 0
    for path in packets:
        require(path.is_absolute() and path.suffix in SUFFIXES and not path.is_symlink(),
                "Require original PRIVATE local packet")
        install.owner_dir(path.parent)
        size = path.lstat().st_size
        require(1 <= size <= MAX_ITEM, "PRIVATE packet size exceeds bound")
        total += size
        require(total <= MAX_TOTAL, "Selected PRIVATE packets exceed 64 MiB")
    return [{"slot": i, **fingerprint(path)} for i, path in enumerate(packets, 1)]

def document(items: list[dict]) -> dict:
    return {
        "kind": KIND, "schema_version": 1, "disposition": DISPOSITION,
        "authority_granted": False, "sender_authenticated": False,
        "consent_verified": False, "remediation_verified": False,
        "chronology_verified": False, "files": items,
        "warning": WARNING,
    }

def load_receipt(path: Path) -> dict:
    raw = receipt_bytes(path)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=install.pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("Nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Hold("Invalid or duplicate-key unsigned PRIVATE receipt") from exc
    require(type(doc) is dict
            and set(doc) == set(document([]))
            and doc["kind"] == KIND
            and type(doc["schema_version"]) is int and doc["schema_version"] == 1
            and doc["disposition"] == DISPOSITION
            and doc["warning"] == WARNING
            and all(doc[key] is False for key in
                    ("authority_granted", "sender_authenticated", "consent_verified",
                     "remediation_verified", "chronology_verified")),
            "Noncanonical or authority-bearing unsigned receipt")
    files = doc["files"]
    require(type(files) is list and 1 <= len(files) <= MAX_FILES,
            "Expected 1–8 original ordered fingerprint slots")
    total = 0
    for slot, item in enumerate(files, 1):
        require(type(item) is dict and set(item) == {"slot", "bytes", "sha256"}
                and type(item["slot"]) is int and item["slot"] == slot
                and type(item["bytes"]) is int and 1 <= item["bytes"] <= MAX_ITEM
                and type(item["sha256"]) is str and len(item["sha256"]) == 64
                and all(c in "0123456789abcdef" for c in item["sha256"]),
                "Malformed slot in unsigned byte receipt")
        total += item["bytes"]
    require(total <= MAX_TOTAL, "Unsigned receipt total exceeds bounds")
    return doc

def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE unsigned source-free SHA-256 byte receipts; NEVER authorization")
    sub = p.add_subparsers(dest="action", required=True)
    cmd = sub.add_parser("create", help="Make NEW owner-private unsigned bytes-only receipt")
    cmd.add_argument("--packet", type=Path, action="append", required=True)
    cmd.add_argument("--output-file", type=Path, required=True)
    cmd = sub.add_parser("compare", help="Compare actually received packets against ORIGINAL unsigned receipt")
    cmd.add_argument("--packet", type=Path, action="append", required=True)
    cmd.add_argument("--receipt", type=Path, required=True)
    cmd.add_argument("--output-dir", type=Path, default=None)
    args = p.parse_args()
    try:
        items = fresh(args.packet)
        if args.action == "create":
            out = args.output_file
            require(out.is_absolute() and out.suffix == ".json"
                    and out not in args.packet
                    and out not in (packet.parent for packet in args.packet),
                    "PRIVATE unsigned receipt destination must be a separate NEW JSON file")
            install.owner_dir(out.parent)
            single_review.review.private_publish(out, install.canonical(document(items)))
            print("REVIEW_ONLY: unsigned PRIVATE local byte receipt saved. File contents were not copied.")
        else:
            expected = load_receipt(args.receipt)
            require(args.receipt not in args.packet, "Expected separate original receipt")
            require(items == expected["files"],
                    "HOLD: actual received packet bytes differ from unsigned expected fingerprint slots")
            if args.output_dir is not None:
                import packet_brief
                raw = receipt_bytes(args.receipt)
                require(load_receipt(args.receipt) == expected,
                        "Expected original unsigned receipt changed before report")
                packet_brief.publish(items, raw, args.output_dir, WARNING)
            print("REVIEW_ONLY: identical lengths and SHA-256 against supplied UNSIGNED receipt.")
        print("SHA-256 does NOT prove real sender, source identity, consent, or authority.")
        return 2
    except (Hold, OSError, ValueError, TypeError, KeyError) as exc:
        print("HOLD:", "Private file I/O failed" if isinstance(exc, OSError)
              else str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
