#!/usr/bin/env python3
"""Detached keyed integrity for the source-free PRIVATE HUMAN Evidence Cockpit.

A local shared HMAC key proves possession of the same out-of-band secret, NOT
human sender identity, original source truth, consent, or remediation success.
The cockpit's native reader remains the authoritative structural admission.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys

# Source owner stays unchanged: use its exact native reconstruction/admission.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent /
                       "remediation-evidence-bundle-integrity"))
import read_cockpit

review = read_cockpit.review
DOMAIN = b"LightUp PRIVATE HUMAN source-free cockpit HMAC v1\x00"
KIND = "lightup.private_human_cockpit_keyed_manifest_receipt"
FIELDS = {"kind", "schema_version", "algorithm", "manifest_sha256", "mac"}
MAX_RECEIPT = 1024


def require(ok: bool) -> None:
    if not ok:
        raise ValueError("PRIVATE HUMAN cockpit attestation HOLD")


def private_parent(path: Path) -> None:
    require(path.is_absolute() and path.parent == path.parent.resolve(strict=True))
    parent = path.parent.stat(follow_symlinks=False)
    require(stat.S_ISDIR(parent.st_mode) and
            parent.st_uid == os.getuid() and parent.st_mode & 0o077 == 0)


def private_file(path: Path, ceiling: int) -> bytes:
    private_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        entry = os.fstat(fd)
        require(stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid() and
                entry.st_mode & 0o177 == 0 and entry.st_nlink == 1 and
                0 < entry.st_size <= ceiling)
        data = bytearray()
        while len(data) <= ceiling:
            part = os.read(fd, ceiling + 1 - len(data))
            if not part:
                break
            data.extend(part)
        require(len(data) == entry.st_size and len(data) <= ceiling)
        return bytes(data)
    finally:
        os.close(fd)


def exclusive_private_write(path: Path, raw: bytes) -> None:
    private_parent(path)
    require(not path.exists() and not path.is_symlink())
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 os.O_WRONLY | os.O_CLOEXEC, 0o600)
    completed = False
    try:
        pos = 0
        while pos < len(raw):
            written = os.write(fd, raw[pos:])
            require(written > 0)
            pos += written
        os.fsync(fd)
        completed = True
    finally:
        os.close(fd)
        if not completed:
            path.unlink(missing_ok=True)


def new_key(path: Path) -> None:
    exclusive_private_write(path, os.urandom(32))


def key_bytes(path: Path) -> bytes:
    value = private_file(path, 32)
    require(len(value) == 32)
    return value


def manifest(cockpit: Path) -> bytes:
    # Native inspect validates the exact inventory and reproduces HTML from
    # anonymous JSON, not merely the self-reported unsigned checksums.
    read_cockpit.inspect(cockpit)
    return review.private_read(cockpit / "manifest.json")


def mac(key: bytes, manifest_bytes: bytes) -> str:
    return hmac.new(key, DOMAIN + len(manifest_bytes).to_bytes(8, "big") +
                    manifest_bytes, hashlib.sha256).hexdigest()


def seal(cockpit: Path, secret: Path, receipt: Path,
         expected_manifest: bytes | None = None) -> dict:
    private_parent(receipt)
    require(receipt != secret and receipt != cockpit and
            cockpit not in receipt.parents and receipt not in cockpit.parents)
    key = key_bytes(secret)
    first = manifest(cockpit)
    require(expected_manifest is None or first == expected_manifest)
    data = {
        "kind": KIND,
        "schema_version": 1,
        "algorithm": "HMAC-SHA256",
        "manifest_sha256": hashlib.sha256(first).hexdigest(),
        "mac": mac(key, first),
    }
    # Reject any moving original evidence/HTML before publishing the detached
    # receipt. The final receiver must still inspect its *own* copy.
    require(manifest(cockpit) == first and
            (expected_manifest is None or first == expected_manifest))
    encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) +
               "\n").encode("ascii")
    exclusive_private_write(receipt, encoded)
    return data


def inspect(cockpit: Path, secret: Path, receipt: Path) -> dict:
    key = key_bytes(secret)
    raw = private_file(receipt, MAX_RECEIPT)
    data = json.loads(raw.decode("ascii"))
    require(type(data) is dict and set(data) == FIELDS and
            data["kind"] == KIND and type(data["schema_version"]) is int and
            data["schema_version"] == 1 and data["algorithm"] == "HMAC-SHA256" and
            type(data["mac"]) is str and len(data["mac"]) == 64 and
            type(data["manifest_sha256"]) is str and
            len(data["manifest_sha256"]) == 64 and
            all(c in "0123456789abcdef" for c in
                data["mac"] + data["manifest_sha256"]))
    require(raw == (json.dumps(data, sort_keys=True, separators=(",", ":")) +
                    "\n").encode("ascii"))
    # Authenticate the exact delivered manifest *before* interpreting HUMAN
    # summaries; native inspect then independently verifies every member.
    first = review.private_read(cockpit / "manifest.json")
    require(hmac.compare_digest(data["manifest_sha256"],
                                hashlib.sha256(first).hexdigest()) and
            hmac.compare_digest(data["mac"], mac(key, first)))
    admitted = read_cockpit.inspect(cockpit)
    require(review.private_read(cockpit / "manifest.json") == first)
    return admitted


def rotate(cockpit: Path, old_key: Path, old_receipt: Path,
           new_key: Path, new_receipt: Path) -> dict:
    # A rotation must preserve *exactly* the originally authenticated cockpit.
    require(old_key != new_key and old_receipt != new_receipt and
            old_receipt != new_key and new_receipt != old_key)
    a = key_bytes(old_key)
    b = key_bytes(new_key)
    require(not hmac.compare_digest(a, b))
    inspect(cockpit, old_key, old_receipt)
    baseline = review.private_read(cockpit / "manifest.json")
    return seal(cockpit, new_key, new_receipt, expected_manifest=baseline)

def key_fingerprint(path: Path) -> str:
    # A short independent comparison hint, NOT sender identity or MAC proof.
    return hashlib.sha256(DOMAIN + b"KEY-FINGERPRINT\x00" +
                          key_bytes(path)).hexdigest()[:20]

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Offline detached shared-key receipt for canonical PRIVATE HUMAN "
        "cockpits; never authenticates a client, scope or remediation"))
    actions = parser.add_subparsers(dest="action", required=True)
    init = actions.add_parser("new-key", help="Generate 32 random key bytes in a NEW owner-private 0600 file")
    init.add_argument("--key-file", required=True, type=Path)
    fingerprint = actions.add_parser("key-fingerprint",
        help="Show a short shared-key pairing hint, not user identity")
    fingerprint.add_argument("--key-file", required=True, type=Path)
    rotate_cmd = actions.add_parser("rotate",
        help="Admit old signed cockpit and re-sign exact same bytes with new key")
    rotate_cmd.add_argument("--cockpit", required=True, type=Path)
    for label in ("old-key-file", "old-receipt", "new-key-file", "new-receipt"):
        rotate_cmd.add_argument("--" + label, required=True, type=Path)
    for name in ("seal", "verify"):
        p = actions.add_parser(name, help="Create or validate a detached keyed manifest receipt")
        p.add_argument("--cockpit", required=True, type=Path)
        p.add_argument("--key-file", required=True, type=Path)
        p.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "new-key":
            new_key(args.key_file)
            print("PRIVATE 0600 key generated. Distribute it out of band only.")
        elif args.action == "key-fingerprint":
            print("Shared-key pairing hint: " + key_fingerprint(args.key_file))
            print("NOT proof of operator identity or consent.")
            return 2
        elif args.action == "rotate":
            rotate(args.cockpit, args.old_key_file, args.old_receipt,
                   args.new_key_file, args.new_receipt)
            print("PRIVATE keyed receipt rotated for unchanged original cockpit.")
        elif args.action == "seal":
            seal(args.cockpit, args.key_file, args.receipt)
            print("PRIVATE detached keyed cockpit receipt created (not client consent).")
        else:
            admitted = inspect(args.cockpit, args.key_file, args.receipt)
            print("REVIEW_ONLY: shared-key receipt and native HUMAN cockpit admitted.")
            print("Original slots: " +
                  str(admitted["original_source_slots_not_unique_cases"]) +
                  "; pending HUMAN follow-ups (NOT verified fixes): " +
                  str(admitted["local_pending_human_questions_not_fixes"]))
        print("No original source, sender identity, customer consent or security verdict authenticated.")
        return 2
    except (OSError, ValueError, TypeError, UnicodeError, review.Hold):
        print("HOLD: private receipt/key/cockpit admission failed; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
