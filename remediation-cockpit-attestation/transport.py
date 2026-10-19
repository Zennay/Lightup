#!/usr/bin/env python3
"""Offline AES-256-GCM transport for the native PRIVATE HUMAN source-free cockpit.

This transports only the already-received canonical anonymous cockpit files
and detached keyed receipt. It neither conveys original evidence material nor
grants authority. Requires the separately distributed 32-byte attestation key.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import attest

review = attest.review
native = attest.read_cockpit
MAGIC = b"LIGHTUP-PRIVATE-HUMAN-COCKPIT-1\x00"
KIND = "lightup.private_human_encrypted_source_free_cockpit"
CONTEXT = b"LightUp PRIVATE HUMAN cockpit AES256GCM transport v1\x00"
NONCE = 12
MAX_PLAIN = 12 * 1024 * 1024
MAX_ENCRYPTED = MAX_PLAIN + len(MAGIC) + NONCE + 16


def require(ok: bool) -> None:
    attest.require(ok)


def encryption_key(root: bytes) -> bytes:
    # Domain-separated from manifest attestation; no new caller-supplied key.
    require(type(root) is bytes and len(root) == 32)
    return hmac.new(root, CONTEXT, hashlib.sha256).digest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_b64(value: object, size: int) -> bytes:
    require(type(value) is str and len(value) <= ((size + 2) // 3) * 4)
    raw = base64.b64decode(value, validate=True)
    require(len(raw) <= size and b64(raw) == value)
    return raw


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(type(key) is str and key not in result)
        result[key] = value
    return result


def canonical(data: dict) -> bytes:
    return (json.dumps(data, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def snapshot(cockpit: Path, receipt: Path | None, key: Path) -> tuple[dict, dict]:
    # With a previous receipt: verify it first. Without: independently
    # admit original native bytes and create the key receipt in memory.
    admitted = (attest.inspect(cockpit, key, receipt) if receipt is not None
                else native.inspect(cockpit))
    manifest_raw = review.private_read(cockpit / "manifest.json")
    manifest_obj = json.loads(manifest_raw.decode("utf-8"),
                              object_pairs_hook=no_duplicate_pairs)
    filenames = set(manifest_obj["files"])
    expected = set(native.DEFAULT) | (set(native.HISTORY)
               if admitted["same_original_source_claimed"] else set())
    require(filenames == expected and len(filenames) <= 6)
    files = {}
    for name in sorted(filenames):
        files[name] = review.private_read(cockpit / name)
    if receipt is not None:
        receipt_raw = attest.private_file(receipt, attest.MAX_RECEIPT)
    else:
        secret = attest.key_bytes(key)
        receipt_raw = canonical({
            "kind": attest.KIND,
            "schema_version": 1,
            "algorithm": "HMAC-SHA256",
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "mac": attest.mac(secret, manifest_raw),
        })
    # Reject changing originals between admission and encrypted packaging.
    require((attest.inspect(cockpit, key, receipt) if receipt is not None
             else native.inspect(cockpit)) == admitted and
            review.private_read(cockpit / "manifest.json") == manifest_raw and
            (receipt is None or
             attest.private_file(receipt, attest.MAX_RECEIPT) == receipt_raw))
    for name, raw in files.items():
        require(review.private_read(cockpit / name) == raw)
    data = {
        "kind": KIND,
        "schema_version": 1,
        "manifest": b64(manifest_raw),
        "receipt": b64(receipt_raw),
        "files": {name: b64(raw) for name, raw in files.items()},
    }
    plain = canonical(data)
    require(len(plain) <= MAX_PLAIN)
    return data, admitted


def pack(cockpit: Path, receipt: Path | None, key_file: Path, output: Path) -> dict:
    attest.private_parent(output)
    require(output != key_file and (receipt is None or output != receipt) and
            output != cockpit and cockpit not in output.parents and
            not output.exists() and not output.is_symlink())
    key = attest.key_bytes(key_file)
    data, admitted = snapshot(cockpit, receipt, key_file)
    nonce = os.urandom(NONCE)
    ciphertext = AESGCM(encryption_key(key)).encrypt(nonce, canonical(data), MAGIC)
    blob = MAGIC + nonce + ciphertext
    require(len(blob) <= MAX_ENCRYPTED)
    attest.exclusive_private_write(output, blob)
    return admitted


def unseal(blob: bytes, key: bytes) -> tuple[bytes, bytes, dict[str, bytes]]:
    require(type(blob) is bytes and
            len(MAGIC) + NONCE + 16 < len(blob) <= MAX_ENCRYPTED and
            blob.startswith(MAGIC))
    nonce = blob[len(MAGIC):len(MAGIC)+NONCE]
    encrypted = blob[len(MAGIC)+NONCE:]
    plain = AESGCM(encryption_key(key)).decrypt(nonce, encrypted, MAGIC)
    require(len(plain) <= MAX_PLAIN)
    doc = json.loads(plain.decode("ascii"), object_pairs_hook=no_duplicate_pairs)
    require(type(doc) is dict and set(doc) ==
            {"kind", "schema_version", "manifest", "receipt", "files"} and
            doc["kind"] == KIND and type(doc["schema_version"]) is int and
            doc["schema_version"] == 1 and plain == canonical(doc) and
            type(doc["files"]) is dict)
    manifest = decode_b64(doc["manifest"], native.verify.MAX_BYTES)
    receipt = decode_b64(doc["receipt"], attest.MAX_RECEIPT)
    manifest_obj = json.loads(manifest.decode("utf-8"),
                              object_pairs_hook=no_duplicate_pairs)
    require(type(manifest_obj) is dict and type(manifest_obj.get("files")) is dict)
    filenames = set(manifest_obj["files"])
    require(filenames in (set(native.DEFAULT), set(native.DEFAULT | native.HISTORY)) and
            set(doc["files"]) == filenames)
    result = {name: decode_b64(doc["files"][name], native.verify.MAX_BYTES)
              for name in sorted(filenames)}
    return manifest, receipt, result


def receive(source: Path, key_file: Path, output_parent: Path) -> tuple[Path, dict]:
    # A private fresh workspace is only promoted after native full admission.
    require(output_parent.is_absolute() and
            output_parent == output_parent.resolve(strict=True))
    pstat = output_parent.stat(follow_symlinks=False)
    require(stat.S_ISDIR(pstat.st_mode) and pstat.st_uid == os.getuid() and
            pstat.st_mode & 0o077 == 0)
    require(source != key_file and output_parent != source and
            source not in output_parent.parents and
            key_file not in output_parent.parents)
    key = attest.key_bytes(key_file)
    blob = attest.private_file(source, MAX_ENCRYPTED)
    manifest, receipt, files = unseal(blob, key)
    # Prove signed source-free manifest BEFORE materializing any plaintext
    # at the recipient. An AEAD key-holder may still forge unsigned evidence.
    expected_mac = attest.mac(key, manifest)
    envelope = json.loads(receipt.decode("ascii"),
                          object_pairs_hook=no_duplicate_pairs)
    require(type(envelope) is dict and set(envelope) == attest.FIELDS and
            envelope["kind"] == attest.KIND and
            type(envelope["schema_version"]) is int and
            envelope["schema_version"] == 1 and
            envelope["algorithm"] == "HMAC-SHA256" and
            type(envelope["mac"]) is str and
            type(envelope["manifest_sha256"]) is str and
            hmac.compare_digest(envelope["mac"], expected_mac) and
            hmac.compare_digest(envelope["manifest_sha256"],
                                hashlib.sha256(manifest).hexdigest()))
    require(receipt == canonical(envelope))
    stage = Path(tempfile.mkdtemp(prefix=".lightup-receiving-", dir=output_parent))
    promoted = False
    try:
        workspace = native.workspace
        workspace.publish_bundle(stage / "cockpit", files, manifest)
        attest.exclusive_private_write(stage / "receipt.json", receipt)
        admitted = attest.inspect(stage / "cockpit", key_file, stage / "receipt.json")
        # Directory name is unguessable and output cannot be an old source;
        # do not merge, overwrite or touch any existing receiving dossier.
        destination = output_parent / ("lightup-private-cockpit-" + secrets.token_hex(16))
        require(not destination.exists() and not destination.is_symlink())
        # Reuse the original native Linux renameat2(RENAME_NOREPLACE) publisher:
        # plain os.rename could otherwise replace a concurrently created
        # empty destination directory (even after the existence check).
        native.workspace.exclusive_dir_publish(stage, destination)
        promoted = True
        return destination, admitted
    finally:
        if not promoted:
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Encrypt or receive canonical source-free PRIVATE HUMAN cockpit as "
        "one offline AEAD file. No network, approval, fix or retest."))
    actions = parser.add_subparsers(dest="action", required=True)
    sender = actions.add_parser("pack", help="Encrypt an existing detached verified receipt and cockpit")
    sender.add_argument("--cockpit", required=True, type=Path)
    sender.add_argument("--receipt", required=True, type=Path)
    sender.add_argument("--key-file", required=True, type=Path)
    sender.add_argument("--output", required=True, type=Path)
    quick = actions.add_parser("send", help="One-command native admission, HMAC receipt and encrypted delivery")
    quick.add_argument("--cockpit", required=True, type=Path)
    quick.add_argument("--key-file", required=True, type=Path)
    quick.add_argument("--output", required=True, type=Path)
    recipient = actions.add_parser("receive", help="Privately unpack, authenticate and admit native cockpit")
    recipient.add_argument("--input", required=True, type=Path)
    recipient.add_argument("--key-file", required=True, type=Path)
    recipient.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action in ("pack", "send"):
            status = pack(args.cockpit, args.receipt if args.action == "pack" else None,
                          args.key_file, args.output)
            print("One PRIVATE AES-256-GCM source-free cockpit file published (0600).")
        else:
            folder, status = receive(args.input, args.key_file, args.output_parent)
            print("PRIVATE HUMAN cockpit opened in new owner-only folder: " + str(folder))
        print("Original slots: " + str(status["original_source_slots_not_unique_cases"]) +
              "; pending human questions (not fixes): " +
              str(status["local_pending_human_questions_not_fixes"]))
        print("No client consent, sender identity, original evidence, remediation or retest verified.")
        return 2
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError,
            InvalidTag, review.Hold):
        print("HOLD: PRIVATE encrypted cockpit rejected; nothing authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
