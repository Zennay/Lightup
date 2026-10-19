#!/usr/bin/env python3
"""Portable AES-256-GCM transfer of an already admitted PRIVATE HUMAN inbox.

Transports only fixed original source-free cockpit members and their existing
HMAC receipts. Recipient rebuilds a completely new workroom using native
original source-reader admission. No original evidence, grants or targets.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import attest
import inbox
import transport

native = attest.read_cockpit
review = attest.review
MAGIC = b"LIGHTUP-PRIVATE-HUMAN-INBOX-1\x00"
CONTEXT = b"LightUp PRIVATE HUMAN inbox AES256GCM v1\x00"
NONCE = 12
MAX_PLAIN = 32 * 1024 * 1024
MAX_ENCRYPTED = MAX_PLAIN + len(MAGIC) + NONCE + 16
KIND = "lightup.encrypted_private_human_cockpit_inbox_handoff"


def require(ok: bool) -> None:
    attest.require(ok)


def group_key(secret: bytes) -> bytes:
    return hmac.new(secret, CONTEXT, hashlib.sha256).digest()


def extract(source: Path, keyfile: Path) -> tuple[bytes, dict]:
    original = inbox.inspect(source, keyfile)
    slots = []
    for index in range(1, original["slot_count"] + 1):
        slot = source / f"slot-{index:02d}"
        cockpit = slot / "cockpit"
        manifest = review.private_read(cockpit / "manifest.json")
        m = native.verify.json_obj(manifest)
        filenames = set(native.DEFAULT) | (
            set(native.HISTORY) if original["slots"][index-1]["same_original_source_claimed"]
            else set())
        require(set(m.get("files", {})) == filenames)
        files = {name: transport.b64(review.private_read(cockpit / name))
                 for name in sorted(filenames)}
        receipt = attest.private_file(slot / "receipt.json", attest.MAX_RECEIPT)
        slots.append({"slot": index, "manifest": transport.b64(manifest),
                      "receipt": transport.b64(receipt), "files": files})
    require(inbox.inspect(source, keyfile) == original)
    result = {"kind": KIND, "schema_version": 1, "slots": slots}
    raw = transport.canonical(result)
    require(len(raw) <= MAX_PLAIN)
    return raw, original


def send(source: Path, keyfile: Path, output: Path) -> dict:
    attest.private_parent(output)
    require(output != keyfile and output != source and
            source not in output.parents and output not in source.parents and
            not output.exists() and not output.is_symlink())
    key = attest.key_bytes(keyfile)
    plaintext, original = extract(source, keyfile)
    nonce = os.urandom(NONCE)
    ciphertext = AESGCM(group_key(key)).encrypt(nonce, plaintext, MAGIC)
    payload = MAGIC + nonce + ciphertext
    require(len(payload) <= MAX_ENCRYPTED)
    attest.exclusive_private_write(output, payload)
    return original


def read_blob(blob: bytes, key: bytes) -> list[dict]:
    require(blob.startswith(MAGIC) and len(MAGIC) + NONCE + 16 < len(blob) <= MAX_ENCRYPTED)
    nonce = blob[len(MAGIC):len(MAGIC)+NONCE]
    raw = AESGCM(group_key(key)).decrypt(nonce, blob[len(MAGIC)+NONCE:], MAGIC)
    require(len(raw) <= MAX_PLAIN)
    data = json.loads(raw.decode("ascii"), object_pairs_hook=transport.no_duplicate_pairs)
    require(type(data) is dict and set(data) == {"kind", "schema_version", "slots"}
            and data["kind"] == KIND and type(data["schema_version"]) is int
            and data["schema_version"] == 1 and type(data["slots"]) is list
            and 1 <= len(data["slots"]) <= inbox.MAX and
            raw == transport.canonical(data))
    for index, slot in enumerate(data["slots"], 1):
        require(type(slot) is dict and set(slot) == {
            "slot", "manifest", "receipt", "files"} and
            type(slot["slot"]) is int and slot["slot"] == index and
            type(slot["files"]) is dict)
    return data["slots"]


def authenticate(slot: dict, key: bytes) -> tuple[bytes, bytes, dict[str, bytes]]:
    manifest = transport.decode_b64(slot["manifest"], native.verify.MAX_BYTES)
    receipt = transport.decode_b64(slot["receipt"], attest.MAX_RECEIPT)
    envelope = json.loads(receipt.decode("ascii"),
                          object_pairs_hook=transport.no_duplicate_pairs)
    require(type(envelope) is dict and set(envelope) == attest.FIELDS and
            envelope["kind"] == attest.KIND and
            type(envelope["schema_version"]) is int and
            envelope["schema_version"] == 1 and
            envelope["algorithm"] == "HMAC-SHA256" and
            type(envelope["mac"]) is str and
            type(envelope["manifest_sha256"]) is str and
            hmac.compare_digest(envelope["mac"], attest.mac(key, manifest)) and
            hmac.compare_digest(envelope["manifest_sha256"],
                                hashlib.sha256(manifest).hexdigest()) and
            receipt == transport.canonical(envelope))
    m = native.verify.json_obj(manifest)
    require(type(m.get("files")) is dict and
            set(m["files"]) in (set(native.DEFAULT),
                                set(native.DEFAULT | native.HISTORY)) and
            set(slot["files"]) == set(m["files"]))
    files = {name: transport.decode_b64(slot["files"][name], native.verify.MAX_BYTES)
             for name in sorted(slot["files"])}
    return manifest, receipt, files


def receive(source: Path, keyfile: Path, output_parent: Path) -> tuple[Path, dict]:
    inbox.strict_private_dir(output_parent)
    require(source.is_absolute() and source != keyfile and
            source != output_parent and
            source not in output_parent.parents and
            output_parent not in keyfile.parents)
    key = attest.key_bytes(keyfile)
    blob = attest.private_file(source, MAX_ENCRYPTED)
    packets = read_blob(blob, key)
    # This is a fresh, private, single transaction. No pre-existing inbox
    # member will ever be modified or deleted by this importer.
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-portable-inbox-", dir=output_parent))
    complete = False
    try:
        rows = []
        sha_set: set[str] = set()
        for index, packet in enumerate(packets, 1):
            manifest, receipt, files = authenticate(packet, key)
            slot_name = f"slot-{index:02d}"
            slot = temporary / slot_name
            slot.mkdir(mode=0o700)
            native.workspace.publish_bundle(slot / "cockpit", files, manifest)
            attest.exclusive_private_write(slot / "receipt.json", receipt)
            admitted = attest.inspect(slot / "cockpit", keyfile, slot / "receipt.json")
            row = inbox.row_from_admission(index, admitted, manifest)
            require(row["source_free_manifest_sha256"] not in sha_set)
            sha_set.add(row["source_free_manifest_sha256"])
            rows.append(row)
        document = inbox.summary(rows)
        html = inbox.render(document)
        counts = inbox.pretty(document)
        manifest = {"kind": inbox.KIND, "schema_version": 1,
                    "slots": [f"slot-{i:02d}" for i in range(1, len(rows)+1)],
                    "files": {"index.html": inbox.descriptor(html),
                              "summary.json": inbox.descriptor(counts)}}
        for filename, raw in (("index.html", html), ("summary.json", counts),
                              ("manifest.json", inbox.pretty(manifest))):
            attest.exclusive_private_write(temporary / filename, raw)
        require(inbox.inspect(temporary, keyfile) == document and
                attest.private_file(source, MAX_ENCRYPTED) == blob)
        target = output_parent / ("lightup-human-inbox-" + secrets.token_hex(16))
        require(not target.exists() and not target.is_symlink())
        native.workspace.exclusive_dir_publish(temporary, target)
        complete = True
        return target, document
    finally:
        if not complete:
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Offline whole PRIVATE HUMAN team-inbox sealed handoff: original "
        "source-free native cockpits only, no grant or security verdict"))
    actions = parser.add_subparsers(dest="action", required=True)
    sender = actions.add_parser("send", help="Seal a complete admitted PRIVATE inbox")
    sender.add_argument("--inbox", required=True, type=Path)
    sender.add_argument("--key-file", required=True, type=Path)
    sender.add_argument("--output", required=True, type=Path)
    recipient = actions.add_parser("receive", help="Rebuild all native original slots atomically")
    recipient.add_argument("--input", required=True, type=Path)
    recipient.add_argument("--key-file", required=True, type=Path)
    recipient.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "send":
            result = send(args.inbox, args.key_file, args.output)
            print("PRIVATE full HUMAN inbox ciphertext sealed in exclusive 0600 file.")
        else:
            folder, result = receive(args.input, args.key_file, args.output_parent)
            print("PRIVATE whole HUMAN inbox reconstructed atomically: " + str(folder))
        print(str(result["slot_count"]) + " source-free slot(s); " +
              str(result["pending_human_questions_not_fixes"]) +
              " pending local HUMAN questions, not unique verified fixes.")
        print("Shared-key possession only. No sender identity, original evidence, "
              "client consent, grant or retest verified.")
        return 2
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError, review.Hold,
            InvalidTag, transport.binascii.Error):
        print("HOLD: PRIVATE whole inbox could not be admitted; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
