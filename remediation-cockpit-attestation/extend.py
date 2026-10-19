#!/usr/bin/env python3
"""Extend a complete PRIVATE HUMAN encrypted cockpit inbox without modifying it.

Existing admitted original source-free cockpits and new encrypted packets are
copied into an entirely NEW private inbox. No client evidence is merged.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

import attest
import inbox
import transport

native = attest.read_cockpit
review = attest.review


def admit_existing_slot(source: Path, destination: Path, secret: Path,
                        slot_number: int) -> dict:
    admitted = attest.inspect(source / "cockpit", secret, source / "receipt.json")
    manifest = review.private_read(source / "cockpit" / "manifest.json")
    original = native.verify.json_obj(manifest)
    names = native.DEFAULT | (native.HISTORY if
                              admitted["same_original_source_claimed"] else frozenset())
    attest.require(set(original["files"]) == set(names))
    payloads = {name: review.private_read(source / "cockpit" / name)
                for name in sorted(names)}
    receipt = attest.private_file(source / "receipt.json", attest.MAX_RECEIPT)
    destination.mkdir(mode=0o700)
    native.workspace.publish_bundle(destination / "cockpit", payloads, manifest)
    attest.exclusive_private_write(destination / "receipt.json", receipt)
    again = attest.inspect(destination / "cockpit", secret,
                           destination / "receipt.json")
    attest.require(again == admitted and
                   review.private_read(source / "cockpit" / "manifest.json") == manifest
                   and attest.private_file(source / "receipt.json",
                                           attest.MAX_RECEIPT) == receipt)
    for name, raw in payloads.items():
        attest.require(review.private_read(source / "cockpit" / name) == raw)
    return inbox.row_from_admission(slot_number, again, manifest)


def accept_new_packet(source: Path, destination: Path,
                      key: bytes, secret: Path, slot_number: int) -> dict:
    raw = attest.private_file(source, transport.MAX_ENCRYPTED)
    manifest, receipt, payloads = inbox.authenticate_packet(raw, key)
    destination.mkdir(mode=0o700)
    native.workspace.publish_bundle(destination / "cockpit", payloads, manifest)
    attest.exclusive_private_write(destination / "receipt.json", receipt)
    admitted = attest.inspect(destination / "cockpit", secret,
                              destination / "receipt.json")
    # Reject moving transport bytes before publication.
    attest.require(attest.private_file(source, transport.MAX_ENCRYPTED) == raw)
    return inbox.row_from_admission(slot_number, admitted, manifest)


def extend(original: Path, packages: list[Path], secret: Path,
           output_parent: Path) -> tuple[Path, dict]:
    inbox.strict_private_dir(original)
    inbox.strict_private_dir(output_parent)
    previous = inbox.inspect(original, secret)
    original_size = previous["slot_count"]
    attest.require(type(packages) is list and 1 <= len(packages) <= inbox.MAX -
                   original_size and
                   len({str(p) for p in packages}) == len(packages))
    attest.require(all(p.is_absolute() and p != secret and
                       p != original and original not in p.parents and
                       p not in output_parent.parents
                       for p in packages))
    attest.require(original != output_parent and
                   original not in output_parent.parents)
    key = attest.key_bytes(secret)
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-inbox-extend-", dir=output_parent))
    complete = False
    try:
        rows = []
        for index in range(1, original_size + 1):
            slot = f"slot-{index:02d}"
            row = admit_existing_slot(original / slot, temporary / slot, secret, index)
            attest.require(row == previous["slots"][index - 1])
            rows.append(row)
        for index, path in enumerate(packages, original_size + 1):
            slot = f"slot-{index:02d}"
            row = accept_new_packet(path, temporary / slot, key, secret, index)
            rows.append(row)
        # A changed original workroom cannot be absorbed into a new snapshot.
        attest.require(inbox.inspect(original, secret) == previous)
        record = inbox.summary(rows)
        html = inbox.render(record)
        summary = inbox.pretty(record)
        slot_names = [f"slot-{i:02d}" for i in range(1, len(rows) + 1)]
        manifest = {"kind": inbox.KIND, "schema_version": 1,
                    "slots": slot_names,
                    "files": {"index.html": inbox.descriptor(html),
                              "summary.json": inbox.descriptor(summary)}}
        for filename, payload in (("index.html", html),
                                  ("summary.json", summary),
                                  ("manifest.json", inbox.pretty(manifest))):
            attest.exclusive_private_write(temporary / filename, payload)
        attest.require(inbox.inspect(temporary, secret) == record)
        target = output_parent / ("lightup-human-inbox-" + secrets.token_hex(16))
        attest.require(not target.exists() and not target.is_symlink())
        native.workspace.exclusive_dir_publish(temporary, target)
        complete = True
        return target, record
    finally:
        if not complete:
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Create a NEW private HUMAN inbox from already-admitted inbox and 1–11 "
        "encrypted source-free cockpit packets, leaving all sources immutable"))
    parser.add_argument("--inbox", required=True, type=Path,
                        help="Existing complete private HUMAN inbox")
    parser.add_argument("--package", action="append", required=True, type=Path,
                        help="One encrypted cockpit; repeat up to 11 times")
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    try:
        path, result = extend(args.inbox, args.package, args.key_file,
                              args.output_parent)
        print("New immutable PRIVATE HUMAN inbox snapshot: " + str(path))
        print(str(result["slot_count"]) + " independently admitted source-free "
              "workrooms; " + str(result["pending_human_questions_not_fixes"]) +
              " pending HUMAN questions (not verified fixes).")
        print("Previous inbox left unchanged. No consent, identities or "
              "security outcomes certified.")
        return 2
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError,
            RecursionError, KeyError, review.Hold,
            transport.InvalidTag, transport.binascii.Error):
        print("HOLD: PRIVATE HUMAN inbox extension rejected; nothing authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
