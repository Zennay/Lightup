#!/usr/bin/env python3
"""Rotate an entire admitted PRIVATE source-free HUMAN workroom to a new team key.

Authenticates old cockpits and plan first, rekeys every detached receipt and
the encrypted local HUMAN plan, regenerates the deterministic operator board,
and publishes one entirely NEW atomic 0700 workroom. No old key revocation.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from cryptography.exceptions import InvalidTag

import attest
import coordination
import inbox
import transport
import workroom
import workroom_control

review = attest.review
native = attest.read_cockpit


def require(ok: bool) -> None:
    attest.require(ok)


def changed_receipt(manifest: bytes, new_key: bytes) -> bytes:
    doc = {"kind": attest.KIND, "schema_version": 1,
           "algorithm": "HMAC-SHA256",
           "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
           "mac": attest.mac(new_key, manifest)}
    return transport.canonical(doc)


def receive_rotated(source: Path, old_key_file: Path,
                    destination: Path, new_key_file: Path,
                    new_key: bytes) -> dict:
    prior = attest.inspect(source / "cockpit", old_key_file,
                           source / "receipt.json")
    manifest = review.private_read(source / "cockpit" / "manifest.json")
    meta = native.verify.json_obj(manifest)
    names = set(native.DEFAULT) | (
        set(native.HISTORY) if prior["same_original_source_claimed"] else set())
    require(set(meta["files"]) == names)
    files = {name: review.private_read(source / "cockpit" / name)
             for name in sorted(names)}
    old_receipt = attest.private_file(source / "receipt.json", attest.MAX_RECEIPT)

    destination.mkdir(mode=0o700)
    native.workspace.publish_bundle(destination / "cockpit", files, manifest)
    attest.exclusive_private_write(destination / "receipt.json",
                                   changed_receipt(manifest, new_key))
    new_admission = attest.inspect(destination / "cockpit", new_key_file,
                                  destination / "receipt.json")
    require(new_admission == prior and
            review.private_read(source / "cockpit" / "manifest.json") == manifest and
            attest.private_file(source / "receipt.json", attest.MAX_RECEIPT) == old_receipt)
    for name, raw in files.items():
        require(review.private_read(source / "cockpit" / name) == raw)
    return new_admission


def rotate(old_workroom: Path, old_secret: Path, new_secret: Path,
           output_parent: Path) -> tuple[Path, dict]:
    inbox.strict_private_dir(old_workroom)
    inbox.strict_private_dir(output_parent)
    require(old_workroom != output_parent and
            old_workroom not in output_parent.parents and
            old_workroom != old_secret and old_workroom != new_secret and
            old_secret != new_secret)
    old = attest.key_bytes(old_secret)
    new = attest.key_bytes(new_secret)
    require(not hmac.compare_digest(old, new))
    previous = workroom_control.inspect(old_workroom, old_secret)
    original = inbox.inspect(old_workroom / "inbox", old_secret)
    encrypted_prior = attest.private_file(old_workroom / "plan.ltplan",
                                         coordination.MAX_FILE)
    require(previous["revision"] < 1000)

    staging = Path(tempfile.mkdtemp(prefix=".lightup-private-rekey-", dir=output_parent))
    published = False
    try:
        incoming = staging / "inbox"
        incoming.mkdir(mode=0o700)
        rows = []
        for index in range(1, original["slot_count"] + 1):
            name = f"slot-{index:02d}"
            new_admission = receive_rotated(
                old_workroom / "inbox" / name, old_secret,
                incoming / name, new_secret, new)
            manifest = review.private_read(incoming / name / "cockpit" / "manifest.json")
            row = inbox.row_from_admission(index, new_admission, manifest)
            # Preserve the exact original source-free slot-by-slot identity;
            # equal anonymous manifests alone do not prove duplicate clients.
            require(row == original["slots"][index-1])
            rows.append(row)
        updated_inbox = inbox.summary(rows)
        require(updated_inbox == original)
        counts = inbox.pretty(updated_inbox)
        browser = inbox.render(updated_inbox)
        descriptor = {"kind": inbox.KIND, "schema_version": 1,
                      "slots": [f"slot-{index:02d}" for index in
                                range(1, len(rows)+1)],
                      "files": {"summary.json": inbox.descriptor(counts),
                                "index.html": inbox.descriptor(browser)}}
        for name, body in (("index.html", browser), ("summary.json", counts),
                           ("manifest.json", inbox.pretty(descriptor))):
            attest.exclusive_private_write(incoming / name, body)

        new_source, new_manifest = coordination.admitted_inbox(incoming, new_secret)
        old_manifest = coordination.manifest_sha(old_workroom / "inbox")
        require(new_source == original and new_manifest == old_manifest)
        # Exact original HUMAN local assignments remain unchanged.
        next_plan = dict(previous)
        next_plan["slots"] = [dict(row) for row in previous["slots"]]
        next_plan["revision"] = previous["revision"] + 1
        next_plan["prior_encrypted_plan_sha256"] = hashlib.sha256(encrypted_prior).hexdigest()
        next_plan["inbox_manifest_sha256"] = new_manifest
        coordination.sealed_fields(next_plan, new_source, new_manifest)
        coordination.encrypt(next_plan, new_secret, staging / "plan.ltplan")
        coordination.publish(incoming, new_secret, staging / "plan.ltplan",
                             staging / "board", linked_workroom=True)
        import workroom_home
        attest.exclusive_private_write(staging / "index.html",
                                       workroom_home.render(next_plan))
        # Full workroom admission by new key, old key untouched.
        require(workroom_control.inspect(staging, new_secret) == next_plan and
                workroom_control.inspect(old_workroom, old_secret) == previous and
                attest.private_file(old_workroom / "plan.ltplan",
                                    coordination.MAX_FILE) == encrypted_prior)
        destination = output_parent / ("lightup-rekeyed-human-workroom-" +
                                       secrets.token_hex(16))
        require(not destination.exists() and not destination.is_symlink())
        native.workspace.exclusive_dir_publish(staging, destination)
        published = True
        return destination, next_plan
    finally:
        if not published:
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Rekey ALL PRIVATE HUMAN source-free cockpit receipts and bound local "
        "coordination plan; atomically publish NEW full workroom, old unchanged"))
    parser.add_argument("--workroom", required=True, type=Path)
    parser.add_argument("--old-key-file", required=True, type=Path)
    parser.add_argument("--new-key-file", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    try:
        folder, plan = rotate(args.workroom, args.old_key_file,
                              args.new_key_file, args.output_parent)
        print("PRIVATE entire source-free HUMAN workroom rekeyed: " + str(folder))
        print(str(len(plan["slots"])) + " independent source-free cockpits "
              "re-signed; local HUMAN plan now encrypted under new key; "
              "revision " + str(plan["revision"]))
        print("Previous copies and old key/receipts remain valid until "
              "separately revoked by authorized HUMAN operators.")
        print("No sender identity, original client consent, verified fix "
              "or security authorization has been established.")
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, InvalidTag,
            transport.binascii.Error, review.Hold):
        print("HOLD: PRIVATE HUMAN workroom rotation rejected; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
