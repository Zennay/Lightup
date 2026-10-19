#!/usr/bin/env python3
"""Batch private HUMAN coordination edits on original source-free inbox slots.

Each edit is an explicit HUMAN-only assignment, local stage/priority, due date
or note. Strict source and encrypted-plan binding prevents stale overwrites.
No original evidence, consent, grants, scans or retest status are changed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

from cryptography.exceptions import InvalidTag

import attest
import coordination
import inbox
import transport
import workroom

review = attest.review
native = attest.read_cockpit
KIND = "lightup.private_human_bulk_slot_edit_v1"
FIELDS = frozenset({"kind", "schema_version", "inbox_manifest_sha256",
                    "base_encrypted_plan_sha256", "base_plan_revision", "edits"})
EDIT_FIELDS = frozenset({"slot", "set"})
MUTABLE = frozenset({"assignee", "stage", "priority", "due_date", "private_note"})
MAX_EDIT_BYTES = 8192


def require(condition: bool) -> None:
    attest.require(condition)


def admitted_sources(folder: Path, key_file: Path,
                     old_plan: Path) -> tuple[dict, str, dict, bytes]:
    original, manifest_digest = coordination.admitted_inbox(folder, key_file)
    plan, encrypted = coordination.decrypt(old_plan, key_file, original, manifest_digest)
    require(plan["revision"] < 1000)
    return original, manifest_digest, plan, encrypted


def edit_template(folder: Path, key_file: Path,
                  old_plan: Path, output: Path) -> dict:
    original, digest, plan, encrypted = admitted_sources(folder, key_file, old_plan)
    require(output != old_plan and output != key_file and output != folder and
            folder not in output.parents and
            not output.exists() and not output.is_symlink())
    document = {
        "kind": KIND, "schema_version": 1,
        "inbox_manifest_sha256": digest,
        "base_encrypted_plan_sha256": hashlib.sha256(encrypted).hexdigest(),
        "base_plan_revision": plan["revision"],
        "edits": [],
    }
    require(coordination.admitted_inbox(folder, key_file) == (original, digest) and
            attest.private_file(old_plan, coordination.MAX_FILE) == encrypted)
    attest.exclusive_private_write(output, transport.canonical(document))
    return document


def admit_edits(edits_file: Path, manifest: str,
                plan: dict, ciphertext: bytes) -> tuple[list[dict], bytes]:
    raw = attest.private_file(edits_file, MAX_EDIT_BYTES)
    # This deliberately permits human-authored whitespace/pretty formatting.
    # Exact JSON keys and duplicate admission remain strict.
    document = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=transport.no_duplicate_pairs)
    require(type(document) is dict and set(document) == FIELDS and
            document["kind"] == KIND and type(document["schema_version"]) is int and
            document["schema_version"] == 1 and
            document["inbox_manifest_sha256"] == manifest and
            document["base_encrypted_plan_sha256"] ==
                hashlib.sha256(ciphertext).hexdigest() and
            type(document["base_plan_revision"]) is int and
            document["base_plan_revision"] == plan["revision"] and
            type(document["edits"]) is list and
            1 <= len(document["edits"]) <= len(plan["slots"]))
    used: set[int] = set()
    operations = []
    for entry in document["edits"]:
        require(type(entry) is dict and set(entry) == EDIT_FIELDS and
                type(entry["slot"]) is int and
                1 <= entry["slot"] <= len(plan["slots"]) and
                entry["slot"] not in used and
                type(entry["set"]) is dict and
                1 <= len(entry["set"]) <= len(MUTABLE) and
                set(entry["set"]) <= MUTABLE)
        used.add(entry["slot"])
        operations.append(entry)
    return operations, raw


def prepare(folder: Path, old_plan: Path, edits_file: Path,
            key_file: Path) -> tuple[dict, dict]:
    original, digest, previous, encrypted = admitted_sources(folder, key_file, old_plan)
    operations, edits_bytes = admit_edits(edits_file, digest, previous, encrypted)
    new_plan = dict(previous)
    new_plan["revision"] = previous["revision"] + 1
    new_plan["prior_encrypted_plan_sha256"] = hashlib.sha256(encrypted).hexdigest()
    new_plan["slots"] = [dict(row) for row in previous["slots"]]
    for operation in operations:
        index = operation["slot"] - 1
        new_plan["slots"][index].update(operation["set"])
        require(new_plan["slots"][index] != previous["slots"][index])
    coordination.sealed_fields(new_plan, original, digest)
    require(new_plan != previous)
    # The same original source and old encrypted plan must still be present
    # at publication. Editing the request JSON mid-command also fails closed.
    require(coordination.admitted_inbox(folder, key_file) == (original, digest) and
            attest.private_file(old_plan, coordination.MAX_FILE) == encrypted and
            attest.private_file(edits_file, MAX_EDIT_BYTES) == edits_bytes)
    detail = {
        "slots_changed": len(operations),
        "new_revision": new_plan["revision"],
        "source_free_workrooms": len(new_plan["slots"]),
        "local_stage_counts": dict(Counter(x["stage"] for x in new_plan["slots"])),
    }
    return new_plan, detail


def apply(folder: Path, old_plan: Path, edits_file: Path, key_file: Path,
          output: Path) -> dict:
    require(output not in (old_plan, edits_file, key_file, folder) and
            folder not in output.parents and
            not output.exists() and not output.is_symlink())
    new_plan, detail = prepare(folder, old_plan, edits_file, key_file)
    coordination.encrypt(new_plan, key_file, output)
    return detail


def publish(folder: Path, old_plan: Path, edits_file: Path,
            key_file: Path, output_parent: Path) -> tuple[Path, dict]:
    inbox.strict_private_dir(output_parent)
    require(output_parent not in (folder, old_plan, edits_file, key_file) and
            folder not in output_parent.parents and
            key_file not in output_parent.parents)
    new_plan, detail = prepare(folder, old_plan, edits_file, key_file)
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-human-bulk-", dir=output_parent))
    try:
        # Only encrypted transitional material is created inside fresh 0700
        # staging. Original owner-private folders/files stay untouched.
        sealed_plan = temporary / "plan.ltplan"
        coordination.encrypt(new_plan, key_file, sealed_plan)
        ciphertext = temporary / "bundle.ltworkroom"
        workroom.seal(folder, sealed_plan, key_file, ciphertext)
        target, received = workroom.open_workroom(ciphertext, key_file, output_parent)
        require(received == new_plan)
        return target, detail
    finally:
        shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Atomic batch HUMAN slot assignment, local priority/date edits and "
        "one-command complete encrypted PRIVATE workroom delivery"))
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("template", "preview", "apply", "publish-workroom"):
        p = actions.add_parser(name)
        p.add_argument("--inbox", required=True, type=Path)
        p.add_argument("--key-file", required=True, type=Path)
        p.add_argument("--plan", required=True, type=Path)
        if name != "template":
            p.add_argument("--edits", required=True, type=Path)
        if name in ("template", "apply"):
            p.add_argument("--output", required=True, type=Path)
        if name == "publish-workroom":
            p.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "template":
            edit_template(args.inbox, args.key_file, args.plan, args.output)
            print("New PRIVATE 0600 batch template created. Edit it locally: "
                  "add slot and set entries; do not share cleartext notes.")
        elif args.action == "preview":
            _, info = prepare(args.inbox, args.plan, args.edits, args.key_file)
            print("PRIVATE local batch preview only; nothing written.")
            print(f"{info['slots_changed']} independently specified HUMAN slots "
                  f"for revision {info['new_revision']}.")
        elif args.action == "apply":
            info = apply(args.inbox, args.plan, args.edits, args.key_file,
                         args.output)
            print("ONE new 0600 encrypted HUMAN plan revision published; "
                  "previous plan and original inbox unchanged.")
            print(f"{info['slots_changed']} HUMAN slots changed in one batch.")
        else:
            destination, info = publish(args.inbox, args.plan, args.edits,
                                        args.key_file, args.output_parent)
            print("ONE complete new PRIVATE offline HUMAN workroom: " +
                  str(destination))
            print(f"{info['slots_changed']} local HUMAN slot(s) updated in "
                  f"plan revision {info['new_revision']}.")
        print("No original source finding, remediation, authenticated HUMAN "
              "identity, client consent, grant or security verdict changed.")
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError,
            RecursionError, InvalidTag, transport.binascii.Error, review.Hold):
        print("HOLD: PRIVATE HUMAN batch not admitted; original data unchanged.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
