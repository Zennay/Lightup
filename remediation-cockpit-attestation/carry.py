#!/usr/bin/env python3
"""Carry only private HUMAN slot planning onto an independently extended inbox.

The existing encrypted plan and original inbox remain unchanged. Only a
byte-exact prefix of original source-free slot manifests may be carried.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

from cryptography.exceptions import InvalidTag

import attest
import coordination
import inbox
import transport

review = attest.review


def carry(old_inbox: Path, new_inbox: Path, key_file: Path,
          old_plan: Path, output: Path) -> dict:
    attest.require(old_inbox != new_inbox and output != old_plan and
                   output != old_inbox and output != new_inbox and
                   old_inbox not in output.parents and
                   new_inbox not in output.parents and
                   key_file != output)
    original, old_manifest = coordination.admitted_inbox(old_inbox, key_file)
    expanded, new_manifest = coordination.admitted_inbox(new_inbox, key_file)
    previous, encrypted = coordination.decrypt(old_plan, key_file, original, old_manifest)
    old_total = original["slot_count"]
    new_total = expanded["slot_count"]
    attest.require(old_total < new_total <= inbox.MAX and
                   previous["revision"] < 1000 and
                   old_manifest != new_manifest)
    for idx, source in enumerate(original["slots"]):
        # New copies must preserve every original independently admitted
        # source-free private cockpit byte identity and anonymous metadata.
        attest.require(expanded["slots"][idx] == source and
                       previous["slots"][idx]["original_cockpit_manifest_sha256"] ==
                       source["source_free_manifest_sha256"])
    rows = [dict(item) for item in previous["slots"]]
    for idx in range(old_total, new_total):
        source = expanded["slots"][idx]
        rows.append({
            "slot": idx + 1,
            "original_cockpit_manifest_sha256": source["source_free_manifest_sha256"],
            "assignee": "", "stage": "unassigned", "priority": "normal",
            "due_date": None, "private_note": "",
        })
    result = dict(previous)
    result["slots"] = rows
    result["revision"] = previous["revision"] + 1
    result["prior_encrypted_plan_sha256"] = hashlib.sha256(encrypted).hexdigest()
    result["inbox_manifest_sha256"] = new_manifest
    coordination.sealed_fields(result, expanded, new_manifest)
    attest.require(inbox.inspect(old_inbox, key_file) == original and
                   inbox.inspect(new_inbox, key_file) == expanded and
                   coordination.manifest_sha(old_inbox) == old_manifest and
                   coordination.manifest_sha(new_inbox) == new_manifest and
                   attest.private_file(old_plan, coordination.MAX_FILE) == encrypted)
    coordination.encrypt(result, key_file, output)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Immutable encrypted HUMAN follow-up plan carry to an extended "
        "exact-original-prefix PRIVATE inbox, never source-side remediation"))
    parser.add_argument("--old-inbox", required=True, type=Path)
    parser.add_argument("--new-inbox", required=True, type=Path)
    parser.add_argument("--old-plan", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = carry(args.old_inbox, args.new_inbox, args.key_file,
                     args.old_plan, args.output)
        print("New encrypted HUMAN plan carried to a source-exact extended inbox.")
        print(str(len(plan["slots"])) + " original source-free slots, plan revision " +
              str(plan["revision"]) + "; previous PRIVATE plan and inbox unchanged.")
        print("No new client consent, verified remediation or automatic human action.")
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, InvalidTag, transport.binascii.Error,
            review.Hold):
        print("HOLD: PRIVATE HUMAN plan carry not admitted; nothing authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
