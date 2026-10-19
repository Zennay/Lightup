#!/usr/bin/env python3
"""PRIVATE HUMAN workroom operator console: inspect and immutable next version.

Uses original cockpit admission and the encrypted plan. Never mutates prior
workrooms, source evidence, grants, active targets or remediation outcomes.
"""
from __future__ import annotations

import argparse
import hashlib
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

native = attest.read_cockpit
review = attest.review
FILES = {"index.html", "inbox", "board", "plan.ltplan"}


def require(value: bool) -> None:
    attest.require(value)


def inspect(root: Path, secret: Path) -> dict:
    inbox.strict_private_dir(root)
    require({p.name for p in root.iterdir()} == FILES)
    inbox.strict_private_dir(root / "board")
    require({p.name for p in (root / "board").iterdir()} ==
            {"index.html", "anonymous-counts.json", "manifest.json"})
    source, digest = coordination.admitted_inbox(root / "inbox", secret)
    plan, encrypted = coordination.decrypt(root / "plan.ltplan", secret, source, digest)
    original_browser = coordination.render(plan)
    anonymous = native.workspace.pretty(coordination.overview(plan))
    manifest = native.verify.json_obj(review.private_read(root / "board" / "manifest.json"))
    require(type(manifest) is dict and set(manifest) ==
            {"kind", "schema_version", "files", "source_inbox_manifest_sha256",
             "encrypted_plan_sha256", "warning"} and
            manifest["kind"] == "lightup.private_human_coordination_browser" and
            type(manifest["schema_version"]) is int and
            manifest["schema_version"] == 1 and
            manifest["warning"] == coordination.WARNING and
            manifest["source_inbox_manifest_sha256"] == digest and
            manifest["encrypted_plan_sha256"] == hashlib.sha256(encrypted).hexdigest() and
            manifest["files"] == {
                "index.html": inbox.descriptor(original_browser),
                "anonymous-counts.json": inbox.descriptor(anonymous)})
    require(review.private_read(root / "board" / "manifest.json") ==
            native.workspace.pretty(manifest) and
            review.private_read(root / "board" / "index.html") == original_browser and
            review.private_read(root / "board" / "anonymous-counts.json") == anonymous and
            review.private_read(root / "index.html") ==
            workroom.root_page(plan["revision"], source["slot_count"]))
    return plan


def revise(original: Path, key_file: Path, output_parent: Path,
           slot: int, assignee: str | None, stage: str | None,
           priority: str | None, due_date: str | None, note: str | None,
           clear_due: bool, clear_note: bool) -> tuple[Path, dict]:
    previous = inspect(original, key_file)
    inbox.strict_private_dir(output_parent)
    require(output_parent != original and original not in output_parent.parents and
            output_parent not in key_file.parents)
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-workroom-revise-", dir=output_parent))
    try:
        next_plan_file = temporary / "next.ltplan"
        next_plan = coordination.revise(
            original / "inbox", key_file, original / "plan.ltplan",
            next_plan_file, slot, assignee, stage, priority, due_date,
            note, clear_due, clear_note)
        require(next_plan["revision"] == previous["revision"] + 1 and
                inspect(original, key_file) == previous)
        sealed = temporary / "delivery.ltworkroom"
        workroom.seal(original / "inbox", next_plan_file, key_file, sealed)
        published, opened = workroom.open_workroom(sealed, key_file, output_parent)
        # Parent workroom is untouched, and new workroom has an entirely
        # independently validated original source-free inbox and new plan.
        require(opened == next_plan)
        return published, opened
    finally:
        shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Inspect a PRIVATE HUMAN team workroom or create the next complete "
        "immutable review assignment version, without source changes"))
    actions = parser.add_subparsers(dest="action", required=True)
    inspector = actions.add_parser("inspect", help="Independently admit the entire private workroom")
    inspector.add_argument("--workroom", required=True, type=Path)
    inspector.add_argument("--key-file", required=True, type=Path)
    editing = actions.add_parser("revise", help="Publish NEW complete workroom after HUMAN slot edit")
    editing.add_argument("--workroom", required=True, type=Path)
    editing.add_argument("--key-file", required=True, type=Path)
    editing.add_argument("--output-parent", required=True, type=Path)
    editing.add_argument("--slot", required=True, type=int)
    editing.add_argument("--assignee")
    editing.add_argument("--stage", choices=coordination.STAGES)
    editing.add_argument("--priority", choices=coordination.PRIORITIES)
    editing.add_argument("--due-date")
    editing.add_argument("--note")
    editing.add_argument("--clear-due", action="store_true")
    editing.add_argument("--clear-note", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "inspect":
            plan = inspect(args.workroom, args.key_file)
            print("REVIEW_ONLY: entire PRIVATE HUMAN workroom and original source-free slots admitted.")
        else:
            target, plan = revise(
                args.workroom, args.key_file, args.output_parent,
                args.slot, args.assignee, args.stage, args.priority,
                args.due_date, args.note, args.clear_due, args.clear_note)
            print("New immutable PRIVATE HUMAN workroom: " + str(target))
            print("Previous workroom, source-free evidence and plan remain unchanged.")
        print(str(len(plan["slots"])) + " source-free local HUMAN work slots; "
              "revision " + str(plan["revision"]) +
              ". No grant, client consent, verified fix or retest.")
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, InvalidTag, transport.binascii.Error,
            review.Hold):
        print("HOLD: PRIVATE HUMAN workroom update/inspection rejected; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
