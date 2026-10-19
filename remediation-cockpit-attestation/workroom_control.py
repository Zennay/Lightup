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
    anonymous = native.workspace.pretty(coordination.overview(plan))
    manifest = native.verify.json_obj(review.private_read(root / "board" / "manifest.json"))
    original_fields = {"kind", "schema_version", "files", "source_inbox_manifest_sha256",
                       "encrypted_plan_sha256", "warning"}
    require(type(manifest) is dict and set(manifest) in
            (original_fields, original_fields | {"navigation"}))
    if "navigation" in manifest:
        import linked_board
        import workroom_home
        import workroom_home_v2
        require(manifest["navigation"] in (linked_board.MODE, workroom_home_v2.MODE))
        original_browser = linked_board.render(plan)
        expected_home = (workroom_home.render(plan) if
                         manifest["navigation"] == linked_board.MODE else
                         workroom_home_v2.render(plan))
    else:
        # Keep every previously published original PRIVATE workroom readable.
        original_browser = coordination.render(plan)
        expected_home = workroom.root_page(plan["revision"], source["slot_count"])
    require(
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
            expected_home)
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




def create_workroom(packages: list[Path], key_file: Path,
                    output_parent: Path) -> tuple[Path, dict]:
    """Complete first-time HUMAN workroom directly from encrypted packets.

    Staging is owner-private; publish only the completed original native
    source-free inbox plus fresh encrypted unassigned HUMAN coordination plan.
    """
    inbox.strict_private_dir(output_parent)
    require(1 <= len(packages) <= inbox.MAX)
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-workroom-create-", dir=output_parent))
    try:
        private_inbox, _ = inbox.receive_many(packages, key_file, temporary)
        initial_plan = temporary / "initial.ltplan"
        plan = coordination.start(private_inbox, key_file, initial_plan)
        sealed = temporary / "initial.ltworkroom"
        workroom.seal(private_inbox, initial_plan, key_file, sealed)
        complete, admitted = workroom.open_workroom(sealed, key_file, output_parent)
        require(admitted == plan and inspect(complete, key_file) == plan)
        return complete, plan
    finally:
        shutil.rmtree(temporary)

def extend_workroom(original: Path, key_file: Path, packages: list[Path],
                    output_parent: Path) -> tuple[Path, dict]:
    """One HUMAN action: encrypted intake + exact old-plan carry + new workroom.

    Only a new workroom is published. Both original source-free bytes and
    local HUMAN notes/assignments in the previous workroom remain untouched.
    """
    previous = inspect(original, key_file)
    inbox.strict_private_dir(output_parent)
    require(original != output_parent and original not in output_parent.parents and
            1 <= len(packages) <= inbox.MAX - len(previous["slots"]))
    import extend
    import carry
    temporary = Path(tempfile.mkdtemp(prefix=".lightup-workroom-intake-", dir=output_parent))
    try:
        new_inbox, _ = extend.extend(original / "inbox", packages, key_file, temporary)
        carried_path = temporary / "carried.ltplan"
        carried = carry.carry(original / "inbox", new_inbox, key_file,
                              original / "plan.ltplan", carried_path)
        require(len(carried["slots"]) == len(previous["slots"]) + len(packages)
                and carried["revision"] == previous["revision"] + 1)
        sealed = temporary / "new.ltworkroom"
        workroom.seal(new_inbox, carried_path, key_file, sealed)
        result, _ = workroom.open_workroom(sealed, key_file, output_parent)
        require(inspect(result, key_file) == carried and
                inspect(original, key_file) == previous)
        return result, carried
    finally:
        shutil.rmtree(temporary)

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Inspect a PRIVATE HUMAN team workroom or create the next complete "
        "immutable review assignment version, without source changes"))
    actions = parser.add_subparsers(dest="action", required=True)
    sending = actions.add_parser("send", help="One-file encrypted send of a fully admitted complete PRIVATE workroom")
    sending.add_argument("--workroom", required=True, type=Path)
    sending.add_argument("--key-file", required=True, type=Path)
    sending.add_argument("--output", required=True, type=Path)
    receiving = actions.add_parser("receive", help="Open a full encrypted PRIVATE workroom and its HUMAN plan")
    receiving.add_argument("--input", required=True, type=Path)
    receiving.add_argument("--key-file", required=True, type=Path)
    receiving.add_argument("--output-parent", required=True, type=Path)
    creating = actions.add_parser("create", help="Receive encrypted source-free cockpits and open a complete PRIVATE workroom in one command")
    creating.add_argument("--package", action="append", required=True, type=Path)
    creating.add_argument("--key-file", required=True, type=Path)
    creating.add_argument("--output-parent", required=True, type=Path)
    intake = actions.add_parser("extend", help="Receive new encrypted cockpits and carry existing HUMAN assignments into one new workroom")
    intake.add_argument("--workroom", required=True, type=Path)
    intake.add_argument("--key-file", required=True, type=Path)
    intake.add_argument("--package", action="append", required=True, type=Path)
    intake.add_argument("--output-parent", required=True, type=Path)
    inspector = actions.add_parser("inspect", help="Independently admit the entire private workroom")
    inspector.add_argument("--workroom", required=True, type=Path)
    inspector.add_argument("--key-file", required=True, type=Path)
    count_export = actions.add_parser("export-counts", help="Export strictly anonymous HUMAN counts without private manifest fingerprints")
    count_export.add_argument("--workroom", required=True, type=Path)
    count_export.add_argument("--key-file", required=True, type=Path)
    count_export.add_argument("--output", required=True, type=Path)
    batch_template = actions.add_parser("bulk-template", help="Create 0600 stale-plan-bound HUMAN batch edit template for a complete workroom")
    batch_template.add_argument("--workroom", required=True, type=Path)
    batch_template.add_argument("--key-file", required=True, type=Path)
    batch_template.add_argument("--output", required=True, type=Path)
    batch_preview = actions.add_parser("bulk-preview", help="Show only aggregate HUMAN changes without publishing")
    batch_preview.add_argument("--workroom", required=True, type=Path)
    batch_preview.add_argument("--key-file", required=True, type=Path)
    batch_preview.add_argument("--edits", required=True, type=Path)
    batch = actions.add_parser("bulk-revise", help="Apply PRIVATE batch to a complete admitted workroom in one atomic new version")
    batch.add_argument("--workroom", required=True, type=Path)
    batch.add_argument("--key-file", required=True, type=Path)
    batch.add_argument("--edits", required=True, type=Path)
    batch.add_argument("--output-parent", required=True, type=Path)
    rekey = actions.add_parser("rekey", help="Re-sign all source-free cockpit receipts and re-encrypt the HUMAN plan under a NEW team key")
    rekey.add_argument("--workroom", required=True, type=Path)
    rekey.add_argument("--old-key-file", required=True, type=Path)
    rekey.add_argument("--new-key-file", required=True, type=Path)
    rekey.add_argument("--output-parent", required=True, type=Path)
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
        if args.action == "send":
            previous = inspect(args.workroom, args.key_file)
            require(args.output != args.workroom and
                    args.workroom not in args.output.parents and
                    args.output != args.key_file)
            transmitted = workroom.seal(args.workroom / "inbox",
                                        args.workroom / "plan.ltplan",
                                        args.key_file, args.output)
            require(transmitted == previous and inspect(args.workroom, args.key_file) == previous)
            plan = previous
            print("One PRIVATE source-free HUMAN workroom encrypted for trusted handoff: " + str(args.output))
        elif args.action == "receive":
            destination, plan = workroom.open_workroom(args.input, args.key_file,
                                                       args.output_parent)
            require(inspect(destination, args.key_file) == plan)
            print("Complete source-free PRIVATE HUMAN workroom independently received: " + str(destination))
        elif args.action == "create":
            result, plan = create_workroom(args.package, args.key_file,
                                           args.output_parent)
            print("PRIVATE HUMAN workroom created from encrypted source-free packets: " + str(result))
            print("All newly received HUMAN coordination slots start unassigned.")
            print("Original encrypted packages and original source bytes untouched.")
        elif args.action == "extend":
            result, plan = extend_workroom(args.workroom, args.key_file,
                                           args.package, args.output_parent)
            print("New complete PRIVATE HUMAN workroom after encrypted intake: " + str(result))
            print("Existing local HUMAN assignees/notes/dates carried byte-exact; "
                  "new received slots start unassigned.")
            print("Previous original workroom and all encrypted incoming packets unchanged.")
        elif args.action == "rekey":
            import rekey_workroom
            destination, plan = rekey_workroom.rotate(
                args.workroom, args.old_key_file, args.new_key_file,
                args.output_parent)
            print("New PRIVATE HUMAN workroom rekeyed and atomically published: " + str(destination))
            print("Previous key, encrypted source-free copies and receipts are NOT revoked.")
        elif args.action == "inspect":
            plan = inspect(args.workroom, args.key_file)
            print("REVIEW_ONLY: entire PRIVATE HUMAN workroom and original source-free slots admitted.")
        elif args.action == "export-counts":
            plan = inspect(args.workroom, args.key_file)
            original = inbox.inspect(args.workroom / "inbox", args.key_file)
            stats = inbox.anonymous_counts(original)
            require(stats["source_free_workrooms_not_unique_cases"] == len(plan["slots"]))
            planning = coordination.overview(plan)
            payload = {
                "kind": "lightup.private_human_workroom_anonymous_counts",
                "schema_version": 1,
                "disposition": "COUNTS_ONLY_NO_AUTHORITY",
                "source_free_inbox": stats,
                "local_human_planning": planning,
                "warning": ("Anonymous aggregate HUMAN workload only: no original "
                            "source truth, client identity, consent, or verified fix."),
                **{flag: False for flag in review.FLAGS},
            }
            require(args.output != args.key_file and args.output != args.workroom and
                    args.workroom not in args.output.parents and
                    inspect(args.workroom, args.key_file) == plan)
            attest.exclusive_private_write(args.output, inbox.pretty(payload))
            print("PRIVATE aggregated HUMAN counts exported without operator aliases,"
                  " private notes, due dates or linkable manifest hashes.")
        elif args.action in ("bulk-template", "bulk-preview"):
            plan = inspect(args.workroom, args.key_file)
            import bulk
            if args.action == "bulk-template":
                bulk.edit_template(args.workroom / "inbox", args.key_file,
                                   args.workroom / "plan.ltplan", args.output)
                print("PRIVATE 0600 HUMAN batch template created for exactly this workroom.")
            else:
                changed, detail = bulk.prepare(args.workroom / "inbox",
                    args.workroom / "plan.ltplan", args.edits, args.key_file)
                require(changed["revision"] == plan["revision"] + 1)
                print(f"REVIEW_ONLY: {detail['slots_changed']} HUMAN slots for revision "
                      f"{detail['new_revision']}; nothing written.")
        elif args.action == "bulk-revise":
            # Do not trust a bare encrypted plan extracted from an incomplete
            # or edited workroom. Admit the full source, plan and rendered UI.
            old_plan = inspect(args.workroom, args.key_file)
            import bulk
            destination, stats = bulk.publish(
                args.workroom / "inbox", args.workroom / "plan.ltplan",
                args.edits, args.key_file, args.output_parent)
            plan = inspect(destination, args.key_file)
            require(plan["revision"] == old_plan["revision"] + 1 and
                    stats["slots_changed"] >= 1)
            print("New complete PRIVATE HUMAN workroom after atomic batch: " + str(destination))
            print("Original workroom and encrypted plan unchanged.")
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
