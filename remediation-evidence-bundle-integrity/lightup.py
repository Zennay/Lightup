#!/usr/bin/env python3
"""One unified OFFLINE PRIVATE LightUp HUMAN evidence workroom entrypoint.

Calls existing pinned production modules directly, without subprocesses,
network I/O, grants, target assessment, security verdicts or native Apply.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import amend
import board
import compare_workrooms
import handoff
import prepare
import read_cockpit
import revise
import verify
import workroom_actions

review = verify.review
triage = verify.triage
workspace = verify.workspace

def private_paths(p: argparse.ArgumentParser, label: str, help_text: str) -> None:
    p.add_argument(label, type=Path, required=True, help=help_text)

def repeat_bundle(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bundle", type=Path, action="append", required=True,
                   help="One complete original PRIVATE Evidence Relationship Desk (repeat 1–12)")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LightUp original-source PRIVATE HUMAN workroom: source-first, offline only")
    actions = parser.add_subparsers(dest="action", required=True)

    p = actions.add_parser("workroom", help="Create native original+cockpit PRIVATE workroom")
    p.add_argument("--input-dir", type=Path, action="append", default=[],
                   help="Original PRIVATE raw current/previous/session directory")
    p.add_argument("--bundle", type=Path, action="append", default=[],
                   help="Already complete original PRIVATE Evidence Relationship Desk")
    private_paths(p, "--output-dir", "NEW owner-private 0700 workroom directory")

    p = actions.add_parser("cockpit", help="Create source-free portable HUMAN cockpit only")
    repeat_bundle(p)
    private_paths(p, "--output-dir", "NEW owner-private portable Cockpit directory")

    p = actions.add_parser("questions", help="Make original-source PRIVATE HUMAN action page")
    repeat_bundle(p)
    private_paths(p, "--html", "NEW PRIVATE owner-only human source task HTML")

    p = actions.add_parser("draft", help="Generate source-session-pinned HUMAN revision plan")
    private_paths(p, "--workroom", "Existing full original owner-private workroom")
    private_paths(p, "--draft-plan", "NEW owner-private JSON revision plan")

    p = actions.add_parser("revise", help="Apply up to 64 HUMAN changes into NEW workroom")
    private_paths(p, "--workroom", "Existing original full source-owner workroom")
    private_paths(p, "--plan", "Owner-private source-bound JSON revision plan")
    private_paths(p, "--output-dir", "NEW complete original source-owner workroom")

    p = actions.add_parser("amend", help="Change one original HUMAN question into NEW workroom")
    private_paths(p, "--workroom", "Existing original owner-private workroom")
    p.add_argument("--slot", type=int, required=True,
                   help="Source slot from PRIVATE tasks.html")
    p.add_argument("--ordinal", type=int, required=True,
                   help="Original HUMAN row ordinal")
    p.add_argument("--stage", choices=triage.STAGES,
                   help="New original HUMAN stage; optional if note changes")
    notes = p.add_mutually_exclusive_group()
    notes.add_argument("--note-file", type=Path,
                       help="Original PRIVATE 0600 note file, NEVER note text in argv")
    notes.add_argument("--clear-note", action="store_true",
                       help="Remove existing note in NEW version only")
    private_paths(p, "--output-dir", "NEW original private workroom")

    p = actions.add_parser("diff", help="Compare two original workrooms' HUMAN edits")
    private_paths(p, "--before", "Original full previous owner-private workroom")
    private_paths(p, "--after", "New full original owner-private workroom")
    private_paths(p, "--output-dir", "NEW private HUMAN diff HTML/JSON folder")

    p = actions.add_parser("handoff", help="Prepare ONLY source-free owner-private Cockpit files")
    private_paths(p, "--workroom", "Original full owner-private workroom")
    private_paths(p, "--output-dir", "NEW owner-private source-free recipient folder")

    p = actions.add_parser("receive", help="Verify received complete PRIVATE Cockpit offline")
    private_paths(p, "--cockpit", "Complete existing source-free private received folder")
    return parser

def execute(args: argparse.Namespace) -> None:
    action = args.action
    if action == "workroom":
        report = prepare.publish(args.input_dir, args.output_dir, args.bundle)
        print("Original PRIVATE HUMAN workroom built; " +
              str(report["source_slots"]) + " source slot(s).")
    elif action == "cockpit":
        report = board.publish(args.bundle, args.output_dir)
        print("Source-free PRIVATE HUMAN cockpit built; " +
              str(report["source_slots"]) + " original slot(s).")
    elif action == "questions":
        sources = args.bundle
        review.require(
            sources and args.html.parent == sources[0].parent and
            all(s.parent == args.html.parent and
                s.name == f"original-{i:02}" for i, s in enumerate(sources, 1)) and
            args.html.name not in {"manifest.json", "index.html"},
            "HUMAN task page must be placed next to original-XX private workspaces")
        triage.private_parent(args.html)
        review.private_publish(args.html, workroom_actions.render(
            workroom_actions.collect(sources)))
        print("Original-private HUMAN tasks page published (not source-free).")
    elif action == "draft":
        review.require(args.draft_plan.parent != args.workroom and
                       args.workroom not in args.draft_plan.parents,
                       "Revision plan cannot modify original source workroom")
        triage.private_parent(args.draft_plan)
        _, snapshot = revise.private_workroom(args.workroom)
        review.private_publish(args.draft_plan,
                               workspace.pretty(revise.proposal(snapshot)))
        print("New source-session-pinned PRIVATE HUMAN plan created.")
    elif action == "revise":
        result = revise.revise(args.workroom, args.plan, args.output_dir)
        print("New original-private workroom with " + str(result["changes"]) +
              " HUMAN question edit(s) published; old source unchanged.")
    elif action == "amend":
        report = amend.change_one(args.workroom, args.output_dir,
                                  args.slot, args.ordinal, args.stage,
                                  args.note_file, args.clear_note)
        print("Original-private HUMAN question amended in NEW workroom; " +
              str(report["locally_pending_not_fixes"]) +
              " questions locally pending, not verified findings.")
    elif action == "diff":
        report = compare_workrooms.publish(args.before, args.after, args.output_dir)
        print("Original-private HUMAN difference desk created; " +
              str(report["changed_original_human_rows"]) + " question(s) changed.")
    elif action == "handoff":
        report = handoff.prepare(args.workroom, args.output_dir)
        print("ONLY " + str(report["only_source_free_files"]) +
              " source-free PRIVATE cockpit files prepared for an authorized receiver.")
    elif action == "receive":
        report = read_cockpit.inspect(args.cockpit)
        print("PRIVATE cockpit local consistency admitted, " +
              str(report["original_source_slots_not_unique_cases"]) +
              " local original source slot(s). No original authenticity.")
    else:
        raise review.Hold("Unknown offline HUMAN workroom command")
    print("HUMAN REVIEW ONLY · INCUBATE M3/M7 · DRAFT/HOLD. "
          "No authenticated source, consent, grant, scan, fix, retest or release.")

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        execute(args)
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE original source/HUMAN operation could not be admitted.",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
