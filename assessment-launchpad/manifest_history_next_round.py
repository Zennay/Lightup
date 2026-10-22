#!/usr/bin/env python3
"""Offline HUMAN continuation orchestrator; only source-bound local review, never assessment."""
from __future__ import annotations

import argparse
import os

import manifest_history_rounds as timeline
import manifest_history_response as return_cli
import manifest_history_followup as delta
from launchpad import Hold, open_output_directory, report_hold

MAX_OLD_ROUNDS = 7


def private_dir(path):
    fd, absolute = open_output_directory(path)
    try:
        files = os.listdir(fd)
    finally:
        os.close(fd)
    return absolute, files


def disjoint_roots(roots):
    for i, first in enumerate(roots):
        for second in roots[i + 1:]:
            common = os.path.commonpath((first, second))
            if common in (first, second):
                raise Hold("source and new PRIVATE destination trees must remain separate")


def run(args):
    if not 1 <= len(args.round_dir) <= MAX_OLD_ROUNDS:
        raise Hold("next-round builder requires 1 to 7 original saved HUMAN rounds")
    if args.answers_dir and args.stage:
        raise Hold("HUMAN continuation requires either PRIVATE CSV or chosen stages, not both")
    if not args.answers_dir and not args.stage and not args.show_pending:
        raise Hold("next-round HUMAN continuation requires PRIVATE CSV or ROW:STAGE edits")
    if args.ack_csv_stage_replace and not args.answers_dir:
        raise Hold("CSV replacement acknowledgement requires a PRIVATE answers directory")
    if args.answers_dir and not (args.ack_csv_stage_replace or args.dry_run):
        raise Hold("PRIVATE browser CSV stage replacement needs explicit acknowledgement")
    previous_paths = args.round_dir
    # Re-admit the *complete* original HUMAN chain; this is local unsigned
    # provenance, never identity, approved scope or operator authority.
    plan_paths, history_root, _, rounds, original = timeline.admit_sources(
        args.plan_dir, args.history_dir, previous_paths, min_rounds=1)
    if args.show_pending:
        if (args.stage or args.answers_dir or args.output_dir or args.timeline_dir
                or args.delta_dir or args.dry_run or args.verify_output
                or args.ack_csv_stage_replace):
            raise Hold("PRIVATE HUMAN pending queue display cannot edit, publish or reopen anything")
        last = rounds[-1][1]["responses"]
        outstanding = ("FOLLOW_UP_REQUIRED", "NEEDS_CONTEXT",
                       "IN_REVIEW", "QUESTION_PREPARED")
        rows = [(i, row) for i, row in enumerate(last, 1)
                if row["human_stage"] in outstanding]
        print("PRIVATE_HUMAN_PENDING_REVIEW_ONLY · active_rows=" + str(len(rows))
              + " · source_rows=" + str(len(last)) + " · unsigned, no authority")
        for index, item in rows:
            print("row=" + str(index) + " · pair=" + str(item["from_ordinal"])
                  + "->" + str(item["to_ordinal"]) + " · literal_change="
                  + item["change"] + " · stage=" + item["human_stage"])
        return 0
    old_roots = [*(plan[0] for plan in plan_paths), history_root,
                 *(round_[0] for round_ in rounds)]
    if args.answers_dir:
        old_roots.append(private_dir(args.answers_dir)[0])
    private_plan_args = [part for path in args.plan_dir for part in ("--plan-dir", path)]
    latest = previous_paths[-1]
    return_args = private_plan_args + [
        "--history-dir", args.history_dir,
        "--continue-from-return-dir", latest,
    ]
    if args.answers_dir:
        return_args += ["--answers-dir", args.answers_dir]
        if args.ack_csv_stage_replace and not args.dry_run:
            return_args += ["--ack-csv-stage-replace"]
    else:
        return_args += [piece for stage in args.stage for piece in ("--stage", stage)]
    if args.dry_run:
        if args.output_dir or args.timeline_dir or args.delta_dir or args.verify_output:
            raise Hold("next-round preview cannot select output/reopen directories")
        if return_cli.main(return_args + ["--dry-run"]) != 0:
            raise Hold("original native HUMAN continuation preview not admitted")
        print("NEXT_HUMAN_ROUND_PREVIEW_REVIEW_ONLY · old_rounds="
              + str(len(rounds)) + " · new_round_ordinal=" + str(len(rounds) + 1)
              + " · no publication, scans, consent or authority")
        return 0
    if not args.output_dir:
        raise Hold("next-round publication/reopen requires a separate PRIVATE output directory")
    destination_paths = [args.output_dir]
    if args.timeline_dir:
        destination_paths.append(args.timeline_dir)
    if args.delta_dir:
        destination_paths.append(args.delta_dir)
    new_roots = [private_dir(path) for path in destination_paths]
    disjoint_roots(old_roots + [root for root, _ in new_roots])
    if not args.verify_output and any(files for _, files in new_roots):
        raise Hold("all selected PRIVATE output directories must be empty before publication")
    flag = "--verify-output-dir" if args.verify_output else "--output-dir"
    if return_cli.main(return_args + [flag, args.output_dir]) != 0:
        raise Hold("original source-bound HUMAN continuation rejected")
    if args.delta_dir:
        delta_args = private_plan_args + [
            "--history-dir", args.history_dir,
            "--before-return-dir", latest,
            "--after-return-dir", args.output_dir,
            flag, args.delta_dir,
        ]
        if delta.main(delta_args) != 0:
            raise Hold("PRIVATE HUMAN round comparison rejected")
    if args.timeline_dir:
        timeline_args = private_plan_args + [
            "--history-dir", args.history_dir,
            *[piece for path in [*previous_paths, args.output_dir]
              for piece in ("--round-dir", path)],
            flag, args.timeline_dir,
        ]
        if timeline.main(timeline_args) != 0:
            raise Hold("PRIVATE HUMAN history timeline rejected")
    print(("NEXT_HUMAN_ROUND_REOPENED" if args.verify_output else
           "NEXT_HUMAN_ROUND_PUBLISHED") + " · new_round_ordinal=" + str(len(rounds) + 1)
          + " · input_mode=" + ("PRIVATE_CSV" if args.answers_dir else "ROW_STAGES")
          + " · REVIEW_ONLY; no source mutation, permission, scan or HUMAN GO")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Continue an exact PRIVATE HUMAN chain with optional delta and timeline; no network or assessment.")
    parser.add_argument("--plan-dir", action="append", required=True,
                        help="original saved PRIVATE combined plan, history order")
    parser.add_argument("--history-dir", required=True,
                        help="original source-bound PRIVATE manifest-history directory")
    parser.add_argument("--round-dir", action="append", required=True,
                        help="1–7 ordered original saved HUMAN returns; first must be v1, rest exact v2 successors")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--stage", action="append", default=[],
                        help="one explicit 1-based original HUMAN row edit, e.g. 3:IN_REVIEW; repeatable")
    source.add_argument("--answers-dir", help="PRIVATE 0700 owner-only directory containing the one complete edited 0600 browser CSV")
    parser.add_argument("--ack-csv-stage-replace", action="store_true",
                        help="explicitly confirm full prior HUMAN stage replacement when importing PRIVATE CSV")
    parser.add_argument("--output-dir", help="new, separate PRIVATE 0700 next HUMAN return directory")
    parser.add_argument("--timeline-dir", help="optional separate PRIVATE 0700 updated timeline directory")
    parser.add_argument("--delta-dir", help="optional separate PRIVATE 0700 previous/new stage-delta directory")
    parser.add_argument("--show-pending", action="store_true",
                        help="display only current HUMAN follow-up row ordinals and stages, no target values")
    parser.add_argument("--dry-run", action="store_true",
                        help="only print source-bound counts and needed HUMAN review; no publication")
    parser.add_argument("--verify-output", action="store_true",
                        help="exact read-only reopen of all selected PRIVATE outputs")
    parser.add_argument("--explain-hold", action="store_true",
                        help="curated PRIVATE HOLD cause; never source paths or endpoint values")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Hold as error:
        report_hold("NEXT_HUMAN_ROUND_HOLD — PRIVATE source chain or output rejected",
                    error, args.explain_hold)
    except Exception:
        report_hold("NEXT_HUMAN_ROUND_HOLD — local PRIVATE source or filesystem rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
