#!/usr/bin/env python3
"""One offline receiver-side entry point for LightUp HUMAN-only count handoffs.

No network, scanner, provider, source writeback or original evidence.
Explicit source-free PRIVATE folders only. All successful product commands
return exit 2 REVIEW_ONLY; exit 3 is HOLD, never security authorization.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import receive
import recipient_workload_series as timeline
import timeline_receive
import trend
import recipient_studio
import recipient_journal
import recipient_journal_receive
import recipient_studio_receive
import recipient_journal_history


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        description="LightUp PRIVATE source-free HUMAN-only recipient desk "
                    "(no original evidence/client/finding records required)")
    cmds = top.add_subparsers(dest="action", required=True)

    p = cmds.add_parser("compare", help="Compare two received full private cockpits")
    p.add_argument("--left", type=Path, required=True)
    p.add_argument("--right", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)

    p = cmds.add_parser("series", help="One 2–12-packet offline workload chart")
    p.add_argument("--cockpit", type=Path, required=True, action="append",
                   help="Full source-free PRIVATE cockpit; repeat 2–12")
    p.add_argument("--output-dir", type=Path, required=True)

    p = cmds.add_parser("reopen-compare",
                        help="Reopen comparison receipt without original snapshots")
    p.add_argument("--receipt", type=Path, required=True)

    p = cmds.add_parser("reopen-series",
                        help="Reopen multi-packet series without original snapshots")
    p.add_argument("--receipt", type=Path, required=True)

    p = cmds.add_parser("human-studio",
                        help="Build offline interactive PRIVATE HUMAN follow-up workroom")
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--kind", choices=("compare", "series"), required=True)
    p.add_argument("--output-dir", type=Path, required=True)

    p = cmds.add_parser("human-open-studio",
                        help="Reopen complete native private interactive studio before browser use")
    p.add_argument("--folder", type=Path, required=True)

    p = cmds.add_parser("human-publish",
                        help="Publish native source-bound PRIVATE HUMAN local journal handoff")
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--kind", choices=("compare", "series"), required=True)
    p.add_argument("--journal", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)

    p = cmds.add_parser("human-reopen",
                        help="Reopen previously published PRIVATE HUMAN handoff without source")
    p.add_argument("--folder", type=Path, required=True)
    p = cmds.add_parser("human-diff",
                        help="Compare two original-receipt-bound PRIVATE HUMAN journal revisions")
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)

    p = cmds.add_parser("human-reopen-diff",
                        help="Reopen locally published HUMAN-only changes without originals")
    p.add_argument("--folder", type=Path, required=True)
    return top


def execute(args: argparse.Namespace) -> None:
    if args.action == "compare":
        result = trend.publish(args.left, args.right, args.output_dir)
        print("Comparison created; left/right locally pending HUMAN questions: " +
              str(result["left_pending_human"]) + " / " +
              str(result["right_pending_human"]))
        print("Open private index.html locally; see recipient-actions.md.")
    elif args.action == "series":
        result = timeline.publish(args.cockpit, args.output_dir)
        print("PRIVATE HUMAN multi-packet series created: " +
              str(result["snapshot_count"]) + " owner-selected packets; " +
              str(result["last_pending"]) + " last-slot pending questions.")
        print("Open private index.html locally; see human-followup.md.")
    elif args.action == "reopen-compare":
        result = receive.inspect(args.receipt)
        print("Original comparison receipt internally consistent: " +
              str(result["left_pending"]) + "/" +
              str(result["right_pending"]) + " pending.")
    elif args.action == "reopen-series":
        result = timeline_receive.inspect(args.receipt)
        print("Original HUMAN series internally consistent: " +
              str(result["packet_count"]) + " locally selected packets.")
    elif args.action == "human-studio":
        result = recipient_studio.publish(args.receipt, args.kind, args.output_dir)
        print("PRIVATE networkless HUMAN reason workroom created; " +
              str(result["human_reason_groups"]) + " local reason groups. "
              "Open private index.html in a trusted offline browser.")
    elif args.action == "human-open-studio":
        result = recipient_studio_receive.inspect(args.folder)
        print("PRIVATE interactive HUMAN studio locally consistent, " +
              str(result["human_reason_groups"]) +
              " reason groups. Sender/client identity not authenticated.")
    elif args.action == "human-publish":
        result = recipient_journal.publish(args.receipt, args.kind,
                                           args.journal, args.output_dir)
        print("PRIVATE original-receipt-bound HUMAN review published; " +
              str(result["local_human_open"]) +
              " unanswered aggregate reason groups. No original owner writeback.")
    elif args.action == "human-reopen":
        result = recipient_journal_receive.inspect(args.folder)
        print("PRIVATE human review locally reproduced; " +
              str(result["human_reason_groups"]) + " local aggregate reason groups.")
    elif args.action == "human-diff":
        result = recipient_journal_history.publish(args.before, args.after,
                                                   args.output_dir)
        print("PRIVATE HUMAN local follow-up changes published: " +
              str(result["local_changed_stage"]) + " stage, " +
              str(result["local_changed_route"]) + " route, " +
              str(result["private_note_changes"]) +
              " PRIVATE note-change flags (no notes copied).")
    elif args.action == "human-reopen-diff":
        result = recipient_journal_history.inspect(args.folder)
        print("PRIVATE local HUMAN change receipt re-opened; " +
              str(result["changed_stage"]) + " locally changed stages.")
    else:
        raise trend.review.Hold("Unrecognized HUMAN-only private action")
    print("REVIEW_ONLY: unsigned owner-selected counts, NOT verified source identity, "
          "same original cases, chronology, security, consent, fix or retest.")


def main() -> int:
    args = parser().parse_args()
    try:
        execute(args)
        return 2
    except (trend.review.Hold, ValueError, UnicodeError, OSError):
        print("HOLD: original PRIVATE source-free HUMAN input or output invalid. "
              "No authorization or verified remediation.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
