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
    else:
        raise trend.review.Hold("Unrecognized HUMAN-only private action")
    print("REVIEW_ONLY: unsigned owner-selected counts, NOT verified source identity, "
          "same original cases, chronology, security, consent, fix or retest.")


def main() -> int:
    args = parser().parse_args()
    try:
        execute(args)
        return 2
    except (trend.review.Hold, ValueError, OSError):
        print("HOLD: original PRIVATE source-free HUMAN input or output invalid. "
              "No authorization or verified remediation.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
