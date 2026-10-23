#!/usr/bin/env python3
"""Reopen an explicitly resolved PRIVATE HUMAN Lab draft in the ORIGINAL Studio.

The original source-owned HUMAN Lab Review Studio remains unchanged, fully
source-bound, manual and non-authorizing. This only composes its documented
prior_room/prior_csv interface with the exact-source PRIVATE conflict result.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import lab_plans
import lab_plan_review
import lab_review_conflict_reopen as reopen
import private_session as privacy


def build(packets: list[str], final_room: str, handoff_room: str,
          original_review_room: str, root_batch: str,
          prior_continuations: tuple[str, ...],
          returns: list[tuple[str, str]], choices_room: str, resolved_room: str,
          parent: str, folder: str) -> Path:
    # Verify the new original-source HUMAN choice result without any writes.
    result = reopen.inspect(packets, final_room, handoff_room, root_batch,
                            prior_continuations, returns, choices_room, resolved_room)
    if (result["status"] != "REVIEW_ONLY"
            or result["explicitly_applied_unfinalized_proposals"] < 1):
        raise privacy.Hold("HOLD: PRIVATE HUMAN source-bound resolution not admitted")
    selected = lab_plans._packet(resolved_room)
    original = lab_plans._packet(original_review_room)
    output = lab_plans._new_path(parent, folder)
    if (original == selected or original == output or
            original in output.parents or selected in output.parents):
        raise privacy.Hold("HOLD: original HUMAN rooms may not be overwritten")
    # Original native Lab Review Studio re-admits its own original packet
    # receipt and complete 0600 prior CSV. This does not grant any authority.
    return lab_plan_review.prepare(
        packets, parent, folder, prior_room=str(original),
        prior_csv=str(selected / "PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reopen manually resolved original HUMAN Lab draft in original Studio")
    parser.add_argument("--packet", action="append", required=True)
    parser.add_argument("--original-review-room", required=True)
    parser.add_argument("--final-room", required=True)
    parser.add_argument("--handoff-room", required=True)
    parser.add_argument("--root-batch", required=True)
    parser.add_argument("--prior-continuation", action="append", default=[])
    parser.add_argument("--team-return", action="append", required=True)
    parser.add_argument("--choices-room", required=True)
    parser.add_argument("--resolved-room", required=True)
    parser.add_argument("--private-parent", required=True)
    parser.add_argument("--folder", required=True)
    parser.add_argument("--human-confirm", required=True)
    args = parser.parse_args(argv)
    try:
        if args.human_confirm != "OPEN ORIGINAL HUMAN CONFLICT REVIEW STUDIO":
            raise privacy.Hold("HOLD: original HUMAN Studio manual confirmation missing")
        returns = []
        for entry in args.team_return:
            if "=" not in entry:
                raise privacy.Hold("HOLD: original team return must be TEAM=PRIVATE_CSV")
            returns.append(tuple(entry.split("=", 1)))
        page = build(
            args.packet, args.final_room, args.handoff_room,
            args.original_review_room, args.root_batch,
            tuple(args.prior_continuation), returns, args.choices_room,
            args.resolved_room, args.private_parent, args.folder)
        print("PRIVATE REVIEW_ONLY: source-bound original HUMAN Studio prepared")
        print("OPEN LOCALLY: " + str(page))
        print("Manual original HUMAN finalization remains a separate action.")
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN source-bound Studio refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
