#!/usr/bin/env python3
"""Foreground original PRIVATE HUMAN batch reopen, no work or approval triggered."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_batch_reopen


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Exact original 0700 FINAL HUMAN Lab review")
    handoff = path_prompt("Same original 0700 HUMAN team handoff room")
    batch = path_prompt("Existing 0700 PRIVATE HUMAN multi-team batch room")
    print("READ ONLY: original source packets, finalized HUMAN Lab rows, original")
    print("team manifest and all saved 0600 candidate/overview/diff file bytes")
    print("will be re-admitted; a SHA is an unsigned consistency marker only.")
    if ask("Type REOPEN ORIGINAL PRIVATE LAB TEAM BATCH", "") != (
            "REOPEN ORIGINAL PRIVATE LAB TEAM BATCH"):
        print("HOLD: original Lab HUMAN batch reopen cancelled.")
        return
    try:
        outcome = lab_review_team_batch_reopen.inspect(packets, final, handoff, batch)
    except Exception:
        print("HOLD: current original source and PRIVATE HUMAN batch disagree.")
        return
    print("PRIVATE REVIEW_ONLY: original source and local batch files admitted.")
    print("Adopted HUMAN team drafts:", outcome["teams_adopted_as_unfinalized_draft"])
    print("Withheld returned HUMAN teams:", outcome["teams_withheld_for_human_review"])
    print("Teams without a response:", outcome["teams_without_reply"])
    print("Changed original HUMAN proposal positions:", outcome["human_candidate_changes"])
    print("No consent, security proof, scan, grant, release, or authenticated actor.")
