#!/usr/bin/env python3
"""Foreground HUMAN multi-team lab return, using only existing native admission."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_batch
import lab_review_team_handoff


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Original 0700 finalized HUMAN Lab review room")
    handoff = path_prompt("Original 0700 owner-only HUMAN Lab team handoff room")
    count = ask("Distinct HUMAN team replies to combine (1–4)", "2")
    if count not in ("1", "2", "3", "4"):
        print("HOLD: choose 1–4 separately prepared team replies.")
        return
    replies = []
    withhold = []
    for number in range(int(count)):
        team = ask(f"Assigned team #{number+1} (Security / Privacy / Client operations / Platform)")
        if team not in lab_review_team_handoff.SLUGS or team in {x[0] for x in replies}:
            print("HOLD: original teams must be distinct and already assigned.")
            return
        reply = path_prompt(f"Completed owner-only 0600 HUMAN {team} reply CSV")
        decision = ask(f"Include {team} edits in NEW UNFINALIZED HUMAN candidate? (yes/no)", "no").lower()
        if decision not in ("yes", "no"):
            print("HOLD: choose yes or no for each returned team explicitly.")
            return
        if decision == "no":
            withhold.append(team)
        replies.append((team, reply))
    parent = path_prompt("Existing owner-only 0700 output parent", session.parent)
    folder = ask("UNUSED original-source PRIVATE multi-team draft folder",
                 "private-lab-human-multiteam-return")
    print("All original packet, FINAL, handoff and individual team CSV bytes are")
    print("re-admitted BEFORE any new output. Only matching original team rows")
    print("can change. Explicitly withheld returned teams and unreturned teams")
    print("retain ORIGINAL decisions; none is implicitly approved.")
    print("The COMPLETE HUMAN candidate must be manually reopened via option 58.")
    if ask("Type ADMIT MULTIPLE PRIVATE LAB TEAM RETURNS", "") != (
            "ADMIT MULTIPLE PRIVATE LAB TEAM RETURNS"):
        print("HOLD: multiple original HUMAN Lab team reply import cancelled.")
        return
    try:
        page = lab_review_team_batch.build(
            packets, final, handoff, replies, parent, folder,
            withhold_teams=tuple(withhold))
    except Exception:
        print("HOLD: original HUMAN team batch admission refused; no finalization.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: combined candidate, unchanged original: " + str(page))
