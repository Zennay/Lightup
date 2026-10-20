#!/usr/bin/env python3
"""Foreground PRIVATE original Lab HUMAN team batch history; never launches activity."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_batch_history


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Unchanged original 0700 FINAL HUMAN Lab review")
    handoff = path_prompt("Same original 0700 HUMAN team handoff room")
    count = ask("Number of existing PRIVATE HUMAN team batch rounds (2–8)", "2")
    if count not in tuple(map(str, range(2, 9))):
        print("HOLD: exactly 2–8 operator-ordered original batches required.")
        return
    rounds = [path_prompt(f"Original 0700 HUMAN team batch round #{i}")
              for i in range(1, int(count) + 1)]
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    folder = ask("UNUSED original source-bound HUMAN history folder",
                 "private-lab-human-multiteam-history")
    print("This compares only SOURCE-RECHECKED saved UNFINALIZED HUMAN proposals.")
    print("Dates, people and actual incident resolutions are NOT inferred.")
    print("No PRIVATE question texts enter summary HTML/JSON/CSV.")
    if ask("Type BUILD PRIVATE LAB TEAM BATCH HISTORY", "") != (
            "BUILD PRIVATE LAB TEAM BATCH HISTORY"):
        print("HOLD: original HUMAN history not created.")
        return
    try:
        page = lab_review_team_batch_history.build(
            packets, final, handoff, rounds, parent, folder)
    except Exception:
        print("HOLD: original saved HUMAN Lab batch history source refused.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: source-bound HUMAN team history created: " + str(page))
