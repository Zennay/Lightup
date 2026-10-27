#!/usr/bin/env python3
"""Original HUMAN finalized Lab Review history in foreground; no activity."""
from __future__ import annotations
import lab_plan_review_console
import lab_review_history


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    rooms = [path_prompt("Original 0700 FINAL HUMAN Lab Review result round #1"),
             path_prompt("Original 0700 FINAL HUMAN Lab Review result round #2")]
    while len(rooms) < lab_review_history.MAX_ROUNDS:
        further = ask("Next original 0700 FINAL HUMAN result (blank ends)")
        if not further:
            break
        if len(further) > 4096 or any(ord(x) < 32 or ord(x) == 127 for x in further):
            print("HOLD: original HUMAN Lab review room path malformed.")
            return
        rooms.append(further)
    parent = path_prompt("Existing owner-only 0700 PRIVATE result parent", session.parent)
    folder = ask("UNUSED PRIVATE HUMAN Lab history folder", "private-lab-human-history")
    print("Source owner and ORIGINAL FINAL HUMAN rows are re-admitted for each round.")
    print("Order is chosen by an operator, NOT proven chronological source history.")
    print("Unchanged private questions are never included in the new summary.")
    print("Nothing is scanned, granted, approved, dispatched, scheduled or fixed.")
    if ask("Confirm exactly BUILD PRIVATE LAB HUMAN HISTORY", "") != "BUILD PRIVATE LAB HUMAN HISTORY":
        print("HOLD: original HUMAN Lab history not created.")
        return
    try:
        page = lab_review_history.build(packets, rooms, parent, folder)
    except Exception:
        print("HOLD: original HUMAN review sources or private output refused.")
        return
    print("PRIVATE REVIEW_ONLY: open locally " + str(page))
