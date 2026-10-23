#!/usr/bin/env python3
"""Foreground original source-bound PRIVATE HUMAN Lab team feedback, no grants."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_return
import lab_review_team_handoff


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Original 0700 FINAL HUMAN Lab Review result")
    handoff = path_prompt("Original 0700 PRIVATE HUMAN Lab TEAM handoff room")
    team = ask("Exact selected HUMAN team (Security / Privacy / Client operations / Platform)")
    if team not in lab_review_team_handoff.SLUGS:
        print("HOLD: select exactly one original assigned team.")
        return
    response = path_prompt("Original completed 0600 private team draft CSV")
    parent = path_prompt("Existing 0700 owner-only PRIVATE output parent", session.parent)
    folder = ask("UNUSED source-bound PRIVATE HUMAN team return folder",
                 "private-lab-human-team-return")
    print("All original Lab Launchpad packet bytes/Studio identities and the")
    print("original FINAL HUMAN CSV will be re-admitted before accepting a return.")
    print("Only selected TEAM stage/questions are allowed to change; no team switch.")
    print("A new full HUMAN draft CSV is prepared for manual Studio review (option 58).")
    print("No scans, grant, credentials, sender/recipient authenticity or GO.")
    if ask("Confirm exactly ADMIT PRIVATE LAB TEAM RETURN", "") != "ADMIT PRIVATE LAB TEAM RETURN":
        print("HOLD: original PRIVATE team return was not admitted.")
        return
    try:
        page = lab_review_team_return.build(
            packets, final, handoff, team, response, parent, folder)
    except Exception:
        print("HOLD: original team source/receipt or response content refused.")
        return
    print("PRIVATE REVIEW_ONLY: team candidate prepared, NOT finalized: " + str(page))
