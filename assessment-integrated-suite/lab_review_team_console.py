#!/usr/bin/env python3
"""Private original HUMAN Lab Review team decks, manual foreground only."""
from __future__ import annotations
import lab_plan_review_console
import lab_review_team_handoff


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Existing 0700 original FINAL HUMAN Lab Review result")
    parent = path_prompt("Existing owner-only 0700 PRIVATE team room parent", session.parent)
    folder = ask("UNUSED PRIVATE original HUMAN Lab team handoff name",
                 "private-lab-human-team-handoff")
    print("Re-admit ALL original Lab Launchpad source packets before publishing.")
    print("Each PRIVATE team-only HTML contains ONLY manually assigned packet slots.")
    print("Original URLs and other teams' questions are NOT copied into that team file.")
    print("No recipient is authenticated; no private package is dispatched.")
    print("No scan, client grant, assessment authority, review GO or model runs.")
    if ask("Confirm exactly BUILD PRIVATE LAB TEAM HANDOFF", "") != "BUILD PRIVATE LAB TEAM HANDOFF":
        print("HOLD: no PRIVATE Lab HUMAN team workrooms published.")
        return
    try:
        page = lab_review_team_handoff.build(packets, final, parent, folder)
    except Exception:
        print("HOLD: original source/FINAL HUMAN receipt or owner-only custody refused.")
        return
    print("PRIVATE REVIEW_ONLY: original HUMAN Lab team handoff: " + str(page))
