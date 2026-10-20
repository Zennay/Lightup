#!/usr/bin/env python3
"""Manual PRIVATE team-only worklist; requires original exact-session queue."""
from __future__ import annotations

import route_team


def prepare(session, path_prompt, ask) -> None:
    parent = path_prompt("EXISTING 0700 owner-only PRIVATE output parent", session.parent)
    source = path_prompt("Original exact-session 0600 PRIVATE-HUMAN-QUEUE.csv")
    team = ask("One team: Security / Privacy / Client operations / Platform", "")
    name = ask("UNUSED PRIVATE single-team output folder", "private-human-team-deck")
    print("This creates only that HUMAN team's proposed tasks and questions.")
    print("No original source files, local client paths or other-team notes included.")
    print("A local team label is NOT authenticated recipient identity or consent.")
    if ask("Confirm exactly BUILD PRIVATE TEAM DECK", "") != "BUILD PRIVATE TEAM DECK":
        print("HOLD: no PRIVATE team deck generated.")
        return
    try:
        page = route_team.build(session, source, team, parent, name)
    except (OSError, ValueError):
        print("HOLD: source/session/team or owner-private custody not admitted.")
        print("Existing HUMAN queue, session and client originals are unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: one-team human task deck: " + str(page))
    print("Recipient identity, allowed sharing and channel require separate HUMAN approval.")
