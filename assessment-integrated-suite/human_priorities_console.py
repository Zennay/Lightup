#!/usr/bin/env python3
"""Manual-only PRIVATE source-bound HUMAN priorities, never a scheduler."""
from __future__ import annotations

import human_priorities


def prepare(session, path_prompt, ask) -> None:
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE output parent", session.parent)
    original = path_prompt("Exact-session original owner-only 0600 HUMAN queue CSV")
    today = path_prompt("HUMAN declared review date YYYY-MM-DD")
    name = ask("UNUSED PRIVATE priorities folder", "private-assessment-human-priorities")
    print("Creates an offline source-free HUMAN triage desk with declared-date")
    print("attention groups and human team capacity. No PRIVATE question text")
    print("or original client file paths are reproduced in summary/export.")
    print("This is not a live deadline monitor, schedule, security PASS or grant.")
    if ask("Confirm exactly BUILD PRIVATE PRIORITIES", "") != "BUILD PRIVATE PRIORITIES":
        print("HOLD: no HUMAN priority desk created.")
        return
    try:
        page = human_priorities.build(session, original, parent, name, today)
    except (OSError, ValueError):
        print("HOLD: source-PATH-bound HUMAN CSV/date/private custody refused;")
        print("current console, original files and earlier HUMAN CSV unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: offline HUMAN priorities: " + str(page))
    print("No actual calendar events, customer contacts or targets modified.")
