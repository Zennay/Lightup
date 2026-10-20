#!/usr/bin/env python3
"""Manual-only route board for existing PRIVATE source-admitted offline pages."""
from __future__ import annotations

import route_board


def prepare(session, path_prompt, ask) -> None:
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE output parent", session.parent)
    name = ask("UNUSED PRIVATE route-board folder", "private-assessment-route-board")
    print("The board only locates existing owner-private original HTML entry pages.")
    print("Its PRIVATE file: bookmarks may disclose local directory names.")
    print("It does not examine customer data, resume work, verify HUMAN review,")
    print("schedule anything, grant authority, certify findings or distribute files.")
    print("No scan, model, targets, source validation, deletions or background jobs.")
    if ask("Confirm exactly BUILD PRIVATE BOARD", "") != "BUILD PRIVATE BOARD":
        print("HOLD: no PRIVATE board was written.")
        return
    try:
        page = route_board.build(session, parent, name)
    except (OSError, ValueError):
        print("HOLD: private owner-only board not admitted. No other work changed.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: original local workrooms indexed.")
    print("Open offline on the original trusted owner device: " + str(page))
    print("No individual source, identity, authorization or consent was revalidated.")
