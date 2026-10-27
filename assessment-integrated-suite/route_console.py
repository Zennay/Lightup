#!/usr/bin/env python3
"""Manual-only route board for existing PRIVATE source-admitted offline pages."""
from __future__ import annotations

from dataclasses import replace
import private_session
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


def saved(session, path_prompt, ask) -> None:
    """Build from a validated older checkpoint without replacing live console."""
    source = path_prompt("Original owner-only 0600 PRIVATE-SESSION.json",
                         session.saved_session)
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE board output parent",
                         session.parent)
    name = ask("UNUSED PRIVATE saved-session route board folder",
               "private-saved-assessment-board")
    print("This reads the original 0600 path-only checkpoint with its STRICT")
    print("all-false authority and full-schema gate. It does not execute a stage")
    print("or restore ANY path into the current interactive operator console.")
    print("The resulting HTML contains local PRIVATE file: links; keep owner-only.")
    if ask("Confirm exactly BOARD SAVED SESSION", "") != "BOARD SAVED SESSION":
        print("HOLD: prior PRIVATE session not opened, board not written.")
        return
    try:
        admitted = private_session.restore(session, source)
        # The existing live dataclass is never modified. Use an isolated
        # in-memory copy for the bookmark-only availability snapshot.
        previous = replace(session, **admitted)
        page = route_board.build(previous, parent, name)
    except (OSError, ValueError, TypeError):
        print("HOLD: original source session or PRIVATE board unavailable;")
        print("current operator paths and existing private workrooms remain unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: saved operator references indexed without restore.")
    print("Open only on the SAME original trusted owner device: " + str(page))
    print("Prior paths can be stale; original source/admission and consent remain HOLD.")
