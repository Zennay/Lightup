#!/usr/bin/env python3
"""Foreground HUMAN-only CSV work queue capture and strict manual re-import."""
from __future__ import annotations

import route_queue


def create(session, path_prompt, ask) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    name = ask("UNUSED PRIVATE HUMAN work queue folder", "private-assessment-human-queue")
    print("Builds owner-private HTML plus exact-session-bound CSV for manual HUMAN edits.")
    print("No current workflow is automatically approved, assigned or executed.")
    if ask("Confirm exactly PREPARE HUMAN QUEUE", "") != "PREPARE HUMAN QUEUE":
        print("HOLD: no HUMAN queue was created.")
        return
    try:
        page = route_queue.build(session, parent, name)
    except (OSError, ValueError):
        print("HOLD: PRIVATE HUMAN queue not created; original sessions unchanged.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: HUMAN CSV and HTML created in: " + str(page.parent))
    print("Edit the owner-only 0600 PRIVATE-HUMAN-QUEUE.csv MANUALLY.")
    print("Use menu 43 with the same unmodified session path references to reopen.")


def reopen(session, path_prompt, ask) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    csv_file = path_prompt("MANUALLY completed owner-only 0600 PRIVATE-HUMAN-QUEUE.csv")
    name = ask("UNUSED folder for new HUMAN queue revision", "private-human-queue-revision")
    print("Exact session-path digest, workflow keys/order, HUMAN team, stage,")
    print("valid calendar dates and question strings are strictly re-admitted.")
    print("This does NOT re-admit original lab bytes or authenticate a reviewer.")
    if ask("Confirm exactly REOPEN HUMAN QUEUE", "") != "REOPEN HUMAN QUEUE":
        print("HOLD: HUMAN queue was not reopened.")
        return
    try:
        page = route_queue.build(session, parent, name, imported_csv=csv_file)
    except (OSError, ValueError):
        print("HOLD: HUMAN CSV/session drift or PRIVATE custody mismatch.")
        print("No original, current console session or existing CSV was modified.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: source-free HUMAN revision created: " + str(page))
    print("All HUMAN statuses remain unauthenticated and non-authorizing.")
