#!/usr/bin/env python3
"""Foreground HUMAN-only comparison of exact-session queue CSV revisions."""
from __future__ import annotations
import route_queue_history


def prepare(session, path_prompt, ask) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE history parent", session.parent)
    inputs = [
        path_prompt("Original owner-only 0600 HUMAN queue CSV revision 1"),
        path_prompt("Original owner-only 0600 HUMAN queue CSV revision 2"),
    ]
    while len(inputs) < 8:
        extra = ask("Another original HUMAN queue CSV (empty to finish)")
        if not extra:
            break
        if len(extra) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in extra):
            print("HOLD: invalid original CSV reference.")
            return
        inputs.append(extra)
    name = ask("UNUSED owner-private HUMAN timeline folder", "private-human-queue-history")
    print("Compare only original source-PATH-bound HUMAN task statuses, team and due.")
    print("HUMAN question TEXT and all source/private folder paths stay out of output.")
    print("Order is your declaration, not authenticated chronology.")
    if ask("Confirm exactly COMPARE PRIVATE QUEUES", "") != "COMPARE PRIVATE QUEUES":
        print("HOLD: no PRIVATE HUMAN queue history created.")
        return
    try:
        page = route_queue_history.build(session, inputs, parent, name)
    except (OSError, ValueError):
        print("HOLD: one or more original HUMAN revisions failed exact-source")
        print("or owner-private admission. All existing sessions and CSVs unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: HUMAN queue history: " + str(page))
    print("No finding, consent, security result or customer work was authenticated.")
