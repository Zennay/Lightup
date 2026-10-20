#!/usr/bin/env python3
"""Manual foreground saved-session continuation of original PRIVATE workpack."""
from __future__ import annotations

from dataclasses import replace
import private_session
import workpack_continue


def prepare(session, path_prompt, ask) -> None:
    checkpoint = path_prompt(
        "Original owner-only saved 0600 PRIVATE-SESSION.json", session.saved_session)
    prior = path_prompt("Original 0700 HUMAN workpack to continue")
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    declared = ask("New operator-declared HUMAN review date YYYY-MM-DD")
    name = ask("UNUSED continued PRIVATE HUMAN workpack folder",
               "private-assessment-continued")
    print("Every existing HUMAN choice is copied from the exact original")
    print("owner-private PINNED CSV. No change is made automatically.")
    print("A fresh editable browser workpack, team decks and priorities")
    print("will be generated for the new manually declared review date.")
    print("The active console and prior workpack remain unchanged.")
    if ask("Confirm exactly CONTINUE PRIVATE WORKPACK", "") != "CONTINUE PRIVATE WORKPACK":
        print("HOLD: original workpack was not continued.")
        return
    try:
        admitted = private_session.restore(session, checkpoint)
        isolated = replace(session, **admitted)
        isolated.saved_session = checkpoint
        page = workpack_continue.build(isolated, prior, parent, name, declared)
    except (OSError, ValueError, TypeError):
        print("HOLD: saved context, exact original workpack, date or owner-only")
        print("output admission refused; previous HUMAN workpacks unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: continued HUMAN workpack at " + str(page))
    print("No original findings, true calendar, consent or security GO authenticated.")
