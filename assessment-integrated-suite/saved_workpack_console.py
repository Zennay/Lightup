#!/usr/bin/env python3
"""Restore original saved HUMAN workpack context, never current console."""
from __future__ import annotations

from dataclasses import replace

import human_workpack
import private_session


def prepare(session, path_prompt, ask) -> None:
    checkpoint = path_prompt("EXISTING original owner-only 0600 PRIVATE-SESSION.json",
                             session.saved_session)
    csv_file = path_prompt("OPTIONAL matching 0600 HUMAN CSV (blank = NEW unassessed)")
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE output parent", session.parent)
    review_date = ask("Declared HUMAN review date YYYY-MM-DD")
    name = ask("UNUSED saved-context HUMAN workpack folder",
               "private-resumed-assessment-workpack")
    print("The original strict 0600 saved PATH-only session is restored ONLY")
    print("into a separate in-memory copy; current console paths stay unchanged.")
    print("Blank CSV seeds UNASSESSED choices from the restored session.")
    print("Provided original CSV must still match the exact saved PATH digest.")
    print("This rebuilds original browser Studio, declared-date priorities,")
    print("and private assigned-team-only task decks; no client source is read.")
    if ask("Confirm exactly RESUME PRIVATE WORKPACK", "") != "RESUME PRIVATE WORKPACK":
        print("HOLD: no saved session opened and no HUMAN workpack created.")
        return
    try:
        admitted = private_session.restore(session, checkpoint)
        isolated = replace(session, **admitted)
        # This is the same native restore-post-state used by menu 38:
        # source PATH-only session JSON omits the newly allocated path to
        # its own manifest, while original post-save queue includes it.
        isolated.saved_session = checkpoint
        page = human_workpack.build(isolated, csv_file, parent, name, review_date)
    except (OSError, ValueError, TypeError):
        print("HOLD: original saved source-PATH checkpoint, matching HUMAN CSV")
        print("or PRIVATE local custody refused; current console is unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: saved-session HUMAN workpack: " + str(page))
    print("All originals and the current console remain unchanged.")
    print("Current separate HUMAN/client approvals and action consent remain HOLD.")
