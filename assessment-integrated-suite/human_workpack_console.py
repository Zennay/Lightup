#!/usr/bin/env python3
"""Explicit manual full PRIVATE HUMAN workpack composition."""
from __future__ import annotations

import human_workpack


def prepare(session, path_prompt, ask) -> None:
    source = path_prompt("OPTIONAL original 0600 HUMAN queue CSV (blank = NEW all-UNASSESSED)")
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE output parent",
                         session.parent)
    review_date = ask("Operator-declared review date YYYY-MM-DD")
    name = ask("UNUSED PRIVATE integrated HUMAN workpack folder",
               "private-human-assessment-workpack")
    print("One PRIVATE local index will compose original queue editor,")
    print("source-free priorities and assigned-team-only HUMAN worklists.")
    print("Blank CSV seeds an all-UNASSESSED HUMAN queue from current paths.")
    print("Existing original CSV still requires exact native PATH binding.")
    print("No original lab data, client login, scan, model, grant, review")
    print("approval, recipient dispatch or real calendar action is performed.")
    print("The original current console Session remains UNCHANGED.")
    if ask("Confirm exactly BUILD PRIVATE WORKPACK", "") != "BUILD PRIVATE WORKPACK":
        print("HOLD: no integrated PRIVATE HUMAN workpack created.")
        return
    try:
        page = human_workpack.build(session, source, parent, name, review_date)
    except (OSError, ValueError):
        print("HOLD: original HUMAN CSV, source-PATH binding or PRIVATE")
        print("workpack assembly refused. Existing originals stay unchanged.")
        return
    print("PRIVATE REVIEW_ONLY: open only on original trusted local device:")
    print(str(page))
    print("No recipient, authorization, consent or security result was verified.")
