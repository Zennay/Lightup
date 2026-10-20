#!/usr/bin/env python3
"""Foreground, opt-in native HUMAN-only original workpack comparison."""
from __future__ import annotations

from dataclasses import replace

import private_session
import workpack_progress


def prepare(session, path_prompt, ask) -> None:
    checkpoint = path_prompt(
        "EXISTING original saved 0600 PRIVATE-SESSION.json", session.saved_session)
    first = path_prompt("Original 0700 HUMAN workpack folder 1")
    second = path_prompt("Original 0700 HUMAN workpack folder 2")
    workpacks = [first, second]
    while len(workpacks) < workpack_progress.MAX_PACKS:
        extra = ask("More original HUMAN workpack folders (empty to finish)")
        if not extra:
            break
        if (len(extra) > private_session.MAX_PATH
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in extra)):
            print("HOLD: malformed original HUMAN workpack directory.")
            return
        workpacks.append(extra)
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    name = ask("UNUSED PRIVATE HUMAN progress folder", "private-assessment-workpack-progress")
    print("This compares only 2-8 existing original owner-private workpack")
    print("snapshots against one original saved PATH-only session.")
    print("Declared dates and snapshot order are NOT authenticated chronology.")
    print("No original source bytes, file paths or HUMAN question text enter output.")
    print("The current foreground console session will NOT be changed.")
    if ask("Confirm exactly BUILD PRIVATE PROGRESS", "") != "BUILD PRIVATE PROGRESS":
        print("HOLD: no PRIVATE HUMAN progress room created.")
        return
    try:
        admitted = private_session.restore(session, checkpoint)
        isolated = replace(session, **admitted)
        isolated.saved_session = checkpoint
        page = workpack_progress.build(isolated, workpacks, parent, name)
    except (OSError, ValueError, TypeError):
        print("HOLD: original session/workpacks failed exact private admission;")
        print("no existing workpack or current foreground console was modified.")
        return
    print("PRIVATE REVIEW_ONLY: HUMAN workpack history: " + str(page))
    print("HUMAN declaration is not evidence, consent or permission to assess.")
