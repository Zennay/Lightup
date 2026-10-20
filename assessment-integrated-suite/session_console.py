#!/usr/bin/env python3
"""Foreground owner-private LightUp console save/reopen without any target action."""
from __future__ import annotations
from pathlib import Path
import private_session


def save(session, path_prompt, ask) -> None:
    parent = path_prompt("EXISTING owner-only 0700 PRIVATE workroom parent", session.parent)
    prefix = ask("UNUSED owner-private workroom name", "private-operator-workspace")
    print("This will save local path references only, NOT client evidence, passwords, notes,")
    print("source bytes, authenticated identity, session tokens or external connections.")
    print("Paths and local folder names remain sensitive. Keep the 0600 JSON PRIVATE.")
    print("The static HTML launcher contains links to existing PRIVATE local pages only.")
    if ask("Confirm exactly SAVE PRIVATE", "") != "SAVE PRIVATE":
        print("HOLD: no PRIVATE operator workspace saved.")
        return
    try:
        manifest, page = private_session.save(session, parent, prefix)
        session.saved_session = str(manifest)
        session.parent = parent
        print("PRIVATE REVIEW_ONLY: original path-only operator session saved.")
        print("Resume next time from PRIVATE-SESSION.json: " + str(manifest))
        print("Open offline, on the same trusted device: " + str(page))
        print("Saved links never authorize a scan or release.")
    except (OSError, ValueError):
        print("HOLD: original PRIVATE operator session could not be exclusively saved.")


def reopen(session, path_prompt, ask) -> None:
    target = path_prompt("Existing owner-only 0600 PRIVATE-SESSION.json", session.saved_session)
    print("HUMAN-only restore will replace CURRENT CONSOLE PATH REFERENCES.")
    print("It does NOT open the source files, re-admit client data, scan targets,")
    print("authenticate clients/reviewers, resume operations or approve a release.")
    if ask("Confirm exactly RESTORE PRIVATE", "") != "RESTORE PRIVATE":
        print("HOLD: existing session unchanged.")
        return
    try:
        new_paths = private_session.restore(session, target)
        # Strict full schema was admitted before ANY field changes.
        for field, value in new_paths.items():
            setattr(session, field, value)
        session.saved_session = target
        print("PRIVATE REVIEW_ONLY: " + str(len(new_paths)) + " path references restored.")
        print("Files, permissions, source bytes and HUMAN decisions still need native checks")
        print("when their individual source workflows are explicitly started.")
        print("This is NOT authorization or consent.")
    except (OSError, ValueError):
        print("HOLD: original private path-only session unavailable or changed;")
        print("existing console session was NOT replaced.")
