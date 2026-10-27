#!/usr/bin/env python3
"""Resume a PRIVATE HUMAN work queue from an original owner-only checkpoint.

Never modify the caller's active console Session. The saved PATH-only
checkpoint is verified by the unchanged original strict native reader.
"""
from __future__ import annotations

from dataclasses import replace
import private_session
import route_queue


def prepare(session, path_prompt, ask) -> None:
    checkpoint = path_prompt(
        "EXISTING original 0600 PRIVATE-SESSION.json", session.saved_session)
    choice = ask("Resume an existing exact-checkpoint HUMAN CSV? (yes/no)", "yes").lower()
    if choice not in ("yes", "no"):
        print("HOLD: choose yes or no. No saved session opened.")
        return
    original_csv = ""
    if choice == "yes":
        original_csv = path_prompt(
            "EXISTING owner-only 0600 HUMAN CSV from this exact saved session")
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    name = ask("UNUSED resumed PRIVATE HUMAN queue folder", "private-human-queue-resumed")
    print("An original strictly admitted 0600 PATH-only saved session is copied")
    print("into an ISOLATED in-memory view; your live console paths are NOT changed.")
    print("If provided, the HUMAN CSV must match all saved original workflow keys")
    print("and the exact prior PATH digest. No original client source is opened.")
    print("No recipient is contacted and no grant, scan or calendar action occurs.")
    if ask("Confirm exactly RESUME PRIVATE HUMAN QUEUE", "") != "RESUME PRIVATE HUMAN QUEUE":
        print("HOLD: no prior PRIVATE session opened and no new workroom written.")
        return
    try:
        restored_paths = private_session.restore(session, checkpoint)
        # Replicate the original save/restore console semantics: after
        # a saved session is restored, it names its current 0600 manifest.
        # Never mutate caller's existing session or original checkpoint.
        isolated = replace(session, **restored_paths)
        isolated.saved_session = checkpoint
        page = route_queue.build(
            isolated, parent, name, imported_csv=original_csv)
    except (OSError, ValueError, TypeError):
        print("HOLD: original saved checkpoint/CSV/path binding or owner-private")
        print("output admission refused; no current session or source was changed.")
        return
    print("PRIVATE REVIEW_ONLY: resumed owner-private HUMAN Studio: " + str(page))
    print("Original readonly fallback: " + str(page.parent / "PRIVATE-READONLY.html"))
    print("Original CSV and saved session remain unchanged. Browser export")
    print("still needs explicit owner-only 0700/0600 custody before native import.")
