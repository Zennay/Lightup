#!/usr/bin/env python3
"""Guided original HUMAN Lab per-ordinal conflict reopen and Studio handoff."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_conflict_reopen
import lab_review_conflict_studio
import lab_review_team_handoff


def prepare(session, path_prompt, ask, *, open_original_studio: bool = False) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Original FINAL source-bound HUMAN Lab room")
    handoff = path_prompt("Original team handoff 0700 PRIVATE room")
    root = path_prompt("Original source-bound 0700 multi-team batch")
    rounds = ask("Previously continued ORIGINAL HUMAN Lab rooms (0–6)", "0")
    if rounds not in tuple(map(str, range(7))):
        print("HOLD: source lineage limited to six earlier HUMAN continuations.")
        return
    earlier = [path_prompt(f"Original PRIVATE HUMAN continuation #{i}")
               for i in range(1, int(rounds) + 1)]
    total = ask("New original HUMAN team returned CSVs (1–4)", "1")
    if total not in ("1", "2", "3", "4"):
        print("HOLD: choose 1–4 original HUMAN teams.")
        return
    returns = []
    for i in range(int(total)):
        team = ask(f"Original assigned HUMAN team #{i+1}")
        if team not in lab_review_team_handoff.SLUGS or team in {x[0] for x in returns}:
            print("HOLD: each returned HUMAN team must be original and distinct.")
            return
        returns.append((team, path_prompt(f"Source-bound owner-0600 {team} returned CSV")))
    choices = path_prompt("Original 0700 PRIVATE HUMAN choice preparation room")
    resolved = path_prompt("Published 0700 source-bound PRIVATE HUMAN conflict result")
    review = ""
    parent = ""
    folder = ""
    if open_original_studio:
        review = path_prompt("ORIGINAL Lab HUMAN Review Studio 0700 room")
        parent = path_prompt("Existing owner-0700 parent for new original Studio", session.parent)
        folder = ask("UNUSED new original HUMAN Review Studio folder",
                     "private-original-human-conflict-review")
    phrase = ("OPEN ORIGINAL HUMAN CONFLICT REVIEW STUDIO" if open_original_studio
              else "REOPEN ORIGINAL HUMAN CONFLICT RESOLUTION")
    print("Original packets, unchanged FINAL, team handoff, all earlier rounds,")
    print("returned team CSVs and per-ordinal decisions are re-admitted afresh.")
    print("No source is scanned or contacted; no reviewer, grant or consent inferred.")
    if ask("Type " + phrase, "") != phrase:
        print("HOLD: manual original HUMAN conflict action cancelled.")
        return
    try:
        if open_original_studio:
            page = lab_review_conflict_studio.build(
                packets, final, handoff, review, root, tuple(earlier),
                returns, choices, resolved, parent, folder)
            session.parent = parent
            print("PRIVATE REVIEW_ONLY: NEW original HUMAN Review Studio: " + str(page))
            print("Existing original FINALIZE requires separate deliberate HUMAN action.")
        else:
            result = lab_review_conflict_reopen.inspect(
                packets, final, handoff, root, tuple(earlier),
                returns, choices, resolved)
            print("PRIVATE REVIEW_ONLY: original conflict decisions source-bound.")
            print("Explicitly chosen HUMAN proposals:", result[
                "explicitly_applied_unfinalized_proposals"])
            print("No auto-finalization, security proof, consent or HUMAN GO.")
    except Exception:
        print("HOLD: original HUMAN source or private conflict decisions refused.")
