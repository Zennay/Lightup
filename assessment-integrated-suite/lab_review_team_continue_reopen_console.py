#!/usr/bin/env python3
"""Read-only foreground HUMAN Lab source and continuation-chain reopen."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_continue_reopen


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Unchanged original FINAL HUMAN Lab 0700 room")
    handoff = path_prompt("Original assigned-team HUMAN handoff 0700 room")
    root = path_prompt("Original source-bound 0700 HUMAN multi-team batch room")
    rounds = ask("Earlier PRIVATE continuation rooms in the chain (0–6)", "0")
    if rounds not in tuple(map(str, range(7))):
        print("HOLD: at most six distinct earlier original continuations.")
        return
    prior = [
        path_prompt(f"Earlier original PRIVATE HUMAN continuation #{i}")
        for i in range(1, int(rounds) + 1)
    ]
    current = path_prompt("Existing 0700 current PRIVATE HUMAN continuation to reopen")
    print("READ ONLY: every earlier original batch/continuation is re-admitted.")
    print("Private 0600 full HUMAN CSVs, original source ordinal decisions and")
    print("unsigned local byte receipts must agree. No source can be skipped.")
    if ask("Type REOPEN PRIVATE LAB HUMAN CONTINUATION", "") != (
            "REOPEN PRIVATE LAB HUMAN CONTINUATION"):
        print("HOLD: original HUMAN chain reopen cancelled.")
        return
    try:
        result = lab_review_team_continue_reopen.inspect(
            packets, final, handoff, root, current,
            prior_continuations=tuple(prior))
    except Exception:
        print("HOLD: original HUMAN source, chain or current PRIVATE files disagree.")
        return
    print("PRIVATE REVIEW_ONLY: complete original HUMAN chain admitted.")
    print("New original HUMAN team replies:", result["new_team_replies"])
    print("Source-bound conflicts withheld:", result["conflict_withheld_team_replies"])
    print("Unfinalized new accepted changes:", result["changed_original_proposals"])
    print("No identity proof, client/operator consent, grant, scan or HUMAN GO.")
