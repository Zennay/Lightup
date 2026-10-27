#!/usr/bin/env python3
"""PRIVATE operator-driven continuation of earlier original HUMAN Lab decisions."""
from __future__ import annotations

import lab_plan_review_console
import lab_review_team_continue
import lab_review_team_handoff


def prepare(session, path_prompt, ask) -> None:
    packets = lab_plan_review_console._packets(path_prompt, ask)
    if packets is None:
        return
    final = path_prompt("Original 0700 FINAL HUMAN Lab review")
    handoff = path_prompt("Original 0700 source-bound HUMAN team handoff")
    prior = path_prompt("Previously saved 0700 original HUMAN team BATCH")
    rounds = ask("Existing additional HUMAN continuation rooms to retain (0–6)", "0")
    if rounds not in tuple(map(str, range(7))):
        print("HOLD: choose at most six previous privately saved HUMAN rounds.")
        return
    prior_continuations = [
        path_prompt(f"Existing source-bound PRIVATE continuation #{i} (oldest first)")
        for i in range(1, int(rounds) + 1)
    ]
    count = ask("Distinct newly returned HUMAN teams (1–4)", "1")
    if count not in ("1", "2", "3", "4"):
        print("HOLD: provide 1–4 distinct returned HUMAN teams.")
        return
    replies, withheld = [], []
    for i in range(int(count)):
        name = ask(f"Original assigned team #{i+1} (Security / Privacy / Client operations / Platform)")
        if name not in lab_review_team_handoff.SLUGS or name in {x[0] for x in replies}:
            print("HOLD: each new reply must match a distinct original assigned team.")
            return
        path = path_prompt(f"Completed private 0600 {name} reply CSV")
        include = ask(f"Adopt {name} only if NO overlap with earlier HUMAN decisions? (yes/no)", "no").lower()
        if include not in ("yes", "no"):
            print("HOLD: choose yes or no for each HUMAN team.")
            return
        if include == "no":
            withheld.append(name)
        replies.append((name, path))
    parent = path_prompt("Existing original owner-only 0700 output parent", session.parent)
    folder = ask("UNUSED PRIVATE original Lab HUMAN continuation folder",
                 "private-lab-human-continuation")
    print("Existing original FINAL, prior source-bound batch and all new source")
    print("replies are re-admitted before creation. Any overlapping newer HUMAN")
    print("reply is withheld for that WHOLE team, even when marked yes.")
    print("The earlier completed PRIVATE room and FINAL remain unchanged.")
    print("New seven-column HUMAN candidate still needs original Studio review.")
    if ask("Type CONTINUE PRIVATE LAB HUMAN BATCH", "") != (
            "CONTINUE PRIVATE LAB HUMAN BATCH"):
        print("HOLD: previous HUMAN decisions remain unchanged.")
        return
    try:
        page = lab_review_team_continue.build(
            packets, final, handoff, prior, replies, parent, folder,
            withhold_teams=tuple(withheld),
            prior_continuations=tuple(prior_continuations))
    except Exception:
        print("HOLD: original HUMAN continuation source or custody refused.")
        return
    session.parent = parent
    print("PRIVATE REVIEW_ONLY: new unfinalized human continuation: " + str(page))
