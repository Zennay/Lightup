#!/usr/bin/env python3
"""Interactive local HUMAN-only original attention revision choices, no authority."""
from __future__ import annotations
import attention_decision as decision
import lab_route_handoff as original


def _paths(ask, path_prompt, prompt, label, smallest, largest):
    chosen = ask(prompt)
    if chosen not in [str(v) for v in range(smallest, largest + 1)]:
        raise original.Hold("HOLD: original PRIVATE input count outside allowed range")
    return [
        path_prompt(label + " #" + str(i))
        for i in range(1, int(chosen) + 1)
    ]


def run(session, path_prompt, ask, mode: str) -> None:
    try:
        routes = _paths(ask, path_prompt, "Original PRIVATE Lab Route room count (1–8)",
                        "Original Lab Route PRIVATE receipt room", 1, 8)
        attention = _paths(ask, path_prompt, "Original Attention revision count (2–8)",
                           "Original saved HUMAN Attention receipt", 2, 8)
        history = path_prompt("Exact original saved HUMAN Attention revision portfolio room")
        choices = path_prompt(
            "Existing 0600 edited copy of HUMAN selection CSV (not inside original portfolio)"
        )
        if mode == "create":
            parent = path_prompt("Existing owner-only 0700 output parent", session.parent)
            folder = ask("New unused PRIVATE HUMAN continuation room name")
            if ask("Type CREATE HUMAN SELECTION ONLY") != "CREATE HUMAN SELECTION ONLY":
                raise original.Hold("HOLD: HUMAN did not explicitly request a new source-free choice draft")
            target = decision.create(routes, attention, history, choices, parent, folder)
            print("NEW source-free HUMAN v2 draft: " + str(target / decision.NEXT))
            print("Offline scriptless HUMAN selection page: " + str(target / decision.VIEW))
        elif mode == "reopen":
            output = path_prompt("Previously saved PRIVATE HUMAN selection output room")
            decision.reopen(routes, attention, history, choices, output)
            print("All original HUMAN choice inputs and complete output bytes re-admitted.")
        else:
            raise original.Hold("HOLD: unsupported PRIVATE HUMAN decision")
        print("REVIEW_ONLY · proposed categories only. No real owner, execution or consent.")
    except (original.Hold, ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, original.Hold)
              else "HOLD: original HUMAN selection could not be admitted")
