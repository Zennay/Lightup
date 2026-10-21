#!/usr/bin/env python3
"""Interactive source-bound HUMAN Attention revision portfolio, OFFLINE/REVIEW_ONLY."""
from __future__ import annotations

import attention_history as history
import lab_route_handoff as original


def _paths(ask, path_prompt, amount_prompt: str, label: str, minimum: int, maximum: int):
    number = ask(amount_prompt)
    if number not in tuple(str(n) for n in range(minimum, maximum + 1)):
        raise original.Hold("HOLD: invalid bounded original PRIVATE room count")
    return [path_prompt(label + " #" + str(i)) for i in range(1, int(number) + 1)]


def run(session, path_prompt, ask, mode: str) -> None:
    try:
        route_rooms = _paths(
            ask, path_prompt, "Original route self-report receipt count (1–8)",
            "Original PRIVATE HUMAN Lab Route receipt", 1, 8,
        )
        attention_rooms = _paths(
            ask, path_prompt, "Original saved attention revision count (2–8)",
            "Original PRIVATE HUMAN Attention receipt revision (manual order)", 2, 8,
        )
        if mode == "create":
            parent = path_prompt("Existing 0700 PRIVATE output parent", session.parent)
            name = ask("New unused PRIVATE Attention revision portfolio folder name")
            if ask("Type CREATE HUMAN REVISION PORTFOLIO to proceed") != "CREATE HUMAN REVISION PORTFOLIO":
                raise original.Hold("HOLD: explicit HUMAN-only revision confirmation is required")
            folder = history.create(route_rooms, attention_rooms, parent, name)
            print("Original PRIVATE HUMAN Attention revisions: " + str(folder / history.VIEWER))
            print("A local grouped stage view, full twenty-row matrix and changes CSV are ready.")
        elif mode == "reopen":
            room = path_prompt("Previously saved original PRIVATE HUMAN Attention revision portfolio")
            history.reopen(route_rooms, attention_rooms, room)
            print("Exact ORIGINAL HUMAN Attention revision inputs and outputs reopened read-only.")
        else:
            raise original.Hold("HOLD: unknown native HUMAN attention revision action")
        print("REVIEW_ONLY · original HUMAN markers, not real owners, timing, scans or consent.")
    except (original.Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, original.Hold)
              else "HOLD: original PRIVATE HUMAN Attention revisions could not be admitted")
