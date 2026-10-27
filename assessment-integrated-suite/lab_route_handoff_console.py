#!/usr/bin/env python3
"""Interactive PRIVATE HUMAN discussion transfer; never executes a lab action."""
from __future__ import annotations

import lab_route_handoff as handoff


def _report(target: str, message: str) -> None:
    print(message)
    print("OPEN LOCALLY: " + target)


def run(session, path_prompt, ask, mode: str) -> None:
    """Additive original console companion; no existing options are changed."""
    try:
        if mode == "receive":
            print("HUMAN-only original offline Lab self-report import; NOT source admission.")
            source = path_prompt("Existing browser self-report JSON (copy to 0700 / 0600 first)")
            parent = path_prompt("Existing 0700 owner-private output parent", session.parent)
            folder = ask("New PRIVATE receipt folder name")
            if ask("Type RECEIVE HUMAN SELF REPORT to proceed") != "RECEIVE HUMAN SELF REPORT":
                raise handoff.Hold("HOLD: no explicit HUMAN self-report receive confirmation")
            new = handoff.receive(source, parent, folder)
            _report(str(new / handoff.HTML), "PRIVATE REVIEW_ONLY: received self-report, all authority false.")
        elif mode == "reopen":
            room = path_prompt("Existing original PRIVATE HUMAN route receipt room")
            states = handoff.reopen(room)
            print("PRIVATE REVIEW_ONLY: exact original self-report and outputs unchanged.")
            print("Self-reported DISCUSSED only: " + str(states.count("DISCUSSED")))
            print("This is NOT proof of any original assessment or authorization.")
        elif mode == "history":
            amount = ask("Number of manually ordered original HUMAN receipt rooms (2-8)")
            if amount not in tuple(str(n) for n in range(2, 9)):
                raise handoff.Hold("HOLD: select 2 to 8 original receipt rooms")
            sources = [
                path_prompt("PRIVATE HUMAN receipt room #" + str(n))
                for n in range(1, int(amount) + 1)
            ]
            parent = path_prompt("Existing 0700 owner-private history parent", session.parent)
            folder = ask("New PRIVATE history folder name")
            if ask("Type BUILD HUMAN ROUTE HISTORY to proceed") != "BUILD HUMAN ROUTE HISTORY":
                raise handoff.Hold("HOLD: no explicit HUMAN discussion history confirmation")
            new = handoff.history(sources, parent, folder)
            _report(str(new / "OPEN-PRIVATE.html"),
                    "PRIVATE REVIEW_ONLY: manual-order HUMAN changes; not verified fixes.")
        elif mode == "reopen_history":
            amount = ask("Number of original human review rooms (2-8)")
            if amount not in tuple(str(n) for n in range(2, 9)):
                raise handoff.Hold("HOLD: select 2 to 8 original receipt rooms")
            sources = [
                path_prompt("Original PRIVATE HUMAN receipt room #" + str(n))
                for n in range(1, int(amount) + 1)
            ]
            original_history = path_prompt("Existing PRIVATE HUMAN history output room")
            handoff.reopen_history(sources, original_history)
            print("PRIVATE REVIEW_ONLY: original source-free HUMAN history fully re-admitted.")
            print("Original HUMAN changes do NOT authorize a scan or verify a fix.")
        else:
            raise handoff.Hold("HOLD: unknown PRIVATE HUMAN route activity")
    except (handoff.Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, handoff.Hold)
              else "HOLD: PRIVATE route input cannot be admitted")
