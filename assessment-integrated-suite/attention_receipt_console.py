#!/usr/bin/env python3
"""Foreground HUMAN-only attention receive/reopen; never run native lab assessment."""
from __future__ import annotations

import attention_receipt
import lab_route_handoff


def run(session, path_prompt, ask, mode: str) -> None:
    try:
        amount = ask("Number of original saved PRIVATE HUMAN Lab Route receipt rooms (1-8)")
        if amount not in tuple(str(i) for i in range(1, 9)):
            raise lab_route_handoff.Hold("HOLD: choose 1 to 8 original HUMAN route receipt rooms")
        rooms = [
            path_prompt("Original 0700 PRIVATE HUMAN route receipt room #" + str(index))
            for index in range(1, int(amount) + 1)
        ]
        proposal = path_prompt("Existing owner-private 0600 browser HUMAN Attention v2 JSON")
        if mode == "receive":
            parent = path_prompt("Existing owner-only 0700 destination outside checkout", session.parent)
            folder = ask("New unused PRIVATE HUMAN attention room name")
            if ask("Type RECEIVE HUMAN ATTENTION ONLY to continue") != "RECEIVE HUMAN ATTENTION ONLY":
                raise lab_route_handoff.Hold("HOLD: explicit HUMAN-only receive confirmation required")
            room = attention_receipt.receive(proposal, rooms, parent, folder)
            print("PRIVATE HUMAN Attention room: " + str(room / attention_receipt.HTML))
            print("All twenty original HUMAN roles and follow-up proposals saved 0600.")
        elif mode == "reopen":
            saved = path_prompt("Existing PRIVATE HUMAN attention output room")
            attention_receipt.reopen(proposal, rooms, saved)
            print("PRIVATE HUMAN Attention receipt reopened from all original source-free marker rounds.")
        else:
            raise lab_route_handoff.Hold("HOLD: unknown HUMAN attention console action")
        print("REVIEW_ONLY / NO SCAN, GRANT, RECIPIENT DISPATCH OR CONSENT.")
    except (lab_route_handoff.Hold, ValueError, OSError) as exc:
        print(str(exc) if isinstance(exc, lab_route_handoff.Hold)
              else "HOLD: original HUMAN Attention files or custody could not be admitted")
