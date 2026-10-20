#!/usr/bin/env python3
"""Foreground PRIVATE original lab proposal HUMAN decisions; no authority."""
from __future__ import annotations

import lab_plan_review


def _packets(path_prompt, ask) -> list[str] | None:
    selected = [
        path_prompt("Original 0700 Lab Launchpad packet #1"),
        path_prompt("Original 0700 Lab Launchpad packet #2"),
        path_prompt("Original 0700 Lab Launchpad packet #3"),
    ]
    while len(selected) < 8:
        candidate = ask("Additional original private Lab Launchpad packet (blank ends)")
        if not candidate:
            break
        if len(candidate) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in candidate):
            print("HOLD: invalid original lab packet path.")
            return None
        selected.append(candidate)
    return selected


def prepare(session, path_prompt, ask) -> None:
    packets = _packets(path_prompt, ask)
    if packets is None:
        return
    parent = path_prompt("Existing 0700 owner-private Lab HUMAN Studio parent", session.parent)
    folder = ask("UNUSED private Lab HUMAN Studio name", "private-original-lab-human-review")
    print("Build a source-bound PRIVATE HUMAN review editor from original packet bytes.")
    print("No source approvals, scans, models, network, grants or automated decisions.")
    print("Browser CSV must be moved to genuine owner-only 0700/0600 custody.")
    if ask("Confirm exactly PREPARE PRIVATE LAB HUMAN REVIEW", "") != "PREPARE PRIVATE LAB HUMAN REVIEW":
        print("HOLD: no original PRIVATE HUMAN Lab Review prepared.")
        return
    try:
        page = lab_plan_review.prepare(packets, parent, folder)
    except Exception:
        print("HOLD: original source binding or private Lab Review publishing refused.")
        return
    print("PRIVATE REVIEW_ONLY: original HUMAN Lab Review Studio: " + str(page))


def finalize(session, path_prompt, ask) -> None:
    packets = _packets(path_prompt, ask)
    if packets is None:
        return
    studio = path_prompt("Original 0700 HUMAN Lab Review Studio workroom")
    decisions = path_prompt("Completed 0600 original-bound HUMAN Lab Review CSV")
    parent = path_prompt("Existing 0700 PRIVATE FINAL HUMAN workroom parent", session.parent)
    name = ask("UNUSED original PRIVATE HUMAN review result name",
               "private-original-lab-human-final")
    print("Native ORIGINAL lab packet policy is re-admitted for ALL sources.")
    print("Exact source identity and HUMAN CSV row order must match original Studio.")
    print("No decision can set PASS, scan authority, current permission or release.")
    if ask("Confirm exactly FINALIZE PRIVATE LAB HUMAN REVIEW", "") != "FINALIZE PRIVATE LAB HUMAN REVIEW":
        print("HOLD: original PRIVATE HUMAN Lab Review remains unfinished.")
        return
    try:
        page = lab_plan_review.finalize(packets, studio, decisions, parent, name)
    except Exception:
        print("HOLD: changed original source, HUMAN CSV, or private room refused.")
        return
    print("PRIVATE REVIEW_ONLY: original HUMAN lab review: " + str(page))
