#!/usr/bin/env python3
"""HUMAN-only multi-packet PRIVATE offline source portfolio."""
from __future__ import annotations
import lab_plan_portfolio


def prepare(session, path_prompt, ask) -> None:
    packets = [
        path_prompt("Original owner-only 0700 lab proposal #1"),
        path_prompt("Original owner-only 0700 lab proposal #2"),
        path_prompt("Original owner-only 0700 lab proposal #3"),
    ]
    while len(packets) < lab_plan_portfolio.MAX_PACKETS:
        extra = ask("Optional original 0700 lab proposal (blank to finish)")
        if not extra:
            break
        if len(extra) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in extra):
            print("HOLD: malformed original PRIVATE lab proposal path")
            return
        packets.append(extra)
    parent = path_prompt("Existing 0700 owner-only PRIVATE portfolio parent", session.parent)
    folder = ask("UNUSED original PRIVATE lab portfolio folder",
                 "private-original-lab-portfolio")
    print("All original proposals re-admit ORIGINAL exact private bytes, scope")
    print("policy and optional Studio source. No scans, execution, network or model.")
    print("Human-selected order is not real chronology or common customer identity.")
    print("Private exact URL changes never prove a vulnerability, fix or consent.")
    if ask("Confirm exactly BUILD PRIVATE LAB PORTFOLIO", "") != "BUILD PRIVATE LAB PORTFOLIO":
        print("HOLD: no original private Lab Portfolio was published.")
        return
    try:
        page = lab_plan_portfolio.build(packets, parent, folder)
    except (OSError, ValueError, TypeError, ImportError):
        print("HOLD: original source admission or owner-private custody rejected.")
        return
    print("PRIVATE REVIEW_ONLY: source-bound lab proposal portfolio " + str(page))
