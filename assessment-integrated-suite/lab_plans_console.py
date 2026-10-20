#!/usr/bin/env python3
"""Foreground PRIVATE original Lab Launchpad human planning choices."""
from __future__ import annotations

import lab_plans


def prepare(session, path_prompt, ask) -> None:
    parent = path_prompt("Existing 0700 owner-PRIVATE lab plan parent", session.parent)
    target = path_prompt("Original 0600 numeric isolated-lab URL manifest")
    studio = ask("Optional original 0600 Studio v1 catalog JSON (blank means none)")
    scenario = ask("Exact selected Studio scenario ID (paired with Studio catalog)") if studio else ""
    name = ask("UNUSED original PRIVATE lab plan folder", "private-lab-plan")
    print("Original unchanged Lab Launchpad admission will prepare OFFLINE source files.")
    print("No scanner, target, provider, model, network, or grant will be called.")
    print("The original required action-time authorization is NOT established by this.")
    if ask("Confirm exactly PREPARE PRIVATE LAB PLAN", "") != "PREPARE PRIVATE LAB PLAN":
        print("HOLD: original lab plan was not prepared.")
        return
    try:
        page = lab_plans.prepare(parent, name, target, studio, scenario)
    except (OSError, ValueError, TypeError):
        print("HOLD: original owner-private Lab Launchpad preparation rejected.")
        return
    print("PRIVATE REVIEW_ONLY: original Lab Launchpad: " + str(page))


def reopen(session, path_prompt, ask) -> None:
    packet = path_prompt("Existing original 0700 PRIVATE lab proposal")
    print("The original owner reader re-admits only original UNSIGNED local bytes.")
    print("Only local file consistency, original lab scope and Studio source membership.")
    print("No target is contacted; no genuine permission or remediation is verified.")
    if ask("Confirm exactly REOPEN PRIVATE LAB PLAN", "") != "REOPEN PRIVATE LAB PLAN":
        print("HOLD: original lab proposal not read.")
        return
    try:
        page = lab_plans.reopen(packet)
    except (OSError, ValueError, TypeError):
        print("HOLD: original lab proposal could not be re-admitted.")
        return
    print("PRIVATE REVIEW_ONLY: original Lab Launchpad: " + str(page))


def compare(session, path_prompt, ask) -> None:
    before = path_prompt("Earlier original 0700 PRIVATE lab proposal")
    after = path_prompt("Later original 0700 PRIVATE lab proposal")
    parent = path_prompt("Existing owner-only 0700 PRIVATE result parent", session.parent)
    folder = ask("UNUSED PRIVATE source revision room", "private-lab-plan-changes")
    print("Original source-owning revision reader admits BOTH original packets.")
    print("Endpoint added/absent are manually declared proposal differences.")
    print("No remediation, target scan, current consent or shared tenancy is inferred.")
    if ask("Confirm exactly COMPARE PRIVATE LAB PLANS", "") != "COMPARE PRIVATE LAB PLANS":
        print("HOLD: no private revision was published.")
        return
    try:
        page = lab_plans.compare(before, after, parent, folder)
    except (OSError, ValueError, TypeError):
        print("HOLD: original lab proposal comparison failed native admission.")
        return
    print("PRIVATE REVIEW_ONLY: original lab proposal difference: " + str(page))
