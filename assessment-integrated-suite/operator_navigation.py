#!/usr/bin/env python3
"""Searchable native LightUp offline console navigation. NO automatic actions.

The existing numeric action dispatch and its privacy/authentication gates
remain the single entry point. This module only prints documentation.
"""
from __future__ import annotations

# Generated from the original 51 action captions in console.py.
ACTIONS: dict[str, str] = {
    '1': 'Prepare PRIVATE original briefing + 15 offline HUMAN workrooms',
    '2': 'Prepare exact-source PRIVATE HUMAN selection studio',
    '3': 'Build source-selected PRIVATE HUMAN finding dossier',
    '4': 'Review two original PRIVATE lab source revisions',
    '5': 'Show local package paths (current session only)',
    '6': 'Prepare original multi-artifact PRIVATE source archive',
    '7': 'Prepare original PRIVATE HUMAN agenda portfolio',
    '8': 'Compare already-recorded lab benchmark originals (single/cohort/scored)',
    '9': 'Generate 3-12 original benchmark cohorts for native offline trends',
    '10': 'Reconcile exact-source PRIVATE HUMAN reviewer plans',
    '11': 'Snapshot 1-12 original PRIVATE packages with byte-bound HUMAN ledger',
    '12': 'Reopen and verify original PRIVATE ledger without making a new one',
    '13': 'Finalize source-bound PRIVATE HUMAN ledger suggestions',
    '14': 'Prepare original credential-masked PRIVATE assessment notes',
    '15': 'Finalize source-bound PRIVATE HUMAN note decisions',
    '16': 'Map original completed benchmark + authenticated client findings into HUMAN follow-up',
    '17': 'Generate canonical original cohort comparison and private HUMAN client finding follow-up',
    '18': 'Prepare bounded PRIVATE HUMAN team review handoff',
    '19': 'Admit a returned PRIVATE HUMAN annotation against original team scope',
    '20': 'Reconcile two to twelve non-overlapping PRIVATE HUMAN team returns',
    '21': 'One-command original PRIVATE comparison to HUMAN casebook and source ledger',
    '22': 'One-command two original cohorts to HUMAN casebook and source ledger',
    '23': 'Prepare PRIVATE original selective evidence HUMAN Studio',
    '24': 'Publish only original HUMAN-selected PRIVATE evidence and recipient questions',
    '25': 'Review 2-12 source-bound PRIVATE HUMAN evidence-selection revisions',
    '26': 'Create PRIVATE original human-curated evidence and recipient overview',
    '27': 'Prepare original PRIVATE HUMAN recipient question studio',
    '28': 'Admit source-bound PRIVATE HUMAN recipient responses',
    '29': 'Prepare original PRIVATE HUMAN sender triage workroom',
    '30': 'Admit original PRIVATE HUMAN sender triage and follow-up',
    '31': 'Prepare exact-source PRIVATE next HUMAN question proposal (no sending)',
    '32': 'Prepare original PRIVATE disclosure preflight + source-free HUMAN workroom',
    '33': 'Admit exact-receipt PRIVATE HUMAN disclosure decisions locally',
    '34': 'Generate original small-cohort-suppressed HUMAN stage counts (PRIVATE)',
    '35': 'Review 2-12 original PRIVATE HUMAN retention plan snapshots',
    '36': 'Show original PRIVATE HUMAN retention source-drift (no deletion)',
    '37': 'Save owner-private PATH-ONLY session + offline workroom bookmarks',
    '38': 'Resume PRIVATE operator paths manually (no source execution)',
    '39': 'Compare 2-8 original PRIVATE operator snapshots (HUMAN-only)',
    '40': 'Build one owner-private assessment route board from current original workrooms',
    '41': 'Build PRIVATE route board from a saved 0600 session WITHOUT restoring paths',
    '42': 'Build PRIVATE HUMAN action queue + original editable CSV',
    '43': 'Reopen HUMAN-updated CSV against exact current session paths',
    '44': 'Create PRIVATE minimal HUMAN team deck from original queue',
    '45': 'Compare 2-8 original PRIVATE HUMAN work queues without notes',
    '46': 'Resume saved PRIVATE HUMAN queue without replacing current session',
    '47': 'Create PRIVATE HUMAN follow-up priorities and team workload desk',
    '48': 'Build complete PRIVATE HUMAN assessment workpack from original queue',
    '49': 'Resume complete PRIVATE HUMAN workpack from ORIGINAL saved session',
    '50': 'Review 2-8 original PRIVATE HUMAN workpack snapshots (saved session)',
    '51': 'Continue an original PRIVATE HUMAN workpack with a new declared date',
    '52': 'Prepare original isolated-lab numeric URL proposal (NO SCAN)',
    '53': 'Reopen original owner-private isolated lab proposal (NO SCAN)',
    '54': 'Compare two original owner-private isolated lab proposals (NO SCAN)',
    '55': 'Review 3–8 original PRIVATE isolated-lab proposals in one portfolio (NO SCAN)',
}

CATEGORIES = (
    ("Original source / benchmarks", tuple(str(x) for x in range(1, 11))),
    ("PRIVATE ledger / notes", tuple(str(x) for x in range(11, 16))),
    ("Human remediation / source handoff", tuple(str(x) for x in range(16, 23))),
    ("Evidence and recipient dialogue", tuple(str(x) for x in range(23, 32))),
    ("Privacy disclosure / retention", tuple(str(x) for x in range(32, 37))),
    ("Owner-private session continuity", tuple(str(x) for x in range(37, 42))),
    ("HUMAN task queues", tuple(str(x) for x in range(42, 48))),
    ("Integrated HUMAN workpacks", tuple(str(x) for x in range(48, 52))),
    ("Isolated lab offline planning", tuple(str(x) for x in range(52, 56))),
)


def overview() -> None:
    print("\n=== LightUp · offline PRIVATE assessment console ===")
    print("REVIEW_ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · NO AUTHORITY")
    for name, ids in CATEGORIES:
        print("  " + ids[0] + "–" + ids[-1] + "   " + name)
    print("Suggested safe HUMAN-only workflow: 37 → 49 → manual editor →")
    print("  50 (compare) → 51 (continue). Lab-only: 52 → 53 → 54 → 55.")
    print("Enter an action number, ALL for full catalog, ?keyword to search,")
    print("HELP for a HUMAN walkthrough or 0 to exit. No action is automatic.")


def all_actions() -> None:
    print("=== Exact original actions (numbers unchanged) ===")
    for key in sorted(ACTIONS, key=int):
        print(key + ". " + ACTIONS[key])
    print("0. Exit without scheduling or executing anything")


def search(query: str) -> set[str]:
    if not query.strip():
        print("Enter a search word after ? (e.g. ?workpack or ?benchmark).")
        return set()
    if len(query) > 120 or any(ord(ch) < 32 or ord(ch) == 127 for ch in query):
        print("HOLD: search text must be a short literal local keyword.")
        return set()
    normalized = query.strip().casefold()
    found = {
        key for key, caption in ACTIONS.items()
        if normalized in caption.casefold() or normalized == key
    }
    if not found:
        print("No matching existing action. Enter ALL for every exact action.")
    else:
        print("Exact original local actions matching the search:")
        for key in sorted(found, key=int):
            print(key + ". " + ACTIONS[key])
    return found


def help_flow() -> None:
    print("=== HUMAN workpack walkthrough (local-only) ===")
    print("37. Deliberately save the current trusted owner-private PATH-only session.")
    print("49. Create an all-UNASSESSED workpack from that strict saved session")
    print("    or supply an exact-session existing original HUMAN queue CSV.")
    print("    Edit HUMAN stage/team/question in its offline local Studio;")
    print("    browser exports require manual 0700/0600 custody and re-admission.")
    print("50. Compare 2-8 original workpack snapshots against the SAME session.")
    print("    Search and filter the source-minimal offline Progress Cockpit.")
    print("51. Continue an admitted original workpack at a NEW manually declared")
    print("    review date, preserving its previous HUMAN choices and questions.")
    print("52. Prepare original numeric isolated-lab proposal (not target execution).")
    print("53. Reopen the original source-bound owner-private proposal.")
    print("54. Compare two original private proposals; missing URL is NOT a fix.")
    print("55. Review 3-8 PRIVATE original proposals in a source-bound portfolio.")
    print("Every step remains PRIVATE and REVIEW_ONLY. No scan, grant, report")
    print("verification, real scheduling, recipient dispatch or consent.")
    print("Original current authenticated client+operator consent, revocation")
    print("at action time, owner review, CI and explicit HUMAN GO are required.")
