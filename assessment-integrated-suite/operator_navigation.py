#!/usr/bin/env python3
"""Searchable native LightUp offline console navigation. NO automatic actions.

The existing numeric action dispatch and its privacy/authentication gates
remain the single entry point. This module only prints documentation.
"""
from __future__ import annotations

# Companion labels mirror original console options 1–81; no actions execute here.
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
    '56': 'Prepare source-bound PRIVATE HUMAN lab proposal decision Studio',
    '57': 'Finalize source-bound HUMAN lab proposal decisions offline (NO SCAN)',
    '58': 'Resume exact original HUMAN Lab decisions in a new PRIVATE Studio',
    '59': 'Compare 2–8 source-bound finalized PRIVATE HUMAN Lab review rounds',
    '60': 'Prepare minimum-necessary PRIVATE HUMAN Lab team workrooms',
    '61': 'Admit exact team-only HUMAN Lab feedback into full PRIVATE draft',
    '62': 'Combine 1–4 original HUMAN lab team replies into one complete PRIVATE candidate',
    '63': 'Reopen original source-bound saved PRIVATE HUMAN multi-team batch read-only',
    '64': 'Compare 2–8 original saved PRIVATE HUMAN Lab team batches, human-only',
    '65': 'Continue earlier original HUMAN Lab decisions, conflict-withhold new team replies',
    '66': 'Reopen an entire original source-bound private HUMAN continuation chain read-only',
    '67': 'Build source-minimal HUMAN stage/team history from root batch and chained rounds',
    '68': 'Prepare original source-bound PRIVATE per-ordinal HUMAN conflict choice worksheet',
    '69': 'Publish explicitly selected HUMAN conflict choices to a NEW PRIVATE candidate',
    '70': 'Reopen PRIVATE HUMAN conflict resolution against exact original source bytes',
    '71': 'Admit resolved HUMAN source and open NEW ORIGINAL review Studio manually',
    '72': 'Receive an offline HUMAN Lab discussion JSON into a PRIVATE exact-byte receipt',
    '73': 'Reopen original HUMAN Lab discussion receipt read-only',
    '74': 'Compare 2–8 complete PRIVATE HUMAN Lab discussion receipts',
    '75': 'Reopen exact original PRIVATE HUMAN Lab discussion history bytes',
    '76': 'Receive source-free HUMAN attention proposal against original PRIVATE route receipts',
    '77': 'Reopen PRIVATE HUMAN attention with exact original receipt bytes',
    '78': 'Create PRIVATE HUMAN attention proposal revision portfolio from 2–8 original receipts',
    '79': 'Reopen exact original source-bound HUMAN attention revision portfolio',
    '80': 'Publish NEW source-free HUMAN Attention v2 proposal from explicit revision choices',
    '81': 'Reopen exact source-bound PRIVATE HUMAN Attention continuation decision',
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
    ("Isolated lab offline planning", tuple(str(x) for x in range(52, 60))),
    ("PRIVATE HUMAN team feedback", tuple(str(x) for x in range(60, 65))),
    ("PRIVATE HUMAN multi-round continuation", tuple(str(x) for x in range(65, 68))),
    ("PRIVATE HUMAN conflict resolution", tuple(str(x) for x in range(68, 72))),
    ("PRIVATE HUMAN Lab discussion custody", tuple(str(x) for x in range(72, 76))),
    ("PRIVATE HUMAN Lab attention custody", ("76", "77")),
    ("PRIVATE HUMAN Attention revisions", ("78", "79")),
    ("Explicit HUMAN Attention continuation", ("80", "81")),
)



LAB_STAGES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("1. Prepare strictly offline proposals", "Original declared numeric lab plan, NEVER a scan",
     ("52", "53", "54", "55"), "52 creates an unexecuted plan; 53 reopens original bytes; 54/55 compare alternatives."),
    ("2. Human source-bound review", "Original proposal packets and HUMAN review only",
     ("56", "57", "58", "59"), "56 prepares the owner-private editor; 57 requires deliberate source-bound HUMAN finalization; 58/59 reopen and compare."),
    ("3. Separate team feedback", "Only if the original HUMAN review and team handoff exist",
     ("60", "61", "62", "63", "64"), "60 assigns separate PRIVATE workrooms; 61 receives one; 62 composes 1–4 with explicit withholding; 63/64 reopen and compare."),
    ("4. Continue across review rounds", "A previously admitted complete HUMAN batch is required",
     ("65", "66", "67"), "65 withholds conflicting returns; 66 reopens the original entire chain; 67 shows source-minimal change history."),
    ("5. Resolve HUMAN disagreements", "Unresolved original source-bound conflict room",
     ("68", "69", "70", "71"), "68 prepares per-ordinal choices; 69 publishes a NEW unfinalized HUMAN candidate; 70 reopens it; 71 opens a NEW original manual review editor."),
)

def lab_guide() -> None:
    """Explain original lab-to-HUMAN action sequence; never execute any of it."""
    print("\n=== Original LightUp LAB -> PRIVATE HUMAN review route ===")
    print("INCUBATE M3/M7 / REVIEW_ONLY / DRAFT/HOLD")
    print("This guide neither reads source nor implies that a stage is completed.")
    for title, prerequisite, ids, guidance in LAB_STAGES:
        print("\n" + title + " [" + " -> ".join(ids) + "]")
        print("  Prerequisite: " + prerequisite)
        print("  " + guidance)
        for option in ids:
            print("  " + option + " · " + ACTIONS[option])
    print("\nChoose an explicit NUMBER from the console to run ONE local stage.")
    print("Retain 0700 owner rooms / 0600 originals, and re-admit exact source bytes.")
    print("No source validation here, no automatic scan, grants, consent, finalization,")
    print("recipient dispatch, security verdict or production release.")
    print("Self-report browser export is NOT source admission or execution proof.")
    print("After copying JSON into 0700/0600 owner custody OUTSIDE the checkout:")
    print("  72 · receive exact browser self-report into PRIVATE HUMAN receipt")
    print("  73 · reopen every original saved report and output byte")
    print("  74 · compare 2–8 complete manually ordered HUMAN review rounds")
    print("  75 · re-admit original rounds and exact saved HUMAN history output")
    print("  76 · receive one saved HUMAN attention v2 proposal against 1–8 native rooms")
    print("  77 · reopen private attention and all original receipt bytes")
    print("  78 · compare 2–8 original saved PRIVATE attention proposals in manual order")
    print("  79 · reopen every original input receipt and complete revision output")
    print("  80 · selectively prepare a NEW HUMAN v2 proposal, default WITHHOLD")
    print("  81 · reopen exact original HUMAN choices and output bytes")
    print("Mandatory original CI, reviews, current authenticated consent and HUMAN GO remain HOLD.")

def overview() -> None:
    print("\n=== LightUp · offline PRIVATE assessment console ===")
    print("REVIEW_ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · NO AUTHORITY")
    for name, ids in CATEGORIES:
        print("  " + ids[0] + "–" + ids[-1] + "   " + name)
    print("Suggested safe HUMAN-only workflow: 37 → 49 → manual editor →")
    print("  50 (compare) → 51 (continue). Original LAB: 52–71.")
    print("  Local LAB discussion custody: 72 (receive) → 73 (reopen) → 74 (history).")
    print("  HUMAN attention: 76 (private receive) → 77 (exact native reopen).")
    print("  Revisions: 78 (source-bound HUMAN portfolio) → 79 (reopen original bytes).")
    print("  HUMAN continuation: 80 (manual choices) → 81 (exact reopen).")
    print("Enter an action number, ALL for full catalog, LAB for source-bound lab route, ?keyword to search,")
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
    print("56. Prepare an original-source-bound HUMAN Lab Review editor.")
    print("57. Re-admit original packets and finalize PRIVATE HUMAN choices.")
    print("58. Reopen exact source-bound HUMAN Lab choices in a NEW PRIVATE editor.")
    print("59. Compare 2-8 exact original finalized HUMAN Lab review snapshots.")
    print("60. Build separate PRIVATE minimal team workrooms from FINAL HUMAN review.")
    print("61. Admit strict team response and produce full PRIVATE HUMAN candidate.")
    print("62. Combine multiple HUMAN teams; optionally withhold returns from draft.")
    print("63. Reopen original-source-bound saved HUMAN team batch read-only.")
    print("64. Review HUMAN team proposal changes over 2–8 original batches.")
    print("65. Continue previous HUMAN decisions; conflicting team replies withheld.")
    print("66. Reopen original source-bound HUMAN continuation chain read-only.")
    print("67. Review source-bound HUMAN decision continuity and team transitions.")
    print("68. Prepare owner-private source-bound per-ordinal HUMAN conflict choices.")
    print("69. Admit edited exact-source HUMAN choices into NEW unfinalized candidate.")
    print("70. Reopen published HUMAN conflict choices read-only against originals.")
    print("71. Open the exact-source resolved draft in NEW ORIGINAL HUMAN Studio.")
    print("72. Admit exported 20-action self-report JSON into owner-private exact receipt.")
    print("73. Reopen saved self-report AND every original output byte read-only.")
    print("74. Compare 2–8 owner-private HUMAN discussion receipts in explicit order.")
    print("75. Re-admit original HUMAN round inputs and exact output history bytes.")
    print("76. Receive saved HUMAN attention v2 against exact original PRIVATE route receipts.")
    print("77. Reopen original HUMAN Attention + all saved native receipt/output bytes.")
    print("78. Compare 2–8 independently reopened PRIVATE HUMAN attention proposals.")
    print("79. Reopen complete original attention revision history and output bytes.")
    print("80. Publish NEW original receipt-bound HUMAN v2 continuation from edited choices.")
    print("81. Reopen exact original HUMAN choices, proposal and outputs read-only.")
    print("Every step remains PRIVATE and REVIEW_ONLY. No scan, grant, report")
    print("verification, real scheduling, recipient dispatch or consent.")
    print("Original current authenticated client+operator consent, revocation")
    print("at action time, owner review, CI and explicit HUMAN GO are required.")
