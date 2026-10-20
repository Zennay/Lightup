#!/usr/bin/env python3
"""Foreground PRIVATE HUMAN LightUp curation console; never runs assessments.

Ten existing offline source-bound workflows in one accessible user menu.
Only explicit local paths, no subprocess, network, browser automation, consent,
source mutation, active target operation, or grant.
"""
from __future__ import annotations

import sys

# curate loads frozen original source admission modules before any code executes.
from curate import Hold, prepare, publish
from revision import compare
from history import history
from response import prepare_reply, return_reply
from response_triage import prepare as prepare_triage, finish as return_triage
from next_round import propose as propose_next_round
from review_hub import build as build_human_overview

WORKFLOWS = {
    "1": ("Prepare PRIVATE offline HUMAN browser selection studio",
          "source, original manifest, exact seven-column HUMAN worksheet; NEW private output"),
    "2": ("Publish selected-only PRIVATE evidence handoff",
          "same original data and matching selection receipt; one private HUMAN selection CSV"),
    "3": ("Compare two PRIVATE HUMAN selection versions",
          "same source/receipt; old and new original-ordinal selections"),
    "4": ("Review 2–12 PRIVATE HUMAN selection versions",
          "same source/receipt; ordered previous selection files"),
    "5": ("Prepare PRIVATE source-bound recipient question reply template",
          "same original source/receipt; original selected HUMAN questions"),
    "6": ("Reopen a returned PRIVATE recipient HUMAN answer package",
          "same original selection and a source/selection-bound human reply"),
    "7": ("Prepare HUMAN sender reply triage workroom",
          "original source-bound recipient response and NEW private triage editor"),
    "8": ("Reopen a finished HUMAN sender triage response",
          "same source, response, triage binding and HUMAN routing worksheet"),
    "9": ("Prepare PRIVATE next HUMAN questions from original sender triage",
          "same original source, response, triage binding and explicit HUMAN proposed next question"),
    "10": ("Create PRIVATE consolidated HUMAN assessment workroom dashboard",
           "original selection and optionally source-bound recipient response and sender HUMAN triage"),
}


def ask_path(label: str) -> str:
    while True:
        value = input(label + ": ").strip()
        if not value:
            raise Hold("Empty input: no PRIVATE operation started")
        if len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value:
            raise Hold("Unsupported local path")
        return value


def ask_history() -> list[str]:
    count = input("How many separately saved ORIGINAL HUMAN selection versions? [2–12]: ").strip()
    if count not in [str(x) for x in range(2, 13)]:
        raise Hold("Only 2–12 HUMAN versions may be opened")
    return [ask_path("HUMAN selection version " + str(x+1) + " PRIVATE CSV")
            for x in range(int(count))]


def run_workflow(choice: str) -> None:
    print("\nPRIVATE HUMAN-only operation:", WORKFLOWS[choice][0])
    print("Required:", WORKFLOWS[choice][1])
    print("HOLD: original lab source and HUMAN reviews are UNVERIFIED.")
    print("Never grants target permission, verifies source identity or changes runtime.")
    source = ask_path("EXISTING original lab source JSON")
    manifest = ask_path("EXISTING original PRIVATE source briefing manifest JSON")
    worksheet = ask_path("EXISTING original seven-column source-bound HUMAN worksheet CSV")
    receipt = None
    selection = None
    before = None
    after = None
    series = None
    if choice != "1":
        receipt = ask_path("EXISTING PRIVATE selection-preparation receipt JSON")
    if choice == "2":
        selection = ask_path("EXISTING PRIVATE human-selection CSV")
    elif choice == "3":
        before = ask_path("Prior HUMAN selection CSV")
        after = ask_path("Current HUMAN selection CSV")
    elif choice == "4":
        series = ask_history()
    elif choice in ("5", "6", "7", "8", "9", "10"):
        selection = ask_path("EXISTING PRIVATE original HUMAN selection CSV")
    response_binding = None
    recipient_response = None
    if choice in ("6", "7", "8", "9"):
        response_binding = ask_path("EXISTING original selection-bound PRIVATE recipient response binding JSON")
        recipient_response = ask_path("Returned HUMAN recipient response CSV")
    triage_binding = None
    triage_csv = None
    if choice in ("8", "9"):
        triage_binding = ask_path("EXISTING original reply-bound PRIVATE sender triage binding JSON")
        triage_csv = ask_path("Completed PRIVATE sender HUMAN triage CSV")
    if choice == "10":
        document_phase = input("Available HUMAN document stage: selection / recipient / triage [selection]: ").strip() or "selection"
        if document_phase not in ("selection", "recipient", "triage"):
            raise Hold("Unsupported PRIVATE HUMAN document phase")
        if document_phase in ("recipient", "triage"):
            response_binding = ask_path("Original source-bound recipient response binding")
            recipient_response = ask_path("Original recipient HUMAN reply CSV")
        if document_phase == "triage":
            triage_binding = ask_path("Original source/recipient-bound sender HUMAN triage binding")
            triage_csv = ask_path("Original source/recipient-bound sender HUMAN triage CSV")
    output = ask_path("EXCLUSIVE NEW PRIVATE output directory (must not already exist)")
    print("\nPRIVATE disclosure profile:")
    if choice == "1":
        print("  Original data admitted locally; generated browser contains ordinal/severity/count only.")
    elif choice == "2":
        print("  New printable dossier includes ORIGINAL private target, finding evidence and HUMAN notes.")
    elif choice == "3":
        print("  Report contains original ordinal/severity and HUMAN questions, potentially confidential.")
    elif choice == "4":
        print("  Timeline contains original ordinals and HUMAN questions, potentially confidential.")
    elif choice == "5":
        print("  PRIVATE template contains original HUMAN questions and source counts, no original target evidence.")
    elif choice == "6":
        print("  PRIVATE response report contains HUMAN replies, which may be client-identifying; identities not verified.")
    elif choice == "7":
        print("  PRIVATE sender browser shows original HUMAN questions and recipient replies; potential client identifiers.")
    elif choice == "8":
        print("  PRIVATE HUMAN sender triage shows original recipient replies and owner-group follow-up proposals.")
    elif choice == "9":
        print("  Generates a new PRIVATE selection CSV with explicitly HUMAN proposed follow-up questions; NO dispatch.")
    else:
        print("  Builds source-identifier-minimized PRIVATE HUMAN workroom overview and priority-specific reports.")
    print("This is NOT a completed assessment, release, authorization or evidence authenticity check.")
    confirmation = input("Enter exactly REVIEW ONLY to create a NEW PRIVATE package: ")
    if confirmation != "REVIEW ONLY":
        raise Hold("Operator did not confirm PRIVATE review-only disclosure")
    if choice == "1":
        prepare(source, manifest, worksheet, output)
    elif choice == "2":
        publish(source, manifest, worksheet, receipt, selection, output)
    elif choice == "3":
        compare(source, manifest, worksheet, receipt, before, after, output)
    elif choice == "4":
        history(source, manifest, worksheet, receipt, series, output)
    elif choice == "5":
        prepare_reply(source, manifest, worksheet, receipt, selection, output)
    elif choice == "6":
        return_reply(source, manifest, worksheet, receipt, selection,
                     response_binding, recipient_response, output)
    elif choice == "7":
        prepare_triage(source, manifest, worksheet, receipt, selection,
                       response_binding, recipient_response, output)
    elif choice == "8":
        return_triage(source, manifest, worksheet, receipt, selection,
                      response_binding, recipient_response, triage_binding,
                      triage_csv, output)
    elif choice == "9":
        propose_next_round(source, manifest, worksheet, receipt, selection,
                           response_binding, recipient_response, triage_binding,
                           triage_csv, output)
    else:
        build_human_overview(source, manifest, worksheet, receipt, selection,
                             response_binding, recipient_response, triage_binding,
                             triage_csv, output)


def main() -> int:
    print("LightUp · PRIVATE lab evidence curation operations")
    print("INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT-HOLD")
    print("Original producer, findings, client/operator consent and execution remain UNVERIFIED.")
    print("All output is separately PRIVATE; source/customer disclosures need HUMAN approval.\n")
    for number, (label, _) in WORKFLOWS.items():
        print(number + ". " + label)
    print("0. Quit without action")
    try:
        choice = input("PRIVATE workflow [0–10]: ").strip()
        if choice == "0":
            print("No operation performed")
            return 0
        if choice not in WORKFLOWS:
            raise Hold("Unknown PRIVATE workflow")
        run_workflow(choice)
    except (EOFError, KeyboardInterrupt, Hold):
        print("\nHOLD: PRIVATE input cancelled, rejected or incomplete; no output claimed", file=sys.stderr)
        return 3
    except OSError:
        # Do not print local filesystem path names or exception messages.
        print("\nHOLD: Private local file access rejected", file=sys.stderr)
        return 3
    print("\nNEW PRIVATE output prepared; HUMAN REVIEW ONLY / NO target execution")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
