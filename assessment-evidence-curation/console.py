#!/usr/bin/env python3
"""Foreground PRIVATE HUMAN LightUp curation console; never runs assessments.

Twenty offline source-bound and local packet workflows in one user menu.
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
from packet_open import reopen as reopen_curated_packet
from packet_handoff import prepare as prepare_priority_handoff, reopen as reopen_priority_handoff
from priority_reply import receive as receive_priority_reply
from priority_return_open import reopen as reopen_priority_return
from priority_reconcile import reconcile as reconcile_original_priority
from priority_inbox import join as join_priority_inbox
from priority_inbox_open import reopen as reopen_priority_inbox
from priority_inbox_action_queue import publish_queue as publish_human_action_queue
from priority_inbox_diff import compare as compare_priority_inbox
from priority_inbox_diff_open import reopen as reopen_priority_inbox_diff

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
    "11": ("Reopen existing PRIVATE selected-evidence packet by local byte integrity",
           "already-produced original 0700 PRIVATE curation packet directory only"),
    "12": ("Prepare minimum-necessary single-priority PRIVATE HUMAN handoff",
           "already-published complete source-bound curated packet; one priority + HUMAN response CSV; NEW private output"),
    "13": ("Reopen existing single-priority PRIVATE HUMAN handoff",
           "existing 0700 HUMAN question-only handoff; no original source required"),
    "14": ("Receive PRIVATE HUMAN reply for a single source-bound priority handoff",
           "complete original priority handoff and edited full recipient HUMAN reply CSV"),
    "15": ("Reopen PRIVATE HUMAN priority reply packet by local unsigned bytes",
           "already-produced full PRIVATE recipient HUMAN response folder"),
    "16": ("Reconcile one HUMAN priority reply with full current ORIGINAL PRIVATE source",
           "original lab/manifest/worksheet/selection, full curated package and HUMAN handoff"),
    "17": ("Combine all detached PRIVATE HUMAN priority replies into one ORIGINAL CSV",
           "full original lab and every separate priority/HUMAN reply pair, all-or-nothing"),
    "18": ("Reopen complete PRIVATE HUMAN inbox against original sources and all replies",
           "full original source/selection, full curated packet, every unique handoff + reply pair"),
    "19": ("Compare two full-lineage PRIVATE HUMAN response inbox revisions",
           "same original source/selection and handoffs; complete before/after reply CSV + inbox pairs"),
    "20": ("Reopen PRIVATE HUMAN response delta against both source-bound inbox revisions",
           "same original source, handoffs, both complete inboxes + before/after reply CSVs"),
    "21": ("Build PRIVATE HUMAN response-stage action queue from an exact source-reopened inbox",
           "original source/selection, every reply group and saved exact-byte PRIVATE inbox"),
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
    if choice == "11":
        private_directory = ask_path("EXISTING PRIVATE curated packet directory")
        print("This checks owner-only local files against UNSIGNED recorded bytes ONLY.")
        print("It CANNOT validate original sources, consent, recipient identity or findings.")
        if input("Enter exactly REVIEW ONLY to reopen without publishing: ") != "REVIEW ONLY":
            raise Hold("Human declined local packet reopen")
        count = reopen_curated_packet(private_directory)
        print("PRIVATE local packet bytes consistent; " + str(count) +
              " HUMAN-selected entries; UNSIGNED / NO permission / REVIEW_ONLY")
        return
    if choice in ("12", "13"):
        directory = ask_path("EXISTING 0700 PRIVATE packet directory")
        if choice == "12":
            priority = input("One HUMAN priority [routine / soon / urgent]: ").strip()
            if priority not in ("routine", "soon", "urgent"):
                raise Hold("Unsupported HUMAN priority")
            output = ask_path("EXCLUSIVE NEW 0700 PRIVATE handoff directory")
            print("Only one priority-specific HUMAN sheet will be copied. "
                  "It may STILL identify the client.")
            if input("Enter exactly REVIEW ONLY to prepare (NOT send): ") != "REVIEW ONLY":
                raise Hold("Human declined private handoff preparation")
            count = prepare_priority_handoff(directory, priority, output)
        else:
            print("Reopen verifies local UNSIGNED bytes, not identity/consent.")
            if input("Enter exactly REVIEW ONLY to reopen: ") != "REVIEW ONLY":
                raise Hold("Human declined private handoff reopening")
            count = reopen_priority_handoff(directory)
        print("PRIVATE HUMAN single-priority question count: " + str(count) +
              "; NO dispatch or authorization.")
        return
    if choice == "14":
        original = ask_path("EXISTING 0700 original PRIVATE priority handoff directory")
        returned = ask_path("EXISTING completed recipient HUMAN reply CSV")
        output = ask_path("EXCLUSIVE NEW private recipient HUMAN return directory")
        print("Recipient claims and identity remain UNVERIFIED. Review-only; "
              "no response dispatch or disclosure approval.")
        if input("Enter exactly REVIEW ONLY to create local HUMAN response: ") != "REVIEW ONLY":
            raise Hold("HUMAN did not confirm private reply preparation")
        count = receive_priority_reply(original, returned, output)
        print("PRIVATE HUMAN self-reported replies recorded: " + str(count) +
              "; NOT validated findings or remediation")
        return
    if choice == "15":
        folder = ask_path("EXISTING PRIVATE HUMAN recipient return directory")
        print("This checks UNSIGNED local packet bytes only; never recipient identity or consent.")
        if input("Enter exactly REVIEW ONLY to reopen: ") != "REVIEW ONLY":
            raise Hold("HUMAN declined local return packet reopen")
        count = reopen_priority_return(folder)
        print("PRIVATE HUMAN return rows: " + str(count) + "; NOT verified findings")
        return
    if choice == "16":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING original full HUMAN selection CSV")
        curated = ask_path("EXISTING published full PRIVATE curated packet")
        handoff = ask_path("EXISTING detached PRIVATE priority HUMAN handoff")
        returned = ask_path("EXISTING complete HUMAN recipient response CSV")
        output = ask_path("EXCLUSIVE NEW PRIVATE reconciliation folder")
        print("Original all-source bytes and current source membership will be "
              "checked; signed identity, authorization and recipient still UNVERIFIED.")
        if input("Enter exactly REVIEW ONLY for local HUMAN reconciliation: ") != "REVIEW ONLY":
            raise Hold("HUMAN did not confirm source-bound private review")
        count = reconcile_original_priority(source, manifest, worksheet,
                                            receipt, selection, curated, handoff,
                                            returned, output)
        print("Original-source HUMAN priority rows checked: " + str(count) +
              "; NO verified remediation, recipient or consent")
        return
    if choice == "21":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete original PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1 / 2 / 3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("HOLD: invalid HUMAN priority group count")
        handoffs = []
        replies = []
        for i in range(int(n)):
            handoffs.append(ask_path("Original PRIVATE priority handoff " + str(i+1)))
            replies.append(ask_path("Corresponding complete HUMAN response CSV " + str(i+1)))
        inbox = ask_path("EXISTING complete original PRIVATE HUMAN inbox directory")
        output = ask_path("EXCLUSIVE NEW PRIVATE HUMAN action queue output directory")
        print("Output contains confidential HUMAN text, is REVIEW ONLY and never assigns tasks.")
        if input("Enter exactly REVIEW ONLY for the offline HUMAN action queue: ") != "REVIEW ONLY":
            raise Hold("Human declined source-bound PRIVATE action queue")
        count = publish_human_action_queue(
            source, manifest, worksheet, receipt, selection,
            curated, handoffs, replies, inbox, output)
        print("Private stage-grouped HUMAN action queue prepared for " + str(count) +
              " original source ordinals; no source, consent or target modified")
        return
    if choice == "18":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete original PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1 / 2 / 3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("HOLD: invalid HUMAN priority group count")
        handoffs = []
        replies = []
        for i in range(int(n)):
            handoffs.append(ask_path("Original PRIVATE priority handoff " + str(i+1)))
            replies.append(ask_path("Corresponding complete HUMAN response CSV " + str(i+1)))
        inbox = ask_path("EXISTING complete PRIVATE original HUMAN inbox directory")
        print("Reopens read-only by regenerating the complete expected inbox from current "
              "original sources, then exact-byte-comparing every member. No repair or send.")
        if input("Enter exactly REVIEW ONLY to reopen: ") != "REVIEW ONLY":
            raise Hold("Human declined source-bound HUMAN inbox reopen")
        count = reopen_priority_inbox(source, manifest, worksheet, receipt,
                                       selection, curated, handoffs, replies, inbox)
        print("PRIVATE original-source HUMAN inbox consistent: " + str(count) +
              " selected rows; UNSIGNED, no consent/dispatch")
        return
    if choice == "20":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete original PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1 / 2 / 3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("HOLD: invalid HUMAN priority group count")
        handoffs = []
        before_replies = []
        after_replies = []
        for i in range(int(n)):
            handoffs.append(ask_path("Original PRIVATE priority handoff " + str(i+1)))
            before_replies.append(ask_path("Prior complete HUMAN response CSV " + str(i+1)))
            after_replies.append(ask_path("Current complete HUMAN response CSV " + str(i+1)))
        before_inbox = ask_path("EXISTING prior complete PRIVATE HUMAN inbox directory")
        after_inbox = ask_path("EXISTING current complete PRIVATE HUMAN inbox directory")
        delta = ask_path("EXISTING PRIVATE HUMAN response-delta directory")
        print("Rebuilds both source-bound inbox revisions and the delta without "
              "writing; only exact local inventory/byte consistency is checked.")
        if input("Enter exactly REVIEW ONLY to reopen: ") != "REVIEW ONLY":
            raise Hold("Human declined PRIVATE response-delta reopen")
        count = reopen_priority_inbox_diff(
            source, manifest, worksheet, receipt, selection, curated, handoffs,
            before_replies, before_inbox, after_replies, after_inbox, delta)
        print("PRIVATE response-delta rows reopened: " + str(count) +
              "; no files changed, no authorization")
        return
    if choice == "19":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete original PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1 / 2 / 3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("HOLD: invalid HUMAN priority group count")
        handoffs = []
        before_replies = []
        after_replies = []
        for i in range(int(n)):
            handoffs.append(ask_path("Original PRIVATE priority handoff " + str(i+1)))
            before_replies.append(ask_path("Prior complete HUMAN response CSV " + str(i+1)))
            after_replies.append(ask_path("Current complete HUMAN response CSV " + str(i+1)))
        before_inbox = ask_path("EXISTING prior complete PRIVATE HUMAN inbox directory")
        after_inbox = ask_path("EXISTING current complete PRIVATE HUMAN inbox directory")
        output = ask_path("EXCLUSIVE NEW PRIVATE HUMAN response-delta directory")
        print("Both inboxes are re-admitted against the same original source and "
              "all source-bound handoffs. The report may contain client-confidential HUMAN text.")
        if input("Enter exactly REVIEW ONLY to create PRIVATE comparison: ") != "REVIEW ONLY":
            raise Hold("Human declined PRIVATE HUMAN response comparison")
        changed = compare_priority_inbox(
            source, manifest, worksheet, receipt, selection, curated, handoffs,
            before_replies, before_inbox, after_replies, after_inbox, output)
        print("PRIVATE HUMAN response rows changed: " + str(changed) +
              "; unverified claims, no consent or dispatch")
        return
    if choice == "17":
        source = ask_path("EXISTING full original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete original PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1 / 2 / 3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("HOLD: invalid HUMAN priority group count")
        handoffs = []
        replies = []
        for i in range(int(n)):
            handoffs.append(ask_path("Original PRIVATE priority handoff " + str(i+1)))
            replies.append(ask_path("Corresponding complete recipient HUMAN CSV " + str(i+1)))
        output = ask_path("EXCLUSIVE NEW PRIVATE unified HUMAN inbox directory")
        print("Requires ALL original nonempty priority groups, each ONCE, "
              "and keeps EVERY original source selection row, even unanswered.")
        if input("Enter exactly REVIEW ONLY to prepare PRIVATE CSV (NOT send): ") != "REVIEW ONLY":
            raise Hold("Human declined original source HUMAN inbox")
        count = join_priority_inbox(source, manifest, worksheet, receipt,
                                    selection, curated, handoffs, replies, output)
        print("PRIVATE original source HUMAN selected rows preserved: " + str(count) +
              "; nothing authenticated, sent, tested or granted")
        return
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
        choice = input("PRIVATE workflow [0–21]: ").strip()
        if choice == "0":
            print("No operation performed")
            return 0
        if choice not in WORKFLOWS:
            raise Hold("Unknown PRIVATE workflow")
        run_workflow(choice)
    except (EOFError, KeyboardInterrupt, Hold) as exc:
        if 'choice' in locals() and choice == "18" and isinstance(exc, Hold):
            # This path emits only static failure categories and member filenames.
            print("\n" + str(exc), file=sys.stderr)
        else:
            print("\nHOLD: PRIVATE input cancelled, rejected or incomplete; no output claimed", file=sys.stderr)
        return 3
    except OSError:
        # Do not print local filesystem path names or exception messages.
        print("\nHOLD: Private local file access rejected", file=sys.stderr)
        return 3
    print("\nEXISTING PRIVATE packet reopened; no new output" if choice in ("11", "13", "15", "18", "20") else
          "\nNEW PRIVATE output prepared; HUMAN REVIEW ONLY / NO target execution")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
