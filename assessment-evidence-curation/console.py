#!/usr/bin/env python3
"""Foreground PRIVATE HUMAN LightUp curation console; never runs assessments.

Offline source-bound and local packet workflows in one foreground menu.
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
from priority_inbox_action_queue_open import reopen as reopen_human_action_queue
from priority_inbox_stage_brief import publish as publish_stage_priority_brief
from priority_inbox_stage_brief_open import reopen as reopen_stage_priority_brief
from priority_inbox_stage_brief_diff import compare as compare_stage_priority_delta
from priority_inbox_stage_brief_diff_open import reopen as reopen_stage_priority_delta
from priority_inbox_stage_brief_timeline import publish as publish_stage_priority_timeline
from priority_inbox_stage_brief_timeline_open import reopen as reopen_stage_priority_timeline
from priority_inbox_portfolio import publish as publish_priority_portfolio
from priority_inbox_portfolio_open import reopen as reopen_priority_portfolio
from priority_inbox_continuity_docket import (
    build as preview_continuity_docket, publish as publish_continuity_docket,
)
from priority_inbox_continuity_docket_open import reopen as reopen_continuity_docket
from priority_inbox_continuity_review import publish as publish_continuity_review
from priority_inbox_continuity_review_open import reopen as reopen_continuity_review
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
    "22": ("Read-only reopen previously published PRIVATE HUMAN action queue",
           "existing private action queue directory; checks local unsigned byte custody"),
    "23": ("Build original-bound PRIVATE single-HUMAN-stage and priority brief",
           "original full inbox and one explicit PRIVATE review group"),
    "24": ("Reopen selected PRIVATE stage/priority brief against full original source lineage",
           "original source, every priority handoff/reply, exact inbox and saved three-file brief"),
    "25": ("Compare source-bound inbox revisions for one PRIVATE HUMAN stage and priority",
           "original source, all handoffs/returns, both inboxes and selected stage/priority"),
    "26": ("Reopen selected stage/priority delta against both original inbox revisions",
           "same original source, before/after replies/inboxes and saved exact delta"),
    "27": ("Build 2–8 round source-bound PRIVATE HUMAN stage/priority timeline",
           "same original source, every handoff and complete HUMAN returns for each ordered inbox"),
    "28": ("Reopen selected HUMAN timeline against every original ordered inbox revision",
           "same original source and returns plus saved exact three-file timeline"),
    "29": ("Build 2–8 round PRIVATE all-priority HUMAN portfolio",
           "every original priority, complete HUMAN returns and saved source-reopened inboxes"),
    "30": ("Reopen PRIVATE all-priority HUMAN portfolio against every original round",
           "same original source, full HUMAN rounds and exact nine-file PRIVATE portfolio"),
    "31": ("Publish separate PRIVATE original-source HUMAN continuity follow-up docket",
           "2–8 complete original HUMAN inboxes; explicit attention/reopened/unanswered/all filter"),
    "32": ("Read-only reopen PRIVATE source-bound HUMAN continuity follow-up docket",
           "all original sources, HUMAN rounds, exact five private files and matching filter"),
    "33": ("Preview matching PRIVATE HUMAN follow-up rows (no file published)",
           "all complete original HUMAN rounds and explicit filter/ordinals; counts-only"),
    "34": ("Ingest exact PRIVATE HUMAN review CSV to a new source-bound review packet",
           "saved original FIVE-file PRIVATE docket and manually saved reviewer CSV"),
    "35": ("Reopen saved PRIVATE source-bound HUMAN review packet, read-only",
           "same original source, docket, HUMAN return CSV, exact owner-only four-file packet"),
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
    if choice in ("27", "28", "29", "30", "31", "32", "33", "34", "35"):
        source = ask_path("EXISTING original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete PRIVATE curated packet")
        n = input("Original nonempty priority groups [1/2/3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("Invalid original priority count")
        handoffs = [ask_path("Original priority handoff " + str(i+1))
                    for i in range(int(n))]
        rounds = input("Number of complete inbox revisions [2–8]: ").strip()
        if rounds not in [str(x) for x in range(2, 9)]:
            raise Hold("Timeline requires 2–8 explicitly ordered inbox revisions")
        round_replies, round_inboxes = [], []
        for round_no in range(1, int(rounds)+1):
            print("Operator-supplied round " + str(round_no) + "; chronology is not verified.")
            round_replies.append([
                ask_path("Round " + str(round_no) + " matching HUMAN return CSV " + str(i+1))
                for i in range(int(n))])
            round_inboxes.append(ask_path("Round " + str(round_no) + " complete PRIVATE inbox"))
        args = (source, manifest, worksheet, receipt, selection, curated,
                handoffs, round_replies, round_inboxes)
        if choice in ("27", "28"):
            stage = ask_path("Exact HUMAN stage to focus on")
            priority = ask_path("Exact original HUMAN priority to focus on")
            saved = ask_path("EXCLUSIVE NEW PRIVATE timeline folder" if choice == "27" else
                             "EXISTING saved PRIVATE timeline folder")
            print("Replies are confidential; only notes in the selected stage are included.")
            if input("Enter exactly REVIEW ONLY for this timeline operation: ") != "REVIEW ONLY":
                raise Hold("Human declined PRIVATE timeline")
            if choice == "27":
                count = publish_stage_priority_timeline(*args, stage, priority, saved)
                print("PRIVATE selected stage/priority timeline published: " + str(count) +
                      " ordinals; no authenticated chronology, dispatch or authority")
            else:
                count = reopen_stage_priority_timeline(*args, stage, priority, saved)
                print("PRIVATE timeline reopened against exact source and every inbox: " +
                      str(count) + " ordinals; no authorization")
        elif choice in ("29", "30"):
            saved = ask_path("EXCLUSIVE NEW PRIVATE portfolio folder" if choice == "29" else
                             "EXISTING saved PRIVATE portfolio folder")
            print("Portfolio contains aggregate stage/priorities only; still PRIVATE.")
            if input("Enter exactly REVIEW ONLY for the all-priority portfolio: ") != "REVIEW ONLY":
                raise Hold("Human declined PRIVATE portfolio")
            if choice == "29":
                count = publish_priority_portfolio(*args, saved)
                print("Source-bound HUMAN all-priority portfolio prepared for " +
                      str(count) + " rows; no remediation or authority inferred")
            else:
                count = reopen_priority_portfolio(*args, saved)
                print("Source-bound HUMAN portfolio reopened from all original rounds: " +
                      str(count) + " rows; no authority")
        else:
            mode = input("Original HUMAN follow-up filter [attention/reopened/unanswered/all]: ").strip()
            if mode not in ("attention", "reopened", "unanswered", "all"):
                raise Hold("HOLD: choose one explicit original-HUMAN continuity filter")
            chosen_ordinals = input(
                "Limit disclosure to up to 16 explicit original HUMAN ordinals "
                "[comma-separated, blank = all matching filter]: ").strip()
            try:
                ordinal_filter = (
                    [int(part) for part in chosen_ordinals.split(",")]
                    if chosen_ordinals else [])
            except ValueError:
                raise Hold("HOLD: original HUMAN ordinal must be an exact integer") from None
            if (len(ordinal_filter) > 16 or
                any(str(part) != str(ordinal) or ordinal <= 0
                    for part, ordinal in zip(chosen_ordinals.split(","),
                                             ordinal_filter)) or
                len(set(ordinal_filter)) != len(ordinal_filter)):
                raise Hold("HOLD: repeated, noncanonical or out-of-bound ordinal")
            if choice == "33":
                count = preview_continuity_docket(
                    *args, mode, ordinal_filter)[1]
                print("NO FILE WRITTEN; " + str(count) +
                      " original HUMAN rows would be included in a PRIVATE "
                      "follow-up docket; no identity or authorization inferred")
                return
            if choice in ("34", "35"):
                original_docket = ask_path("EXISTING original source-bound five-file PRIVATE docket")
                review_file = ask_path("EXISTING manually saved PRIVATE HUMAN review-return CSV")
                dest = ask_path("EXCLUSIVE NEW PRIVATE HUMAN review packet folder" if choice == "34"
                                else "EXISTING PRIVATE HUMAN review packet folder")
                print("This intake requires all original HUMAN source/rounds, exact docket and "
                      "the manually entered untrusted HUMAN review; no consent/authority.")
                if input("Enter exactly REVIEW ONLY for source-bound HUMAN review intake: ") != "REVIEW ONLY":
                    raise Hold("HUMAN review intake declined")
                if choice == "34":
                    count = publish_continuity_review(
                        *args, mode, ordinal_filter, original_docket, review_file, dest)
                    print("PRIVATE source-bound HUMAN review packet created for " +
                          str(count) + " original rows; no authority")
                else:
                    count = reopen_continuity_review(
                        *args, mode, ordinal_filter, original_docket, review_file, dest)
                    print("PRIVATE HUMAN review packet reopened read-only for " +
                          str(count) + " rows; no bytes changed")
                return
            saved = ask_path("EXCLUSIVE NEW separate PRIVATE follow-up folder" if choice == "31" else
                             "EXISTING separate PRIVATE follow-up folder")
            print("CAUTION: unlike the aggregate portfolio this docket includes PRIVATE "
                  "original HUMAN questions and latest replies; no recipient or disclosure "
                  "authorization is inferred.")
            if input("Enter exactly REVIEW ONLY for the explicit PRIVATE follow-up: ") != "REVIEW ONLY":
                raise Hold("HUMAN declined source-specific PRIVATE follow-up")
            if choice == "31":
                count = publish_continuity_docket(*args, mode, ordinal_filter, saved)
                print("PRIVATE HUMAN follow-up docket created for " + str(count) +
                      " source-bound original rows, no assignment or authority")
            else:
                count = reopen_continuity_docket(*args, mode, ordinal_filter, saved)
                print("PRIVATE original HUMAN follow-up reopened from all original rounds: " +
                      str(count) + " rows; nothing changed")
        return
    if choice in ("25", "26"):
        source = ask_path("EXISTING original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING complete PRIVATE curated packet")
        n = input("Original nonempty priority groups [1/2/3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("Invalid original priority count")
        handoffs, before_replies, after_replies = [], [], []
        for i in range(int(n)):
            handoffs.append(ask_path("Original priority handoff " + str(i+1)))
            before_replies.append(ask_path("Prior complete HUMAN return CSV " + str(i+1)))
            after_replies.append(ask_path("Current complete HUMAN return CSV " + str(i+1)))
        before_inbox = ask_path("EXISTING prior PRIVATE HUMAN inbox")
        after_inbox = ask_path("EXISTING current PRIVATE HUMAN inbox")
        stage = ask_path("Exact HUMAN stage")
        priority = ask_path("Exact original HUMAN priority")
        saved = ask_path("EXCLUSIVE NEW PRIVATE delta folder" if choice == "25" else
                         "EXISTING saved PRIVATE stage/priority delta folder")
        print("Selected HUMAN text may identify clients; no remediation is inferred.")
        if input("Enter exactly REVIEW ONLY for this source-bound operation: ") != "REVIEW ONLY":
            raise Hold("Human declined PRIVATE stage/priority delta")
        args = (source, manifest, worksheet, receipt, selection, curated,
                handoffs, before_replies, before_inbox, after_replies,
                after_inbox, stage, priority)
        if choice == "25":
            count = compare_stage_priority_delta(*args, saved)
            print("PRIVATE selected stage/priority delta published: " + str(count) +
                  " changed rows; nothing sent or authorized")
        else:
            count = reopen_stage_priority_delta(*args, saved)
            print("PRIVATE selected stage/priority delta reopened: " + str(count) +
                  " changed rows; original bytes match, no authorization")
        return
    if choice == "24":
        source = ask_path("EXISTING original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING full HUMAN selection CSV")
        curated = ask_path("EXISTING PRIVATE curated packet")
        n = input("Original nonempty priority groups [1/2/3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("Invalid original priority count")
        handoffs, replies = [], []
        for i in range(int(n)):
            handoffs.append(ask_path("Original priority handoff " + str(i+1)))
            replies.append(ask_path("Matching complete HUMAN return CSV " + str(i+1)))
        inbox = ask_path("EXISTING exact source PRIVATE inbox")
        stage = ask_path("Exact original HUMAN stage")
        priority = ask_path("Exact original HUMAN priority")
        saved = ask_path("EXISTING saved PRIVATE stage/priority brief directory")
        if input("Enter exactly REVIEW ONLY for read-only source reopen: ") != "REVIEW ONLY":
            raise Hold("Human declined read-only PRIVATE brief reopen")
        count = reopen_stage_priority_brief(
            source, manifest, worksheet, receipt, selection, curated,
            handoffs, replies, inbox, stage, priority, saved)
        print("Original-source PRIVATE brief reopened by exact bytes: " + str(count) +
              " rows; unsigned REVIEW_ONLY, no authorization or delivery")
        return
    if choice == "23":
        source = ask_path("EXISTING original lab source JSON")
        manifest = ask_path("EXISTING original briefing manifest")
        worksheet = ask_path("EXISTING original full HUMAN worksheet")
        receipt = ask_path("EXISTING original selection receipt")
        selection = ask_path("EXISTING complete HUMAN selection CSV")
        curated = ask_path("EXISTING full PRIVATE curated packet")
        n = input("Original nonempty HUMAN priority groups [1/2/3]: ").strip()
        if n not in ("1", "2", "3"):
            raise Hold("Invalid original priority group count")
        handoffs, replies = [], []
        for index in range(int(n)):
            handoffs.append(ask_path("Original priority handoff " + str(index+1)))
            replies.append(ask_path("Matching HUMAN response CSV " + str(index+1)))
        inbox = ask_path("EXISTING exact source PRIVATE inbox")
        stage = ask_path("Human stage (blocked_human / needs_more_information / no_human_response / responded_claimed)")
        priority = ask_path("Human priority (routine / soon / urgent)")
        output = ask_path("EXCLUSIVE NEW PRIVATE limited HUMAN brief directory")
        print("This PRIVATE brief may reveal client identities in HUMAN-entered text.")
        if input("Enter exactly REVIEW ONLY to create the private selected brief: ") != "REVIEW ONLY":
            raise Hold("Human declined private selected brief")
        amount = publish_stage_priority_brief(
            source, manifest, worksheet, receipt, selection, curated,
            handoffs, replies, inbox, stage, priority, output)
        print("PRIVATE selected HUMAN follow-up brief: " + str(amount) +
              " original ordinals; no disclosure, verified fix or authority")
        return
    if choice == "22":
        directory = ask_path("EXISTING published PRIVATE HUMAN action queue folder")
        print("This checks ONLY unsigned local byte custody, NOT current original source or authority.")
        if input("Enter exactly REVIEW ONLY for local byte custody: ") != "REVIEW ONLY":
            raise Hold("Human declined PRIVATE action queue reopen")
        count = reopen_human_action_queue(directory)
        print("PRIVATE HUMAN action queue local byte consistency: " + str(count) +
              " HUMAN rows; no source/authentication/authorization verdict")
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
        choice = input("PRIVATE workflow [0–35]: ").strip()
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
    if choice == "33":
        print("\nPRIVATE HUMAN selection preview completed; no file published")
    else:
        print("\nEXISTING PRIVATE packet reopened; no new output" if choice in
              ("11", "13", "15", "18", "20", "22", "24", "26", "28", "30", "32", "35") else
              "\nNEW PRIVATE output prepared; HUMAN REVIEW ONLY / NO target execution")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
