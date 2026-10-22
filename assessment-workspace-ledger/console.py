#!/usr/bin/env python3
"""Foreground HUMAN-only operator console for existing PRIVATE assessment kits.

Exactly one locally chosen original-source action at a time.
No shell, subprocess, background jobs, network, models, scanner or grant APIs.
"""
from __future__ import annotations

import argparse
import os
import sys

import ledger
import compare
import continuity
import human_revisions
import history
import history_human
import history_team
import history_actions
import history_owner_brief
import history_progress
import portfolio
import portfolio_delta
import portfolio_owner_packets
import portfolio_dayboard
import portfolio_focus
import portfolio_focus_review
import portfolio_focus_history
import portfolio_focus_owner_handoff
import portfolio_owner_reply
import portfolio_owner_inbox
import portfolio_owner_inbox_review
import portfolio_inbox_studio
import portfolio_owner_attention
import portfolio_inbox_history
import portfolio_inbox_timeline
import portfolio_inbox_timeline_selection
import portfolio_inbox_timeline_batch
import portfolio_inbox_owner_return
import portfolio_inbox_owner_return_studio
import portfolio_inbox_owner_reconcile
import portfolio_owner_inbox_viewer
import portfolio_owner_followup
import portfolio_owner_followup_studio
import portfolio_owner_change_briefs
import portfolio_owner_change_board
import portfolio_owner_change_history
import portfolio_owner_change_history_studio
import portfolio_operator_calendar
import portfolio_operator_calendar_studio
import portfolio_operator_calendar_history
import portfolio_operator_calendar_continuity
import portfolio_operator_calendar_decisions
import portfolio_operator_calendar_decision_studio
import portfolio_operator_calendar_decision_handoff
import portfolio_owner_studio
import portfolio_focus_studio
import browser_intake
import package
from browser_studio import render_studio

TITLE = "LightUp PRIVATE Assessment Workspace · Foreground HUMAN Console"
MENU = (
    ("1", "Capture current private original kit inventory"),
    ("2", "Reopen exact original source bytes against ledger"),
    ("3", "Record newly completed HUMAN review CSV (never permission)"),
    ("4", "Review historical change between two stored inventories"),
    ("5", "Continue previous HUMAN proposals on unchanged original kits"),
    ("6", "Export complete source-free single-file offline HUMAN studio"),
    ("7", "Show PRIVATE session-only action results"),
    ("8", "Review historical HUMAN stage/owner/question changes on unchanged kit bytes"),
    ("9", "Build a NEW source-only offline software ZIP"),
    ("10", "Inspect unsigned software ZIP file inventory locally"),
    ("11", "Import browser-downloaded HUMAN CSV safely into PRIVATE native custody"),
    ("12", "Import PRIVATE browser CSV and immediately prepare original HUMAN follow-up packet"),
    ("13", "Review 2-12 ORIGINAL capture-linked inventory snapshots as PRIVATE HUMAN history"),
    ("14", "Native-finalize ORIGINAL chain-bound HUMAN historical review CSV"),
    ("15", "Native-finalize explicit browser-downloaded HUMAN historical CSV in PRIVATE custody"),
    ("16", "Prepare PRIVATE source-bound two-to-eight HUMAN reviewer conflict workroom"),
    ("17", "Finalize explicit original HUMAN reviewer choices in native PRIVATE custody"),
    ("18", "Finalize browser-downloaded original HUMAN reviewer choices in PRIVATE custody"),
    ("19", "Prepare source-exact PRIVATE HUMAN action planning after finalized team choices"),
    ("20", "Finalize owner-private source-exact HUMAN action planning CSV"),
    ("21", "Finalize explicit browser-downloaded PRIVATE HUMAN action CSV"),
    ("22", "Build source-exact PRIVATE single-HUMAN-owner minimum-necessary briefing"),
    ("23", "Compare 2-8 ORIGINAL HUMAN action versions + PRIVATE changes and worklist"),
    ("24", "Combine 2-8 DIFFERENT source-bound HUMAN cases in one private portfolio desk"),
    ("25", "Compare two PRIVATE cross-case HUMAN proposal portfolios as a local delta"),
    ("26", "Create owner-scoped PRIVATE HUMAN handoff workrooms from a previous portfolio"),
    ("27", "Open a PRIVATE date/priority HUMAN planning dayboard from an original portfolio"),
    ("28", "Prepare a filtered PRIVATE HUMAN meeting packet"),
    ("29", "Import source-bound HUMAN meeting decisions as PRIVATE HOLD-only return"),
    ("30", "Create a source-free offline HUMAN focus browser editor"),
    ("31", "Compare 2–8 original PRIVATE HUMAN meeting review return versions"),
    ("32", "Create minimum-necessary PRIVATE HUMAN owner packets from finalized meeting"),
    ("33", "Receive one local original owner human reply into PRIVATE HOLD packet"),
    ("34", "Reconcile 1–8 source-bound owner HUMAN replies in PRIVATE inbox"),
    ("35", "Build source-free offline HUMAN owner reply browser Studio"),
    ("36", "Record original-inbox-bound PRIVATE HUMAN team discussion"),
    ("37", "Build source-free offline multi-owner HUMAN Inbox Studio"),
    ("38", "Export source-bound one-owner PRIVATE HUMAN discussion brief"),
    ("39", "Compare 2–8 original source-exact PRIVATE HUMAN inbox discussions"),
    ("40", "Export one original proposed HUMAN owner's PRIVATE discussion history"),
    ("41", "Build source-free offline original HUMAN inbox timeline browser"),
    ("42", "Native-admit source-bound PRIVATE HUMAN timeline owner selection"),
    ("43", "Prepare separate PRIVATE HUMAN history packets for 1–8 original owners"),
    ("44", "Prepare source-exact PRIVATE HUMAN owner reply template"),
    ("45", "Receive complete original PRIVATE HUMAN owner reply"),
    ("46", "Build source-free offline PRIVATE HUMAN owner reply Studio"),
    ("47", "Reconcile 1–8 source-bound PRIVATE HUMAN owner replies into operator inbox"),
    ("48", "Build portable source-free PRIVATE HUMAN reply operator inbox viewer"),
    ("49", "Prepare original-source PRIVATE HUMAN operator follow-up template"),
    ("50", "Receive original-source PRIVATE HUMAN operator follow-up"),
    ("51", "Build standalone PRIVATE HUMAN operator follow-up Studio"),
    ("52", "Create source-bound per-owner PRIVATE HUMAN follow-up change briefs"),
    ("53", "Build portable offline PRIVATE HUMAN operator change board"),
    ("54", "Compare 2–8 original HUMAN operator versions per private owner"),
    ("55", "Build portable offline ORIGINAL HUMAN operator version explorer"),
    ("56", "Prepare full original-bound PRIVATE HUMAN proposed review calendar CSV"),
    ("57", "Receive complete original-bound HUMAN calendar into PRIVATE owner workrooms"),
    ("58", "Read-only reopen original HUMAN calendar CSV and private receipt"),
    ("59", "Build source-free portable PRIVATE HUMAN proposed-calendar browser Studio"),
    ("60", "Compare 2–8 original PRIVATE HUMAN proposed-calendar versions"),
    ("61", "Start new original-bound HUMAN calendar round blank or explicitly carry proposals"),
    ("62", "Prepare original-bound HUMAN calendar disagreement and decision workroom"),
    ("63", "Native-receive complete original-bound HUMAN calendar decision CSV"),
    ("64", "Build portable offline PRIVATE HUMAN calendar decision browser Studio"),
    ("65", "Read-only reopen complete original HUMAN calendar decision receipt"),
    ("66", "Convert exact completed HUMAN decisions to a new unreviewed calendar DRAFT"),
    ("0", "Exit"),
)


def prompt(label, required=True):
    while True:
        value = input(label + (": " if required else " (Enter to skip): ")).strip()
        if value or not required:
            return value
        print("A path/value is required, no implicit discovery.")


def source_paths():
    paths = []
    print("Enter 1–12 absolute existing PRIVATE kit paths; blank after the first to finish.")
    while len(paths) < 12:
        value = prompt("PRIVATE kit " + str(len(paths) + 1), required=not paths)
        if not value:
            break
        paths.append(value)
    return paths


def labels(paths):
    print("Optional HUMAN labels are metadata; avoid customer/target names on shared terminals.")
    result = [prompt("HUMAN display label for kit " + str(i), False) for i in range(1, len(paths) + 1)]
    if all(not x for x in result):
        return None
    return [v or "PRIVATE kit " + str(i) for i, v in enumerate(result, 1)]


def private_parent():
    return prompt("Existing owner-private 0700 directory OUTSIDE checkout")


def history_paths():
    print("Choose 2-12 ORIGINAL 0600 ledgers in exact capture --previous order.")
    paths = []
    while len(paths) < 12:
        entry = prompt("Original ledger snapshot " + str(len(paths) + 1),
                       required=len(paths) < 2)
        if not entry:
            break
        paths.append(entry)
    return paths


def handle_action(action):
    if action == "1":
        paths = source_paths()
        selected_labels = labels(paths)
        previous = prompt("Exact previous owner-only ledger.json for source change capture", False)
        return ledger.capture(argparse.Namespace(
            kit=paths, label=selected_labels, previous=previous or None,
            private_parent=private_parent()
        ))
    if action == "2":
        return ledger.reopen(argparse.Namespace(
            ledger=prompt("Original owner-only ledger.json")
        ))
    if action == "3":
        return ledger.finalize(argparse.Namespace(
            ledger=prompt("Original owner-only ledger.json"),
            plan=prompt("Human-edited PRIVATE 0600 HUMAN-review.csv"),
            private_parent=private_parent()
        ))
    if action == "4":
        return compare.run(argparse.Namespace(
            before=prompt("Original previous PRIVATE ledger.json"),
            after=prompt("Original current PRIVATE ledger.json"),
            private_parent=private_parent()
        ))
    if action == "13":
        return history.run(argparse.Namespace(
            ledger=history_paths(), private_parent=private_parent()
        ))
    if action in ("14", "15"):
        originals = history_paths()
        csv_path = prompt("Original PRIVATE HUMAN timeline CSV" if action == "14"
                          else "Explicit original browser-downloaded HUMAN-history-review.csv")
        return history_human.finalize(argparse.Namespace(
            ledger=originals,
            plan=csv_path if action == "14" else None,
            browser_csv=csv_path if action == "15" else None,
            private_parent=private_parent()
        ))
    if action == "16":
        print("Select 2-8 distinct original native PRIVATE-HUMAN-history.json packets.")
        reviewer_packets = []
        while len(reviewer_packets) < 8:
            source = prompt("Original HUMAN packet " + str(len(reviewer_packets) + 1),
                            required=len(reviewer_packets) < 2)
            if not source:
                break
            reviewer_packets.append(source)
        return history_team.prepare(argparse.Namespace(
            ledger=history_paths(), reviewer=reviewer_packets,
            private_parent=private_parent()
        ))
    if action in ("17", "18"):
        return history_team.finalize(argparse.Namespace(
            context=prompt("Exact original PRIVATE-team-context.json"),
            csv=prompt("Original PRIVATE HUMAN-team-review.csv") if action == "17" else None,
            browser_csv=prompt("Explicit browser Downloads HUMAN-team-review.csv")
            if action == "18" else None,
            private_parent=private_parent()
        ))
    if action == "19":
        return history_actions.prepare(argparse.Namespace(
            context=prompt("Original PRIVATE-team-context.json"),
            team_choice=prompt("Original PRIVATE-HUMAN-team-choice.json"),
            team_csv=prompt("Original native HUMAN-team-review.csv"),
            private_parent=private_parent()
        ))
    if action in ("20", "21"):
        original = prompt("Original PRIVATE-action-context.json")
        selected = prompt("Owner-private HUMAN-action-plan.csv" if action == "20" else
                          "Explicit browser Downloads HUMAN-action-plan.csv")
        return history_actions.finalize(argparse.Namespace(
            action_context=original,
            plan=selected if action == "20" else None,
            browser_csv=selected if action == "21" else None,
            private_parent=private_parent()
        ))
    if action == "22":
        return history_owner_brief.run(argparse.Namespace(
            action_context=prompt("Original PRIVATE-action-context.json"),
            actions=prompt("Original PRIVATE-HUMAN-actions.json"),
            plan=prompt("Original 0600 HUMAN-action-plan.csv"),
            owner=prompt("EXACT proposed HUMAN owner for minimum-necessary PRIVATE handoff"),
            private_parent=private_parent()
        ))
    if action == "23":
        print("Select 2-8 distinct ORIGINAL native completed action JSON and matching")
        print("HUMAN-action-plan.csv files in deliberate HUMAN comparison order.")
        actions, plans = [], []
        while len(actions) < 8:
            selected = prompt("Original PRIVATE-HUMAN-actions.json " +
                              str(len(actions) + 1), required=len(actions) < 2)
            if not selected:
                break
            original_plan = prompt("Matching original HUMAN-action-plan.csv " +
                                   str(len(actions) + 1))
            actions.append(selected)
            plans.append(original_plan)
        return history_progress.run(argparse.Namespace(
            action_context=prompt("ORIGINAL PRIVATE-action-context.json"),
            actions=actions, plan=plans, private_parent=private_parent()
        ))
    if action == "66":
        receipts, plans = [], []
        print("Choose the EXACT original calendar receipt/CSV rounds used in the HUMAN decision.")
        while len(receipts) < 8:
            packet = prompt("Original PRIVATE-HUMAN-proposed-calendar.json " +
                            str(len(receipts) + 1), required=len(receipts) < 2)
            if not packet:
                break
            receipts.append(packet)
            plans.append(prompt("Matching ORIGINAL complete HUMAN calendar CSV"))
        return portfolio_operator_calendar_decision_handoff.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=prompt("Original PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Matching original complete HUMAN operator follow-up CSV"),
            calendar_receipts=receipts,
            proposed_csvs=plans,
            decisions_csv=prompt("Original complete PRIVATE-HUMAN-decision-original.csv"),
            decision_receipt=prompt("Matching original PRIVATE-HUMAN-decision-receipt.json"),
            private_parent=private_parent(),
        ))
    if action == "64":
        return portfolio_operator_calendar_decision_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW owner-private HUMAN decision Studio .html")
        ))
    if action in ("62", "63", "65"):
        receipts, plans = [], []
        print("Choose 2–8 ORIGINAL full native HUMAN calendar receipt/CSV pairs.")
        while len(receipts) < 8:
            receipt = prompt("Original PRIVATE-HUMAN-proposed-calendar.json " +
                             str(len(receipts) + 1), required=len(receipts) < 2)
            if not receipt:
                break
            receipts.append(receipt)
            plans.append(prompt("Matching ORIGINAL full HUMAN calendar CSV"))
        return portfolio_operator_calendar_decisions.run(argparse.Namespace(
            mode="prepare" if action == "62" else ("receive" if action == "63" else "reopen"),
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=prompt("Original PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Matching original full HUMAN operator CSV"),
            calendar_receipts=receipts,
            proposed_csvs=plans,
            decisions_csv=prompt("Complete HUMAN-calendar-decision-template.csv")
            if action in ("63", "65") else None,
            decision_receipt=prompt("Original PRIVATE-HUMAN-decision-receipt.json")
            if action == "65" else None,
            private_parent=private_parent(),
        ))
    if action == "61":
        selected = prompt("Start next HUMAN-only calendar BLANK or CARRY prior proposals? blank/carry").lower()
        if selected not in ("blank", "carry"):
            ledger.reject("PRIVATE HOLD: explicit blank or carry required")
        return portfolio_operator_calendar_continuity.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=prompt("Original completed PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Matching original operator HUMAN follow-up CSV"),
            previous_csv=prompt("Original completed PRIVATE-HUMAN-proposed-calendar.csv"),
            previous_receipt=prompt("Matching native original PRIVATE-HUMAN-proposed-calendar.json"),
            reference_day=prompt("NEW explicit HUMAN reference day 20xx-mm-dd"),
            mode=selected,
            private_parent=private_parent(),
        ))
    if action == "60":
        receipts, plans = [], []
        print("Choose 2–8 ORIGINAL complete HUMAN calendar receipt/CSV pairs.")
        while len(receipts) < 8:
            receipt = prompt("Original PRIVATE-HUMAN-proposed-calendar.json " +
                             str(len(receipts) + 1), required=len(receipts) < 2)
            if not receipt:
                break
            receipts.append(receipt)
            plans.append(prompt("Matching ORIGINAL complete HUMAN calendar CSV"))
        return portfolio_operator_calendar_history.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=prompt("Original PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Original complete HUMAN operator follow-up CSV"),
            calendar_receipts=receipts,
            proposed_csvs=plans,
            changed_only=prompt("Only changed HUMAN proposals? y/n").lower() == "y",
            private_parent=private_parent(),
        ))
    if action == "59":
        return portfolio_operator_calendar_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW source-free HUMAN calendar Studio .html in owner-private folder")
        ))
    if action in ("56", "57", "58"):
        return portfolio_operator_calendar.run(argparse.Namespace(
            mode="prepare" if action == "56" else ("receive" if action == "57" else "reopen"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            followup=prompt("Original native PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Matching original complete HUMAN operator follow-up CSV"),
            proposed_csv=prompt("Edited complete HUMAN-proposed-calendar-template.csv")
            if action in ("57", "58") else None,
            receipt=prompt("Original PRIVATE-HUMAN-proposed-calendar.json")
            if action == "58" else None,
            reference_day=prompt("Explicit HUMAN reference day 20xx-mm-dd (not real booking)"),
            private_parent=private_parent(),
        ))
    if action == "55":
        return portfolio_owner_change_history_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW PRIVATE HUMAN version Studio .html inside 0700 parent")
        ))
    if action == "54":
        originals, csvs = [], []
        while len(originals) < 8:
            packet = prompt("ORIGINAL HUMAN operator reply " + str(len(originals)+1),
                            required=len(originals)<2)
            if not packet:
                break
            originals.append(packet)
            csvs.append(prompt("Matching complete original HUMAN operator CSV"))
        return portfolio_owner_change_history.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=originals, operator_csv=csvs,
            private_parent=private_parent()
        ))
    if action == "53":
        return portfolio_owner_change_board.build(argparse.Namespace(
            output=prompt("Absolute NEW PRIVATE HUMAN owner change-board .html in 0700 directory")
        ))
    if action == "52":
        return portfolio_owner_change_briefs.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            followup=prompt("Original native PRIVATE-HUMAN-operator-followup.json"),
            operator_csv=prompt("Matching original PRIVATE-HUMAN-original-operator-followup.csv"),
            private_parent=private_parent(),
            changed_only=prompt("Only changed HUMAN proposals or private notes? y/n").strip().lower() == "y"
        ))
    if action == "51":
        return portfolio_owner_followup_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW PRIVATE operator HUMAN follow-up .html in 0700 directory")
        ))
    if action in ("49", "50"):
        return portfolio_owner_followup.run(argparse.Namespace(
            mode="prepare" if action == "49" else "receive",
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            followup_csv=prompt("Complete HUMAN-operator-followup-template.csv")
            if action == "50" else None,
            private_parent=private_parent()
        ))
    if action == "48":
        return portfolio_owner_inbox_viewer.build(argparse.Namespace(
            output=prompt("Absolute NEW PRIVATE HUMAN reply inbox .html in 0700 directory")
        ))
    if action == "47":
        packets, selections, replies, edited = [], [], [], []
        print("Choose 1–8 matching original owner JSON, selected CSV, native HUMAN reply JSON and edited reply CSV quartets.")
        while len(packets) < 8:
            pth = prompt("Original owner selection JSON " + str(len(packets)+1),
                         required=not packets)
            if not pth:
                break
            packets.append(pth)
            selections.append(prompt("Matching original owner selection CSV"))
            replies.append(prompt("Matching original native HUMAN owner reply JSON"))
            edited.append(prompt("Matching complete edited HUMAN owner reply CSV"))
        return portfolio_inbox_owner_reconcile.run(argparse.Namespace(
            history=prompt("ONE original PRIVATE-HUMAN-inbox-history.json"),
            selection=packets, selection_csv=selections,
            reply=replies, reply_csv=edited, private_parent=private_parent()
        ))
    if action == "46":
        return portfolio_inbox_owner_return_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW source-free owner HUMAN reply .html in 0700 folder")
        ))
    if action in ("44", "45"):
        return portfolio_inbox_owner_return.run(argparse.Namespace(
            mode="prepare" if action == "44" else "receive",
            selection=prompt("Original PRIVATE-HUMAN-history-selection.json"),
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            selection_csv=prompt("Original PRIVATE-HUMAN-original-selection.csv"),
            reply_csv=prompt("Completed original HUMAN-owner-history-reply-template.csv")
            if action == "45" else None,
            private_parent=private_parent()
        ))
    if action == "43":
        owners, selections = [], []
        print("Select 1–8 exact original HUMAN owner labels and their source-bound CSVs.")
        while len(owners) < 8:
            owner = prompt("Original HUMAN owner label " + str(len(owners)+1),
                           required=not owners)
            if not owner:
                break
            selected = prompt("Matching explicit PRIVATE HUMAN browser-selection.csv")
            owners.append(owner)
            selections.append(selected)
        return portfolio_inbox_timeline_batch.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            owner=owners, selection_csv=selections,
            private_parent=private_parent()
        ))
    if action == "42":
        return portfolio_inbox_timeline_selection.run(argparse.Namespace(
            history=prompt("Original PRIVATE-HUMAN-inbox-history.json"),
            selection_csv=prompt("Explicit browser-downloaded PRIVATE HUMAN owner selection CSV"),
            owner=prompt("EXACT ORIGINAL proposed HUMAN owner label"),
            private_parent=private_parent()
        ))
    if action == "41":
        return portfolio_inbox_timeline.build(argparse.Namespace(
            output=prompt("Absolute NEW source-free HUMAN timeline .html in 0700 PRIVATE folder")
        ))
    if action in ("39", "40"):
        print("Choose 2–8 original inbox HUMAN discussions and their matching CSVs.")
        rounds, original_csvs = [], []
        while len(rounds) < 8:
            path = prompt("Original finalized HUMAN discussion " + str(len(rounds) + 1),
                          required=len(rounds) < 2)
            if not path:
                break
            csv_path = prompt("Corresponding original complete HUMAN-inbox-review-template.csv")
            rounds.append(path)
            original_csvs.append(csv_path)
        return portfolio_inbox_history.run(argparse.Namespace(
            inbox=prompt("ORIGINAL PRIVATE-HUMAN-owner-inbox.json"),
            discussion=rounds, review_csv=original_csvs,
            owner=prompt("EXACT original proposed HUMAN owner (minimum-necessary)", True)
            if action == "40" else None,
            private_parent=private_parent()
        ))
    if action == "38":
        return portfolio_owner_attention.run(argparse.Namespace(
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            discussion=prompt("Original finalized PRIVATE-HUMAN-inbox-review.json"),
            original_review_csv=prompt("Original HUMAN-inbox-review-template.csv"),
            owner=prompt("Exact original proposed HUMAN owner label"),
            private_parent=private_parent()
        ))
    if action == "37":
        return portfolio_inbox_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW 0600 .html in original 0700 PRIVATE folder")
        ))
    if action == "36":
        return portfolio_owner_inbox_review.run(argparse.Namespace(
            inbox=prompt("Original PRIVATE-HUMAN-owner-inbox.json"),
            review=prompt("Original edited HUMAN-inbox-review-template.csv"),
            private_parent=private_parent()
        ))
    if action == "35":
        return portfolio_owner_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW .html software path in original 0700 PRIVATE folder")
        ))
    if action == "34":
        originals, returns, csvs = [], [], []
        print("Choose 1–8 original exact owner-packet/reply/CSV triples.")
        while len(originals) < 8:
            path = prompt("PRIVATE-HUMAN-owner.json " + str(len(originals) + 1),
                          required=not originals)
            if not path:
                break
            response = prompt("Corresponding original PRIVATE-HUMAN-owner-reply.json")
            csv_file = prompt("Matching original 0600 HUMAN owner reply CSV")
            originals.append(path)
            returns.append(response)
            csvs.append(csv_file)
        return portfolio_owner_inbox.run(argparse.Namespace(
            portfolio=prompt("Original PRIVATE-HUMAN-portfolio.json"),
            meeting=prompt("Original PRIVATE-HUMAN-meeting.json"),
            review_return=prompt("Original PRIVATE-HUMAN-review-return.json"),
            owner_packet=originals, owner_reply=returns, reply_csv=csvs,
            private_parent=private_parent()
        ))
    if action == "33":
        return portfolio_owner_reply.run(argparse.Namespace(
            owner_packet=prompt("Original 0600 PRIVATE-HUMAN-owner.json"),
            review=prompt("Original source-bound edited HUMAN-owner-reply-template.csv"),
            private_parent=private_parent()
        ))
    if action == "32":
        owners = []
        print("Choose 1–8 EXACT original proposed HUMAN owner labels.")
        while len(owners) < 8:
            item = prompt("Original proposed HUMAN owner label " + str(len(owners) + 1),
                          required=not owners)
            if not item:
                break
            owners.append(item)
        return portfolio_focus_owner_handoff.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            meeting=prompt("Original PRIVATE-HUMAN-meeting.json"),
            review_return=prompt("Original PRIVATE-HUMAN-review-return.json"),
            owner=owners, private_parent=private_parent()
        ))
    if action == "31":
        print("Choose 2–8 original source-bound HUMAN meeting return JSONs, in historical order.")
        versions = []
        while len(versions) < 8:
            path = prompt("Original PRIVATE HUMAN review return version " + str(len(versions) + 1),
                          required=len(versions) < 2)
            if not path:
                break
            versions.append(path)
        return portfolio_focus_history.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            meeting=prompt("Original PRIVATE-HUMAN-meeting.json"),
            returns=versions, private_parent=private_parent()
        ))
    if action == "30":
        return portfolio_focus_studio.build(argparse.Namespace(
            output=prompt("Absolute NEW offline HTML path within existing PRIVATE 0700 parent")
        ))
    if action == "29":
        return portfolio_focus_review.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            meeting=prompt("Original PRIVATE-HUMAN-meeting.json"),
            review=prompt("0600 HUMAN-meeting-review-template.csv edited locally"),
            private_parent=private_parent()
        ))
    if action == "28":
        print("Priorities: human_urgent,near_term,routine,unset")
        print("Buckets: past_proposed_day,selected_reference_day,later_proposed_day,no_proposed_day")
        return portfolio_focus.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            reference_day=prompt("Explicit yyyy-mm-dd HUMAN reference day"),
            owner=prompt("EXACT proposed HUMAN owner (blank for all)", False) or None,
            title=prompt("PRIVATE HUMAN meeting title"),
            priority=[v.strip() for v in prompt("Comma-separated priorities").split(",")],
            bucket=[v.strip() for v in prompt("Comma-separated day buckets").split(",")],
            private_parent=private_parent()
        ))
    if action == "27":
        return portfolio_dayboard.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            reference_day=prompt("Manually SELECTED yyyy-mm-dd historical HUMAN reference day"),
            owner=prompt("EXACT original proposed HUMAN owner (blank for all)", False) or None,
            private_parent=private_parent()
        ))
    if action == "26":
        print("Choose 1–8 EXACT proposed HUMAN owner labels for SEPARATE local workrooms.")
        owners = []
        while len(owners) < 8:
            name = prompt("Exact HUMAN owner label " + str(len(owners) + 1),
                          required=not owners)
            if not name:
                break
            owners.append(name)
        return portfolio_owner_packets.run(argparse.Namespace(
            portfolio=prompt("ORIGINAL PRIVATE-HUMAN-portfolio.json"),
            owner=owners, private_parent=private_parent()
        ))
    if action == "25":
        return portfolio_delta.run(argparse.Namespace(
            before=prompt("ORIGINAL previous PRIVATE-HUMAN-portfolio.json"),
            after=prompt("ORIGINAL later PRIVATE-HUMAN-portfolio.json"),
            private_parent=private_parent()
        ))
    if action == "24":
        print("Choose 2–8 DIFFERENT original private HUMAN action cases.")
        print("Each case needs its exact original source context + native action JSON/CSV.")
        contexts, actions, plans = [], [], []
        while len(contexts) < 8:
            context = prompt("Original case context " + str(len(contexts) + 1),
                             required=len(contexts) < 2)
            if not context:
                break
            selected_actions = prompt("Corresponding ORIGINAL HUMAN actions JSON")
            selected_plan = prompt("Corresponding ORIGINAL HUMAN action-plan CSV")
            contexts.append(context)
            actions.append(selected_actions)
            plans.append(selected_plan)
        return portfolio.run(argparse.Namespace(
            context=contexts, actions=actions, plan=plans,
            owner=prompt("EXACT proposed HUMAN owner filter (blank for all)", False) or None,
            private_parent=private_parent()
        ))
    if action == "5":
        return continuity.run(argparse.Namespace(
            previous=prompt("Original PRIVATE previous ledger.json"),
            human=prompt("Native old HUMAN-only.json from finalize"),
            current=prompt("Original current ledger.json from capture --previous"),
            private_parent=private_parent()
        ))
    if action in ("11", "12"):
        return browser_intake.import_browser(argparse.Namespace(
            ledger=prompt("Original owner-private ledger.json"),
            csv=prompt("Explicit original browser download HUMAN-review.csv"),
            private_parent=private_parent(),
            finalize=(action == "12")
        ))
    if action == "9":
        output = prompt("Absolute new source-only software ZIP path in owner-private folder")
        sidecar = prompt("Create detached adjacent .sha256 sidecar? [y/N]", False).lower()
        return package.build(argparse.Namespace(
            output=output, sha256_sidecar=sidecar in ("y", "yes")
        ))
    if action == "10":
        archive = prompt("Absolute existing LightUp source-only software ZIP")
        sidecar = prompt("Verify adjacent .sha256 sidecar? [y/N]", False).lower()
        return package.inspect(argparse.Namespace(
            archive=archive, sha256_sidecar=sidecar in ("y", "yes")
        ))
    if action == "8":
        return human_revisions.run(argparse.Namespace(
            ledger=prompt("Exact original PRIVATE ledger.json"),
            before=prompt("Original earlier native HUMAN-only.json"),
            after=prompt("Original later native HUMAN-only.json"),
            private_parent=private_parent()
        ))
    if action == "6":
        parent = private_parent()
        ledger.private_parent(parent)
        name = prompt("Name for NEW standalone local .html software file (no /)")
        if "/" in name or "\\" in name or name in (".", "..") or not name.endswith(".html"):
            ledger.reject("PRIVATE HOLD: enter plain .html filename only")
        path = os.path.join(parent, name)
        data = render_studio().encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            at = 0
            while at < len(data):
                at += os.write(fd, data[at:])
            os.fsync(fd)
        finally:
            os.close(fd)
        print("PRIVATE REVIEW_ONLY: standalone offline software generated at " + path)
        return 2
    return 3


def console():
    print(TITLE)
    print("INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. This console NEVER grants permission.")
    print("Do not process unapproved original client data or run against active targets.")
    session = []
    while True:
        print("\n" + "\n".join(number + ". " + label for number, label in MENU))
        try:
            choice = input("Choose a foreground action: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nPRIVATE session ended; no background work started.")
            break
        if choice == "0":
            break
        if choice == "7":
            if not session:
                print("No local HUMAN operations in this session.")
            else:
                for ordinal, (step, state) in enumerate(session, 1):
                    print(str(ordinal) + ". " + step + ": " + state +
                          " (never permission, never confirmed security)")
            continue
        if choice not in {number for number, _ in MENU if number not in ("0", "7")}:
            print("Select a listed action.")
            continue
        try:
            status = handle_action(choice)
        except (ledger.Hold, OSError, ValueError, UnicodeError):
            print("PRIVATE HOLD: original/private inputs rejected; no external action.", file=sys.stderr)
            status = 3
        except (EOFError, KeyboardInterrupt):
            print("\nPRIVATE selection cancelled, no retry scheduled.")
            status = 3
        session.append((choice, "REVIEW_ONLY" if status == 2 else "HOLD"))
        print("Action status: " + ("REVIEW_ONLY (2)" if status == 2 else "HOLD (3)") +
              ". No PASS, consent, verified finding or authorization.")
    print("PRIVATE session closed; nothing queued, sent, deleted or deployed.")
    return 3  # Console sessions are never approval or a release signal.


if __name__ == "__main__":
    raise SystemExit(console())
