#!/usr/bin/env python3
"""PRIVATE source-bound consolidated HUMAN workroom status.

A read-only, no-network view over the ORIGINAL lab source and optionally the
received HUMAN reply and HUMAN sender triage. Never infers verified findings,
real ownership, consent, remediations, dispatch or active runtime state.
"""
from __future__ import annotations

import argparse
import collections
import csv
import io
import sys

from curate import (
    Hold, MAX_CSV_BYTES, MAX_RECEIPT_BYTES, PRIORITIES, SEVERITIES,
    UNVERIFIED, digest, h, json_bytes, publish_new,
)
from human_return import read_limited_file
from response import (
    accepted_original, admit_response_binding, admit_returned_reply, csv_template,
)
from recipient_studio import render_studio as render_recipient_studio
from response_triage import (
    binding_fields, read_binding, read_triage, triage_template,
)
from triage_studio import render_studio as render_triage_studio
from revision import private_frame
from hub_browser import render_browser

PHASES = ("awaiting_human_recipient", "recipient_self_reported",
          "sender_human_followup_recorded")
RECIPIENT_STAGES = ("no_human_response", "responded_claimed",
                    "needs_more_information", "blocked_human")
ROUTES = ("unreviewed", "needs_human_review", "request_clarification",
          "route_to_owner", "documented_for_followup")
MAX_REPORT_ITEMS = 64


def admit_all(source_path: str, manifest_path: str, worksheet_path: str,
              receipt_path: str, selection_path: str,
              response_binding: str | None, response_path: str | None,
              triage_binding: str | None, triage_path: str | None):
    if (response_binding is None) != (response_path is None):
        raise Hold("HOLD: PRIVATE recipient binding and HUMAN reply are a pair")
    if (triage_binding is None) != (triage_path is None):
        raise Hold("HOLD: PRIVATE triage binding and worksheet are a pair")
    if triage_binding and not response_binding:
        raise Hold("HOLD: HUMAN sender triage requires original recipient reply")

    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, receipt_path, selection_path)
    if len(selected) > MAX_REPORT_ITEMS:
        raise Hold("HOLD: source HUMAN selection exceeds private report limit")

    response_raw = None
    triage_raw = None
    recipients = None
    triaged = None
    if response_binding is not None:
        admit_response_binding(
            read_limited_file(response_binding, MAX_RECEIPT_BYTES),
            source_sha, worksheet_sha, digest(selection_raw),
            digest(csv_template(source, selected)),
            digest(render_recipient_studio(source, selected)), len(selected)
        )
        response_raw = read_limited_file(response_path, MAX_CSV_BYTES)
        recipients = admit_returned_reply(response_raw, source, selected)
    if triage_binding is not None:
        binding = binding_fields(
            source_sha, worksheet_sha, digest(selection_raw),
            digest(response_raw), digest(triage_template(recipients)),
            len(recipients), digest(render_triage_studio(recipients))
        )
        read_binding(read_limited_file(triage_binding, MAX_RECEIPT_BYTES), binding)
        triage_raw = read_limited_file(triage_path, MAX_CSV_BYTES)
        triaged = read_triage(triage_raw, recipients)
    return (source, source_sha, worksheet_sha, selection_raw, selected,
            response_raw, recipients, triage_raw, triaged)


def build_rows(source: dict, selected: list[dict],
               recipients: list[dict] | None, triage: list[dict] | None):
    recip_by_original = {} if recipients is None else {
        r["ordinal"]: r for r in recipients
    }
    triage_by_original = {} if triage is None else {
        r["ordinal"]: r for r in triage
    }
    items = []
    for item in selected:
        ordinal = item["ordinal"]
        source_record = source["findings"][ordinal - 1]
        response = recip_by_original.get(ordinal)
        sender = triage_by_original.get(ordinal)
        response_stage = (response["recipient_reported_stage"]
                          if response is not None else "no_human_response")
        human_route = (sender["sender_human_route"]
                       if sender is not None else "unreviewed")
        # This is a descriptive HUMAN document phase, not a run/task status.
        phase = ("sender_human_followup_recorded" if sender is not None and
                 human_route != "unreviewed"
                 else "recipient_self_reported" if response_stage !=
                 "no_human_response" else "awaiting_human_recipient")
        items.append({
            "original_ordinal": ordinal,
            "source_reported_severity": source_record["severity"],
            "original_evidence_reference_count": len(source_record["evidence_ids"]),
            "human_priority": item["priority"],
            "human_question": item["question"],
            "recipient_human_stage": response_stage,
            "recipient_human_reply": "" if response is None else response["recipient_human_reply"],
            "recipient_human_next_question": "" if response is None else response["recipient_human_next_question"],
            "sender_human_route": human_route,
            "sender_human_owner_group": "" if sender is None else sender["sender_human_owner_group"],
            "sender_human_next_question": "" if sender is None else sender["sender_human_next_question"],
            "human_document_phase": phase,
        })
    return items


def by_count(rows: list[dict], key: str, labels: tuple[str, ...]) -> dict[str, int]:
    count = collections.Counter(r[key] for r in rows)
    return {label: count[label] for label in labels}


def human_action(row: dict) -> str:
    route = row["sender_human_route"]
    if route == "route_to_owner":
        return "HUMAN: privately coordinate the proposed group and next question"
    if route == "request_clarification":
        return "HUMAN: review the clarification question before PRIVATE routing"
    if route == "needs_human_review":
        return "HUMAN: independently review original source evidence"
    if route == "documented_for_followup":
        return "HUMAN: consider follow-up documentation; no fix is verified"
    if row["recipient_human_stage"] == "responded_claimed":
        return "HUMAN: inspect the claimed answer against original evidence"
    if row["recipient_human_stage"] == "needs_more_information":
        return "HUMAN: determine what additional original evidence is required"
    if row["recipient_human_stage"] == "blocked_human":
        return "HUMAN: discuss the self-reported blocker"
    return "HUMAN: await separately approved recipient response; no message sent"


def human_review_queue(rows: list[dict]) -> bytes:
    """Local proposed HUMAN action list; NO actual queue, assignment or dispatch.

    Only original ordinal and canonical source-reported severity, HUMAN priority
    and self-reported workflow fields. Does not export raw original targets,
    client IDs, findings, evidence or human freeform questions/replies.
    """
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow((
        "original_ordinal", "source_reported_severity", "human_priority",
        "recipient_human_stage", "sender_human_route",
        "proposed_human_next_action_not_executed",
    ))
    rank = {key: i for i, key in enumerate(("urgent", "soon", "routine"))}
    for row in sorted(rows, key=lambda r: (
            rank[r["human_priority"]], r["original_ordinal"])):
        writer.writerow((
            row["original_ordinal"], row["source_reported_severity"],
            row["human_priority"], row["recipient_human_stage"],
            row["sender_human_route"], human_action(row),
        ))
    return output.getvalue().encode("utf-8")


def label_cards(counts: dict[str, int], caption: str) -> str:
    return ("<section class='card'><h2>" + h(caption) + "</h2>" +
            "".join("<p><strong>" + h(name) + ":</strong> " + str(value) +
                    "</p>" for name, value in counts.items()) + "</section>")


def render_hub(rows: list[dict], reported_total: int,
               bundle_stage: str, priority: str | None = None) -> bytes:
    selected = [row for row in rows if priority is None or
                row["human_priority"] == priority]
    parts = []
    for row in selected:
        detail = [
            ("Original HUMAN question", row["human_question"]),
            ("Recipient HUMAN reply (UNVERIFIED)", row["recipient_human_reply"]),
            ("Recipient HUMAN follow-up question", row["recipient_human_next_question"]),
            ("Sender HUMAN owner/group (NOT authenticated)",
             row["sender_human_owner_group"]),
            ("Sender HUMAN next question", row["sender_human_next_question"]),
        ]
        private_notes = "".join("<h3>" + h(title) + "</h3><pre>" +
                                h(data or "Not recorded") + "</pre>"
                                for title, data in detail)
        parts.append(
            "<article><h2>Original ordinal #" + str(row["original_ordinal"]) +
            " · HUMAN " + h(row["human_priority"]) + "</h2>"
            "<p>Source-reported severity: <strong>" +
            h(row["source_reported_severity"]) +
            "</strong> · original evidence-reference count: " +
            str(row["original_evidence_reference_count"]) + "</p>"
            "<p>HUMAN document phase: <strong>" +
            h(row["human_document_phase"]) +
            "</strong> · recipient HUMAN stage: " +
            h(row["recipient_human_stage"]) + " · sender HUMAN route: " +
            h(row["sender_human_route"]) + "</p>"
            "<p><strong>Suggested HUMAN-only next action (NOT executed):</strong> " +
            h(human_action(row)) + "</p>"
            "<details><summary>Show PRIVATE HUMAN questions and replies</summary>" +
            private_notes + "</details></article>"
        )
    phase_counts = by_count(selected, "human_document_phase", PHASES)
    priority_counts = by_count(selected, "human_priority", PRIORITIES)
    route_counts = by_count(selected, "sender_human_route", ROUTES)
    response_counts = by_count(selected, "recipient_human_stage", RECIPIENT_STAGES)
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN assessment workroom overview</h1>"
        "<p class='notice'>REVIEW ONLY · No producer authenticity, verified finding,"
        " actual owner, client consent, operator consent, source evidence, grant,"
        " revocation, remediation, live runtime, scanner dispatch or release"
        " is established by this report or any source-reported stage.</p>"
        "<p>This is a local HUMAN document handoff, not a live assessment queue."
        " Nothing is sent, approved, rescanned or scheduled automatically.</p>"
        "<p>Source-identifier-minimized fields only, but HUMAN freeform questions,"
        " group names and recipient replies can still identify clients."
        " Keep all report pages PRIVATE and separately review disclosure.</p>"
        "<p>Original source-reported findings: " + str(reported_total) +
        " · selected in this PRIVATE view: " + str(len(selected)) +
        " · HUMAN available document stage: " + h(bundle_stage) + "</p></header>"
    )
    body += label_cards(phase_counts, "HUMAN document phase")
    body += label_cards(priority_counts, "HUMAN priority (UNVERIFIED)")
    body += label_cards(response_counts, "Recipient HUMAN stages")
    body += label_cards(route_counts, "Sender HUMAN follow-up routes")
    return private_frame("PRIVATE HUMAN workroom overview",
                         body + "".join(parts))


def build(source_path: str, manifest_path: str, worksheet_path: str,
          receipt_path: str, selection_path: str,
          response_binding: str | None, response_path: str | None,
          triage_binding: str | None, triage_path: str | None,
          destination: str) -> None:
    (source, source_sha, worksheet_sha, selected_bytes, selected,
     recipient_bytes, recipient_notes, triage_bytes, triage_notes) = admit_all(
        source_path, manifest_path, worksheet_path, receipt_path, selection_path,
        response_binding, response_path, triage_binding, triage_path
    )
    records = build_rows(source, selected, recipient_notes, triage_notes)
    document_stage = ("HUMAN_SENDER_TRIAGE_AVAILABLE" if triage_notes is not None
                      else "HUMAN_RECIPIENT_REPLY_AVAILABLE" if recipient_notes is not None
                      else "HUMAN_SELECTION_ONLY")
    master = render_hub(records, len(source["findings"]), document_stage)
    interactive = render_browser(
        [dict(row, human_action=human_action(row)) for row in records],
        len(source["findings"]), document_stage
    )
    action_queue = human_review_queue(records)
    priorities = {
        priority: render_hub(records, len(source["findings"]), document_stage,
                             priority)
        for priority in PRIORITIES
        if any(r["human_priority"] == priority for r in records)
    }
    aggregate = {
        "schema": "lightup.private_human_assessment_overview_counts.v1",
        "status": "REVIEW_ONLY",
        "human_document_stage": document_stage,
        "original_source_reported_finding_count": len(source["findings"]),
        "human_selected_original_ordinal_count": len(records),
        "human_document_phase_counts":
            by_count(records, "human_document_phase", PHASES),
        "human_priority_counts": by_count(records, "human_priority", PRIORITIES),
        "recipient_self_reported_stage_counts":
            by_count(records, "recipient_human_stage", RECIPIENT_STAGES),
        "sender_self_reported_route_counts": by_count(records, "sender_human_route", ROUTES),
        "source_identifiers_included": False,
        **UNVERIFIED,
    }
    receipt = {
        "schema": "lightup.private_human_assessment_overview_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_human_worksheet_sha256_unsigned": worksheet_sha,
        "human_selection_sha256_unsigned": digest(selected_bytes),
        "recipient_human_response_sha256_unsigned":
            None if recipient_bytes is None else digest(recipient_bytes),
        "sender_human_triage_sha256_unsigned":
            None if triage_bytes is None else digest(triage_bytes),
        "private_master_overview_sha256_unsigned": digest(master),
        "private_interactive_workroom_sha256_unsigned": digest(interactive),
        "private_human_review_queue_sha256_unsigned": digest(action_queue),
        "private_priority_overview_sha256_unsigned": {
            priority: digest(contents) for priority, contents in priorities.items()
        },
        "selected_original_ordinals": [r["original_ordinal"] for r in records],
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-HUMAN-assessment-overview.html": master,
        "PRIVATE-HUMAN-interactive-workroom.html": interactive,
        "PRIVATE-HUMAN-review-candidates-NOT-DISPATCHED.csv": action_queue,
        "PRIVATE-HUMAN-assessment-overview-receipt.json": json_bytes(receipt),
        "PRIVATE-HUMAN-assessment-overview-counts.json": json_bytes(aggregate),
        **{
            "PRIVATE-HUMAN-priority-" + priority + "-overview.html": contents
            for priority, contents in priorities.items()
        }
    })


def main() -> int:
    p = argparse.ArgumentParser(
        description="Consolidate existing PRIVATE source-bound HUMAN documents, no assessment")
    for name in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "output-dir"):
        p.add_argument("--" + name, required=True)
    for name in ("response-binding", "response", "triage-binding", "triage"):
        p.add_argument("--" + name)
    args = p.parse_args()
    try:
        build(args.source, args.manifest, args.worksheet, args.selection_receipt,
              args.selection, args.response_binding, args.response,
              args.triage_binding, args.triage, args.output_dir)
    except Hold:
        print("HOLD: PRIVATE original source/HUMAN document bundle rejected; no output published",
              file=sys.stderr)
        return 3
    print("PRIVATE HUMAN document overview generated, REVIEW ONLY; NO target or grant")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
