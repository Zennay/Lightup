#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN proposed next-question selection, no assessment.

Builds a new optional HUMAN selection proposal from an ALREADY produced
original source, original recipient HUMAN reply, and explicitly saved HUMAN
sender triage. Never dispatches an activity or infers a fixed finding.
"""
from __future__ import annotations

import argparse
import csv
import io
import sys

from curate import (HEADER, Hold, UNVERIFIED, digest, json_bytes,
                    read_original, read_receipt, read_selection,
                    MAX_CSV_BYTES, MAX_RECEIPT_BYTES)
from briefing import h, publish_new
from human_return import read_limited_file
from response_triage import (original_reply, triage_template, binding_fields,
                             read_binding, read_triage)
from revision import private_frame


def propose(source_path: str, manifest_path: str, worksheet_path: str,
            receipt_path: str, selection_path: str, response_binding: str,
            response_path: str, triage_binding: str, triage_path: str,
            destination: str) -> None:
    source, source_sha, human_sha, selection_sha, response_raw, notes = original_reply(
        source_path, manifest_path, worksheet_path, receipt_path,
        selection_path, response_binding, response_path
    )
    triage_blank = triage_template(notes)
    expected = binding_fields(source_sha, human_sha, selection_sha,
                              digest(response_raw), digest(triage_blank),
                              len(notes), digest(__import__("triage_studio").render_studio(notes)))
    read_binding(read_limited_file(triage_binding, MAX_RECEIPT_BYTES), expected)
    triage_raw = read_limited_file(triage_path, MAX_CSV_BYTES)
    reviewed = read_triage(triage_raw, notes)

    prior = {record["ordinal"]: record for record in notes}
    changed = {}
    for row in reviewed:
        if row["sender_human_route"] not in ("request_clarification", "route_to_owner"):
            continue
        next_question = row["sender_human_next_question"]
        if next_question and next_question != row["original_question"]:
            changed[row["ordinal"]] = {
                "ordinal": row["ordinal"],
                "human_route": row["sender_human_route"],
                "human_owner_group": row["sender_human_owner_group"],
                "prior_question": row["original_question"],
                "proposed_question": next_question,
            }
    if not changed:
        raise Hold("HOLD: no new HUMAN questions proposed, no new selection published")

    document = io.StringIO(newline="")
    writer = csv.writer(document, lineterminator="\r\n")
    writer.writerow(HEADER)
    for ordinal, finding in enumerate(source["findings"], 1):
        item = prior.get(ordinal)
        if item is None:
            writer.writerow((ordinal, finding["severity"],
                             len(finding["evidence_ids"]), "", "", ""))
        else:
            question = (changed[ordinal]["proposed_question"]
                        if ordinal in changed else item["original_question"])
            writer.writerow((ordinal, finding["severity"],
                             len(finding["evidence_ids"]), "yes",
                             item["priority"], question))
    selection_bytes = document.getvalue().encode("utf-8")
    if len(selection_bytes) > MAX_CSV_BYTES:
        raise Hold("HOLD: PRIVATE proposed selection too large")

    groups = ("request_clarification", "route_to_owner")
    html_blocks = []
    for item in changed.values():
        html_blocks.append(
            "<article><h2>Original ordinal #" + str(item["ordinal"]) +
            " · HUMAN " + h(item["human_route"]) + "</h2>"
            "<p>HUMAN owner/group proposal (NOT authenticated): " +
            h(item["human_owner_group"] or "Unassigned") + "</p>"
            "<h3>Prior original HUMAN question</h3><pre>" +
            h(item["prior_question"]) + "</pre>"
            "<h3>Proposed next HUMAN question</h3><pre>" +
            h(item["proposed_question"]) + "</pre>"
            "<div class='worksheet'>Human operator: accept new proposed question?"
            " _________ · Separate PRIVATE disclosure approval: __________</div></article>"
        )
    report = private_frame(
        "PRIVATE source-bound HUMAN next-round question proposal",
        "<header><h1>LightUp · PRIVATE next HUMAN reply round proposal</h1>"
        "<p class='notice'>REVIEW ONLY — this prepares a NEW optional HUMAN question"
        " CSV, not a new lab assessment or permission to contact targets."
        " Original producer, client/recipient identity, consent, findings,"
        " claimed fixes, evidence, risk and authorization remain UNVERIFIED.</p>"
        "<p>Every original source finding ordinal, severity and evidence-count"
        " remains bound to the same original source. All originally selected"
        " findings stay selected; no missing response becomes fixed. Only"
        " explicitly HUMAN-routed changed questions are proposed.</p>"
        "<p>HUMAN next-round questions changed: " + str(len(changed)) +
        ". A human must deliberately inspect the PRIVATE proposal and independently"
        " choose to use it. Nothing is sent, no appointment scheduled.</p>"
        "<p>Original targets/evidence/tenant/finding IDs are not included in this"
        " HUMAN-only brief. Human questions may STILL identify a client.</p>"
        "</header>" + "".join(html_blocks)
    )
    aggregate = {
        "schema": "lightup.private_human_next_round_counts.v1",
        "status": "REVIEW_ONLY",
        "original_source_reported_findings": len(source["findings"]),
        "previous_human_selected_count": len(notes),
        "proposed_human_selected_count": len(notes),
        "proposed_human_question_changes": len(changed),
        "human_route_question_counts": {
            name: sum(row["human_route"] == name for row in changed.values())
            for name in groups
        },
        "source_identifiers_included": False, **UNVERIFIED,
    }
    receipt = {
        "schema": "lightup.private_human_next_round_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "human_worksheet_sha256_unsigned": human_sha,
        "prior_human_selection_sha256_unsigned": selection_sha,
        "original_recipient_reply_sha256_unsigned": digest(response_raw),
        "sender_human_triage_sha256_unsigned": digest(triage_raw),
        "proposed_human_selection_sha256_unsigned": digest(selection_bytes),
        "private_proposal_brief_sha256_unsigned": digest(report),
        "changed_human_question_ordinals": sorted(changed),
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-proposed-next-HUMAN-selection.csv": selection_bytes,
        "PRIVATE-next-HUMAN-question-proposal.html": report,
        "PRIVATE-next-HUMAN-proposal-receipt.json": json_bytes(receipt),
        "PRIVATE-next-HUMAN-proposal-counts.json": json_bytes(aggregate),
    })


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local original-source-bound HUMAN next-question proposals ONLY, NO target")
    for flag in ("source", "manifest", "worksheet", "selection-receipt",
                 "selection", "response-binding", "response",
                 "triage-binding", "triage", "output-dir"):
        parser.add_argument("--" + flag, required=True)
    a = parser.parse_args()
    try:
        propose(
            a.source, a.manifest, a.worksheet, a.selection_receipt,
            a.selection, a.response_binding, a.response, a.triage_binding,
            a.triage, a.output_dir
        )
    except Hold:
        print("HOLD: Original source / HUMAN triage invalid or no changed HUMAN follow-up; no output", file=sys.stderr)
        return 3
    print("PRIVATE next-HUMAN-question selection PROPOSED only, no target permission or dispatch")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
