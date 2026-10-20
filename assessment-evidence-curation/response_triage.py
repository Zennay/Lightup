#!/usr/bin/env python3
"""Original-source-bound PRIVATE HUMAN sender triage of recipient reply declarations.

Read-only existing lab results and human metadata. No tool execution, finding
verification, real consent, respondent identity, authorization or remediation.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import sys

from curate import (Hold, MAX_CSV_BYTES, MAX_RECEIPT_BYTES, UNVERIFIED,
                    digest, human_text_ok, literal_sha, require)
from briefing import h, json_bytes, publish_new, strict_pairs
from human_return import read_limited_file
from response import (accepted_original, admit_response_binding,
                      admit_returned_reply, csv_template)
from recipient_studio import render_studio
from revision import private_frame
from triage_studio import render_studio

SCHEMA = "lightup.private_human_recipient_triage.v1"
HEADER = (
    "original_ordinal", "original_human_priority", "recipient_reported_stage",
    "recipient_human_reply_sha256_unsigned",
    "recipient_human_next_question_sha256_unsigned",
    "sender_human_route", "sender_human_owner_group", "sender_human_next_question",
)
ROUTES = ("", "needs_human_review", "request_clarification",
          "route_to_owner", "documented_for_followup")


def original_reply(source_path: str, manifest: str, worksheet: str,
                   receipt_path: str, selection_path: str,
                   binding_path: str, reply_path: str):
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest, worksheet, receipt_path, selection_path)
    admit_response_binding(
        read_limited_file(binding_path, MAX_RECEIPT_BYTES), source_sha,
        worksheet_sha, digest(selection_raw), digest(csv_template(source, selected)),
        digest(render_studio(source, selected)), len(selected)
    )
    response_raw = read_limited_file(reply_path, MAX_CSV_BYTES)
    notes = admit_returned_reply(response_raw, source, selected)
    return source, source_sha, worksheet_sha, digest(selection_raw), response_raw, notes


def row_digest(value: str) -> str:
    return digest(value.encode("utf-8"))


def triage_template(notes: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(HEADER)
    for note in notes:
        writer.writerow((
            note["ordinal"], note["priority"], note["recipient_reported_stage"],
            row_digest(note["recipient_human_reply"]),
            row_digest(note["recipient_human_next_question"]), "", "", ""
        ))
    return output.getvalue().encode("utf-8")


def binding_fields(source_sha: str, worksheet_sha: str,
                   selection_sha: str, response_sha: str,
                   template_sha: str, note_count: int, studio_sha: str) -> dict:
    return {
        "schema": SCHEMA, "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_human_worksheet_sha256_unsigned": worksheet_sha,
        "original_human_selection_sha256_unsigned": selection_sha,
        "original_recipient_response_sha256_unsigned": response_sha,
        "original_blank_triage_template_sha256_unsigned": template_sha,
        "human_recipient_question_count": note_count,
        "private_sender_triage_studio_sha256_unsigned": studio_sha,
        **UNVERIFIED,
    }


def read_binding(raw: bytes, expected: dict) -> None:
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                         parse_constant=lambda _: require(False))
        require(type(obj) is dict and set(obj) == set(expected))
        require(all(obj[k] is False for k in UNVERIFIED))
        for field, value in expected.items():
            if field.endswith("_sha256_unsigned"):
                require(literal_sha(obj[field]))
            require(obj[field] == value and
                    (field != "human_recipient_question_count" or type(obj[field]) is int))
    except (ValueError, KeyError, TypeError, RecursionError,
            UnicodeError, OverflowError, MemoryError):
        raise Hold("PRIVATE sender triage binding rejected (HOLD)") from None


def read_triage(raw: bytes, notes: list[dict]) -> list[dict]:
    try:
        source = raw.decode("utf-8-sig")
        require("\x00" not in source and "\r" not in source.replace("\r\n", ""))
        reader = csv.reader(io.StringIO(source, newline=""), strict=True)
        require(tuple(next(reader)) == HEADER)
        rows = list(reader)
        require(len(rows) == len(notes))
        result = []
        for row, original in zip(rows, notes):
            require(len(row) == len(HEADER))
            require(row[0] == str(original["ordinal"]))
            require(row[1] == original["priority"])
            require(row[2] == original["recipient_reported_stage"])
            require(row[3] == row_digest(original["recipient_human_reply"]))
            require(row[4] == row_digest(original["recipient_human_next_question"]))
            require(row[5] in ROUTES)
            require(human_text_ok(row[6]) and human_text_ok(row[7]))
            require(len(row[6]) <= 120 and len(row[7]) <= 500)
            if row[5] == "":
                require(not row[6] and not row[7])
            if row[5] == "route_to_owner":
                require(bool(row[6].strip()) and bool(row[7].strip()))
            if row[5] == "request_clarification":
                require(bool(row[7].strip()))
            if row[5] in ("needs_human_review", "documented_for_followup"):
                require(bool(row[6].strip()) or bool(row[7].strip()))
            result.append({
                **original,
                "sender_human_route": row[5] or "unreviewed",
                "sender_human_owner_group": row[6],
                "sender_human_next_question": row[7],
            })
        return result
    except (csv.Error, ValueError, StopIteration, TypeError,
            UnicodeError, RecursionError, OverflowError, MemoryError):
        raise Hold("PRIVATE sender triage CSV rejected; original reply changed (HOLD)") from None


def render_triage(notes: list[dict]) -> bytes:
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN recipient-reply triage</h1>"
        "<p class='notice'>REVIEW ONLY / NO GRANT. Original findings, respondent identity,"
        " HUMAN routes, answers, source authenticity, current consent, actual remediation"
        " and target authorization are NOT verified.</p>"
        "<p>Original target names, original finding IDs, source hashes and evidence bodies"
        " are intentionally absent. HUMAN replies, owner labels and questions may"
        " identify a customer; this full report is PRIVATE.</p>"
        "<p>Sender HUMAN triage records: " + str(len(notes)) + "</p></header>"
    )
    for note in notes:
        body += (
            "<article><h2>Original ordinal #" + str(note["ordinal"]) +
            " · HUMAN priority " + h(note["priority"]) + "</h2>"
            "<p>Recipient-reported stage: " + h(note["recipient_reported_stage"]) +
            " · Sender HUMAN route: " + h(note["sender_human_route"]) + "</p>"
            "<h3>Original HUMAN question</h3><pre>" +
            h(note["original_question"]) + "</pre>"
            "<h3>Recipient HUMAN reply (not verified)</h3><pre>" +
            h(note["recipient_human_reply"] or "No recipient reply") + "</pre>"
            "<h3>Recipient HUMAN follow-up question</h3><pre>" +
            h(note["recipient_human_next_question"] or "None") + "</pre>"
            "<h3>Sender HUMAN owner/group label (not authenticated)</h3><p>" +
            h(note["sender_human_owner_group"] or "Unassigned") + "</p>"
            "<h3>Sender HUMAN next question</h3><pre>" +
            h(note["sender_human_next_question"] or "Not recorded") +
            "</pre><div class='worksheet'>Human independent evidence check:"
            " __________________ · Follow-up: __________________</div></article>"
        )
    return private_frame("PRIVATE HUMAN response triage", body)



def private_human_handoff(notes: list[dict], route: str) -> bytes:
    """Print only a route-specific recipient HUMAN action queue.

    No original assessment target, original finding IDs, raw evidence or other
    route recipients' notes. HUMAN questions/owner labels remain PRIVATE.
    """
    selected = [note for note in notes if note["sender_human_route"] == route]
    blocks = []
    for note in selected:
        blocks.append(
            "<article><h2>Original ordinal #" + str(note["ordinal"]) + "</h2>"
            "<p>HUMAN priority: " + h(note["priority"]) +
            " · recipient-self-reported stage: " +
            h(note["recipient_reported_stage"]) + "</p>"
            "<p>HUMAN owner/group label (NOT an authenticated recipient): " +
            h(note["sender_human_owner_group"] or "Not assigned") + "</p>"
            "<h3>Sender HUMAN next question</h3><pre>" +
            h(note["sender_human_next_question"] or "Not recorded") +
            "</pre><p>Source-provided evidence and targets are not included."
            " Human review and separately authorized private handoff are required.</p>"
            "</article>"
        )
    return private_frame("PRIVATE sender HUMAN handoff: " + route, (
        "<header><h1>PRIVATE sender HUMAN next actions · " + h(route) + "</h1>"
        "<p class='notice'>HUMAN proposal ONLY, not authenticated identity,"
        " actual owner assignment, original finding validity, verified"
        " remediation, client consent, scope authorization or active task."
        " No message was sent. This private report can still contain"
        " identifying HUMAN questions and groups.</p>"
        "<p>Original ordinal-only recipient packets: " + str(len(selected)) +
        ".</p></header>" +
        ("".join(blocks) if blocks else
         "<section class='card'>No HUMAN next actions of this route.</section>")
    ))


def human_action_csv(notes: list[dict]) -> bytes:
    """PRIVATE human-only route handoff with original ordinal and next question.

    This carries no original finding, target, evidence, run or tenant identifiers.
    Recipient/channel consent and security/privacy review remain separate.
    """
    buf = io.StringIO(newline="")
    out = csv.writer(buf, lineterminator="\r\n")
    out.writerow((
        "original_ordinal", "sender_human_route",
        "sender_human_owner_group", "sender_human_next_question",
    ))
    for note in notes:
        if note["sender_human_route"] == "unreviewed":
            continue
        out.writerow((
            note["ordinal"], note["sender_human_route"],
            note["sender_human_owner_group"],
            note["sender_human_next_question"],
        ))
    return buf.getvalue().encode("utf-8")


def prepare(source: str, manifest: str, worksheet: str, receipt: str,
            selection: str, binding: str, reply: str, destination: str):
    _, source_sha, worksheet_sha, selection_sha, reply_raw, notes = original_reply(
        source, manifest, worksheet, receipt, selection, binding, reply
    )
    template = triage_template(notes)
    browser = render_studio(notes)
    metadata = binding_fields(source_sha, worksheet_sha, selection_sha,
                              digest(reply_raw), digest(template), len(notes), digest(browser))
    publish_new(destination, {
        "PRIVATE-sender-triage-template.csv": template,
        "PRIVATE-sender-triage-browser.html": browser,
        "PRIVATE-sender-triage-binding.json": json_bytes(metadata),
        "PRIVATE-sender-triage-instructions.html": private_frame(
            "PRIVATE HUMAN sender triage instructions",
            "<header><h1>PRIVATE HUMAN sender response triage</h1>"
            "<p class='notice'>REVIEW ONLY — no finding, producer, recipient identity,"
            " original evidence or consent is verified.</p>"
            "<p>Original first five columns bind to the exact previously received"
            " recipient HUMAN response; fill only route, owner/group and next HUMAN"
            " question. Routes are solely human coordination labels, never actual"
            " remediation, approval, authorization or verified retest.</p>"
            "<p>Accepted routes: needs_human_review, request_clarification,"
            " route_to_owner, documented_for_followup. Leave all three human fields"
            " blank for an unreviewed row. A route_to_owner needs both owner/group"
            " and next question. A request_clarification needs a next question."
            " Keep all private files within an approved human channel.</p></header>"
        ),
    })


def finish(source: str, manifest: str, worksheet: str, receipt: str,
           selection: str, binding: str, reply: str, triage_binding: str,
           triage_csv: str, destination: str):
    _, source_sha, worksheet_sha, selection_sha, reply_raw, notes = original_reply(
        source, manifest, worksheet, receipt, selection, binding, reply
    )
    template = triage_template(notes)
    expected = binding_fields(source_sha, worksheet_sha, selection_sha,
                              digest(reply_raw), digest(template), len(notes),
                              digest(render_studio(notes)))
    read_binding(read_limited_file(triage_binding, MAX_RECEIPT_BYTES), expected)
    triage_bytes = read_limited_file(triage_csv, MAX_CSV_BYTES)
    final = read_triage(triage_bytes, notes)
    html_report = render_triage(final)
    clarifications = private_human_handoff(final, "request_clarification")
    owner_handoff = private_human_handoff(final, "route_to_owner")
    human_actions = human_action_csv(final)
    routes = {k: sum(n["sender_human_route"] == k for n in final)
              for k in ("unreviewed", *ROUTES[1:])}
    aggregate = {
        "schema": "lightup.private_human_recipient_triage_counts.v1",
        "status": "REVIEW_ONLY",
        "human_reply_count": len(final),
        "sender_self_reported_route_counts": routes,
        "recipient_self_reported_answer_count":
            sum(bool(n["recipient_human_reply"]) for n in final),
        "sender_next_question_count":
            sum(bool(n["sender_human_next_question"]) for n in final),
        "source_identifiers_included": False, **UNVERIFIED,
    }
    receipt_info = {
        "schema": "lightup.private_human_recipient_triage_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_human_worksheet_sha256_unsigned": worksheet_sha,
        "original_human_selection_sha256_unsigned": selection_sha,
        "original_recipient_reply_sha256_unsigned": digest(reply_raw),
        "sender_human_triage_sha256_unsigned": digest(triage_bytes),
        "private_sender_triage_report_sha256_unsigned": digest(html_report),
        "private_human_clarifications_sha256_unsigned": digest(clarifications),
        "private_human_owner_handoff_sha256_unsigned": digest(owner_handoff),
        "private_human_action_csv_sha256_unsigned": digest(human_actions),
        "human_original_ordinal_list": [x["ordinal"] for x in final],
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-sender-HUMAN-triage.html": html_report,
        "PRIVATE-HUMAN-request-clarification.html": clarifications,
        "PRIVATE-HUMAN-route-to-owner.html": owner_handoff,
        "PRIVATE-HUMAN-next-actions.csv": human_actions,
        "PRIVATE-sender-HUMAN-triage-receipt.json": json_bytes(receipt_info),
        "sender-HUMAN-route-counts-PRIVATE.json": json_bytes(aggregate),
    })


def main():
    p = argparse.ArgumentParser(
        description="Offline PRIVATE human triage of an existing recipient reply — NO assessment execution")
    sub = p.add_subparsers(dest="command",required=True)
    for mode in ("prepare","return"):
        x=sub.add_parser(mode)
        for name in ("source","manifest","worksheet","selection-receipt",
                     "selection","response-binding","response","output-dir"):
            x.add_argument("--"+name,required=True)
        if mode=="return":
            x.add_argument("--triage-binding",required=True)
            x.add_argument("--triage",required=True)
    args=p.parse_args()
    try:
        common=(args.source,args.manifest,args.worksheet,args.selection_receipt,
                args.selection,args.response_binding,args.response)
        if args.command=="prepare":prepare(*common,args.output_dir)
        else:finish(*common,args.triage_binding,args.triage,args.output_dir)
    except Hold:
        print("HOLD: Original PRIVATE recipient or HUMAN triage input rejected; no output published",file=sys.stderr)
        return 3
    print("PRIVATE HUMAN sender triage prepared — REVIEW ONLY; no grant, consent or remediation")
    return 2

if __name__=="__main__":
    raise SystemExit(main())
