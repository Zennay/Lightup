#!/usr/bin/env python3
"""PRIVATE source-bound HUMAN recipient response to a curated lab question list.

No network, assessment, source rewriting, authority, validated human identity,
verified finding/remediation, or silent adoption of a recipient's assertions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys

from curate import (Hold, MAX_CSV_BYTES, MAX_RECEIPT_BYTES, UNVERIFIED,
                    digest, human_text_ok, literal_sha, read_original,
                    read_receipt, read_selection)
from briefing import CSS, h, json_bytes, publish_new, require, strict_pairs
from human_return import read_limited_file
from revision import private_frame
from recipient_studio import render_studio

RESPONSE_SCHEMA = "lightup.private_human_curated_response_v1"
HEADER = (
    "original_ordinal", "source_reported_severity", "evidence_reference_count",
    "original_human_priority", "original_human_question",
    "recipient_reported_stage", "recipient_human_reply",
    "recipient_human_next_question",
)
STAGES = ("", "responded_claimed", "needs_more_information", "blocked_human")

def accepted_original(source_path: str, manifest_path: str, worksheet_path: str,
                      receipt_path: str, selection_path: str):
    source, source_sha, human_raw, _ = read_original(
        source_path, manifest_path, worksheet_path)
    worksheet_sha = digest(human_raw)
    read_receipt(read_limited_file(receipt_path, MAX_RECEIPT_BYTES),
                 source_sha, worksheet_sha, source)
    selection_raw = read_limited_file(selection_path, MAX_CSV_BYTES)
    selected = read_selection(selection_raw, source)
    return source, source_sha, worksheet_sha, selection_raw, selected


def csv_template(source: dict, selected: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(HEADER)
    for row in selected:
        f = source["findings"][row["ordinal"]-1]
        writer.writerow((
            row["ordinal"], f["severity"], len(f["evidence_ids"]),
            row["priority"], row["question"], "", "", ""
        ))
    return output.getvalue().encode("utf-8")


def instruction_html(count: int) -> bytes:
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN recipient reply</h1>"
        "<p class='notice'>REVIEW ONLY — original producer, original findings, "
        "evidence, client/operator consent, recipient identity and remediation "
        "are UNVERIFIED. This never authorizes a target or proves any resolution.</p>"
        "<p>This HUMAN-only template contains original ordinals, source-reported "
        "severity and number of evidence IDs, plus the sender's original HUMAN "
        "priority/questions. A question may disclose confidential clients.</p>"
        "<p>Complete the three recipient HUMAN columns only, leave every "
        "original five source/proposal columns exactly as supplied and do not "
        "reorder rows. Choose blank, responded_claimed, needs_more_information "
        "or blocked_human; a claimed answer is NOT a verified result. "
        "One answer and one additional question may be entered, up to 500 "
        "safe characters each, without formula/control prefixes.</p>"
        "<p>Selection includes " + str(count) + " original ordinals. "
        "Use separately approved PRIVATE channels; spreadsheet cloud sync "
        "can expose confidential questions. Never imply recipient identity "
        "from possession of this template.</p></header>"
    )
    return private_frame("PRIVATE HUMAN reply instructions", body)


def prepare_reply(source_path: str, manifest_path: str, worksheet_path: str,
                  receipt_path: str, selection_path: str, output: str) -> None:
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, receipt_path, selection_path)
    template = csv_template(source, selected)
    browser_studio = render_studio(source, selected)
    binding = {
        "schema": RESPONSE_SCHEMA, "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_human_worksheet_sha256_unsigned": worksheet_sha,
        "original_human_selection_sha256_unsigned": digest(selection_raw),
        "blank_recipient_response_template_sha256_unsigned": digest(template),
        "private_recipient_studio_sha256_unsigned": digest(browser_studio),
        "human_selected_ordinal_count": len(selected),
        **UNVERIFIED,
    }
    publish_new(output, {
        "PRIVATE-recipient-response-template.csv": template,
        "PRIVATE-recipient-browser-studio.html": browser_studio,
        "PRIVATE-recipient-response-binding.json": json_bytes(binding),
        "PRIVATE-recipient-response-instructions.html": instruction_html(len(selected)),
    })


def admit_response_binding(raw: bytes, source_sha: str, worksheet_sha: str,
                           selection_sha: str, template_sha: str,
                           studio_sha: str, count: int) -> None:
    try:
        x = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                       parse_constant=lambda _: require(False))
        needed = {
            "schema", "status", "original_source_sha256_unsigned",
            "original_human_worksheet_sha256_unsigned",
            "original_human_selection_sha256_unsigned",
            "blank_recipient_response_template_sha256_unsigned",
            "human_selected_ordinal_count", *UNVERIFIED,
        }
        # Original v1 binding remains admitted; new packages additionally bind
        # the generated, source-minimized browser studio to exact source bytes.
        require(type(x) is dict and set(x) in
                (needed, needed | {"private_recipient_studio_sha256_unsigned"}))
        require(x["schema"] == RESPONSE_SCHEMA and x["status"] == "REVIEW_ONLY")
        require(all(x[k] is False for k in UNVERIFIED))
        require(all(literal_sha(x[k]) for k in (
            "original_source_sha256_unsigned",
            "original_human_worksheet_sha256_unsigned",
            "original_human_selection_sha256_unsigned",
            "blank_recipient_response_template_sha256_unsigned"
        )))
        require(x["original_source_sha256_unsigned"] == source_sha)
        require(x["original_human_worksheet_sha256_unsigned"] == worksheet_sha)
        require(x["original_human_selection_sha256_unsigned"] == selection_sha)
        require(x["blank_recipient_response_template_sha256_unsigned"] == template_sha)
        if "private_recipient_studio_sha256_unsigned" in x:
            require(literal_sha(x["private_recipient_studio_sha256_unsigned"]) and
                    x["private_recipient_studio_sha256_unsigned"] == studio_sha)
        require(type(x["human_selected_ordinal_count"]) is int and
                x["human_selected_ordinal_count"] == count)
    except (ValueError, TypeError, UnicodeError, KeyError,
            OverflowError, MemoryError, RecursionError):
        raise Hold("PRIVATE recipient reply binding rejected (HOLD)") from None


def admit_returned_reply(raw: bytes, source: dict, selected: list[dict]) -> list[dict]:
    try:
        decoded = raw.decode("utf-8-sig")
        require("\x00" not in decoded and "\r" not in decoded.replace("\r\n", ""))
        records = csv.reader(io.StringIO(decoded, newline=""), strict=True)
        require(tuple(next(records)) == HEADER)
        rows = list(records)
        require(len(rows) == len(selected))
        notes = []
        for row, item in zip(rows, selected):
            f = source["findings"][item["ordinal"] - 1]
            require(len(row) == len(HEADER) and
                    row[0] == str(item["ordinal"]) and
                    row[1] == f["severity"] and
                    row[2] == str(len(f["evidence_ids"])) and
                    row[3] == item["priority"] and
                    row[4] == item["question"])
            require(row[5] in STAGES)
            require(human_text_ok(row[6]) and human_text_ok(row[7]))
            if row[5] == "":
                require(not row[6] and not row[7])
            elif row[5] == "responded_claimed":
                require(bool(row[6].strip()))
            else:
                require(bool(row[6].strip()) or bool(row[7].strip()))
            notes.append({
                "ordinal": item["ordinal"], "priority": item["priority"],
                "original_question": item["question"],
                "recipient_reported_stage": row[5] or "no_human_response",
                "recipient_human_reply": row[6],
                "recipient_human_next_question": row[7],
            })
        return notes
    except (csv.Error, StopIteration, ValueError, TypeError, UnicodeError,
            OverflowError, MemoryError, RecursionError):
        raise Hold("PRIVATE recipient reply rejected; original HUMAN fields changed (HOLD)") from None


def private_reply_html(source: dict, notes: list[dict]) -> bytes:
    segments = []
    for entry in notes:
        f = source["findings"][entry["ordinal"]-1]
        segments.append(
            "<article><h2>Original ordinal #" + str(entry["ordinal"]) +
            " · HUMAN priority " + h(entry["priority"]) + "</h2>"
            "<p>Source-reported severity: " + h(f["severity"]) +
            " · original evidence reference count: " +
            str(len(f["evidence_ids"])) + "</p>"
            "<h3>Original HUMAN question</h3><pre>" +
            h(entry["original_question"]) + "</pre>"
            "<h3>RECIPIENT-reported stage (UNVERIFIED)</h3><p>" +
            h(entry["recipient_reported_stage"]) + "</p>"
            "<h3>RECIPIENT human reply (UNVERIFIED)</h3><pre>" +
            h(entry["recipient_human_reply"] or "No human reply provided") + "</pre>"
            "<h3>RECIPIENT additional HUMAN question</h3><pre>" +
            h(entry["recipient_human_next_question"] or "No additional question") +
            "</pre><div class='worksheet'>Independent original producer and "
            "evidence review: __________________ · HUMAN discussion: __________"
            "</div></article>"
        )
    body = (
        "<header><h1>LightUp · PRIVATE recipient HUMAN response</h1>"
        "<p class='notice'>REVIEW ONLY: original source/target validity, "
        "HUMAN respondent identity, questions and replies NOT authenticated. "
        "Responded_claimed is NOT verified evidence, remediation, target action, "
        "current consent, release or authorization.</p>"
        "<p>The original target, finding IDs, evidence bodies, run/scenario IDs, "
        "hashes and original source/HUMAN worksheet owner notes are NOT copied "
        "into this response report. Freeform questions and human replies can "
        "still identify clients. PRIVATE only.</p>"
        "<p>Human-selected original ordinals: " + str(len(notes)) +
        "</p></header>" + "".join(segments)
    )
    return private_frame("PRIVATE HUMAN recipient response", body)


def return_reply(source_path: str, manifest_path: str, worksheet_path: str,
                 receipt_path: str, selection_path: str,
                 reply_binding_path: str, reply_path: str, output: str) -> None:
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, receipt_path, selection_path)
    admit_response_binding(
        read_limited_file(reply_binding_path, MAX_RECEIPT_BYTES),
        source_sha, worksheet_sha, digest(selection_raw),
        digest(csv_template(source, selected)),
        digest(render_studio(source, selected)), len(selected)
    )
    reply_raw = read_limited_file(reply_path, MAX_CSV_BYTES)
    notes = admit_returned_reply(reply_raw, source, selected)
    private_html = private_reply_html(source, notes)
    summary = {
        "schema": "lightup.private_human_curated_response_counts.v1",
        "status": "REVIEW_ONLY",
        "human_selected_original_ordinal_count": len(selected),
        "human_recipient_self_reported_stage_counts": {
            stage: sum(n["recipient_reported_stage"] == stage for n in notes)
            for stage in ("no_human_response", *STAGES[1:])
        },
        "human_additional_question_count": sum(bool(n["recipient_human_next_question"])
                                              for n in notes),
        "source_identifiers_included": False, **UNVERIFIED,
    }
    private_receipt = {
        "schema": "lightup.private_human_curated_response_return_v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "human_worksheet_sha256_unsigned": worksheet_sha,
        "original_human_selection_sha256_unsigned": digest(selection_raw),
        "recipient_human_response_csv_sha256_unsigned": digest(reply_raw),
        "private_reply_html_sha256_unsigned": digest(private_html),
        "selected_original_ordinals": [r["ordinal"] for r in selected],
        **UNVERIFIED,
    }
    publish_new(output, {
        "PRIVATE-recipient-HUMAN-replies.html": private_html,
        "PRIVATE-recipient-HUMAN-reply-receipt.json": json_bytes(private_receipt),
        "recipient-HUMAN-reply-counts-PRIVATE.json": json_bytes(summary),
    })


def main() -> int:
    p = argparse.ArgumentParser(
        description="Strict offline PRIVATE human recipient answer handoff, NO original finding verdict")
    sub = p.add_subparsers(dest="command", required=True)
    for verb in ("prepare", "return"):
        s = sub.add_parser(verb)
        s.add_argument("--source", required=True)
        s.add_argument("--manifest", required=True)
        s.add_argument("--worksheet", required=True)
        s.add_argument("--selection-receipt", required=True)
        s.add_argument("--selection", required=True)
        s.add_argument("--output-dir", required=True)
        if verb == "return":
            s.add_argument("--response-binding", required=True)
            s.add_argument("--response", required=True)
    a = p.parse_args()
    try:
        if a.command == "prepare":
            prepare_reply(a.source, a.manifest, a.worksheet,
                          a.selection_receipt, a.selection, a.output_dir)
        else:
            return_reply(a.source, a.manifest, a.worksheet,
                         a.selection_receipt, a.selection,
                         a.response_binding, a.response, a.output_dir)
    except Hold:
        print("PRIVATE HUMAN respondent input rejected (HOLD); no output published", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN response materials prepared; REVIEW ONLY, not an approved finding")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
