#!/usr/bin/env python3
"""Strictly local source-bound follow-up return for a PRIVATE HUMAN focus meeting.

Never validates a real finding, scope, recipient, scheduling, consent or grant.
The submitted CSV is a human proposal, not authenticated reviewer evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import json
import shutil
from pathlib import Path
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    literal_false_authority, new_private, object_unique, private_parent,
    read_owner_file, reject, safe_human, write_private,
)
from portfolio_delta import read_portfolio
from portfolio_dayboard import BUCKETS, PRIORITY, select
from portfolio_focus import SCHEMA as FOCUS_SCHEMA, REVIEW_HEADERS, local_path

SCHEMA = "lightup.private.workspace-ledger-human-focus-review.v1"
STAGES = ("needs_discussion", "proposed_followup", "hold")
FOCUS_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_portfolio_sha256",
    "original_case_contexts", "meeting_title", "manually_selected_reference_day",
    "proposed_human_owner_filter", "selected_date_buckets",
    "selected_human_priorities", "historical_human_proposals",
}
SOURCE_KEYS = {
    "local_case", "historical_transition", "original_kit", "human_priority",
    "human_status", "proposed_day", "date_bucket", "proposed_owner",
    "next_human_step",
}
MAX_ROWS = 2048


def read_focus(path, source):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite meeting data"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: malformed HUMAN meeting") from exc
    if (type(doc) is not dict or set(doc) != FOCUS_KEYS or
        doc["schema"] != FOCUS_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[key] is not False for key in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or raw != canonical(doc) or
        doc["original_portfolio_sha256"] != digest(source[0])):
        reject("PRIVATE HOLD: meeting not bound to exact original HUMAN portfolio")
    name = doc["meeting_title"]
    if (type(name) is not str or not 1 <= len(name) <= 100 or
        name.strip() != name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)):
        reject("PRIVATE HOLD: invalid HUMAN meeting title")
    proposed = doc["proposed_human_owner_filter"]
    if proposed is not None:
        if type(proposed) is not str or not proposed:
            reject("PRIVATE HOLD: invalid meeting owner")
        safe_human(proposed, 80)
    priorities = doc["selected_human_priorities"]
    buckets = doc["selected_date_buckets"]
    if (type(priorities) is not list or not priorities or
        len(priorities) != len(set(map(str, priorities))) or
        any(type(v) is not str or v not in PRIORITY for v in priorities) or
        priorities != [v for v in PRIORITY if v in priorities] or
        type(buckets) is not list or not buckets or
        len(buckets) != len(set(map(str, buckets))) or
        any(type(v) is not str or v not in BUCKETS for v in buckets) or
        buckets != [v for v in BUCKETS if v in buckets]):
        reject("PRIVATE HOLD: missing/ambiguous original HUMAN filters")
    entries, owner = select(argparse.Namespace(
        owner=proposed, reference_day=doc["manually_selected_reference_day"]
    ), source)
    expected = [
        e for e in entries if e["human_priority"] in priorities and
        e["date_bucket"] in buckets
    ]
    actual = doc["historical_human_proposals"]
    if (type(actual) is not list or not 1 <= len(actual) <= MAX_ROWS or
        any(type(e) is not dict or set(e) != SOURCE_KEYS for e in actual) or
        actual != expected or owner != proposed):
        reject("PRIVATE HOLD: HUMAN meeting content diverges from strict original")
    cases = {c["case_ordinal"]: c for c in source[1]["cases"]}
    expected_context = [{
        "case_ordinal": n,
        "original_context_sha256": cases[n]["context_sha256"],
        "original_human_actions_sha256": cases[n]["original_human_actions_sha256"],
    } for n in sorted({row["local_case"] for row in expected})]
    if doc["original_case_contexts"] != expected_context:
        reject("PRIVATE HOLD: original HUMAN case context mismatch")
    return raw, doc, expected


def review_rows(raw, entries, meeting_sha):
    try:
        decoded = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        if reader.fieldnames != list(REVIEW_HEADERS):
            reject("PRIVATE HOLD: HUMAN meeting review CSV schema")
        rows = list(reader)
    except (UnicodeError, csv.Error, ValueError) as exc:
        raise Hold("PRIVATE HOLD: malformed original HUMAN review CSV") from exc
    if len(rows) != len(entries):
        reject("PRIVATE HOLD: all original HUMAN focus entries must be covered")
    accepted = []
    for ordinal, (row, original) in enumerate(zip(rows, entries)):
        if type(row) is not dict or set(row) != set(REVIEW_HEADERS):
            reject("PRIVATE HOLD: ambiguous HUMAN review CSV columns")
        # Never accept reordered, missing or foreign original HUMAN slots.
        for col, key in (
            ("local_case", "local_case"),
            ("historical_transition", "historical_transition"),
            ("original_kit", "original_kit"),
        ):
            if row[col] != str(original[key]):
                reject("PRIVATE HOLD: HUMAN review original source slot drift")
        if row["meeting_sha256"] != meeting_sha:
            reject("PRIVATE HOLD: different original HUMAN meeting SHA")
        status = row["human_meeting_stage"]
        note = row["human_decision_note"]
        if status not in STAGES or type(note) is not str or (
            "\n" in note or "\r" in note or "\t" in note
        ):
            reject("PRIVATE HOLD: HUMAN meeting stage/note invalid")
        safe_human(note, 240)
        accepted.append({
            "local_case": original["local_case"],
            "historical_transition": original["historical_transition"],
            "original_kit": original["original_kit"],
            "human_meeting_stage": status,
            "human_decision_note": note,
        })
    return accepted


def anonymous_html(rows):
    counts = Counter(r["human_meeting_stage"] for r in rows)
    body = [
        "<h2>HUMAN meeting return · source-minimal</h2>",
        "<p><strong>PRIVATE/HOLD. Human draft only.</strong> No real task, "
        "authenticated reviewer, scheduling, authorization, consent, "
        "active scan, verified finding or remediation is evidenced.</p>",
        "<p>Locally reviewed historical HUMAN rows: " + str(len(rows)) +
        ". No original identifiers, dates, owners, hashes or human notes appear here.</p>",
        "<table><thead><tr><th>Local HUMAN proposed stage</th><th>Count</th>"
        "</tr></thead><tbody>",
    ]
    for stage in STAGES:
        body.append("<tr><td>" + html.escape(stage) + "</td><td>" +
                    str(counts[stage]) + "</td></tr>")
    body.append("</tbody></table><p>Nothing was sent or applied to original source.</p>")
    return html_page("LightUp PRIVATE HUMAN review counts", "".join(body))


def detailed_html(rows, source):
    body = [
        "<p><strong>OWNER-PRIVATE human-only meeting return.</strong> "
        "This local document records unsigned HUMAN text choices, not verified "
        "security, task execution, grant, client consent or reviewer identity. "
        "Original assessment kits were not reopened.</p>",
        "<p>Selected original historical HUMAN workroom: " +
        html.escape(source["meeting_title"], quote=True) + "</p>",
        "<table><thead><tr><th>Case / transition / kit</th><th>HUMAN"
        " proposed review stage</th><th>PRIVATE human note</th></tr></thead><tbody>",
    ]
    for row in rows:
        body.append(
            "<tr><td>" + str(row["local_case"]) + " / " +
            str(row["historical_transition"]) + " / " +
            str(row["original_kit"]) + "</td><td>" +
            html.escape(row["human_meeting_stage"]) + "</td><td>" +
            html.escape(row["human_decision_note"], quote=True) + "</td></tr>"
        )
    body.append("</tbody></table><p>Discuss independently; no actual dispatch"
                " or release followed from this local review.</p>")
    return html_page("LightUp PRIVATE HUMAN meeting review", "".join(body))


def run(args):
    if any(not local_path(p) for p in (
        args.portfolio, args.meeting, args.review, args.private_parent
    )) or len({args.portfolio, args.meeting, args.review}) != 3:
        reject("PRIVATE HOLD: unique canonical original absolute paths required")
    private_parent(args.private_parent)
    source = read_portfolio(args.portfolio)
    meeting, document, entries = read_focus(args.meeting, source)
    review = read_owner_file(args.review, MAX_MANIFEST)
    original_sha = digest(source[0])
    meeting_sha = digest(meeting)
    decisions = review_rows(review, entries, meeting_sha)
    # Strict original-source AND submitted-HUMAN-byte re-admission, before writing.
    if read_portfolio(args.portfolio)[0] != source[0] or (
        read_focus(args.meeting, source)[0] != meeting
    ) or read_owner_file(args.review, MAX_MANIFEST) != review:
        reject("PRIVATE HOLD: original HUMAN review inputs changed before output")
    result = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_portfolio_sha256": original_sha,
        "original_human_meeting_sha256": meeting_sha,
        "original_human_review_csv_sha256": digest(review),
        "original_case_contexts": document["original_case_contexts"],
        "human_review_rows": decisions,
    }
    encoded = canonical(result)
    private_html = detailed_html(decisions, document)
    if len(encoded) > MAX_MANIFEST or len(private_html.encode("utf-8")) > MAX_MANIFEST:
        reject("PRIVATE HOLD: review packet exceeds original native limit")
    folder = new_private(args.private_parent)
    try:
        write_private(folder, "OPEN-PRIVATE.html", anonymous_html(decisions))
        write_private(folder, "PRIVATE-HUMAN-review-return.html", private_html)
        write_private(folder, "PRIVATE-HUMAN-review-return.json", encoded)
        write_private(folder, "PRIVATE-HUMAN-review-original.csv", review)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: HUMAN decisions recorded as unsigned historical proposals only")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(description="Finalize owner-private source-bound HUMAN meeting review")
    parser.add_argument("--portfolio", required=True, help="Original private portfolio JSON")
    parser.add_argument("--meeting", required=True, help="Original PRIVATE-HUMAN-meeting.json")
    parser.add_argument("--review", required=True, help="Private edited HUMAN-meeting-review-template.csv")
    parser.add_argument("--private-parent", required=True, help="Existing owner-private 0700 parent")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: HUMAN focus review could not be admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
