#!/usr/bin/env python3
"""PRIVATE original-meeting HUMAN review history: proposals, never security progress.

Only compares 2–8 previously finalized ORIGINAL HUMAN review returns from one
unchanged ORIGINAL portfolio and meeting. No client/target access or scheduling.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
import json
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    literal_false_authority, new_private, object_unique, private_parent,
    read_owner_file, reject, safe_human, write_private,
)
from portfolio_delta import read_portfolio
from portfolio_focus import local_path, REVIEW_HEADERS
from portfolio_focus_review import (
    SCHEMA as RETURN_SCHEMA, STAGES, read_focus,
)

SCHEMA = "lightup.private.workspace-ledger-human-focus-history.v1"
RETURN_KEYS = {
    "schema", "authority", "historical_only", "sources_reopened",
    "recipient_authenticated", "consent_assumed", "actions_dispatched",
    "appointments_booked", "verified_remediation", "original_portfolio_sha256",
    "original_human_meeting_sha256", "original_human_review_csv_sha256",
    "original_case_contexts", "human_review_rows",
}
ROW_KEYS = {
    "local_case", "historical_transition", "original_kit",
    "human_meeting_stage", "human_decision_note",
}
MAX_RETURNS = 8
HEADERS = (
    "historical_revision_from", "historical_revision_to",
    "local_case", "historical_transition", "original_kit",
    "prior_human_stage", "later_human_stage",
    "prior_private_human_note", "later_private_human_note",
    "stage_changed", "human_note_changed",
)


def read_return(path, source_sha, meeting_sha, contexts, originals):
    raw = read_owner_file(path, MAX_MANIFEST)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN return"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: malformed HUMAN review return") from exc
    if (type(doc) is not dict or set(doc) != RETURN_KEYS or
        doc["schema"] != RETURN_SCHEMA or
        not literal_false_authority(doc["authority"], FLAGS) or
        doc["historical_only"] is not True or
        any(doc[field] is not False for field in (
            "sources_reopened", "recipient_authenticated", "consent_assumed",
            "actions_dispatched", "appointments_booked", "verified_remediation"
        )) or doc["original_portfolio_sha256"] != source_sha or
        doc["original_human_meeting_sha256"] != meeting_sha or
        type(doc["original_human_review_csv_sha256"]) is not str or
        len(doc["original_human_review_csv_sha256"]) != 64 or
        any(c not in "0123456789abcdef" for c in doc["original_human_review_csv_sha256"]) or
        doc["original_case_contexts"] != contexts or raw != canonical(doc)):
        reject("PRIVATE HOLD: HUMAN return not canonical or exact-source-bound")
    rows = doc["human_review_rows"]
    if type(rows) is not list or len(rows) != len(originals):
        reject("PRIVATE HOLD: HUMAN return population changed")
    for row, original in zip(rows, originals):
        if (type(row) is not dict or set(row) != ROW_KEYS or
            any(type(row[key]) is not int or row[key] != original[key] for key in (
                "local_case", "historical_transition", "original_kit"
            )) or type(row["human_meeting_stage"]) is not str or
            row["human_meeting_stage"] not in STAGES or
            type(row["human_decision_note"]) is not str or
            any(c in row["human_decision_note"] for c in "\r\n\t")):
            reject("PRIVATE HOLD: HUMAN return rows differ from original meeting")
        safe_human(row["human_decision_note"], 240)
    return raw, rows


def compare(returns, originals):
    revisions, changed = [], []
    for i, (raw, rows) in enumerate(returns, 1):
        stages = Counter(row["human_meeting_stage"] for row in rows)
        revisions.append({
            "human_revision": i,
            "unsigned_private_return_sha256": digest(raw),
            "original_human_rows": len(rows),
            "human_stage_counts": {s: stages[s] for s in STAGES},
        })
        if i == 1:
            continue
        previous = returns[i-2][1]
        stage_changes = 0
        note_changes = 0
        for left, right, original in zip(previous, rows, originals):
            stage_delta = left["human_meeting_stage"] != right["human_meeting_stage"]
            note_delta = left["human_decision_note"] != right["human_decision_note"]
            if not stage_delta and not note_delta:
                continue
            stage_changes += stage_delta
            note_changes += note_delta
            changed.append({
                "historical_revision_from": i-1,
                "historical_revision_to": i,
                "local_case": original["local_case"],
                "historical_transition": original["historical_transition"],
                "original_kit": original["original_kit"],
                "prior_human_stage": left["human_meeting_stage"],
                "later_human_stage": right["human_meeting_stage"],
                "prior_private_human_note": left["human_decision_note"],
                "later_private_human_note": right["human_decision_note"],
                "stage_changed": stage_delta,
                "human_note_changed": note_delta,
            })
        revisions[-1]["human_stage_changed_slots_vs_previous"] = stage_changes
        revisions[-1]["human_note_changed_slots_vs_previous"] = note_changes
    return revisions, changed


def private_csv(changes):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\n")
    w.writerow(HEADERS)
    for change in changes:
        w.writerow([change[field] for field in HEADERS])
    return out.getvalue()


def next_review_template(last_rows, meeting_sha):
    """Manual next HUMAN draft, never an approved or scheduled action."""
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(REVIEW_HEADERS)
    for row in last_rows:
        writer.writerow([
            row["local_case"], row["historical_transition"],
            row["original_kit"], meeting_sha,
            row["human_meeting_stage"], row["human_decision_note"],
        ])
    return out.getvalue()


def overview(revisions, changes):
    rows = [
        "<p><strong>PRIVATE, source-minimal ORIGINAL human review history.</strong> "
        "These are unsigned HUMAN proposals, not real work completed, "
        "remediation, security PASS, verified finding, scan, authorization, "
        "consent, task, authenticated person or appointment. No original kit "
        "file has been reopened.</p>",
        "<p>Historical HUMAN return versions: " + str(len(revisions)) +
        ". Changed HUMAN proposal cells across consecutive reviews: " +
        str(len(changes)) + ". Neither improvement nor degradation of "
        "real security is inferred.</p>",
        "<table><thead><tr><th>Review version</th><th>Needs discussion</th>"
        "<th>Proposed follow-up</th><th>HOLD</th><th>HUMAN status edits</th>"
        "<th>HUMAN note edits</th></tr></thead><tbody>",
    ]
    for row in revisions:
        counts = row["human_stage_counts"]
        rows.append(
            "<tr><td>" + str(row["human_revision"]) + "</td>" +
            "".join("<td>" + str(counts[s]) + "</td>" for s in STAGES) +
            "<td>" + str(row.get("human_stage_changed_slots_vs_previous", 0)) +
            "</td><td>" + str(row.get("human_note_changed_slots_vs_previous", 0)) +
            "</td></tr>"
        )
    rows.append("</tbody></table><p>No owner names, case/target names, source "
                "hashes, original HUMAN free text or detailed case references "
                "appear in this counts-only overview. All outputs remain PRIVATE.</p>")
    return html_page("LightUp PRIVATE HUMAN review-version summary", "".join(rows))


def detail(revisions, changes, meeting_title):
    content = [
        "<p><strong>PRIVATE HUMAN-only historical proposal change record, "
        "NOT verified security progress.</strong> Original source-byte "
        "identity is unsigned and does not authenticate a recipient or "
        "grant permission. No independent source kits reopened.</p>",
        "<p>Original HUMAN meeting: " + html.escape(meeting_title, quote=True) +
        ". Historical versions: " + str(len(revisions)) +
        ". Original HUMAN proposal differences: " + str(len(changes)) + ".</p>",
        "<table><thead><tr><th>Version</th><th>Original slot</th><th>Prior "
        "HUMAN status</th><th>Later HUMAN status</th><th>Prior PRIVATE note</th>"
        "<th>Later PRIVATE note</th></tr></thead><tbody>",
    ]
    for row in changes:
        def h(key):
            return html.escape(str(row[key]), quote=True)
        content.append(
            "<tr><td>" + h("historical_revision_from") + " → " +
            h("historical_revision_to") + "</td><td>" + h("local_case") +
            " / " + h("historical_transition") + " / " + h("original_kit") +
            "</td><td>" + h("prior_human_stage") +
            "</td><td>" + h("later_human_stage") +
            "</td><td>" + h("prior_private_human_note") +
            "</td><td>" + h("later_private_human_note") + "</td></tr>"
        )
    content.append("</tbody></table><p>Every comparison is between explicit "
                   "archived HUMAN return bytes, not physical target state.</p>")
    return html_page("LightUp PRIVATE source-bound HUMAN review history", "".join(content))


def run(args):
    paths = [args.portfolio, args.meeting, args.private_parent] + args.returns
    if (type(args.returns) is not list or not 2 <= len(args.returns) <= MAX_RETURNS or
        any(not local_path(p) for p in paths) or
        len(set(paths)) != len(paths)):
        reject("PRIVATE HOLD: use original 2–8 distinct canonical PRIVATE HUMAN return paths")
    private_parent(args.private_parent)
    source = read_portfolio(args.portfolio)
    meeting, doc, originals = read_focus(args.meeting, source)
    source_sha, meeting_sha = digest(source[0]), digest(meeting)
    returns = [
        read_return(path, source_sha, meeting_sha, doc["original_case_contexts"], originals)
        for path in args.returns
    ]
    if len({digest(raw) for raw, _ in returns}) != len(returns):
        reject("PRIVATE HOLD: duplicate historical HUMAN return bytes")
    # Re-admit the original FULL source chain, not merely copies of stored
    # human-only rows, before creating the next confidential immutable folder.
    if (read_portfolio(args.portfolio)[0] != source[0] or
        read_focus(args.meeting, source)[0] != meeting or
        any(read_return(path, source_sha, meeting_sha,
                        doc["original_case_contexts"], originals)[0] != raw
            for path, (raw, _) in zip(args.returns, returns))):
        reject("PRIVATE HOLD: historical HUMAN source changed before output")
    revisions, changes = compare(returns, originals)
    result = {
        "schema": SCHEMA, "authority": FLAGS,
        "historical_only": True, "sources_reopened": False,
        "recipient_authenticated": False, "consent_assumed": False,
        "actions_dispatched": False, "appointments_booked": False,
        "verified_remediation": False,
        "original_portfolio_sha256": source_sha,
        "original_meeting_sha256": meeting_sha,
        "original_return_shas_in_explicit_human_order": [
            digest(raw) for raw, _ in returns
        ],
        "human_revisions": revisions,
        "private_human_proposal_changes": changes,
    }
    artifacts = {
        "OPEN-PRIVATE.html": overview(revisions, changes),
        "PRIVATE-HUMAN-history.html": detail(revisions, changes, doc["meeting_title"]),
        "PRIVATE-HUMAN-history.csv": private_csv(changes),
        "HUMAN-next-review-draft.csv": next_review_template(returns[-1][1], meeting_sha),
        "PRIVATE-HUMAN-history.json": canonical(result),
    }
    if any(len(data if isinstance(data, bytes) else data.encode("utf-8")) > MAX_MANIFEST
           for data in artifacts.values()):
        reject("PRIVATE HOLD: original private HUMAN history output too large")
    folder = new_private(args.private_parent)
    try:
        for filename, contents in artifacts.items():
            write_private(folder, filename, contents)
    except BaseException:
        shutil.rmtree(folder)
        raise
    print("PRIVATE HOLD: unapproved source-bound next-round HUMAN CSV draft prepared")
    print("PRIVATE HOLD: historical HUMAN proposal changes only, NEVER verified remediation")
    print(str(Path(folder) / "OPEN-PRIVATE.html"))
    return 3


def main():
    ap = argparse.ArgumentParser(
        description="Compare 2–8 original PRIVATE HUMAN meeting returns; never a security verdict"
    )
    ap.add_argument("--portfolio", required=True)
    ap.add_argument("--meeting", required=True)
    ap.add_argument("--return", dest="returns", required=True, action="append",
                    help="Repeat 2–8 original private HUMAN return JSON files in HUMAN history order")
    ap.add_argument("--private-parent", required=True)
    args = ap.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN review versions rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
