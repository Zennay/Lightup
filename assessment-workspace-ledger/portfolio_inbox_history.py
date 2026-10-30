#!/usr/bin/env python3
"""Offline, owner-private original HUMAN inbox discussion history.

Compares 2–8 independently finalized HUMAN discussion rounds against the
same exact native owner inbox. No targets, sender, grants, approval or scans.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import io
from pathlib import Path
import shutil
import sys

from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    private_parent, read_owner_file, reject, safe_human, write_private,
)
from portfolio_focus import local_path
from portfolio_owner_attention import read_discussion
from portfolio_owner_inbox_review import STAGES, read_inbox

SCHEMA = "lightup.private.workspace-ledger-human-inbox-history.v1"
COLUMNS = (
    "local_case", "historical_transition", "original_kit",
    "original_proposed_human_owner", "original_human_stage",
    "original_owner_reply_stage", "first_human_triage_stage",
    "latest_human_triage_stage", "stage_changed_rounds",
    "private_note_changed_rounds",
)
MAX_ROUNDS = 8


def admit(args):
    if not (2 <= len(args.discussion) == len(args.review_csv) <= MAX_ROUNDS):
        reject("PRIVATE HOLD: require 2–8 explicit finalized HUMAN rounds and original CSVs")
    paths = [args.inbox, args.private_parent, *args.discussion, *args.review_csv]
    if any(not local_path(p) for p in paths) or len(paths) != len(set(paths)):
        reject("PRIVATE HOLD: original HUMAN history paths must be distinct absolute paths")
    private_parent(args.private_parent)
    original_raw, original_doc, original_rows = read_inbox(args.inbox)
    rounds = []
    seen = set()
    for discussion_path, csv_path in zip(args.discussion, args.review_csv):
        csv_raw = read_owner_file(csv_path, MAX_MANIFEST)
        discussion_raw, rows = read_discussion(
            discussion_path, original_raw, original_doc, csv_raw, original_rows
        )
        fingerprint = digest(discussion_raw)
        if fingerprint in seen:
            reject("PRIVATE HOLD: repeated byte-identical HUMAN round cannot form history")
        seen.add(fingerprint)
        rounds.append({
            "discussion_path": discussion_path,
            "csv_path": csv_path,
            "discussion_raw": discussion_raw,
            "csv_raw": csv_raw,
            "digest": fingerprint,
            "csv_digest": digest(csv_raw),
            "rows": rows,
        })
    return original_raw, original_doc, original_rows, rounds


def summarize(original_rows, rounds):
    out = []
    events = Counter()
    for index, original in enumerate(original_rows):
        history = [round_["rows"][index] for round_ in rounds]
        first = history[0]
        change_steps = []
        note_steps = []
        for step in range(1, len(history)):
            before, after = history[step - 1], history[step]
            if before["human_triage_stage"] != after["human_triage_stage"]:
                change_steps.append(step + 1)
                events["stage_changes"] += 1
            if before["private_human_triage_note"] != after["private_human_triage_note"]:
                note_steps.append(step + 1)
                events["note_changes"] += 1
        latest = history[-1]
        events["latest_" + latest["human_triage_stage"]] += 1
        if change_steps or note_steps:
            events["changed_rows"] += 1
        out.append({
            "local_case": original["local_case"],
            "historical_transition": original["historical_transition"],
            "original_kit": original["original_kit"],
            "original_proposed_human_owner": original["original_proposed_human_owner"],
            "original_human_stage": original["original_human_stage"],
            "original_owner_reply_stage": original["new_human_reply_stage"],
            "first_human_triage_stage": first["human_triage_stage"],
            "latest_human_triage_stage": latest["human_triage_stage"],
            "stage_changed_rounds": change_steps,
            "private_note_changed_rounds": note_steps,
            "round_stages": [row["human_triage_stage"] for row in history],
        })
    return out, events


def minimal_html(rows, rounds, counts):
    lines = [
        "<p><strong>PRIVATE historical HUMAN discussion only, NOT a finding, "
        "fix, work completion, recipient identity, consent, scope, scan or grant.</strong> "
        "Original owner labels, case identifiers, free notes, paths and source "
        "hashes are omitted from this count-only summary.</p>",
        "<p>Explicit, manually ordered original HUMAN rounds: " + str(len(rounds)) +
        "; original unchanged HUMAN source slots: " + str(len(rows)) + ".</p>",
        "<table><thead><tr><th>Human-only metric</th><th>Count</th></tr></thead><tbody>",
    ]
    for label, value in (
        ("Slots with changed proposed stage or private note", counts["changed_rows"]),
        ("Proposed stage transitions between adjacent rounds", counts["stage_changes"]),
        ("PRIVATE human notes changed between adjacent rounds", counts["note_changes"]),
        *((("Latest human stage: " + stage), counts["latest_" + stage]) for stage in STAGES),
    ):
        lines.append("<tr><td>" + html.escape(label) + "</td><td>" +
                     str(value) + "</td></tr>")
    lines.append("</tbody></table><p>No automatic follow-up or release signal.</p>")
    return html_page("LightUp PRIVATE HUMAN discussion timeline counts", "".join(lines))


def private_html(rows, rounds):
    lines = [
        "<p><strong>Owner-private HUMAN-only history, DRAFT/HOLD.</strong> "
        "Round numbers are solely the explicit operator-provided order, "
        "not dated/authenticated meetings. No verified remediation, real "
        "owner assignment, permission, security clearance or event notification.</p>",
        "<table><thead><tr><th>Original HUMAN owner label</th><th>Source slot</th>"
        "<th>Original stage / owner reply</th><th>HUMAN stage by original round</th>"
        "<th>Stage changes at rounds</th><th>Private note changed at rounds (text never included)</th>"
        "</tr></thead><tbody>",
    ]
    for row in rows:
        def escape(value):
            return html.escape(str(value), quote=True)
        lines.append(
            "<tr><td>" + escape(row["original_proposed_human_owner"]) +
            "</td><td>" + escape(row["local_case"]) + " / " +
            escape(row["historical_transition"]) + " / " +
            escape(row["original_kit"]) + "</td><td>" +
            escape(row["original_human_stage"]) + " / " +
            escape(row["original_owner_reply_stage"]) + "</td><td>" +
            escape(" → ".join(row["round_stages"])) + "</td><td>" +
            escape(", ".join(map(str, row["stage_changed_rounds"])) or "none") +
            "</td><td>" +
            escape(", ".join(map(str, row["private_note_changed_rounds"])) or "none") +
            "</td></tr>"
        )
    lines.append("</tbody></table><p>Private free-text review notes remain exclusively "
                 "in the ORIGINAL HUMAN discussion files. This derived history "
                 "never copies their text.</p>")
    return html_page("LightUp PRIVATE original HUMAN discussion timeline", "".join(lines))


def changed_brief_html(rows, original_slot_count, rounds):
    body = [
        "<p><strong>PRIVATE HUMAN-only change discussion — no verified fix, "
        "security finding, recipient approval, consent or real work order.</strong> "
        "Includes only original HUMAN rows whose proposed stage or private "
        "note changed between adjacent explicitly supplied rounds. "
        "Free-text notes are never copied.</p>",
        "<p>Original scoped HUMAN slots: " + str(original_slot_count) +
        "; changed HUMAN discussion rows: " + str(len(rows)) +
        "; explicit HUMAN rounds: " + str(len(rounds)) + ".</p>",
    ]
    if not rows:
        body.append("<p>No HUMAN-only proposed changes across these original rounds. "
                    "This is NOT evidence that a finding was resolved.</p>")
    else:
        body.append("<table><thead><tr><th>Proposed HUMAN owner</th>"
                    "<th>Original case / transition / kit</th>"
                    "<th>First → latest HUMAN proposal</th>"
                    "<th>Stage changes at rounds</th>"
                    "<th>Private note changed at rounds (not content)</th>"
                    "</tr></thead><tbody>")
        for r in rows:
            def esc(x):
                return html.escape(str(x), quote=True)
            body.append("<tr><td>" + esc(r["original_proposed_human_owner"]) +
                        "</td><td>" + esc(r["local_case"]) + " / " +
                        esc(r["historical_transition"]) + " / " +
                        esc(r["original_kit"]) + "</td><td>" +
                        esc(r["first_human_triage_stage"]) + " → " +
                        esc(r["latest_human_triage_stage"]) + "</td><td>" +
                        esc(",".join(map(str, r["stage_changed_rounds"])) or "none") +
                        "</td><td>" +
                        esc(",".join(map(str, r["private_note_changed_rounds"])) or "none") +
                        "</td></tr>")
        body.append("</tbody></table>")
    body.append("<p>All inputs remain unchanged. Original notes stay solely "
                "in the owner's original PRIVATE records.</p>")
    return html_page("LightUp PRIVATE original HUMAN discussion changes", "".join(body))


def as_csv(rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([
            ",".join(map(str, row[key])) if isinstance(row[key], list)
            else row[key] for key in COLUMNS
        ])
    return stream.getvalue()


def run(args):
    original_raw, original_doc, original_rows, rounds = admit(args)
    rows, counts = summarize(original_rows, rounds)
    owner = getattr(args, "owner", None)
    if owner is not None:
        if type(owner) is not str or not owner or owner != owner.strip():
            reject("PRIVATE HOLD: explicit exact original HUMAN owner required")
        safe_human(owner, 80)
        scoped = [row for row in rows if row["original_proposed_human_owner"] == owner]
        if not scoped:
            reject("PRIVATE HOLD: proposed HUMAN owner absent from original inbox")
        rows = scoped
        counts = Counter()
        for row in rows:
            if row["stage_changed_rounds"] or row["private_note_changed_rounds"]:
                counts["changed_rows"] += 1
            counts["stage_changes"] += len(row["stage_changed_rounds"])
            counts["note_changes"] += len(row["private_note_changed_rounds"])
            counts["latest_" + row["latest_human_triage_stage"]] += 1
    # Exact original native admissions are repeated BEFORE PRIVATE publication.
    # If any owner-controlled input drifted, publish nothing.
    if read_inbox(args.inbox)[0] != original_raw:
        reject("PRIVATE HOLD: original inbox bytes changed before output")
    for round_ in rounds:
        csv_raw = read_owner_file(round_["csv_path"], MAX_MANIFEST)
        if csv_raw != round_["csv_raw"]:
            reject("PRIVATE HOLD: original HUMAN CSV changed before output")
        native, rebuilt = read_discussion(
            round_["discussion_path"], original_raw, original_doc,
            csv_raw, original_rows
        )
        if native != round_["discussion_raw"] or rebuilt != round_["rows"]:
            reject("PRIVATE HOLD: original HUMAN round changed before output")
    result = {
        "schema": SCHEMA, "authority": FLAGS, "historical_only": True,
        "sources_reopened": False, "recipient_authenticated": False,
        "consent_assumed": False, "actions_dispatched": False,
        "appointments_booked": False, "verified_remediation": False,
        "original_inbox_sha256": digest(original_raw),
        "selected_original_proposed_human_owner_label": owner,
        "owner_scoped_private_export": owner is not None,
        "original_human_discussion_rounds": [
            {"round": ordinal, "original_discussion_sha256": round_["digest"],
             "original_review_csv_sha256": round_["csv_digest"]}
            for ordinal, round_ in enumerate(rounds, 1)
        ],
        "private_human_history_slots": rows,
    }
    changed = [r for r in rows if r["stage_changed_rounds"] or
               r["private_note_changed_rounds"]]
    # Package source-free CSP-pinned browser software alongside this original
    # owner-private report; never embed any original HUMAN source in the HTML.
    from portfolio_inbox_timeline import render as render_timeline
    exports = {
        "PRIVATE-HUMAN-history-explorer.html": render_timeline(),
        "OPEN-PRIVATE.html": minimal_html(rows, rounds, counts),
        "PRIVATE-HUMAN-inbox-history.html": private_html(rows, rounds),
        "PRIVATE-HUMAN-inbox-history.csv": as_csv(rows),
        "PRIVATE-HUMAN-inbox-history.json": canonical(result),
        "PRIVATE-HUMAN-changed-only.html": changed_brief_html(changed, len(rows), rounds),
        "PRIVATE-HUMAN-changed-only.csv": as_csv(changed),
    }
    if any(len(x if isinstance(x, bytes) else x.encode("utf-8")) >
           MAX_MANIFEST for x in exports.values()):
        reject("PRIVATE HOLD: original HUMAN discussion history exceeds private artifact limit")
    directory = new_private(args.private_parent)
    try:
        for name, payload in exports.items():
            write_private(directory, name, payload)
    except BaseException:
        shutil.rmtree(directory)
        raise
    print("PRIVATE HOLD: source-exact original HUMAN discussion history; no action or authority")
    print(str(Path(directory) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Compare 2–8 original source-bound PRIVATE HUMAN inbox review rounds offline"
    )
    parser.add_argument("--inbox", required=True, help="Original PRIVATE-HUMAN-owner-inbox.json")
    parser.add_argument("--discussion", required=True, action="append",
                        help="Original finalized PRIVATE-HUMAN-inbox-review.json; repeat 2–8")
    parser.add_argument("--review-csv", required=True, action="append",
                        help="Corresponding unchanged HUMAN-inbox-review-template.csv; repeat 2–8")
    parser.add_argument("--owner", required=False,
                        help="Optional EXACT original proposed HUMAN owner; export only own slots")
    parser.add_argument("--private-parent", required=True,
                        help="Existing private owner-only 0700 parent outside repository")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, TypeError, ValueError, UnicodeError, csv.Error):
        print("PRIVATE HOLD: original HUMAN discussion history cannot be admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
