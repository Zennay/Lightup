#!/usr/bin/env python3
"""A single PRIVATE offline operator workspace from genuine completed HUMAN reviews.

Modes are explicit: timeline = manually ordered HUMAN revisions;
reviewers = manually selected HUMAN reviewer submissions (NOT verified identities).
Existing source-bound readers and source-free offline renderer modules are reused.
No model, network, target, scan, consent, approval, communication or release.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import Hold, file_new, private_directory, save_json
from privacy_triage import (
    FALSE_FLAGS, SCHEMA as TRIAGE_SCHEMA, completed_packet, default_rows, csv_bytes,
)
from privacy_triage_history import (
    MAX_ROUNDS, change_rows, changes_csv, counts_csv, history_html, load_round,
)
from privacy_triage_reconcile import (
    matrix, matrix_csv, private_page, agenda_page,
)
from privacy_triage_timeline import render as timeline_studio
from privacy_triage_reconcile_studio import render as reviewer_studio
from privacy_triage_studio import render as blank_editor

SCHEMA = "lightup.private_notes_human_sensitivity_workbench.v1"
MODES = ("timeline", "reviewers")
REVIEWERS_MAX = 8


def portal(mode: str, originals: int, rounds: int, duplicate_pairs: int) -> bytes:
    is_timeline = mode == "timeline"
    label = ("Manually ordered HUMAN revisions" if is_timeline else
             "Manually selected HUMAN reviewer packets")
    links = [
        ("PRIVATE-HUMAN-board.html",
         "Interactive offline HUMAN " + ("timeline" if is_timeline else "reviewer comparison and next-review editor")),
        ("PRIVATE-HUMAN-overview.html",
         "Printable original-bound HUMAN overview"),
        ("PRIVATE-HUMAN-detail.csv",
         "PRIVATE complete original HUMAN " + ("transition" if is_timeline else "reviewer matrix") + " CSV"),
        ("PRIVATE-HUMAN-compact.csv",
         "PRIVATE aggregate round/category counts" if is_timeline else
         "PRIVATE follow-up source numbers only"),
        ("PRIVATE-HUMAN-attention.html",
         "Owner-private, selected-original-only HUMAN discussion agenda"),
        ("PRIVATE-HUMAN-workbench-bindings.json",
         "Private unsigned source and original review custody receipt"),
        ("PRIVATE-HUMAN-sensitivity-editor.html",
         "Independent BLANK next HUMAN review editor"),
        ("PRIVATE-HUMAN-sensitivity-template.csv",
         "Canonical blank full original-bound next HUMAN CSV"),
        ("PRIVATE-triage-bindings.json",
         "Next draft exact original source binding"),
    ]
    if is_timeline:
        links.append(("PRIVATE-HUMAN-last-round.csv",
                      "Complete LAST PRIVATE HUMAN decisions (contains confidential HUMAN note text)"))
    links_html = "".join(
        "<li><a href='" + html.escape(filename, quote=True) + "'>" +
        html.escape(title) + "</a></li>"
        for filename, title in links
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>LightUp PRIVATE HUMAN assessment sensitivity workbench</title>
<style>body{font:17px/1.6 system-ui;max-width:900px;padding:20px;margin:auto;color:#1c3048}
aside{border-left:5px solid #b34b2b;background:#fff1e9;padding:16px}
a{color:#124d77}a:focus-visible{outline:3px solid #db8624}li{margin:.5rem}</style>
<header><h1>PRIVATE HUMAN original-bound review workbench</h1>
<aside><b>DRAFT/HOLD · NOT CLEARED FOR RELEASE OR CLIENT USE.</b>
This is an owner-private local comparison of human-declared sensitivity
labels, not authentication, privacy safety, a confirmed fix, consent,
source ownership, verified reviewer independence, or approval. No network,
model, source scanning, grant, upload, external recipient or assessment run.</aside>
<p>Mode: <strong>""" + html.escape(label) + """</strong>.
Original positions: """ + str(originals) + """.
Original review packets: """ + str(rounds) + """.
Same-content original HUMAN CSV pairs: """ + str(duplicate_pairs) + """.
Byte-identical reviewer choices are NOT evidence of independently authenticated
people; manually ordered rounds are NOT authenticated timestamps.</p></header>
<main><h2>Offline files in this owner-private room</h2>
<ul>""" + links_html + """</ul>
<h2>Next independent HUMAN decision</h2><p>
All next-review choices start PENDING/UNKNOWN. The interactive reviewer Studio
may help prepare an explicit human proposal, never an automatic consensus or
grant. Export a complete PRIVATE CSV, move it into an owner-only directory,
chmod 600, and invoke unchanged native
<code>notes.py sensitivity-finalize --completed-packet ORIGINAL
--triage-kit THIS_WORKBENCH --completed-csv PRIVATE_CSV
--private-parent PRIVATE_0700</code>.
The native original source/decision and template admission is unchanged;
this workbench is not a substitute for it. Finalization always HOLD.</p>
</main><footer>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
No main merge, deployment or active operations authorized here.</footer></html>""").encode("utf-8")


def compact_review_csv(summaries: list[dict]) -> bytes:
    """One selected ORIGINAL position per line. No source identity or note text."""
    import csv
    import io
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(("original_ordinal", "human_attention", "human_status_disagreement",
                     "human_topic_disagreement", "private_note_disagreement",
                     "at_least_one_human_withhold", "at_least_one_human_review_required"))
    for row in summaries:
        # A handoff that includes every unaffected source slot increases
        # disclosure for no operator benefit. Full original/source-bound rows
        # stay available only in the separate owner-private reviewer matrix.
        if not row["human_action_needed"]:
            continue
        writer.writerow([
            row["original_ordinal"],
            "TRUE",
            "TRUE" if row["status_disagreement"] else "FALSE",
            "TRUE" if row["topic_disagreement"] else "FALSE",
            "TRUE" if row["human_note_disagreement"] else "FALSE",
            "TRUE" if row["any_withhold"] else "FALSE",
            "TRUE" if row["any_review_required"] else "FALSE",
        ])
    return out.getvalue().encode("utf-8")


def timeline_attention(packets: list[dict], transitions: list[dict]) -> bytes:
    """A printable PRIVATE latest-HUMAN attention agenda across declared rounds.

    Only original ordinals, literal labels, and change Booleans are emitted;
    never source content, previous/next free notes, URLs, original SHAs,
    guessed authors, automated classifications or inferred risk reduction.
    """
    source_count = len(packets[0]["rows"])
    lines = []
    for original in range(1, source_count + 1):
        changes = [row for row in transitions
                   if int(row["original_ordinal"]) == original]
        reasons = []
        if any(row["from_status"] != row["to_status"] for row in changes):
            reasons.append("Declared HUMAN stage changed across rounds")
        if any(row["from_topics"] != row["to_topics"] for row in changes):
            reasons.append("Declared possible categories changed across rounds")
        if any(row["human_note_changed"] for row in changes):
            reasons.append("PRIVATE HUMAN follow-up note changed; text withheld")
        latest = packets[-1]["rows"][original - 1]
        if latest["review_status"] == "WITHHOLD":
            reasons.append("Latest HUMAN status: WITHHOLD")
        elif latest["review_status"] == "REVIEW_REQUIRED":
            reasons.append("Latest HUMAN status: REVIEW_REQUIRED")
        if reasons:
            lines.append(
                "<li><b>Original #" + str(original) + "</b>: " +
                html.escape("; ".join(reasons)) + "</li>"
            )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>LightUp PRIVATE HUMAN next-round discussion</title>
<style>body{max-width:850px;margin:2rem auto;padding:1rem;font:16px/1.55 system-ui}
aside{border-left:5px solid #b34c2e;background:#fff1e8;padding:14px}
li{padding:7px 2px}</style>
<h1>PRIVATE HUMAN continuity discussion</h1>
<aside><b>HOLD · OWNER-PRIVATE · NO AUTHENTICATED HUMAN OR CLIENT APPROVAL.</b>
Only manually supplied, source-bound HUMAN round declarations. This private
source-position agenda is not a privacy safety, remediation or recipient
clearance verdict. Changes are not security fixes; unchanged labels do not
prove that confidential data has been removed.</aside>
<p>Manually ordered original HUMAN rounds: """ + str(len(packets)) +
            """ · original positions with literal change or latest HUMAN attention:
""" + str(len(lines)) + """ of """ + str(source_count) + """.</p><ol>""" +
            "".join(lines) + """</ol>
<p>No other original slots or free HUMAN note text are distributed in this
minimal local view. Source-bound original complete decisions remain in their
own 0600 private files. No network, scheduling, assignment, grant or sharing.</p>
</html>""").encode("utf-8")


def build(original: str, mode: str, review_paths: list[str], parent_name: str) -> int:
    if mode not in MODES:
        raise Hold("HOLD: explicitly choose timeline or reviewers mode")
    if not 2 <= len(review_paths) <= REVIEWERS_MAX:
        raise Hold("HOLD: choose 2–8 genuine original completed HUMAN review packets")
    paths = [str(Path(path).absolute()) for path in review_paths]
    if len(set(paths)) != len(paths):
        raise Hold("HOLD: duplicate original REVIEW directory selection")
    parent = private_directory(parent_name)
    sources, original_manifest_sha, original_decisions_sha = completed_packet(original)
    packets = [
        load_round(path, sources, original_manifest_sha, original_decisions_sha)
        for path in paths
    ]
    duplicates = [
        [i + 1, j + 1]
        for i in range(len(packets))
        for j in range(i + 1, len(packets))
        if packets[i]["csv_sha256_unsigned"] == packets[j]["csv_sha256_unsigned"]
    ]
    reviews = [
        {
            "declared_slot": i,
            "original_review_receipt_sha256_unsigned": packet["receipt_sha256_unsigned"],
            "original_review_csv_sha256_unsigned": packet["csv_sha256_unsigned"],
            "human_status_counts": packet["status_counts"],
            "human_topic_counts": packet["topic_counts"],
        }
        for i, packet in enumerate(packets, start=1)
    ]
    # All original source, completed-human and reviewer input has already
    # been fully admitted before allocating any new PRIVATE result directory.
    dest = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-workbench-", dir=parent))
    os.chmod(dest, 0o700)
    complete = False
    try:
        receipt = {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "mode": mode, "human_only_not_privacy_clearance": True,
            "declared_slots_not_authenticated_reviewers": True,
            "manual_order_not_verified_chronology": True,
            "original_count": len(sources),
            "original_manifest_sha256_unsigned": original_manifest_sha,
            "original_human_csv_sha256_unsigned": original_decisions_sha,
            "original_review_packets": reviews,
            "matching_human_csv_slot_pairs_not_independence_proof": duplicates,
            **{key: False for key in FALSE_FLAGS},
        }
        save_json(dest / "PRIVATE-HUMAN-workbench-bindings.json", receipt)
        if mode == "timeline":
            transitions = change_rows(packets)
            file_new(dest / "PRIVATE-HUMAN-overview.html",
                     history_html(packets, transitions))
            file_new(dest / "PRIVATE-HUMAN-board.html", timeline_studio(packets))
            file_new(dest / "PRIVATE-HUMAN-detail.csv",
                     changes_csv(transitions))
            file_new(dest / "PRIVATE-HUMAN-compact.csv",
                     counts_csv(packets, transitions))
            file_new(dest / "PRIVATE-HUMAN-attention.html",
                     timeline_attention(packets, transitions))
            # This is the only extra generated output containing PRIVATE
            # free-human-note text. File and directory remain owner-only.
            file_new(dest / "PRIVATE-HUMAN-last-round.csv",
                     packets[-1]["csv_raw"])
        else:
            all_rows, summaries = matrix(packets)
            file_new(dest / "PRIVATE-HUMAN-overview.html",
                     private_page(all_rows, summaries, len(packets)))
            file_new(dest / "PRIVATE-HUMAN-board.html",
                     reviewer_studio(sources, packets))
            file_new(dest / "PRIVATE-HUMAN-detail.csv",
                     matrix_csv(all_rows))
            file_new(dest / "PRIVATE-HUMAN-compact.csv",
                     compact_review_csv(summaries))
            file_new(dest / "PRIVATE-HUMAN-attention.html",
                     agenda_page(summaries))
        # The ORIGINAL sensitivity-finalize verifies these against original
        # completed notes and the exact, still-blank canonical source roster.
        source_binding = {
            "schema": TRIAGE_SCHEMA, "claimed_status": "HOLD",
            "original_manifest_sha256_unsigned": original_manifest_sha,
            "original_human_csv_sha256_unsigned": original_decisions_sha,
            "sources": [
                {
                    "ordinal": row["ordinal"],
                    "source_sha256_unsigned": row["source_sha256_unsigned"],
                }
                for row in sources
            ],
            **{flag: False for flag in FALSE_FLAGS},
        }
        blank = default_rows(sources)
        save_json(dest / "PRIVATE-triage-bindings.json", source_binding)
        file_new(dest / "PRIVATE-HUMAN-sensitivity-template.csv",
                 csv_bytes(blank))
        file_new(dest / "PRIVATE-HUMAN-sensitivity-editor.html",
                 blank_editor(blank))
        file_new(dest / "OPEN-PRIVATE.html",
                 portal(mode, len(sources), len(packets), len(duplicates)))
        complete = True
        print("REVIEW_ONLY: original-bound PRIVATE HUMAN unified workbench created")
        print("OPEN LOCALLY: " + str(dest / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not complete:
            shutil.rmtree(dest)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified offline PRIVATE source-bound HUMAN workbench; never a clearance")
    parser.add_argument("--completed-packet", required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--review", action="append", required=True,
                        help="2–8 existing completed original sensitivity reviews")
    parser.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    try:
        return build(args.completed_packet, args.mode, args.review,
                     args.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: PRIVATE original-bound HUMAN workbench refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
