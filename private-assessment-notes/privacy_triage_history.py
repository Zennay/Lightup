#!/usr/bin/env python3
"""Compare 2–8 genuine completed PRIVATE HUMAN sensitivity reviews, offline.

No claims of effective masking, remediation, consent, release or reviewer identity.
All artifacts remain owner-private and existing source checks are reused unchanged.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import (Hold, file_new, private_directory, private_input,
                   read_json, save_json)
from privacy_triage import (
    SCHEMA as TRIAGE_SCHEMA, FALSE_FLAGS, STATUSES, TOPICS,
    completed_packet, csv_bytes, default_rows, read_completed_csv,
)

SCHEMA = "lightup.private_notes_human_sensitivity_history.v1"
FIELDS = ("original_ordinal", "from_round", "to_round", "from_status",
          "to_status", "from_topics", "to_topics", "human_note_changed")
MAX_ROUNDS = 8


def load_round(path: str, sources: list[dict],
               manifest_sha: str, decision_sha: str) -> dict:
    kit = private_directory(path)
    original_receipt = private_input(
        str(kit / "PRIVATE-HUMAN-sensitivity-receipt.json"), 64 * 1024)
    receipt = read_json(
        kit / "PRIVATE-HUMAN-sensitivity-receipt.json", 64 * 1024)
    csv_raw = private_input(
        str(kit / "PRIVATE-HUMAN-sensitivity.csv"), 64 * 1024)
    rows = read_completed_csv(csv_raw, sources)
    allowed = {"schema", "claimed_status", "human_review_only",
               "original_count", "original_manifest_sha256_unsigned",
               "original_human_csv_sha256_unsigned",
               "sensitivity_human_csv_sha256_unsigned",
               "status_counts", "topic_counts", *FALSE_FLAGS}
    if (set(receipt) != allowed
            or receipt["schema"] != TRIAGE_SCHEMA
            or receipt["claimed_status"] != "HOLD"
            or receipt["human_review_only"] is not True
            or type(receipt["original_count"]) is not int
            or receipt["original_count"] != len(sources)
            or receipt["original_manifest_sha256_unsigned"] != manifest_sha
            or receipt["original_human_csv_sha256_unsigned"] != decision_sha
            or receipt["sensitivity_human_csv_sha256_unsigned"] != sha256(csv_raw).hexdigest()
            or receipt["status_counts"] != {
                status: sum(row["review_status"] == status for row in rows)
                for status in STATUSES}
            or receipt["topic_counts"] != {
                topic: sum(topic in row["privacy_topics"].split("|")
                           for row in rows) for topic in TOPICS}
            or any(receipt[key] is not False for key in FALSE_FLAGS)):
        raise Hold("HOLD: source-bound HUMAN sensitivity round has altered receipt/counts")
    return {
        "rows": rows,
        "receipt_sha256_unsigned": sha256(original_receipt).hexdigest(),
        "csv_sha256_unsigned": sha256(csv_raw).hexdigest(),
        "csv_raw": csv_raw,
        "status_counts": receipt["status_counts"],
        "topic_counts": receipt["topic_counts"],
    }


def change_rows(rounds: list[dict]) -> list[dict]:
    changes = []
    for ridx in range(1, len(rounds)):
        for previous, current in zip(rounds[ridx - 1]["rows"],
                                     rounds[ridx]["rows"]):
            changes.append({
                "original_ordinal": previous["source_ordinal"],
                "from_round": ridx,
                "to_round": ridx + 1,
                "from_status": previous["review_status"],
                "to_status": current["review_status"],
                "from_topics": previous["privacy_topics"],
                "to_topics": current["privacy_topics"],
                "human_note_changed": previous["human_followup"] != current["human_followup"],
            })
    return changes


def changes_csv(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            key: ("TRUE" if row[key] else "FALSE")
            if key == "human_note_changed" else row[key]
            for key in FIELDS
        })
    return stream.getvalue().encode("utf-8")


def counts_csv(rounds: list[dict], changes: list[dict]) -> bytes:
    """PRIVATE category and stage counts. No original identities or human text."""
    columns = ("round", "originals", "pending", "review_required", "withhold",
               "credentials", "personal_data", "client_data", "other", "unknown",
               "literal_changed_since_previous", "note_changed_since_previous")
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=columns, lineterminator="\r\n")
    writer.writeheader()
    for ridx, packet in enumerate(rounds, start=1):
        counts = packet["status_counts"]
        topics = packet["topic_counts"]
        shifted = [row for row in changes if row["to_round"] == ridx]
        writer.writerow({
            "round": ridx, "originals": len(packet["rows"]),
            "pending": counts["PENDING"],
            "review_required": counts["REVIEW_REQUIRED"],
            "withhold": counts["WITHHOLD"],
            "credentials": topics["CREDENTIALS"],
            "personal_data": topics["PERSONAL_DATA"],
            "client_data": topics["CLIENT_DATA"],
            "other": topics["OTHER"], "unknown": topics["UNKNOWN"],
            "literal_changed_since_previous": sum(
                row["from_status"] != row["to_status"]
                or row["from_topics"] != row["to_topics"]
                or row["human_note_changed"] for row in shifted),
            "note_changed_since_previous": sum(row["human_note_changed"]
                                               for row in shifted),
        })
    return out.getvalue().encode("utf-8")


def history_html(rounds: list[dict], changes: list[dict]) -> bytes:
    cards = []
    for index, round_data in enumerate(rounds, start=1):
        counts = round_data["status_counts"]
        cards.append(
            "<section class='card'><h2>Manual HUMAN round #" + str(index) +
            "</h2><p>Pending " + str(counts["PENDING"]) +
            " · Review required " + str(counts["REVIEW_REQUIRED"]) +
            " · Withhold " + str(counts["WITHHOLD"]) +
            "</p></section>"
        )
    lines = []
    for item in changes:
        moved = (item["from_status"] != item["to_status"]
                 or item["from_topics"] != item["to_topics"]
                 or item["human_note_changed"])
        lines.append(
            "<tr class='" + ("changed" if moved else "unchanged") + "'>"
            "<th scope='row'>#" + html.escape(item["original_ordinal"]) + "</th>"
            "<td>" + str(item["from_round"]) + " → " + str(item["to_round"]) + "</td>"
            "<td>" + html.escape(item["from_status"]) + " → " +
            html.escape(item["to_status"]) + "</td>"
            "<td>" + html.escape(item["from_topics"]) + " → " +
            html.escape(item["to_topics"]) + "</td>"
            "<td>" + ("Yes" if item["human_note_changed"] else "No") + "</td>"
            "<td>" + ("HUMAN change" if moved else "No literal change") + "</td>"
            "</tr>"
        )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; connect-src 'none'; form-action 'none'; object-src 'none'">
<title>LightUp · PRIVATE HUMAN sensitivity history</title>
<style>body{max-width:1200px;margin:2rem auto;padding:1rem;font:16px/1.55 system-ui;color:#152e44}
.warning{background:#fff0e6;border-left:5px solid #ad482c;padding:15px}
.card{display:inline-block;border:1px solid #ccd9e5;margin:10px 10px 10px 0;padding:12px}
table{border-collapse:collapse;width:100%}td,th{padding:10px;border:1px solid #c6d5e1;text-align:left}
.changed{background:#f2f7ff}thead{background:#e7eef6}
@media(max-width:680px){table{display:block;overflow-x:auto}}</style>
<h1>Original-bound PRIVATE HUMAN sensitivity history</h1>
<aside class="warning"><b>HOLD · NOT CLEARED FOR RELEASE</b><p>
HUMAN labels, changing privacy concern counts, reduced WITHHOLD counts or unchanged
source notes never prove a fix, privacy safety, independent reviewer identity,
consent, security clearance or permission to share. No source-note content and
no free HUMAN note text are embedded in this history page.</p></aside>
""" + "".join(cards) + """
<h2>All original HUMAN transitions, in the operator-declared round order</h2>
<table><thead><tr><th>Original</th><th>Rounds</th><th>HUMAN statuses</th>
<th>Possible categories</th><th>Free note changed?</th>
<th>Literal state</th></tr></thead><tbody>""" + "".join(lines) + """</tbody></table>
<p>The chronology is a manual local order, not verified timestamps or authorship.
Open the PRIVATE change CSV and bindings for original source-bound references.
The next blank review is a new HUMAN draft, not an automatic copy of prior
clearances. In the offline editor, explicitly select the last-round PRIVATE
CSV to resume after complete source matching and manual confirmation.</p>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No scanning, execution,
network, publishing, grants, deletion or external recipients.</p></html>""").encode("utf-8")


def landing(n: int, originals: int, identical_pairs: list[list[int]]) -> bytes:
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none'">
<title>LightUp PRIVATE sensitivity continuity</title>
<style>body{max-width:850px;margin:2rem auto;padding:1rem;font:17px/1.55 system-ui}
aside{border-left:5px solid #a94c30;background:#fff0e8;padding:16px}
li{padding:.3rem}</style>
<h1>PRIVATE HUMAN sensitivity continuity</h1>
<aside><b>HOLD · REVIEW ONLY · NO CONSENT OR PRIVACY CLEARANCE.</b>
This workroom contains unsent, owner-private HUMAN proposals and source
hashes. Local review history never proves risk reduction or recipient authority.</aside>
<p>Original source positions: """ + str(originals) + """ · manually ordered
PRIVATE completed review rounds: """ + str(n) + """; byte-identical HUMAN decision round pairs: """ + str(len(identical_pairs)) + """.
Matching review CSV bytes are declared duplicate content, not validated author identities, independent reviewer opinions, chronological evidence, or privacy PASS.</p>
<ul><li><a href="PRIVATE-HUMAN-timeline.html">Explore interactive offline HUMAN timeline</a></li>
<li><a href="PRIVATE-HUMAN-history.html">Read printable HUMAN history</a></li>
<li><a href="PRIVATE-HUMAN-transitions.csv">Read full PRIVATE change table</a></li>
<li><a href="PRIVATE-HUMAN-round-counts.csv">PRIVATE counts-only per-round overview</a></li>
<li><a href="PRIVATE-HUMAN-history-bindings.json">Read PRIVATE unsigned history receipt</a></li>
<li><a href="PRIVATE-HUMAN-last-round.csv">Review previous full PRIVATE HUMAN draft</a></li>
<li><a href="PRIVATE-HUMAN-sensitivity-editor.html">Open next blank HUMAN review editor</a></li>
<li><a href="PRIVATE-HUMAN-sensitivity-template.csv">Next blank PRIVATE template</a></li>
<li><a href="PRIVATE-triage-bindings.json">Next draft source binding</a></li>
</ul><p>The new draft is PENDING/UNKNOWN for every original. The offline editor
supports explicit, source-exact reimport of the previous full CSV, with HUMAN
confirmation. Finalize with the original complete source packet and this
history kit as --triage-kit using the existing native sensitivity-finalize.
This is not proof of privacy or permission to transmit.</p></html>""").encode("utf-8")


def build(original: str, review_paths: list[str], parent_string: str) -> int:
    if not 2 <= len(review_paths) <= MAX_ROUNDS:
        raise Hold("HOLD: choose 2-8 completed original PRIVATE sensitivity reviews")
    normalized = [str(Path(value).absolute()) for value in review_paths]
    if len(set(normalized)) != len(normalized):
        raise Hold("HOLD: duplicate PRIVATE HUMAN review round")
    parent = private_directory(parent_string)
    sources, manifest_sha, decision_sha = completed_packet(original)
    rounds = [
        load_round(value, sources, manifest_sha, decision_sha)
        for value in normalized
    ]
    # Distinct completed review packets may contain unchanged HUMAN decisions.
    # Keep all manually ordered rounds, but never treat matching bytes as proof
    # of independent authors or additional security/privacy confidence.
    digests = [entry["csv_sha256_unsigned"] for entry in rounds]
    identical_pairs = [
        [earlier + 1, later + 1]
        for earlier in range(len(digests))
        for later in range(earlier + 1, len(digests))
        if digests[earlier] == digests[later]
    ]
    transitions = change_rows(rounds)
    destination = Path(tempfile.mkdtemp(
        prefix="PRIVATE-lightup-sensitivity-history-", dir=parent))
    os.chmod(destination, 0o700)
    done = False
    try:
        previous = []
        for ordinal, round_data in enumerate(rounds, start=1):
            previous.append({
                "human_round": ordinal,
                "private_receipt_sha256_unsigned":
                    round_data["receipt_sha256_unsigned"],
                "private_complete_human_csv_sha256_unsigned":
                    round_data["csv_sha256_unsigned"],
                "status_counts": round_data["status_counts"],
                "topic_counts": round_data["topic_counts"],
            })
        change_counts = {
            "literal_transition_positions": sum(
                row["from_status"] != row["to_status"]
                or row["from_topics"] != row["to_topics"]
                or row["human_note_changed"]
                for row in transitions),
            "status_changed_positions": sum(
                row["from_status"] != row["to_status"] for row in transitions),
            "topic_changed_positions": sum(
                row["from_topics"] != row["to_topics"] for row in transitions),
            "human_note_changed_positions": sum(
                row["human_note_changed"] for row in transitions),
        }
        save_json(destination / "PRIVATE-HUMAN-history-bindings.json", {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "manual_round_order_not_verified_chronology": True,
            "human_only_not_privacy_clearance": True,
            "original_count": len(sources),
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decision_sha,
            "review_rounds": previous, "literal_change_counts": change_counts,
            "identical_human_csv_round_pairs_not_independent_proof": identical_pairs,
            **{flag: False for flag in FALSE_FLAGS},
        })
        file_new(destination / "PRIVATE-HUMAN-history.html",
                 history_html(rounds, transitions))
        from privacy_triage_timeline import render as interactive_timeline
        file_new(destination / "PRIVATE-HUMAN-timeline.html",
                 interactive_timeline(rounds))
        file_new(destination / "PRIVATE-HUMAN-transitions.csv",
                 changes_csv(transitions))
        file_new(destination / "PRIVATE-HUMAN-round-counts.csv",
                 counts_csv(rounds, transitions))
        file_new(destination / "PRIVATE-HUMAN-last-round.csv",
                 rounds[-1]["csv_raw"])
        # This genuinely is a fresh, strictly original-source-bound triage
        # preflight. The existing original native sensitivity-finalize accepts
        # this as --triage-kit only if the original completed source remains
        # exactly byte-identical. There is NO implicit carryover of conclusions.
        save_json(destination / "PRIVATE-triage-bindings.json", {
            "schema": TRIAGE_SCHEMA, "claimed_status": "HOLD",
            "original_manifest_sha256_unsigned": manifest_sha,
            "original_human_csv_sha256_unsigned": decision_sha,
            "sources": [
                {"ordinal": row["ordinal"],
                 "source_sha256_unsigned": row["source_sha256_unsigned"]}
                for row in sources
            ],
            **{flag: False for flag in FALSE_FLAGS},
        })
        file_new(destination / "PRIVATE-HUMAN-sensitivity-template.csv",
                 csv_bytes(default_rows(sources)))
        from privacy_triage_studio import render as browser_editor
        file_new(destination / "PRIVATE-HUMAN-sensitivity-editor.html",
                 browser_editor(default_rows(sources)))
        file_new(destination / "OPEN-PRIVATE.html",
                 landing(len(rounds), len(sources), identical_pairs))
        done = True
        print("REVIEW_ONLY: source-exact PRIVATE HUMAN history and blank next round created")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not done:
            shutil.rmtree(destination)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Owner-private source-bound HUMAN sensitivity history; no clearance")
    p.add_argument("--completed-packet", required=True)
    p.add_argument("--review", action="append", required=True,
                   help="original completed HUMAN sensitivity review, in manual order, 2-8")
    p.add_argument("--private-parent", required=True)
    args = p.parse_args()
    try:
        return build(args.completed_packet, args.review, args.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: PRIVATE HUMAN sensitivity history refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
