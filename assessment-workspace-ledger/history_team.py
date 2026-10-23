#!/usr/bin/env python3
"""PRIVATE source-chain-exact human reviewer reconciliation for original kit timelines.

Existing independently authored native HUMAN packets are UNSIGNED. Side-by-side
review never proves authorship, consent, remediation, scope or permission.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from history import load_history, summarize
from history_human import expected_rows
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, hexhash, html_page,
    new_private, object_unique, read_owner_file, reject, safe_human, write_private,
)

MIN_REVIEWERS = 2
MAX_REVIEWERS = 8
MAX_REVIEW_CSV = 192 * 1024
HEADERS = ("transition", "kit_ordinal", "to_ledger_sha256", "to_kit_digest",
           "chosen_packet_sha256", "stage", "owner", "question")
def literal_false_authority(value):
    # Python's equality treats 0 == False: no implicit numeric authority aliases.
    return (type(value) is dict and set(value) == set(FLAGS) and
            all(value[key] is False for key in FLAGS))


PACKET_KEYS = {
    "schema", "authority", "sources_reopened", "historical_only",
    "human_review_is_not_authorization", "original_ledger_sha256",
    "human_plan_sha256", "rows",
}


def parse_packet(raw, sources, expected):
    if not raw or len(raw) > MAX_MANIFEST:
        reject("PRIVATE HOLD: native HUMAN reviewer packet size")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: invalid HUMAN JSON number"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable HUMAN reviewer packet") from exc
    if (not isinstance(obj, dict) or set(obj) != PACKET_KEYS or
            obj["schema"] != "lightup.private.workspace-ledger-history-human.v1" or
            not literal_false_authority(obj["authority"]) or obj["sources_reopened"] is not False or
            obj["historical_only"] is not True or
            obj["human_review_is_not_authorization"] is not True or
            not hexhash(obj["human_plan_sha256"])):
        reject("PRIVATE HOLD: reviewer packet schema and literal no-authority")
    if (type(obj["original_ledger_sha256"]) is not list or
            obj["original_ledger_sha256"] != [s["sha256"] for s in sources]):
        reject("PRIVATE HOLD: reviewer packet from another ORIGINAL ledger sequence")
    rows = obj["rows"]
    if type(rows) is not list or len(rows) != len(expected):
        reject("PRIVATE HOLD: reviewer packet original row count")
    admitted = []
    keys = {"transition", "kit_ordinal", "from_ledger_sha256",
            "to_ledger_sha256", "to_kit_digest", "label_changed",
            "change_counts", "stage", "owner", "question"}
    for row, origin in zip(rows, expected):
        if not isinstance(row, dict) or set(row) != keys:
            reject("PRIVATE HOLD: reviewer row unknown fields")
        fields = (
            ("transition", "transition"), ("kit_ordinal", "kit_ordinal"),
            ("from_ledger_sha256", "from_ledger_sha256"),
            ("to_ledger_sha256", "to_ledger_sha256"), ("to_kit_digest", "to_kit_digest")
        )
        for key, baseline in fields:
            value = int(origin[baseline]) if key in ("transition", "kit_ordinal") else origin[baseline]
            if type(row[key]) is not type(value) or row[key] != value:
                reject("PRIVATE HOLD: original row ledger SHA or kit ordinal mismatch")
        if type(row["label_changed"]) is not bool or row["label_changed"] != bool(int(origin["label_changed"])):
            reject("PRIVATE HOLD: altered source dossier label drift")
        counts = row["change_counts"]
        if not isinstance(counts, dict) or set(counts) != {"added","removed","changed","unchanged"}:
            reject("PRIVATE HOLD: malformed original file counts")
        if any(type(counts[key]) is not int or counts[key] != int(origin[key]) for key in counts):
            reject("PRIVATE HOLD: original file counts changed")
        stage, owner, question = row["stage"], row["owner"], row["question"]
        if type(stage) is not str or stage not in ("needs_review", "owner_followup", "hold", "reference_only"):
            reject("PRIVATE HOLD: invalid original HUMAN stage")
        safe_human(owner, 80)
        safe_human(question, 500)
        if any("\n" in v or "\t" in v for v in (owner, question)):
            reject("PRIVATE HOLD: unexpected multiline HUMAN value")
        admitted.append({"stage": stage, "owner": owner, "question": question})
    return admitted


def packets_from_paths(paths, sources, expected, expected_hashes=None):
    if not MIN_REVIEWERS <= len(paths) <= MAX_REVIEWERS or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: select 2-8 distinct native original HUMAN packet paths")
    packets, hashes = [], set()
    for index, path in enumerate(paths):
        raw = read_owner_file(path, MAX_MANIFEST)
        fingerprint = digest(raw)
        if fingerprint in hashes or (expected_hashes and fingerprint != expected_hashes[index]):
            reject("PRIVATE HOLD: repeated or modified native HUMAN original")
        hashes.add(fingerprint)
        packets.append({"sha256": fingerprint, "rows": parse_packet(raw, sources, expected)})
    return packets


def context_from_inputs(paths, reviewer_paths, sources, packets):
    return {
        "schema": "lightup.private.workspace-ledger-team-context.v1",
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "original_ledgers": [{"path": p, "sha256": source["sha256"]}
                             for p, source in zip(paths, sources)],
        "original_reviewers": [{"path": p, "sha256": packet["sha256"]}
                               for p, packet in zip(reviewer_paths, packets)]
    }


def exact_context(raw):
    if len(raw) > MAX_MANIFEST or not raw:
        reject("PRIVATE HOLD: team context too large")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: invalid context number"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: invalid original context") from exc
    if (not isinstance(obj, dict) or set(obj) != {
            "schema", "authority", "historical_only", "sources_reopened",
            "original_ledgers", "original_reviewers"
        } or obj["schema"] != "lightup.private.workspace-ledger-team-context.v1" or
            not literal_false_authority(obj["authority"]) or obj["historical_only"] is not True or
            obj["sources_reopened"] is not False):
        reject("PRIVATE HOLD: team context not from original private workflow")
    for key, low, high in (("original_ledgers", 2, 12), ("original_reviewers", 2, 8)):
        arr = obj[key]
        if type(arr) is not list or not low <= len(arr) <= high:
            reject("PRIVATE HOLD: team context count")
        seen = set()
        for row in arr:
            if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
                reject("PRIVATE HOLD: malformed team source reference")
            path = row["path"]
            if (not isinstance(path, str) or len(path) > 4096 or
                    not os.path.isabs(path) or os.path.normpath(path) != path or path in seen or
                    not hexhash(row["sha256"])):
                reject("PRIVATE HOLD: ambiguous or missing original private file")
            seen.add(path)
    return obj


def rows_template(expected):
    return [
        {"transition": x["transition"], "kit_ordinal": x["kit_ordinal"],
         "to_ledger_sha256": x["to_ledger_sha256"], "to_kit_digest": x["to_kit_digest"],
         "chosen_packet_sha256": "none", "stage": "needs_review", "owner": "", "question": ""}
        for x in expected
    ]


def csv_content(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=HEADERS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def parse_choices(payload, expected, packets):
    if not payload or len(payload) > MAX_REVIEW_CSV:
        reject("PRIVATE HOLD: empty or oversized HUMAN reconciliation CSV")
    try:
        value = payload.decode("utf-8", errors="strict")
        if "\r" in value or "\x00" in value:
            reject("PRIVATE HOLD: invalid HUMAN reconciliation control characters")
        reader = csv.DictReader(io.StringIO(value, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != HEADERS:
            reject("PRIVATE HOLD: original HUMAN reconciliation CSV headers")
        rows = list(reader)
    except (UnicodeError, csv.Error, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable HUMAN reconciliation CSV") from exc
    if len(rows) != len(expected):
        reject("PRIVATE HOLD: missing or extra HUMAN reconciliation decisions")
    lookup = {packet["sha256"]: packet for packet in packets}
    result = []
    for index, (row, reference) in enumerate(zip(rows, expected)):
        if None in row or set(row) != set(HEADERS) or any(
            row[field] != reference[field] for field in HEADERS[:4]
        ):
            reject("PRIVATE HOLD: HUMAN decision original source identity changed")
        chosen = row["chosen_packet_sha256"]
        fields = (row["stage"], row["owner"], row["question"])
        if chosen == "none":
            if fields != ("needs_review", "", ""):
                reject("PRIVATE HOLD: unspecified reviewer must remain needs_review")
            original_index = None
        elif chosen in lookup:
            candidate = lookup[chosen]["rows"][index]
            if fields != (candidate["stage"], candidate["owner"], candidate["question"]):
                reject("PRIVATE HOLD: selected reviewer decision was changed or spliced")
            original_index = next(i + 1 for i, pkt in enumerate(packets) if pkt["sha256"] == chosen)
        else:
            reject("PRIVATE HOLD: unknown or stale reviewer packet SHA")
        result.append({
            "transition": int(reference["transition"]),
            "kit_ordinal": int(reference["kit_ordinal"]),
            "to_ledger_sha256": reference["to_ledger_sha256"],
            "to_kit_digest": reference["to_kit_digest"],
            "human_selected_packet": chosen,
            "human_selected_reviewer_slot": original_index,
            "human_stage": fields[0], "human_owner": fields[1], "human_question": fields[2],
        })
    return result


def render_overview(sources, expected, packets):
    conflicts = 0
    changes = 0
    for index in range(len(expected)):
        opinions = {(p["rows"][index]["stage"], p["rows"][index]["owner"],
                     p["rows"][index]["question"]) for p in packets}
        if len(opinions) > 1:
            conflicts += 1
        else:
            changes += 1
    return html_page(
        "LightUp PRIVATE historical HUMAN reviewer coordination",
        "<p>Original unsigned reviewer packets compared on the SAME chained original "
        "source ledgers. An identical opinion is not an approved result, authentic reviewer, "
        "client consent or verified remediation. Original kit files were NOT reopened.</p>"
        "<p>HUMAN decisions requiring explicit choice: " + str(len(expected)) +
        "; disagreeing proposed HUMAN decisions: " + str(conflicts) +
        "; identical proposed HUMAN decisions: " + str(changes) +
        " (NEVER auto-selected).</p><p><a href='REVIEW-TEAM-IN-BROWSER.html'>"
        "Open locally the PRIVATE multi-reviewer browser workroom</a> and "
        "download HUMAN-team-review.csv, then call history_team.py finalize "
        "against this exact PRIVATE-team-context.json.</p>"
        "<p>Original labels, reviewer opinions, source fingerprints and HUMAN questions "
        "remain PRIVATE. NOTHING dispatched, consented, scanned or signed.</p>"
    )


def private_parent_for_originals(parent, sources):
    value = os.path.normpath(parent)
    if value != parent or not os.path.isabs(value):
        reject("PRIVATE HOLD: canonical absolute destination required")
    for kit in sources[0]["doc"]["kits"]:
        if os.path.commonpath((kit["path"], value)) == kit["path"]:
            reject("PRIVATE HOLD: output cannot be placed in original source kit")
    return value


def prepare(args):
    # Recorded original file paths must remain directly usable for strict
    # exact-byte reopening. Reject paths that would be held by native finalize.
    all_paths = list(args.ledger) + list(args.reviewer)
    if any(not isinstance(p, str) or not os.path.isabs(p) or
           os.path.normpath(p) != p or len(p) > 4096 for p in all_paths):
        reject("PRIVATE HOLD: all original owner-private paths must be canonical absolute")
    sources = load_history(args.ledger)
    transitions, _, _ = summarize(sources)
    expected = expected_rows(sources, transitions)
    packets = packets_from_paths(args.reviewer, sources, expected)
    context = context_from_inputs(args.ledger, args.reviewer, sources, packets)
    private = new_private(private_parent_for_originals(args.private_parent, sources))
    try:
        from history_team_browser import render
        write_private(private, "PRIVATE-team-context.json", canonical(context))
        write_private(private, "HUMAN-team-review-template.csv", csv_content(rows_template(expected)))
        write_private(private, "REVIEW-TEAM-IN-BROWSER.html", render(sources, transitions, expected, packets))
        write_private(private, "OPEN-PRIVATE.html", render_overview(sources, expected, packets))
    except BaseException:
        shutil.rmtree(private)
        raise
    print("PRIVATE HOLD: reviewer proposals compared, NEVER consent or verified result")
    print(str(Path(private) / "OPEN-PRIVATE.html"))
    return 3


def read_explicit_download(path):
    p = Path(path)
    if not p.is_absolute() or not re.fullmatch(r"HUMAN-team-review(?: ?\([1-9][0-9]{0,3}\))?\.csv", p.name):
        reject("PRIVATE HOLD: choose explicit original HUMAN-team-review.csv browser download")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_REVIEW_CSV):
            reject("PRIVATE HOLD: browser CSV is not owner-owned regular bounded single-link")
        data = bytearray()
        while True:
            blob = os.read(fd, 32768)
            if not blob:
                break
            data.extend(blob)
            if len(data) > MAX_REVIEW_CSV:
                reject("PRIVATE HOLD: oversized browser review")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(data) != before.st_size:
            reject("PRIVATE HOLD: browser review mutated during admission")
        return bytes(data), bool(before.st_mode & 0o077)
    finally:
        os.close(fd)


def finalize(args):
    original_context = read_owner_file(args.context, MAX_MANIFEST)
    context = exact_context(original_context)
    paths = [item["path"] for item in context["original_ledgers"]]
    sources = load_history(paths)
    if [source["sha256"] for source in sources] != [
        item["sha256"] for item in context["original_ledgers"]
    ]:
        reject("PRIVATE HOLD: an ORIGINAL stored ledger changed")
    steps, _, _ = summarize(sources)
    expected = expected_rows(sources, steps)
    packets = packets_from_paths(
        [item["path"] for item in context["original_reviewers"]], sources, expected,
        [item["sha256"] for item in context["original_reviewers"]]
    )
    if bool(args.csv) == bool(args.browser_csv):
        reject("PRIVATE HOLD: choose precisely one CSV source")
    if args.csv:
        payload = read_owner_file(args.csv, MAX_REVIEW_CSV)
        exposed = False
    else:
        payload, exposed = read_explicit_download(args.browser_csv)
    choices = parse_choices(payload, expected, packets)
    # One more exact-source admission before publishing final new PRIVATE packet.
    if digest(read_owner_file(args.context, MAX_MANIFEST)) != digest(original_context):
        reject("PRIVATE HOLD: context changed before publication")
    if [source["sha256"] for source in load_history(paths)] != [
        source["sha256"] for source in sources
    ]:
        reject("PRIVATE HOLD: original private source ledger changed before publication")
    if [p["sha256"] for p in packets_from_paths(
        [item["path"] for item in context["original_reviewers"]], sources, expected
    )] != [p["sha256"] for p in packets]:
        reject("PRIVATE HOLD: original reviewer bytes changed before publication")
    artifact = {
        "schema": "lightup.private.workspace-ledger-team-human.v1",
        "authority": FLAGS,
        "sources_reopened": False, "review_only": True,
        "context_sha256": digest(original_context),
        "reviewer_packet_sha256": [p["sha256"] for p in packets],
        "human_choice_csv_sha256": digest(payload),
        "rows": choices,
    }
    body = [
        "<p>All selections are PRIVATE HUMAN proposals between original unsigned "
        "reviewer packets. Reviewer agreement and selected stages never grant "
        "consent or verify remediation. No source kits reopened, no scans, no PASS.</p>",
        "<table><thead><tr><th>Step</th><th>Kit</th><th>Selected original reviewer</th>"
        "<th>HUMAN stage</th><th>Proposed HUMAN owner</th>"
        "<th>PRIVATE human question</th></tr></thead><tbody>"
    ]
    for row in choices:
        body.append(
            "<tr><td>" + str(row["transition"]) + "</td><td>" +
            str(row["kit_ordinal"]) + "</td><td>" +
            ("NONE / fresh HUMAN review required" if row["human_selected_reviewer_slot"] is None
             else str(row["human_selected_reviewer_slot"])) +
            "</td><td>" + html.escape(row["human_stage"]) +
            "</td><td>" + html.escape(row["human_owner"]) +
            "</td><td>" + html.escape(row["human_question"]) + "</td></tr>"
        )
    body.append("</tbody></table><p>Only a HUMAN proposal on EXACT original unsigned "
                "source-ledger/packet bytes. No actual client/operator authorization.</p>")
    private = new_private(private_parent_for_originals(args.private_parent, sources))
    try:
        write_private(private, "PRIVATE-HUMAN-team-choice.json", canonical(artifact))
        write_private(private, "PRIVATE-HUMAN-team-choice.html",
                      html_page("LightUp PRIVATE HUMAN team reconciliation", "".join(body)))
        write_private(private, "HUMAN-team-review.csv", payload)
        write_private(private, "OPEN-PRIVATE.html", html_page(
            "LightUp PRIVATE HUMAN reconciliation custody",
            "<p>ORIGINAL reviewer packets and source ledgers were exact-byte reopened, "
            "NOT the original customer source kits. New owner-private 0700/0600 "
            "packet is a HUMAN review HOLD, never permission.</p>"
            "<p><a href='PRIVATE-HUMAN-team-choice.html'>Open PRIVATE HUMAN choices</a>.</p>" +
            ("<p>Original browser download untouched. Existing group/other-readable "
             "exposure cannot be undone.</p>" if exposed else "")
        ))
    except BaseException:
        shutil.rmtree(private)
        raise
    print("PRIVATE HOLD: native source-bound reviewer choices recorded; NEVER grant or clearance")
    print(str(Path(private) / "OPEN-PRIVATE.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(description="Offline PRIVATE multi-HUMAN review of identical original ledger timeline")
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("prepare", help="Original-bound PRIVATE comparison workroom")
    start.add_argument("--ledger", action="append", required=True)
    start.add_argument("--reviewer", action="append", required=True)
    start.add_argument("--private-parent", required=True)
    end = sub.add_parser("finalize", help="Record explicit HUMAN selections under exact native source context")
    end.add_argument("--context", required=True)
    group = end.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv")
    group.add_argument("--browser-csv")
    end.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    try:
        return prepare(args) if args.action == "prepare" else finalize(args)
    except (Hold, OSError, ValueError, UnicodeError, TypeError, csv.Error):
        print("PRIVATE HOLD: source-exact HUMAN team operation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
