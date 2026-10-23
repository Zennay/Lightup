#!/usr/bin/env python3
"""Explicit, offline HUMAN-only conflict choices for overlapping role returns.

No automatic precedence, identity verification, real authorization, or target I/O.
"""
from __future__ import annotations

import argparse
import base64
import copy
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
import sys

from launchpad import FLAGS, Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import read_original_bundle, require_private_file, validate_worksheet
from history import admitted_rounds
from role_return_receipt import admit_return, canonical
from role_return_conflict_editor import NAME as EDITOR_FILE, render as render_editor

PREPARE = (
    "lightup-lab-human-conflict-choice-template.csv",
    "lightup-lab-human-conflict-review-private.html",
    EDITOR_FILE,
    "START-HERE-CONFLICT-PRIVATE.txt",
)
RESOLVED = (
    "lightup-lab-human-conflict-resolved-private.json",
    "lightup-lab-human-conflict-source-context.json",
    "lightup-lab-human-conflict-decisions-private.csv",
    "START-HERE-CONFLICT-PRIVATE.txt",
)
HEADER = ("source_set_sha256", "original_slot", "eligible_packet_numbers", "chosen_packet_number")
LIMIT = 65536
STYLE = (
    "body{font:15px/1.55 system-ui,sans-serif;max-width:1000px;margin:2rem auto;"
    "padding:0 1rem;background:#f2f5fa;color:#13243a}"
    ".hold{background:#fff1d9;border-left:6px solid #a15a14;padding:1rem;font-weight:750}"
    "section{background:white;padding:1rem;margin:1.2rem 0;border:1px solid #b9c9d8}"
    "table{width:100%;border-collapse:collapse}td,th{text-align:left;"
    "border:1px solid #c5d4e3;padding:.65rem}th{background:#e9f0f9}"
)


def read_packets(paths, rounds, endpoints, digest):
    if not 2 <= len(paths) <= 5:
        raise Hold("conflict choice requires 2-5 original role returns")
    packets = []
    seen = set()
    for path in paths:
        absolute, work, selected = admit_return(path, rounds, endpoints, digest)
        if absolute in seen:
            raise Hold("same source return directory supplied twice")
        seen.add(absolute)
        packets.append((absolute, work, selected))
    return packets


def source_set_digest(digest, rounds, packets):
    holder = sha256()
    holder.update(digest.encode("ascii"))
    for record in rounds:
        item = canonical(record)
        holder.update(len(item).to_bytes(8, "big"))
        holder.update(item)
    for _directory, work, slots in packets:
        item = canonical(work)
        holder.update(len(item).to_bytes(8, "big"))
        holder.update(item)
        holder.update(canonical([i + 1 for i in slots]))
    return holder.hexdigest()


def overlap_map(packets):
    indexes = {}
    for number, (_directory, _work, slots) in enumerate(packets, 1):
        for slot in slots:
            indexes.setdefault(slot, []).append(number)
    return indexes


def prepare_files(rounds, packets, fingerprint):
    overlaps = {slot: choices for slot, choices in overlap_map(packets).items()
                if len(choices) > 1}
    if not overlaps:
        raise Hold("original role packets are disjoint; use advance.py --role-return-dir")
    sink = io.StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(HEADER)
    rows = []
    editor_rows = []
    original = rounds[-1]["human_rows"]
    for slot in sorted(overlaps):
        options = overlaps[slot]
        writer.writerow((fingerprint, slot + 1, "|".join(map(str, options)), ""))
        editor_options = []
        for number in options:
            proposed = packets[number - 1][1]["human_rows"][slot]
            prior = original[slot]
            rows.append((slot + 1, number, prior["role"], prior["stage"],
                         proposed["stage"],
                         "YES" if proposed["note"] != prior["note"] else "NO"))
            editor_options.append({"packet": number, "role": prior["role"],
                                   "stage": proposed["stage"],
                                   "noteChanged": proposed["note"] != prior["note"]})
        editor_rows.append({"slot": slot + 1, "options": editor_options})
    tr = "".join(
        "<tr>" + "".join("<td>" + escape(str(cell)) + "</td>" for cell in row)
        + "</tr>" for row in rows
    )
    hashed = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + hashed + "'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN overlap choices</title><style>" + STYLE
        + "</style></head><body><h1>PRIVATE HUMAN role overlap decisions</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD ·"
        " REVIEW_ONLY · NO AUTHORIZATION</p><section><p>" +
        str(len(overlaps)) + " original local HUMAN slots have more than one "
        "source-bound return. There is NEVER automatic precedence. "
        "Record a conscious packet number for every conflicting slot in the "
        "separate PRIVATE CSV template. All other original slots have one "
        "unambiguous source packet or retain original HUMAN state.</p>"
        "<p>Packet numbers are only the ORDER of --role-return-dir flags."
        " No endpoint URLs, private note text, paths, recipient identities or"
        " original source hashes appear in this PRIVATE HTML.</p></section>"
        "<section><table><thead><tr><th>Original slot</th><th>Return packet number</th>"
        "<th>Voluntary HUMAN role</th><th>Prior HUMAN stage</th>"
        "<th>Proposed HUMAN stage</th><th>Private note changed?</th>"
        "</tr></thead><tbody>" + tr + "</tbody></table></section>"
        "<p>Only the ORIGINAL source-bound return files are admitted. This "
        "display does not verify the identity of a reviewer, consent, a fix, "
        "scope, approval or HUMAN GO. Never host or share publicly.</p>"
        "</body></html>"
    ).encode("utf-8")
    return dict(zip(PREPARE, (
        sink.getvalue().encode("utf-8"), html,
        render_editor(editor_rows, fingerprint), guide(False))))


def guide(resolved):
    mode = "OWNER-PRIVATE RESULT" if resolved else "MANUAL HUMAN CHOICE"
    return (
        "LIGHTUP PRIVATE HUMAN RETURN OVERLAP — " + mode + "\n"
        "INCUBATE M3/M7 · DRAFT/HOLD · REVIEW_ONLY · NO AUTHORIZATION\n"
        "All original PRIVATE inputs and reviewer roles are UNSIGNED.\n"
        "Resolved output includes an ordinal-only PRIVATE decision ledger CSV.\n"
        "The operator MUST consciously select exactly one original packet\n"
        "for EACH overlapping source slot; no automatic precedence is allowed.\n"
        "Never rewrite original packets. Overlap choice proves no consent or fix.\n"
        "Use the source-minimal offline browser choice editor OR manually edit CSV.\n"
        "The browser saves an explicit bounded CSV for native --decision-file.\n"
        "No endpoint values, private note text or source path appears in the\n"
        "choice CSV or HTML; final full worksheet is OWNER-PRIVATE and contains\n"
        "every role's original PRIVATE note, so NEVER forward it to recipients.\n"
        "Pass the full resolved JSON to advance.py --responses to create\n"
        "a NEW HUMAN planning round. No scan, model, target or grant occurs.\n"
    ).encode("utf-8")


def chosen_packets(raw, fingerprint, overlaps):
    if len(raw) > 32768 or raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise Hold("noncanonical or oversized conflict choice CSV")
    reader = csv.reader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
    if tuple(next(reader, ())) != HEADER:
        raise Hold("wrong HUMAN conflict choice columns")
    rows = list(reader)
    slots = sorted(overlaps)
    if len(rows) != len(slots):
        raise Hold("every overlapping original slot requires one explicit choice")
    choices = {}
    for slot, record in zip(slots, rows):
        expected = "|".join(map(str, overlaps[slot]))
        if len(record) != 4 or record[:3] != [fingerprint, str(slot + 1), expected]:
            raise Hold("HUMAN conflict input altered source/slot/packet list")
        choice = record[3]
        if choice not in tuple(map(str, overlaps[slot])):
            raise Hold("original conflict requires a human-selected eligible packet")
        choices[slot] = int(choice)
    return choices


def resolve_files(rounds, endpoints, digest, packets, fingerprint, decisions):
    grouped = overlap_map(packets)
    conflicts = {slot: candidates for slot, candidates in grouped.items()
                 if len(candidates) > 1}
    choice_map = chosen_packets(decisions, fingerprint, conflicts)
    full = copy.deepcopy(rounds[-1])
    for slot, candidate in grouped.items():
        chosen = choice_map[slot] if len(candidate) > 1 else candidate[0]
        full["human_rows"][slot] = copy.deepcopy(
            packets[chosen - 1][1]["human_rows"][slot])
    validate_worksheet(full, digest, len(endpoints))
    source = canonical(full)
    # Explicit ordinal choice is owner-private and deterministic. No endpoint
    # values, note text, recipient identity or paths enter this decision ledger.
    journal = io.StringIO(newline="")
    ledger = csv.writer(journal, lineterminator="\n")
    ledger.writerow(("original_slot", "manually_selected_packet_number",
                     "eligible_original_packet_numbers", "chosen_human_stage",
                     "private_note_changed"))
    for slot in sorted(choice_map):
        picked = choice_map[slot]
        original = rounds[-1]["human_rows"][slot]
        chosen = full["human_rows"][slot]
        ledger.writerow((slot + 1, picked, "|".join(map(str, grouped[slot])),
                         chosen["stage"], "YES" if original["note"] != chosen["note"] else "NO"))
    ledger_bytes = journal.getvalue().encode("utf-8")
    context = canonical({
        "schema": "lightup.assessment_launchpad_private_human_conflict_context.v1",
        "status": "REVIEW_ONLY",
        "source_set_sha256": fingerprint,
        "original_manifest_sha256": digest,
        "manual_conflict_count": len(choice_map),
        "source_packet_count": len(packets),
        "manual_choice_sha256": sha256(decisions).hexdigest(),
        "private_decision_ledger_sha256": sha256(ledger_bytes).hexdigest(),
        "owner_worksheet_sha256": sha256(source).hexdigest(),
        "identity_verified": False,
        "authorization_granted": False,
        "human_go": False,
        **{key: False for key in FLAGS},
    })
    return dict(zip(RESOLVED, (source, context, ledger_bytes, guide(True))))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit private source-bound HUMAN overlap decisions")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--round-dir", action="append", required=True)
    parser.add_argument("--role-return-dir", action="append", required=True)
    parser.add_argument("--decision-file", help="exact owner-private 0600 completed overlap CSV")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", help="fresh owner-only 0700 directory")
    mode.add_argument("--verify-output-dir", help="read-only exact source replay")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        source_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
        packets = read_packets(args.role_return_dir, rounds, endpoints, digest)
        fingerprint = source_set_digest(digest, rounds, packets)
        if args.decision_file:
            raw = require_private_file(args.decision_file, 32768)
            expected = resolve_files(rounds, endpoints, digest, packets,
                                     fingerprint, raw)
        else:
            expected = prepare_files(rounds, packets, fingerprint)
        if any(not 0 < len(data) <= LIMIT for data in expected.values()):
            raise Hold("PRIVATE HUMAN conflict output exceeds size bound")
        fd, dest = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            sources = (original, *source_dirs, *(packet[0] for packet in packets))
            if args.decision_file:
                sources = (*sources, os.path.abspath(args.decision_file))
            if any(os.path.commonpath((source, dest)) in (source, dest)
                   for source in sources):
                raise Hold("conflict output must be separate from all original inputs")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(expected) or any(
                        read_private_bundle_item(fd, name, LIMIT) != value
                        for name, value in expected.items()):
                    raise Hold("PRIVATE HUMAN conflict result drifted")
            else:
                if os.listdir(fd):
                    raise Hold("new PRIVATE conflict output must start empty")
                a, e, d = read_original_bundle(args.bundle_dir)
                new_dirs, new_rounds = admitted_rounds(args.round_dir, d, e)
                new_packets = read_packets(args.role_return_dir, new_rounds, e, d)
                if (a, e, d, new_dirs, new_rounds, new_packets) != (
                        original, endpoints, digest, source_dirs, rounds, packets):
                    raise Hold("PRIVATE role-return source changed before publication")
                if args.decision_file and require_private_file(
                        args.decision_file, 32768) != raw:
                    raise Hold("manual HUMAN choice input changed before publication")
                publish_bundle(fd, list(expected.items()))
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_CONFLICT_" +
              ("REOPENED" if args.verify_output_dir else
               "RESOLVED" if args.decision_file else "PREPARED") +
              " — MANUAL HUMAN ONLY; NO AUTHORITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_CONFLICT_HOLD — original packet or manual choices not admitted", error, args.explain_hold)
        return 3
    except (OSError, ValueError, UnicodeError, TypeError, OverflowError, csv.Error):
        report_hold("PRIVATE_HUMAN_CONFLICT_HOLD — original packet or manual choices not admitted", None, args.explain_hold)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
