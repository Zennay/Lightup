#!/usr/bin/env python3
"""Owner-local, non-authorizing return of a voluntarily role-filtered HUMAN handoff.

Produces a blank note-only CSV for the selected role, then admits a completed CSV
to build a full source-bound HUMAN worksheet for advance.py --responses.
Unsigned self-reports never establish reviewer identity, consent or authority.
"""
from __future__ import annotations

import argparse
import copy
import csv
import getpass
from hashlib import sha256
import io
import json
import os
import sys
import unicodedata

from launchpad import Hold, FLAGS, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import ROLES, STAGES, read_original_bundle, require_private_file, validate_worksheet
from history import admitted_rounds
from role_handoff import NAMES as HANDOFF_NAMES, LIMIT, assemble, select
from role_return_browser import NAME as EDITOR, render_editor
from role_return_receipt import CONTEXT_FILE, receipt, canonical

TEMPLATE = "lightup-lab-human-role-return-template.csv"
RESPONSE = "lightup-lab-human-role-return-private.json"
GUIDE = "START-HERE-HUMAN-RETURN-PRIVATE.txt"
HEADER = ("handoff_sha256", "original_slot", "selected_role",
          "latest_human_stage", "proposed_human_stage", "proposed_private_note")
MAX_REPLY = 32768


def read_handoff(directory, rounds, endpoints, role, stage, slots):
    expected = dict(assemble(rounds, endpoints, role, stage, slots))
    fd, absolute = open_output_directory(directory)
    try:
        if set(os.listdir(fd)) != set(HANDOFF_NAMES):
            raise Hold("role packet must have exactly its original four private files")
        actual = {name: read_private_bundle_item(fd, name, LIMIT) for name in HANDOFF_NAMES}
    finally:
        os.close(fd)
    if actual != expected:
        raise Hold("role packet is not the exact original source-bound handoff")
    fingerprint = sha256()
    for name in HANDOFF_NAMES:
        fingerprint.update(name.encode("ascii") + b"\x00")
        fingerprint.update(len(expected[name]).to_bytes(8, "big"))
        fingerprint.update(expected[name])
    return absolute, fingerprint.hexdigest()


def selected_template(rounds, role, stage, slots, fingerprint):
    indices = select(rounds, role, stage, slots)
    if not indices:
        raise Hold("no selected HUMAN return slots")
    sink = io.StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(HEADER)
    for index in indices:
        current = rounds[-1]["human_rows"][index]
        writer.writerow((fingerprint, index + 1, role,
                         current["stage"], current["stage"], ""))
    data = sink.getvalue().encode("utf-8")
    if not 0 < len(data) <= MAX_REPLY:
        raise Hold("bounded role-return template exceeded")
    return data, indices


def parse_reply(raw, rounds, role, fingerprint, indices):
    if len(raw) > MAX_REPLY or raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
        raise Hold("invalid or oversized HUMAN role return")
    decoded = raw.decode("utf-8")
    reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
    if tuple(next(reader, ())) != HEADER:
        raise Hold("unexpected role-return columns")
    rows = list(reader)
    if len(rows) != len(indices):
        raise Hold("role-return must include each selected original slot exactly once")
    previous = rounds[-1]["human_rows"]
    new_worksheet = copy.deepcopy(rounds[-1])
    for index, record in zip(indices, rows):
        if len(record) != len(HEADER):
            raise Hold("invalid HUMAN response row shape")
        digest, ordinal, reported_role, prior, proposed, note = record
        if (digest != fingerprint or ordinal != str(index + 1)
                or reported_role != role or prior != previous[index]["stage"]
                or proposed not in STAGES):
            raise Hold("role-return changed source binding, slot order, role or stage")
        # Quoting CSV does not neutralize spreadsheet formula cells.
        normalized = unicodedata.normalize("NFKC", note).lstrip()
        if note not in ("", "-") and normalized.startswith(("=", "+", "-", "@")):
            raise Hold("PRIVATE HUMAN CSV note resembles a spreadsheet formula")
        new_worksheet["human_rows"][index]["stage"] = proposed
        # An empty role-only export MUST NOT silently erase prior PRIVATE notes.
        # Explicit '-' is the sole clear operation; nonempty means replacement.
        if note == "-":
            new_worksheet["human_rows"][index]["note"] = ""
        elif note:
            new_worksheet["human_rows"][index]["note"] = note
        # The role assignment is deliberately immutable in this role reply.
    return new_worksheet



def interactive_reply(rounds, indices):
    """Edit only the selected HUMAN rows, without echoing PRIVATE note text."""
    if not sys.stdin.isatty():
        raise Hold("interactive role return requires a local human terminal")
    work = copy.deepcopy(rounds[-1])
    print("PRIVATE role return — self-reported only, no authorization")
    for index in indices:
        row = work["human_rows"][index]
        print("Original slot " + str(index + 1) + "; latest stage " + row["stage"] +
              "; private prior note characters " + str(len(row["note"])))
        print("  1 NEEDS_INPUT | 2 HUMAN_REVIEW | 3 FOLLOW_UP | Enter retain")
        selected = input("New HUMAN stage: ").strip()
        if selected not in ("", "1", "2", "3"):
            raise Hold("invalid fixed HUMAN stage response")
        if selected:
            row["stage"] = STAGES[int(selected) - 1]
        new_note = getpass.getpass("PRIVATE note (Enter retain, '-' clear): ")
        if new_note == "-":
            row["note"] = ""
        elif new_note:
            row["note"] = new_note
    return work


def return_guide(role, selected_count):
    return (
        "LIGHTUP PRIVATE HUMAN ROLE RETURN — REVIEW_ONLY / DRAFT-HOLD\n"
        "This is a voluntarily selected role, NOT an authenticated reviewer.\n"
        "Selected role: " + role + "; selected source slots: " + str(selected_count) + "\n"
        "Use the offline PRIVATE browser editor or edit only proposed_human_stage "+
        "and proposed_private_note in the CSV. Empty notes RETAIN prior content;\n"
        "a sole hyphen clears a prior private note intentionally.\n"
        "Keep all rows, their order and all other columns untouched.\n"
        "Proposed stages: " + ", ".join(STAGES) + ". Notes <=400 characters.\n"
        "Do not use spreadsheet formulas. Keep the CSV strictly PRIVATE and offline.\n"
        "The owner must import this file using role_return.py --reply-file.\n"
        "The resulting full worksheet is OWNER-PRIVATE: it may contain notes for OTHER roles.\n"
        "NEVER distribute the full worksheet back to a role recipient.\n"
        "Pass the resulting JSON to advance.py --responses with the unchanged source.\n"
        "Neither a role, return nor a successful import proves identity, consent,\n"
        "scope authorization, completion, safety, or HUMAN GO. No scans or targets.\n"
    ).encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline source-bound private HUMAN role-return")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--round-dir", action="append", required=True,
                        help="2-8 complete HUMAN rounds, original order")
    parser.add_argument("--handoff-dir", required=True,
                        help="the complete originally produced four-file PRIVATE handoff")
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--stage", choices=("ALL", *STAGES), default="ALL")
    parser.add_argument("--slot", type=int, action="append")
    reply = parser.add_mutually_exclusive_group()
    reply.add_argument("--reply-file", help="edited owner-private role-return CSV")
    reply.add_argument("--interactive", action="store_true",
                       help="owner-private TTY-only guided HUMAN reply without CSV")
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output-dir", help="separate empty owner-only 0700 destination")
    output.add_argument("--verify-output-dir", help="read-only exact original return reopen")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        if args.verify_output_dir and args.interactive:
            raise Hold("TTY capture cannot be regenerated without its original private reply")
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        round_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
        handoff_dir, fingerprint = read_handoff(args.handoff_dir, rounds, endpoints,
                                                args.role, args.stage, args.slot)
        template, indices = selected_template(rounds, args.role, args.stage,
                                              args.slot, fingerprint)
        fd, destination = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            inputs = (original, *round_dirs, handoff_dir)
            if args.reply_file:
                inputs += (os.path.abspath(args.reply_file),)
            for source in inputs:
                if os.path.commonpath((source, destination)) in (source, destination):
                    raise Hold("output and input paths must be separate")
            if args.output_dir and os.listdir(fd):
                raise Hold("PRIVATE role-return output must start empty")
            if args.reply_file or args.interactive:
                if args.reply_file:
                    raw = require_private_file(args.reply_file, MAX_REPLY)
                    work = parse_reply(raw, rounds, args.role, fingerprint, indices)
                else:
                    work = interactive_reply(rounds, indices)
                validate_worksheet(work, digest, len(endpoints))
                payload = canonical(work)
                if len(payload) > 65536:
                    raise Hold("new owner-private HUMAN worksheet exceeds bound")
                files = [(RESPONSE, payload), (CONTEXT_FILE, receipt(
                    rounds, endpoints, digest, args.role, args.stage, args.slot, payload))]
            else:
                files = [(TEMPLATE, template), (EDITOR, render_editor(template)),
                         (GUIDE, return_guide(args.role, len(indices)))]
            if any(not 0 < len(blob) <= 65536 for _, blob in files):
                raise Hold("PRIVATE role-return output exceeds exact reopen capacity")
            # Re-admit source inputs immediately before exclusive publication.
            latest_original, latest_endpoints, latest_digest = read_original_bundle(args.bundle_dir)
            latest_dirs, latest_rounds = admitted_rounds(args.round_dir, latest_digest, latest_endpoints)
            latest_handoff_dir, latest_fingerprint = read_handoff(
                args.handoff_dir, latest_rounds, latest_endpoints,
                args.role, args.stage, args.slot)
            if ((latest_original, latest_endpoints, latest_digest, latest_dirs,
                 latest_rounds, latest_handoff_dir, latest_fingerprint)
                    != (original, endpoints, digest, round_dirs, rounds,
                        handoff_dir, fingerprint)):
                raise Hold("original source, HUMAN rounds, or handoff drifted")
            if args.reply_file and require_private_file(args.reply_file, MAX_REPLY) != raw:
                raise Hold("HUMAN return changed before publication")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != {name for name, _ in files}:
                    raise Hold("PRIVATE role-return inventory differs")
                if any(read_private_bundle_item(fd, name, 65536) != blob
                       for name, blob in files):
                    raise Hold("role-return output does not match original admitted inputs")
            else:
                if os.listdir(fd):
                    raise Hold("role-return output changed before publication")
                publish_bundle(fd, files)
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_ROLE_RETURN_" + ("REOPENED" if args.verify_output_dir else "IMPORTED" if args.reply_file else "CAPTURED" if args.interactive else "PREPARED")
              + " slots=" + str(len(indices)) + " — UNSIGNED REVIEW_ONLY; NO AUTHORITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_ROLE_RETURN_HOLD — refused invalid PRIVATE source or reply", error, args.explain_hold)
        return 3
    except (OSError, ValueError, UnicodeError, TypeError, csv.Error, OverflowError, EOFError, KeyboardInterrupt):
        report_hold("PRIVATE_HUMAN_ROLE_RETURN_HOLD — refused invalid PRIVATE source or reply", None, args.explain_hold)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
