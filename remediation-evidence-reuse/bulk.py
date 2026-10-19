#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN bulk editor for original evidence reuse follow-up.

Operates on the local HUMAN inbox only; never issues original native HUMAN Apply,
security approval, evidence deletion, grant, scan, retest or network request.
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys

from review import Hold, exact_string, private_publish, private_read, require, pairs, reject_constant
from triage import (STAGES, admit_session, canonical, durable_replace, fresh_original_bytes,
                    make_session, now_utc, selected_sources, single_host_lock, sha)

KIND = "lightup.private_evidence_reuse_bulk_edit"
FIELDS = frozenset(("kind", "schema_version", "disposition", "source_packet_sha256",
                    "previous_packet_sha256", "proposal_sha256", "session_sha256",
                    "rows", "warning"))
ITEM_FIELDS = frozenset(("ordinal", "finding_id", "local_sha256",
                         "proposed_human_questions", "baseline_stage",
                         "baseline_human_note", "new_stage", "new_human_note"))


def worksheet(expected: dict, current_session: dict, session_bytes: bytes) -> dict:
    rows = []
    for row in current_session["records"]:
        rows.append({
            "ordinal": row["ordinal"],
            "finding_id": row["finding_id"],
            "local_sha256": row["local_sha256"],
            "proposed_human_questions": list(row["reasons"]),
            "baseline_stage": row["stage"],
            "baseline_human_note": row["human_note"],
            "new_stage": row["stage"],
            "new_human_note": row["human_note"],
        })
    return {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_DRAFT_ONLY",
        "source_packet_sha256": expected["source_packet_sha256"],
        "previous_packet_sha256": expected["previous_packet_sha256"],
        "proposal_sha256": expected["proposal_sha256"],
        "session_sha256": sha(session_bytes),
        "rows": rows,
        "warning": "Edit ONLY new_stage and new_human_note. HUMAN draft only; no native Apply, verification, consent, grant or scan.",
    }


def read_worksheet(path: Path, reference: dict) -> tuple[list[dict], list[dict]]:
    raw = private_read(path)
    require(len(raw) <= 1024 * 1024, "PRIVATE human edit worksheet too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Hold("Malformed PRIVATE HUMAN worksheet") from exc
    require(type(value) is dict and set(value) == FIELDS,
            "Unknown or missing HUMAN edit worksheet fields")
    for field in FIELDS - {"rows"}:
        require(type(value[field]) is type(reference[field]) and
                value[field] == reference[field],
                "Edited original source or unchanged HUMAN worksheet metadata")
    baseline = reference["rows"]
    rows = value["rows"]
    require(type(rows) is list and len(rows) == len(baseline),
            "PRIVATE HUMAN worksheet is incomplete or reordered")
    updates = []
    for number, (item, original) in enumerate(zip(rows, baseline), 1):
        require(type(item) is dict and set(item) == ITEM_FIELDS,
                "Unknown or missing HUMAN worksheet row fields")
        for field in ITEM_FIELDS - {"new_stage", "new_human_note"}:
            require(type(item[field]) is type(original[field]) and
                    item[field] == original[field],
                    "Original HUMAN row identity/baseline changed")
        require(type(item["ordinal"]) is int and item["ordinal"] == number,
                "Noncanonical HUMAN ordinal")
        require(type(item["new_stage"]) is str and item["new_stage"] in STAGES,
                "Invalid HUMAN-only proposed stage")
        exact_string(item["new_human_note"], 1200, "PRIVATE HUMAN proposed note")
        if item["new_stage"] != original["baseline_stage"] or (
                item["new_human_note"] != original["baseline_human_note"]):
            updates.append({
                "ordinal": number,
                "before": original["baseline_stage"],
                "after": item["new_stage"],
                "note_changed": item["new_human_note"] != original["baseline_human_note"],
            })
    return rows, updates


def main() -> int:
    parser = argparse.ArgumentParser(description="Source-bound offline PRIVATE HUMAN bulk review workflow")
    parser.add_argument("action", choices=("export", "preview", "apply"))
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--worksheet", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.worksheet != args.current and args.worksheet != args.previous and
                args.worksheet != args.session,
                "PRIVATE worksheet and actual source/session paths must differ")
        current, previous, current_bytes, previous_bytes = selected_sources(
            args.current, args.previous)
        expected = make_session(current, previous, current_bytes, previous_bytes)
        with single_host_lock(args.session):
            session_bytes = private_read(args.session)
            session = admit_session(session_bytes, expected)
            reference = worksheet(expected, session, session_bytes)
            if args.action == "export":
                fresh_original_bytes(args, current_bytes, previous_bytes)
                require(private_read(args.session) == session_bytes,
                        "PRIVATE HUMAN stage changed during worksheet preparation")
                private_publish(args.worksheet, canonical(reference))
                print("PRIVATE editable HUMAN worksheet created with " +
                      str(len(reference["rows"])) + " exact source-bound rows.")
                return 2
            rows, changed = read_worksheet(args.worksheet, reference)
            # No private notes displayed, including on preview.
            print("PRIVATE HUMAN BULK PREVIEW: " + str(len(changed)) + " changed of " +
                  str(len(rows)) + " original local actions.")
            for row in changed:
                print("Ordinal " + str(row["ordinal"]) + ": " +
                      row["before"] + " -> " + row["after"] +
                      " | private note changed: " + str(row["note_changed"]).lower())
            if args.action == "preview":
                return 2
            require(changed, "No changed HUMAN rows to apply")
            require(sys.stdin.isatty() and sys.stderr.isatty(),
                    "Actual HUMAN bulk Apply requires an interactive private terminal")
            confirmation = getpass.getpass(
                "Type APPLY PRIVATE HUMAN NOTES ONLY to replace selected local states: ")
            require(confirmation == "APPLY PRIVATE HUMAN NOTES ONLY",
                    "Human acknowledgement required; nothing modified")
            for row in rows:
                existing = session["records"][row["ordinal"] - 1]
                if existing["stage"] == row["new_stage"] and (
                        existing["human_note"] == row["new_human_note"]):
                    continue
                existing["stage"] = row["new_stage"]
                existing["human_note"] = row["new_human_note"]
                existing["updated_utc"] = now_utc()
            fresh_original_bytes(args, current_bytes, previous_bytes)
            require(private_read(args.session) == session_bytes,
                    "PRIVATE HUMAN session changed during operator review; no update")
            # Editing worksheet during preview/acknowledgement must also HOLD.
            final_rows, final_changes = read_worksheet(args.worksheet, reference)
            require(final_rows == rows and final_changes == changed,
                    "Worksheet changed while awaiting operator confirmation")
            durable_replace(args.session, canonical(session))
            print("Published " + str(len(changed)) +
                  " PRIVATE HUMAN-only changes atomically; original evidence unchanged.")
            return 2
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
