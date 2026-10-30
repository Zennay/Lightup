#!/usr/bin/env python3
"""Minimum-necessary owner-private HUMAN concern follow-up from original triage.

Never distributes source notes, grants permission or authenticates an audience.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import csv
import io
import json
import os
import shutil
import sys
import tempfile

from notes import (Hold, file_new, private_directory, private_input,
                   read_json, save_json)
from privacy_triage import (SCHEMA as TRIAGE_SCHEMA, STATUSES, TOPICS, FALSE_FLAGS,
                            completed_packet, read_completed_csv, render)

SCHEMA = "lightup.private_notes_human_sensitivity_focus.v1"
CSV_FIELDS = ("source_ordinal", "review_status", "privacy_topics", "human_followup")


def focus(original: str, review: str, topic: str, status: str,
          parent_string: str) -> int:
    parent = private_directory(parent_string)
    triage_kit = private_directory(review)
    sources, original_manifest_sha, decision_sha = completed_packet(original)

    receipt_raw = private_input(str(triage_kit / "PRIVATE-HUMAN-sensitivity-receipt.json"),
                                64 * 1024)
    receipt = read_json(triage_kit / "PRIVATE-HUMAN-sensitivity-receipt.json", 64 * 1024)
    complete_raw = private_input(str(triage_kit / "PRIVATE-HUMAN-sensitivity.csv"), 64 * 1024)
    all_rows = read_completed_csv(complete_raw, sources)
    valid_keys = {"schema", "claimed_status", "human_review_only", "original_count",
                  "original_manifest_sha256_unsigned", "original_human_csv_sha256_unsigned",
                  "sensitivity_human_csv_sha256_unsigned", "status_counts", "topic_counts",
                  *FALSE_FLAGS}
    if (set(receipt) != valid_keys
            or receipt["schema"] != TRIAGE_SCHEMA
            or receipt["claimed_status"] != "HOLD"
            or receipt["human_review_only"] is not True
            or type(receipt["original_count"]) is not int
            or receipt["original_count"] != len(sources)
            or receipt["original_manifest_sha256_unsigned"] != original_manifest_sha
            or receipt["original_human_csv_sha256_unsigned"] != decision_sha
            or receipt["sensitivity_human_csv_sha256_unsigned"] != sha256(complete_raw).hexdigest()
            or any(receipt[flag] is not False for flag in FALSE_FLAGS)
            or receipt["status_counts"] != {
                name: sum(row["review_status"] == name for row in all_rows)
                for name in STATUSES}
            or receipt["topic_counts"] != {
                name: sum(name in row["privacy_topics"].split("|") for row in all_rows)
                for name in TOPICS}):
        raise Hold("HOLD: original full PRIVATE HUMAN triage receipt cannot be re-admitted")

    # Never silently broaden from one explicitly selected topic and one HUMAN
    # discussion status. UNKNOWN is possible, but never implies sanitization.
    selected = [row for row in all_rows if row["review_status"] == status
                and topic in row["privacy_topics"].split("|")]
    if not selected:
        raise Hold("HOLD: no original HUMAN concerns match exactly this request")

    destination = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-sensitivity-focus-", dir=parent))
    os.chmod(destination, 0o700)
    complete = False
    try:
        csv_sink = io.StringIO(newline="")
        writer = csv.DictWriter(csv_sink, fieldnames=CSV_FIELDS, lineterminator="\r\n")
        writer.writeheader()
        for row in selected:
            writer.writerow({column: row[column] for column in CSV_FIELDS})
        manifest = {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "audience_authenticated": False, "human_review_only": True,
            "original_manifest_sha256_unsigned": original_manifest_sha,
            "original_human_csv_sha256_unsigned": decision_sha,
            "complete_triage_receipt_sha256_unsigned": sha256(receipt_raw).hexdigest(),
            "complete_triage_csv_sha256_unsigned": sha256(complete_raw).hexdigest(),
            "selected_status": status, "selected_topic": topic,
            "selected_original_positions": [int(row["source_ordinal"]) for row in selected],
            "selected_count": len(selected),
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(destination / "PRIVATE-HUMAN-focus-bindings.json", manifest)
        file_new(destination / "PRIVATE-HUMAN-focus-only.csv",
                 csv_sink.getvalue().encode("utf-8"))
        file_new(destination / "OPEN-PRIVATE.html", render(selected, prepared=False))
        complete = True
        print("HOLD: PRIVATE minimum-necessary HUMAN concern agenda prepared locally.")
        print("OPEN LOCALLY: " + str(destination / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not complete:
            shutil.rmtree(destination)


def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE source-bound HUMAN sensitivity focus; no release")
    p.add_argument("--completed-packet", required=True)
    p.add_argument("--triage-review", required=True)
    p.add_argument("--topic", required=True, choices=TOPICS)
    p.add_argument("--status", required=True, choices=STATUSES)
    p.add_argument("--private-parent", required=True)
    a = p.parse_args()
    try:
        return focus(a.completed_packet, a.triage_review, a.topic, a.status, a.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError):
        print("HOLD: source-bound PRIVATE HUMAN sensitivity focus refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
