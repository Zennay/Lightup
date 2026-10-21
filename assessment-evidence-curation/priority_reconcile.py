#!/usr/bin/env python3
"""Offline full-source reconciliation of ONE unverified priority HUMAN return.

Original lab source, manifest, worksheet, selection and entire curated packet
are all re-admitted by their original native validators. No finding is
verified, no consent is conferred, no scan or network call is performed.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys

from briefing import json_bytes, publish_new
from curate import Hold, digest, literal_sha
from human_return import read_limited_file
from packet_open import MAX_JSON, json_private, read_private, reopen as reopen_curated
from packet_handoff import RECEIPT, TEMPLATE, reopen as reopen_handoff
from priority_reply import admit_rows, printable, MAX_RETURN_BYTES, UNTRUSTED_FLAGS
from response import accepted_original, csv_template, STAGES

REPORT = "PRIVATE-original-source-HUMAN-reconciliation.html"
COUNTS = "PRIVATE-original-source-HUMAN-reconciliation-counts.json"
RECEIPT_OUT = "PRIVATE-original-source-HUMAN-reconciliation-receipt.json"


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: full original-source HUMAN reconciliation refused")


def read_owner_dir(path: str, names: tuple[str, ...]) -> dict[str, bytes]:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        mode = os.fstat(fd)
        require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                stat.S_IMODE(mode.st_mode) == 0o700)
        return {name: read_private(fd, name, MAX_JSON if name.endswith(".json")
                                   else MAX_RETURN_BYTES) for name in names}
    finally:
        if fd >= 0:
            os.close(fd)


def reconcile(source_path: str, manifest_path: str, worksheet_path: str,
              receipt_path: str, selection_path: str, curated_dir: str,
              handoff_dir: str, returned_csv: str, output_dir: str) -> int:
    # First admit original source and all original HUMAN selection membership.
    source, source_sha, worksheet_sha, selection_raw, selected = accepted_original(
        source_path, manifest_path, worksheet_path, receipt_path, selection_path)
    # Reopen entire previously published owner-private original dossier.
    reopen_curated(curated_dir)
    curated = read_owner_dir(curated_dir, ("PRIVATE-curation-receipt.json",))
    original_packet_raw = curated["PRIVATE-curation-receipt.json"]
    original_packet = json_private(original_packet_raw)
    require(original_packet["original_source_sha256_unsigned"] == source_sha and
            original_packet["human_worksheet_sha256_unsigned"] == worksheet_sha and
            original_packet["human_selection_sha256_unsigned"] == digest(selection_raw))
    require(original_packet["selected_original_ordinals"] ==
            [row["ordinal"] for row in selected])

    # Reopen the original detached HUMAN priority handoff independently and
    # bind it back to this exact full ORIGINAL PRIVATE curation receipt.
    count = reopen_handoff(handoff_dir)
    handoff_files = read_owner_dir(handoff_dir, (RECEIPT, TEMPLATE))
    handoff_raw = handoff_files[RECEIPT]
    handoff = json_private(handoff_raw)
    require(handoff["original_private_packet_receipt_sha256_unsigned"] ==
            digest(original_packet_raw))
    priority = handoff["source_human_priority"]
    chosen = [row for row in selected if row["priority"] == priority]
    require(len(chosen) == count and count > 0)
    template = csv_template(source, chosen)
    require(handoff_files[TEMPLATE] == template and
            digest(template) == handoff["private_reply_template_sha256_unsigned"])

    human_raw = read_limited_file(returned_csv, MAX_RETURN_BYTES)
    human = admit_rows(template, human_raw)
    require(len(human) == count)
    report = printable(human)
    counts = {
        "schema": "lightup.private_full_source_priority_human_counts.v1",
        "status": "REVIEW_ONLY",
        "human_priority": priority,
        "original_reported_total_findings": len(source["findings"]),
        "original_human_selected_count": len(selected),
        "received_human_priority_rows": count,
        "recipient_human_stage_counts": {
            stage or "no_human_response":
                sum(r["recipient_stage"] == (stage or "no_human_response") for r in human)
            for stage in STAGES
        },
        **UNTRUSTED_FLAGS,
    }
    receipt = {
        "schema": "lightup.private_full_source_priority_human_reconciliation.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": source_sha,
        "original_worksheet_sha256_unsigned": worksheet_sha,
        "original_selection_sha256_unsigned": digest(selection_raw),
        "original_curated_packet_receipt_sha256_unsigned": digest(original_packet_raw),
        "original_priority_handoff_receipt_sha256_unsigned": digest(handoff_raw),
        "human_return_csv_sha256_unsigned": digest(human_raw),
        "private_report_sha256_unsigned": digest(report),
        "private_counts_sha256_unsigned": digest(json_bytes(counts)),
        "received_human_priority_rows": count,
        **UNTRUSTED_FLAGS,
    }
    publish_new(output_dir, {
        REPORT: report, COUNTS: json_bytes(counts),
        RECEIPT_OUT: json_bytes(receipt),
    })
    return count


def main() -> int:
    p = argparse.ArgumentParser(
        description="Offline original-source + PRIVATE human priority reply reconciliation, NOT authority")
    for key in ("source", "manifest", "worksheet", "selection-receipt", "selection",
                "curated-packet", "private-handoff", "returned-csv", "output-dir"):
        p.add_argument("--" + key, required=True)
    args = p.parse_args()
    try:
        count = reconcile(args.source, args.manifest, args.worksheet,
                          args.selection_receipt, args.selection,
                          args.curated_packet, args.private_handoff,
                          args.returned_csv, args.output_dir)
    except (Hold, OSError, ValueError, TypeError, KeyError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: original source or HUMAN handoff drift; no output authorized",
              file=sys.stderr)
        return 3
    print("PRIVATE ORIGINAL-source HUMAN reply reconciled: " + str(count) +
          " rows, REVIEW ONLY. Source identity UNSIGNED; no authenticated "
          "recipient, verified remediation, consent, action or deployment.")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
