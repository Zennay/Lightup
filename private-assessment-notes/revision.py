#!/usr/bin/env python3
"""Create a NEW PRIVATE HUMAN notes revision from an unchanged source-bound packet."""
from __future__ import annotations
import argparse
from hashlib import sha256
import os
from pathlib import Path
import shutil
import sys
import tempfile

from browser_studio import render as render_browser_studio
from notes import (ALLOWED, FALSE_FLAGS, Hold, SCHEMA, csv_document, file_new,
                   landing, load_decisions, load_workroom, private_directory,
                   private_input, save_json, summary)

def reopen(previous: str, private_parent: str) -> int:
    prior = private_directory(previous)
    parent = private_directory(private_parent)
    bindings, sources, rows = load_workroom(prior)
    if bindings.get("human_proposals_recorded") is not True:
        raise Hold("HOLD: only a previously completed HUMAN PRIVATE packet may be reopened")
    old_version = bindings.get("revision_level", 0)
    if type(old_version) is not int or not 0 <= old_version < 32:
        raise Hold("HOLD: original HUMAN revision depth is invalid")
    raw_manifest = private_input(str(prior / "PRIVATE-source-bindings.json"), 128 * 1024)
    raw_decisions = private_input(str(prior / "PRIVATE-HUMAN-decisions.csv"), 64 * 1024)
    original_sha = bindings.get("human_decisions_sha256_unsigned")
    if (type(original_sha) is not str or len(original_sha) != 64
            or sha256(raw_decisions).hexdigest() != original_sha):
        raise Hold("HOLD: prior PRIVATE original HUMAN decision bytes changed")
    decisions = load_decisions(raw_decisions, sources)
    expected_counts = {
        name: sum(row["human_stage"] == name for row in decisions) for name in ALLOWED
    }
    if bindings.get("human_stages") != expected_counts:
        raise Hold("HOLD: prior source-bound HUMAN stage counts disagree")

    dest = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-reopened-", dir=parent))
    os.chmod(dest, 0o700)
    completed = False
    try:
        notes = dest / "notes"
        notes.mkdir(mode=0o700)
        for row in rows:
            file_new(notes / f"PRIVATE-redacted-{row['ordinal']:03d}.txt",
                     row["redacted_text"].encode("utf-8"))
        # A reopened review is once again in the non-final HUMAN proposal state.
        reopened = {key: bindings[key] for key in (
            "schema", "claimed_status", "reviewed",
            "pattern_redaction_not_anonymization", "sources", *FALSE_FLAGS
        )}
        if reopened["schema"] != SCHEMA or reopened["claimed_status"] != "HOLD":
            raise Hold("HOLD: cannot turn original proposal into permission")
        reopened["revision_level"] = old_version + 1
        reopened["prior_packet_manifest_sha256_unsigned"] = sha256(raw_manifest).hexdigest()
        reopened["prior_human_decisions_sha256_unsigned"] = sha256(raw_decisions).hexdigest()
        reopened["human_proposals_recorded"] = False
        save_json(dest / "PRIVATE-source-bindings.json", reopened)
        rows_with_prior = [{**row, **decision} for row, decision in zip(rows, decisions)]
        file_new(dest / "PRIVATE-HUMAN-decisions.csv", csv_document(rows_with_prior))
        file_new(dest / "PRIVATE-HUMAN-editor.html",
                 render_browser_studio(rows, decisions))
        file_new(dest / "PRIVATE-HUMAN-summary.html", summary(rows, decisions))
        file_new(dest / "OPEN-PRIVATE.html", landing(len(rows), False))
        completed = True
        print("REVIEW_ONLY: prior PRIVATE masked bytes preserved in NEW HUMAN revision.")
        print("OPEN LOCALLY: " + str(dest / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not completed:
            shutil.rmtree(dest)


def main() -> int:
    cli = argparse.ArgumentParser(description="Reopen unchanged PRIVATE original HUMAN notes as a new offline revision; no release")
    cli.add_argument("--prior-packet", required=True, help="original completed HUMAN PRIVATE packet")
    cli.add_argument("--private-parent", required=True, help="existing owner-controlled 0700 directory")
    args = cli.parse_args()
    try:
        return reopen(args.prior_packet, args.private_parent)
    except (Hold, OSError, ValueError, KeyError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: original PRIVATE revision refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
