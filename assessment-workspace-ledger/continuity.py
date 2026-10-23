#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN stage continuity across original kit snapshots.

A previous human note is NEVER confirmation of a newly changed source, security
assessment, approval, producer identity, or consent. No scans, network or grants.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
from pathlib import Path
import shutil
import sys

from ledger import (
    CSV_HEADERS, FLAGS, Hold, MAX_CSV, MAX_KITS, MAX_MANIFEST, STAGES,
    canonical, digest, hexhash, html_page, manifest_from_source, new_private,
    object_unique, read_owner_file, reject, safe_human, verify_snapshot,
    write_private,
)
from browser_studio import render_studio


def original_human(raw, old, ledger_digest):
    """Verify the former native finalized HUMAN-only artifact, not its author."""
    if len(raw) > MAX_MANIFEST or not raw:
        reject("PRIVATE HOLD: former HUMAN handoff size")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite HUMAN JSON"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Hold("PRIVATE HOLD: unreadable former HUMAN handoff") from exc
    if not isinstance(obj, dict) or set(obj) != {
        "schema", "authority", "ledger_sha256", "plan_sha256", "rows"
    }:
        reject("PRIVATE HOLD: unknown HUMAN packet schema")
    if obj["schema"] != "lightup.private.workspace-ledger-human.v1":
        reject("PRIVATE HOLD: former HUMAN schema mismatch")
    if obj["authority"] != FLAGS or obj["ledger_sha256"] != ledger_digest or not hexhash(obj["plan_sha256"]):
        reject("PRIVATE HOLD: HUMAN source binding/authority invalid")
    rows = obj["rows"]
    if not isinstance(rows, list) or len(rows) != len(old["kits"]) or len(rows) > MAX_KITS:
        reject("PRIVATE HOLD: former HUMAN row count mismatch")
    for expected, row in zip(old["kits"], rows):
        if not isinstance(row, dict) or set(row) != {"ordinal", "stage", "owner", "question", "kit_digest"}:
            reject("PRIVATE HOLD: former HUMAN row keys")
        if type(row["ordinal"]) is not int or row["ordinal"] != expected["ordinal"] or row["kit_digest"] != expected["digest"]:
            reject("PRIVATE HOLD: former HUMAN row identity mismatch")
        if row["stage"] not in STAGES or type(row["stage"]) is not str:
            reject("PRIVATE HOLD: former HUMAN stage invalid")
        safe_human(row["owner"], 80)
        safe_human(row["question"], 500)
    return rows


def carry(old_raw, old_human_raw, current_raw):
    previous = manifest_from_source(old_raw)
    current = manifest_from_source(current_raw)
    if not current["previous_sha256"] or current["previous_sha256"] != digest(old_raw):
        reject("PRIVATE HOLD: current inventory does not reference EXACT previous snapshot")
    if len(previous["kits"]) != len(current["kits"]):
        reject("PRIVATE HOLD: original source kit slot count changed")
    original_rows = original_human(old_human_raw, previous, digest(old_raw))
    verify_snapshot(current)  # native exact-byte re-admission of ALL current source kits
    proposals = []
    carried = 0
    for old_kit, new_kit, older in zip(previous["kits"], current["kits"], original_rows):
        if old_kit["ordinal"] != new_kit["ordinal"] or old_kit["path"] != new_kit["path"]:
            reject("PRIVATE HOLD: original kit ordinal/path identity changed")
        unchanged = (
            old_kit["digest"] == new_kit["digest"]
            and old_kit["files"] == new_kit["files"]
            and old_kit["label"] == new_kit["label"]
        )
        if unchanged:
            stage, owner, question = older["stage"], older["owner"], older["question"]
            carried += 1
        else:
            # A changed source is always a NEW HUMAN decision, no inherited owner or answers.
            stage, owner, question = "needs_review", "", ""
        proposals.append({
            "ordinal": new_kit["ordinal"],
            "kit_digest": new_kit["digest"],
            "stage": stage,
            "owner": owner,
            "question": question,
            "carried": unchanged,
        })
    handoff = {
        "schema": "lightup.private.workspace-ledger-carry.v1",
        "authority": FLAGS,
        "current_ledger_sha256": digest(current_raw),
        "previous_ledger_sha256": digest(old_raw),
        "previous_human_sha256": digest(old_human_raw),
        "requires_human_reconfirmation": True,
        "rows": proposals,
    }
    return handoff, carried


def run(args):
    old_raw = read_owner_file(args.previous, MAX_MANIFEST)
    old_human_raw = read_owner_file(args.human, MAX_MANIFEST)
    current_raw = read_owner_file(args.current, MAX_MANIFEST)
    if args.previous == args.current or digest(old_raw) == digest(current_raw):
        reject("PRIVATE HOLD: must use a new, separate captured snapshot")
    handoff, carried = carry(old_raw, old_human_raw, current_raw)
    current = manifest_from_source(current_raw)
    table = ["<p>Current exact PRIVATE ledger SHA-256: <code>" + digest(current_raw) +
             "</code>. Previous HUMAN decisions are copied only for literally identical "
             "source-file inventories in the original ordinal and path. "
             "All carried decisions remain HUMAN proposals requiring manual reconfirmation.</p>",
             "<table><thead><tr><th>Kit ordinal</th><th>Human label</th><th>Original files</th>"
             "<th>Human continuation</th><th>Proposed stage</th></tr></thead><tbody>"]
    csv_output = io.StringIO(newline="")
    writer = csv.writer(csv_output, lineterminator="\n")
    writer.writerow(CSV_HEADERS)
    for kit, row in zip(current["kits"], handoff["rows"]):
        table.append("<tr><td>" + str(row["ordinal"]) + "</td><td>" +
                     html.escape(kit["label"]) + "</td><td>" +
                     str(len(kit["files"])) + "</td><td>" +
                     ("Eligible for HUMAN reconfirmation" if row["carried"] else
                      "CHANGED: prior HUMAN decisions discarded") + "</td><td>" +
                     html.escape(row["stage"]) + "</td></tr>")
        writer.writerow((row["ordinal"], digest(current_raw), row["kit_digest"], row["stage"], row["owner"], row["question"]))
    table.append("</tbody></table><p>Next: open REVIEW-IN-BROWSER.html, load the ORIGINAL current "
                 "ledger.json separately, optionally import HUMAN-carry.json to prefill. "
                 "Review every HUMAN decision and save a NEW HUMAN-review.csv. "
                 "Native ledger.py finalize must re-admit exact source bytes again. "
                 "This session does not finalize, authenticate, grant or approve anything.</p>")
    output = new_private(args.private_parent)
    try:
        write_private(output, "HUMAN-carry.json", canonical(handoff))
        write_private(output, "HUMAN-review.csv", csv_output.getvalue())
        write_private(output, "REVIEW-IN-BROWSER.html", render_studio())
        write_private(output, "OPEN-PRIVATE.html", html_page("LightUp PRIVATE HUMAN continuity", "".join(table)))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: source change requires fresh HUMAN review" if carried != len(current["kits"])
          else "PRIVATE REVIEW_ONLY: unchanged source; HUMAN decisions still require reconfirmation")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3 if carried != len(current["kits"]) else 2


def main():
    p = argparse.ArgumentParser(
        description="Carry HUMAN proposals only across exact unchanged PRIVATE source-kit snapshots"
    )
    p.add_argument("--previous", required=True, help="Exact previous original PRIVATE ledger.json")
    p.add_argument("--human", required=True, help="Native former HUMAN-only.json from ledger.py finalize")
    p.add_argument("--current", required=True, help="NEW original ledger.json captured with --previous")
    p.add_argument("--private-parent", required=True, help="Existing owner-only 0700 PRIVATE parent")
    a = p.parse_args()
    try:
        return run(a)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: original HUMAN/source continuity rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
