#!/usr/bin/env python3
"""PRIVATE source-exact HUMAN decision revision log without external authorization.

Reads two existing native HUMAN-only.json packets against ONE unchanged
original PRIVATE ledger and the currently present exact original kit bytes.
Publishes independent PRIVATE historical human change dossier. No grant/scan.
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
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, manifest_from_source,
    new_private, read_owner_file, reject, verify_snapshot, write_private
)
from continuity import original_human


def compare_human(old_rows, new_rows):
    changes = []
    for before, after in zip(old_rows, new_rows):
        if before["ordinal"] != after["ordinal"] or before["kit_digest"] != after["kit_digest"]:
            reject("PRIVATE HOLD: original HUMAN source identity changed")
        fields = tuple(key for key in ("stage", "owner", "question") if before[key] != after[key])
        if fields:
            changes.append({
                "ordinal": before["ordinal"],
                "kit_digest": before["kit_digest"],
                "changed_human_fields": list(fields),
                "before": {name: before[name] for name in ("stage", "owner", "question")},
                "after": {name: after[name] for name in ("stage", "owner", "question")},
            })
    return changes


def render(changes, total, old_hash, new_hash, ledger_hash):
    content = [
        "<p><strong>HUMAN proposals only.</strong> Both source-byte-bound native HUMAN packets "
        "refer to the exact same original kit ledger. Current original kit files were re-admitted "
        "when this PRIVATE dossier was prepared. That does not prove producer identity, original "
        "approval, consent, real client authorization, verified assessment, mitigation or security.</p>",
        "<p>Original ledger SHA-256: <code>" + ledger_hash + "</code><br>"
        "Old HUMAN packet (unsigned): <code>" + old_hash + "</code><br>"
        "Next HUMAN packet (unsigned): <code>" + new_hash + "</code></p>",
        "<p>Human-reviewed kit slots with changed proposals: " + str(len(changes)) +
        " of " + str(total) + ". No changes never means PASS.</p>",
        "<table><thead><tr><th>Kit</th><th>Changed HUMAN fields</th>"
        "<th>Previous HUMAN stage</th><th>Next HUMAN stage</th></tr></thead><tbody>",
    ]
    for item in changes:
        content.append("<tr><td>" + str(item["ordinal"]) + "</td><td>" +
                       html.escape(", ".join(item["changed_human_fields"])) + "</td><td>" +
                       html.escape(item["before"]["stage"]) + "</td><td>" +
                       html.escape(item["after"]["stage"]) + "</td></tr>")
    content.append("</tbody></table><p>PRIVATE exact HUMAN owner and question changes appear "
                   "in PRIVATE-human-revision.json only. Old packets are preserved untouched. "
                   "An improved HUMAN status is NOT an automated finding clearance.</p>")
    return html_page("LightUp PRIVATE HUMAN revision history", "".join(content))


def run(args):
    if args.before == args.after or args.before == args.ledger or args.after == args.ledger:
        reject("PRIVATE HOLD: distinct source and HUMAN paths required")
    ledger_data = read_owner_file(args.ledger, MAX_MANIFEST)
    ledger_obj = manifest_from_source(ledger_data)
    verify_snapshot(ledger_obj)
    old_raw = read_owner_file(args.before, MAX_MANIFEST)
    new_raw = read_owner_file(args.after, MAX_MANIFEST)
    if digest(old_raw) == digest(new_raw):
        reject("PRIVATE HOLD: identical HUMAN packets have no distinct historical revision")
    source_hash = digest(ledger_data)
    old_rows = original_human(old_raw, ledger_obj, source_hash)
    new_rows = original_human(new_raw, ledger_obj, source_hash)
    changes = compare_human(old_rows, new_rows)
    old_hash, new_hash = digest(old_raw), digest(new_raw)
    report = {
        "schema": "lightup.private.workspace-ledger-human-revision.v1",
        "authority": FLAGS,
        "source_ledger_sha256": source_hash,
        "before_human_sha256": old_hash,
        "after_human_sha256": new_hash,
        "original_source_reopened": True,
        "human_decisions_are_not_authority": True,
        "changes": changes,
    }
    csv_source = io.StringIO(newline="")
    csv_writer = csv.writer(csv_source, lineterminator="\n")
    csv_writer.writerow(("ordinal", "stage_changed", "owner_changed", "question_changed",
                         "human_followup", "proposed_owner", "next_question"))
    for item in changes:
        names = item["changed_human_fields"]
        csv_writer.writerow((item["ordinal"], int("stage" in names), int("owner" in names),
                             int("question" in names), "needs_review", "", ""))
    path = new_private(args.private_parent)
    try:
        write_private(path, "PRIVATE-human-revision.json", canonical(report))
        write_private(path, "PRIVATE-HUMAN-change-followup.csv", csv_source.getvalue())
        write_private(path, "OPEN-PRIVATE.html", render(
            changes, len(ledger_obj["kits"]), old_hash, new_hash, source_hash
        ))
    except BaseException:
        shutil.rmtree(path)
        raise
    print("PRIVATE HOLD: historical HUMAN changes require HUMAN review" if changes
          else "PRIVATE REVIEW_ONLY: HUMAN proposals unchanged; never authorization")
    print(str(Path(path) / "OPEN-PRIVATE.html"))
    return 3 if changes else 2


def main():
    p = argparse.ArgumentParser(description="Offline original-source-exact PRIVATE HUMAN revision history")
    p.add_argument("--ledger", required=True, help="Unchanged original PRIVATE ledger.json")
    p.add_argument("--before", required=True, help="Previous original native HUMAN-only.json")
    p.add_argument("--after", required=True, help="Later original native HUMAN-only.json")
    p.add_argument("--private-parent", required=True, help="Owner-only 0700 PRIVATE output parent")
    args = p.parse_args()
    try:
        return run(args)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: cannot admit original human revision records", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
