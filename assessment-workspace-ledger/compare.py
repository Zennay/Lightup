#!/usr/bin/env python3
"""Offline PRIVATE metadata-only comparison of two stored LightUp kit ledgers.

No source-kit read is attempted by this historical view. No change is interpreted
as verification of a fix. Use ledger.py reopen for current exact-byte admission.
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
    Hold, MAX_MANIFEST, FLAGS, canonical, digest, html_page,
    manifest_from_source, new_private, read_owner_file, reject, write_private,
)


def compare(before, after):
    if len(before["kits"]) != len(after["kits"]):
        reject("PRIVATE HOLD: different number of source slots")
    results = []
    changed = False
    for old, new in zip(before["kits"], after["kits"]):
        if old["ordinal"] != new["ordinal"] or old["path"] != new["path"]:
            reject("PRIVATE HOLD: incomparable source kit identity/order")
        previous = {r["path"]: (r["sha256"], r["size"]) for r in old["files"]}
        current = {r["path"]: (r["sha256"], r["size"]) for r in new["files"]}
        shared = previous.keys() & current.keys()
        row = {
            "ordinal": old["ordinal"],
            "label": new["label"],
            "baseline_kit_sha256": old["digest"],
            "new_kit_sha256": new["digest"],
            "added_file_count": len(current.keys() - previous.keys()),
            "removed_file_count": len(previous.keys() - current.keys()),
            "changed_file_count": sum(previous[key] != current[key] for key in shared),
            "unchanged_file_count": sum(previous[key] == current[key] for key in shared),
            "human_attention": False,
            "authority": FLAGS.copy(),
        }
        row["human_attention"] = bool(
            row["added_file_count"] or row["removed_file_count"] or row["changed_file_count"]
        )
        changed |= row["human_attention"]
        results.append(row)
    return results, changed


def render(results, old_sha, new_sha):
    rows = [
        "<p>Two originally stored PRIVATE unsigned ledger snapshots. "
        "<strong>This operation does not reopen, inspect or establish continued existence of the source files.</strong> "
        "Open the original PRIVATE archives yourself and run native ledger.py reopen separately "
        "before relying even on unchanged-byte inventory statements.</p>",
        "<p>Previous source-ledger SHA-256: <code>" + old_sha + "</code><br>"
        "Later source-ledger SHA-256: <code>" + new_sha + "</code></p>",
        "<table><thead><tr><th>Ordinal</th><th>Human label</th>"
        "<th>Added</th><th>Removed</th><th>Changed</th><th>Unchanged</th>"
        "<th>Human follow-up</th></tr></thead><tbody>",
    ]
    for record in results:
        rows.append(
            "<tr><td>" + str(record["ordinal"]) + "</td><td>" +
            html.escape(record["label"]) + "</td><td>" +
            str(record["added_file_count"]) + "</td><td>" +
            str(record["removed_file_count"]) + "</td><td>" +
            str(record["changed_file_count"]) + "</td><td>" +
            str(record["unchanged_file_count"]) + "</td><td>" +
            ("HOLD: review source differences" if record["human_attention"] else
             "Source-declared inventory unchanged; not externally verified") + "</td></tr>"
        )
    rows.append("</tbody></table><p>Removed source files do not mean a vulnerability is fixed. "
                "Zero differences is never PASS, consent, security review, provenance attestation "
                "or evidence of remediation. Treat all counts and hashes as PRIVATE.</p>")
    return html_page("LightUp PRIVATE historical kit ledger comparison", "".join(rows))


def run(args):
    old_raw = read_owner_file(args.before, MAX_MANIFEST)
    new_raw = read_owner_file(args.after, MAX_MANIFEST)
    if args.before == args.after or digest(old_raw) == digest(new_raw):
        reject("PRIVATE HOLD: use two independently captured source snapshots")
    before = manifest_from_source(old_raw)
    after = manifest_from_source(new_raw)
    result, changed = compare(before, after)
    digest_before, digest_after = digest(old_raw), digest(new_raw)
    artifact = {
        "schema": "lightup.private.workspace-ledger-comparison.v1",
        "authority": FLAGS,
        "before_ledger_sha256": digest_before,
        "after_ledger_sha256": digest_after,
        "sources_reopened": False,
        "historical_byte_comparison_only": True,
        "results": result,
    }
    csv_output = io.StringIO(newline="")
    writer = csv.writer(csv_output, lineterminator="\n")
    writer.writerow(["ordinal", "added", "removed", "changed", "unchanged",
                     "human_stage", "proposed_owner", "next_question"])
    for row in result:
        writer.writerow([
            row["ordinal"], row["added_file_count"], row["removed_file_count"],
            row["changed_file_count"], row["unchanged_file_count"], "needs_review", "", ""
        ])
    output = new_private(args.private_parent)
    try:
        write_private(output, "PRIVATE-historical-comparison.json", canonical(artifact))
        write_private(output, "PRIVATE-HUMAN-comparison-template.csv", csv_output.getvalue())
        write_private(output, "OPEN-PRIVATE.html", render(result, digest_before, digest_after))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: historical differences require HUMAN review" if changed
          else "PRIVATE REVIEW_ONLY: historical ledgers contain the same per-file bytes; not proof of fixes")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3 if changed else 2


def main():
    parser = argparse.ArgumentParser(
        description="Compare two PRIVATE offline stored kit ledgers; no source files read or verified"
    )
    parser.add_argument("--before", required=True, help="First original owner-only ledger.json")
    parser.add_argument("--after", required=True, help="Second original owner-only ledger.json")
    parser.add_argument("--private-parent", required=True, help="Existing owner-only 0700 output parent")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: historical ledgers rejected without external action", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
