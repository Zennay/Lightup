#!/usr/bin/env python3
"""PRIVATE multi-snapshot source-byte inventory history for human follow-up only.

Historical unsigned ledgers are read in explicit operator order. No original kit
content is opened, no source/consent authority is inferred, and no network runs.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import os
import sys
import shutil
from pathlib import Path

from compare import compare, detailed_changes
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page,
    manifest_from_source, new_private, read_owner_file, reject, write_private,
)

MAX_SNAPSHOTS = 12


def load_history(paths):
    if not 2 <= len(paths) <= MAX_SNAPSHOTS or len(set(paths)) != len(paths):
        reject("PRIVATE HOLD: choose 2-12 distinct, ordered original ledgers")
    sources = []
    seen_hashes = set()
    for position, path in enumerate(paths):
        raw = read_owner_file(path, MAX_MANIFEST)
        fingerprint = digest(raw)
        if fingerprint in seen_hashes:
            reject("PRIVATE HOLD: duplicate original snapshot bytes")
        seen_hashes.add(fingerprint)
        source = manifest_from_source(raw)
        if position and source["previous_sha256"] != sources[-1]["sha256"]:
            reject("PRIVATE HOLD: non-contiguous original capture --previous ledger chain")
        sources.append({"sha256": fingerprint, "doc": source})
    original = [(kit["ordinal"], kit["path"]) for kit in sources[0]["doc"]["kits"]]
    for source in sources[1:]:
        if [(kit["ordinal"], kit["path"]) for kit in source["doc"]["kits"]] != original:
            reject("PRIVATE HOLD: original source kits changed positions or identity")
    return sources


def summarize(sources):
    transitions = []
    hotspots = {}
    attention = False
    for index in range(1, len(sources)):
        earlier = sources[index - 1]
        later = sources[index]
        results, changed = compare(earlier["doc"], later["doc"])
        changes = detailed_changes(earlier["doc"], later["doc"])
        for item in changes:
            key = (item["kit_ordinal"], item["relative_path"])
            count = hotspots.setdefault(key, {"kit_ordinal": item["kit_ordinal"],
                                               "relative_path": item["relative_path"],
                                               "added": 0, "removed": 0, "changed": 0,
                                               "first_transition": index,
                                               "last_transition": index})
            count[item["kind"]] += 1
            count["last_transition"] = index
        transitions.append({
            "transition": index,
            "from_sha256": earlier["sha256"],
            "to_sha256": later["sha256"],
            "human_attention": changed,
            "kits": [
                {key: row[key] for key in (
                    "ordinal", "label", "previous_label", "label_changed",
                    "added_file_count", "removed_file_count", "changed_file_count",
                    "unchanged_file_count", "human_attention"
                )} for row in results
            ],
        })
        attention |= changed
    frequent = sorted(hotspots.values(),
                      key=lambda row: (-sum(row[k] for k in ("added", "removed", "changed")),
                                       row["kit_ordinal"], row["relative_path"]))
    return transitions, frequent, attention


def render(sources, transitions, hotspots):
    body = [
        "<p>HUMAN selected order, NOT independently dated or signed. "
        "Each adjacent historical ledger contains the exact unsigned SHA-256 of "
        "the preceding supplied ledger bytes. This proves only internal "
        "consistency of local records, NOT origin, timing, live kit state or a fixed finding.</p>",
        "<p><strong>" + str(len(sources)) + " stored snapshots · " +
        str(len(transitions)) + " consecutive local comparisons · " +
        str(len(hotspots)) + " source-relative file paths with historical churn.</strong></p>",
        "<table><thead><tr><th>Step</th><th>Original kit</th><th>Human dossier</th>"
        "<th>Added</th><th>Removed</th><th>Changed</th><th>Unchanged</th>"
        "<th>Human review</th></tr></thead><tbody>",
    ]
    for transition in transitions:
        for row in transition["kits"]:
            body.append(
                "<tr><td>" + str(transition["transition"]) + "</td><td>" +
                str(row["ordinal"]) + "</td><td>" + html.escape(row["label"]) +
                (" <strong>(RELABELED)</strong>" if row["label_changed"] else "") +
                "</td><td>" + str(row["added_file_count"]) + "</td><td>" +
                str(row["removed_file_count"]) + "</td><td>" +
                str(row["changed_file_count"]) + "</td><td>" +
                str(row["unchanged_file_count"]) + "</td><td>" +
                ("HOLD: HUMAN attention" if row["human_attention"] else
                 "REVIEW_ONLY: historical files unchanged") + "</td></tr>"
            )
    body.append("</tbody></table><p><a href='REVIEW-HISTORY-IN-BROWSER.html'>"
                "Open local PRIVATE HUMAN historical editor</a> to review all "
                "original source-bound transitions, resume saved HUMAN drafts "
                "and export native-finalizable CSV. HUMAN proposals are NOT "
                "verified findings, repairs or consent.</p>"
                "<p><a href='PRIVATE-hotspots.html'>"
                "Open PRIVATE per-file churn review</a> for source-relative "
                "filenames and repeat changes. This separate HTML is sensitive.</p>"
                "<p>Original relative filenames and any hashes are "
                "omitted from this overview; they are PRIVATE in "
                "PRIVATE-relative-file-hotspots.json. Never publish that file or "
                "treat file churn as a remediation verdict.</p>"
                "<p>Original source kits were NOT reopened. Reopen the latest original "
                "ledger using ledger.py reopen on a trusted owner-private machine "
                "before making a new HUMAN decision. Each unsigned link is forgeable "
                "by anyone who can alter all records. Original source changes, "
                "consent, approval and verification remain UNKNOWN.</p>")
    return html_page("LightUp PRIVATE chained historical inventory", "".join(body))


def render_hotspots(hotspots):
    body = [
        "<p><strong>PRIVATE ORIGINAL SOURCE-RELATIVE FILENAMES.</strong> "
        "These are historical file-list differences, not validated security "
        "findings or remediations. HUMAN selected order is NOT signed chronology. "
        "Source kits were not reopened and no current existence is implied.</p>",
        "<p>" + str(len(hotspots)) + " historical path changes; showing " +
        str(min(len(hotspots), 500)) + " by highest repeated churn. "
        "The separately private JSON contains all bounded original paths.</p>",
        "<table><thead><tr><th>Kit</th><th>Original relative path</th>"
        "<th>Added</th><th>Removed</th><th>Changed bytes</th>"
        "<th>First step</th><th>Last step</th></tr></thead><tbody>",
    ]
    for row in hotspots[:500]:
        body.append(
            "<tr><td>" + str(row["kit_ordinal"]) + "</td><td><code>" +
            html.escape(row["relative_path"]) + "</code></td><td>" +
            str(row["added"]) + "</td><td>" + str(row["removed"]) +
            "</td><td>" + str(row["changed"]) + "</td><td>" +
            str(row["first_transition"]) + "</td><td>" +
            str(row["last_transition"]) + "</td></tr>"
        )
    body.append("</tbody></table><p>Missing sources or lower churn never "
                "establish a fix, consent, trusted producer, PASS or permission. "
                "<a href='OPEN-PRIVATE.html'>Back to PRIVATE source-minimal overview</a>.</p>")
    return html_page("LightUp PRIVATE repeated original-file changes", "".join(body))


def run(args):
    sources = load_history(args.ledger)
    transitions, hotspots, changed = summarize(sources)
    parent = os.path.normpath(args.private_parent)
    if parent != args.private_parent or not os.path.isabs(parent):
        reject("PRIVATE HOLD: private output parent must be absolute and canonical")
    for kit in sources[0]["doc"]["kits"]:
        if os.path.commonpath((kit["path"], parent)) == kit["path"]:
            reject("PRIVATE HOLD: private history output cannot be inside original source kit")
    overview = {
        "schema": "lightup.private.workspace-ledger-history.v1",
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "human_selected_order_not_proven_chronology": True,
        "chain_unsigned": True,
        "snapshots": [{"slot": i + 1, "ledger_sha256": item["sha256"]}
                      for i, item in enumerate(sources)],
        "transitions": transitions,
        "source_relative_hotspot_count": len(hotspots),
    }
    hot = {
        "schema": "lightup.private.workspace-ledger-history-hotspots.v1",
        "authority": FLAGS,
        "sources_reopened": False,
        "items": hotspots,
    }
    # Native exporter/finalizer share EXACT immutable source-bound CSV fields.
    from history_human import encode_csv, expected_rows
    from history_studio import render as render_history_studio
    review_csv = encode_csv(expected_rows(sources, transitions))
    private = new_private(args.private_parent)
    try:
        write_private(private, "PRIVATE-history.json", canonical(overview))
        write_private(private, "PRIVATE-relative-file-hotspots.json", canonical(hot))
        write_private(private, "PRIVATE-HUMAN-history-template.csv", review_csv)
        write_private(private, "OPEN-PRIVATE.html", render(sources, transitions, hotspots))
        write_private(private, "PRIVATE-hotspots.html", render_hotspots(hotspots))
        write_private(private, "REVIEW-HISTORY-IN-BROWSER.html",
                      render_history_studio(sources, transitions))
    except BaseException:
        shutil.rmtree(private)
        raise
    print("PRIVATE HOLD: source-history drift requires fresh HUMAN review" if changed else
          "PRIVATE REVIEW_ONLY: historical unsigned byte inventories unchanged (NOT verified)")
    print(str(Path(private) / "OPEN-PRIVATE.html"))
    return 3 if changed else 2


def main():
    parser = argparse.ArgumentParser(description=(
        "Reconcile 2-12 originally capture --previous linked PRIVATE ledgers; "
        "historical human-only metadata, no original file reads or authority"
    ))
    parser.add_argument("--ledger", action="append", required=True,
                        help="Original 0600 ledger.json in explicit human-selected order (repeat 2-12x)")
    parser.add_argument("--private-parent", required=True,
                        help="Existing owner-only 0700 destination OUTSIDE code checkout")
    args = parser.parse_args()
    try:
        return run(args)
    except (Hold, OSError, ValueError, UnicodeError, TypeError):
        print("PRIVATE HOLD: historical source chain rejected without external action", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
