#!/usr/bin/env python3
"""PRIVATE 2–12 stage HUMAN selection history; source-origin findings UNVERIFIED.

Never infers remediation, source truth, actual grant, runtime or permission.
Produces a scriptless source-minimized HUMAN timeline and counts-only handoff.
"""
from __future__ import annotations

import argparse
import sys
from curate import UNVERIFIED, digest, PRIORITIES
from briefing import Hold, SEVERITIES, h, json_bytes, publish_new
from revision import admit_revision_inputs, change_records, private_frame

MIN_VERSIONS = 2
MAX_VERSIONS = 12


def snapshot_data(source: dict, selected: list[dict], version_number: int) -> dict:
    return {
        "human_version_ordinal": version_number,
        "human_selected_count": len(selected),
        "human_priority_counts": {
            p: sum(x["priority"] == p for x in selected) for p in PRIORITIES
        },
        "source_reported_severity_counts": {
            severity: sum(source["findings"][x["ordinal"]-1]["severity"] == severity
                          for x in selected) for severity in SEVERITIES
        },
    }


def history(source_path: str, manifest_path: str, worksheet_path: str,
            receipt_path: str, selection_paths: list[str],
            destination: str) -> None:
    if not MIN_VERSIONS <= len(selection_paths) <= MAX_VERSIONS:
        raise Hold("HOLD: Two through twelve original HUMAN selection versions required")
    source, original_sha, worksheet_sha, versions = admit_revision_inputs(
        source_path, manifest_path, worksheet_path, receipt_path, selection_paths)

    snapshots = []
    transitions = []
    changed_html = []
    recurring = {}
    for index, (version_sha, selection) in enumerate(versions):
        n = index + 1
        snapshots.append(snapshot_data(source, selection, n))
        for entry in selection:
            recurring[entry["ordinal"]] = recurring.get(entry["ordinal"], 0) + 1
        if index == 0:
            continue
        prior_sha, prior_selection = versions[index-1]
        changes = change_records(prior_selection, selection, source)
        count_by_kind = {
            kind: sum(x["kind"] == kind for x in changes)
            for kind in ("HUMAN_ADDED", "HUMAN_REMOVED",
                         "HUMAN_PRIORITY_CHANGED", "HUMAN_QUESTION_CHANGED",
                         "HUMAN_PRIORITY_AND_QUESTION_CHANGED")
        }
        transitions.append({
            "human_from_version": index,
            "human_to_version": n,
            "human_changed_ordinal_count": len(changes),
            "human_change_category_counts": count_by_kind,
        })
        card_parts = []
        for change in changes:
            ordinal = change["ordinal"]
            prior = change["before"]
            current = change["after"]
            def state(entry: dict | None) -> str:
                return ("Not HUMAN selected" if entry is None else
                        h(entry["priority"]) + ": <span>" + h(entry["question"]) + "</span>")
            card_parts.append(
                "<article><h3>Original ordinal #" + str(ordinal) +
                " · " + h(change["kind"]) + "</h3>"
                "<p>Source-reported severity (UNVERIFIED): " +
                h(change["reported_severity"]) + "</p>"
                "<p><strong>Prior HUMAN:</strong> " + state(prior) + "</p>"
                "<p><strong>Current HUMAN:</strong> " + state(current) + "</p>"
                "</article>"
            )
        changed_html.append(
            "<section class='card'><details><summary>HUMAN version " + str(index) +
            " → " + str(n) + " · " + str(len(changes)) +
            " changed original ordinals</summary>"
            "<p>HUMAN selection movement only, not finding changes.</p>" +
            ("".join(card_parts) if card_parts else
             "<p>Human selection unchanged.</p>") +
            "</details></section>"
        )
    distinct_selected = len(recurring)
    carried_all = sum(n == len(versions) for n in recurring.values())
    first_count = len(versions[0][1])
    last_count = len(versions[-1][1])
    churn = sum(t["human_changed_ordinal_count"] for t in transitions)

    # A matrix for each distinct HUMAN-selected original ordinal is a helpful
    # full product, but never transports original finding IDs/targets.
    matrix_rows = []
    for ordinal in sorted(recurring):
        r = source["findings"][ordinal-1]
        items = []
        for _, selection in versions:
            row = next((x for x in selection if x["ordinal"] == ordinal), None)
            label = ("not selected" if row is None else row["priority"])
            items.append("<td>" + h(label) + "</td>")
        matrix_rows.append("<tr><td>#" + str(ordinal) + "</td><td>" +
                           h(r["severity"]) + "</td><td>" +
                           str(recurring[ordinal]) + "</td>" +
                           "".join(items) + "</tr>")
    header = "<th>Ordinal</th><th>Source severity</th><th>Versions selected</th>" + "".join(
        "<th>HUMAN v" + str(i+1) + "</th>" for i in range(len(versions))
    )
    matrix = ("<section class='card'><h2>Source-minimized HUMAN selection matrix</h2>"
              "<div class='scroll-table'><table><thead><tr>" + header +
              "</tr></thead><tbody>" + "".join(matrix_rows) +
              "</tbody></table></div></section>")
    summary = (
        "<header><h1>LightUp · PRIVATE HUMAN selection version history</h1>"
        "<p class='notice'>REVIEW ONLY — original findings and provenance are "
        "NOT independently verified. HUMAN selection changes are NOT fixes, "
        "new vulnerabilities, an updated target, client/operator consent, "
        "revocation or authorization.</p>"
        "<p>This page has no original source URLs, finding IDs, evidence bodies, "
        "source hashes or original HUMAN worksheet owner/action fields. "
        "HUMAN freeform questions can still reveal confidential clients: "
        "this is source-minimized, not anonymously certified. PRIVATE only.</p>"
        "<p>Original source-reported findings: " + str(len(source["findings"])) +
        " · HUMAN snapshots: " + str(len(versions)) +
        " · first selected: " + str(first_count) +
        " · latest selected: " + str(last_count) +
        " · distinct selected across versions: " + str(distinct_selected) +
        " · changes across consecutive snapshots: " + str(churn) + "</p></header>"
    )
    report = private_frame("PRIVATE HUMAN curation version history",
                           summary + matrix + "".join(changed_html))
    counts = {
        "schema": "lightup.private_human_curation_history_counts.v1",
        "status": "REVIEW_ONLY",
        "original_source_reported_finding_count": len(source["findings"]),
        "human_version_count": len(versions),
        "human_snapshot_counts": snapshots,
        "human_consecutive_transition_counts": transitions,
        "human_distinct_selected_original_ordinals_count": distinct_selected,
        "human_selected_every_version_count": carried_all,
        "human_changed_ordinal_steps_total": churn,
        "source_identifiers_included": False,
        **UNVERIFIED,
    }
    private_receipt = {
        "schema": "lightup.private_human_curation_history_receipt.v1",
        "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": original_sha,
        "human_worksheet_sha256_unsigned": worksheet_sha,
        "ordered_human_selection_sha256_unsigned": [digest_value for digest_value, _ in versions],
        "human_selected_ordinal_series": [
            [row["ordinal"] for row in selected] for _, selected in versions
        ],
        "private_human_history_html_sha256_unsigned": digest(report),
        **UNVERIFIED,
    }
    publish_new(destination, {
        "PRIVATE-human-curation-history.html": report,
        "PRIVATE-human-curation-history-receipt.json": json_bytes(private_receipt),
        "human-curation-history-counts-PRIVATE.json": json_bytes(counts),
    })


def main() -> int:
    p = argparse.ArgumentParser(
        description="PRIVATE source-bound HUMAN curation history; 2–12 previously saved local CSVs")
    p.add_argument("--source", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--worksheet", required=True)
    p.add_argument("--selection-receipt", required=True)
    p.add_argument("--selection", action="append", required=True,
                   help="Repeat 2–12 times in desired earliest to latest HUMAN order")
    p.add_argument("--output-dir", required=True)
    args = p.parse_args()
    try:
        history(args.source, args.manifest, args.worksheet, args.selection_receipt,
                args.selection, args.output_dir)
    except Hold:
        print("HOLD: PRIVATE source/selection history rejected; no output published", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN selection history prepared — REVIEW ONLY, no original findings verdict")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
