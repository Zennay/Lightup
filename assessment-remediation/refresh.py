#!/usr/bin/env python3
"""Private offline renewal of manual lab-to-finding links across source revisions."""
from __future__ import annotations

import argparse
from hashlib import sha256
from html import escape
import os
from pathlib import Path
import re
import sys

from bridge import (
    FLAGS, LINK_SCHEMA, MAX_COMPARE, MAX_FINDINGS, MAX_LINKS,
    fail_if, links_document, original_comparison,
    original_findings, private_dir,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "assessment-archive"))
from archive import Hold, encode, publish, read_regular


def capture(compare_path, finding_path):
    original_cmp = read_regular(compare_path, MAX_COMPARE)
    original_csv = read_regular(finding_path, MAX_FINDINGS)
    return {
        "comparison": original_comparison(original_cmp),
        "findings": original_findings(original_csv),
        "comparison_sha": sha256(original_cmp).hexdigest(),
        "findings_sha": sha256(original_csv).hexdigest(),
        "comparison_raw": original_cmp,
        "findings_raw": original_csv,
    }


def changes(original, current):
    old, new = set(original), set(current)
    return {
        "added": sorted(new - old),
        "missing": sorted(old - new),
        "changed": sorted(i for i in old & new if original[i] != current[i]),
        "unchanged": sorted(i for i in old & new if original[i] == current[i]),
    }


def private_html(old, new, source_changes, preserved, dropped, copy_unchanged, posture):
    css = (
        "body{font:15px/1.55 system-ui,sans-serif;color:#1b2b45;background:#f6f8fb;"
        "max-width:1050px;margin:2rem auto;padding:0 1rem}main,header{background:white;"
        "border:1px solid #d3dfed;border-radius:.7rem;padding:1.3rem;margin-bottom:1rem}"
        "h1{font-size:2rem}h2{font-size:1.25rem}table{width:100%;border-collapse:collapse}"
        "td,th{border-bottom:1px solid #d3dfed;padding:.65rem;text-align:left;overflow-wrap:anywhere}"
        "code{overflow-wrap:anywhere}.warning{border-left:4px solid #b26427;padding-left:1rem}"
        "ul{line-height:1.7}@media print{main,header{break-inside:avoid}}"
    )
    import base64
    style_hash = base64.b64encode(sha256(css.encode()).digest()).decode()
    csp = "default-src 'none'; style-src 'sha256-" + style_hash + "'; form-action 'none'; connect-src 'none'; base-uri 'none'"
    totals = source_changes
    description = (
        "<p>Identical original row data can preserve a manual human link only when the "
        "operator explicitly chose to carry unchanged links. A changed or missing original "
        "scenario/finding always drops its links. An absent finding never means fixed. "
        "All source files remain unsigned and independently unauthenticated.</p>"
    )
    parts = [
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">',
        "<title>LightUp source revision human link renewal</title><style>" + css + "</style>",
        "<header><h1>Assessment ↔ finding source revision</h1><p class=warning><strong>PRIVATE / HUMAN REVIEW / " + posture + " · NEVER AUTHORIZED</strong><br>",
        "One source revision is not proof of completion, remediation, permission or same engagement.</p>",
        "<p>Old comparator SHA-256 <code>" + old["comparison_sha"] + "</code><br>",
        "New comparator SHA-256 <code>" + new["comparison_sha"] + "</code><br>",
        "Old findings SHA-256 <code>" + old["findings_sha"] + "</code><br>",
        "New findings SHA-256 <code>" + new["findings_sha"] + "</code></p>",
        "<p>Operator-selected carry for semantically unchanged original rows: <b>" +
        ("YES — local self-declaration; not authenticated" if copy_unchanged else
         "NO — all old manual links withheld pending renewed human review") +
        "</b></p></header><main>",
        description,
        "<h2>Original source change overview</h2><table><thead><tr><th>Source</th>",
        "<th>Added</th><th>Changed</th><th>Missing</th><th>Unchanged</th></tr></thead><tbody>"
    ]
    for category in ("scenarios", "findings"):
        rows = source_changes[category]
        parts.append("<tr><th>" + category + "</th>" + "".join(
            "<td>" + str(len(rows[k])) + "</td>"
            for k in ("added", "changed", "missing", "unchanged")) + "</tr>")
    parts.append("</tbody></table><h2>Human link continuation</h2><p>" +
                 str(len(preserved)) + " retained manual links; " + str(len(dropped)) +
                 " withheld for new human review.</p>")
    parts.append("<table><thead><tr><th>Original lab scenario</th><th>Original finding</th>"
                 "<th>Local disposition</th></tr></thead><tbody>")
    for link, reason in dropped:
        parts.append("<tr><td>" + escape(link["scenario_id"]) + "</td><td>" +
                     escape(link["finding_id"]) + "</td><td>" +
                     escape(reason) + " — no automatic carried stage</td></tr>")
    for link in preserved:
        parts.append("<tr><td>" + escape(link["scenario_id"]) + "</td><td>" +
                     escape(link["finding_id"]) + "</td><td>Human-only stage carried as <b>" +
                     escape(link["stage"]) + "</b>; source equality is not evidence</td></tr>")
    parts.append("</tbody></table><h2>Original source changes for human attention</h2>")
    for category in ("scenarios", "findings"):
        parts.append("<h3>" + category.title() + "</h3>")
        for key in ("added", "changed", "missing"):
            values = source_changes[category][key]
            parts.append("<details><summary>" + key.title() + " (" + str(len(values)) + ")</summary><ul>" +
                         "".join("<li><code>" + escape(v) + "</code></li>" for v in values) +
                         "</ul></details>")
    parts.append("<p>Any original HOLD/regression remains a HOLD. Both original and new client/engagement "
                 "origins require real independent operator verification before manual sharing. "
                 "This document does not carry approval or release state.</p></main></html>")
    return "".join(parts).encode("utf-8")


def renew(args):
    fail_if(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix),
            "invalid new output prefix")
    folder = private_dir(args.output_dir)
    older = capture(args.old_comparison, args.old_findings_csv)
    newer = capture(args.new_comparison, args.new_findings_csv)
    old_scenarios = {row["scenario_id"]: row
                     for row in older["comparison"]["comparisons"]}
    new_scenarios = {row["scenario_id"]: row
                     for row in newer["comparison"]["comparisons"]}
    raw_links = read_regular(args.old_links, MAX_LINKS)
    manual_links = links_document(
        raw_links, older["comparison_sha"], older["findings_sha"],
        set(old_scenarios), older["findings"])
    delta = {
        "scenarios": changes(old_scenarios, new_scenarios),
        "findings": changes(older["findings"], newer["findings"]),
    }
    keep_scenarios = set(delta["scenarios"]["unchanged"])
    keep_findings = set(delta["findings"]["unchanged"])
    preserved, dropped = [], []
    for link in manual_links:
        if (args.carry_unchanged and link["scenario_id"] in keep_scenarios
                and link["finding_id"] in keep_findings):
            preserved.append(link)
        else:
            reason = ("scenario removed" if link["scenario_id"] not in new_scenarios
                      else "original scenario source changed"
                      if link["scenario_id"] not in keep_scenarios
                      else "finding removed" if link["finding_id"] not in newer["findings"]
                      else "original finding source changed"
                      if link["finding_id"] not in keep_findings
                      else "awaiting new human confirmation")
            dropped.append((link, reason))
    review_required = (
        bool(dropped) or
        any(delta[category][key] for category in delta
            for key in ("added", "missing", "changed")) or
        older["comparison_sha"] != newer["comparison_sha"] or
        older["findings_sha"] != newer["findings_sha"] or
        newer["comparison"]["status"] == "HOLD"
    )
    posture = "HOLD" if review_required else "REVIEW_ONLY"
    bound = {
        "schema": LINK_SCHEMA,
        "comparison_sha256": newer["comparison_sha"],
        "findings_sha256": newer["findings_sha"],
        "links": preserved,
        **{key: False for key in FLAGS},
    }
    aggregate = {
        "schema": "lightup.assessment_remediation_refresh_aggregate.v1",
        "status": posture,
        "prior_human_link_count": len(manual_links),
        "retained_human_link_count": len(preserved),
        "withheld_human_link_count": len(dropped),
        "original_scenario_change_counts": {
            key: len(value) for key, value in delta["scenarios"].items()},
        "original_finding_change_counts": {
            key: len(value) for key, value in delta["findings"].items()},
        "source_bytes_changed": (older["comparison_sha"] != newer["comparison_sha"] or
                                 older["findings_sha"] != newer["findings_sha"]),
        **{key: False for key in FLAGS},
    }
    outputs = {
        "refreshed-links.json": encode(bound),
        "private-change-report.html": private_html(older, newer, delta, preserved,
                                                    dropped, args.carry_unchanged, posture),
        "refresh-aggregate.json": encode(aggregate),
    }
    paths = [(folder / (args.prefix + "-" + name), payload)
             for name, payload in outputs.items()]
    fail_if(any(os.path.lexists(path) for path, _ in paths),
            "destination exists; never overwrite original operator output")
    for path, bound, expected in (
        (args.old_comparison, MAX_COMPARE, older["comparison_sha"]),
        (args.old_findings_csv, MAX_FINDINGS, older["findings_sha"]),
        (args.new_comparison, MAX_COMPARE, newer["comparison_sha"]),
        (args.new_findings_csv, MAX_FINDINGS, newer["findings_sha"]),
    ):
        fail_if(sha256(read_regular(path, bound)).hexdigest() != expected,
                "original source changed during private renewal")
    fail_if(read_regular(args.old_links, MAX_LINKS) != raw_links,
            "original human draft changed during private renewal")
    published = []
    try:
        for path, payload in paths:
            publish(path, payload)
            published.append((path, sha256(payload).digest()))
    except Exception:
        for path, expected in published:
            try:
                if sha256(read_regular(str(path), MAX_FINDINGS)).digest() == expected:
                    path.unlink()
            except (OSError, Hold):
                pass
        raise
    print("PRIVATE_ASSESSMENT_REFRESH_" + posture)
    print(str(len(preserved)) + " unchanged-source manual links retained; " +
          str(len(dropped)) + " withheld for renewed human review.")
    print("Three owner-private new-only artifacts created; no original data or security state changed.")
    return 3 if posture == "HOLD" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Offline source revision handoff. Drops links involving any changed or missing "
        "original scenario/finding. Does not grant permission or verify fixes."
    ))
    for key in ("old_comparison", "old_findings_csv",
                "new_comparison", "new_findings_csv", "old_links", "output_dir"):
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    parser.add_argument("--prefix", default="lightup-refresh")
    parser.add_argument("--carry-unchanged", action="store_true",
                        help="Only after human same-client/engagement verification: retain local "
                             "notes for exact semantically identical source rows")
    try:
        return renew(parser.parse_args(argv))
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_ASSESSMENT_REFRESH_HOLD — unsafe, incomplete or changed source", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
