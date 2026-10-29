#!/usr/bin/env python3
"""Human-only PRIVATE source-declaration drift briefing for two finished lab JSONs.

Never runs scans, interprets absence as a fix, or attests source authenticity.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import sys

from briefing import CSS, Hold, DENIAL_FLAGS, h, open_source, publish_new, json_bytes

MAX_GROUPS = 4096
FIELDS = ("severity", "finding", "impact", "fix", "retest",
          "evidence_summary")
CATEGORIES = ("ambiguous", "reported_only_before", "reported_only_after",
              "source_description_changed", "source_description_equal")


def group(source: dict) -> dict:
    groups = {}
    for ordinal, finding in enumerate(source["findings"], 1):
        key = (finding["target"], finding["capability_id"], finding["check_id"])
        groups.setdefault(key, []).append((ordinal, finding))
    return groups


def compare(a: dict, b: dict) -> list[dict]:
    # Same original declaration, not source-proven ownership or consent.
    if (a["scenario_id"] != b["scenario_id"] or
            len(a["targets"]) != len(b["targets"]) or
            set(a["targets"]) != set(b["targets"]) or
            a["run_id"] == b["run_id"]):
        raise Hold("Private source identities/scenario differ (HOLD)")
    left, right = group(a), group(b)
    rows = []
    for k in sorted(set(left) | set(right)):
        la, lb = left.get(k, []), right.get(k, [])
        if len(la) > 1 or len(lb) > 1:
            state = "ambiguous"
        elif not la:
            state = "reported_only_after"
        elif not lb:
            state = "reported_only_before"
        elif any(la[0][1][field] != lb[0][1][field] for field in FIELDS):
            state = "source_description_changed"
        else:
            state = "source_description_equal"
        rows.append({"category": state, "key": k, "before": la, "after": lb})
    if len(rows) > MAX_GROUPS:
        raise Hold("Too many source groups (HOLD)")
    return rows


def report(rows: list[dict], before_sha: str, after_sha: str) -> str:
    stats = {k: sum(item["category"] == k for item in rows) for k in CATEGORIES}
    tiles = "".join("<section class='card'><strong>" + h(category.replace("_", " ")) +
                    "</strong><div class='value'>" + str(count) + "</div></section>"
                    for category, count in stats.items())
    sections = []
    for i, row in enumerate(rows, 1):
        before, after = row["before"], row["after"]
        def snapshot(label: str, entries: list) -> str:
            if not entries:
                return "<p>" + h(label) + ": no source group declaration</p>"
            parts = []
            for ordinal, f in entries:
                private = "".join("<dt>" + h(name) + "</dt><dd>" + h(f[name]) +
                                  "</dd>" for name in FIELDS)
                private += "<dt>Original source ID</dt><dd>" + h(f["finding_id"]) + "</dd>"
                private += "<dt>Source evidence reference count</dt><dd>" + \
                           str(len(f["evidence_ids"])) + "</dd>"
                parts.append("<details><summary>" + h(label) + " / original #" +
                             str(ordinal) + " · " + h(f["severity"]) +
                             "</summary><div><dl>" + private + "</dl></div></details>")
            return "".join(parts)
        sections.append("<article><h3>Group " + str(i) + " · " +
                        h(row["category"].replace("_", " ")) + "</h3>" +
                        "<p class='muted'>PRIVATE literal source target: " +
                        h(row["key"][0]) + " · capability " + h(row["key"][1]) +
                        " · check " + h(row["key"][2]) + "</p>" +
                        snapshot("BEFORE", before) + snapshot("AFTER", after) +
                        "<div class='worksheet'><strong>Human independent follow-up</strong>" +
                        "<p>Open question: ______________________________________</p>" +
                        "<p>Original evidence authenticity checked by: ________________</p>" +
                        "<p>Do not infer actual new/fixed/retested vulnerabilities.</p></div></article>")
    notice = ("<header><h1>PRIVATE source-declaration drift review</h1>" +
              "<p class='notice'>REVIEW ONLY. The report compares two unverified original " +
              "offline lab declarations, not targets, actual exposures or remediation.</p>" +
              "<p>Reported-only-before NEVER means fixed. Reported-only-after NEVER " +
              "means a new verified vulnerability. Ambiguity NEVER auto-matches.</p>" +
              "<p>PRIVATE original SHA-256 BEFORE: <code>" + before_sha +
              "</code><br>AFTER: <code>" + after_sha + "</code>. " +
              "These are UNSIGNED local byte digests, NOT producer signatures.</p></header>")
    import base64
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; " +
           "object-src 'none'; base-uri 'none'; form-action 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE lab source drift</title><style>" + CSS +
            "</style></head><body>" + notice + "<div class='grid'>" +
            tiles + "</div>" + "".join(sections) + "</body></html>\n")


def human_csv(rows: list[dict]) -> str:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    # Export source-only ordinal + category, never source text, target, IDs or raw evidence.
    writer.writerow(("group_ordinal", "unverified_source_category",
                     "before_declaration_count", "after_declaration_count",
                     "human_owner", "human_followup", "human_blocker"))
    for i, row in enumerate(rows, 1):
        writer.writerow((i, row["category"], len(row["before"]), len(row["after"]),
                         "", "", ""))
    return out.getvalue()


def create_comparison(before: str, after: str, destination: str) -> None:
    a, _, sha_a = open_source(before)
    b, _, sha_b = open_source(after)
    if sha_a == sha_b:
        raise Hold("Duplicate identical source bytes (HOLD)")
    rows = compare(a, b)
    page = report(rows, sha_a, sha_b).encode("utf-8")
    table = human_csv(rows).encode("utf-8")
    summary = {
        "schema": "lightup.private_lab_source_drift.v1", "status": "REVIEW_ONLY",
        "before_source_sha256_unsigned": sha_a, "after_source_sha256_unsigned": sha_b,
        "original_source_group_count": len(rows),
        "source_reported_only": {key: sum(r["category"] == key for r in rows)
                                 for key in CATEGORIES},
        "private_artifact_sha256": {
            "private-drift.html": hashlib.sha256(page).hexdigest(),
            "human-drift-followup.csv": hashlib.sha256(table).hexdigest()},
        "source_authenticated": False, "ground_truth_verified": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        **DENIAL_FLAGS,
    }
    publish_new(destination, {"private-drift.html": page,
                              "human-drift-followup.csv": table,
                              "manifest.json": json_bytes(summary)})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE offline original lab source drift, NOT vulnerability verdict")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--output-dir", required=True, help="NEW PRIVATE directory")
    args = parser.parse_args()
    try:
        create_comparison(args.before, args.after, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE human source drift comparison created; REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
