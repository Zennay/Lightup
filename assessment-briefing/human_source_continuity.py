#!/usr/bin/env python3
"""Offline HUMAN follow-up continuity draft for TWO already-produced lab results.

No original scan, finding validity, remediation, person or permission is inferred.
A source-only similarity never authorizes reuse of old decisions as truth.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import sys
import unicodedata

from briefing import CSS, DENIAL_FLAGS, Hold, h, json_bytes, open_source, publish_new
from human_return import (MAX_CSV_BYTES, MAX_MANIFEST_BYTES,
                          read_human_csv, read_limited_file, source_manifest)

MATCH_KEYS = ("target", "capability_id", "check_id")
SOURCE_FIELDS = ("severity", "finding", "impact", "fix", "retest",
                 "evidence_summary", "evidence_ids")
ORIGINAL_HEADER = ("original_ordinal", "source_reported_severity",
                   "evidence_reference_count", "human_stage", "human_owner_group",
                   "human_next_action", "human_blocker")
CATEGORIES = ("literal_source_equal", "finding_id_changed",
              "evidence_refs_changed", "descriptive_source_changed",
              "only_in_next_source", "ambiguous_key")


def index_keys(source: dict) -> dict[tuple[str, ...], list[tuple[int, dict]]]:
    output: dict[tuple[str, ...], list[tuple[int, dict]]] = {}
    for ordinal, f in enumerate(source["findings"], 1):
        output.setdefault(tuple(f[key] for key in MATCH_KEYS), []).append((ordinal, f))
    return output


def spreadsheet_safe(value: str) -> bool:
    text = unicodedata.normalize("NFKC", value)
    text = text.lstrip(" \t\u00a0\u2000\u2001\u2002\u2003\u2004\u2005"
                       "\u2006\u2007\u2008\u2009\u200a\u200b\u200e\u200f"
                       "\u202a\u202b\u202c\u202d\u202e\u2060\ufeff")
    return not text.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))


def compare_sources(before: dict, after: dict, human: list[dict]) -> tuple[list, dict]:
    if (before["scenario_id"] != after["scenario_id"] or
            before["run_id"] == after["run_id"] or
            set(before["targets"]) != set(after["targets"]) or
            len(before["targets"]) != len(after["targets"])):
        raise Hold("PRIVATE original source scenarios/target membership not coherent (HOLD)")
    old = index_keys(before)
    new = index_keys(after)
    updated = []
    counts = {key: 0 for key in CATEGORIES}
    old_absent = 0
    for key, rows in old.items():
        if key not in new:
            old_absent += len(rows)
    for current_ordinal, finding in enumerate(after["findings"], 1):
        key = tuple(finding[k] for k in MATCH_KEYS)
        a, b = old.get(key, []), new[key]
        if len(a) != 1 or len(b) != 1:
            category = "ambiguous_key" if a or len(b) > 1 else "only_in_next_source"
            previous_ordinal = None
        else:
            previous_ordinal, older = a[0]
            if any(older[field] != finding[field]
                   for field in SOURCE_FIELDS if field != "evidence_ids"):
                category = "descriptive_source_changed"
            elif older["evidence_ids"] != finding["evidence_ids"]:
                category = "evidence_refs_changed"
            elif older["finding_id"] != finding["finding_id"]:
                category = "finding_id_changed"
            else:
                category = "literal_source_equal"
        counts[category] += 1
        new_human = {"stage": "needs_review", "group": "",
                     "action": "", "blocker": ""}
        if previous_ordinal is not None:
            previous = human[previous_ordinal-1]
            # A group is solely a HUMAN routing *suggestion*. Never inherit any
            # human stage, approved state, consent, verification or triage verdict.
            new_human["group"] = previous["owner"]
            if category == "literal_source_equal":
                # Even identical source text is no verified vulnerability.
                # The new stage is ALWAYS needs_review, intentionally.
                new_human["action"] = previous["action"]
                new_human["blocker"] = previous["blocker"]
        if not all(spreadsheet_safe(new_human[field])
                   for field in ("group", "action", "blocker")):
            raise Hold("Unsafe HUMAN formula-shaped note in PRIVATE input (HOLD)")
        updated.append({
            "ordinal": current_ordinal,
            "source": finding,
            "previous_ordinal": previous_ordinal,
            "status": category,
            "human_proposal": new_human,
        })
    return updated, {"by_source_declaration_status": counts,
                     "before_only_source_declarations": old_absent}


def original_csv(rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(ORIGINAL_HEADER)
    for row in rows:
        source = row["source"]
        human = row["human_proposal"]
        writer.writerow((row["ordinal"], source["severity"],
                         len(source["evidence_ids"]), human["stage"],
                         human["group"], human["action"], human["blocker"]))
    return output.getvalue().encode("utf-8")


def source_review_html(rows: list[dict], before_hash: str, after_hash: str,
                       totals: dict) -> bytes:
    counts = totals["by_source_declaration_status"]
    cards = "".join("<section class='card'><h3>" + h(state.replace("_", " ")) +
                    "</h3><p class='value'>" + str(n) + "</p></section>"
                    for state, n in counts.items())
    pieces = []
    for row in rows:
        f = row["source"]
        human = row["human_proposal"]
        pieces.append(
            "<article><h3>NEW source ordinal #" + str(row["ordinal"]) +
            " · " + h(row["status"].replace("_", " ")) + "</h3>" +
            "<p class='muted'>Prior original ordinal: " +
            h(row["previous_ordinal"] or "none / ambiguous") +
            " · source declared severity: " + h(f["severity"]) + "</p>" +
            "<details><summary>PRIVATE newest original source declaration</summary>" +
            "<dl><dt>Source target</dt><dd>" + h(f["target"]) +
            "</dd><dt>Source title</dt><dd>" + h(f["finding"]) +
            "</dd><dt>Source check</dt><dd>" + h(f["check_id"]) +
            "</dd><dt>Source capability</dt><dd>" + h(f["capability_id"]) +
            "</dd><dt>Source impact</dt><dd>" + h(f["impact"]) +
            "</dd><dt>Source suggested fix</dt><dd>" + h(f["fix"]) +
            "</dd><dt>Source evidence summary</dt><dd>" + h(f["evidence_summary"]) +
            "</dd></dl></details>" +
            "<p><strong>Next review: HUMAN-only, never transferred verified status.</strong></p>" +
            "<dl><dt>Proposed HUMAN stage</dt><dd>needs_review</dd>" +
            "<dt>Proposed HUMAN group</dt><dd>" + h(human["group"] or "Unassigned") +
            "</dd><dt>Prior proposed action (only if literal source equal)</dt><dd>" +
            h(human["action"] or "Fresh HUMAN input required") +
            "</dd><dt>Human uncertainty/blocker proposal</dt><dd>" +
            h(human["blocker"] or "Not carried") + "</dd></dl></article>"
        )
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; img-src 'none'; connect-src 'none'; " +
           "base-uri 'none'; form-action 'none'; object-src 'none'")
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN follow-up continuation proposal</h1>" +
        "<p class='notice'>REVIEW ONLY. Different lab run declarations are NOT " +
        "verified new/fixed findings, actual target states, retests or consent. " +
        "Any copied HUMAN proposal remains unreviewed. Every newer source stage " +
        "has been reset to needs_review.</p>" +
        "<p>PRIOR original source SHA-256 (UNSIGNED): <code>" + before_hash +
        "</code><br>NEW original source SHA-256 (UNSIGNED): <code>" + after_hash +
        "</code></p><p>Prior source declarations absent from newer report: " +
        str(totals["before_only_source_declarations"]) +
        " (ABSENT is NOT fixed or resolved).</p>" +
        "<p>PRIVATE targets, titles and evidence details appear in the following " +
        "cards and require separately approved private handling. Neither source " +
        "hash authenticates its producer.</p></header><div class='grid'>" +
        cards + "</div>" + "".join(pieces)
    )
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) +
            "\"><meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE HUMAN continuation proposal</title><style>" +
            CSS + "</style></head><body>" + body + "</body></html>\n").encode("utf-8")


def create(before_file: str, before_manifest: str, before_csv: str,
           after_file: str, output_dir: str) -> None:
    before, _, old_hash = open_source(before_file)
    source_manifest(read_limited_file(before_manifest, MAX_MANIFEST_BYTES),
                    old_hash, before)
    human = read_human_csv(read_limited_file(before_csv, MAX_CSV_BYTES), before)
    after, _, new_hash = open_source(after_file)
    if new_hash == old_hash:
        raise Hold("Original source byte hashes are identical; no new source (HOLD)")
    rows, categories = compare_sources(before, after, human)
    human_csv = original_csv(rows)
    if len(human_csv) > MAX_CSV_BYTES:
        raise Hold("PRIVATE proposed HUMAN CSV too large (HOLD)")
    page = source_review_html(rows, old_hash, new_hash, categories)
    proposed = {
        "schema": "lightup.private_human_source_continuity.v1",
        "status": "REVIEW_ONLY",
        "before_source_sha256_unsigned": old_hash,
        "after_source_sha256_unsigned": new_hash,
        "new_source_finding_count": len(rows),
        **categories,
        "proposed_human_csv_sha256_unsigned": hashlib.sha256(human_csv).hexdigest(),
        "private_proposal_report_sha256_unsigned": hashlib.sha256(page).hexdigest(),
        "human_stage_always_needs_review": True,
        "source_authenticated": False,
        "human_identity_authenticated": False,
        "finding_validity_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        **DENIAL_FLAGS,
    }
    publish_new(output_dir, {
        "PRIVATE-next-human-review-PROPOSAL.csv": human_csv,
        "PRIVATE-human-source-continuity.html": page,
        "PRIVATE-proposal-manifest.json": json_bytes(proposed),
    })


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE source-safe HUMAN next-run proposal (NO execution/authority)")
    parser.add_argument("--before", required=True, help="earlier original PRIVATE lab JSON")
    parser.add_argument("--before-manifest", required=True,
                        help="original unsigned earlier briefing manifest")
    parser.add_argument("--before-worksheet", required=True,
                        help="earlier human-filled original-format CSV")
    parser.add_argument("--after", required=True, help="newer independently obtained lab JSON")
    parser.add_argument("--output-dir", required=True,
                        help="NEW protected PRIVATE proposal directory")
    options = parser.parse_args()
    try:
        create(options.before, options.before_manifest,
               options.before_worksheet, options.after, options.output_dir)
    except Hold:
        print("HOLD: PRIVATE source continuity not admitted; no proposal published",
              file=sys.stderr)
        return 3
    print("Created new PRIVATE HUMAN-only proposed follow-up; all stages require REVIEW")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
