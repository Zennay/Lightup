#!/usr/bin/env python3
"""PRIVATE offline comparison of two human-only review CSV revisions on one source.

Source is unverified; HUMAN revisions are not authority or verified progress.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys

from briefing import CSS, DENIAL_FLAGS, Hold, h, json_bytes, open_source, publish_new
from human_return import (MAX_CSV_BYTES, MAX_MANIFEST_BYTES, read_human_csv,
                          read_limited_file, source_manifest)

FIELDS = ("stage", "owner", "action", "blocker")
STAGE_KEYS = ("needs_review", "discussing", "blocked", "documented")


def revisions(before: list[dict], after: list[dict]) -> tuple[list[dict], dict]:
    if len(before) != len(after):
        raise Hold("PRIVATE HUMAN revision source count mismatch (HOLD)")
    differences = []
    status = {"unchanged": 0, "changed": 0, "stage_changed": 0,
              "owner_changed": 0, "action_changed": 0, "blocker_changed": 0}
    transition = {a + "_to_" + b: 0 for a in STAGE_KEYS for b in STAGE_KEYS if a != b}
    for ordinal, (old, new) in enumerate(zip(before, after), 1):
        altered = [field for field in FIELDS if old[field] != new[field]]
        if not altered:
            status["unchanged"] += 1
            continue
        status["changed"] += 1
        for field in altered:
            status[field + "_changed"] += 1
        if old["stage"] != new["stage"]:
            transition[old["stage"] + "_to_" + new["stage"]] += 1
        differences.append({"ordinal": ordinal, "altered": altered,
                            "before": old, "after": new})
    return differences, {"counts": status, "human_declared_stage_transitions": transition}


def render(source: dict, original_hash: str,
           before_hash: str, after_hash: str, changes: list[dict],
           stats: dict) -> str:
    tiles = "".join("<section class='card'><h3>" + h(k.replace("_", " ")) +
                    "</h3><p class='value'>" + str(v) + "</p></section>"
                    for k, v in stats["counts"].items())
    cards = []
    for change in changes:
        ordinal = change["ordinal"]
        original = source["findings"][ordinal-1]
        fields = []
        for name in change["altered"]:
            fields.append("<dt>" + h(name) + " · BEFORE (human)</dt><dd><pre>" +
                          h(change["before"][name] or "blank") +
                          "</pre></dd><dt>" + h(name) +
                          " · AFTER (human)</dt><dd><pre>" +
                          h(change["after"][name] or "blank") + "</pre></dd>")
        cards.append("<article><h3>Original ordinal #" + str(ordinal) +
                     " · source-declared " + h(original["severity"]) + "</h3>" +
                     "<p class='muted'>PRIVATE original source finding: " +
                     h(original["finding"]) + "</p>" +
                     "<p>Changed human fields: " + ", ".join(map(h, change["altered"])) +
                     "</p><dl>" + "".join(fields) + "</dl>" +
                     "<div class='worksheet'>Reviewer question: ____________________________" +
                     "<p>Was any real remediation or source change independently verified? " +
                     "Not established by this report.</p></div></article>")
    notices = ("<header><h1>LightUp · PRIVATE HUMAN revision differences</h1>" +
               "<p class='notice'>REVIEW ONLY — compares two HUMAN note files tied to the " +
               "same unchanged original lab source. Dates, actors, current consent, " +
               "remediation and fixes are NOT proven. No change is automatically progress.</p>" +
               "<p>Source fingerprint (UNSIGNED): <code>" + original_hash +
               "</code><br>BEFORE worksheet unsigned SHA-256: <code>" + before_hash +
               "</code><br>AFTER worksheet unsigned SHA-256: <code>" + after_hash +
               "</code></p><p>Source text and human notes are PRIVATE. Do not forward " +
               "outside a separately approved confidential review channel.</p></header>")
    pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + pin +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; " +
           "object-src 'none'; base-uri 'none'; form-action 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE human revisions</title><style>" + CSS +
            "</style></head><body>" + notices + "<div class='grid'>" + tiles +
            "</div>" + ("".join(cards) if cards else
                        "<section class='card'><p>No changes in HUMAN fields.</p></section>") +
            "</body></html>\n")


def create(source_path: str, manifest_path: str, before_path: str,
           after_path: str, destination: str) -> None:
    source, _, fingerprint = open_source(source_path)
    source_manifest(read_limited_file(manifest_path, MAX_MANIFEST_BYTES),
                    fingerprint, source)
    a = read_limited_file(before_path, MAX_CSV_BYTES)
    b = read_limited_file(after_path, MAX_CSV_BYTES)
    before = read_human_csv(a, source)
    after = read_human_csv(b, source)
    change_rows, stats = revisions(before, after)
    html = render(source, fingerprint, hashlib.sha256(a).hexdigest(),
                  hashlib.sha256(b).hexdigest(), change_rows, stats).encode("utf-8")
    data = {"schema": "lightup.private_lab_human_revision.v1", "status": "REVIEW_ONLY",
            "original_source_sha256_unsigned": fingerprint,
            "before_human_csv_sha256_unsigned": hashlib.sha256(a).hexdigest(),
            "after_human_csv_sha256_unsigned": hashlib.sha256(b).hexdigest(),
            "private_revision_html_sha256_unsigned": hashlib.sha256(html).hexdigest(),
            **stats, "source_authenticated": False, "human_identity_authenticated": False,
            "human_progress_verified": False, "client_consent_verified": False,
            "operator_consent_verified": False, **DENIAL_FLAGS}
    publish_new(destination, {"private-human-revisions.html": html,
                              "human-revision-counts.json": json_bytes(data)})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE HUMAN revision review — NO source changes or authority")
    parser.add_argument("--source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--before-worksheet", required=True)
    parser.add_argument("--after-worksheet", required=True)
    parser.add_argument("--output-dir", required=True, help="new PRIVATE directory")
    args = parser.parse_args()
    try:
        create(args.source, args.manifest, args.before_worksheet,
               args.after_worksheet, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE human revision differences created; REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
