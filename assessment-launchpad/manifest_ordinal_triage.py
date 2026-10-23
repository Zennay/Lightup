#!/usr/bin/env python3
"""Original-manifest-bound, endpoint-free HUMAN triage for an existing PRIVATE change desk.

This local command never scans, resolves targets, contacts a provider or grants authority.
"""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
from html import escape
import io
import json
import os
import sys

from launchpad import (
    Hold, open_output_directory, publish_bundle, read_private_bundle_item,
    report_hold, reject_constant, unique_pairs,
)
from manifest_change_desk import (
    DELTA_JSON, OUTPUT_LIMIT, admit_saved_bundle, compare,
)

JSON_NAME = "lightup-private-manifest-human-triage.json"
HTML_NAME = "lightup-private-manifest-human-triage.html"
CSV_NAME = "lightup-private-manifest-human-triage.csv"
MAX_OUTPUT = 32768
DECISIONS = {
    "REMOVED": ("SOURCE_GAP", "Ask whether this original ordinal was intentionally removed; absence never proves a fix."),
    "ADDED": ("NEW_SOURCE", "Ask the original source holder to review this newly declared ordinal, without approving a scan."),
    "MOVED": ("ORDER_CHANGE", "Confirm ordinal reassignment with the source holder before reusing HUMAN notes."),
    "UNCHANGED": ("REFERENCE_ONLY", "Confirm literal source continuity; identical URLs are not authorization."),
}
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;color:#17212f;"
    "max-width:950px;margin:2rem auto;padding:1rem}"
    ".hold{border-left:5px solid #94600c;background:#fff5de;padding:1rem}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{padding:.55rem;border:1px solid #cbd5e1;text-align:left}"
    "th{background:#e9f1fb}small{color:#59677a}"
    "a{color:#18467b;font-weight:750}"
)

def original_delta(before_raw, after_raw, before, after):
    changes, totals = compare(before, after)
    return {
        "schema": "lightup.private-manifest-delta.v1",
        "status": "REVIEW_ONLY",
        "before_count": len(before), "after_count": len(after),
        "before_sha256": sha256(before_raw).hexdigest(),
        "after_sha256": sha256(after_raw).hexdigest(),
        "totals": totals, "changes": changes,
        "source_authenticated": False, "client_consent_verified": False,
        "operator_consent_verified": False, "authorized": False,
        "human_go": False, "target_contact": False, "release_allowed": False,
    }

def admit_delta(path, expected):
    fd, absolute = open_output_directory(path)
    try:
        names = set(os.listdir(fd))
        if not {
            "lightup-private-manifest-delta.json",
            "lightup-private-manifest-delta.html",
        }.issubset(names):
            raise Hold("existing change desk has missing original artifacts")
        raw = read_private_bundle_item(fd, DELTA_JSON, OUTPUT_LIMIT)
    finally:
        os.close(fd)
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                            parse_constant=reject_constant, parse_float=reject_constant)
    except (UnicodeError, TypeError, ValueError) as exc:
        raise Hold("original change receipt is not canonical JSON") from exc
    canonical = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if parsed != expected or raw != canonical:
        raise Hold("original PRIVATE change receipt or source context changed")
    return absolute, raw

def make_packet(original, delta_sha):
    entries = []
    for row, change in enumerate(original["changes"], 1):
        status = change["state"]
        code, question = DECISIONS[status]
        entries.append({
            "original_change_row": row,
            "change_state": status,
            "before_ordinal": change["before_slot"],
            "after_ordinal": change["after_slot"],
            "human_queue": code,
            "human_question": question,
            "human_decision_recorded": False,
        })
    entries.sort(key=lambda x: (
        {"SOURCE_GAP": 0, "NEW_SOURCE": 1, "ORDER_CHANGE": 2, "REFERENCE_ONLY": 3}[x["human_queue"]],
        x["original_change_row"],
    ))
    return {
        "schema": "lightup.private-manifest-human-triage.v1",
        "status": "REVIEW_ONLY",
        "source_delta_sha256": delta_sha,
        "before_manifest_sha256": original["before_sha256"],
        "after_manifest_sha256": original["after_sha256"],
        "before_count": original["before_count"],
        "after_count": original["after_count"],
        "totals": original["totals"],
        "human_rows": entries,
        "authorized": False, "client_consent_verified": False,
        "operator_consent_verified": False, "human_go": False,
        "source_authenticated": False, "target_contact": False,
        "release_allowed": False, "human_decision_verified": False,
    }

def html_content(packet):
    pin = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    lines = []
    for row in packet["human_rows"]:
        before = "—" if row["before_ordinal"] is None else str(row["before_ordinal"])
        after = "—" if row["after_ordinal"] is None else str(row["after_ordinal"])
        cells = (row["original_change_row"], row["human_queue"], before,
                 after, row["human_question"])
        lines.append("<tr>" + "".join("<td>" + escape(str(v)) + "</td>" for v in cells) + "</tr>")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'none'; style-src 'sha256-" + pin + "'; connect-src 'none'; "
        "img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE manifest HUMAN triage</title><style>" + STYLE + "</style></head><body>"
        "<h1>PRIVATE manifest-change HUMAN triage</h1>"
        "<p class='hold'>INCUBATE M3/M7 · LAB ONLY · REVIEW_ONLY · NOT AUTHORIZED</p>"
        "<p>These are literal changes in two separately saved PRIVATE lab manifests, "
        "not verified timeline events. Ordinals and labels only: no target URL, "
        "credentials, source paths or HUMAN notes. Missing assets are never proven fixed.</p>"
        "<p>Original change rows are preserved, reordered only for HUMAN attention. "
        "Priority: removed, added, moved, unchanged. No selection or decision is made here.</p>"
        "<table><thead><tr><th>Original row</th><th>HUMAN queue</th>"
        "<th>Before slot</th><th>After slot</th><th>Human follow-up question</th>"
        "</tr></thead><tbody>" + "".join(lines) + "</tbody></table>"
        "<p><a href='" + CSV_NAME + "'>Open original-ordinal HUMAN queue CSV</a></p>"
        "<p><small>Source consistency is only an unsigned SHA-256 comparison; "
        "no authenticated source, identity, client/operator consent, scope grant, "
        "at-use revocation, HUMAN GO, scan permission, or release authority.</small></p>"
        "</body></html>"
    )
    return html.encode("utf-8")

def csv_content(packet):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("original_change_row", "change_state", "human_queue",
                     "before_ordinal", "after_ordinal", "human_decision_recorded"))
    for item in packet["human_rows"]:
        writer.writerow((item["original_change_row"], item["change_state"],
                         item["human_queue"], item["before_ordinal"] or "",
                         item["after_ordinal"] or "", "false"))
    return out.getvalue().encode("ascii")

def source_inputs(before_dir, after_dir, delta_dir):
    bpath, braw, before = admit_saved_bundle(before_dir)
    apath, araw, after = admit_saved_bundle(after_dir)
    if bpath == apath:
        raise Hold("original manifests must be separately saved source directories")
    original = original_delta(braw, araw, before, after)
    dpath, draw = admit_delta(delta_dir, original)
    return (bpath, apath, dpath), (braw, araw, draw), original

def build_outputs(original, delta_raw):
    packet = make_packet(original, sha256(delta_raw).hexdigest())
    data = {
        JSON_NAME: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        HTML_NAME: html_content(packet),
        CSV_NAME: csv_content(packet),
    }
    if any(not 0 < len(value) <= MAX_OUTPUT for value in data.values()):
        raise Hold("PRIVATE triage workroom exceeded the fixed output limit")
    return data, packet

def run(args):
    sources, originals, original = source_inputs(args.before_dir, args.after_dir, args.delta_dir)
    data, packet = build_outputs(original, originals[2])
    fd, output = open_output_directory(args.output_dir or args.verify_output_dir)
    try:
        for path in sources:
            common = os.path.commonpath((output, path))
            if common in (output, path):
                raise Hold("PRIVATE HUMAN triage must be separate from all source directories")
        # Fail closed if any original source or the canonical change receipt moved
        # between initial admission and the publication/reopen boundary.
        latest_sources, latest_raw, latest_original = source_inputs(
            args.before_dir, args.after_dir, args.delta_dir
        )
        if sources != latest_sources or originals != latest_raw or original != latest_original:
            raise Hold("original source changed before PRIVATE HUMAN triage publication")
        if args.verify_output_dir:
            if set(os.listdir(fd)) != set(data):
                raise Hold("original HUMAN triage output is missing or contains extra artifacts")
            for name, expected in data.items():
                if read_private_bundle_item(fd, name, MAX_OUTPUT) != expected:
                    raise Hold("original HUMAN triage output no longer matches source bytes")
        else:
            if os.listdir(fd):
                raise Hold("PRIVATE HUMAN triage destination must be empty")
            publish_bundle(fd, list(data.items()))
    finally:
        os.close(fd)
    print(("MANIFEST_TRIAGE_REOPENED" if args.verify_output_dir else "MANIFEST_TRIAGE_CREATED")
          + " · rows=" + str(len(packet["human_rows"]))
          + " · HUMAN REVIEW_ONLY, no endpoint disclosure, authority or scan")
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline PRIVATE ordinal-only HUMAN manifest-change queue.")
    parser.add_argument("--before-dir", required=True, help="original owner-private before manifest bundle")
    parser.add_argument("--after-dir", required=True, help="original owner-private after manifest bundle")
    parser.add_argument("--delta-dir", required=True, help="original native PRIVATE manifest change-desk bundle")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir", help="new empty owner-private mode-0700 destination")
    action.add_argument("--verify-output-dir", help="read-only exact source-bound reopening")
    parser.add_argument("--explain-hold", action="store_true")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Hold as exc:
        report_hold("PRIVATE_MANIFEST_TRIAGE_HOLD — original source or HUMAN output not admitted",
                    exc, args.explain_hold)
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        report_hold("PRIVATE_MANIFEST_TRIAGE_HOLD — filesystem or source parsing failed",
                    None, args.explain_hold)
    return 3

if __name__ == "__main__":
    raise SystemExit(main())
