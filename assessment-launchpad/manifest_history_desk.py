#!/usr/bin/env python3
"""Offline, source-bound review of ordered PRIVATE saved manifest plans; never runs an assessment."""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
from html import escape
from io import StringIO
import json
import os

from launchpad import (
    Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold,
)
from manifest_change_desk import admit_saved_bundle, compare

MAX_PLANS = 8
LIMIT = 65536
SUMMARY = "lightup-manifest-history-private.json"
HTML = "lightup-manifest-history-private.html"
CSV = "lightup-manifest-history-counts-private.csv"
QUEUE = "lightup-manifest-history-review-queue-private.csv"
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:950px;margin:2rem auto;"
    "padding:1rem;color:#182439}h1{font-size:1.7rem}"
    ".hold{background:#fff3dc;border-left:5px solid #9a6711;padding:1rem}"
    "table{border-collapse:collapse;width:100%}th,td{border:1px solid #bac6d3;"
    "padding:.55rem;text-align:right}th:first-child,td:first-child{text-align:left}"
    "th{background:#e9f1fa}small{color:#4b596d}"
)


def prepare(paths):
    if not 2 <= len(paths) <= MAX_PLANS:
        raise Hold("choose 2 to 8 ordered saved PRIVATE manifest bundles")
    plans = [admit_saved_bundle(path) for path in paths]
    if len(set(absolute for absolute, _, _ in plans)) != len(plans):
        raise Hold("saved PRIVATE source bundle directories must be distinct")
    rows = []
    queue = []
    for index in range(1, len(plans)):
        _, _, before = plans[index - 1]
        _, _, after = plans[index]
        changes, counts = compare(before, after)
        for change in changes:
            if change["state"] != "UNCHANGED":
                queue.append({
                    "from_ordinal": index, "to_ordinal": index + 1,
                    "change": change["state"],
                    "before_slot": change["before_slot"],
                    "after_slot": change["after_slot"],
                    "human_stage": "FOLLOW_UP_REQUIRED",
                })
        rows.append({
            "from_ordinal": index, "to_ordinal": index + 1,
            "before_count": len(before), "after_count": len(after),
            "unchanged": counts["UNCHANGED"], "moved": counts["MOVED"],
            "removed": counts["REMOVED"], "added": counts["ADDED"],
        })
    _, net_counts = compare(plans[0][2], plans[-1][2])
    packet = {
        "schema": "lightup.private-manifest-history.v1",
        "status": "REVIEW_ONLY",
        "plan_count": len(plans),
        "source_manifest_sha256": [sha256(raw).hexdigest() for _, raw, _ in plans],
        "transitions": rows,
        "human_review_queue": queue,
        "human_review_queue_count": len(queue),
        "first_to_last": {
            "before_count": len(plans[0][2]), "after_count": len(plans[-1][2]),
            "unchanged": net_counts["UNCHANGED"], "moved": net_counts["MOVED"],
            "removed": net_counts["REMOVED"], "added": net_counts["ADDED"],
        },
        "source_authenticated": False, "authorized": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        "revocation_checked": False, "human_go": False,
        "assessment_executed": False, "release_allowed": False,
    }
    return plans, packet


def render_html(packet):
    style_hash = base64.b64encode(sha256(STYLE.encode()).digest()).decode("ascii")
    cols = ("from_ordinal", "to_ordinal", "before_count", "after_count",
            "unchanged", "moved", "removed", "added")
    heading = ("Before", "After", "Old slots", "New slots", "Unchanged", "Moved", "Removed", "Added")
    rows = "".join("<tr>" + "".join("<td>" + escape(str(row[name])) + "</td>"
                                      for name in cols) + "</tr>"
                   for row in packet["transitions"])
    queue_rows = "".join(
        "<tr><td>" + str(row["from_ordinal"]) + " → " + str(row["to_ordinal"]) +
        "</td><td>" + escape(row["change"]) + "</td><td>" +
        (str(row["before_slot"]) if row["before_slot"] is not None else "—") +
        "</td><td>" +
        (str(row["after_slot"]) if row["after_slot"] is not None else "—") +
        "</td><td>HUMAN follow-up required</td></tr>"
        for row in packet["human_review_queue"]
    )
    net = packet["first_to_last"]
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'none'; style-src 'sha256-" + style_hash +
        "'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE manifest history</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE lab plan history</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY ·"
        " NO TARGET CONTACT, CONSENT, AUTHORITY OR ASSESSMENT</p>"
        "<p>" + str(packet["plan_count"]) + " operator-ordered saved plans."
        " Order is not authenticated chronology. Endpoint identity is used only"
        " in local memory to compute literal equality; URLs, filenames,"
        " paths, notes and digests are absent from this HTML and the CSV.</p>"
        "<table><thead><tr>" +
        "".join("<th scope='col'>" + escape(label) + "</th>" for label in heading) +
        "</tr></thead><tbody>" + rows + "</tbody></table>"
        "<details><summary>Ordinal HUMAN follow-up queue (" +
        str(packet["human_review_queue_count"]) + " changes)</summary>"
        "<p>These rows are suggestions for PRIVATE HUMAN review, not actual"
        " findings, authorization or remediation status. Each row refers only"
        " to the two local snapshots selected by the operator.</p>"
        "<table><thead><tr><th>Plan pair</th><th>Literal change</th>"
        "<th>Before slot</th><th>After slot</th><th>Stage</th></tr></thead>"
        "<tbody>" + queue_rows + "</tbody></table></details>"
        "<h2>First-to-last literal change</h2><p>Unchanged " +
        str(net["unchanged"]) + " · Moved " + str(net["moved"]) +
        " · Removed " + str(net["removed"]) + " · Added " + str(net["added"]) +
        "</p><p><small>Changes in a manifest are not evidence of risk,"
        " findings, fixes or remediation. Local unsigned digests do not"
        " authenticate origin, identity or client/operator consent. Action-time"
        " revocation, independent approval and HUMAN GO remain mandatory."
        " Counts and ordering can also be sensitive: keep this report PRIVATE."
        "</small></p></body></html>"
    ).encode("utf-8")


def render_csv(packet):
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    columns = ("from_ordinal", "to_ordinal", "before_count", "after_count",
               "unchanged", "moved", "removed", "added")
    writer.writerow(columns)
    for row in packet["transitions"]:
        writer.writerow([row[name] for name in columns])
    return output.getvalue().encode("utf-8")


def render_queue_csv(packet):
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    cols = ("from_ordinal", "to_ordinal", "change", "before_slot",
            "after_slot", "human_stage")
    writer.writerow(cols)
    for row in packet["human_review_queue"]:
        writer.writerow([row[name] if row[name] is not None else "" for name in cols])
    return output.getvalue().encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Summarize 2–8 previously saved PRIVATE combined manifests; no assessment.")
    parser.add_argument("--plan-dir", action="append", default=[], required=True,
                        help="ordered saved PRIVATE combined bundle; repeat 2–8 times")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="separate empty private 0700 directory")
    destination.add_argument("--verify-output-dir", help="read-only exact reopen of prior history")
    parser.add_argument("--explain-hold", action="store_true", help="curated HOLD only; never source values")
    args = parser.parse_args(argv)
    try:
        plans, packet = prepare(args.plan_dir)
        files = {
            SUMMARY: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            HTML: render_html(packet),
            CSV: render_csv(packet),
            QUEUE: render_queue_csv(packet),
        }
        if any(not 0 < len(value) <= LIMIT for value in files.values()):
            raise Hold("PRIVATE history output exceeds byte limit")
        destination_path = args.output_dir or args.verify_output_dir
        fd, target = open_output_directory(destination_path)
        try:
            for source, _, _ in plans:
                shared = os.path.commonpath((source, target))
                if shared in (source, target):
                    raise Hold("history output must be separate from every source tree")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(files):
                    raise Hold("saved PRIVATE history has missing or extra files")
                for name, expected in files.items():
                    if read_private_bundle_item(fd, name, LIMIT) != expected:
                        raise Hold("saved PRIVATE history drifted from re-admitted sources")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE history output directory must be empty")
                # Re-admit immediately before publication: held source bytes must not drift.
                for (source, raw, _), path in zip(plans, args.plan_dir):
                    reopened, current, _ = admit_saved_bundle(path)
                    if reopened != source or current != raw:
                        raise Hold("saved source bundle changed before history publication")
                publish_bundle(fd, list(files.items()))
        finally:
            os.close(fd)
        print(("MANIFEST_HISTORY_REOPENED" if args.verify_output_dir else
               "MANIFEST_HISTORY_CREATED") + " · plans=" + str(len(plans)) +
              " · transitions=" + str(len(packet["transitions"])) +
              " · REVIEW_ONLY; no target action or authority")
        return 0
    except Hold as error:
        report_hold("PRIVATE_MANIFEST_HISTORY_HOLD — original source or output not admitted",
                    error, args.explain_hold)
    except Exception:
        report_hold("PRIVATE_MANIFEST_HISTORY_HOLD — private parsing or filesystem failure",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
