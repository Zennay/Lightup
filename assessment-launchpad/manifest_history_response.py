#!/usr/bin/env python3
"""Source-bound HUMAN-only return for a PRIVATE saved lab-plan history; never authorizes assessment."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import csv
from hashlib import sha256
from html import escape
from io import StringIO
import json
import os

import manifest_history_desk as history
from launchpad import (
    Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold,
)

RESPONSE = "lightup-manifest-history-human-return-private.json"
HTML = "lightup-manifest-history-human-return-private.html"
COUNTS = "lightup-manifest-history-human-status-private.csv"
LIMIT = 65536
STAGES = ("FOLLOW_UP_REQUIRED", "NEEDS_CONTEXT", "IN_REVIEW",
          "QUESTION_PREPARED", "PARKED", "HUMAN_REVIEWED")
COLS = ("from_ordinal", "to_ordinal", "change", "before_slot", "after_slot", "human_stage")
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;"
    "padding:1rem;color:#172133}.hold{padding:1rem;background:#fff2d8;"
    "border-left:5px solid #987014}table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #bbc7d6;text-align:left;padding:.6rem}"
    "th{background:#eaf1f9}small{color:#536073}"
)


def admit_answers(answers_dir, expected):
    fd, absolute = open_output_directory(answers_dir)
    try:
        if set(os.listdir(fd)) != {history.QUEUE}:
            raise Hold("PRIVATE answers directory must contain exactly the copied review-queue CSV")
        raw = read_private_bundle_item(fd, history.QUEUE, LIMIT)
    finally:
        os.close(fd)
    try:
        parsed = list(csv.reader(StringIO(raw.decode("utf-8"), newline=""),
                                 strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Hold("PRIVATE HUMAN response CSV format invalid") from error
    if not parsed or tuple(parsed[0]) != COLS or len(parsed) != len(expected) + 1:
        raise Hold("PRIVATE HUMAN CSV header or source row count drifted")
    responses = []
    for submitted, source in zip(parsed[1:], expected):
        if len(submitted) != len(COLS):
            raise Hold("PRIVATE HUMAN CSV row shape changed")
        keys = (
            str(source["from_ordinal"]), str(source["to_ordinal"]),
            source["change"],
            str(source["before_slot"]) if source["before_slot"] is not None else "",
            str(source["after_slot"]) if source["after_slot"] is not None else "",
        )
        if tuple(submitted[:5]) != keys:
            raise Hold("PRIVATE HUMAN CSV literal source ordinal row changed")
        if submitted[5] not in STAGES:
            raise Hold("PRIVATE HUMAN stage outside fixed non-authorizing vocabulary")
        responses.append({
            **{field: source[field] for field in COLS[:5]},
            "human_stage": submitted[5],
        })
    return absolute, raw, responses


def render_html(packet):
    style_hash = base64.b64encode(sha256(STYLE.encode()).digest()).decode("ascii")
    rows = []
    for row in packet["responses"]:
        cells = (
            str(row["from_ordinal"]) + " → " + str(row["to_ordinal"]),
            row["change"],
            str(row["before_slot"]) if row["before_slot"] is not None else "—",
            str(row["after_slot"]) if row["after_slot"] is not None else "—",
            row["human_stage"],
        )
        rows.append("<tr>" + "".join("<td>" + escape(item) + "</td>"
                                      for item in cells) + "</tr>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'none'; style-src 'sha256-" + style_hash +
        "'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN manifest response</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE HUMAN lab-plan review return</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY."
        " Every stage below is an unsigned, local HUMAN note."
        " Even HUMAN_REVIEWED never approves an assessment or release.</p>"
        "<p>" + str(packet["row_count"]) + " changed ordinal slots across " +
        str(packet["plan_count"]) + " operator-ordered plans.</p>"
        "<table><thead><tr><th>Plan pair</th><th>Literal change</th>"
        "<th>Before slot</th><th>After slot</th><th>HUMAN stage</th></tr>"
        "</thead><tbody>" + "".join(rows) + "</tbody></table>"
        "<p><small>PRIVATE data: never upload this report as proof of source authenticity,"
        " risk, a fixed issue, client or operator consent, action-time revocation,"
        " independent review or HUMAN GO. No URL, filename, path or source digest"
        " appears in this HTML. No network requests, target contact or scanning.</small>"
        "</p></body></html>"
    ).encode("utf-8")


def render_counts(packet):
    sink = StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(("human_stage", "count"))
    for stage in STAGES:
        writer.writerow((stage, packet["stage_counts"][stage]))
    return sink.getvalue().encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review a saved PRIVATE lab history with local HUMAN stage edits only.")
    parser.add_argument("--plan-dir", action="append", default=[], required=True,
                        help="each original saved PRIVATE combined plan, in exact history order")
    parser.add_argument("--history-dir", required=True, help="original exact PRIVATE 4-file history bundle")
    parser.add_argument("--answers-dir", required=True, help="separate owner-private 0700 directory with one edited 0600 queue CSV")
    dest = parser.add_mutually_exclusive_group(required=True)
    dest.add_argument("--output-dir", help="new separate empty PRIVATE 0700 result directory")
    dest.add_argument("--verify-output-dir", help="exact read-only reopen")
    parser.add_argument("--explain-hold", action="store_true", help="curated HOLD only; never source values")
    args = parser.parse_args(argv)
    try:
        verify_args = [part for path in args.plan_dir for part in ("--plan-dir", path)]
        verify_args += ["--verify-output-dir", args.history_dir]
        if history.main(verify_args) != 0:
            raise Hold("original saved PRIVATE plan history no longer matches exact source")
        plans, source_packet = history.prepare(args.plan_dir)
        source_fd, history_abs = open_output_directory(args.history_dir)
        try:
            history_bytes = read_private_bundle_item(source_fd, history.SUMMARY, LIMIT)
        finally:
            os.close(source_fd)
        answers_abs, answers_raw, responses = admit_answers(
            args.answers_dir, source_packet["human_review_queue"])
        stages = Counter(row["human_stage"] for row in responses)
        packet = {
            "schema": "lightup.private-manifest-history-human-return.v1",
            "status": "REVIEW_ONLY",
            "history_sha256": sha256(history_bytes).hexdigest(),
            "answers_sha256": sha256(answers_raw).hexdigest(),
            "plan_count": source_packet["plan_count"],
            "row_count": len(responses),
            "responses": responses,
            "stage_counts": {stage: stages[stage] for stage in STAGES},
            "source_authenticated": False, "authorized": False,
            "client_consent_verified": False, "operator_consent_verified": False,
            "revocation_checked": False, "human_go": False,
            "assessment_executed": False, "release_allowed": False,
        }
        files = {
            RESPONSE: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            HTML: render_html(packet),
            COUNTS: render_counts(packet),
        }
        if any(not 0 < len(value) <= LIMIT for value in files.values()):
            raise Hold("PRIVATE HUMAN return exceeds output bound")
        fd, output = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            for source in [*(item[0] for item in plans), history_abs, answers_abs]:
                shared = os.path.commonpath((source, output))
                if shared in (source, output):
                    raise Hold("PRIVATE HUMAN return output must be separate from all source trees")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(files):
                    raise Hold("saved PRIVATE HUMAN return contains missing or extra files")
                for name, value in files.items():
                    if read_private_bundle_item(fd, name, LIMIT) != value:
                        raise Hold("saved PRIVATE HUMAN return drifted from current exact sources")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE HUMAN return output directory must be empty")
                # Reopen exact sources immediately before publishing an unsigned HUMAN return.
                for (source, raw, _), path in zip(plans, args.plan_dir):
                    reopened, current, _ = history.admit_saved_bundle(path)
                    if reopened != source or current != raw:
                        raise Hold("original PRIVATE plan changed before HUMAN return publication")
                _, answer_now, _ = admit_answers(args.answers_dir, source_packet["human_review_queue"])
                if answer_now != answers_raw:
                    raise Hold("PRIVATE HUMAN edits changed before return publication")
                if history.main(verify_args) != 0:
                    raise Hold("original PRIVATE history changed before HUMAN return publication")
                history_check_fd, _ = open_output_directory(args.history_dir)
                try:
                    if read_private_bundle_item(history_check_fd, history.SUMMARY, LIMIT) != history_bytes:
                        raise Hold("original PRIVATE history receipt changed before HUMAN return publication")
                finally:
                    os.close(history_check_fd)
                publish_bundle(fd, list(files.items()))
        finally:
            os.close(fd)
        print(("HUMAN_HISTORY_RETURN_REOPENED" if args.verify_output_dir else
               "HUMAN_HISTORY_RETURN_CREATED") + " · rows=" + str(len(responses)) +
              " · REVIEW_ONLY; no findings, authorization, scans or HUMAN GO")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HISTORY_HUMAN_HOLD — source or HUMAN stage not admitted",
                    error, args.explain_hold)
    except Exception:
        report_hold("PRIVATE_HISTORY_HUMAN_HOLD — private input or filesystem rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
