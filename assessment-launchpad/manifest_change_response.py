#!/usr/bin/env python3
"""Receive source-bound PRIVATE HUMAN manifest-delta follow-up, offline only.

This records unsigned review stages; it never permits assessment, target contact,
consent, scope grants or release.
"""
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

import manifest_change_desk as delta
from launchpad import (
    Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold,
)

ANSWERS_CSV = "lightup-private-manifest-human-follow-up.csv"
RETURN_JSON = "lightup-private-manifest-human-return.json"
RETURN_HTML = "lightup-private-manifest-human-return.html"
RETURN_COUNTS = "lightup-private-manifest-human-counts.csv"
MAX_BYTES = 65536
MAX_ROWS = 32
SOURCE_COLS = ("change_state", "before_slot", "after_slot", "review_state")
ANSWER_COLS = SOURCE_COLS + ("human_follow_up",)
STAGES = ("NOT_REVIEWED", "REVIEWED", "FOLLOW_UP", "NOT_APPLICABLE")
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;"
    "padding:1rem;color:#182639}h1{font-size:1.8rem}"
    ".hold{background:#fff2d8;border-left:5px solid #96610d;padding:1rem}"
    "table{width:100%;border-collapse:collapse}"
    "th,td{border:1px solid #bdcbdc;padding:.6rem;text-align:left}"
    "th{background:#eef3fa}small{color:#4f5c6d}"
)


def same_tree(first, second):
    shared = os.path.commonpath((first, second))
    return shared in (first, second)


def read_private_file(directory, name, limit):
    fd, absolute = open_output_directory(directory)
    try:
        if set(os.listdir(fd)) != {name}:
            raise Hold("HUMAN intake directory must contain only the expected private CSV")
        raw = read_private_bundle_item(fd, name, limit)
    finally:
        os.close(fd)
    return absolute, raw


def read_source(before_dir, after_dir, change_dir):
    # Reuse the ORIGINAL bounded, policy-admitted manifest comparison and its
    # byte-exact read-only reopen rather than accepting a self-declared CSV.
    if delta.main(["--before-dir", before_dir, "--after-dir", after_dir,
                   "--verify-output-dir", change_dir]) != 0:
        raise Hold("original PRIVATE change desk cannot be reopened")
    before_abs, before_raw, before = delta.admit_saved_bundle(before_dir)
    after_abs, after_raw, after = delta.admit_saved_bundle(after_dir)
    fd, change_abs = open_output_directory(change_dir)
    try:
        delta_json = read_private_bundle_item(fd, delta.DELTA_JSON, delta.OUTPUT_LIMIT)
        native_csv = read_private_bundle_item(fd, delta.DELTA_CSV, delta.OUTPUT_LIMIT)
    finally:
        os.close(fd)
    changes, _ = delta.compare(before, after)
    if not 0 < len(changes) <= MAX_ROWS:
        raise Hold("original manifest delta has no bounded HUMAN review rows")
    packet = {
        "source_before_sha256": sha256(before_raw).hexdigest(),
        "source_after_sha256": sha256(after_raw).hexdigest(),
        "delta_json_sha256": sha256(delta_json).hexdigest(),
        "delta_csv_sha256": sha256(native_csv).hexdigest(),
    }
    return (before_abs, after_abs, change_abs), packet, changes


def source_cells(row):
    return (row["state"],
            "" if row["before_slot"] is None else str(row["before_slot"]),
            "" if row["after_slot"] is None else str(row["after_slot"]),
            "REVIEW_ONLY")


def admit_answers(answers_dir, changes):
    absolute, raw = read_private_file(answers_dir, ANSWERS_CSV, MAX_BYTES)
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff") or "\x00" in text:
            raise Hold("HUMAN CSV contains a forbidden BOM or NUL")
        rows = list(csv.reader(StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error) as exc:
        raise Hold("HUMAN CSV is not strict UTF-8 CSV") from exc
    if (not rows or tuple(rows[0]) != ANSWER_COLS
            or len(rows) != len(changes) + 1):
        raise Hold("HUMAN CSV header or source row count has changed")
    accepted = []
    for answer, original in zip(rows[1:], changes):
        if len(answer) != len(ANSWER_COLS):
            raise Hold("HUMAN CSV row has unexpected columns")
        if tuple(answer[:4]) != source_cells(original):
            raise Hold("HUMAN CSV row no longer matches exact original delta and order")
        if answer[4] not in STAGES:
            raise Hold("unknown or authorizing HUMAN stage is forbidden")
        accepted.append({
            "change_state": original["state"],
            "before_slot": original["before_slot"],
            "after_slot": original["after_slot"],
            "human_follow_up": answer[4],
        })
    return absolute, raw, accepted


def make_packet(source, raw_answers, responses):
    counts = Counter(row["human_follow_up"] for row in responses)
    return {
        "schema": "lightup.private-manifest-human-return.v1",
        "status": "REVIEW_ONLY",
        **source,
        "answers_sha256": sha256(raw_answers).hexdigest(),
        "response_count": len(responses),
        "human_stage_counts": {stage: counts[stage] for stage in STAGES},
        "responses": responses,
        "source_authenticated": False,
        "client_identity_verified": False,
        "operator_identity_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "revocation_checked": False,
        "authorized": False,
        "human_go": False,
        "assessment_executed": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }


def render_html(packet):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    rendered = []
    for item in packet["responses"]:
        cells = (
            item["change_state"],
            "—" if item["before_slot"] is None else str(item["before_slot"]),
            "—" if item["after_slot"] is None else str(item["after_slot"]),
            item["human_follow_up"],
        )
        rendered.append("<tr>" + "".join("<td>" + escape(value) + "</td>"
                                           for value in cells) + "</tr>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'none'; style-src 'sha256-" + style_hash + "'; "
        "connect-src 'none'; img-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN manifest return</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE manifest HUMAN follow-up</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY. "
        "Not an assessment approval, verified scope, finding, fix, client consent or HUMAN GO.</p>"
        "<p>Ordinal-only stages from " + str(packet["response_count"]) +
        " original PRIVATE delta rows. These stages are unsigned HUMAN statements. "
        "The original endpoint URLs and source names are deliberately absent.</p>"
        "<table><thead><tr><th>Change</th><th>Before slot</th>"
        "<th>After slot</th><th>HUMAN stage</th></tr></thead><tbody>" +
        "".join(rendered) + "</tbody></table>"
        "<p><small>Reviewing a row never authorizes scanning. Literal manifest "
        "removal does not prove remediation. Local SHA-256 binding is not authenticated "
        "provenance. Require current separate client/operator consent, action-time "
        "revocation checks, independent review and explicit HUMAN GO for any later "
        "authorized activity. This page contains no scripts or network requests."
        "</small></p></body></html>"
    ).encode("utf-8")


def render_counts(packet):
    sink = StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    writer.writerow(("human_stage", "count"))
    for stage in STAGES:
        writer.writerow((stage, packet["human_stage_counts"][stage]))
    return sink.getvalue().encode("ascii")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Native source-bound PRIVATE HUMAN delta return; offline REVIEW_ONLY.")
    parser.add_argument("--before-dir", required=True, help="original saved PRIVATE before bundle")
    parser.add_argument("--after-dir", required=True, help="original saved PRIVATE after bundle")
    parser.add_argument("--change-dir", required=True, help="reopen original PRIVATE change report")
    parser.add_argument("--answers-dir", required=True,
                        help="separate 0700 directory with a single edited PRIVATE 0600 HUMAN CSV")
    dest = parser.add_mutually_exclusive_group(required=True)
    dest.add_argument("--output-dir", help="separate empty PRIVATE 0700 output directory")
    dest.add_argument("--verify-output-dir", help="exact source-bound read-only reopen")
    parser.add_argument("--explain-hold", action="store_true",
                        help="curated HOLD reasons only; never original source or path values")
    args = parser.parse_args(argv)
    try:
        sources, original_binding, changes = read_source(
            args.before_dir, args.after_dir, args.change_dir)
        answers_abs, raw_answers, responses = admit_answers(args.answers_dir, changes)
        if len(set((*sources, answers_abs))) != 4:
            raise Hold("source and answers directories must be distinct")
        output_fd, output_abs = open_output_directory(
            args.output_dir or args.verify_output_dir)
        try:
            for source in (*sources, answers_abs):
                if same_tree(source, output_abs):
                    raise Hold("HUMAN output must not overlap any original PRIVATE source tree")
            packet = make_packet(original_binding, raw_answers, responses)
            artifacts = {
                RETURN_JSON: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                RETURN_HTML: render_html(packet),
                RETURN_COUNTS: render_counts(packet),
            }
            if any(not 0 < len(raw) <= MAX_BYTES for raw in artifacts.values()):
                raise Hold("PRIVATE HUMAN return exceeds byte bound")
            if args.verify_output_dir:
                if set(os.listdir(output_fd)) != set(artifacts):
                    raise Hold("saved PRIVATE HUMAN return has missing or extra files")
                for name, raw in artifacts.items():
                    if read_private_bundle_item(output_fd, name, MAX_BYTES) != raw:
                        raise Hold("saved HUMAN return drifted from current original PRIVATE sources")
            else:
                if os.listdir(output_fd):
                    raise Hold("private HUMAN return output must be empty")
                # Fail closed if the input artifacts drift before any output is published.
                current_sources, current_binding, current_changes = read_source(
                    args.before_dir, args.after_dir, args.change_dir)
                current_answers_abs, current_raw, current_rows = admit_answers(
                    args.answers_dir, current_changes)
                if (current_sources != sources or current_binding != original_binding
                        or current_answers_abs != answers_abs or current_raw != raw_answers
                        or current_rows != responses):
                    raise Hold("original PRIVATE source or HUMAN edits changed before publication")
                publish_bundle(output_fd, list(artifacts.items()))
        finally:
            os.close(output_fd)
        print(("MANIFEST_HUMAN_RETURN_REOPENED" if args.verify_output_dir
               else "MANIFEST_HUMAN_RETURN_CREATED")
              + " · original_rows=" + str(len(responses))
              + " · REVIEW_ONLY; no assessment, authority, consent or target contact")
        return 0
    except Hold as exc:
        report_hold("PRIVATE_MANIFEST_HUMAN_HOLD — original source or HUMAN return rejected",
                    exc, args.explain_hold)
    except Exception:
        report_hold("PRIVATE_MANIFEST_HUMAN_HOLD — private parsing or filesystem rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
