#!/usr/bin/env python3
"""Compare two saved PRIVATE HUMAN stage returns bound to the same original lab-plan history."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from hashlib import sha256
from html import escape
import csv
from io import StringIO
import json
import os
import re

import manifest_history_desk as history
import manifest_history_response as response
from launchpad import (Hold, open_output_directory, publish_bundle,
                       read_private_bundle_item, report_hold, unique_pairs, reject_constant)

LIMIT = 65536
DETAIL = "lightup-human-history-stage-delta-private.json"
HTML = "lightup-human-history-stage-delta-private.html"
CSV = "lightup-human-history-stage-delta-counts-private.csv"
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;color:#162335;max-width:980px;"
    "margin:2rem auto;padding:1rem}.hold{background:#fff3d9;padding:1rem;"
    "border-left:5px solid #936a1b}table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #bac6d3;padding:.65rem;text-align:left}"
    "th{background:#e7eff8}small{color:#526071}"
)
FLAGS = ("source_authenticated", "authorized", "client_consent_verified",
         "operator_consent_verified", "revocation_checked", "human_go",
         "assessment_executed", "release_allowed")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROW_KEYS = ("from_ordinal", "to_ordinal", "change", "before_slot",
            "after_slot", "human_stage")

RESPONSE_FIELDS = frozenset((
    "schema", "status", "history_sha256", "answers_sha256",
    "plan_count", "row_count", "responses", "stage_counts", *FLAGS,
))
CONTINUED_FIELDS = RESPONSE_FIELDS | {
    "previous_return_sha256", "source_continuity_claim",
}


def read_response(path, original, history_bytes):
    fd, absolute = open_output_directory(path)
    try:
        if set(os.listdir(fd)) != {response.RESPONSE, response.HTML, response.COUNTS}:
            raise Hold("PRIVATE HUMAN return contains missing or extra files")
        raw = read_private_bundle_item(fd, response.RESPONSE, LIMIT)
        try:
            packet = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                                parse_constant=reject_constant)
        except (ValueError, UnicodeError, TypeError) as error:
            raise Hold("PRIVATE HUMAN return is not canonical JSON") from error
        if not isinstance(packet, dict):
            raise Hold("PRIVATE HUMAN return is not an object")
        schema = packet.get("schema")
        if schema not in ("lightup.private-manifest-history-human-return.v1",
                          "lightup.private-manifest-history-human-return.v2"):
            raise Hold("unknown PRIVATE HUMAN return schema")
        allowed = CONTINUED_FIELDS if schema.endswith(".v2") else RESPONSE_FIELDS
        if set(packet) != allowed:
            raise Hold("PRIVATE HUMAN return contains unknown, missing or non-schema fields")
        if schema.endswith(".v2"):
            if (not isinstance(packet.get("previous_return_sha256"), str)
                    or not HEX.fullmatch(packet["previous_return_sha256"])
                    or packet.get("source_continuity_claim") != "UNSIGNED_LOCAL_CONSISTENCY_ONLY"):
                raise Hold("continued PRIVATE HUMAN round source reference malformed")
        elif "previous_return_sha256" in packet or "source_continuity_claim" in packet:
            raise Hold("legacy PRIVATE HUMAN return cannot claim a previous round")
        if (packet.get("status") != "REVIEW_ONLY"
                or packet.get("history_sha256") != sha256(history_bytes).hexdigest()
                or packet.get("plan_count") != original["plan_count"]):
            raise Hold("PRIVATE HUMAN return history source binding drifted")
        if any(packet.get(flag) is not False for flag in FLAGS):
            raise Hold("PRIVATE HUMAN return contains prohibited authority assertions")
        if (type(packet.get("row_count")) is not int
                or packet["row_count"] != len(original["human_review_queue"])
                or not isinstance(packet.get("responses"), list)
                or len(packet["responses"]) != packet["row_count"]):
            raise Hold("PRIVATE HUMAN return row inventory drifted")
        if not isinstance(packet.get("answers_sha256"), str) or not HEX.fullmatch(packet["answers_sha256"]):
            raise Hold("PRIVATE HUMAN input digest malformed")
        expected_counts = Counter()
        for index, (actual, source) in enumerate(
                zip(packet["responses"], original["human_review_queue"]), 1):
            if not isinstance(actual, dict) or set(actual) != set(ROW_KEYS):
                raise Hold("PRIVATE HUMAN response row schema rejected")
            for field in ROW_KEYS[:-1]:
                if type(actual[field]) is not type(source[field]) or actual[field] != source[field]:
                    raise Hold("PRIVATE HUMAN original source ordinal or change drifted")
            if actual["human_stage"] not in response.STAGES:
                raise Hold("PRIVATE HUMAN stage vocabulary rejected")
            expected_counts[actual["human_stage"]] += 1
        if packet.get("stage_counts") != {stage: expected_counts[stage] for stage in response.STAGES}:
            raise Hold("PRIVATE HUMAN counts drifted from literal row stages")
        expected_json = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if raw != expected_json:
            raise Hold("PRIVATE HUMAN response JSON is noncanonical")
        if read_private_bundle_item(fd, response.HTML, LIMIT) != response.render_html(packet):
            raise Hold("PRIVATE HUMAN printable response changed")
        if read_private_bundle_item(fd, response.COUNTS, LIMIT) != response.render_counts(packet):
            raise Hold("PRIVATE HUMAN stage counts changed")
        return absolute, packet, sha256(raw).hexdigest()
    finally:
        os.close(fd)


def render_html(packet):
    hashed = base64.b64encode(sha256(STYLE.encode()).digest()).decode("ascii")
    rows = []
    for item in packet["stage_changes"]:
        cells = (str(item["row_ordinal"]), str(item["from_plan"]) + " → " + str(item["to_plan"]),
                 item["literal_change"], item["before_stage"], item["after_stage"])
        rows.append("<tr>" + "".join("<td>" + escape(value) + "</td>" for value in cells) + "</tr>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'none'; style-src 'sha256-" + hashed +
        "'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN round comparison</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE HUMAN stage comparison</h1>"
        "<p class='hold'>INCUBATE M3/M7 · REVIEW_ONLY · NO AUTHORITY."
        " Input ordering is a human convention, not authenticated chronology."
        " A stage transition is never remediation proof, consent or HUMAN GO.</p>"
        "<p>" + str(packet["source_rows"]) + " original changed-slot rows · " +
        str(packet["unchanged_count"]) + " unchanged HUMAN stages · " +
        str(packet["changed_count"]) + " changed HUMAN stages.</p>"
        "<table><thead><tr><th>Original row</th><th>Plan pair</th>"
        "<th>Original literal change</th><th>First HUMAN stage</th>"
        "<th>Second HUMAN stage</th></tr></thead><tbody>" + "".join(rows) +
        "</tbody></table><p><small>Source-bound local unsigned consistency only."
        " No URLs, filenames, paths or original source hashes are included."
        " Authenticity, current client/operator permission, revocation at use,"
        " security/privacy review and explicit HUMAN GO remain mandatory."
        " Keep this local report PRIVATE.</small></p></body></html>"
    ).encode()


def render_csv(packet):
    out = StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("stage", "before_count", "after_count"))
    for stage in response.STAGES:
        writer.writerow((stage, packet["before_stage_counts"][stage],
                         packet["after_stage_counts"][stage]))
    return out.getvalue().encode()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare two original-source-bound PRIVATE HUMAN review rounds; no target action.")
    parser.add_argument("--plan-dir", action="append", default=[], required=True,
                        help="original PRIVATE combined-plan bundle, in exact history order")
    parser.add_argument("--history-dir", required=True, help="original saved PRIVATE 4-file history")
    parser.add_argument("--before-return-dir", required=True, help="first saved PRIVATE HUMAN return")
    parser.add_argument("--after-return-dir", required=True, help="second saved PRIVATE HUMAN return")
    dest = parser.add_mutually_exclusive_group(required=True)
    dest.add_argument("--output-dir", help="new separate empty PRIVATE 0700 comparison directory")
    dest.add_argument("--verify-output-dir", help="read-only exact source-bound reopen")
    parser.add_argument("--explain-hold", action="store_true", help="show curated HOLD, not paths")
    args = parser.parse_args(argv)
    try:
        source_args = [item for p in args.plan_dir for item in ("--plan-dir", p)]
        if history.main(source_args + ["--verify-output-dir", args.history_dir]) != 0:
            raise Hold("saved original PRIVATE history admission failed")
        plans, source = history.prepare(args.plan_dir)
        hf, history_abs = open_output_directory(args.history_dir)
        try:
            original_history = read_private_bundle_item(hf, history.SUMMARY, LIMIT)
        finally:
            os.close(hf)
        before_abs, before, before_sha = read_response(
            args.before_return_dir, source, original_history)
        after_abs, after, after_sha = read_response(
            args.after_return_dir, source, original_history)
        if before_abs == after_abs:
            raise Hold("PRIVATE HUMAN before and after returns must be separate")
        changed = []
        for index, (a, b) in enumerate(zip(before["responses"], after["responses"]), 1):
            if a["human_stage"] != b["human_stage"]:
                changed.append({
                    "row_ordinal": index, "from_plan": a["from_ordinal"],
                    "to_plan": a["to_ordinal"], "literal_change": a["change"],
                    "before_stage": a["human_stage"], "after_stage": b["human_stage"],
                })
        result = {
            "schema": "lightup.private-human-history-stage-delta.v1",
            "status": "REVIEW_ONLY",
            "history_sha256": sha256(original_history).hexdigest(),
            "before_response_sha256": before_sha,
            "after_response_sha256": after_sha,
            "source_rows": before["row_count"],
            "changed_count": len(changed),
            "unchanged_count": before["row_count"] - len(changed),
            "before_stage_counts": before["stage_counts"],
            "after_stage_counts": after["stage_counts"],
            "stage_changes": changed,
            **{flag: False for flag in FLAGS},
        }
        files = {
            DETAIL: (json.dumps(result, sort_keys=True, separators=(",", ":"))+"\n").encode(),
            HTML: render_html(result),
            CSV: render_csv(result),
        }
        if any(not 0 < len(raw) <= LIMIT for raw in files.values()):
            raise Hold("PRIVATE HUMAN stage comparison output too large")
        output_fd, output_abs = open_output_directory(
            args.output_dir or args.verify_output_dir)
        try:
            sources = [*(row[0] for row in plans), history_abs, before_abs, after_abs]
            for source_path in sources:
                shared = os.path.commonpath((source_path, output_abs))
                if shared in (source_path, output_abs):
                    raise Hold("PRIVATE HUMAN stage comparison output must be separate from all input trees")
            if args.verify_output_dir:
                if set(os.listdir(output_fd)) != set(files):
                    raise Hold("PRIVATE HUMAN stage comparison inventory changed")
                for name, expected in files.items():
                    if read_private_bundle_item(output_fd, name, LIMIT) != expected:
                        raise Hold("PRIVATE HUMAN stage comparison drifted")
            else:
                if os.listdir(output_fd):
                    raise Hold("PRIVATE HUMAN stage comparison directory must be empty")
                # Source admission must still hold immediately before publishing.
                if history.main(source_args + ["--verify-output-dir", args.history_dir]) != 0:
                    raise Hold("original PRIVATE history drifted before comparison publication")
                if read_response(args.before_return_dir, source, original_history)[2] != before_sha:
                    raise Hold("first PRIVATE HUMAN return drifted before publication")
                if read_response(args.after_return_dir, source, original_history)[2] != after_sha:
                    raise Hold("second PRIVATE HUMAN return drifted before publication")
                publish_bundle(output_fd, list(files.items()))
        finally:
            os.close(output_fd)
        print(("HUMAN_STAGE_DELTA_REOPENED" if args.verify_output_dir else
               "HUMAN_STAGE_DELTA_CREATED") + " · changed=" + str(len(changed)) +
              " · original_rows=" + str(before["row_count"]) +
              " · REVIEW_ONLY; no consent, remediation proof or authorization")
        return 0
    except Hold as error:
        report_hold("HUMAN_STAGE_DELTA_HOLD — PRIVATE sources or outputs not admitted",
                    error, args.explain_hold)
    except Exception:
        report_hold("HUMAN_STAGE_DELTA_HOLD — private input or filesystem rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
