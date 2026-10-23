#!/usr/bin/env python3
"""Compare two PRIVATE source-bound HUMAN manifest-change returns without target access."""
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

import manifest_change_response as human
from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold

SUMMARY = "lightup-private-manifest-human-rounds.json"
HTML = "lightup-private-manifest-human-rounds.html"
CSV = "lightup-private-manifest-human-rounds-changed.csv"
LIMIT = 65536
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;"
    "padding:1rem;color:#172639}.hold{padding:1rem;background:#fff3df;"
    "border-left:5px solid #986b11}table{border-collapse:collapse;width:100%}"
    "th,td{padding:.6rem;border:1px solid #c5d0dd;text-align:left}"
    "th{background:#e9f2fa}small{color:#536176}"
)


def reopen_sources(args, answer_dir, return_dir):
    cli = [
        "--before-dir", args.before_dir,
        "--after-dir", args.after_dir,
        "--change-dir", args.change_dir,
        "--answers-dir", answer_dir,
        "--verify-output-dir", return_dir,
    ]
    if human.main(cli) != 0:
        raise Hold("an original HUMAN return no longer matches its exact source")
    fd, path = open_output_directory(return_dir)
    try:
        raw = read_private_bundle_item(fd, human.RETURN_JSON, LIMIT)
    finally:
        os.close(fd)
    # All JSON bytes have just been independently reproduced byte-for-byte
    # against the source and answer files by the original HUMAN receiver.
    packet = json.loads(raw.decode("utf-8"))
    return path, raw, packet


def compare_rounds(first, second, first_raw, second_raw):
    shared = (
        "source_before_sha256", "source_after_sha256",
        "delta_json_sha256", "delta_csv_sha256", "response_count",
    )
    if any(first.get(field) != second.get(field) for field in shared):
        raise Hold("HUMAN rounds do not refer to the same original PRIVATE delta")
    early, late = first["responses"], second["responses"]
    if len(early) != len(late):
        raise Hold("HUMAN round row counts differ")
    transitions = []
    counts = Counter()
    for ordinal, (old, new) in enumerate(zip(early, late), start=1):
        identity = ("change_state", "before_slot", "after_slot")
        if any(old.get(key) != new.get(key) for key in identity):
            raise Hold("HUMAN round original ordinal identity changed")
        former, current = old["human_follow_up"], new["human_follow_up"]
        if former not in human.STAGES or current not in human.STAGES:
            raise Hold("unknown HUMAN review stage in saved return")
        if former == current:
            continue
        counts[(former, current)] += 1
        transitions.append({
            "original_row": ordinal,
            "change_state": old["change_state"],
            "before_slot": old["before_slot"],
            "after_slot": old["after_slot"],
            "previous_human_stage": former,
            "current_human_stage": current,
        })
    return {
        "schema": "lightup.private-manifest-human-round-delta.v1",
        "status": "REVIEW_ONLY",
        **{key: first[key] for key in shared},
        "first_return_sha256": sha256(first_raw).hexdigest(),
        "second_return_sha256": sha256(second_raw).hexdigest(),
        "previous_human_stage_counts": first["human_stage_counts"],
        "current_human_stage_counts": second["human_stage_counts"],
        "changed_rows": len(transitions),
        "unchanged_rows": len(early) - len(transitions),
        "stage_transitions": [
            {"from": old, "to": new, "count": counts[(old, new)]}
            for old in human.STAGES for new in human.STAGES if counts[(old, new)]
        ],
        "changed_original_rows": transitions,
        "source_authenticated": False,
        "client_identity_verified": False,
        "operator_identity_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "revocation_checked": False,
        "human_go": False,
        "authorized": False,
        "assessment_executed": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }


def render_html(packet):
    digest = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    lines = []
    for row in packet["changed_original_rows"]:
        before = "—" if row["before_slot"] is None else str(row["before_slot"])
        after = "—" if row["after_slot"] is None else str(row["after_slot"])
        cells = (str(row["original_row"]), row["change_state"], before, after,
                 row["previous_human_stage"], row["current_human_stage"])
        lines.append("<tr>" + "".join("<td>" + escape(value) + "</td>"
                                         for value in cells) + "</tr>")
    rows = "".join(lines) if lines else "<tr><td colspan='6'>No HUMAN stage changes</td></tr>"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'none'; style-src 'sha256-" + digest + "';"
        " connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN progress comparison</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE HUMAN review changes</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY."
        " Review status is not permission, a finding, a remediation verdict or HUMAN GO.</p>"
        "<p>Compared two separately saved HUMAN returns against the same original"
        " offline manifest delta. " + str(packet["changed_rows"]) +
        " rows changed; " + str(packet["unchanged_rows"]) + " retained their stage."
        " Operator-selected order is not an authenticated chronology.</p>"
        "<table><thead><tr><th>Original row</th><th>Manifest change</th>"
        "<th>Before slot</th><th>After slot</th><th>Earlier HUMAN stage</th>"
        "<th>Later HUMAN stage</th></tr></thead><tbody>" + rows + "</tbody></table>"
        "<p><small>Only original ordinals and non-authorizing HUMAN labels appear"
        " here. Original endpoint URLs, paths, filenames and digests are not embedded."
        " Unsigned local SHA-256 checks do not verify origin, actual client/operator"
        " consent, action-time revocation, independent review, or HUMAN GO."
        " No network, scans, scripts or target contact.</small></p></body></html>"
    ).encode("utf-8")


def render_csv(packet):
    out = StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    cols = ("original_row", "change_state", "before_slot", "after_slot",
            "previous_human_stage", "current_human_stage")
    writer.writerow(cols)
    for row in packet["changed_original_rows"]:
        writer.writerow(row[key] if row[key] is not None else "" for key in cols)
    return out.getvalue().encode("ascii")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare original PRIVATE HUMAN review returns offline.")
    parser.add_argument("--before-dir", required=True, help="original PRIVATE combined manifest")
    parser.add_argument("--after-dir", required=True, help="original PRIVATE updated manifest")
    parser.add_argument("--change-dir", required=True, help="saved PRIVATE change desk")
    parser.add_argument("--first-answers-dir", required=True, help="original first HUMAN answers")
    parser.add_argument("--first-return-dir", required=True, help="saved first HUMAN return")
    parser.add_argument("--second-answers-dir", required=True, help="original later HUMAN answers")
    parser.add_argument("--second-return-dir", required=True, help="saved later HUMAN return")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="new separate empty PRIVATE 0700 output")
    destination.add_argument("--verify-output-dir", help="read-only source-bound exact reopen")
    parser.add_argument("--explain-hold", action="store_true", help="curated reason only; no source values")
    args = parser.parse_args(argv)
    try:
        first_abs, first_raw, first = reopen_sources(
            args, args.first_answers_dir, args.first_return_dir)
        second_abs, second_raw, second = reopen_sources(
            args, args.second_answers_dir, args.second_return_dir)
        protected = (args.before_dir, args.after_dir, args.change_dir,
                     args.first_answers_dir, args.second_answers_dir,
                     first_abs, second_abs)
        output_fd, output_abs = open_output_directory(
            args.output_dir or args.verify_output_dir)
        try:
            absolute_paths = [os.path.abspath(item) for item in protected]
            if len(set(absolute_paths)) != len(absolute_paths):
                raise Hold("original HUMAN source and return paths must be distinct")
            for source in absolute_paths:
                if human.same_tree(source, output_abs):
                    raise Hold("PRIVATE round result output must not overlap source trees")
            packet = compare_rounds(first, second, first_raw, second_raw)
            files = {
                SUMMARY: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                HTML: render_html(packet),
                CSV: render_csv(packet),
            }
            if any(not 0 < len(raw) <= LIMIT for raw in files.values()):
                raise Hold("PRIVATE HUMAN round comparison exceeds byte limit")
            if args.verify_output_dir:
                if set(os.listdir(output_fd)) != set(files):
                    raise Hold("saved PRIVATE HUMAN comparison has missing or extra files")
                for name, expected in files.items():
                    if read_private_bundle_item(output_fd, name, LIMIT) != expected:
                        raise Hold("saved HUMAN round comparison drifted from original source bytes")
            else:
                if os.listdir(output_fd):
                    raise Hold("PRIVATE HUMAN rounds output must be empty")
                # Reopen BOTH original source-bound returns just before committing output.
                again_first_abs, again_first_raw, again_first = reopen_sources(
                    args, args.first_answers_dir, args.first_return_dir)
                again_second_abs, again_second_raw, again_second = reopen_sources(
                    args, args.second_answers_dir, args.second_return_dir)
                if (again_first_abs != first_abs or again_second_abs != second_abs
                        or again_first_raw != first_raw or again_second_raw != second_raw
                        or again_first != first or again_second != second):
                    raise Hold("original PRIVATE source or HUMAN return changed before publication")
                publish_bundle(output_fd, list(files.items()))
        finally:
            os.close(output_fd)
        print(("MANIFEST_HUMAN_ROUNDS_REOPENED" if args.verify_output_dir
               else "MANIFEST_HUMAN_ROUNDS_CREATED") +
              " · changed_rows=" + str(packet["changed_rows"]) +
              " · unchanged_rows=" + str(packet["unchanged_rows"]) +
              " · REVIEW_ONLY; no assessment, grant, consent or HUMAN GO")
        return 0
    except Hold as exc:
        report_hold("PRIVATE_MANIFEST_ROUNDS_HOLD — source-bound HUMAN comparison rejected",
                    exc, args.explain_hold)
    except Exception:
        report_hold("PRIVATE_MANIFEST_ROUNDS_HOLD — private filesystem or parsing rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
