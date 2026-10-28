#!/usr/bin/env python3
"""Offline PRIVATE multi-version manifest timeline. Never executes an assessment."""
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
    Hold, open_output_directory, publish_bundle, read_private_bundle_item,
    report_hold,
)
from manifest_change_desk import admit_saved_bundle

JSON_NAME = "lightup-private-manifest-timeline.json"
HTML_NAME = "lightup-private-manifest-timeline.html"
CSV_NAME = "lightup-private-manifest-timeline.csv"
MAX_SOURCES = 8
MAX_ITEM_BYTES = 65_536
TRANSITIONS = ("ADDED", "REMOVED", "MOVED", "UNCHANGED", "ABSENT")
AUTHORITY_FLAGS = (
    "source_authenticated", "chronology_authenticated",
    "client_identity_verified", "operator_identity_verified",
    "client_consent_verified", "operator_consent_verified",
    "revocation_checked", "authorized", "human_go",
    "assessment_executed", "target_contact", "dispatch_allowed",
    "release_allowed",
)
STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:1120px;margin:2rem auto;"
    "padding:1rem;color:#172639}h1{font-size:1.8rem}"
    ".hold{background:#fff2d8;border-left:5px solid #96610d;padding:1rem}"
    "table{width:100%;border-collapse:collapse;margin:1rem 0}"
    "th,td{border:1px solid #bdcbdc;padding:.45rem;text-align:center}"
    "th{background:#eef3fa}small{color:#4f5c6d}"
)


def same_tree(first: str, second: str) -> bool:
    try:
        shared = os.path.commonpath((first, second))
    except ValueError:
        return False
    return shared in (first, second)


def admit_sources(paths: list[str]):
    """Re-admit 2–8 original source bundles through the existing pinned scope gate."""
    if not 2 <= len(paths) <= MAX_SOURCES:
        raise Hold("source timeline requires 2–8 original PRIVATE manifest bundles")
    # Reject repeated inputs before opening any private source. The admitted
    # canonical paths below remain the authoritative overlap check.
    if len(set(paths)) != len(paths):
        raise Hold("source timeline directories must be distinct")
    admitted = [admit_saved_bundle(path) for path in paths]
    absolute = [item[0] for item in admitted]
    if len(set(absolute)) != len(absolute):
        raise Hold("source timeline directories must be distinct")
    for index, first in enumerate(absolute):
        for second in absolute[index + 1:]:
            if same_tree(first, second):
                raise Hold("source timeline directories must not overlap")
    return admitted


def build_packet(admitted, compare_from=None, compare_to=None):
    """Create an operator-ordered source timeline without publishing endpoint values."""
    snapshot_count = len(admitted)
    if not 2 <= snapshot_count <= MAX_SOURCES:
        raise Hold("source timeline requires 2–8 original PRIVATE manifest bundles")
    if (compare_from is None) != (compare_to is None):
        raise Hold("select both interval snapshot ordinals or neither")
    if compare_from is None:
        compare_from, compare_to = 1, snapshot_count
    if (type(compare_from) is not int or type(compare_to) is not int
            or not 1 <= compare_from < compare_to <= snapshot_count):
        raise Hold("selected interval must be two ordered snapshot ordinals")
    source_rows = []
    positions = []
    ordered_endpoints = []
    seen = set()

    for ordinal, (_path, raw_manifest, endpoints) in enumerate(admitted, start=1):
        # Direct callers must not bypass the source admission contract: avoid
        # silently treating malformed endpoint collections as a valid timeline.
        if (not isinstance(endpoints, list) or
                any(type(value) is not str or not value for value in endpoints)):
            raise Hold("original PRIVATE manifest has invalid endpoint identities")
        if len(set(endpoints)) != len(endpoints):
            raise Hold("original PRIVATE manifest contains duplicate endpoint identities")
        position = {value: slot for slot, value in enumerate(endpoints, start=1)}
        positions.append(position)
        for value in endpoints:
            if value not in seen:
                seen.add(value)
                ordered_endpoints.append(value)
        source_rows.append({
            "snapshot": ordinal,
            "manifest_sha256": sha256(raw_manifest).hexdigest(),
            "endpoint_count": len(endpoints),
        })

    timeline_rows = []
    interval_counts = {state: 0 for state in TRANSITIONS}
    transition_totals = []
    for snapshot_index in range(1, len(admitted)):
        counts = {state: 0 for state in TRANSITIONS}
        transition_totals.append({
            "from_snapshot": snapshot_index,
            "to_snapshot": snapshot_index + 1,
            "counts": counts,
        })

    for timeline_ordinal, endpoint in enumerate(ordered_endpoints, start=1):
        slots = [position.get(endpoint) for position in positions]
        present = [index for index, slot in enumerate(slots, start=1) if slot is not None]
        states = []
        for index in range(1, len(slots)):
            previous, current = slots[index - 1], slots[index]
            if previous is None and current is None:
                state = "ABSENT"
            elif previous is None:
                state = "ADDED"
            elif current is None:
                state = "REMOVED"
            elif previous == current:
                state = "UNCHANGED"
            else:
                state = "MOVED"
            states.append(state)
            transition_totals[index - 1]["counts"][state] += 1
        interval_before = slots[compare_from - 1]
        interval_after = slots[compare_to - 1]
        if interval_before is None and interval_after is None:
            interval_state = "ABSENT"
        elif interval_before is None:
            interval_state = "ADDED"
        elif interval_after is None:
            interval_state = "REMOVED"
        elif interval_before == interval_after:
            interval_state = "UNCHANGED"
        else:
            interval_state = "MOVED"
        interval_counts[interval_state] += 1
        timeline_rows.append({
            "timeline_row": timeline_ordinal,
            "first_seen_snapshot": present[0],
            "last_seen_snapshot": present[-1],
            "snapshot_slots": slots,
            "transitions": states,
            "interval_state": interval_state,
        })

    return {
        "schema": "lightup.private-manifest-source-timeline.v2",
        "status": "REVIEW_ONLY",
        "order_is_operator_supplied": True,
        "snapshot_count": len(admitted),
        "selected_interval": {
            "from_snapshot": compare_from,
            "to_snapshot": compare_to,
            "counts": interval_counts,
        },
        "unique_endpoint_count": len(ordered_endpoints),
        "snapshot_endpoint_counts": [len(item[2]) for item in admitted],
        "snapshots": source_rows,
        "transition_totals": transition_totals,
        "timeline_rows": timeline_rows,
        "endpoint_values_embedded": False,
        "source_paths_embedded": False,
        **{flag: False for flag in AUTHORITY_FLAGS},
    }


def render_html(packet):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    snapshot_count = packet["snapshot_count"]
    snapshot_headers = "".join(
        "<th>Snapshot " + str(index) + " slot</th>"
        for index in range(1, snapshot_count + 1)
    )
    transition_headers = "".join(
        "<th>" + str(index) + "→" + str(index + 1) + "</th>"
        for index in range(1, snapshot_count)
    )
    rows = []
    for item in packet["timeline_rows"]:
        slots = "".join(
            "<td>" + ("—" if slot is None else str(slot)) + "</td>"
            for slot in item["snapshot_slots"]
        )
        states = "".join("<td>" + escape(state) + "</td>" for state in item["transitions"])
        rows.append(
            "<tr><td>" + str(item["timeline_row"]) + "</td><td>" +
            str(item["first_seen_snapshot"]) + "</td><td>" +
            str(item["last_seen_snapshot"]) + "</td><td>" +
            escape(item["interval_state"]) + "</td>" + slots + states + "</tr>"
        )
    summary_rows = []
    for item in packet["transition_totals"]:
        counts = item["counts"]
        summary_rows.append(
            "<tr><td>" + str(item["from_snapshot"]) + "→" +
            str(item["to_snapshot"]) + "</td>" +
            "".join("<td>" + str(counts[state]) + "</td>" for state in TRANSITIONS) +
            "</tr>"
        )
    interval_counts = packet["selected_interval"]["counts"]
    interval_summary_rows = "".join(
        "<tr><td>" + state + "</td><td>" + str(interval_counts[state]) + "</td></tr>"
        for state in TRANSITIONS
    )
    source_counts = " · ".join(
        "Snapshot " + str(index) + ": " + str(count) + " endpoints"
        for index, count in enumerate(packet["snapshot_endpoint_counts"], start=1)
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " script-src 'none'; style-src 'sha256-" + style_hash + "';"
        " connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE manifest timeline</title><style>" + STYLE +
        "</style></head><body><h1>PRIVATE manifest source timeline</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY · NO AUTHORITY</p>"
        "<p>Compared " + str(snapshot_count) + " saved PRIVATE manifest bundles in "
        "the operator-supplied order. That order is not authenticated chronology. "
        "The net interval is Snapshot " + str(packet["selected_interval"]["from_snapshot"]) +
        "→" + str(packet["selected_interval"]["to_snapshot"]) +
        "; intermediate transitions remain visible below. "
        "Literal endpoint equality and slot movement are descriptive only: absence "
        "does not prove remediation and addition does not establish a finding.</p>"
        "<p>" + escape(source_counts) + "</p>"
        "<h2>Per-endpoint ordinal timeline</h2>"
        "<p>Endpoint values, paths and source digests are deliberately omitted from "
        "this HTML. Each row is a local timeline ordinal; slots are local positions.</p>"
        "<table><thead><tr><th>Timeline row</th><th>First seen</th><th>Last seen</th>"
        "<th>Net interval state</th>" + snapshot_headers + transition_headers + "</tr></thead><tbody>" +
        "".join(rows) + "</tbody></table>"
        "<h2>Transition totals</h2><table><thead><tr><th>Snapshot pair</th>" +
        "".join("<th>" + state + "</th>" for state in TRANSITIONS) +
        "</tr></thead><tbody>" + "".join(summary_rows) + "</tbody></table>"
        "<h2>Selected interval totals</h2><table><thead><tr><th>Net state</th><th>Count</th></tr></thead>"
        "<tbody>" + interval_summary_rows + "</tbody></table>"
        "<p><a href='" + CSV_NAME + "'>Download PRIVATE ordinal timeline CSV</a></p>"
        "<p><small>Local unsigned consistency only. Source authenticity, chronology, "
        "client/operator identity and consent, action-time revocation, independent "
        "review and explicit HUMAN GO remain unverified. This page contains no "
        "scripts, external assets or network requests.</small></p>"
        "</body></html>"
    ).encode("utf-8")


def render_csv(packet):
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    header = [
        "timeline_row", "interval_from_snapshot", "interval_to_snapshot",
        "first_seen_snapshot", "last_seen_snapshot", "interval_state",
        *("snapshot_" + str(index) + "_slot"
          for index in range(1, packet["snapshot_count"] + 1)),
        *("transition_" + str(index) + "_to_" + str(index + 1)
          for index in range(1, packet["snapshot_count"])),
    ]
    writer.writerow(header)
    for item in packet["timeline_rows"]:
        writer.writerow([
            item["timeline_row"], packet["selected_interval"]["from_snapshot"],
            packet["selected_interval"]["to_snapshot"], item["first_seen_snapshot"],
            item["last_seen_snapshot"], item["interval_state"],
            *("" if slot is None else slot for slot in item["snapshot_slots"]),
            *item["transitions"],
        ])
    return output.getvalue().encode("ascii")


def build_outputs(packet):
    contents = {
        JSON_NAME: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        HTML_NAME: render_html(packet),
        CSV_NAME: render_csv(packet),
    }
    if any(not 0 < len(data) <= MAX_ITEM_BYTES for data in contents.values()):
        raise Hold("PRIVATE source timeline exceeds its output byte bound")
    return contents


def render_preview(packet):
    """Return aggregate-only preview text; never expose source identity or open output paths."""
    interval = packet["selected_interval"]
    lines = [
        "MANIFEST_TIMELINE_PREVIEW · REVIEW_ONLY",
        "snapshots=" + str(packet["snapshot_count"]),
        "unique_endpoints=" + str(packet["unique_endpoint_count"]),
        "selected_interval=" + str(interval["from_snapshot"]) + "->" + str(interval["to_snapshot"]),
    ]
    for ordinal, count in enumerate(packet["snapshot_endpoint_counts"], start=1):
        lines.append("snapshot_" + str(ordinal) + "_endpoint_count=" + str(count))
    for item in packet["transition_totals"]:
        counts = item["counts"]
        lines.append(
            "transition_" + str(item["from_snapshot"]) + "_to_" + str(item["to_snapshot"]) + " " +
            " ".join(state.lower() + "=" + str(counts[state]) for state in TRANSITIONS)
        )
    lines.append(
        "selected_interval_counts " +
        " ".join(state.lower() + "=" + str(interval["counts"][state]) for state in TRANSITIONS)
    )
    lines.append("authority=NONE · no assessment, target contact, grant, dispatch or release")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare 2–8 saved PRIVATE lab manifest bundles as an offline ordinal timeline."
    )
    parser.add_argument(
        "--source-dir", action="append", required=True,
        help="existing original-policy-admitted PRIVATE manifest bundle; repeat 2–8 times in operator order",
    )
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output-dir", help="new empty owner-private 0700 output directory")
    destination.add_argument("--verify-output-dir", help="read-only exact reopen of a saved timeline")
    destination.add_argument(
        "--preview-only", action="store_true",
        help="print bounded aggregate counts only; never open or write an output directory",
    )
    parser.add_argument("--compare-from-snapshot", type=int,
                        help="optional one-based start ordinal for net interval comparison")
    parser.add_argument("--compare-to-snapshot", type=int,
                        help="optional one-based end ordinal; must be later than the start")
    parser.add_argument(
        "--explain-hold", action="store_true",
        help="show curated HOLD reasons without source URLs, endpoint values or paths",
    )
    args = parser.parse_args(argv)
    try:
        if (args.compare_from_snapshot is None) != (args.compare_to_snapshot is None):
            raise Hold("select both interval snapshot ordinals or neither")
        admitted = admit_sources(args.source_dir)
        packet = build_packet(admitted, args.compare_from_snapshot, args.compare_to_snapshot)
        if args.preview_only:
            print(render_preview(packet))
            return 0
        contents = build_outputs(packet)
        output_path = args.output_dir or args.verify_output_dir
        output_fd, output_abs = open_output_directory(output_path)
        try:
            for source_path, _raw, _endpoints in admitted:
                if same_tree(output_abs, source_path):
                    raise Hold("PRIVATE timeline output must be separate from all source trees")
            if args.verify_output_dir:
                if set(os.listdir(output_fd)) != set(contents):
                    raise Hold("saved PRIVATE timeline has missing or unexpected files")
                for name, expected in contents.items():
                    if read_private_bundle_item(output_fd, name, MAX_ITEM_BYTES) != expected:
                        raise Hold("saved PRIVATE timeline differs from current source bytes")
            else:
                if os.listdir(output_fd):
                    raise Hold("PRIVATE timeline output directory must be empty")
                # Re-admit every original bundle at the publication boundary.
                current = admit_sources(args.source_dir)
                if current != admitted:
                    raise Hold("original PRIVATE source bundles changed before publication")
                publish_bundle(output_fd, list(contents.items()))
        finally:
            os.close(output_fd)
        print(
            ("MANIFEST_TIMELINE_REOPENED" if args.verify_output_dir else "MANIFEST_TIMELINE_CREATED") +
            " · snapshots=" + str(packet["snapshot_count"]) +
            " · unique_endpoints=" + str(packet["unique_endpoint_count"]) +
            " · net_interval=" + str(packet["selected_interval"]["from_snapshot"]) +
            "→" + str(packet["selected_interval"]["to_snapshot"]) +
            " · REVIEW_ONLY; no assessment, authorization or target contact"
        )
        return 0
    except Hold as error:
        report_hold(
            "PRIVATE_MANIFEST_TIMELINE_HOLD — original private source or output not admitted",
            error, args.explain_hold,
        )
    except Exception:
        report_hold(
            "PRIVATE_MANIFEST_TIMELINE_HOLD — private parsing or filesystem error",
            None, args.explain_hold,
        )
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
