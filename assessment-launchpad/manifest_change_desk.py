#!/usr/bin/env python3
"""PRIVATE, source-minimal offline comparison of two saved canonical lab manifest bundles."""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
import json
import os
import io
import stat
from html import escape

from combine_manifest import (
    BOARD, FILES, MANIFEST, SLOT_MAP, SUMMARY, canonical_lines,
)
from launchpad import (
    Hold, MAX_ENDPOINTS, MAX_MANIFEST_BYTES, open_output_directory,
    publish_bundle, read_private_bundle_item, reject_constant, report_hold,
    unique_pairs, validate_endpoints,
)
from source_board import render_board, slot_map_csv

DELTA_JSON = "lightup-private-manifest-delta.json"
DELTA_HTML = "lightup-private-manifest-delta.html"
DELTA_CSV = "lightup-private-manifest-delta.csv"
DELTA_EDITOR = "manifest_change_review.html"
OUTPUT_LIMIT = 32768

def read_review_editor():
    """Read the adjacent pinned offline editor as a bounded stable regular file."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DELTA_EDITOR)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= OUTPUT_LIMIT:
            raise Hold("offline HUMAN follow-up editor is not a bounded regular file")
        data = bytearray()
        while len(data) <= OUTPUT_LIMIT:
            chunk = os.read(fd, min(4096, OUTPUT_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (len(data) != before.st_size or after.st_size != before.st_size
                or after.st_ino != before.st_ino or after.st_mtime_ns != before.st_mtime_ns):
            raise Hold("offline HUMAN follow-up editor changed while being read")
        return bytes(data)
    finally:
        os.close(fd)



STYLE = ("body{font:16px/1.5 system-ui,sans-serif;color:#17212f;"
         "max-width:950px;margin:2rem auto;padding:1rem}"
         ".hold{border-left:5px solid #94600c;background:#fff5de;padding:1rem}"
         "table{border-collapse:collapse;width:100%}"
         "th,td{padding:.6rem;border:1px solid #cbd5e1;text-align:left}"
         "th{background:#e9f1fb}small{color:#59677a}a{color:#18467b;font-weight:750}")


def admit_saved_bundle(path):
    """Reconstruct local output consistency, not source-authenticity or client authority."""
    fd, absolute = open_output_directory(path)
    try:
        available = set(os.listdir(fd))
        raw_receipt = read_private_bundle_item(fd, SUMMARY, FILES[SUMMARY])
        try:
            receipt = json.loads(raw_receipt.decode("utf-8"), object_pairs_hook=unique_pairs,
                                 parse_constant=reject_constant)
        except (UnicodeError, ValueError, TypeError) as error:
            raise Hold("saved PRIVATE receipt is not canonical JSON") from error
        if not isinstance(receipt, dict):
            raise Hold("saved PRIVATE receipt schema rejected")
        canonical_receipt = (
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if raw_receipt != canonical_receipt:
            raise Hold("saved PRIVATE receipt is not byte-canonical JSON")
        schema = receipt.get("schema")
        if schema == "lightup.offline-manifest-combine.v1":
            admitted_sets = ({MANIFEST, SUMMARY},)
        elif schema == "lightup.offline-manifest-combine.v2":
            admitted_sets = ({MANIFEST, SUMMARY, BOARD},
                             {MANIFEST, SUMMARY, BOARD, SLOT_MAP})
        elif schema == "lightup.offline-manifest-combine.v3":
            admitted_sets = ({MANIFEST, SUMMARY, BOARD, SLOT_MAP},)
        else:
            raise Hold("unknown saved manifest schema")
        if available not in admitted_sets:
            raise Hold("saved PRIVATE bundle is incomplete or has unexpected files")
        if (receipt.get("status") != "REVIEW_ONLY" or
                receipt.get("original_policy_checked") is not True or
                receipt.get("mode") not in ("append", "replace") or
                any(receipt.get(key) is not False for key in (
                    "authorized", "consent_verified", "dispatch_allowed",
                    "release_allowed", "human_go", "client_identity_verified",
                    "operator_identity_verified"))):
            raise Hold("saved manifest claims prohibited authority")
        raw_manifest = read_private_bundle_item(fd, MANIFEST, MAX_MANIFEST_BYTES)
        try:
            lines = raw_manifest.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise Hold("saved manifest has invalid UTF-8") from error
        if (not 1 <= len(lines) <= MAX_ENDPOINTS or len(set(lines)) != len(lines)
                or canonical_lines(lines) != raw_manifest):
            raise Hold("saved PRIVATE manifest must be canonical and bounded")
        if len(validate_endpoints(lines)) != len(lines):
            raise Hold("saved original lab scope admission failed")
        if receipt.get("result_manifest_sha256") != sha256(raw_manifest).hexdigest():
            raise Hold("saved manifest no longer matches unsigned output digest")
        counts = receipt.get("counts")
        if not isinstance(counts, dict) or counts.get("result_endpoints") != len(lines):
            raise Hold("saved source counts differ from manifest")
        for name in (BOARD, SLOT_MAP):
            if name in available:
                expected = render_board(receipt) if name == BOARD else slot_map_csv(receipt)
                if read_private_bundle_item(fd, name, FILES[name]) != expected:
                    raise Hold("saved PRIVATE source board or slot map drifted")
        return absolute, raw_manifest, lines
    finally:
        os.close(fd)


def compare(before, after):
    before_positions = {value: idx + 1 for idx, value in enumerate(before)}
    after_positions = {value: idx + 1 for idx, value in enumerate(after)}
    changes = []
    totals = dict(UNCHANGED=0, MOVED=0, REMOVED=0, ADDED=0)
    for index, value in enumerate(before, 1):
        next_index = after_positions.get(value)
        state = ("REMOVED" if next_index is None else
                 "UNCHANGED" if index == next_index else "MOVED")
        totals[state] += 1
        changes.append({"state": state, "before_slot": index, "after_slot": next_index})
    for index, value in enumerate(after, 1):
        if value not in before_positions:
            totals["ADDED"] += 1
            changes.append({"state": "ADDED", "before_slot": None, "after_slot": index})
    return changes, totals


def render_html(packet, *, include_editor=True):
    hash_value = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    rows = []
    for item in packet["changes"]:
        first = str(item["before_slot"]) if item["before_slot"] is not None else "—"
        last = str(item["after_slot"]) if item["after_slot"] is not None else "—"
        rows.append("<tr><td>" + escape(item["state"]) + "</td><td>" + first +
                    "</td><td>" + last + "</td></tr>")
    editor_link = (
        "<p><a href='manifest_change_review.html'>Open the offline HUMAN follow-up editor</a> "
        "and import the PRIVATE ordinal change CSV.</p>"
        if include_editor else ""
    )
    totals = packet["totals"]
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "script-src 'none'; style-src 'sha256-" + hash_value +
            "'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none';"
            " form-action 'none'\">"
            "<title>LightUp PRIVATE manifest change desk</title><style>" + STYLE +
            "</style></head><body><h1>PRIVATE lab manifest change desk</h1>"
            "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY ·"
            " NO ASSESSMENT OR CLIENT AUTHORITY</p>"
            "<p>Manual before/after order, not authenticated chronology. Literal URL"
            " equality only; movement is not a new finding and absence is not a fix.</p>"
            "<p>Before: " + str(packet["before_count"]) + " · After: " +
            str(packet["after_count"]) + " · Unchanged: " + str(totals["UNCHANGED"]) +
            " · Moved: " + str(totals["MOVED"]) + " · Removed: " +
            str(totals["REMOVED"]) + " · Added: " + str(totals["ADDED"]) + "</p>"
            "<table><thead><tr><th>Literal change</th><th>Before slot</th>"
            "<th>After slot</th></tr></thead><tbody>" + "".join(rows) +
            "</tbody></table><p><a href='lightup-private-manifest-delta.csv'>"
            "Download PRIVATE ordinal change CSV</a></p>" + editor_link +
            "<p><small>PRIVATE, unsigned local consistency only."
            " No endpoint URLs, notes, filenames or original source paths are embedded."
            " The source bundles are not independently authenticated. Client/operator"
            " consent, scope approval, revocation and HUMAN GO remain required.</small>"
            "</p></body></html>")
    return html.encode("utf-8")


def render_csv(packet):
    """Ordinal-only portable change ledger; never export endpoint values or source paths."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("change_state", "before_slot", "after_slot", "review_state"))
    for item in packet["changes"]:
        writer.writerow((
            item["state"],
            "" if item["before_slot"] is None else item["before_slot"],
            "" if item["after_slot"] is None else item["after_slot"],
            "REVIEW_ONLY",
        ))
    return output.getvalue().encode("ascii")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare two existing PRIVATE canonical manifests offline; never execute a scan.")
    parser.add_argument("--before-dir", required=True, help="existing owner-private combined source directory")
    parser.add_argument("--after-dir", required=True, help="existing separate owner-private combined source directory")
    parser.add_argument("--output-dir", help="separate empty 0700 private output directory")
    parser.add_argument("--verify-output-dir", help="reopen prior result, without writing")
    parser.add_argument("--explain-hold", action="store_true", help="curated HOLD reason without paths or URLs")
    args = parser.parse_args(argv)
    try:
        if bool(args.output_dir) == bool(args.verify_output_dir):
            raise Hold("choose output publication or exact read-only reopen")
        before_abs, before_raw, before = admit_saved_bundle(args.before_dir)
        after_abs, after_raw, after = admit_saved_bundle(args.after_dir)
        if before_abs == after_abs:
            raise Hold("before and after source directories must be different")
        changes, totals = compare(before, after)
        packet = {
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
        contents = {
            DELTA_JSON: (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            DELTA_HTML: render_html(packet),
            DELTA_CSV: render_csv(packet),
        }
        if any(not 0 < len(data) <= OUTPUT_LIMIT for data in contents.values()):
            raise Hold("private change desk exceeds output bound")
        output = args.output_dir or args.verify_output_dir
        fd, output_abs = open_output_directory(output)
        try:
            for source in (before_abs, after_abs):
                common = os.path.commonpath((output_abs, source))
                if common in (output_abs, source):
                    raise Hold("change output must remain separate from both source directories")
            # Re-admit both source bundles at the output boundary; a manifest
            # changed while the comparison was being prepared must never be published.
            _, latest_before_raw, latest_before = admit_saved_bundle(args.before_dir)
            _, latest_after_raw, latest_after = admit_saved_bundle(args.after_dir)
            if (latest_before_raw != before_raw or latest_after_raw != after_raw
                    or latest_before != before or latest_after != after):
                raise Hold("original private manifest changed during change-desk preparation")
            if args.verify_output_dir:
                found = set(os.listdir(fd))
                current_names = set(contents)
                full_names = current_names | {DELTA_EDITOR}
                legacy_three_names = current_names
                legacy_two_names = current_names - {DELTA_CSV}
                if found not in (full_names, legacy_three_names, legacy_two_names):
                    raise Hold("saved change output has missing or extra files")
                expected = dict(contents)
                if found == full_names:
                    expected[DELTA_EDITOR] = read_review_editor()
                else:
                    # Older two/three-file packets predate the editor link and
                    # remain strictly read-only reopenable byte-for-byte.
                    expected[DELTA_HTML] = render_html(packet, include_editor=False)
                for name in found:
                    if read_private_bundle_item(fd, name, OUTPUT_LIMIT) != expected[name]:
                        raise Hold("source-bound change desk bytes drifted")
            else:
                if os.listdir(fd):
                    raise Hold("change output directory must be empty")
                editor_bytes = read_review_editor()
                contents[DELTA_EDITOR] = editor_bytes
                if any(not 0 < len(data) <= OUTPUT_LIMIT for data in contents.values()):
                    raise Hold("private change desk or editor exceeds output bound")
                # Re-admit the exact editor bytes immediately before publishing.
                if read_review_editor() != editor_bytes:
                    raise Hold("offline HUMAN follow-up editor changed before publication")
                publish_bundle(fd, list(contents.items()))
        finally:
            os.close(fd)
        print(("MANIFEST_CHANGE_REOPENED" if args.verify_output_dir else
               "MANIFEST_CHANGE_CREATED") + " · before=" + str(len(before)) +
              " after=" + str(len(after)) + " added=" + str(totals["ADDED"]) +
              " removed=" + str(totals["REMOVED"]) + " moved=" + str(totals["MOVED"]) +
              " · PRIVATE ordinal CSV; REVIEW_ONLY; no authorization, scan or target interaction")
        return 0
    except Hold as error:
        report_hold("PRIVATE_MANIFEST_CHANGE_HOLD — original private source or output not admitted", error, args.explain_hold)
    except Exception:
        report_hold("PRIVATE_MANIFEST_CHANGE_HOLD — private parsing or filesystem error", None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
