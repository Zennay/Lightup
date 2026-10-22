#!/usr/bin/env python3
"""Source-bound offline HUMAN handoff desk for an existing LightUp lab Launchpad packet.

Reads only local owner-private files. Never runs the preview command, grants authority,
accesses a target, performs DNS, or changes the original source bundle.
"""
from __future__ import annotations

import argparse
import base64
import getpass
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import sys
import unicodedata

from launchpad import (
    FLAGS, Hold, MAX_MANIFEST_BYTES, open_output_directory, publish_bundle,
    read_private_bundle_item, unique_pairs, reject_constant, verify_existing, report_hold,
)

SCHEMA = "lightup.assessment_launchpad_human_worksheet.v1"
STAGES = ("NEEDS_INPUT", "HUMAN_REVIEW", "FOLLOW_UP")
ROLES = ("UNASSIGNED", "LAB_OPERATOR", "SCOPE_OWNER", "SECURITY_REVIEWER", "PRIVACY_REVIEWER")
STATUS = "REVIEW_ONLY"
FILE_NAMES = (
    "lightup-lab-human-private.json",
    "lightup-lab-human-private.html",
    "lightup-lab-human-counts.json",
    "lightup-lab-human-counts.csv",
)
STYLE = ("body{font:15px/1.55 system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
         "padding:0 1rem;color:#17212f}h1{font-size:1.8rem}.hold{border:2px solid #9a5b18;"
         "background:#fff7ed;padding:1rem;font-weight:750}table{width:100%;border-collapse:collapse}"
         "th,td{padding:.7rem;text-align:left;border:1px solid #cad4df;vertical-align:top}"
         "th{background:#eff3f8}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;"
         "overflow-wrap:anywhere}small{color:#485569}@media print{body{margin:0;max-width:none}}")

def require_private_file(path, limit=32768):
    """Open a regular mode-0600 single-link input under a 0700 owned directory."""
    absolute = os.path.abspath(os.fspath(path))
    name = os.path.basename(absolute)
    if name in ("", ".", ".."):
        raise Hold("invalid PRIVATE worksheet path")
    directory_fd, _ = open_output_directory(os.path.dirname(absolute))
    try:
        return read_private_bundle_item(directory_fd, name, limit)
    finally:
        os.close(directory_fd)

def load_json(raw):
    if b"\x00" in raw or raw.startswith(b"\xef\xbb\xbf"):
        raise Hold("PRIVATE JSON encoding not canonical")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                     parse_constant=reject_constant, parse_float=reject_constant)
    if type(obj) is not dict:
        raise Hold("PRIVATE worksheet must be an object")
    return obj

def validate_worksheet(work, manifest_sha, endpoint_count):
    if set(work) != {"schema", "status", "canonical_manifest_sha256", "source_endpoint_count",
                     "human_rows", *FLAGS}:
        raise Hold("PRIVATE worksheet has unexpected keys")
    if (work["schema"] != SCHEMA or work["status"] != STATUS
            or work["canonical_manifest_sha256"] != manifest_sha
            or type(work["source_endpoint_count"]) is not int
            or work["source_endpoint_count"] != endpoint_count):
        raise Hold("PRIVATE worksheet does not belong to this exact manifest")
    if any(work[key] is not False for key in FLAGS):
        raise Hold("HUMAN worksheet cannot carry affirmative authority")
    rows = work["human_rows"]
    if type(rows) is not list or len(rows) != endpoint_count:
        raise Hold("PRIVATE worksheet slot count differs")
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != {"slot", "stage", "role", "note"}:
            raise Hold("invalid HUMAN row")
        if type(row["slot"]) is not int or row["slot"] != index:
            raise Hold("HUMAN rows must preserve original ordered slots")
        if type(row["stage"]) is not str or row["stage"] not in STAGES:
            raise Hold("HUMAN stage is not an admitted non-authorizing state")
        if type(row["role"]) is not str or row["role"] not in ROLES:
            raise Hold("HUMAN role is outside the fixed vocabulary")
        note = row["note"]
        if (type(note) is not str or len(note) > 400
                or any(unicodedata.category(char).startswith("C") and char not in "\n\t"
                       for char in note)):
            raise Hold("HUMAN note is overlong or contains controls")
    return work

def read_original_bundle(directory):
    # The original five-file bundle and original lab URL/scope pins must be
    # readmitted before anything based on its endpoint content is published.
    if verify_existing(directory) != 0:
        raise Hold("original Launchpad packet could not be reopened")
    fd, absolute = open_output_directory(directory)
    try:
        raw = read_private_bundle_item(fd, "lightup-lab-targets.txt", MAX_MANIFEST_BYTES)
    finally:
        os.close(fd)
    decoded = raw.decode("utf-8")
    endpoints = decoded.splitlines()
    if not endpoints or decoded != "\n".join(endpoints) + "\n":
        raise Hold("original Launchpad manifest not canonical")
    return absolute, endpoints, sha256(raw).hexdigest()

def blank_worksheet(digest, count):
    return {
        "schema": SCHEMA, "status": STATUS,
        "canonical_manifest_sha256": digest, "source_endpoint_count": count,
        "human_rows": [
            {"slot": i, "stage": "NEEDS_INPUT", "role": "UNASSIGNED", "note": ""}
            for i in range(1, count + 1)
        ],
        **{key: False for key in FLAGS},
    }

def counts(work):
    rows = work["human_rows"]
    return {
        "schema": "lightup.assessment_launchpad_human_counts.v1",
        "status": STATUS, "source_reported_endpoint_count": len(rows),
        "human_stage_counts": {key: sum(row["stage"] == key for row in rows) for key in STAGES},
        "human_role_counts": {key: sum(row["role"] == key for row in rows) for key in ROLES},
        "endpoint_values_embedded": False, "source_digest_embedded": False,
        "private_notes_embedded": False, "source_paths_embedded": False,
        "human_self_report_not_authority": True,
        **{key: False for key in FLAGS},
    }

def render_private_html(work, endpoints):
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    rows = []
    for row, endpoint in zip(work["human_rows"], endpoints):
        rows.append("<tr><td>" + str(row["slot"]) + "</td><td><code>" +
                    escape(endpoint) + "</code></td><td>" + escape(row["stage"]) +
                    "</td><td>" + escape(row["role"]) +
                    "</td><td><pre>" + escape(row["note"]) + "</pre></td></tr>")
    result = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-" + style_hash + "'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp private HUMAN launchpad desk</title><style>" + STYLE +
        "</style></head><body><h1>Private isolated-lab HUMAN follow-up</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "REVIEW_ONLY · NOT AUTHORIZED</p>"
        "<p>Original manifest fingerprint (unsigned local consistency only): "
        "<code>" + escape(work["canonical_manifest_sha256"]) + "</code></p>"
        "<p>This PRIVATE handoff shows literal endpoint values and HUMAN notes. "
        "Do not distribute or host it; store as mode 0600. Every entry is a human "
        "self-report, not evidence of a tested endpoint, permission, client consent, "
        "remediation, completed review or HUMAN GO.</p>"
        "<table><thead><tr><th>Slot</th><th>Original local endpoint</th>"
        "<th>HUMAN stage</th><th>Suggested reviewer role</th><th>Private HUMAN note"
        "</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        "<p><small>To update, edit only HUMAN stage/role/note fields in the private "
        "JSON worksheet and use --responses with a NEW empty private output folder. "
        "Original endpoint values are never changed. "
        "The anonymized counts-only outputs exclude these values and all notes. "
        "No network, assessment, command execution, release or authorization occurred."
        "</small></p></body></html>"
    )
    return result.encode("utf-8")

def make_artifacts(work, endpoints):
    summary = counts(work)
    csv_lines = ["category,value,count"]
    csv_lines.extend("stage," + stage + "," + str(summary["human_stage_counts"][stage])
                     for stage in STAGES)
    csv_lines.extend("role," + role + "," + str(summary["human_role_counts"][role])
                     for role in ROLES)
    csv_lines.append("source_reported_endpoint_count,all," + str(len(endpoints)))
    return [
        (FILE_NAMES[0], (json.dumps(work, ensure_ascii=False, indent=2) + "\n").encode("utf-8")),
        (FILE_NAMES[1], render_private_html(work, endpoints)),
        (FILE_NAMES[2], (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8")),
        (FILE_NAMES[3], ("\n".join(csv_lines) + "\n").encode("utf-8")),
    ]


def interactive_review(work):
    """Explicit local terminal HUMAN editing; never prompts for URLs or secrets."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise Hold("HUMAN interactive review requires a private terminal")
    print("PRIVATE HUMAN review: no original endpoint URLs will be printed.")
    print("Use stage 1=NEEDS_INPUT, 2=HUMAN_REVIEW, 3=FOLLOW_UP.")
    print("Use role 1=UNASSIGNED, 2=LAB_OPERATOR, 3=SCOPE_OWNER, "
          "4=SECURITY_REVIEWER, 5=PRIVACY_REVIEWER.")
    print("Press Enter to keep current value. For a note, '-' clears the note.")
    for row in work["human_rows"]:
        print("HUMAN slot " + str(row["slot"]).zfill(2) +
              " — " + row["stage"] + " / " + row["role"] +
              "; private note length " + str(len(row["note"])))
        stage = input("  Stage [1-3 or Enter to keep]: ").strip()
        if stage:
            if stage not in ("1", "2", "3"):
                raise Hold("unrecognized HUMAN stage selection")
            row["stage"] = STAGES[int(stage) - 1]
        role = input("  Reviewer role [1-5 or Enter to keep]: ").strip()
        if role:
            if role not in ("1", "2", "3", "4", "5"):
                raise Hold("unrecognized HUMAN role selection")
            row["role"] = ROLES[int(role) - 1]
        # getpass keeps private notes out of terminal scrollback and shell history.
        note = getpass.getpass("  Private note [Enter=keep, -=clear]: ")
        if note == "-":
            row["note"] = ""
        elif note:
            row["note"] = note
    print("HUMAN draft complete. No scan, approval, grant or release was issued.")
    return work

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Compose or reopen original-source-bound PRIVATE HUMAN follow-up. "
        "Never executes a lab assessment or supplies authorization."))
    parser.add_argument("--bundle-dir", required=True,
                        help="original private five-file Launchpad packet directory")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", help="separate empty mode-0700 directory")
    mode.add_argument("--verify-review-dir", help="read-only verify exact four-file HUMAN handoff")
    parser.add_argument("--responses", help="optional existing owner-private HUMAN worksheet JSON")
    parser.add_argument("--interactive", action="store_true",
                        help="edit admitted HUMAN stage/role/private notes on a local TTY")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        if args.verify_review_dir and (args.responses or args.interactive):
            raise Hold("verification cannot also import amended responses")
        original_dir, endpoints, digest = read_original_bundle(args.bundle_dir)
        output_dir = args.verify_review_dir or args.output_dir
        fd, absolute = open_output_directory(output_dir)
        try:
            if os.path.commonpath((original_dir, absolute)) in (original_dir, absolute):
                raise Hold("HUMAN output directory must be separate from original source bundle")
            if args.verify_review_dir:
                if set(os.listdir(fd)) != set(FILE_NAMES):
                    raise Hold("PRIVATE HUMAN review has unknown or missing files")
                stored = {name: read_private_bundle_item(fd, name, 65536)
                          for name in FILE_NAMES}
                work = load_json(stored[FILE_NAMES[0]])
                validate_worksheet(work, digest, len(endpoints))
                expected = dict(make_artifacts(work, endpoints))
                if stored != expected:
                    raise Hold("HUMAN packet changed or does not match exact source")
            else:
                if os.listdir(fd):
                    raise Hold("new PRIVATE HUMAN review directory must be empty")
                if args.responses:
                    response_parent = os.path.dirname(os.path.abspath(os.fspath(args.responses)))
                    if os.path.commonpath((response_parent, absolute)) in (response_parent, absolute):
                        raise Hold("PRIVATE HUMAN response input must be in a separate directory")
                work = (load_json(require_private_file(args.responses)) if args.responses
                        else blank_worksheet(digest, len(endpoints)))
                validate_worksheet(work, digest, len(endpoints))
                if args.interactive:
                    interactive_review(work)
                    validate_worksheet(work, digest, len(endpoints))
                artifacts = make_artifacts(work, endpoints)
                # HUMAN review can take time; readmit the exact source at publication time.
                renewed_dir, renewed_endpoints, renewed_digest = read_original_bundle(args.bundle_dir)
                if (renewed_dir, renewed_endpoints, renewed_digest) != (original_dir, endpoints, digest):
                    raise Hold("original source packet changed during HUMAN editing")
                publish_bundle(fd, artifacts)
        finally:
            os.close(fd)
        print("HUMAN_LAUNCHPAD_" + ("REOPENED" if args.verify_review_dir else "CREATED") +
              " endpoint_count=" + str(len(endpoints)) +
              " — PRIVATE HUMAN REVIEW ONLY; UNSIGNED; NO AUTHORIZATION OR EXECUTION")
        return 0
    except Hold as error:
        report_hold("HUMAN_LAUNCHPAD_HOLD — original bundle or private human review not admitted",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError,
            OverflowError, EOFError, KeyboardInterrupt):
        report_hold("HUMAN_LAUNCHPAD_HOLD — original bundle or private human review not admitted",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
