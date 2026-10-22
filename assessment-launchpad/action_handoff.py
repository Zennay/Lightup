#!/usr/bin/env python3
"""Offline, source-bound PRIVATE HUMAN selected-action handoff (never authority)."""
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

from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from history import admitted_rounds
from review_desk import read_original_bundle, ROLES
from role_return_reconcile import admitted_replies, render_files

WORK_CSV = "lightup-lab-human-role-worklist-private.csv"
PRIVATE_CSV = "lightup-lab-human-selected-actions-private.csv"
PRIVATE_HTML = "lightup-lab-human-selected-actions-private.html"
PRIVATE_SUMMARY = "lightup-lab-human-selected-actions-counts-private.json"
GUIDE = "START-HERE-SELECTED-HUMAN-ACTIONS-PRIVATE.txt"
FILES = (PRIVATE_CSV, PRIVATE_HTML, PRIVATE_SUMMARY, GUIDE)
LIMIT = 65536
HEADER = (
    "original_slot", "latest_suggested_role", "private_human_reply_status",
    "latest_self_reported_human_stage", "suggested_operator_next_step",
    "private_note_changed",
)
STYLE = (
    "body{font:15px/1.5 system-ui,sans-serif;color:#193148;"
    "max-width:1100px;margin:2rem auto;padding:1rem;background:#f3f6fa}"
    "h1{font-size:2rem}.hold{background:#fff1dd;padding:1rem;"
    "border-left:5px solid #985917;font-weight:750}"
    "table{border-collapse:collapse;width:100%;background:white}"
    ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.8rem}"
    ".summary section{background:white;border:1px solid #c4d3e2;border-radius:.4rem;padding:.6rem}"
    ".summary h2{font-size:1rem}.summary ul{padding-left:1.2rem}"
    "th,td{padding:.7rem;border:1px solid #c4d3e2;text-align:left}"
    "th{background:#e5effb}.tablewrap{overflow-x:auto}"
    "@media(max-width:700px){table{min-width:920px}}"
)

def read_selected(path):
    absolute = os.path.abspath(path)
    filename = os.path.basename(absolute)
    if filename in ("", ".", "..") or filename != os.path.basename(path):
        raise Hold("selected HUMAN CSV path is not canonical")
    directory_fd, folder = open_output_directory(os.path.dirname(absolute))
    try:
        raw = read_private_bundle_item(directory_fd, filename, 8192)
    finally:
        os.close(directory_fd)
    return folder, raw


def parse_csv(raw):
    try:
        data = raw.decode("utf-8", errors="strict")
        # Browser exports canonical CRLF and a fixed six-cell CSV schema.
        if not data or not data.endswith("\r\n") or "\ufeff" in data:
            raise Hold("noncanonical PRIVATE selected HUMAN CSV encoding")
        rows = list(csv.reader(io.StringIO(data, newline=""), strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Hold("invalid PRIVATE selected HUMAN CSV") from error
    if len(rows) < 2 or len(rows) > 17 or tuple(rows[0]) != HEADER:
        raise Hold("PRIVATE selected HUMAN CSV header or row count mismatch")
    if any(len(row) != len(HEADER) for row in rows[1:]):
        raise Hold("PRIVATE selected HUMAN CSV has an invalid row")
    return [tuple(row) for row in rows[1:]]


def canonical_selection(rows):
    # No escaping is required: all values must match the original enum/ordinal
    # worklist exactly. This output is never confused with a source grant.
    return ("\r\n".join([",".join(HEADER)] + [",".join(row) for row in rows])
            + "\r\n").encode("utf-8")


def selected_source_rows(source_csv, selection_raw):
    source = list(csv.reader(io.StringIO(source_csv.decode("utf-8"), newline=""), strict=True))
    if not source or tuple(source[0]) != HEADER:
        raise Hold("original source worklist schema drift")
    known = {tuple(row): index for index, row in enumerate(source[1:])}
    if len(known) != len(source) - 1:
        raise Hold("original worklist has duplicate rows")
    chosen = parse_csv(selection_raw)
    positions = [known.get(row) for row in chosen]
    if any(index is None for index in positions) or positions != sorted(set(positions)):
        raise Hold("PRIVATE HUMAN selection is not a unique ordered original subset")
    if canonical_selection(chosen) != selection_raw:
        raise Hold("PRIVATE HUMAN selection bytes are not canonical")
    return chosen, len(source) - 1


def render_artifacts(rows, total, role_filter="ALL", all_role_selected_count=None):
    body = "".join("<tr>" + "".join(
        "<td>" + escape(item.replace("_", " ")) + "</td>" for item in row
    ) + "</tr>" for row in rows)
    dimensions = (("Suggested roles", 1), ("Original reply status", 2),
                  ("Self-reported HUMAN stage", 3), ("Suggested HUMAN next action", 4),
                  ("PRIVATE note changed", 5))
    dimension_counts = {
        label: {value: sum(row[index] == value for row in rows)
                for value in sorted({row[index] for row in rows})}
        for label, index in dimensions
    }
    summary_html = "<div class='summary'>" + "".join(
        "<section><h2>" + escape(label) + "</h2><ul>" + "".join(
            "<li>" + escape(value.replace("_", " ")) + ": <strong>" + str(count)
            + "</strong></li>" for value, count in counts.items()
        ) + "</ul></section>" for label, counts in dimension_counts.items()
    ) + "</div>"
    scope = {
        "schema": "lightup.assessment_launchpad_private_human_selected_actions.v1",
        "status": "REVIEW_ONLY",
        "original_local_slot_count": total,
        "selected_local_slot_count": len(rows),
        "unselected_local_slot_count": total - len(rows),
        "selected_action_counts": dimension_counts,
        "identity_authenticated": False,
        "source_authority_authenticated": False,
        "client_operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "human_go": False,
        "release_allowed": False,
    }
    if role_filter != "ALL":
        if (all_role_selected_count is None or
                not len(rows) <= all_role_selected_count <= total):
            raise Hold("role-only handoff needs consistent all-role selection counts")
        scope["unselected_local_slot_count"] = total - len(rows)
        scope.update({
            "operator_role_filter": role_filter,
            "selected_local_slot_count_all_roles": all_role_selected_count,
            "selected_other_role_count": all_role_selected_count - len(rows),
            "unselected_local_slot_count_all_roles": total - all_role_selected_count,
            "role_filter_applied_after_full_source_admission": True,
            "role_filter_verifies_recipient_identity": False,
        })
    role_message = (" Operator-selected proposed role filter: " +
                    escape(role_filter.replace("_", " ")) + ". " +
                    str(all_role_selected_count - len(rows)) +
                    " selected rows from other roles are omitted; this is not a verified role assignment.") if role_filter != "ALL" else ""
    selection_message = (str(len(rows)) + " of " + str(total) +
                         " original local source slots deliberately selected.")
    if role_filter != "ALL":
        selection_message = (str(len(rows)) + " selected rows in this proposed role; " +
            str(all_role_selected_count) + " selected across all roles; " +
            str(total - all_role_selected_count) + " unselected across all roles, out of " +
            str(total) + " original local source slots.")
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + style_hash
        + "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
        + "frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'\">"
        + "<title>LightUp PRIVATE selected HUMAN action handoff</title><style>"
        + STYLE + "</style></head><body><h1>PRIVATE selected HUMAN action handoff</h1>"
        + "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        + "REVIEW_ONLY · NO AUTHORIZATION</p><p>"
        + selection_message + " "
        + "Original slot order is a worklist order, not verified event chronology. "
        + "Roles and statuses are unauthenticated HUMAN self-reports."
        + role_message + "</p>"
        + "<p>No target URLs, note text, source path, source digests or recipient "
        + "identities are embedded. Role/slot combinations can remain identifying. "
        + "Treat every generated file as unencrypted PRIVATE data.</p>"
        + summary_html
        + "<div class='tablewrap'><table><thead><tr>"
        + "".join("<th>" + escape(name.replace("_", " ")) + "</th>" for name in HEADER)
        + "</tr></thead><tbody>" + body + "</tbody></table></div>"
        + "<p>Source consistency is an unsigned local check, NOT proof of "
        + "reviewer identity, client/operator consent, action-time revocation, "
        + "assessment permission, remediation, dispatch, release or HUMAN GO.</p>"
        + "</body></html>"
    ).encode("utf-8")
    guide = (
        "LIGHTUP SELECTED PRIVATE HUMAN ACTIONS — REVIEW_ONLY\n"
        "SOURCE-BOUND UNSIGNED LOCAL CONSISTENCY, NOT SOURCE AUTHENTICATION\n"
        "This handoff includes only operator-selected local ordinal/enumeration rows.\n"
        "It is PRIVATE unencrypted data; verify recipients independently.\n"
        "The selected CSV was admitted against original HUMAN role returns.\n"
        + ("Optional proposed-role filtering never authenticates a recipient.\n"
           if role_filter != "ALL" else "")
        + "No endpoint URL, PRIVATE note, client asset or source digest is copied.\n"
        "Reopen with the same original bundle, rounds, returns and CSV bytes.\n"
        "No assessment, grant, consent, release or HUMAN GO is performed.\n"
    ).encode("utf-8")
    return dict(zip(FILES, (
        canonical_selection(rows), html,
        (json.dumps(scope, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        guide,
    )))


def admit_all(args):
    bundle, endpoints, digest = read_original_bundle(args.bundle_dir)
    round_dirs, rounds = admitted_rounds(args.round_dir, digest, endpoints)
    replies = admitted_replies(args.role_return_dir, rounds, endpoints, digest)
    original_work = render_files(replies, rounds, endpoints)[WORK_CSV]
    selected_folder, selected_bytes = read_selected(args.selected_csv)
    selection, total = selected_source_rows(original_work, selected_bytes)
    # Include original decoded source/round/return objects and scope digest in
    # the publication-time stability snapshot, not just the output selection.
    return (bundle, tuple(round_dirs), tuple(row[0] for row in replies),
            selected_folder, selected_bytes, selection, total,
            digest, tuple(endpoints), rounds, replies)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline PRIVATE original-source-bound selected HUMAN action handoff")
    parser.add_argument("--bundle-dir", required=True,
                        help="original source-pinned five-file PRIVATE Launchpad packet")
    parser.add_argument("--round-dir", action="append", required=True,
                        help="original PRIVATE HUMAN round; repeat 2-8 in operator-selected order")
    parser.add_argument("--role-return-dir", action="append", required=True,
                        help="original selected-role return packet; repeat 1-5")
    parser.add_argument("--selected-csv", required=True,
                        help="browser-exported CSV; owner-only 0700 parent, file mode 0600")
    parser.add_argument("--suggested-role", choices=ROLES,
                        help="optional recipient-minimal original suggested HUMAN role only")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir",
                      help="new empty owner-owned mode-0700 destination, separate from every source")
    mode.add_argument("--verify-output-dir",
                      help="existing PRIVATE packet; exact read-only reopen, writes nothing")
    mode.add_argument("--preview-only", action="store_true",
                      help="admit all original sources and selected CSV, show counts, create no files")
    parser.add_argument("--explain-hold", action="store_true", help="print curated HOLD reason; raw paths, endpoint values and exceptions stay hidden")
    args = parser.parse_args(argv)
    try:
        source = admit_all(args)
        all_role_selected_count = len(source[5])
        scoped_rows = [row for row in source[5] if
                       args.suggested_role is None or row[1] == args.suggested_role]
        if not scoped_rows:
            raise Hold("no exact original selected HUMAN slots in chosen suggested role")
        role_filter = args.suggested_role or "ALL"
        artifacts = render_artifacts(scoped_rows, source[6], role_filter,
            all_role_selected_count if args.suggested_role is not None else None)
        selection_status = (str(len(scoped_rows)) + "/" + str(source[6]) +
                            " original slots selected")
        if args.suggested_role is not None:
            selection_status = (str(len(scoped_rows)) + " selected for " +
                args.suggested_role.replace("_", " ") + "; " +
                str(all_role_selected_count) + " selected across all roles; " +
                str(source[6] - all_role_selected_count) + " unselected across all roles")
        if any(not 0 < len(item) <= LIMIT for item in artifacts.values()):
            raise Hold("PRIVATE selected HUMAN handoff capacity exceeded")
        if args.preview_only:
            print("PRIVATE_HUMAN_SELECTED_ACTIONS_PREVIEW_ONLY — " +
                  selection_status + "; no files written; REVIEW_ONLY; NO AUTHORITY")
            preview = json.loads(artifacts[PRIVATE_SUMMARY].decode("utf-8"))
            print("Selected HUMAN dimension counts only (no slot rows, notes, targets or paths):")
            print(json.dumps(preview["selected_action_counts"], sort_keys=True,
                             separators=(",", ":")))
            return 0
        fd, destination = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            # Flatten every source directory explicitly; source[:4] contains
            # tuples as well as paths and would fail before admission can finish.
            source_dirs = [source[0], *source[1], *source[2], source[3]]
            for folder in source_dirs:
                common = os.path.commonpath((folder, destination))
                if common in (folder, destination):
                    raise Hold("PRIVATE handoff destination overlaps original source")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(FILES) or any(
                    read_private_bundle_item(fd, name, LIMIT) != artifacts[name]
                    for name in FILES
                ):
                    raise Hold("PRIVATE selected HUMAN output differs from original source")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE selected HUMAN output directory must be empty")
                if source != admit_all(args):
                    raise Hold("original source or selected HUMAN CSV changed")
                publish_bundle(fd, list(artifacts.items()))
        finally:
            os.close(fd)
        print("PRIVATE_HUMAN_SELECTED_ACTIONS_" +
              ("REOPENED" if args.verify_output_dir else "CREATED") +
              " — " + selection_status + "; REVIEW_ONLY; NO AUTHORITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_SELECTED_ACTIONS_HOLD — source or selection rejected", error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, csv.Error, OverflowError):
        report_hold("PRIVATE_HUMAN_SELECTED_ACTIONS_HOLD — source or selection rejected", None, args.explain_hold)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
