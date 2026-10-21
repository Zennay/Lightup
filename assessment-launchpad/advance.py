#!/usr/bin/env python3
"""One-command source-bound PRIVATE HUMAN next-round workroom.

This only packages human review changes. It never authorizes/executes a scan,
contacts an endpoint, runs the displayed preview or touches previous source.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from html import escape
import os
import sys

from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item
from review_desk import (
    FILE_NAMES as REVIEW_FILES, load_json, make_artifacts,
    read_original_bundle, require_private_file, validate_worksheet,
)
from editor import NAME as EDITOR_FILE, render_editor
from routing import FILES as ROUTING_FILES, create_artifacts as routing_artifacts
from compare_review import NAMES as DELTA_FILES, make_artifacts as delta_artifacts, read_round
from workspace import private_child
from history import output_artifacts as history_artifacts

ROUND = "human-round"
EDITOR = "human-editor"
ROUTING = "human-routing"
DELTA = "human-changes"
HISTORY = "human-history"
GUIDE = "START-HERE-PRIVATE.txt"
HOME = "OPEN-NEXT-ROUND-PRIVATE.html"
SUBDIRS = (ROUND, EDITOR, ROUTING, DELTA, HISTORY)
STYLE = ("body{font:16px/1.55 system-ui,sans-serif;color:#17212f;"
         "max-width:950px;margin:2rem auto;padding:0 1rem;background:#f2f5f9}"
         ".hold{background:#fff4e7;border-left:6px solid #9a5b18;padding:1rem;font-weight:750}"
         "section{background:white;padding:1rem;border:1px solid #d9e2ed;"
         "border-radius:.6rem;margin:1rem 0}a{color:#184a84;font-weight:750}"
         "a:focus-visible{outline:3px solid #dbad43;outline-offset:3px}"
         "small{color:#465467}")

def render_home(source_count, changed, history_count):
    h = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'sha256-" + h +
        "'; script-src 'none'; connect-src 'none'; img-src 'none';"
        " object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp PRIVATE HUMAN next round</title><style>" + STYLE +
        "</style></head><body><h1>Private HUMAN follow-up workroom</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "
        "NO AUTHORIZATION, SCAN OR RELEASE</p><p>" + str(source_count) +
        " original source-bound HUMAN slots; " + str(changed) +
        " changed self-reported slot(s) compared to a manually selected "
        "previous HUMAN round. This is not verified chronology, consent, "
        "scope or remediation.</p>"
        "<section><h2>Updated PRIVATE HUMAN round</h2>"
        "<a href='human-round/lightup-lab-human-private.html'>Open local HUMAN notes</a>"
        "<p><small>Contains original endpoint URL values and HUMAN note text; "
        "never host or share.</small></p></section>"
        "<section><h2>Edit another HUMAN round</h2>"
        "<a href='human-editor/lightup-lab-human-editor.html'>Open source-bound editor</a>"
        "<p><small>Downloads a revised PRIVATE JSON proposal. "
        "Native re-admission remains mandatory.</small></p></section>"
        "<section><h2>Role-specific HUMAN inbox</h2>"
        "<a href='human-routing/lightup-lab-human-routing-private.html'>"
        "Open local role routing</a></section>"
        "<section><h2>View " + str(history_count) + " manually ordered HUMAN rounds</h2>"
        "<a href='human-history/lightup-lab-human-history-private.html'>"
        "Open PRIVATE source-bound HUMAN round history</a>"
        "<p><small>The operator selects the sequence. It is not authenticated chronology; "
        "this PRIVATE view contains original endpoints and all HUMAN notes.</small></p></section>"
        "<section><h2>Compare previous and current HUMAN planning</h2>"
        "<a href='human-changes/lightup-lab-human-delta-private.html'>"
        "Open source-free HUMAN delta</a><p><small>"
        "No endpoint values, source hashes or actual HUMAN notes embedded."
        "</small></p></section>"
        "<p><small>Read START-HERE-PRIVATE.txt. Neither the source identity "
        "nor authentic client/operator authority, revocation, actual security "
        "review or HUMAN GO is established by this local workroom.</small>"
        "</p></body></html>"
    ).encode("utf-8")

def guide(count, changed, history_count):
    return (
        "LightUp offline PRIVATE HUMAN next-round workroom\n"
        "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED\n"
        "Original source-bound HUMAN slots: " + str(count) + "\n"
        "Human self-report slot changes: " + str(changed) + "\n"
        "Manually selected HUMAN round count: " + str(history_count) + "\n"
        "Prior vs current order is operator-selected and not authenticated time.\n"
        "OPEN-NEXT-ROUND-PRIVATE.html is the scriptless local navigation page.\n"
        "human-round: updated private source-bound HUMAN worksheet/HTML/counts.\n"
        "human-editor: source-bound local browser editor of that worksheet.\n"
        "human-routing: PRIVATE role/stage queue and source-free counts.\n"
        "human-changes: source-free HUMAN ordinal change HTML and counts.\n"
        "human-history: PRIVATE manually ordered 2–8 HUMAN rounds and source-free counts.\n"
        "All outputs are owner-only, unsigned, private, not client approval.\n"
        "To edit another round, download private JSON from the offline editor, "
        "put it in an owner-only mode-0700 folder and chmod 600, then use "
        "advance.py again with this workroom's human-round as --previous-round-dir "
        "and a DIFFERENT empty output directory.\n"
        "Original lab/CI/security/privacy/source-owner/real consent "
        "with action-time revocation/HUMAN GO are independent mandatory gates.\n"
    ).encode("utf-8")

def content_for(before, after, endpoints, earlier):
    return {
        ROUND: dict(make_artifacts(after, endpoints)),
        EDITOR: {EDITOR_FILE: render_editor(after)},
        ROUTING: dict(routing_artifacts(after, endpoints, "ALL", "ALL")),
        DELTA: dict(delta_artifacts(before, after)),
        HISTORY: dict(history_artifacts([*earlier, before, after], endpoints)),
    }

def inspect_root(fd, root_path, before, endpoints, after, earlier):
    if set(os.listdir(fd)) != {*SUBDIRS, GUIDE, HOME}:
        raise Hold("follow-up workroom missing canonical inventory")
    expected = content_for(before, after, endpoints, earlier)
    for dirname in SUBDIRS:
        folder_fd, _ = open_output_directory(os.path.join(root_path, dirname))
        try:
            actual = {name: read_private_bundle_item(folder_fd, name, 196608)
                      for name in expected[dirname]}
        finally:
            os.close(folder_fd)
        if actual != expected[dirname]:
            raise Hold("follow-up workroom file changed or source mismatch")
    changes = sum(a != b for a, b in zip(before["human_rows"], after["human_rows"]))
    count = len(earlier) + 2
    if (read_private_bundle_item(fd, HOME, 32768) != render_home(len(endpoints), changes, count)
            or read_private_bundle_item(fd, GUIDE, 16384) != guide(len(endpoints), changes, count)):
        raise Hold("follow-up workroom navigation changed")
    return changes

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Bundle one PRIVATE HUMAN follow-up round with role and delta review.")
    parser.add_argument("--bundle-dir", required=True, help="original private Launchpad packet")
    parser.add_argument("--previous-round-dir", required=True,
                        help="independently admitted immediately preceding HUMAN round")
    parser.add_argument("--earlier-round-dir", action="append", default=[],
                        help="optional older HUMAN rounds, oldest first, up to six; not authenticated chronology")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output-dir", help="new EMPTY current-user-owned 0700 root")
    target.add_argument("--verify-workroom-dir", help="read-only reopen exact current workroom")
    parser.add_argument("--responses", help="new owner-only mode-0600 HUMAN JSON (creation only)")
    args = parser.parse_args(argv)
    try:
        if bool(args.responses) != bool(args.output_dir):
            raise Hold("new private HUMAN JSON required for creation, not for reopen")
        original, endpoints, digest = read_original_bundle(args.bundle_dir)
        previous_dir, before = read_round(args.previous_round_dir, digest, endpoints)
        if len(args.earlier_round_dir) > 6:
            raise Hold("max eight HUMAN rounds including updated and previous rounds")
        earlier_dirs, earlier_rounds, seen = [], [], {previous_dir}
        for old_path in args.earlier_round_dir:
            old_dir, old_round = read_round(old_path, digest, endpoints)
            if old_dir in seen:
                raise Hold("a HUMAN round cannot appear twice in the history")
            seen.add(old_dir)
            earlier_dirs.append(old_dir)
            earlier_rounds.append(old_round)
        root_fd, root_path = open_output_directory(args.output_dir or args.verify_workroom_dir)
        try:
            for source in (original, previous_dir, *earlier_dirs):
                if os.path.commonpath((source, root_path)) in (source, root_path):
                    raise Hold("next-round output must be separate from original inputs")
            if args.output_dir:
                response_parent = os.path.dirname(os.path.abspath(os.fspath(args.responses)))
                if os.path.commonpath((response_parent, root_path)) in (response_parent, root_path):
                    raise Hold("new HUMAN response source must be in a separate private directory")
                after = load_json(require_private_file(args.responses))
                validate_worksheet(after, digest, len(endpoints))
                if os.listdir(root_fd):
                    raise Hold("next-round output root must be empty")
                renewed, renewed_endpoints, renewed_digest = read_original_bundle(args.bundle_dir)
                renewed_previous, renewed_before = read_round(
                    args.previous_round_dir, renewed_digest, renewed_endpoints)
                renewed_earlier = [read_round(old_path, renewed_digest, renewed_endpoints)
                                   for old_path in args.earlier_round_dir]
                if renewed_earlier != list(zip(earlier_dirs, earlier_rounds)):
                    raise Hold("older HUMAN rounds changed before publication")
                again = load_json(require_private_file(args.responses))
                validate_worksheet(again, renewed_digest, len(renewed_endpoints))
                if ((renewed, renewed_endpoints, renewed_digest, renewed_previous, renewed_before, again)
                        != (original, endpoints, digest, previous_dir, before, after)):
                    raise Hold("previous HUMAN or original source changed before publication")
                for name in SUBDIRS:
                    private_child(root_fd, name)
                expected = content_for(before, after, endpoints, earlier_rounds)
                for dirname in SUBDIRS:
                    fd, _ = open_output_directory(os.path.join(root_path, dirname))
                    try:
                        publish_bundle(fd, list(expected[dirname].items()))
                    finally:
                        os.close(fd)
                changed = sum(a != b for a, b in zip(before["human_rows"], after["human_rows"]))
                publish_bundle(root_fd, [
                    (GUIDE, guide(len(endpoints), changed, len(earlier_rounds) + 2)),
                    (HOME, render_home(len(endpoints), changed, len(earlier_rounds) + 2)),
                ])
            else:
                fd, _ = open_output_directory(os.path.join(root_path, ROUND))
                try:
                    source = read_private_bundle_item(fd, REVIEW_FILES[0], 65536)
                finally:
                    os.close(fd)
                after = load_json(source)
                validate_worksheet(after, digest, len(endpoints))
            changed = inspect_root(root_fd, root_path, before, endpoints, after, earlier_rounds)
        finally:
            os.close(root_fd)
        print("PRIVATE_HUMAN_NEXT_ROUND_" +
              ("CREATED" if args.output_dir else "REOPENED") +
              " human_changed_slots=" + str(changed) +
              " — REVIEW_ONLY; NOT AUTHORIZED; NO TARGET ACTIVITY")
        return 0
    except (Hold, OSError, ValueError, TypeError, UnicodeError, ImportError,
            OverflowError, EOFError, KeyboardInterrupt):
        print("PRIVATE_HUMAN_NEXT_ROUND_HOLD — original or HUMAN inputs not admitted; "
              "partial output is not valid", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
