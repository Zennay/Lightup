#!/usr/bin/env python3
"""One-command source-bound PRIVATE HUMAN next-round workroom.

This only packages human review changes. It never authorizes/executes a scan,
contacts an endpoint, runs the displayed preview or touches previous source.
"""
from __future__ import annotations

import argparse
import base64
import copy
from hashlib import sha256
from html import escape
import os
import sys

from launchpad import Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold
from review_desk import (
    FILE_NAMES as REVIEW_FILES, ROLES, STAGES, load_json, make_artifacts,
    read_original_bundle, require_private_file, validate_worksheet, interactive_review,
)
from editor import NAME as EDITOR_FILE, render_editor
from routing import FILES as ROUTING_FILES, create_artifacts as routing_artifacts
from compare_review import NAMES as DELTA_FILES, make_artifacts as delta_artifacts, read_round
from workspace import private_child
from history import output_artifacts as history_artifacts
from role_handoff import assemble as handoff_artifacts
from role_return_receipt import combine_returns, handoff_digest
from role_return import selected_template, return_guide, TEMPLATE as RETURN_CSV, GUIDE as RETURN_GUIDE
from role_return_browser import NAME as RETURN_EDITOR, render_editor as render_return_editor
from role_return_reconcile import admitted_replies, render_files as reconciliation_files
from role_return_conflict_intake import (admit_manual_resolution, FOLDER as MANUAL_CONFLICT)

ROUND = "human-round"
EDITOR = "human-editor"
ROUTING = "human-routing"
DELTA = "human-changes"
HISTORY = "human-history"
HANDOFF = "human-selected-role"
RETURN_FORM = "human-role-reply-form"
RECONCILIATION = "human-role-reconciliation"
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

def render_home(source_count, changed, history_count, handoff_role=None, handoff_stage='ALL', handoff_slots=None, reconciled=False, manual_conflict=False):
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
        "<section><h2>Aggregate HUMAN management overview</h2>"
        "<a href='human-history/lightup-lab-human-history-brief.html'>"
        "Open source-free HUMAN briefing</a>"
        "<p><small>Fixed-vocabulary HUMAN counts without endpoint values or "
        "private note text; small cohorts can still be identifiable. "
        "This is not authorization or verified security evidence.</small></p></section>" +
        ("<section><h2>Selected PRIVATE role handoff</h2>"
         "<a href='human-selected-role/lightup-lab-role-handoff-private.html'>"
         "Open voluntarily filtered HUMAN role packet</a><p>"
         "<a href='human-role-reply-form/lightup-lab-human-role-return-editor.html'>"
         "Open selected-role offline response editor</a></p><p><small>"
         "The PRIVATE response form includes only selected source ordinals, "
         "fixed HUMAN stages and a source fingerprint, without original "
         "endpoints, previous notes, or other-role data. A generated "
         "download MUST be re-admitted on the owner's device using "
         "role_return.py before a subsequent advance; it is never "
         "a clearance or authenticated review.</small></p><p><small>"
         "Selected suggested HUMAN role: " + escape(handoff_role or "") +
         "; latest HUMAN stage: " + escape(handoff_stage) +
         "; explicit private slot subset: " +
         (str(len(handoff_slots)) if handoff_slots else "none (all matching slots)") +
         ". Other-role HUMAN notes are intentionally withheld. This is "
         "NOT identity authentication or permission.</small></p></section>"
         if handoff_role is not None else "") +
        ("<section><h2>Returned HUMAN roles and changed planning</h2>"
         "<a href='human-role-reconciliation/lightup-lab-human-return-reconciliation-private.html'>"
         "Open original-bound PRIVATE HUMAN role reconciliation</a><p>"
         "<a href='human-role-reconciliation/lightup-lab-human-next-actions-private.html'>"
         "Open PRIVATE filtered HUMAN next-action desk</a></p><p><small>"
         "This source-minimal HUMAN-only desk shows local slot ordinals, "
         "suggested roles and changed stages/notes WITHOUT original endpoint "
         "URLs or PRIVATE note text. The roles are not authenticated, and this "
         "report is not clearance, consent or verified chronology."
         "</small></p></section>" if reconciled else "") +
        ("<section><h2>Owner-resolved HUMAN source conflicts</h2>"
         "<a href='human-manual-conflict-review/lightup-lab-human-conflict-choices-private.html'>"
         "Open PRIVATE manual original-packet decision desk</a><p>"
         "<a href='human-manual-conflict-review/lightup-lab-human-next-actions-private.html'>"
         "Open filtered HUMAN next actions after manual resolution</a></p><p><small>"
         "Each overlap was explicitly chosen from original role-return packets."
         " No auto precedence, recipient identity, real security review,"
         " authorization or HUMAN GO. PRIVATE source-bound records only."
         "</small></p></section>" if manual_conflict else "") +
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

def guide(count, changed, history_count, handoff_role=None, handoff_stage='ALL', handoff_slots=None, reconciled=False, manual_conflict=False):
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
        "   Open human-history/lightup-lab-human-history-brief.html for a "
        "PRIVATE by default, counts-only management overview.\n" +
        ("human-selected-role: PRIVATE selected role-specific notes and local URL subset; "
         "other-role HUMAN notes withheld.\n"
         "human-role-reply-form: offline selected-role private browser editor,"
         " role-only blank-note CSV and a private return guide.\n"
         "Owner must re-admit the CSV through role_return.py before"
         " next-round --role-return-dir.\n"
         "Selected HUMAN role: " + handoff_role +
         "; selected latest HUMAN stage: " + handoff_stage + "\n"
         "Explicit slot subset: " +
         (str(len(handoff_slots)) + " selected original slots\n"
          if handoff_slots else "none (all matching original slots)\n")
         if handoff_role is not None else "") +
        ("human-role-reconciliation: exact original-bound role/slot change desk, "
         "PRIVATE HTML/CSV and source-free HUMAN counts.\n"
         if reconciled else "") +
        ("human-manual-conflict-review: ordinal-only, original-source-bound"
         " owner HUMAN conflict choice desk, PRIVATE CSV and receipt.\n"
         "The complete full HUMAN response remains in human-round ONLY;"
         " no duplicate full-note worksheet in this review folder.\n"
         if manual_conflict else "") +
        "All outputs are owner-only, unsigned, private, not client approval.\n"
        "To edit another round, download private JSON from the offline editor, "
        "put it in an owner-only mode-0700 folder and chmod 600, then use "
        "advance.py again with this workroom's human-round as --previous-round-dir "
        "and a DIFFERENT empty output directory.\n"
        "Original lab/CI/security/privacy/source-owner/real consent "
        "with action-time revocation/HUMAN GO are independent mandatory gates.\n"
    ).encode("utf-8")

def content_for(before, after, endpoints, earlier, handoff_role=None, handoff_stage='ALL', handoff_slots=None, reconciliation=None, manual_review=None):
    artifacts = {
        ROUND: dict(make_artifacts(after, endpoints)),
        EDITOR: {EDITOR_FILE: render_editor(after)},
        ROUTING: dict(routing_artifacts(after, endpoints, "ALL", "ALL")),
        DELTA: dict(delta_artifacts(before, after)),
        HISTORY: dict(history_artifacts([*earlier, before, after], endpoints)),
    }
    if handoff_role is not None:
        rounds = [*earlier, before, after]
        artifacts[HANDOFF] = dict(
            handoff_artifacts(rounds, endpoints, handoff_role,
                              handoff_stage, handoff_slots))
        fingerprint = handoff_digest(rounds, endpoints, handoff_role,
                                     handoff_stage, handoff_slots)
        template, indices = selected_template(rounds, handoff_role,
                                               handoff_stage, handoff_slots, fingerprint)
        artifacts[RETURN_FORM] = {
            RETURN_CSV: template,
            RETURN_EDITOR: render_return_editor(template),
            RETURN_GUIDE: return_guide(handoff_role, len(indices)),
        }
    if reconciliation is not None:
        artifacts[RECONCILIATION] = reconciliation
    if manual_review is not None:
        artifacts[MANUAL_CONFLICT] = manual_review
    return artifacts

def inspect_root(fd, root_path, before, endpoints, after, earlier,
                 handoff_role=None, handoff_stage='ALL', handoff_slots=None, reconciliation=None, manual_review=None):
    expected = content_for(before, after, endpoints, earlier, handoff_role,
                           handoff_stage, handoff_slots, reconciliation, manual_review)
    if set(os.listdir(fd)) != {*expected, GUIDE, HOME}:
        raise Hold("follow-up workroom missing canonical inventory")
    for dirname in expected:
        folder_fd, _ = open_output_directory(os.path.join(root_path, dirname))
        try:
            if set(os.listdir(folder_fd)) != set(expected[dirname]):
                raise Hold("PRIVATE follow-up subfolder has unknown or missing files")
            bound = 524288 if dirname in (HISTORY, HANDOFF) else 196608
            actual = {name: read_private_bundle_item(folder_fd, name, bound)
                      for name in expected[dirname]}
        finally:
            os.close(folder_fd)
        if actual != expected[dirname]:
            raise Hold("follow-up workroom file changed or source mismatch")
    changes = sum(a != b for a, b in zip(before["human_rows"], after["human_rows"]))
    count = len(earlier) + 2
    if (read_private_bundle_item(fd, HOME, 32768) !=
            render_home(len(endpoints), changes, count, handoff_role, handoff_stage,
                        handoff_slots, reconciliation is not None, manual_review is not None)
            or read_private_bundle_item(fd, GUIDE, 16384) !=
            guide(len(endpoints), changes, count, handoff_role, handoff_stage,
                  handoff_slots, reconciliation is not None, manual_review is not None)):
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
    reply_mode = parser.add_mutually_exclusive_group()
    reply_mode.add_argument("--responses", help="private full HUMAN JSON (creation only)")
    reply_mode.add_argument("--interactive", action="store_true",
                            help="local terminal HUMAN reply")
    reply_mode.add_argument("--role-return-dir", action="append", default=[],
                            help="one to five disjoint source-bound owner-private role returns")
    reply_mode.add_argument("--conflict-resolved-dir",
                            help="original exact four-file PRIVATE manual HUMAN decision result")
    parser.add_argument("--conflict-return-dir", action="append", default=[],
                        help="2-5 original overlapping selected-role return dirs (same order)")
    parser.add_argument("--conflict-decision-file",
                        help="original current-user-only explicit HUMAN conflict choice CSV")
    parser.add_argument("--handoff-role", choices=ROLES,
                        help="optionally include a voluntary PRIVATE role-selected HUMAN handoff")
    parser.add_argument("--handoff-stage", choices=("ALL", *STAGES), default="ALL",
                        help="optional latest HUMAN stage filter; requires --handoff-role")
    parser.add_argument("--handoff-slot", type=int, action="append",
                        help="optional minimal original slot subset for selected role; repeat as needed")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        if (args.handoff_stage != "ALL" or args.handoff_slot) and args.handoff_role is None:
            raise Hold("selected HUMAN stage/slot requires a selected HANDOFF role")
        if bool(args.conflict_resolved_dir) != bool(args.conflict_return_dir) or (
                bool(args.conflict_resolved_dir) != bool(args.conflict_decision_file)):
            raise Hold("manual conflict intake requires original resolved result,"
                       " original return dirs AND original manual decision CSV")
        if args.conflict_resolved_dir and not args.earlier_round_dir:
            raise Hold("manual conflict source replay requires earlier original HUMAN rounds")
        if args.output_dir:
            if sum(bool(c) for c in (args.responses, args.interactive,
                                     args.role_return_dir, args.conflict_resolved_dir)) != 1:
                raise Hold("creation requires exactly one HUMAN input method")
        elif args.responses or args.interactive:
            raise Hold("read-only reopen cannot edit HUMAN responses; "
                       "original role-return dirs may be supplied for exact source re-admission")
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
        reconciliation = None
        manual_review = None
        try:
            if args.output_dir and os.listdir(root_fd):
                raise Hold("new PRIVATE HUMAN next-round workspace must be empty")
            sources = (original, previous_dir, *earlier_dirs)
            if args.role_return_dir:
                sources = (*sources, *(os.path.abspath(d) for d in args.role_return_dir))
            if args.conflict_resolved_dir:
                sources = (*sources, os.path.abspath(args.conflict_resolved_dir),
                           os.path.abspath(args.conflict_decision_file),
                           *(os.path.abspath(d) for d in args.conflict_return_dir))
            for source in sources:
                if os.path.commonpath((source, root_path)) in (source, root_path):
                    raise Hold("next-round output must be separate from original inputs")
            if args.output_dir:
                if args.interactive:
                    # The original prior round stays unchanged even when a
                    # HUMAN operator edits several rows and then aborts.
                    after = interactive_review(copy.deepcopy(before))
                elif args.role_return_dir:
                    if not earlier_rounds:
                        raise Hold("role return requires one earlier original HUMAN round")
                    source_rounds = [*earlier_rounds, before]
                    replies = admitted_replies(
                        args.role_return_dir, source_rounds, endpoints, digest)
                    reconciliation = reconciliation_files(
                        replies, source_rounds, endpoints)
                    after = combine_returns(args.role_return_dir,
                                            source_rounds, endpoints, digest)
                elif args.conflict_resolved_dir:
                    _, after, manual_review = admit_manual_resolution(
                        args.conflict_resolved_dir, args.conflict_decision_file,
                        args.conflict_return_dir, [*earlier_rounds, before],
                        endpoints, digest)
                else:
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
                if args.interactive:
                    again = after
                elif args.role_return_dir:
                    again = combine_returns(
                        args.role_return_dir,
                        [*(entry for _, entry in renewed_earlier), renewed_before],
                        renewed_endpoints, renewed_digest)
                elif args.conflict_resolved_dir:
                    _, again, newer_review = admit_manual_resolution(
                        args.conflict_resolved_dir, args.conflict_decision_file,
                        args.conflict_return_dir,
                        [*(entry for _, entry in renewed_earlier), renewed_before],
                        renewed_endpoints, renewed_digest)
                    if newer_review != manual_review:
                        raise Hold("original private HUMAN conflict choices changed before publication")
                else:
                    again = load_json(require_private_file(args.responses))
                if args.role_return_dir:
                    newer_source_rounds = [
                        *(record for _, record in renewed_earlier), renewed_before]
                    newer_replies = admitted_replies(
                        args.role_return_dir, newer_source_rounds,
                        renewed_endpoints, renewed_digest)
                    if (newer_replies != replies or
                            reconciliation_files(newer_replies, newer_source_rounds,
                                                 renewed_endpoints) != reconciliation):
                        raise Hold("selected HUMAN return packets changed before publication")
                validate_worksheet(again, renewed_digest, len(renewed_endpoints))
                if ((renewed, renewed_endpoints, renewed_digest, renewed_previous, renewed_before, again)
                        != (original, endpoints, digest, previous_dir, before, after)):
                    raise Hold("previous HUMAN or original source changed before publication")
                expected = content_for(
                    before, after, endpoints, earlier_rounds, args.handoff_role,
                    args.handoff_stage, args.handoff_slot, reconciliation, manual_review)
                # The standalone HISTORY producer has a fixed 512-KiB cap. The
                # integrated pipeline must enforce the same cap BEFORE it creates
                # any of the fresh workroom directories, or it could leave a
                # seemingly complete but impossible-to-reopen private packet.
                for dirname, files in expected.items():
                    limit = 524288 if dirname in (HISTORY, HANDOFF) else 196608
                    if any(not 0 < len(blob) <= limit for blob in files.values()):
                        raise Hold("PRIVATE HUMAN next-round artifact exceeds reopen limit")
                for name in expected:
                    private_child(root_fd, name)
                for dirname in expected:
                    fd, _ = open_output_directory(os.path.join(root_path, dirname))
                    try:
                        publish_bundle(fd, list(expected[dirname].items()))
                    finally:
                        os.close(fd)
                changed = sum(a != b for a, b in zip(before["human_rows"], after["human_rows"]))
                publish_bundle(root_fd, [
                    (GUIDE, guide(len(endpoints), changed, len(earlier_rounds) + 2,
                                  args.handoff_role, args.handoff_stage, args.handoff_slot,
                                  reconciliation is not None, manual_review is not None)),
                    (HOME, render_home(len(endpoints), changed, len(earlier_rounds) + 2,
                                       args.handoff_role, args.handoff_stage, args.handoff_slot,
                                       reconciliation is not None, manual_review is not None)),
                ])
            else:
                fd, _ = open_output_directory(os.path.join(root_path, ROUND))
                try:
                    source = read_private_bundle_item(fd, REVIEW_FILES[0], 65536)
                finally:
                    os.close(fd)
                after = load_json(source)
                validate_worksheet(after, digest, len(endpoints))
                if args.role_return_dir:
                    if not earlier_rounds:
                        raise Hold("reopening a role-return workroom needs earlier source rounds")
                    original_rounds = [*earlier_rounds, before]
                    reopened_replies = admitted_replies(
                        args.role_return_dir, original_rounds, endpoints, digest)
                    rebuilt = combine_returns(
                        args.role_return_dir, original_rounds, endpoints, digest)
                    if rebuilt != after:
                        raise Hold("original private HUMAN returns differ from published round")
                    reconciliation = reconciliation_files(
                        reopened_replies, original_rounds, endpoints)
                elif RECONCILIATION in os.listdir(root_fd):
                    raise Hold("provide the original --role-return-dir inputs to reopen this workroom")
                if args.conflict_resolved_dir:
                    _, reconstructed, manual_review = admit_manual_resolution(
                        args.conflict_resolved_dir, args.conflict_decision_file,
                        args.conflict_return_dir, [*earlier_rounds, before], endpoints, digest)
                    if reconstructed != after:
                        raise Hold("original private manual HUMAN decisions do not match published round")
                elif MANUAL_CONFLICT in os.listdir(root_fd):
                    raise Hold("source-bound conflict workroom reopening requires original choice"
                               " CSV, resolved result and overlapping role-return dirs")
            changed = inspect_root(root_fd, root_path, before, endpoints, after,
                                   earlier_rounds, args.handoff_role, args.handoff_stage,
                                   args.handoff_slot, reconciliation, manual_review)
        finally:
            os.close(root_fd)
        print("PRIVATE_HUMAN_NEXT_ROUND_" +
              ("CREATED" if args.output_dir else "REOPENED") +
              " human_changed_slots=" + str(changed) +
              " — REVIEW_ONLY; NOT AUTHORIZED; NO TARGET ACTIVITY")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_NEXT_ROUND_HOLD — original or HUMAN inputs not admitted; partial output is not valid",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError,
            OverflowError, EOFError, KeyboardInterrupt):
        report_hold("PRIVATE_HUMAN_NEXT_ROUND_HOLD — original or HUMAN inputs not admitted; partial output is not valid",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
