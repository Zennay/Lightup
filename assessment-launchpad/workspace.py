#!/usr/bin/env python3
"""Create/reopen a complete private offline LightUp Lab Launchpad HUMAN workspace.

All operations are local, bounded and non-authorizing. The preview command is
written for a human, never executed. No target/network/subprocess interaction.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from html import escape
import os
import stat
import sys

from launchpad import (
    FLAGS, Hold, open_output_directory, publish_bundle, read_private_bundle_item, report_hold,
    run as run_launchpad, verify_existing, validate_endpoints, MAX_MANIFEST_BYTES,
)
from review_desk import (
    FILE_NAMES as REVIEW_FILES, blank_worksheet, load_json, make_artifacts,
    read_original_bundle, validate_worksheet,
)
from editor import NAME as EDITOR_FILE, render_editor
from routing import FILES as ROUTING_FILES, create_artifacts as routing_artifacts

BUNDLE_DIR = "launchpad"
REVIEW_DIR = "human-round-01"
EDITOR_DIR = "human-editor"
ROUTING_DIR = "human-routing"
GUIDE_FILE = "START-HERE-PRIVATE.txt"
HOME_FILE = "OPEN-WORKSPACE-PRIVATE.html"
SUBDIRS = (BUNDLE_DIR, REVIEW_DIR, EDITOR_DIR, ROUTING_DIR)
LAB_ONLY = "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED"
INPUT_FILE = "lightup-lab-input-manifest.txt"

def private_child(root_fd, dirname):
    """Reserve a new owned mode-0700 directory with no symlink redirection."""
    os.mkdir(dirname, 0o700, dir_fd=root_fd)
    # open_output_directory independently re-admits the full path.
    info = os.stat(dirname, dir_fd=root_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Hold("new private workspace directory could not be admitted")


HOME_STYLE = ("body{font:16px/1.55 system-ui,sans-serif;color:#17212f;"
              "background:#f3f5f9;max-width:980px;margin:0 auto;padding:2rem 1rem}"
              "h1{font-size:2.4rem}.hold{border-left:6px solid #9a5b18;"
              "background:#fff3dd;padding:1rem;font-weight:750}"
              "section{background:white;border:1px solid #d7e0eb;border-radius:.7rem;"
              "padding:1.15rem;margin:1rem 0}a{color:#18467b;font-weight:750}"
              "a:focus-visible{outline:3px solid #e5ae46;outline-offset:3px}"
              "small{color:#475569}code{overflow-wrap:anywhere}")

def render_home(count, digest):
    """Static no-network local navigation. Links are only known relative PRIVATE files."""
    style_hash = base64.b64encode(sha256(HOME_STYLE.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-" + style_hash +
        "'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " base-uri 'none'; form-action 'none'\">"
        "<title>LightUp · PRIVATE offline LAB HUMAN workspace</title>"
        "<style>" + HOME_STYLE + "</style></head><body>"
        "<p>LIGHTUP / ASSESSMENT RUNTIME / OFFLINE WORKROOM</p>"
        "<h1>Isolated Lab · Private HUMAN Workspace</h1>"
        "<p class='hold'>" + escape(LAB_ONLY) +
        " · PREVIEW NOT RUN · NO AUTHORITY</p>"
        "<p>This original-source-bound local desk groups the preview, HUMAN review "
        "and editing lifecycle. It is entirely private, unsigned and lab-only. "
        "The underlying endpoint values and HUMAN notes exist in OTHER PRIVATE "
        "files. Do not host or share this workspace.</p>"
        "<section><h2>1 · Original lab preview</h2><p>" + str(count) +
        " original locally declared endpoints; source SHA-256 "
        "<code>" + escape(digest) + "</code></p>"
        "<a href='launchpad/lightup-lab-plan-handoff.html'>"
        "Open original preview handoff</a><p><small>Generated --preview-only "
        "command is for human inspection, never executed here. "
        "No consent or scope authority.</small></p></section>"
        "<section><h2>2 · Initial PRIVATE HUMAN review</h2>"
        "<a href='human-round-01/lightup-lab-human-private.html'>"
        "Open human follow-up desk</a>"
        "<p><small>Contains endpoint URLs and private notes. HUMAN status is "
        "self-reported and cannot clear findings or grant permission.</small></p></section>"
        "<section><h2>3 · Browser-only HUMAN editor</h2>"
        "<a href='human-editor/lightup-lab-human-editor.html'>"
        "Open local editable HUMAN worksheet</a>"
        "<p><small>Edited JSON must be privately downloaded and independently "
        "re-admitted by the native --responses option into a NEW private round."
        "</small></p></section>"
        "<section><h2>4 · Role-specific PRIVATE HUMAN queue</h2>"
        "<a href='human-routing/lightup-lab-human-routing-private.html'>"
        "Open role-ordered HUMAN routing desk</a>"
        "<p><small>Contains PRIVATE endpoint URLs and HUMAN notes. "
        "Create later filtered exports through routing.py after updated HUMAN rounds.</small></p></section>"
        "<section><h2>5 · Source-free HUMAN counts</h2>"
        "<a href='human-round-01/lightup-lab-human-counts.json'>"
        "Open low-detail counts JSON</a>"
        "<p><small>No endpoint values or HUMAN text. Counts can still be "
        "sensitive for small engagements.</small></p></section>"
        "<p><small>Read START-HERE-PRIVATE.txt for further native operations. "
        "All original source-owner, independent security/privacy, hosted/permanent "
        "CI, authentic separate consent with revocation and HUMAN GO gates "
        "remain unchanged.</small></p></body></html>"
    ).encode("utf-8")

def guide(root_dir, source_count, digest):
    """One source-bound, PRIVATE on-disk entry point; never an execution script."""
    return (
        "LightUp — PRIVATE isolated-lab HUMAN workspace\n"
        + LAB_ONLY + "\n"
        "Original local manifest endpoint count: " + str(source_count) + "\n"
        "Canonical unsigned source SHA-256: " + digest + "\n\n"
        "OPEN-WORKSPACE-PRIVATE.html is the offline start screen for this bundle.\n\n"
        "1. Original Launchpad plan: launchpad/lightup-lab-plan-handoff.html\n"
        "   Original human-inspectable preview command: "
        "launchpad/lightup-lab-preview-command.txt\n"
        "   The preview command HAS NOT been executed. Do not treat it as a scan permit.\n"
        "2. Private human planning worksheet: "
        "human-round-01/lightup-lab-human-private.json\n"
        "   Private scriptless endpoint/notes review: "
        "human-round-01/lightup-lab-human-private.html\n"
        "3. Offline interactive HUMAN editor: human-editor/" + EDITOR_FILE + "\n"
        "   The editor embeds PRIVATE notes and an unsigned source fingerprint. "
        "Never publish or host.\n"
        "   It downloads a revised JSON file only; native --responses "
        "must independently re-admit that file.\n"
        "4. Role-ordered HUMAN inbox: human-routing/" + ROUTING_FILES[0] + "\n"
        "   Private CSV: human-routing/" + ROUTING_FILES[1] + "\n"
        "   Anonymous-looking source-free counts: human-routing/" + ROUTING_FILES[2] + "\n"
        "   To filter a later round by HUMAN role/stage, use assessment-launchpad/routing.py.\n"
        "5. Human counts-only exports are in human-round-01; do not assume "
        "statistical anonymity for small populations.\n\n"
        "To update HUMAN stages, reviewer roles or notes, download the "
        "edited JSON, move it into a current-user-owned 0700 directory, "
        "and set its file mode to 0600. Then choose a NEW 0700 "
        "output directory and run:\n"
        "  python3 assessment-launchpad/review_desk.py "
        "--bundle-dir " + root_dir + "/" + BUNDLE_DIR + " "
        "--responses /PRIVATE/edited-human.json "
        "--output-dir /PRIVATE/new-human-round\n\n"
        "To compare independently admitted HUMAN rounds, use "
        "assessment-launchpad/compare_review.py with --bundle-dir, "
        "--before-dir, --after-dir and a NEW --output-dir.\n"
        "To reopen this original workspace without execution:\n"
        "  python3 assessment-launchpad/workspace.py "
        "--verify-workspace-dir " + root_dir + "\n\n"
        "All source ownership, independent security/privacy review, "
        "exact-head hosted/permanent VPS CI, distinct authentic "
        "client/operator consent with action-time revocation, and "
        "HUMAN GO remain required. There is no scan, permission, "
        "grant, actual verified finding or release here.\n"
    ).encode("utf-8")

def original_info(root_dir):
    location = os.path.join(root_dir, BUNDLE_DIR)
    if verify_existing(location) != 0:
        raise Hold("original bundle failed reopen")
    _, endpoints, digest = read_original_bundle(location)
    return endpoints, digest

def read_review(root_dir, endpoints, digest):
    location = os.path.join(root_dir, REVIEW_DIR)
    fd, _ = open_output_directory(location)
    try:
        if set(os.listdir(fd)) != set(REVIEW_FILES):
            raise Hold("private HUMAN review folder has missing or unknown files")
        recorded = {name: read_private_bundle_item(fd, name, 65536)
                    for name in REVIEW_FILES}
    finally:
        os.close(fd)
    work = load_json(recorded[REVIEW_FILES[0]])
    validate_worksheet(work, digest, len(endpoints))
    if recorded != dict(make_artifacts(work, endpoints)):
        raise Hold("HUMAN round changed or is not source-bound")
    return work

def check_workspace(root_fd, root_dir):
    """Readmit every artifact; reject invented, missing, or modified workspace files."""
    entries = set(os.listdir(root_fd))
    if entries != {*SUBDIRS, GUIDE_FILE, HOME_FILE}:
        raise Hold("workspace has missing or unknown top-level entries")
    endpoints, digest = original_info(root_dir)
    work = read_review(root_dir, endpoints, digest)
    fd, _ = open_output_directory(os.path.join(root_dir, EDITOR_DIR))
    try:
        if set(os.listdir(fd)) != {EDITOR_FILE}:
            raise Hold("private HUMAN editor folder has missing or unknown files")
        stored = read_private_bundle_item(fd, EDITOR_FILE, 131072)
    finally:
        os.close(fd)
    if stored != render_editor(work):
        raise Hold("offline HUMAN editor no longer matches original private worksheet")
    dashboard_bytes = read_private_bundle_item(root_fd, HOME_FILE, 32768)
    if dashboard_bytes != render_home(len(endpoints), digest):
        raise Hold("private workspace start screen changed or became noncanonical")
    routing_fd, _ = open_output_directory(os.path.join(root_dir, ROUTING_DIR))
    try:
        if set(os.listdir(routing_fd)) != set(ROUTING_FILES):
            raise Hold("private HUMAN routing folder has missing or unknown files")
        recorded_routing = {name: read_private_bundle_item(routing_fd, name, 65536)
                            for name in ROUTING_FILES}
    finally:
        os.close(routing_fd)
    if recorded_routing != dict(routing_artifacts(work, endpoints, "ALL", "ALL")):
        raise Hold("private HUMAN routing packet changed or no longer matches source")
    guide_bytes = read_private_bundle_item(root_fd, GUIDE_FILE, 16384)
    if guide_bytes != guide(root_dir, len(endpoints), digest):
        raise Hold("private workspace guide no longer matches original source")
    return len(endpoints), digest


def guided_manifest(input_directory, root_dir):
    """Human-entered literal endpoints; pinned original lab validation, local private file only."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise Hold("guided manifest requires a private interactive terminal")
    input_fd, input_dir = open_output_directory(input_directory)
    try:
        if os.path.commonpath((input_dir, root_dir)) in (input_dir, root_dir):
            raise Hold("private guided input and workspace must be separate directories")
        if os.listdir(input_fd):
            raise Hold("guided source directory must be empty and exclusive")
        endpoints = []
        print("PRIVATE LAB MANIFEST COMPOSER · NO TARGET ACTIVITY")
        print("Enter 1–16 literal isolated-lab HTTP(S) URLs. Blank line ends.")
        print("The original pinned URL + LabScenario source gate will admit the whole batch.")
        print("Terminal input is visible to your local operator, never sent over network.")
        while len(endpoints) < 16:
            entry = input("Lab endpoint " + str(len(endpoints) + 1).zfill(2) + " (blank=end): ")
            if entry == "":
                break
            if entry != entry.strip() or len(entry) > 2048 or any(
                    ord(character) < 33 or ord(character) == 127 for character in entry):
                raise Hold("guided endpoint contains unsupported whitespace/control data")
            endpoints.append(entry)
        if not endpoints or len(set(endpoints)) != len(endpoints):
            raise Hold("enter 1–16 distinct literal lab endpoints")
        admitted = validate_endpoints(endpoints)
        data = ("\n".join(admitted) + "\n").encode("utf-8")
        if not 0 < len(data) <= MAX_MANIFEST_BYTES:
            raise Hold("guided manifest exceeds original native input limit")
        publish_bundle(input_fd, [(INPUT_FILE, data)])
        return os.path.join(input_dir, INPUT_FILE)
    finally:
        os.close(input_fd)

def create_workspace(manifest, root_fd, root_dir):
    if os.listdir(root_fd):
        raise Hold("workspace directory must start empty; no overwrite permitted")
    manifest_absolute = os.path.abspath(os.fspath(manifest))
    manifest_parent = os.path.dirname(manifest_absolute)
    if os.path.commonpath((manifest_parent, root_dir)) in (manifest_parent, root_dir):
        raise Hold("input manifest and output workspace must be in separate directories")
    for name in SUBDIRS:
        private_child(root_fd, name)
    launchpad_dir = os.path.join(root_dir, BUNDLE_DIR)
    result = run_launchpad(argparse.Namespace(manifest=manifest, output_dir=launchpad_dir))
    if result != 0:
        raise Hold("original Launchpad admission rejected private manifest")
    endpoints, digest = original_info(root_dir)
    # The initial HUMAN state must be explicitly non-authorizing, not inferred
    # from a passed URL validator or any source-provided target claims.
    work = blank_worksheet(digest, len(endpoints))
    validate_worksheet(work, digest, len(endpoints))
    human_fd, _ = open_output_directory(os.path.join(root_dir, REVIEW_DIR))
    try:
        publish_bundle(human_fd, make_artifacts(work, endpoints))
    finally:
        os.close(human_fd)
    editor_fd, _ = open_output_directory(os.path.join(root_dir, EDITOR_DIR))
    try:
        publish_bundle(editor_fd, [(EDITOR_FILE, render_editor(work))])
    finally:
        os.close(editor_fd)
    routing_fd, _ = open_output_directory(os.path.join(root_dir, ROUTING_DIR))
    try:
        publish_bundle(routing_fd, routing_artifacts(work, endpoints, "ALL", "ALL"))
    finally:
        os.close(routing_fd)
    publish_bundle(root_fd, [
        (GUIDE_FILE, guide(root_dir, len(endpoints), digest)),
        (HOME_FILE, render_home(len(endpoints), digest)),
    ])
    # Recheck complete packet before reporting success. Partial directories, if
    # any error occurs, remain private and cannot be mistaken for a valid pack.
    return check_workspace(root_fd, root_dir)

def main(argv=None):
    parser = argparse.ArgumentParser(description=(
        "Offline HUMAN Launchpad workspace: create/reopen only, no command execution."))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--workspace-dir", help="an existing EMPTY owner-only mode-0700 directory")
    group.add_argument("--verify-workspace-dir", help="read-only reopen an existing private workspace")
    parser.add_argument("--manifest", help="existing private mode-0600 isolated-lab manifest")
    parser.add_argument("--interactive-manifest", action="store_true",
                        help="create private source input by guided original-validator terminal admission")
    parser.add_argument("--input-dir",
                        help="an existing EMPTY owner-only mode-0700 source directory for guided input")
    parser.add_argument("--explain-hold", action="store_true",
                        help="print the curated non-sensitive HOLD reason; never prints paths, endpoint values or raw exceptions")
    args = parser.parse_args(argv)
    try:
        if args.verify_workspace_dir:
            if args.manifest or args.interactive_manifest or args.input_dir:
                raise Hold("workspace reopen cannot create or import sources")
        else:
            if (bool(args.manifest) == bool(args.interactive_manifest)
                    or bool(args.input_dir) != args.interactive_manifest):
                raise Hold("creation requires either one private manifest OR a guided input directory")
        root_fd, root_dir = open_output_directory(args.workspace_dir or args.verify_workspace_dir)
        try:
            if args.workspace_dir:
                manifest = (guided_manifest(args.input_dir, root_dir)
                            if args.interactive_manifest else args.manifest)
                count, digest = create_workspace(manifest, root_fd, root_dir)
            else:
                count, digest = check_workspace(root_fd, root_dir)
        finally:
            os.close(root_fd)
        print(("PRIVATE_HUMAN_WORKSPACE_CREATED" if args.workspace_dir else
               "PRIVATE_HUMAN_WORKSPACE_REOPENED") +
              " slots=" + str(count) + " source_sha256=" + digest +
              " — UNSIGNED LOCAL CONSISTENCY; NO AUTHORIZATION, "
              "TARGET ACTIVITY OR COMMAND EXECUTION")
        return 0
    except Hold as error:
        report_hold("PRIVATE_HUMAN_WORKSPACE_HOLD — private packet not admitted; do not use any partial output as valid",
                    error, args.explain_hold)
        return 3
    except (OSError, ValueError, TypeError, UnicodeError, ImportError,
            OverflowError, EOFError, KeyboardInterrupt):
        report_hold("PRIVATE_HUMAN_WORKSPACE_HOLD — private packet not admitted; do not use any partial output as valid",
                    None, args.explain_hold)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
