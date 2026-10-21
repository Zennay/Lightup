#!/usr/bin/env python3
"""Create/reopen a complete private offline LightUp Lab Launchpad HUMAN workspace.

All operations are local, bounded and non-authorizing. The preview command is
written for a human, never executed. No target/network/subprocess interaction.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
import stat
import sys

from launchpad import (
    FLAGS, Hold, open_output_directory, publish_bundle, read_private_bundle_item,
    run as run_launchpad, verify_existing,
)
from review_desk import (
    FILE_NAMES as REVIEW_FILES, blank_worksheet, load_json, make_artifacts,
    read_original_bundle, validate_worksheet,
)
from editor import NAME as EDITOR_FILE, render_editor

BUNDLE_DIR = "launchpad"
REVIEW_DIR = "human-round-01"
EDITOR_DIR = "human-editor"
GUIDE_FILE = "START-HERE-PRIVATE.txt"
SUBDIRS = (BUNDLE_DIR, REVIEW_DIR, EDITOR_DIR)
LAB_ONLY = "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED"

def private_child(root_fd, dirname):
    """Reserve a new owned mode-0700 directory with no symlink redirection."""
    os.mkdir(dirname, 0o700, dir_fd=root_fd)
    # open_output_directory independently re-admits the full path.
    info = os.stat(dirname, dir_fd=root_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Hold("new private workspace directory could not be admitted")

def guide(root_dir, source_count, digest):
    """One source-bound, PRIVATE on-disk entry point; never an execution script."""
    return (
        "LightUp — PRIVATE isolated-lab HUMAN workspace\n"
        + LAB_ONLY + "\n"
        "Original local manifest endpoint count: " + str(source_count) + "\n"
        "Canonical unsigned source SHA-256: " + digest + "\n\n"
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
        "4. Human counts-only exports are in human-round-01; do not assume "
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
    if entries != {*SUBDIRS, GUIDE_FILE}:
        raise Hold("workspace has missing or unknown top-level entries")
    endpoints, digest = original_info(root_dir)
    work = read_review(root_dir, endpoints, digest)
    fd, _ = open_output_directory(os.path.join(root_dir, EDITOR_DIR))
    try:
        stored = read_private_bundle_item(fd, EDITOR_FILE, 131072)
    finally:
        os.close(fd)
    if stored != render_editor(work):
        raise Hold("offline HUMAN editor no longer matches original private worksheet")
    guide_bytes = read_private_bundle_item(root_fd, GUIDE_FILE, 16384)
    if guide_bytes != guide(root_dir, len(endpoints), digest):
        raise Hold("private workspace guide no longer matches original source")
    return len(endpoints), digest

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
    publish_bundle(root_fd, [(GUIDE_FILE, guide(root_dir, len(endpoints), digest))])
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
    args = parser.parse_args(argv)
    try:
        if bool(args.workspace_dir) != bool(args.manifest):
            raise Hold("creation requires a private manifest and a private workspace directory")
        root_fd, root_dir = open_output_directory(args.workspace_dir or args.verify_workspace_dir)
        try:
            if args.workspace_dir:
                count, digest = create_workspace(args.manifest, root_fd, root_dir)
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
    except (Hold, OSError, ValueError, TypeError, UnicodeError, ImportError, OverflowError):
        print("PRIVATE_HUMAN_WORKSPACE_HOLD — private packet not admitted; "
              "do not use any partial output as valid", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
