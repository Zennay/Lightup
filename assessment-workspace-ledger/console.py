#!/usr/bin/env python3
"""Foreground HUMAN-only operator console for existing PRIVATE assessment kits.

Exactly one locally chosen original-source action at a time.
No shell, subprocess, background jobs, network, models, scanner or grant APIs.
"""
from __future__ import annotations

import argparse
import os
import sys

import ledger
import compare
import continuity
import human_revisions
import browser_intake
import package
from browser_studio import render_studio

TITLE = "LightUp PRIVATE Assessment Workspace · Foreground HUMAN Console"
MENU = (
    ("1", "Capture current private original kit inventory"),
    ("2", "Reopen exact original source bytes against ledger"),
    ("3", "Record newly completed HUMAN review CSV (never permission)"),
    ("4", "Review historical change between two stored inventories"),
    ("5", "Continue previous HUMAN proposals on unchanged original kits"),
    ("6", "Export complete source-free single-file offline HUMAN studio"),
    ("7", "Show PRIVATE session-only action results"),
    ("8", "Review historical HUMAN stage/owner/question changes on unchanged kit bytes"),
    ("9", "Build a NEW source-only offline software ZIP"),
    ("10", "Inspect unsigned software ZIP file inventory locally"),
    ("11", "Import browser-downloaded HUMAN CSV safely into PRIVATE native custody"),
    ("12", "Import PRIVATE browser CSV and immediately prepare original HUMAN follow-up packet"),
    ("0", "Exit"),
)


def prompt(label, required=True):
    while True:
        value = input(label + (": " if required else " (Enter to skip): ")).strip()
        if value or not required:
            return value
        print("A path/value is required, no implicit discovery.")


def source_paths():
    paths = []
    print("Enter 1–12 absolute existing PRIVATE kit paths; blank after the first to finish.")
    while len(paths) < 12:
        value = prompt("PRIVATE kit " + str(len(paths) + 1), required=not paths)
        if not value:
            break
        paths.append(value)
    return paths


def labels(paths):
    print("Optional HUMAN labels are metadata; avoid customer/target names on shared terminals.")
    result = [prompt("HUMAN display label for kit " + str(i), False) for i in range(1, len(paths) + 1)]
    if all(not x for x in result):
        return None
    return [v or "PRIVATE kit " + str(i) for i, v in enumerate(result, 1)]


def private_parent():
    return prompt("Existing owner-private 0700 directory OUTSIDE checkout")


def handle_action(action):
    if action == "1":
        paths = source_paths()
        selected_labels = labels(paths)
        previous = prompt("Exact previous owner-only ledger.json for source change capture", False)
        return ledger.capture(argparse.Namespace(
            kit=paths, label=selected_labels, previous=previous or None,
            private_parent=private_parent()
        ))
    if action == "2":
        return ledger.reopen(argparse.Namespace(
            ledger=prompt("Original owner-only ledger.json")
        ))
    if action == "3":
        return ledger.finalize(argparse.Namespace(
            ledger=prompt("Original owner-only ledger.json"),
            plan=prompt("Human-edited PRIVATE 0600 HUMAN-review.csv"),
            private_parent=private_parent()
        ))
    if action == "4":
        return compare.run(argparse.Namespace(
            before=prompt("Original previous PRIVATE ledger.json"),
            after=prompt("Original current PRIVATE ledger.json"),
            private_parent=private_parent()
        ))
    if action == "5":
        return continuity.run(argparse.Namespace(
            previous=prompt("Original PRIVATE previous ledger.json"),
            human=prompt("Native old HUMAN-only.json from finalize"),
            current=prompt("Original current ledger.json from capture --previous"),
            private_parent=private_parent()
        ))
    if action in ("11", "12"):
        return browser_intake.import_browser(argparse.Namespace(
            ledger=prompt("Original owner-private ledger.json"),
            csv=prompt("Explicit original browser download HUMAN-review.csv"),
            private_parent=private_parent(),
            finalize=(action == "12")
        ))
    if action == "9":
        return package.build(argparse.Namespace(
            output=prompt("Absolute new source-only software ZIP path in owner-private folder")
        ))
    if action == "10":
        return package.inspect(argparse.Namespace(
            archive=prompt("Absolute existing LightUp source-only software ZIP")
        ))
    if action == "8":
        return human_revisions.run(argparse.Namespace(
            ledger=prompt("Exact original PRIVATE ledger.json"),
            before=prompt("Original earlier native HUMAN-only.json"),
            after=prompt("Original later native HUMAN-only.json"),
            private_parent=private_parent()
        ))
    if action == "6":
        parent = private_parent()
        ledger.private_parent(parent)
        name = prompt("Name for NEW standalone local .html software file (no /)")
        if "/" in name or "\\" in name or name in (".", "..") or not name.endswith(".html"):
            ledger.reject("PRIVATE HOLD: enter plain .html filename only")
        path = os.path.join(parent, name)
        data = render_studio().encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            at = 0
            while at < len(data):
                at += os.write(fd, data[at:])
            os.fsync(fd)
        finally:
            os.close(fd)
        print("PRIVATE REVIEW_ONLY: standalone offline software generated at " + path)
        return 2
    return 3


def console():
    print(TITLE)
    print("INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. This console NEVER grants permission.")
    print("Do not process unapproved original client data or run against active targets.")
    session = []
    while True:
        print("\n" + "\n".join(number + ". " + label for number, label in MENU))
        try:
            choice = input("Choose a foreground action: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nPRIVATE session ended; no background work started.")
            break
        if choice == "0":
            break
        if choice == "7":
            if not session:
                print("No local HUMAN operations in this session.")
            else:
                for ordinal, (step, state) in enumerate(session, 1):
                    print(str(ordinal) + ". " + step + ": " + state +
                          " (never permission, never confirmed security)")
            continue
        if choice not in {number for number, _ in MENU if number not in ("0", "7")}:
            print("Select a listed action.")
            continue
        try:
            status = handle_action(choice)
        except (ledger.Hold, OSError, ValueError, UnicodeError):
            print("PRIVATE HOLD: original/private inputs rejected; no external action.", file=sys.stderr)
            status = 3
        except (EOFError, KeyboardInterrupt):
            print("\nPRIVATE selection cancelled, no retry scheduled.")
            status = 3
        session.append((choice, "REVIEW_ONLY" if status == 2 else "HOLD"))
        print("Action status: " + ("REVIEW_ONLY (2)" if status == 2 else "HOLD (3)") +
              ". No PASS, consent, verified finding or authorization.")
    print("PRIVATE session closed; nothing queued, sent, deleted or deployed.")
    return 3  # Console sessions are never approval or a release signal.


if __name__ == "__main__":
    raise SystemExit(console())
