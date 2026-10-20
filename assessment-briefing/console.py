#!/usr/bin/env python3
"""Foreground offline LightUp PRIVATE HUMAN briefing menu. No target execution."""
from __future__ import annotations

import sys

from briefing import Hold, make_package
from compare import create_comparison
from aggregate import create as create_aggregate
from human_return import create as create_human_return
from human_revision import create as create_human_revision
from paged_review import make_paged_package
from human_matrix import create as create_human_matrix
from private_paged_zip import create as create_private_paged_zip
from private_paged_restore import restore as restore_private_paged_zip
from human_source_continuity import create as create_human_source_continuity

MENU = (
    ("Create PRIVATE full source briefing + editable HUMAN worksheet",
     ("Original PRIVATE lab result JSON", "NEW PRIVATE output directory"),
     make_package),
    ("Compare two PRIVATE original lab source declarations",
     ("PRIVATE original before JSON", "PRIVATE original after JSON",
      "NEW PRIVATE output directory"),
     create_comparison),
    ("Create minimal PRIVATE count-only HUMAN briefing",
     ("Original PRIVATE lab result JSON", "NEW PRIVATE output directory"),
     create_aggregate),
    ("Import original HUMAN worksheet edits into PRIVATE report",
     ("Original PRIVATE lab result JSON", "Original briefing manifest.json",
      "Filled original human-followup.csv", "NEW PRIVATE output directory"),
     create_human_return),
    ("Build paged PRIVATE original finding library (up to 52 local pages)",
     ("Original PRIVATE lab result JSON", "NEW PRIVATE output directory"),
     make_paged_package),
    ("Package existing PRIVATE paged library as bounded UNENCRYPTED offline ZIP",
     ("EXISTING PRIVATE paged report directory", "NEW PRIVATE ZIP output directory"),
     create_private_paged_zip),
    ("Restore received PRIVATE UNENCRYPTED paged ZIP to NEW protected folder",
     ("Existing PRIVATE paged ZIP file", "NEW PRIVATE restored output directory"),
     restore_private_paged_zip),
    ("Produce PRIVATE severity × HUMAN attention matrix and ordinal queue",
     ("Original PRIVATE lab result JSON", "Original briefing manifest.json",
      "Filled original HUMAN CSV", "NEW PRIVATE output directory"),
     create_human_matrix),
    ("Draft NEXT-RUN HUMAN notes with strict source continuity and reset stages",
     ("Earlier original PRIVATE lab JSON", "Earlier PRIVATE briefing manifest",
      "Earlier human-filled original CSV", "Newer original PRIVATE lab JSON",
      "NEW PRIVATE proposal output directory"),
     create_human_source_continuity),
    ("Compare two source-bound original HUMAN worksheet revisions",
     ("Original PRIVATE lab result JSON", "Original briefing manifest.json",
      "Older human-followup.csv", "Newer human-followup.csv",
      "NEW PRIVATE output directory"),
     create_human_revision),
)


def one_path(title: str) -> str:
    value = input(title + ": ").strip()
    if not value or len(value) > 2048 or any(ord(x) < 32 for x in value):
        raise Hold("Invalid private local path (HOLD)")
    return value


def main() -> int:
    print("LightUp PRIVATE offline HUMAN briefing workroom")
    print("INCUBATE M3/M7 · LAB/PLAN ONLY · NOT PERMISSION, EXECUTION OR RELEASE")
    print("All inputs are already-produced PRIVATE local files; output must be a NEW directory.")
    for number, (title, _, _) in enumerate(MENU, 1):
        print(str(number) + ". " + title)
    try:
        selection = input("Choose 1-" + str(len(MENU)) + " (or anything else to cancel): ").strip()
        if selection not in {str(i) for i in range(1, len(MENU) + 1)}:
            print("Cancelled; no operation performed.")
            return 3
        title, labels, operation = MENU[int(selection)-1]
        print("\n" + title + "\n")
        paths = tuple(one_path(label) for label in labels)
        print("\nREVIEW ONLY. Original source claims and human notes are unverified.")
        print("Never use this tool for consent, assessment execution or security verdicts.")
        confirmation = input("Type REVIEW ONLY to create NEW PRIVATE output: ").strip()
        if confirmation != "REVIEW ONLY":
            print("Cancelled; no operation performed.")
            return 3
        operation(*paths)
    except (EOFError, KeyboardInterrupt, Hold) as exc:
        # Never include exception from imported file data or operating system.
        print("HOLD: cancelled or original PRIVATE source not admitted; no existing files changed.",
              file=sys.stderr)
        return 3
    print("PRIVATE package written. Human review required. No authorization granted.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
