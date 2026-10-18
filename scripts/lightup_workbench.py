#!/usr/bin/env python3
"""One operator command surface for EXISTING private LAB review tools.

This is an additive routing shell around original source-owner CLIs. No scan
runner, request/grant, model, network, execution or test runner is imported.
All real artifact-producing operations retain their 2 REVIEW_ONLY / 3 HOLD
codes; no supplied evidence can become release authority.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "assessment-archive"
if not all(path.is_dir() for path in (ROOT / "src", ARCHIVE)):
    raise SystemExit("ORIGINAL_REVIEW_HOLD")
sys.path.insert(0, str(ARCHIVE))

import archive
import agenda
import console
import followup
import packet
import packet_inspect
import lightup_composed_review
import lightup_review

HANDLERS = {
    "review": lightup_review.main,
    "archive": archive.main,
    "studio": lambda arguments: archive.main(["studio", *arguments]),
    "followup": followup.main,
    "agenda": agenda.main,
    "packet": packet.main,
    "packet-inspect": packet_inspect.main,
    "console": console.main,
    "compose": lightup_composed_review.main,
}

def workbench(arguments):
    path = ROOT / "assessment-workspace" / "composed-workbench.html"
    if arguments in (["--help"], ["-h"]):
        print("Open the fully offline composed original Lab + Archive workbench locally.")
        print("Usage: python3 scripts/lightup_workbench.py workspace")
        return 0
    if arguments or not path.is_file():
        print("ORIGINAL_REVIEW_HOLD")
        return 3
    print("ORIGINAL_SOURCE_AND_ARCHIVE_OFFLINE_WORKSPACE — NOT AUTHORIZED")
    print(path.as_uri())
    return 2

HANDLERS["workspace"] = workbench


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(
        prog="lightup-workbench",
        description="Original lab comparator, archive, private human follow-up and "
                    "non-authorizing source-bound review. No network or execution.",
    )
    parser.add_argument("operation", choices=tuple(HANDLERS),
                        help="workspace (local original app links), review "
                             "(existing original CLI), compose (original comparison "
                             "plus archived review outputs), archive, studio, followup, "
                             "agenda, packet, packet-inspect or console")
    if not args or args[0] in ("-h", "--help"):
        parser.print_help()
        return 0 if args else 3
    command = args[0]
    if command not in HANDLERS:
        parser.print_usage(sys.stderr)
        print("ORIGINAL_REVIEW_HOLD")
        return 3
    return HANDLERS[command](args[1:])


if __name__ == "__main__":
    raise SystemExit(main())
