#!/usr/bin/env python3
"""Original source-bound PRIVATE evidence curation; HUMAN-only, offline.

Fixed original owner CLIs; never scans, verifies findings, issues grants or
sends customer material. No replacement of original records or older packages.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "assessment-evidence-curation"
COMMANDS = {
    "prepare": ("curate.py", "PRIVATE package created: human REVIEW ONLY; NO scan, approval or release",
                "PRIVATE-source-free-selection-studio.html",
                ("selection-template.csv", "selection-receipt.json",
                 "PRIVATE-source-free-selection-studio.html", "PRIVATE-selection-instructions.html")),
    "publish": ("curate.py", "PRIVATE package created: human REVIEW ONLY; NO scan, approval or release",
                "PRIVATE-curated-dossier.html",
                ("PRIVATE-curated-dossier.html", "PRIVATE-source-minimized-HUMAN-handoff.html",
                 "PRIVATE-curation-receipt.json", "anonymous-counts-PRIVATE.json")),
    "history": ("history.py", "PRIVATE HUMAN selection history prepared — REVIEW ONLY, no original findings verdict",
                "PRIVATE-human-curation-history.html",
                ("PRIVATE-human-curation-history.html", "PRIVATE-human-curation-history-receipt.json",
                 "human-curation-history-counts-PRIVATE.json")),
    "overview": ("review_hub.py", "PRIVATE HUMAN document overview generated, REVIEW ONLY; NO target or grant",
                 "PRIVATE-HUMAN-interactive-workroom.html",
                 ("PRIVATE-HUMAN-assessment-overview.html", "PRIVATE-HUMAN-interactive-workroom.html",
                  "PRIVATE-HUMAN-review-candidates-NOT-DISPATCHED.csv",
                  "PRIVATE-HUMAN-assessment-overview-receipt.json",
                  "PRIVATE-HUMAN-assessment-overview-counts.json")),
}


def hold() -> int:
    print("HOLD: original PRIVATE evidence-curation source/output refused; no scan, consent or release.",
          file=sys.stderr)
    return 3


def owned(path: Path, directory: bool = False) -> bool:
    info = path.lstat()
    return (info.st_uid == os.geteuid()
            and not (stat.S_IMODE(info.st_mode) & 0o077)
            and (stat.S_ISDIR(info.st_mode) if directory else
                 stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 24 * 1024 * 1024))


def produce(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        return hold()
    try:
        parent = Path(args.private_parent).absolute()
        if parent == ROOT or ROOT in parent.parents or not owned(parent, True):
            return hold()
        output = parent / args.prefix
        if os.path.lexists(output):
            return hold()
        script, receipt, page, files = COMMANDS[args.command]
        script_path = ORIGINAL / script
        source_info = script_path.lstat()
        if not stat.S_ISREG(source_info.st_mode) or not 0 < source_info.st_size <= 1024 * 1024:
            return hold()
        argv = [sys.executable, "-P", str(script_path)]
        if args.command in ("prepare", "publish"):
            argv.append(args.command)
        argv += ["--source", args.source, "--manifest", args.manifest,
                 "--worksheet", args.worksheet]
        if args.command != "prepare":
            argv += ["--selection-receipt", args.selection_receipt]
        if args.command in ("publish", "overview"):
            argv += ["--selection", args.selection]
        if args.command == "history":
            if not 2 <= len(args.selection) <= 12 or len(set(args.selection)) != len(args.selection):
                return hold()
            for item in args.selection:
                argv += ["--selection", item]
        argv += ["--output-dir", str(output)]
        result = subprocess.run(
            argv, cwd=ROOT, capture_output=True, check=False, timeout=240,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if (result.returncode != 2 or len(result.stdout) > 4096 or len(result.stderr) > 4096
                or result.stdout.decode("utf-8", "strict").strip() != receipt):
            return hold()
        if not owned(output, True) or not all(owned(output / file) for file in files):
            return hold()
        print("PRIVATE HUMAN REVIEW_ONLY — original source-bound evidence " + args.command + " prepared.")
        print("OPEN LOCALLY: " + str(output / page))
        print("Original identity, real consent, release and recipient authenticity remain unverified.")
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return hold()


def main() -> int:
    cli = argparse.ArgumentParser(description="Original PRIVATE selective lab evidence dossiers; never a scan or grant")
    modes = cli.add_subparsers(dest="command", required=True)
    for operation in COMMANDS:
        parser = modes.add_parser(operation)
        parser.add_argument("--source", required=True, help="already recorded original lab source JSON")
        parser.add_argument("--manifest", required=True, help="matching original PRIVATE briefing manifest")
        parser.add_argument("--worksheet", required=True, help="exact original seven-column HUMAN worksheet")
        parser.add_argument("--private-parent", required=True, help="existing 0700 private parent outside checkout")
        parser.add_argument("--prefix", required=True, help="unused unique PRIVATE folder name")
        if operation != "prepare":
            parser.add_argument("--selection-receipt", required=True)
        if operation in ("publish", "overview"):
            parser.add_argument("--selection", required=True)
        elif operation == "history":
            parser.add_argument("--selection", action="append", required=True)
    return produce(cli.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
