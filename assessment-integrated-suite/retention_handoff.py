#!/usr/bin/env python3
"""Original local HUMAN retention history and source-drift, no deletion or grant."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "assessment-retention-desk"
SOURCES = {
    "history": ("history.py", "PRIVATE HUMAN timeline created (unsigned, non-authorizing, no source contents).",
                "PRIVATE-HUMAN-retention-history.html"),
    "drift": ("drift.py", "PRIVATE non-authorizing HUMAN source-drift briefing created.",
              "PRIVATE-HUMAN-source-drift.html"),
}


def held():
    print("HOLD: original PRIVATE HUMAN retention source/admission refused; no delete, grant or upload.",
          file=sys.stderr)
    return 3


def private(path: Path, directory: bool) -> bool:
    try:
        info = path.lstat()
        return info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077 and (
            stat.S_ISDIR(info.st_mode) if directory else
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 8 * 1024 * 1024)
    except OSError:
        return False


def produce(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        return held()
    if (not 2 <= len(args.plan) <= (12 if args.action == "history" else 2) or
            len(set(args.plan)) != len(args.plan)):
        return held()
    parent = Path(args.private_parent).absolute()
    if parent == ROOT or ROOT in parent.parents or not private(parent, True):
        return held()
    output = parent / args.prefix
    if os.path.lexists(output):
        return held()
    script, marker, name = SOURCES[args.action]
    script_path = ORIGINAL / script
    try:
        if not stat.S_ISREG(script_path.lstat().st_mode):
            return held()
        output.mkdir(mode=0o700)
        if not private(output, True):
            return held()
        report = output / name
        args_source = [str(Path(path).absolute()) for path in args.plan]
        result = subprocess.run(
            [sys.executable, "-P", str(script_path), "--output", str(report),
             *args_source], cwd=ROOT, capture_output=True, check=False,
            timeout=180, env={**os.environ, "PYTHONNOUSERSITE": "1",
                              "PYTHONDONTWRITEBYTECODE": "1"},
        )
        # The original held owner CLI uses 0 for a completed HUMAN-only report,
        # while an original source refusal exits 2; never reclassify either as
        # active authority. Exact native receipt and 0600 output are mandatory.
        if (result.returncode != 0 or len(result.stdout) > 4096 or len(result.stderr) > 4096
                or result.stdout.decode("utf-8", "strict").strip() != marker
                or not private(report, False)):
            return held()
        print("PRIVATE HUMAN REVIEW_ONLY: original source-owned " + args.action +
              " report available; no remediation claim.")
        print("OPEN LOCALLY: " + str(report))
        print("Original plan timestamps and HUMAN custody are declarations, never proof of consent or lawful deletion.")
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return held()


def main() -> int:
    parser = argparse.ArgumentParser(description="Original PRIVATE HUMAN retention comparison; never deletes")
    commands = parser.add_subparsers(dest="action", required=True)
    for mode in SOURCES:
        cmd = commands.add_parser(mode)
        cmd.add_argument("--plan", action="append", required=True,
                         help="2-12 existing original browser source-bound HUMAN JSON plans")
        cmd.add_argument("--private-parent", required=True)
        cmd.add_argument("--prefix", required=True)
    return produce(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
