#!/usr/bin/env python3
"""Original PRIVATE HUMAN team handoff and conflict-safe reconciliation adapter.

Only invokes original source-owned local file admission. No identity authentication
or authority to share externally, scan, retest, authorize or release is conferred.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from remediation_handoff import ROOT, private_output, bounded_file, held

ORIGINAL = ROOT / "assessment-remediation"
MAX_REPLY = 4096
ACTIONS = {
    "prepare": ("team_handoff.py", "PRIVATE_TEAM_HANDOFF_CREATED",
                ("-team-handoff.json", "-team-room.html", "-private-team-kit.zip")),
    "receive": ("team_handoff.py", "PRIVATE_TEAM_RETURN_ACCEPTED",
                ("-reviewed-links.json", "-private-team-diff.html", "-human-changes.json")),
    "reconcile": ("multi_team.py", "PRIVATE_MULTI_TEAM_HUMAN_RETURN_CREATED",
                  ("-reviewed-links.json", "-private-multi-team-diff.html",
                   "-human-changes.json", "-private-team-selection.json")),
}


def produce(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        return held("invalid private team output prefix")
    try:
        parent = private_output(args.output_dir)
    except (OSError, ValueError):
        return held("owner-private output directory required")
    script_name, marker, endings = ACTIONS[args.action]
    script = ORIGINAL / script_name
    try:
        if not stat.S_ISREG(script.lstat().st_mode):
            return held("original private team producer unavailable")
    except OSError:
        return held("original private team producer unavailable")
    required = [parent / (args.prefix + suffix) for suffix in endings]
    if any(os.path.lexists(path) for path in required):
        return held("private original team outputs already exist")
    flags = (["--links", args.links, "--output-dir", str(parent),
              "--prefix", args.prefix])
    if args.action == "prepare":
        for scenario in args.scenario:
            flags += ["--scenario", scenario]
    elif args.action == "receive":
        flags += ["--returned", args.returned]
        if args.handoff:
            flags += ["--handoff", args.handoff]
    else:
        if len(args.team_handoff) != len(args.team_return) or not 2 <= len(args.team_handoff) <= 12:
            return held("2–12 matching original private team handoff/return pairs required")
        for item in args.team_handoff:
            flags += ["--team-handoff", item]
        for item in args.team_return:
            flags += ["--team-return", item]
    # No inferred identities or grants. Optional original source renderer
    # intentionally remains a separate explicit original bridge command.
    try:
        argv = [sys.executable, "-P", str(script)]
        if args.action != "reconcile":
            argv.append(args.action)
        result = subprocess.run(
            [*argv, *flags], cwd=ROOT, capture_output=True, timeout=180,
            check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if (result.returncode != 2 or len(result.stdout) > MAX_REPLY
                or len(result.stderr) > MAX_REPLY):
            raise ValueError("original team producer refused")
        answer = result.stdout.decode("utf-8", "strict").splitlines()
        if not answer or not answer[0].startswith(marker):
            raise ValueError("unrecognized original team production receipt")
        if not all(bounded_file(path) for path in required):
            raise ValueError("incomplete private team product")
        page = required[1]
        print("PRIVATE HUMAN REVIEW_ONLY: " + args.action + " original source bound.")
        print("OPEN LOCALLY: " + str(page))
        print("Private human team identities, consent and recipients were NOT authenticated.")
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return held("original owner PRIVATE team workflow refused or incomplete")


def main() -> int:
    p = argparse.ArgumentParser(description="LightUp PRIVATE HUMAN team returns; never authorizes target work")
    sub = p.add_subparsers(dest="action", required=True)
    for action in ACTIONS:
        cmd = sub.add_parser(action)
        cmd.add_argument("--links", required=True)
        cmd.add_argument("--output-dir", required=True)
        cmd.add_argument("--prefix", required=True)
        if action == "prepare":
            cmd.add_argument("--scenario", action="append", default=[])
        elif action == "receive":
            cmd.add_argument("--returned", required=True)
            cmd.add_argument("--handoff")
        else:
            cmd.add_argument("--team-handoff", action="append", required=True)
            cmd.add_argument("--team-return", action="append", required=True)
    return produce(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
