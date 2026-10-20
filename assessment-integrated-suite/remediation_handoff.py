#!/usr/bin/env python3
"""Original-source PRIVATE benchmark -> HUMAN follow-up launcher.

Never obtains permission, contacts a target or interprets findings as repaired.
Delegates source admission solely to the original held owner components.
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
ORIGINAL = ROOT / "assessment-remediation"
SCRIPTS = {"bridge": ORIGINAL / "bridge.py", "cohorts": ORIGINAL / "from_cohorts.py"}
MAX_REPLY = 4096


def held(reason: str) -> int:
    print("HOLD: " + reason + "; no security authority or external transfer.", file=sys.stderr)
    return 3


def private_output(parent: str) -> Path:
    path = Path(parent).absolute()
    if path == ROOT or ROOT in path.parents or not path.is_absolute():
        raise ValueError("PRIVATE output must remain outside checkout")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("PRIVATE output parent must be owned and mode 0700")
    return path


def bounded_file(path: Path) -> bool:
    try:
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and not (stat.S_IMODE(info.st_mode) & 0o077)
                and info.st_nlink == 1 and 0 < info.st_size <= 8 * 1024 * 1024)
    except OSError:
        return False


def run(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
        return held("invalid bounded private dossier prefix")
    try:
        output = private_output(args.output_dir)
    except (ValueError, OSError):
        return held("owner-private 0700 output location required")
    script = SCRIPTS[args.command]
    try:
        if not stat.S_ISREG(script.lstat().st_mode):
            return held("original native source is missing or unsafe")
    except OSError:
        return held("original native source unavailable")

    flags = ["--output-dir", str(output), "--prefix", args.prefix]
    if args.command == "bridge":
        flags += ["--comparison", args.comparison, "--findings-csv", args.findings_csv]
    else:
        flags += ["--baseline", args.baseline, "--candidate", args.candidate,
                  "--findings-csv", args.findings_csv]
    if args.links:
        flags += ["--links", args.links]
    if args.bundle:
        flags += ["--bundle"]
    required = [
        output / (args.prefix + suffix) for suffix in
        ("-private.html", "-links.json", "-aggregate.json", "-private-agenda.csv")
    ]
    if args.command == "cohorts":
        required += [output / (args.prefix + suffix) for suffix in
                     ("-canonical-comparison.json", "-mapping-studio.html")]
    if args.bundle:
        required.append(output / (args.prefix + "-private-room.zip"))
    # No overwrites, including a leftover completed packet or symlink.
    if any(os.path.lexists(path) for path in required):
        return held("one or more original PRIVATE packet files already exist")
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(script), *flags],
            cwd=ROOT, env={**os.environ, "PYTHONNOUSERSITE": "1",
                           "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, timeout=180, check=False,
        )
        if len(result.stdout) > MAX_REPLY or len(result.stderr) > MAX_REPLY:
            raise ValueError("unbounded native output")
        lines = result.stdout.decode("utf-8", "strict").splitlines()
        prefix = ("PRIVATE_ASSESSMENT_REMEDIATION_" if args.command == "bridge"
                  else "ORIGINAL_COMPLETE_COHORT_TO_REMEDIATION_")
        # A complete-cohort original producer first prints receipts from its
        # ORIGINAL comparator and canonical bridge. Its own terminal status is
        # deliberately last, never the first stdout line. Source IDs/evidence
        # in earlier output are never forwarded to the operator.
        if result.returncode not in (2, 3) or len(lines) < (3 if args.command == "cohorts" else 1):
            raise ValueError("source admission refused")
        receipts = [line for line in lines if line.startswith(prefix)]
        if len(receipts) != 1 or (args.command == "cohorts" and lines[-3] != receipts[0]) \
                or (args.command == "bridge" and lines[0] != receipts[0]):
            raise ValueError("original source receipt missing, duplicate or unexpected")
        original_posture = receipts[0][len(prefix):]
        if original_posture not in ("REVIEW_ONLY", "HOLD"):
            raise ValueError("unexpected original source declaration")
        if result.returncode != (2 if original_posture == "REVIEW_ONLY" else 3):
            raise ValueError("contradictory native result")
        if not all(bounded_file(path) for path in required):
            raise ValueError("one or more original private artifacts not published")
        print("PRIVATE " + original_posture + " — original source-bound HUMAN-only packet.")
        print("OPEN LOCALLY: " + str(required[0]))
        print("Separate authenticated client/operator authority, recipient and privacy review remain required.")
        return result.returncode
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return held("original PRIVATE packet admission or publication refused")


def main() -> int:
    p = argparse.ArgumentParser(description="Original offline lab-to-human follow-up; no scan or authorization")
    commands = p.add_subparsers(dest="command", required=True)
    for name, title in (("bridge", "existing canonical comparison + original client findings"),
                        ("cohorts", "existing original complete cohorts + original client findings")):
        c = commands.add_parser(name, help=title)
        if name == "bridge":
            c.add_argument("--comparison", required=True)
        else:
            c.add_argument("--baseline", required=True)
            c.add_argument("--candidate", required=True)
        c.add_argument("--findings-csv", required=True)
        c.add_argument("--links", help="optional manual exact-original source-bound PRIVATE mapping")
        c.add_argument("--output-dir", required=True)
        c.add_argument("--prefix", required=True, help="new unique name; no replacements")
        c.add_argument("--bundle", action="store_true", help="also create confidential offline recipient room ZIP")
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
