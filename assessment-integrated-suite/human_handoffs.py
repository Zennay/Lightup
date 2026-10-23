#!/usr/bin/env python3
"""Foreground source-owned PRIVATE workspace continuity and notes routing.

All source operations are delegated to the original fixed local owner CLI.
No scan, consent, approval, network, job scheduling or outward publication.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    "ledger": ROOT / "assessment-workspace-ledger" / "ledger.py",
    "notes": ROOT / "private-assessment-notes" / "notes.py",
}
EXPECTED = {
    ("ledger", "capture"): ("PRIVATE REVIEW_ONLY", "PRIVATE HOLD: source-file differences require HUMAN review"),
    ("ledger", "reopen"): ("PRIVATE REVIEW_ONLY: recorded kit bytes currently match",),
    ("ledger", "finalize"): ("PRIVATE HOLD: HUMAN decisions recorded; never permission",),
    ("notes", "prepare"): ("REVIEW_ONLY: local PRIVATE notes workroom created",),
    ("notes", "finalize"): ("HOLD: PRIVATE HUMAN decision handoff locally prepared",),
}
MAX_OUTPUT = 8192


def private_page(location: str, parent: str) -> str:
    """Require a newly created owner-only page directly in a private child of parent."""
    base = Path(parent).absolute()
    page = Path(location)
    if not page.is_absolute() or page.name not in ("OPEN-PRIVATE.html", "HUMAN-private.html"):
        raise ValueError("private entry page identity")
    if page.parent.parent != base or ROOT == base or ROOT in base.parents:
        raise ValueError("private output location")
    for path, expect_dir in ((base, True), (page.parent, True), (page, False)):
        info = path.lstat()
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
                or (not expect_dir and info.st_nlink != 1)
                or (not stat.S_ISDIR(info.st_mode) if expect_dir else not stat.S_ISREG(info.st_mode))):
            raise ValueError("private output permissions")
    return str(page)


def run(kind: str, action: str, argv: list[str], private_parent: str | None) -> int:
    script = SOURCES[kind]
    source = script.lstat()
    if not stat.S_ISREG(source.st_mode) or source.st_size > 1024 * 1024:
        print("HOLD: original local source is absent or unsafe", file=sys.stderr)
        return 3
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(script), action, *argv],
            cwd=ROOT, capture_output=True, timeout=180, check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
            raise ValueError("bounded original response")
        rows = result.stdout.decode("utf-8", "strict").strip().splitlines()
        allowed = EXPECTED[(kind, action)]
        if not rows or not any(rows[0].startswith(prefix) for prefix in allowed):
            raise ValueError("original source refused or changed its response contract")
        expected_code = 3 if (action == "finalize" or
                              (kind == "ledger" and action == "capture" and rows[0].startswith("PRIVATE HOLD"))) else 2
        if result.returncode != expected_code:
            raise ValueError("original workflow returned an unexpected result")
        if action == "reopen":
            if len(rows) != 1:
                raise ValueError("unexpected original reopen response")
            print("REVIEW_ONLY: previously recorded exact PRIVATE kit bytes match.")
            return 2
        if len(rows) != 2 or not private_parent:
            raise ValueError("original output page missing")
        page = rows[1].removeprefix("OPEN LOCALLY: ").strip()
        page = private_page(page, private_parent)
        print("PRIVATE HUMAN HOLD: changed source or final decision is never an authorization."
              if expected_code == 3 else "PRIVATE REVIEW_ONLY: offline workroom prepared.")
        print("OPEN LOCALLY: " + page)
        return expected_code
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: native PRIVATE workflow refused; no release or outward action.", file=sys.stderr)
        return 3


def main() -> int:
    parser = argparse.ArgumentParser(description="LightUp original PRIVATE HUMAN handoff hub; no execution")
    cmds = parser.add_subparsers(dest="cmd", required=True)
    cap = cmds.add_parser("ledger-capture", help="capture 1-12 already-produced PRIVATE kits")
    cap.add_argument("--kit", action="append", required=True)
    cap.add_argument("--label", action="append")
    cap.add_argument("--previous")
    cap.add_argument("--private-parent", required=True)
    read = cmds.add_parser("ledger-reopen", help="read-only exact PRIVATE kit byte admission")
    read.add_argument("--ledger", required=True)
    fin = cmds.add_parser("ledger-finalize", help="finalize HUMAN review without granting authority")
    fin.add_argument("--ledger", required=True)
    fin.add_argument("--plan", required=True)
    fin.add_argument("--private-parent", required=True)
    notes = cmds.add_parser("notes-prepare", help="prepare PRIVATE credential-masked HUMAN review")
    notes.add_argument("--source", action="append", required=True)
    notes.add_argument("--private-parent", required=True)
    review = cmds.add_parser("notes-finalize", help="finalize original source-bound HUMAN notes")
    review.add_argument("--original-kit", required=True)
    review.add_argument("--decisions", required=True)
    review.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    if args.cmd == "ledger-capture":
        flags = sum((["--kit", path] for path in args.kit), [])
        if args.label:
            flags += sum((["--label", label] for label in args.label), [])
        if args.previous:
            flags += ["--previous", args.previous]
        return run("ledger", "capture", [*flags, "--private-parent", args.private_parent], args.private_parent)
    if args.cmd == "ledger-reopen":
        return run("ledger", "reopen", ["--ledger", args.ledger], None)
    if args.cmd == "ledger-finalize":
        return run("ledger", "finalize", ["--ledger", args.ledger, "--plan", args.plan,
                                         "--private-parent", args.private_parent], args.private_parent)
    if args.cmd == "notes-prepare":
        flags = sum((["--source", path] for path in args.source), [])
        return run("notes", "prepare", [*flags, "--private-parent", args.private_parent], args.private_parent)
    return run("notes", "finalize", ["--original-kit", args.original_kit, "--decisions", args.decisions,
                                      "--private-parent", args.private_parent], args.private_parent)


if __name__ == "__main__":
    raise SystemExit(main())
