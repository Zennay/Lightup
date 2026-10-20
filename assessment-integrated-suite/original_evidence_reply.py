#!/usr/bin/env python3
"""Original PRIVATE HUMAN recipient/sender dialogue; no outbound action.

Uses fixed original owner response / triage / next-round producers. Human
answers are source-bound but NOT authenticated security or client consent.
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
ACTIONS = {
    "recipient-prepare": ("response.py", "prepare",
        "PRIVATE HUMAN response materials prepared; REVIEW ONLY, not an approved finding",
        ("PRIVATE-recipient-response-template.csv", "PRIVATE-recipient-browser-studio.html",
         "PRIVATE-recipient-response-binding.json"), "PRIVATE-recipient-browser-studio.html"),
    "recipient-return": ("response.py", "return",
        "PRIVATE HUMAN response materials prepared; REVIEW ONLY, not an approved finding",
        ("PRIVATE-recipient-HUMAN-replies.html", "PRIVATE-recipient-HUMAN-reply-receipt.json"),
        "PRIVATE-recipient-HUMAN-replies.html"),
    "sender-prepare": ("response_triage.py", "prepare",
        "PRIVATE HUMAN sender triage prepared — REVIEW ONLY; no grant, consent or remediation",
        ("PRIVATE-sender-triage-template.csv", "PRIVATE-sender-triage-browser.html",
         "PRIVATE-sender-triage-binding.json"), "PRIVATE-sender-triage-browser.html"),
    "sender-return": ("response_triage.py", "return",
        "PRIVATE HUMAN sender triage prepared — REVIEW ONLY; no grant, consent or remediation",
        ("PRIVATE-sender-HUMAN-triage.html", "PRIVATE-HUMAN-next-actions.csv",
         "PRIVATE-sender-HUMAN-triage-receipt.json"), "PRIVATE-sender-HUMAN-triage.html"),
    "next-round": ("next_round.py", None,
        "PRIVATE next-HUMAN-question selection PROPOSED only, no target permission or dispatch",
        ("PRIVATE-proposed-next-HUMAN-selection.csv", "PRIVATE-next-HUMAN-question-proposal.html",
         "PRIVATE-next-HUMAN-proposal-receipt.json"), "PRIVATE-next-HUMAN-question-proposal.html"),
}


def hold():
    print("HOLD: original PRIVATE HUMAN dialogue source/response refused; no recipient contacted.",
          file=sys.stderr)
    return 3


def safe_source(path: Path, folder: bool) -> bool:
    st = path.lstat()
    return (st.st_uid == os.geteuid() and not (stat.S_IMODE(st.st_mode) & 0o077)
            and (stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode)
                 and st.st_nlink == 1 and 0 < st.st_size <= 24 * 1024 * 1024))


def run(args):
    try:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", args.prefix):
            return hold()
        parent = Path(args.private_parent).absolute()
        if parent == ROOT or ROOT in parent.parents or not safe_source(parent, True):
            return hold()
        output = parent / args.prefix
        if os.path.lexists(output):
            return hold()
        script, mode, receipt, mandatory, entry = ACTIONS[args.action]
        path = ORIGINAL / script
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 1024 * 1024:
            return hold()
        flags = (["--source", args.source, "--manifest", args.manifest,
                  "--worksheet", args.worksheet,
                  "--selection-receipt", args.selection_receipt,
                  "--selection", args.selection])
        if args.action != "recipient-prepare":
            flags += ["--response-binding", args.response_binding, "--response", args.response]
        if args.action in ("sender-return", "next-round"):
            flags += ["--triage-binding", args.triage_binding, "--triage", args.triage]
        flags += ["--output-dir", str(output)]
        argv = [sys.executable, "-P", str(path)] + ([mode] if mode else []) + flags
        done = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False, timeout=240,
                              env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if (done.returncode != 2 or len(done.stdout) > 4096 or len(done.stderr) > 4096
                or done.stdout.decode("utf-8", "strict").strip() != receipt):
            return hold()
        if not safe_source(output, True) or not all(safe_source(output / f, False) for f in mandatory):
            return hold()
        print("PRIVATE HUMAN REVIEW_ONLY: source-bound " + args.action + " generated.")
        print("OPEN LOCALLY: " + str(output / entry))
        print("Original finding, client, reviewer, recipient and consent authority NOT verified.")
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return hold()


def main():
    parser = argparse.ArgumentParser(description="PRIVATE original HUMAN recipient dialogue, no dispatch, scan or consent")
    modes = parser.add_subparsers(dest="action", required=True)
    for action in ACTIONS:
        p = modes.add_parser(action)
        for field in ("source", "manifest", "worksheet", "selection-receipt", "selection",
                      "private-parent", "prefix"):
            p.add_argument("--" + field, required=True)
        if action != "recipient-prepare":
            for field in ("response-binding", "response"):
                p.add_argument("--" + field, required=True)
        if action in ("sender-return", "next-round"):
            for field in ("triage-binding", "triage"):
                p.add_argument("--" + field, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
