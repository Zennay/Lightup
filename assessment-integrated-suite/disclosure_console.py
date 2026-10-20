#!/usr/bin/env python3
"""Foreground PRIVATE HUMAN disclosure workroom; no grant or recipient send."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
HUB = ROOT / "disclosure_handoff.py"


def original(session, ask, path_prompt, action: str) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    flags = ["--private-parent", parent]
    if action == "prepare":
        sources = [path_prompt("Already-produced ORIGINAL PRIVATE lab JSON (first)", session.original)]
        while len(sources) < 12:
            value = ask("Optional next ORIGINAL PRIVATE lab JSON (empty to finish)", "")
            if not value:
                break
            if len(value) > 4096 or any(c in value for c in "\x00\r\n"):
                raise ValueError("HOLD: invalid original PRIVATE local source name")
            sources.append(value)
        flags += sum((["--source", path] for path in sources), [])
    else:
        receipt = path_prompt(
            "Exact original PRIVATE preflight receipt JSON",
            str(Path(session.disclosure_workroom) / "PRIVATE-receipt.json")
            if session.disclosure_workroom else "")
        answers = path_prompt(
            "Completed source-free PRIVATE HUMAN review CSV",
            str(Path(session.disclosure_workroom) / "PRIVATE-human-template.csv")
            if session.disclosure_workroom else "")
        flags += ["--receipt", receipt, "--answers", answers]

    floor = ask("Small-cohort suppression threshold, integer 5–12", "5")
    if floor not in [str(n) for n in range(5, 13)]:
        raise ValueError("HOLD: original minimum HUMAN suppression must be 5–12")
    flags += ["--minimum-cohort", floor]
    print("Original PRIVATE review operation: " + action)
    print("HUMAN notes, even count-only summaries, can be sensitive or identifying.")
    print("Original producer/source, recipients, operator/client consent and authority")
    print("must be separately established. Nothing is sent, authorized or released.")
    if ask("Confirm by typing exactly REVIEW ONLY", "") != "REVIEW ONLY":
        print("HOLD: PRIVACY disclosure review not confirmed. No output created.")
        return
    prefix = ask("Unique unused PRIVATE result folder name", "disclosure-human-" + action)
    if not prefix or len(prefix) > 40:
        raise ValueError("HOLD: new PRIVATE folder prefix required")
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(HUB), action, *flags, "--prefix", prefix],
            cwd=ROOT.parent, capture_output=True, check=False, timeout=300,
            env={**os.environ, "PYTHONNOUSERSITE": "1",
                 "PYTHONDONTWRITEBYTECODE": "1"})
        if (result.returncode != 2 or len(result.stdout) > 4096
                or len(result.stderr) > 4096):
            raise ValueError("original source-owned PRIVATE result refused")
        lines = result.stdout.decode("utf-8", "strict").strip().splitlines()
        if (len(lines) != 3 or lines[0] !=
                "PRIVATE REVIEW_ONLY: source-owned disclosure " + action +
                " generated; no external share."
                or not lines[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("original receipt not admitted")
        page = Path(lines[1][len("OPEN LOCALLY: "):])
        if len(str(page)) > 4096 or not page.is_file():
            raise ValueError("source-owned PRIVATE report missing")
        print("REVIEW_ONLY: original PRIVATE HUMAN " + action + " available locally:")
        print(str(page))
        session.parent = parent
        if action == "prepare":
            session.disclosure_workroom = str(page.parent)
        else:
            session.disclosure_review = str(page.parent)
        print("No client/operator permission, actual remedial fix or recipient delivery.")
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original PRIVATE disclosure refused; inspect any completed local outputs.")
