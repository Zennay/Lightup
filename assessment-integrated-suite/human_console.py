#!/usr/bin/env python3
"""Integrate original PRIVATE ledger and credential-masked note workflows in the human console."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
HUB = ROOT / "human_handoffs.py"


def call(flags: list[str], read_only: bool = False) -> tuple[bool, str]:
    try:
        reply = subprocess.run([sys.executable, "-P", str(HUB), *flags],
                               cwd=ROOT.parent, capture_output=True, timeout=240, check=False,
                               env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if len(reply.stdout) > 8192 or len(reply.stderr) > 8192:
            raise ValueError("oversized local output")
        lines = reply.stdout.decode("utf-8", "strict").strip().splitlines()
        if read_only:
            if reply.returncode != 2 or len(lines) != 1 or not lines[0].startswith("REVIEW_ONLY:"):
                raise ValueError("original private bytes changed")
            print("REVIEW_ONLY: original PRIVATE snapshot matches; not verified consent/provenance.")
            return True, ""
        if reply.returncode not in (2, 3) or len(lines) != 2 or not lines[0].startswith("PRIVATE "):
            raise ValueError("original private producer refused")
        prefix = "OPEN LOCALLY: "
        if not lines[1].startswith(prefix):
            raise ValueError("missing original private page")
        page = Path(lines[1][len(prefix):])
        if len(str(page)) > 4096 or not page.is_file():
            raise ValueError("missing private artifact")
        print("HOLD: HUMAN review is still required; no permission or release." if reply.returncode == 3
              else "REVIEW_ONLY: new PRIVATE offline workroom prepared.")
        print("Open locally: " + str(page))
        return True, str(page.parent)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original PRIVATE workflow refused; no external action performed.")
        return False, ""


def collect(label: str, path_prompt, ask, first: str = "") -> list[str]:
    paths = [path_prompt(label + " 1", first)]
    while len(paths) < 12:
        value = ask(label + " next (empty to finish)")
        if not value:
            break
        if len(value) > 4096 or any(char in value for char in "\x00\r\n"):
            raise ValueError("HOLD: invalid PRIVATE input path")
        paths.append(value)
    return paths


def ledger_capture(session, path_prompt, ask):
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    paths = collect("Already-produced owner-private kit directory", path_prompt, ask, session.initial_kit)
    previous = ask("Optional previous ledger.json (empty for initial capture)")
    flags = sum((["--kit", path] for path in paths), [])
    if previous:
        flags += ["--previous", previous]
    ok, folder = call(["ledger-capture", *flags, "--private-parent", parent])
    if ok:
        session.parent, session.ledger_kit = parent, folder
        print("Choose original ledger.json in the offline HUMAN ledger studio.")


def ledger_reopen(session, path_prompt, ask):
    default = str(Path(session.ledger_kit) / "ledger.json") if session.ledger_kit else ""
    path = path_prompt("Original owner-private ledger.json", default)
    call(["ledger-reopen", "--ledger", path], read_only=True)


def ledger_finalize(session, path_prompt, ask):
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    default = str(Path(session.ledger_kit) / "ledger.json") if session.ledger_kit else ""
    source = path_prompt("Original ledger.json", default)
    human = path_prompt("Completed source-bound PRIVATE HUMAN review CSV")
    call(["ledger-finalize", "--ledger", source, "--plan", human, "--private-parent", parent])


def notes_prepare(session, path_prompt, ask):
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    sources = collect("Owner-private UTF-8 assessment note", path_prompt, ask)
    flags = sum((["--source", path] for path in sources), [])
    ok, folder = call(["notes-prepare", *flags, "--private-parent", parent])
    if ok:
        session.parent, session.notes_kit = parent, folder
        print("Redaction is pattern-based and incomplete: HUMAN privacy review remains mandatory.")


def notes_finalize(session, path_prompt, ask):
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    original = path_prompt("Unchanged original PRIVATE masked-notes workroom", session.notes_kit)
    human = path_prompt("Completed original-source-bound PRIVATE HUMAN decisions CSV")
    call(["notes-finalize", "--original-kit", original,
          "--decisions", human, "--private-parent", parent])
