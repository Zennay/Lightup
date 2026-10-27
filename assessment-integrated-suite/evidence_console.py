#!/usr/bin/env python3
"""Guided native original PRIVATE evidence curation, no automatic disclosure."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PRODUCER = ROOT / "original_evidence.py"


def choose_origins(session, path_prompt):
    source = path_prompt("Existing ORIGINAL privately completed lab JSON", session.evidence_source)
    manifest = path_prompt("Matching ORIGINAL private source briefing manifest JSON", session.evidence_manifest)
    worksheet = path_prompt("Matching ORIGINAL seven-column HUMAN worksheet CSV", session.evidence_worksheet)
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent outside checkout", session.parent)
    return source, manifest, worksheet, parent


def run_native(action, args):
    try:
        done = subprocess.run(
            [sys.executable, "-P", str(PRODUCER), action, *args],
            cwd=ROOT.parent, capture_output=True, timeout=300, check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if done.returncode != 2 or len(done.stdout) > 4096 or len(done.stderr) > 4096:
            raise ValueError("original source refused")
        lines = done.stdout.decode("utf-8", "strict").strip().splitlines()
        if (len(lines) != 3 or lines[0] !=
                "PRIVATE HUMAN REVIEW_ONLY — original source-bound evidence " + action + " prepared."
                or not lines[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("unexpected source-owned receipt")
        page = Path(lines[1][len("OPEN LOCALLY: "):])
        if not page.is_file() or len(str(page)) > 4096:
            raise ValueError("original PRIVATE page unavailable")
        print("REVIEW_ONLY: original PRIVATE source-bound HUMAN evidence " + action + " generated.")
        print("Open locally on an authorized PRIVATE device: " + str(page))
        print("Recipient permission, client/operator consent and findings are NOT verified.")
        return str(page.parent)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original PRIVATE source/selection refused. No disclosure or external action.")
        return ""


def prepare(session, path_prompt, ask, action="prepare"):
    source, manifest, worksheet, parent = choose_origins(session, path_prompt)
    flags = ["--source", source, "--manifest", manifest, "--worksheet", worksheet,
             "--private-parent", parent]
    if action != "prepare":
        selection_receipt = path_prompt(
            "Exact-original preparation receipt JSON",
            str(Path(session.evidence_preparation) / "selection-receipt.json") if session.evidence_preparation else "")
        flags += ["--selection-receipt", selection_receipt]
        if action in ("publish", "overview"):
            flags += ["--selection", path_prompt("EXPLICIT HUMAN-selected original source-bound CSV",
                                                session.evidence_selection)]
        elif action == "history":
            count = ask("How many ordered ORIGINAL HUMAN selection CSV snapshots (2-12)?", "2")
            if count not in [str(n) for n in range(2, 13)]:
                raise ValueError("HOLD: 2-12 original HUMAN snapshots required")
            history = [path_prompt("Private HUMAN selection snapshot " + str(i)) for i in range(1, int(count) + 1)]
            flags += sum((["--selection", name] for name in history), [])
    label = {
        "prepare": "new offline HUMAN selection studio (source ordinal/severity/count only)",
        "publish": "selected-only FULL ORIGINAL PRIVATE evidence dossier",
        "history": "chronology of 2-12 locally recorded HUMAN selections (not verified dates)",
        "overview": "PRIVATE HUMAN review board, proposed owner actions, original selection",
    }[action]
    print("Original producer:", label)
    print("PRIVATE output may contain original client findings, human notes or confidential identifiers.")
    print("Nothing is verified, authorized, shared or sent. This does NOT approve an assessment.")
    if ask("Type exactly REVIEW ONLY to admit local ORIGINAL source", "") != "REVIEW ONLY":
        print("HOLD: original PRIVATE local HUMAN action not confirmed.")
        return
    prefix = ask("Unique unused owner-private result folder name", "human-evidence-" + action)
    flags += ["--prefix", prefix]
    folder = run_native(action, flags)
    if folder:
        session.parent, session.evidence_source, session.evidence_manifest, session.evidence_worksheet = (
            parent, source, manifest, worksheet)
        if action == "prepare":
            session.evidence_preparation = folder
            print("Use the generated PRIVATE-source-free-selection-studio.html to export your HUMAN choice CSV.")
        if action == "publish":
            session.evidence_dossier = folder
            session.evidence_selection = flags[flags.index("--selection") + 1]
            print("The source-minimized recipient questions are still PRIVATE, not approved for distribution.")
        if action in ("overview", "history"):
            session.evidence_dossier = folder
