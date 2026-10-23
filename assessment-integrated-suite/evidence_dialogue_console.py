#!/usr/bin/env python3
"""HUMAN-only native original evidence dialogue UI, local files only."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def execute(session, path_prompt, ask, action):
    original = path_prompt("Previously completed original PRIVATE lab JSON", session.evidence_source)
    manifest = path_prompt("Exact original PRIVATE source manifest", session.evidence_manifest)
    worksheet = path_prompt("Exact original HUMAN worksheet CSV", session.evidence_worksheet)
    receipt = path_prompt("Original selection receipt JSON",
                          str(Path(session.evidence_preparation) / "selection-receipt.json")
                          if session.evidence_preparation else "")
    selection = path_prompt("Original HUMAN-selected CSV", session.evidence_selection)
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    flags = ["--source", original, "--manifest", manifest, "--worksheet", worksheet,
             "--selection-receipt", receipt, "--selection", selection, "--private-parent", parent]
    reply = ""
    triage = ""
    if action != "recipient-prepare":
        binding = path_prompt(
            "Original response-bound recipient receipt JSON",
            str(Path(session.recipient_preparation) / "PRIVATE-recipient-response-binding.json")
            if session.recipient_preparation else "")
        reply = path_prompt("Returned source-bound PRIVATE recipient response CSV", session.recipient_reply)
        flags += ["--response-binding", binding, "--response", reply]
    if action in ("sender-return", "next-round"):
        binding = path_prompt(
            "Original sender triage-binding JSON",
            str(Path(session.sender_preparation) / "PRIVATE-sender-triage-binding.json")
            if session.sender_preparation else "")
        triage = path_prompt("Returned source-bound PRIVATE sender triage CSV", session.sender_triage)
        flags += ["--triage-binding", binding, "--triage", triage]
    print("Original source-backed local HUMAN dialogue stage: " + action)
    print("PRIVATE content can include client identifiers or reviewer notes.")
    print("No recipient is contacted. Identity, fixes and consent are NOT verified.")
    if ask("Confirm by typing REVIEW ONLY", "") != "REVIEW ONLY":
        print("HOLD: original HUMAN-only dialog not confirmed")
        return
    prefix = ask("Unique unused private output name", "human-" + action)
    try:
        done = subprocess.run(
            [sys.executable, "-P", str(ROOT / "original_evidence_reply.py"), action,
             *flags, "--prefix", prefix], cwd=ROOT.parent, capture_output=True,
            check=False, timeout=300,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if done.returncode != 2 or len(done.stdout) > 4096 or len(done.stderr) > 4096:
            raise ValueError("original source refused")
        lines = done.stdout.decode("utf-8", "strict").strip().splitlines()
        if (len(lines) != 3 or lines[0] != "PRIVATE HUMAN REVIEW_ONLY: source-bound " + action + " generated."
                or not lines[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("original source receipt missing")
        page = Path(lines[1][len("OPEN LOCALLY: "):])
        if len(str(page)) > 4096 or not page.is_file():
            raise ValueError("original PRIVATE HUMAN page missing")
        print("REVIEW_ONLY: Open the original PRIVATE HUMAN result locally: " + str(page))
        session.parent = parent
        session.evidence_source, session.evidence_manifest, session.evidence_worksheet = (
            original, manifest, worksheet)
        session.evidence_selection = selection
        if action == "recipient-prepare":
            session.recipient_preparation = str(page.parent)
        elif action == "recipient-return":
            session.recipient_reply = reply
        elif action == "sender-prepare":
            session.sender_preparation = str(page.parent)
        elif action == "sender-return":
            session.sender_triage = triage
        else:
            session.evidence_dossier = str(page.parent)
        print("No actual external receipt, recipient authentication, consent or security GO.")
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original source-native PRIVATE HUMAN dialogue refused; no outbound action.")
