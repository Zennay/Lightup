#!/usr/bin/env python3
"""Human-only independent PRIVATE team handoff console integration."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
ORIGINAL_HUB = ROOT / "remediation_team.py"


def submit(flags: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(ORIGINAL_HUB), *flags],
            cwd=ROOT.parent, capture_output=True, timeout=240, check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if result.returncode != 2 or len(result.stdout) > 4096 or len(result.stderr) > 4096:
            raise ValueError("native original team admission refused")
        lines = result.stdout.decode("utf-8", "strict").strip().splitlines()
        if len(lines) != 3 or not lines[0].startswith("PRIVATE HUMAN REVIEW_ONLY: ") or not lines[1].startswith("OPEN LOCALLY: "):
            raise ValueError("unexpected original source status")
        file = Path(lines[1][len("OPEN LOCALLY: "):])
        if len(str(file)) > 4096 or not file.is_file():
            raise ValueError("private result page missing")
        print("REVIEW_ONLY: human-only source-bound original team packet prepared.")
        print("Open locally: " + str(file))
        print("Private team recipient identity and authorization still require HUMAN verification.")
        return True, str(file.parent)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original PRIVATE team source/packet refused. No external transfer.")
        return False, ""


def shared(session, path_prompt, ask):
    output = path_prompt("Owner-only 0700 PRIVATE output directory", session.parent)
    baseline = path_prompt("Original completed source-bound PRIVATE human mapping links JSON",
                           session.remediation_links)
    prefix = ask("Unused original PRIVATE team output prefix", "team-human-followup")
    return output, baseline, prefix


def prepare(session, path_prompt, ask):
    output, baseline, prefix = shared(session, path_prompt, ask)
    choices = []
    while len(choices) < 64:
        scenario = ask("Optional original scenario ID assigned to this team (empty for all)")
        if not scenario:
            break
        if len(scenario) > 256 or any(ord(c) < 32 for c in scenario):
            raise ValueError("HOLD: invalid original human scenario ID")
        choices += ["--scenario", scenario]
    ok, folder = submit(["prepare", "--links", baseline, "--output-dir", output,
                          "--prefix", prefix, *choices])
    if ok:
        session.parent, session.remediation_links, session.team_kit = output, baseline, folder
        print("The package contains human-only annotations, not original client findings or credentials.")
        print("Do not send it until the real recipient identity and scope are independently verified.")


def receive(session, path_prompt, ask):
    output, baseline, prefix = shared(session, path_prompt, ask)
    response = path_prompt("Untrusted PRIVATE team-return JSON")
    handoff = ask("Original separate team handoff JSON (required for subset)")
    flags = ["receive", "--links", baseline, "--returned", response,
             "--output-dir", output, "--prefix", prefix]
    if handoff:
        if len(handoff) > 4096 or any(c in handoff for c in "\x00\r\n"):
            raise ValueError("HOLD: invalid private handoff input")
        flags += ["--handoff", handoff]
    ok, folder = submit(flags)
    if ok:
        session.parent, session.remediation_links, session.team_kit = output, baseline, folder
        print("This is a human-only private before/after; original findings remain unchanged.")


def reconcile(session, path_prompt, ask):
    output, baseline, prefix = shared(session, path_prompt, ask)
    pairs = []
    for i in range(1, 13):
        first = ask(f"Original team handoff #{i} (empty after at least two complete pairs)")
        if not first and len(pairs) >= 2:
            break
        if not first or len(first) > 4096 or any(c in first for c in "\x00\r\n"):
            raise ValueError("HOLD: at least two exact original team handoff pairs required")
        second = path_prompt(f"Original returned HUMAN annotation JSON #{i}")
        pairs.append((first, second))
    if len(pairs) < 2:
        raise ValueError("HOLD: original multi-team reconciliation requires two pairs")
    flags = ["reconcile", "--links", baseline, "--output-dir", output, "--prefix", prefix]
    for handoff, _ in pairs:
        flags += ["--team-handoff", handoff]
    for _, returned in pairs:
        flags += ["--team-return", returned]
    ok, folder = submit(flags)
    if ok:
        session.parent, session.remediation_links, session.team_kit = output, baseline, folder
        print("Overlapping or contradictory original team assignments require HOLD.")
