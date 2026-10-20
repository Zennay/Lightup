#!/usr/bin/env python3
"""Foreground guided HUMAN-only lab → findings review, no assessment or authority."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
HUB = ROOT / "remediation_handoff.py"


def submit(flags: list[str]) -> tuple[bool, str]:
    try:
        output = subprocess.run(
            [sys.executable, "-P", str(HUB), *flags],
            cwd=ROOT.parent, capture_output=True, timeout=240,
            check=False, env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if len(output.stdout) > 4096 or len(output.stderr) > 4096:
            raise ValueError("oversized result")
        lines = output.stdout.decode("utf-8", "strict").strip().splitlines()
        if (output.returncode not in (2, 3) or len(lines) != 3 or
                not lines[0].startswith("PRIVATE ") or
                not lines[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("original owner source or bundle refused")
        page = Path(lines[1][len("OPEN LOCALLY: "):])
        if len(str(page)) > 4096 or not page.is_file():
            raise ValueError("private page is missing")
        print("HUMAN HOLD: original adverse source requires review; no fix/consent verified." if
              output.returncode == 3 else "REVIEW_ONLY: original PRIVATE human link packet prepared.")
        print("Open privately and locally: " + str(page))
        print("The original source and authenticated client/engagement identity MUST be checked independently.")
        return True, str(page.parent)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original source or PRIVATE output refused. No external execution.")
        return False, ""


def prepare(session, path_prompt, ask, cohorts=False):
    parent = path_prompt("Existing PRIVATE 0700 output directory outside repository", session.parent)
    source_flags = []
    if cohorts:
        source_flags += ["--baseline", path_prompt("Existing original complete baseline cohort JSON")]
        source_flags += ["--candidate", path_prompt("Existing original complete candidate cohort JSON")]
    else:
        source_flags += ["--comparison", path_prompt(
            "Existing ORIGINAL canonical completed cohort comparison JSON",
            session.original_comparison)]
    findings = path_prompt("Separately authenticated ORIGINAL five-column client findings CSV",
                           session.findings_csv)
    source_flags += ["--findings-csv", findings]
    old = ask("Optional existing ORIGINAL exact-source-bound HUMAN mapping JSON")
    if old:
        if len(old) > 4096 or any(c in old for c in "\x00\r\n"):
            raise ValueError("HOLD: invalid original local mapping name")
        source_flags += ["--links", old]
    prefix = ask("New unused PRIVATE output filename prefix", "human-followup")
    bundle = ask("Also prepare owner-private confidential recipient room ZIP? yes/no", "no")
    if bundle.lower() not in ("yes", "no"):
        raise ValueError("HOLD: answer yes or no")
    if bundle.lower() == "yes":
        source_flags.append("--bundle")
    command = "cohorts" if cohorts else "bridge"
    ok, folder = submit([command, *source_flags, "--output-dir", parent, "--prefix", prefix])
    if ok:
        session.parent = parent
        session.findings_csv = findings
        session.remediation_kit = folder
        session.remediation_links = str(Path(folder) / (prefix + "-links.json"))
        if not cohorts:
            session.original_comparison = source_flags[1]
        print("Manual mapping does not prove the sources belong to the same client or engagement.")
        print("Any private recipient ZIP remains confidential and is NOT sent or released.")


def prepare_casebook(session, path_prompt, ask, cohorts=False):
    """One foreground original remediation + exact-byte PRIVATE HUMAN workroom."""
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    flags = []
    if cohorts:
        flags += ["--baseline", path_prompt("Previously completed original baseline cohort JSON")]
        flags += ["--candidate", path_prompt("Previously completed original candidate cohort JSON")]
    else:
        flags += ["--comparison", path_prompt("Previously completed original canonical comparison JSON",
                                               session.original_comparison)]
    source = path_prompt("Original separately authenticated five-column findings CSV",
                         session.findings_csv)
    flags += ["--findings-csv", source]
    links = ask("Optional unchanged original source-bound HUMAN links JSON")
    if links:
        if len(links) > 4096 or any(c in links for c in "\x00\r\n"):
            raise ValueError("HOLD: invalid PRIVATE links input")
        flags += ["--links", links]
    prefix = ask("Unique private casebook prefix", "human-casebook")
    bundle = ask("Also create confidential local original review ZIP? yes/no", "no").lower()
    if bundle not in ("yes", "no"):
        raise ValueError("HOLD: choose yes or no")
    if bundle == "yes":
        flags += ["--bundle"]
    try:
        output = subprocess.run(
            [sys.executable, "-P", str(ROOT / "remediation_casebook.py"), *flags,
             "--private-parent", parent, "--prefix", prefix],
            cwd=ROOT.parent, capture_output=True, timeout=300, check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        if (output.returncode not in (2, 3) or len(output.stdout) > 4096
                or len(output.stderr) > 4096):
            raise ValueError("original private casebook rejected")
        rows = output.stdout.decode("utf-8", "strict").strip().splitlines()
        if (len(rows) != 3 or not rows[0].startswith("PRIVATE ")
                or not rows[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("original source output not confirmed")
        page = Path(rows[1][len("OPEN LOCALLY: "):])
        if not page.is_file() or len(str(page)) > 4096:
            raise ValueError("original local casebook page unavailable")
        print("PRIVATE HOLD: source requires HUMAN review; never verified consent or fix." if
              output.returncode == 3 else "PRIVATE REVIEW_ONLY: original casebook + ledger ready.")
        print("Open locally: " + str(page))
        session.parent, session.findings_csv, session.remediation_kit = parent, source, str(page.parent)
        if not cohorts:
            session.original_comparison = flags[1]
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: PRIVATE original source casebook refused; inspect any original-only output locally.")
