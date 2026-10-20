#!/usr/bin/env python3
"""Foreground original PRIVATE retention comparison guide; never deletes."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def prepare(session, path_prompt, ask, kind: str):
    parent = path_prompt("Existing owner-only 0700 PRIVATE output parent", session.parent)
    older = path_prompt("Existing ORIGINAL previous HUMAN retention plan JSON", session.retention_last_plan)
    later = path_prompt("Existing ORIGINAL current HUMAN retention plan JSON")
    plans = [older, later]
    if kind == "history":
        while len(plans) < 12:
            extra = ask("Further saved HUMAN plan in operator-declared order (empty to finish)", "")
            if not extra:
                break
            if len(extra) > 4096 or any(c in extra for c in "\x00\r\n"):
                raise ValueError("HOLD: invalid original source-bound HUMAN plan")
            plans.append(extra)
    print("Original PRIVATE HUMAN-only retention " + kind + ".")
    print("No source deletion, automatic retention change or consent verification.")
    print("Human-proposed deletion is only a human suggestion; absent never means fixed.")
    if ask("Confirm exactly REVIEW ONLY", "") != "REVIEW ONLY":
        print("HOLD: no original PRIVATE retention result created.")
        return
    prefix = ask("Unique unused PRIVATE output folder name", "human-retention-" + kind)
    flags = sum((["--plan", item] for item in plans), [])
    try:
        out = subprocess.run(
            [sys.executable, "-P", str(ROOT / "retention_handoff.py"), kind,
             "--private-parent", parent, "--prefix", prefix, *flags],
            cwd=ROOT.parent, capture_output=True, timeout=240, check=False,
            env={**os.environ, "PYTHONNOUSERSITE": "1",
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if out.returncode != 2 or len(out.stdout) > 4096 or len(out.stderr) > 4096:
            raise ValueError("original source refused")
        lines = out.stdout.decode("utf-8", "strict").strip().splitlines()
        if (len(lines) != 3 or lines[0] !=
                "PRIVATE HUMAN REVIEW_ONLY: original source-owned " + kind +
                " report available; no remediation claim."
                or not lines[1].startswith("OPEN LOCALLY: ")):
            raise ValueError("unexpected original private receipt")
        page = Path(lines[1][len("OPEN LOCALLY: "):])
        if len(str(page)) > 4096 or not page.is_file():
            raise ValueError("PRIVATE source-native page unavailable")
        print("REVIEW_ONLY: Open original private HUMAN retention report locally: " + str(page))
        session.parent, session.retention_last_plan, session.retention_workroom = (
            parent, plans[-1], str(page.parent))
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("HOLD: original PRIVATE HUMAN retention source refused; no state changed.")
