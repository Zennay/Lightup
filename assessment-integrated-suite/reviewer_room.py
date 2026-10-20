#!/usr/bin/env python3
"""PRIVATE original multi-HUMAN plan reconciliation; never review authority."""
from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from suite import Hold, ROOT, parent_dir, read_safe, copy_app

ORIGINAL = ROOT / "assessment-reviewer-consensus/consensus.py"
BROWSER = ROOT / "assessment-reviewer-consensus/reviewer-studio.html"
COMMON = (
    ("Original PRIVATE conflicts", "private-conflicts.html"),
    ("Original PRIVATE HUMAN conflict resolver", "private-resolver.html"),
    ("Original PRIVATE unresolved/resolved choices JSON", "private-resolutions.json"),
    ("PRIVATE original count summary", "anonymous-counts.json"),
)
MERGED = ("Original PRIVATE merged HUMAN plan (not authorization)",
          "private-merged-original-plan.json")


def prepare(args: argparse.Namespace) -> int:
    if not 2 <= len(args.plan) <= 8:
        raise Hold("HOLD: original HUMAN reconciliation needs 2–8 plan packets")
    parent = parent_dir(args.private_parent)
    originals = [str(Path(p).absolute()) for p in args.plan]
    if len(set(originals)) != len(originals):
        raise Hold("HOLD: reviewer input paths cannot repeat")
    for filename in originals:
        read_safe(Path(filename), 3 * 1024 * 1024)
    for source in (ORIGINAL, BROWSER):
        read_safe(source, 2 * 1024 * 1024)
    requested = []
    if args.resolutions:
        path = Path(args.resolutions).absolute()
        read_safe(path, 3 * 1024 * 1024)
        requested = ["--resolutions", str(path)]
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-reviewers-", dir=parent))
    os.chmod(kit, 0o700)
    done = False
    try:
        native_dir = kit / "reconciliation"
        try:
            native = subprocess.run(
                [sys.executable, "-P", str(ORIGINAL), *originals,
                 "--output", str(native_dir), *requested],
                cwd=ROOT, capture_output=True, check=False, timeout=180,
                env={**os.environ, "PYTHONNOUSERSITE": "1"},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Hold("HOLD: original offline HUMAN reconciliation did not finish") from None
        if native.returncode not in (2, 3) or not native_dir.is_dir():
            raise Hold("HOLD: original HUMAN source admission refused")
        for _, filename in COMMON:
            read_safe(native_dir / filename, 3 * 1024 * 1024)
        counts_path = native_dir / "anonymous-counts.json"
        try:
            counts = json.loads(counts_path.read_text("utf-8"))
        except (OSError, ValueError, UnicodeError):
            raise Hold("HOLD: native original counts are invalid") from None
        if (type(counts) is not dict or
            counts.get("kind") != "lightup.anonymous_lab_human_reconciliation_counts" or
            type(counts.get("source_bound_human_plan_emitted")) is not bool):
            raise Hold("HOLD: unsupported original HUMAN output")
        resolved = counts["source_bound_human_plan_emitted"]
        if native.returncode != (2 if resolved else 3):
            raise Hold("HOLD: contradictory original HUMAN decision output")
        rows = list(COMMON)
        if resolved:
            read_safe(native_dir / MERGED[1], 3 * 1024 * 1024)
            rows.append(MERGED)
        copy_app(BROWSER, kit / "PRIVATE-original-reviewer-studio.html")
        links = "".join(
            "<li><a href='reconciliation/" + html.escape(file, quote=True) + "'>" +
            html.escape(title) + "</a></li>" for title, file in rows
        )
        state = "REVIEW_ONLY" if resolved else "HOLD"
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE multi-reviewer HUMAN room</title>
<style>body{max-width:870px;margin:3rem auto;padding:20px;font:17px/1.55 system-ui;
background:#eef3f8;color:#192638}main{background:white;border:1px solid #d1dfea;
border-radius:16px;padding:26px}a{color:#185c85}li{margin:.7rem}
b{color:#904020}</style><main><h1>PRIVATE original HUMAN reviewer workroom</h1>
<p><b>""" + state + """ · HUMAN-only · DRAFT/HOLD</b>.
Original separate reviewer packets: """ + str(len(originals)) + """.</p>
<p><a href="PRIVATE-original-reviewer-studio.html">Open the original complete
offline encrypted Reviewer Studio</a> to inspect original HUMAN plans and
resolve potential conflicts locally.</p><ul>""" + links + """</ul>
<p>Unresolved conflicts remain HOLD and no merged HUMAN proposal is provided.
If desired, separately save completed PRIVATE resolutions from the original
conflict resolver and rerun this launcher with --resolutions and the
**same exact original reviewer files in the same order** to produce a new
PRIVATE output. The original source code independently verifies byte
fingerprints and all enumerated HUMAN choices.</p>
<p>Even a complete original HUMAN consensus is not authenticated reviewer
identity, evidence or ground-truth verification, scope approval, client
consent, model permission, live dispatch or release. All outputs remain
PRIVATE, even aggregate small-group counts. No scan, network, grant,
model, retest or external handoff was performed.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
        fd = os.open(kit / "OPEN-PRIVATE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(page)
        done = True
        print("ORIGINAL HUMAN CONSENSUS: " + state +
              "; local PRIVATE workroom prepared; no verification or authority.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2 if resolved else 3
    finally:
        if not done:
            shutil.rmtree(kit)


def main() -> int:
    cli = argparse.ArgumentParser(
        description="PRIVATE original 2–8 HUMAN reviewer plan reconciliation, no source assessment"
    )
    cli.add_argument("--plan", action="append", required=True,
                     help="2–8 previously produced PRIVATE reviewer plans")
    cli.add_argument("--resolutions",
                     help="optional completed original source-bound PRIVATE conflict choices")
    cli.add_argument("--private-parent", required=True,
                     help="existing 0700 owner-controlled PRIVATE directory")
    args = cli.parse_args()
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: original PRIVATE HUMAN reviewer admission refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
