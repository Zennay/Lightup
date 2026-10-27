#!/usr/bin/env python3
"""Original offline PRIVATE human agenda portfolio, no authority or scheduling."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile
from suite import Hold, ROOT, read_safe, parent_dir, original

PORTFOLIO = ROOT / "assessment-portfolio" / "portfolio.py"
ARCHIVE = ROOT / "assessment-archive" / "archive.py"

def prepare(args: argparse.Namespace) -> int:
    if not 1 <= len(args.agenda) <= 12:
        raise Hold("HOLD: 1-12 previously-produced original PRIVATE agendas required")
    owner = parent_dir(args.private_parent)
    read_safe(PORTFOLIO, 2 * 1024 * 1024)
    read_safe(ARCHIVE, 2 * 1024 * 1024)
    agendas = [str(Path(path).absolute()) for path in args.agenda]
    if len(set(agendas)) != len(agendas):
        raise Hold("HOLD: original HUMAN agenda was repeated")
    for path in agendas:
        read_safe(Path(path), 256 * 1024)
    if not args.as_of or len(args.as_of) != 10:
        raise Hold("HOLD: original HUMAN planning reference day must be YYYY-MM-DD")
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-portfolio-", dir=owner))
    os.chmod(kit, 0o700)
    finished = False
    try:
        args_list = sum((["--agenda", path] for path in agendas), [])
        args_list.extend(["--as-of", args.as_of])
        original(PORTFOLIO, [
            *args_list, "--format", "workspace-zip",
            "--output", str(kit / "PRIVATE-HUMAN-workroom.zip"),
        ])
        original(PORTFOLIO, [
            *args_list, "--format", "aggregate-html",
            "--output", str(kit / "PRIVATE-HUMAN-counts.html"),
        ])
        original(PORTFOLIO, [
            *args_list, "--format", "aggregate-json",
            "--output", str(kit / "PRIVATE-HUMAN-counts.json"),
        ])
        for file in ("PRIVATE-HUMAN-workroom.zip",
                     "PRIVATE-HUMAN-counts.html", "PRIVATE-HUMAN-counts.json"):
            read_safe(kit / file, 32 * 1024 * 1024)
        links = (
            ("PRIVATE full HUMAN workroom ZIP", "PRIVATE-HUMAN-workroom.zip"),
            ("PRIVATE counts-only original HUMAN summary", "PRIVATE-HUMAN-counts.html"),
            ("PRIVATE machine-readable counts-only HUMAN summary", "PRIVATE-HUMAN-counts.json"),
        )
        items = "".join(
            "<li><a href='" + html.escape(file, quote=True) + "'>" +
            html.escape(label) + "</a></li>" for label, file in links
        )
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE original HUMAN portfolio</title>
<style>body{font:17px/1.6 system-ui;max-width:820px;margin:3rem auto;padding:1rem}
li{margin:.7rem}a{color:#17618b}.warning{font-weight:700;color:#87361a}</style>
<h1>LightUp PRIVATE original HUMAN planning portfolio</h1>
<p class="warning">REVIEW_ONLY / HOLD — hypothetical human coordination,
not a scan, review signoff, verified vulnerability or approval.</p>
<p>Human-selected original private agendas: """ + str(len(agendas)) + """.
Planning reference date: """ + html.escape(args.as_of) + """.
No original agenda files were copied into this package.</p><ul>""" + items +
"""</ul><p>The ZIP contains source-bound private HUMAN planning content and
digest information: never distribute publicly. Unzip only in a newly created
owner-private directory on a trusted offline device; open the ZIP's index.html
locally to use existing capacity and collaboration studios. De-identified
summaries can still reveal sensitive small-cohort details.
No network, scheduler, customer notification, worker dispatch, model,
target assessment, grant, evidence collection, retest, deletion or publication
has occurred. INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></html>""")
        fd = os.open(kit / "OPEN-PRIVATE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(page)
        finished = True
        print("REVIEW_ONLY: PRIVATE original HUMAN portfolio prepared; no tasks scheduled.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not finished:
            shutil.rmtree(kit)

def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE offline HUMAN agendas; no scheduling or execution")
    p.add_argument("--agenda", action="append", required=True, help="1–12 original PRIVATE human agenda JSON files")
    p.add_argument("--as-of", required=True, help="original shared human reference date YYYY-MM-DD")
    p.add_argument("--private-parent", required=True, help="existing owner-controlled mode 0700 directory")
    args = p.parse_args()
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: PRIVATE original HUMAN portfolio refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
