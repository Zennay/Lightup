#!/usr/bin/env python3
"""PRIVATE original lab A/B declared drift, no verification or target interaction."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile
from suite import Hold, ROOT, read_safe, original, parent_dir, source

COMPARE = ROOT / "assessment-briefing" / "compare.py"
RESULTS = (
    ("PRIVATE original-declaration A/B differences", "private-drift.html"),
    ("PRIVATE original HUMAN follow-up worksheet", "human-drift-followup.csv"),
    ("Original unsigned source-byte manifest", "manifest.json"),
)

def prepare(args: argparse.Namespace) -> int:
    owner = parent_dir(args.private_parent)
    before = source(args.before)
    after = source(args.after)
    if before == after:
        raise Hold("HOLD: choose two different original source files")
    read_safe(COMPARE, 2 * 1024 * 1024)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-drift-", dir=owner))
    os.chmod(kit, 0o700)
    finished = False
    try:
        original(COMPARE, [
            "--before", before, "--after", after, "--output-dir", str(kit / "drift"),
        ])
        for _, file in RESULTS:
            read_safe(kit / "drift" / file, 8 * 1024 * 1024)
        links = "".join(
            "<li><a href='drift/" + html.escape(name, quote=True) + "'>" +
            html.escape(label) + "</a></li>" for label, name in RESULTS
        )
        page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE source drift</title>
<style>body{max-width:820px;margin:3rem auto;padding:1rem;font:17px/1.6 system-ui}
a{color:#176083}li{margin:.65rem}.warning{color:#823b19;font-weight:700}</style>
<h1>PRIVATE original lab source drift</h1>
<p class="warning">REVIEW_ONLY / HOLD. A change in claimed findings is not proof
of new exposure, repair, source authenticity, validated retest or consent.</p>
<ul>""" + links + """</ul><p>Original source A and B were admitted by the unchanged
native offline comparator. Source declarations are not verified by unsigned
hashes. Both selected original JSON files remain unmodified and were never
included in this PRIVATE kit. Keep all outputs offline and private; separate
authenticated permissions, independent security/privacy review and HUMAN GO
are required before any external release.</p>
<p>No DNS, network request, model, scan, grant, retest, deletion or production
deployment. INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.</p></html>""")
        fd = os.open(kit / "OPEN-PRIVATE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(page)
        finished = True
        print("REVIEW_ONLY: PRIVATE literal original-source drift prepared; not a retest.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not finished:
            shutil.rmtree(kit)

def main() -> int:
    cli = argparse.ArgumentParser(description="PRIVATE two-original-source HUMAN drift; no target scan")
    cli.add_argument("--before", required=True, help="already-produced original PRIVATE lab JSON A")
    cli.add_argument("--after", required=True, help="separately produced original PRIVATE lab JSON B")
    cli.add_argument("--private-parent", required=True, help="existing owner-controlled 0700 PRIVATE directory")
    args = cli.parse_args()
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: original source drift was refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
