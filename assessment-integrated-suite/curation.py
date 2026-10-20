#!/usr/bin/env python3
"""PRIVATE original-source HUMAN selection after a native integrated briefing."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile
from suite import Hold, parent_dir, read_safe, source, original, ROOT

CURATE = ROOT / "assessment-evidence-curation" / "curate.py"
OUTPUTS = (
    ("HUMAN private selection studio", "PRIVATE-source-free-selection-studio.html"),
    ("Complete source-bound HUMAN selection CSV", "selection-template.csv"),
    ("Original unsigned selection receipt", "selection-receipt.json"),
    ("HUMAN selection instructions", "PRIVATE-selection-instructions.html"),
)

def prepare(args: argparse.Namespace) -> int:
    parent = parent_dir(args.private_parent)
    prior = parent_dir(args.original_kit)
    input_file = source(args.source)
    manifest = prior / "briefing" / "manifest.json"
    worksheet = prior / "briefing" / "human-followup.csv"
    for p in (CURATE, manifest, worksheet):
        read_safe(p, 2 * 1024 * 1024)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-curation-", dir=parent))
    os.chmod(kit, 0o700)
    done = False
    try:
        original(CURATE, [
            "prepare", "--source", input_file, "--manifest", str(manifest),
            "--worksheet", str(worksheet), "--output-dir", str(kit / "curation"),
        ])
        for _, name in OUTPUTS:
            read_safe(kit / "curation" / name, 2 * 1024 * 1024)
        li = "".join(
            "<li><a href='curation/" + html.escape(name, quote=True) + "'>" +
            html.escape(title) + "</a></li>"
            for title, name in OUTPUTS
        )
        webpage = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE original HUMAN selection</title>
<style>body{font:17px/1.6 system-ui;max-width:800px;margin:3rem auto;padding:1rem}
li{margin:.75rem}a{color:#185e92}strong{color:#863d21}</style>
<h1>LightUp original-source HUMAN curation</h1>
<p><strong>REVIEW_ONLY / HOLD</strong>: no original finding, actor, consent or
security result is verified by a source hash or local HUMAN selection.</p><ul>""" + li +
"""</ul><p>Original source unchanged. Open locally only on a trusted private
computer. The PRIVATE recipient output requires separately validated owner and
current client/operator consent; this interface grants nothing and runs no scan,
model, retest, publication or target activity.</p>
<p>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></html>""")
        fd = os.open(kit / "OPEN-PRIVATE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(webpage)
        done = True
        print("REVIEW_ONLY: exact-original HUMAN curation prepared; no authorization.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not done:
            shutil.rmtree(kit)

def main() -> int:
    p = argparse.ArgumentParser(description="Original source bound HUMAN selection — no scan")
    p.add_argument("--source", required=True, help="same original PRIVATE source used by --brief")
    p.add_argument("--original-kit", required=True, help="existing PRIVATE bundle made with suite.py --brief")
    p.add_argument("--private-parent", required=True, help="existing owner-only mode 0700 directory")
    args = p.parse_args()
    try:
        return prepare(args)
    except (Hold, ValueError, OSError) as err:
        print(str(err) if isinstance(err, Hold) else "HOLD: original HUMAN curation refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
