#!/usr/bin/env python3
"""Private multi-artifact archive of already-produced originals, never a scan."""
from __future__ import annotations
import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile
from suite import Hold, ROOT, parent_dir, read_safe, original

ARCHIVE = ROOT / "assessment-archive" / "archive.py"
MAX_ARCHIVE_SOURCE = 32 * 1024 * 1024

def prepare(args: argparse.Namespace) -> int:
    if not 2 <= len(args.source) <= 64:
        raise Hold("HOLD: original offline archive requires 2-64 explicit files")
    parent = parent_dir(args.private_parent)
    read_safe(ARCHIVE, 2 * 1024 * 1024)
    paths = [str(Path(s).absolute()) for s in args.source]
    if len(set(paths)) != len(paths):
        raise Hold("HOLD: repeated original source files are ambiguous")
    for path in paths:
        read_safe(Path(path), MAX_ARCHIVE_SOURCE)
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-archive-", dir=parent))
    os.chmod(kit, 0o700)
    ready = False
    try:
        manifest = kit / "PRIVATE-original-archive.json"
        original(ARCHIVE, ["capture", *paths, "--output", str(manifest)])
        original(ARCHIVE, [
            "view", "--manifest", str(manifest),
            "--output", str(kit / "PRIVATE-original-archive.html"),
        ])
        original(ARCHIVE, [
            "view", "--aggregate-only", "--manifest", str(manifest),
            "--output", str(kit / "PRIVATE-aggregate-archive.html"),
        ])
        original(ARCHIVE, [
            "share", "--manifest", str(manifest),
            "--output", str(kit / "PRIVATE-aggregate-archive.json"),
        ])
        names = (
            ("PRIVATE original source archive and digest inventory", "PRIVATE-original-archive.html"),
            ("PRIVATE exact-source unsigned manifest", "PRIVATE-original-archive.json"),
            ("PRIVATE no-source-digest aggregate view", "PRIVATE-aggregate-archive.html"),
            ("PRIVATE no-source-digest counts JSON", "PRIVATE-aggregate-archive.json"),
        )
        for _, name in names:
            read_safe(kit / name, 4 * 1024 * 1024)
        links = "".join(
            '<li><a href="' + html.escape(name, quote=True) + '">' +
            html.escape(label) + "</a></li>" for label, name in names
        )
        landing = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE original artifact archive</title>
<style>body{font:17px/1.6 system-ui;max-width:820px;margin:3rem auto;padding:1rem}
a{color:#1c5c82}li{margin:.6rem}.hold{font-weight:700;color:#89381f}</style>
<h1>LightUp PRIVATE original artifact archive</h1><p class="hold">REVIEW_ONLY / HOLD</p>
<p>Original locally selected artifacts: """ + str(len(paths)) + """. Every file was
handled only by the unchanged original offline archive source; original bytes
were not copied into this package.</p><ul>""" + links + """</ul>
<p>Source digest matching does not prove producer, client ownership, authentic
scope, ground truth, findings, grant, consent or review acceptance. Even counts
without hashes may be sensitive to a small cohort; review recipient permissions
separately before an external HUMAN-only handoff. Original targets, network,
models, grant issuance, retests and deletions were never invoked.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></html>""")
        fd = os.open(kit / "OPEN-PRIVATE.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(landing)
        ready = True
        print("REVIEW_ONLY: original PRIVATE local artifact archive published.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not ready:
            shutil.rmtree(kit)

def main() -> int:
    p = argparse.ArgumentParser(description="PRIVATE original offline artifact archive; no network")
    p.add_argument("--source", action="append", required=True, help="2–64 existing selected original files")
    p.add_argument("--private-parent", required=True, help="existing 0700 owner-controlled directory")
    args = p.parse_args()
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: original PRIVATE archive refused",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
