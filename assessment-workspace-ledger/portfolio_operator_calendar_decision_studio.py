#!/usr/bin/env python3
"""Source-free CSP-bound PRIVATE HUMAN proposal-reconciliation editor."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys

from ledger import Hold, private_parent, reject
from portfolio_focus_studio import STYLE

ROOT = Path(__file__).resolve().parent
JS = "portfolio_operator_calendar_decision_studio.js"
MAX = 262144


def read_js():
    fd = os.open(ROOT / JS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX:
            reject("PRIVATE HOLD: invalid source-free HUMAN decisions code")
        data = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX:
                reject("PRIVATE HOLD: oversized source-free HUMAN decisions")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            reject("PRIVATE HOLD: source-free HUMAN decisions code changed")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def render():
    js = read_js()
    if "</script" in js.casefold() or "\x00" in js:
        reject("PRIVATE HOLD: unexpected embedded HUMAN decision source")
    sha = lambda v: base64.b64encode(hashlib.sha256(v.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; "
        "object-src 'none'; frame-src 'none'; img-src 'none'; "
        "style-src 'sha256-" + sha(STYLE) +
        "'; script-src 'sha256-" + sha(js) + "'"
    )
    html = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="CSP-PLACEHOLDER">
<title>LightUp PRIVATE HUMAN Calendar Decision Studio</title><style>''' + STYLE + '''</style></head>
<body><header><h1>LightUp · PRIVATE HUMAN calendar decision workroom</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · offline DRAFT/HOLD</p></header>
<main><section><h2>Original-source-bound HUMAN calendar disagreement proposals</h2>
<p class="notice"><strong>This is a local HUMAN proposal editor, NOT a grant,
verified remediation, real appointment, security review or authority.</strong>
Use native console 62 to prepare a complete original-source-bound 13-column
HUMAN decision CSV from 2–8 original calendar proposal packets.
Select it below, edit every original slot as desired, then export the FULL
CSV. Native console 63 must independently read the original source and
every complete original receipt before a PRIVATE HUMAN decision packet exists.
This browser NEVER authenticates reviewers, original files or consent, and
never uses network, external scripts, storage, scanning or task scheduling.</p>
<label for="file">Select original HUMAN-calendar-decision-template.csv (≤1 MiB)
<input id="file" type="file" accept=".csv,text/csv"></label>
<p id="status" role="status" aria-live="polite"></p></section>
<section id="room" hidden><h2>Complete HUMAN-only source reconciliation</h2>
<p id="summary"></p>
<label for="options">Optional: open source-matching PRIVATE ORIGINAL HUMAN proposal alternatives JSON
<input id="options" type="file" accept=".json,application/json"></label>
<p><small>Native prepare provides PRIVATE-HUMAN-original-calendar-options.json:
original HUMAN candidate dates and priorities per round, without any previous
free-text question contents. This is an unsigned local preview. Copying one
candidate is an EXPLICIT human proposal and NEVER changes approval stage.</small></p>
<div class="controls">
<label for="owner">Filter proposed HUMAN owner
<select id="owner"><option value="">All proposed HUMAN owners</option></select></label>
<label for="stage">HUMAN proposal stage
<select id="stage"><option value="">All proposed stages</option>
<option value="needs_discussion">Needs discussion</option>
<option value="hold">HOLD</option>
<option value="human_alignment_proposed">Human alignment proposed</option></select></label>
<label for="conflict">Filter original HUMAN disagreements
<select id="conflict"><option value="all">All originals</option>
<option value="diff">Any original proposal difference</option>
<option value="stable">Identical proposals in inputs</option></select></label>
<label for="search">Local PRIVATE search by source or question
<input id="search" type="search"></label></div>
<p id="visible"></p>
<label for="restore">Restore earlier COMPLETE original-source HUMAN decision draft
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>Import matches the entire original source SHA, all original ordinals,
owner labels and conflict flags BEFORE changing any local choices. Filtering
does not remove any original rows. HUMAN alignment is never automatic.</small></p>
<div class="actions">
<button id="undo" type="button" class="secondary" disabled>Undo HUMAN edit</button>
<button id="redo" type="button" class="secondary" disabled>Redo HUMAN edit</button>
<button id="bulk-hold" type="button" class="secondary">Mark visible proposals HUMAN HOLD</button>
<button id="bulk-discuss" type="button" class="secondary">Mark visible proposals NEEDS DISCUSSION</button>
<button id="export" type="button">Export COMPLETE HUMAN decision CSV</button>
<button id="clear" type="button" class="secondary">Clear local private workroom</button></div>
<p id="history-summary" role="status">Local edit history: none.</p>
<p><small>Bulk decisions affect only the currently filtered visible original
source slots and require separate HUMAN confirmation. All original rows stay
in exports. Undo/redo is bounded local memory, reset on source replacement,
and never authenticates original records, reviewers, appointments or consent.</small></p>
<div id="cards"></div></section></main>
<footer>Offline human proposals only. No actual booking, grant, permission,
task assignment, reviewer identity or verified security result.</footer>
<script>'''
    return (html + js + "</script></body></html>\n").replace("CSP-PLACEHOLDER", csp)


def build(args):
    target = Path(args.output)
    if not target.is_absolute() or target.suffix.lower() != ".html":
        reject("PRIVATE HOLD: require NEW absolute PRIVATE .html software path")
    private_parent(str(target.parent))
    if target == ROOT or ROOT in target.parents:
        reject("PRIVATE HOLD: cannot overwrite original checkout")
    data = render().encode("utf-8")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        pos = 0
        while pos < len(data):
            pos += os.write(fd, data[pos:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE REVIEW_ONLY: source-free original HUMAN calendar decisions Studio built")
    print(str(target), "unsigned software SHA256", hashlib.sha256(data).hexdigest())
    return 2


def main():
    parser = argparse.ArgumentParser(description="Build portable source-free PRIVATE HUMAN decisions HTML")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        return build(args)
    except (Hold, OSError, TypeError, ValueError, UnicodeError):
        print("PRIVATE HOLD: offline HUMAN decisions Studio refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
