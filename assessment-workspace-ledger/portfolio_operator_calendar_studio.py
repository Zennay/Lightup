#!/usr/bin/env python3
"""Build source-free offline HUMAN calendar browser Studio (no real scheduling)."""
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
JS = "portfolio_operator_calendar_studio.js"
MAX = 262144


def js_source():
    fd = os.open(ROOT / JS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX:
            reject("PRIVATE HOLD: invalid offline HUMAN calendar Studio source")
        raw = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX:
                reject("PRIVATE HOLD: oversized offline HUMAN calendar Studio source")
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, a) != getattr(after, a) for a in attrs) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: offline HUMAN calendar software changed during read")
        return raw.decode("utf-8")
    finally:
        os.close(fd)


def render():
    js = js_source()
    if "</script" in js.lower() or "\x00" in js:
        reject("PRIVATE HOLD: embedded source-free HUMAN JS refused")
    sha = lambda data: base64.b64encode(hashlib.sha256(data.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "connect-src 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; "
        "style-src 'sha256-" + sha(STYLE) + "'; script-src 'sha256-" + sha(js) + "'"
    )
    head = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="CSP-PLACEHOLDER">
<title>LightUp PRIVATE HUMAN review calendar Studio</title><style>''' + STYLE + '''</style></head>
<body><header><h1>LightUp · PRIVATE HUMAN proposed-review Studio</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · offline DRAFT/HOLD</p></header>
<main><section><h2>Open original native HUMAN calendar template</h2>
<p class="notice"><strong>HUMAN discussion-day proposals only.</strong>
Use console 56 to prepare an ORIGINAL source-bound 10-column PRIVATE HUMAN
calendar CSV. Select it below; this browser makes local edits and exports the
COMPLETE source-bound CSV. The browser never opens or verifies original client
material, authoritative permission, authenticated identities or actual work.
Console 57 remains the obligatory native exact-original receipt step.
No remote network, API, browser storage, scanner, grant, actual scheduling,
message, reminder, booking or recipient verification occurs.</p>
<label for="file">Select original HUMAN-proposed-calendar-template.csv (≤1 MiB)
<input id="file" type="file" accept=".csv,text/csv"></label>
<p id="status" role="status" aria-live="polite"></p></section>
<section id="room" hidden>
<h2>HUMAN-only original source proposal workroom</h2><p id="summary"></p>
<div class="controls">
<label for="owner">Proposed HUMAN owner
<select id="owner"><option value="">All owners</option></select></label>
<label for="priority">Human-only priority
<select id="priority"><option value="">All priorities</option>
<option value="unset">Unset</option><option value="human_urgent">Human urgent</option>
<option value="near_term">Near term</option><option value="routine">Routine</option></select></label>
<label for="proposal">HUMAN proposed day
<select id="proposal"><option value="all">All dates</option>
<option value="set">Date proposed</option><option value="empty">Unscheduled proposal</option></select></label>
<label for="query">Search owner, case and HUMAN questions locally
<input id="query" type="search" placeholder="Search PRIVATE memory only"></label>
</div>
<p id="visible"></p>
<label for="restore">Optional: reopen an earlier COMPLETE original-source HUMAN calendar CSV
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>Restore is all-or-nothing, source-ordinal- and original-byte-hash-bound.
No filtered subset export or assumed completion. Every original row is retained.</small></p>
<div class="actions"><button type="button" id="export">Export COMPLETE PRIVATE HUMAN calendar CSV</button>
<button type="button" id="clear" class="secondary">Clear local private workroom</button></div>
<div id="cards"></div></section></main>
<footer>Offline owner-private HUMAN editing only. No release approval,
real dates booked, actual tasks assigned, verified remediation or grants.</footer>
<script>'''
    return (head + js + "</script></body></html>\n").replace("CSP-PLACEHOLDER", csp)


def build(args):
    target = Path(args.output)
    if not target.is_absolute() or target.suffix.lower() != ".html":
        reject("PRIVATE HOLD: absolute NEW offline .html software path required")
    private_parent(str(target.parent))
    if target == ROOT or ROOT in target.parents:
        reject("PRIVATE HOLD: cannot write software over original repository")
    data = render().encode("utf-8")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        at = 0
        while at < len(data):
            at += os.write(fd, data[at:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE REVIEW_ONLY: local HUMAN calendar Studio software generated")
    print(str(target), "unsigned software SHA256", hashlib.sha256(data).hexdigest())
    return 2


def main():
    parser = argparse.ArgumentParser(description="Source-free offline HUMAN calendar editor builder")
    parser.add_argument("--output", required=True, help="NEW .html inside existing 0700 owner-private directory")
    args = parser.parse_args()
    try:
        return build(args)
    except (Hold, OSError, ValueError, UnicodeError):
        print("PRIVATE HOLD: offline HUMAN calendar Studio source refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
