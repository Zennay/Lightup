#!/usr/bin/env python3
"""Build standalone unsigned source-free CSP-pinned HUMAN inbox Studio.

PRIVATE inbox bytes must be explicitly selected later by the human.
Never claims authenticated original sources, grants or verified remediation.
"""
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
SOURCE = "portfolio_inbox_studio.js"
MAX_JS = 262144


def source_script():
    fd = os.open(ROOT / SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or not 1 <= initial.st_size <= MAX_JS:
            reject("PRIVATE HOLD: invalid offline HUMAN inbox software source")
        content = bytearray()
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            content.extend(part)
            if len(content) > MAX_JS:
                reject("PRIVATE HOLD: original browser source too large")
        final = os.fstat(fd)
        if (initial.st_dev, initial.st_ino, initial.st_size,
            initial.st_mtime_ns, initial.st_ctime_ns) != (
            final.st_dev, final.st_ino, final.st_size,
            final.st_mtime_ns, final.st_ctime_ns
        ) or len(content) != initial.st_size:
            reject("PRIVATE HOLD: original offline inbox source changed")
        return bytes(content).decode("utf-8")
    finally:
        os.close(fd)


def render():
    script = source_script()
    if "</script" in script.casefold() or "\x00" in script:
        reject("PRIVATE HOLD: unsafe inline browser source")
    sha = lambda s: base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "object-src 'none'; connect-src 'none'; frame-src 'none'; img-src 'none'; "
        "style-src 'sha256-" + sha(STYLE) +
        "'; script-src 'sha256-" + sha(script) + "'"
    )
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="REPLACE-CSP-HERE">
<title>LightUp · PRIVATE HUMAN Inbox Studio</title><style>""" + STYLE + """</style></head>
<body><header><h1>LightUp · PRIVATE HUMAN Inbox Studio</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · HUMAN DRAFT/HOLD · Offline only</p></header>
<main><section><h2>Open original PRIVATE HUMAN assessment inbox</h2>
<p class="notice"><strong>Local HUMAN proposal editor.</strong> Selected original
inbox bytes are unsigned and do not independently prove who supplied them,
whether anyone consented, or that any security finding was fixed. This software
performs no API request, scan, grant, customer dispatch or real task assignment.
The complete original source-bound HUMAN CSV must still be processed by the
native <code>portfolio_owner_inbox_review.py</code> finalizer in 0700/0600
trusted PRIVATE custody. Do not upload client secrets to this UI.</p>
<label for="source">Choose original PRIVATE-HUMAN-owner-inbox.json (≤1 MiB)
<input id="source" type="file" accept=".json,application/json"></label>
<p id="status" class="status" role="status" aria-live="polite"></p></section>
<section id="workroom" hidden>
<h2 id="owner">Original HUMAN response inbox</h2><p id="totals"></p>
<div class="controls">
<label for="query">Search HUMAN owner and private original reply locally
<input id="query" type="search" placeholder="Search only in memory"></label>
<label for="ownerFilter">Filter originally proposed HUMAN owner
<select id="ownerFilter"><option value="">All source owners</option></select></label>
<label for="stageFilter">Filter new HUMAN discussion
<select id="stageFilter"><option value="">All human discussion stages</option>
<option value="needs_discussion">Needs discussion</option>
<option value="proposed_followup">Proposed follow-up</option>
<option value="hold">HOLD</option></select></label>
</div><p id="visible"></p>
<div class="controls">
<label for="bulkStage">Set only VISIBLE rows for explicitly filtered HUMAN owner
<select id="bulkStage">
<option value="needs_discussion">Needs discussion (HUMAN draft)</option>
<option value="proposed_followup">Proposed follow-up (HUMAN draft)</option>
<option value="hold">HOLD (HUMAN draft)</option>
</select></label>
<div><p>Only one selected original HUMAN owner, exact currently visible
filters and explicit local HUMAN confirmation are allowed.</p>
<button id="bulkApply" type="button" class="secondary">
Set visible HUMAN discussion proposals</button></div>
</div>
<label for="restore">Optional: restore complete same-inbox HUMAN review CSV
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>Original inbox SHA, every original case/transition/kit and entire
row order must match. Existing local changes survive a rejected restore.</small></p>
<div class="actions">
<button id="download" type="button">Export ALL original HUMAN slots to private CSV</button>
<button id="clear" type="button" class="secondary">Clear selected PRIVATE data</button>
</div><p><small>Filters never drop original source rows. Downloads may initially
be saved to a browser-accessible Downloads folder; move them into trusted
0600 private custody before native import. No actual work assigned.</small></p>
<div id="cards" aria-label="Original source-bound HUMAN meeting rows"></div>
</section></main>
<footer>Source-free offline software · no network · no persistent state ·
no reviewer authentication, active security scan, grants or approvals.</footer>
<script>""" + script + """</script></body></html>
""").replace("REPLACE-CSP-HERE", csp)


def build(args):
    path = Path(args.output)
    if not path.is_absolute() or path.suffix.lower() != ".html":
        reject("PRIVATE HOLD: explicit new absolute HTML output required")
    private_parent(str(path.parent))
    if ROOT in path.parents or path == ROOT:
        reject("PRIVATE HOLD: generated software cannot overwrite original source")
    raw = render().encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE HOLD: original source-free HUMAN inbox Studio software created")
    print(str(path), "unsigned SHA256:", hashlib.sha256(raw).hexdigest())
    return 2


def main():
    ap = argparse.ArgumentParser(
        description="Build source-free standalone offline HUMAN inbox browser Studio"
    )
    ap.add_argument("--output", required=True,
                    help="NEW absolute .html path inside existing 0700 PRIVATE parent")
    a = ap.parse_args()
    try:
        return build(a)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: HUMAN inbox browser software could not be produced", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
