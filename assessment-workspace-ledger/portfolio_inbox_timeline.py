#!/usr/bin/env python3
"""Build standalone CSP-pinned, source-free original HUMAN timeline viewer.

Original PRIVATE HUMAN data is loaded only after an operator separately selects
a native-derived local history JSON. Browser UI is unsigned preview only.
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
NAME = "portfolio_inbox_timeline.js"
MAX_JS = 262144


def read_source():
    fd = os.open(ROOT / NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_JS:
            reject("PRIVATE HOLD: invalid standalone HUMAN timeline software")
        data = bytearray()
        while True:
            fragment = os.read(fd, 65536)
            if not fragment:
                break
            data.extend(fragment)
            if len(data) > MAX_JS:
                reject("PRIVATE HOLD: oversized timeline browser software")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before,k)!=getattr(after,k) for k in fields) or
            len(data)!=before.st_size):
            reject("PRIVATE HOLD: timeline browser software changed while read")
        return bytes(data).decode("utf-8")
    finally:
        os.close(fd)


def render():
    script = read_source()
    if "</script" in script.casefold() or "\x00" in script:
        reject("PRIVATE HOLD: embedded JS has forbidden terminator")
    hash64 = lambda value: base64.b64encode(
        hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; base-uri 'none'; form-action 'none'; "
           "connect-src 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; "
           "style-src 'sha256-" + hash64(STYLE) +
           "'; script-src 'sha256-" + hash64(script) + "'")
    before = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="CSP-PLACEHOLDER">
<title>LightUp PRIVATE HUMAN Review History</title>
<style>''' + STYLE + '''</style></head><body>
<header><h1>LightUp · PRIVATE HUMAN History Explorer</h1>
<p>Source-bound original PRIVATE human proposals · Incubate M3/M7 · PLAN/LAB ONLY</p></header>
<main><section><h2>Open one ORIGINAL private native history</h2>
<p class="notice"><strong>Offline local HUMAN timeline, not an assessment.</strong>
Choose an existing original native
<code>PRIVATE-HUMAN-inbox-history.json</code> produced by console 39 or 40.
This browser makes only a schema-checked UNSIGNED preview, does not re-admit
original inputs, does not authenticate any reviewer, grant permission or
verify any security fix. Native <code>portfolio_inbox_history.py</code>
and original source owner remain the required admission boundary. No
network, tracking, storage, target access, APIs or automatic sharing.</p>
<label for="source">Select original owner-private history JSON (max 1 MiB)
<input id="source" type="file" accept=".json,application/json"></label>
<p id="status" class="status" role="status" aria-live="polite"></p></section>
<section id="room" hidden>
<h2>Original PRIVATE HUMAN timeline</h2><p id="total"></p>
<div class="controls">
<label for="ownerFilter">Original proposed HUMAN owner
<select id="ownerFilter"><option value="">All original owners</option></select></label>
<label for="round">Compare proposed HUMAN round
<select id="round"><option value="latest">Latest original HUMAN round</option></select></label>
<label for="stage">HUMAN proposed stage in selected round
<select id="stage"><option value="">All HUMAN stages</option>
<option value="needs_discussion">Needs discussion</option>
<option value="proposed_followup">Proposed follow-up</option>
<option value="hold">HOLD</option></select></label>
<label for="change">PRIVATE human changes across rounds
<select id="change"><option value="all">All original source slots</option>
<option value="changed">Stage or note changed</option>
<option value="stage">Stage changed</option>
<option value="note">Private HUMAN note changed (not its text)</option>
<option value="stable">No HUMAN change recorded</option></select></label>
<label for="search">Search original proposed HUMAN owner or source ordinal
<input id="search" type="search" placeholder="Search only locally in memory"></label>
</div><p id="shown"></p>
<div class="actions">
<button id="counts" type="button">Export anonymous visible HUMAN counts</button>
<button id="ownerCsv" type="button" class="secondary">Export PRIVATE owner-scoped visible CSV</button>
<button id="clear" type="button" class="secondary">Clear all selected source bytes</button>
</div><p><small>PRIVATE owner CSV is only available after selecting exactly one
proposed ORIGINAL owner; recipient identity is NOT authenticated. The
anonymous counts export has no owner names, source ordinals or source SHA.
Both exports describe HUMAN proposals, never a fix, consent, evidence
verification, work order or authorized scan. Browser Downloads may not be
private: manually move any PRIVATE CSV into 0700/0600 owner custody.</small></p>
<div id="cards"></div></section></main>
<footer>Local-only source-free HTML software · no approval, client identity,
permission, production release or actual assessment.</footer><script>'''
    return (before + script + "</script></body></html>\n").replace(
        "CSP-PLACEHOLDER", csp)


def build(args):
    path = Path(args.output)
    if not path.is_absolute() or path.suffix.lower() != ".html":
        reject("PRIVATE HOLD: NEW absolute .html destination required")
    private_parent(str(path.parent))
    if ROOT == path or ROOT in path.parents:
        reject("PRIVATE HOLD: cannot overwrite original software repository")
    raw = render().encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        count = 0
        while count < len(raw):
            count += os.write(fd, raw[count:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE HOLD: source-free offline HUMAN history explorer created")
    print(str(path), "unsigned software SHA256", hashlib.sha256(raw).hexdigest())
    return 2


def main():
    p = argparse.ArgumentParser(description="Build PRIVATE offline source-free HUMAN history explorer")
    p.add_argument("--output", required=True,
                   help="NEW .html inside an existing operator-private 0700 directory")
    a = p.parse_args()
    try:
        return build(a)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: original PRIVATE HUMAN software builder refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
