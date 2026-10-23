#!/usr/bin/env python3
"""Render source-free PRIVATE HUMAN owner history reply studio.

Unsigned local-only browser for operator-selected HUMAN proposals. It never
authenticates an owner or replaces original native source-bound admission.
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

ROOT=Path(__file__).resolve().parent
NAME="portfolio_inbox_owner_return_studio.js"
MAX_SOURCE=262144


def read_js():
    fd=os.open(ROOT/NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1<=before.st_size<=MAX_SOURCE:
            reject("PRIVATE HOLD: invalid original offline HUMAN owner browser software")
        raw=bytearray()
        while True:
            part=os.read(fd,65536)
            if not part:break
            raw.extend(part)
            if len(raw)>MAX_SOURCE:
                reject("PRIVATE HOLD: oversized HUMAN owner browser source")
        after=os.fstat(fd)
        fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")
        if any(getattr(before,f)!=getattr(after,f) for f in fields) or len(raw)!=before.st_size:
            reject("PRIVATE HOLD: HUMAN owner browser source changed")
        return bytes(raw).decode("utf-8")
    finally:
        os.close(fd)


def render():
    code=read_js()
    if "</script" in code.casefold() or "\x00" in code:
        reject("PRIVATE HOLD: invalid inline PRIVATE HUMAN owner software")
    hashed=lambda s:base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode("ascii")
    csp=("default-src 'none'; base-uri 'none'; form-action 'none'; "
         "connect-src 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; "
         "script-src 'sha256-"+hashed(code)+"'; style-src 'sha256-"+hashed(STYLE)+"'")
    start='''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="__CSP__">
<title>LightUp PRIVATE HUMAN Owner Reply Studio</title><style>'''+STYLE+'''</style>
</head><body><header><h1>LightUp · PRIVATE HUMAN Owner Reply Studio</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · Offline DRAFT/HOLD</p></header>
<main><section><h2>Open one original native PRIVATE HUMAN owner selection</h2>
<p class="notice"><strong>Historical human proposals only.</strong> Choose
a complete original <code>PRIVATE-HUMAN-history-selection.json</code>.
This browser does not authenticate recipient, client consent, findings,
task assignments, source hashes or real remediation. It sends no data.
Export a complete owner-only HUMAN CSV, then process the result using the
original native <code>portfolio_inbox_owner_return.py receive</code>
together with unchanged original selection, history and CSV.</p>
<label for="source">Choose original native PRIVATE-HUMAN-history-selection.json
<input id="source" type="file" accept=".json,application/json"></label>
<p id="status" class="status" role="status" aria-live="polite"></p></section>
<section id="room" hidden><h2 id="owner"></h2><p id="totals"></p>
<div class="controls"><label for="search">Search PRIVATE HUMAN source locally
<input id="search" type="search" placeholder="Source ordinal / proposed stage"></label>
<label for="stage">Filter local HUMAN replies (does not exclude CSV rows)
<select id="stage"><option value="">All HUMAN proposals</option>
<option value="needs_discussion">Needs discussion</option>
<option value="proposed_followup">Proposed follow-up</option>
<option value="hold">HOLD</option></select></label></div><p id="visible"></p>
<label for="restore">Optional complete original same-selection HUMAN reply draft CSV
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>Source SHA, exact original row order, every original stage and
all HUMAN values must match before a full HUMAN draft can be restored.
Rejected imports never replace existing choices.</small></p>
<div class="actions">
<button id="export" type="button">Export COMPLETE PRIVATE HUMAN reply CSV</button>
<button id="clear" type="button" class="secondary">Clear PRIVATE browser memory</button>
</div>
<p><small>Filtered rows are still included in the complete CSV. Move downloaded
PRIVATE HUMAN files out of shared Downloads into trusted owner-private 0700/0600
custody before native admission. SHA hashes are unsigned source identities,
not recipient authentication or consent. No email, scan, grant or action.</small></p>
<div id="cards"></div></section></main>
<footer>Source-free CSP-pinned software · no network, persistent storage,
actual task, verified fix, authorization or release.</footer><script>'''
    return (start+code+"</script></body></html>\n").replace("__CSP__",csp)


def build(args):
    target=Path(args.output)
    if not target.is_absolute() or target.suffix.lower()!=".html":
        reject("PRIVATE HOLD: require NEW absolute .html software output")
    private_parent(str(target.parent))
    if target==ROOT or ROOT in target.parents:
        reject("PRIVATE HOLD: cannot overwrite original software checkout")
    data=render().encode("utf-8")
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        offset=0
        while offset<len(data):offset+=os.write(fd,data[offset:])
        os.fsync(fd)
    finally:os.close(fd)
    print("PRIVATE HOLD: source-free original HUMAN owner Studio created; no transfer")
    print(str(target),"unsigned SHA256",hashlib.sha256(data).hexdigest())
    return 2


def main():
    p=argparse.ArgumentParser(description="Build source-free offline HUMAN owner reply Studio")
    p.add_argument("--output",required=True,help="NEW .html inside existing 0700 PRIVATE folder")
    a=p.parse_args()
    try:return build(a)
    except (Hold,OSError,UnicodeError,ValueError):
        print("PRIVATE HOLD: private HUMAN owner Studio software could not be produced",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
