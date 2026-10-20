#!/usr/bin/env python3
"""Build original-source-free CSP-pinned PRIVATE HUMAN owner reply browser studio.

No private client or original owner data is embedded. Native strict source
admission and HUMAN-only return generation remain separate and mandatory.
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
SOURCE = "portfolio_owner_studio.js"
MAX_JS = 262144


def source_script():
    fd = os.open(ROOT / SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_JS:
            reject("PRIVATE HOLD: unsupported original browser source")
        raw = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_JS:
                reject("PRIVATE HOLD: original offline browser source exceeds byte limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns
        ) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: browser code changed during source-only build")
        return raw.decode("utf-8")
    finally:
        os.close(fd)


def render():
    script = source_script()
    if "</script" in script.casefold() or "\x00" in script:
        reject("PRIVATE HOLD: browser code cannot be safely embedded")
    sha = lambda text: base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "object-src 'none'; connect-src 'none'; frame-src 'none'; "
        "img-src 'none'; style-src 'sha256-" + sha(STYLE) +
        "'; script-src 'sha256-" + sha(script) + "'"
    )
    html = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="LOCAL_EXACT_SHA256_CSP">
<title>LightUp · PRIVATE HUMAN owner reply Studio</title><style>""" + STYLE + """</style></head>
<body><header><h1>LightUp · PRIVATE HUMAN Owner Reply Studio</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · Offline source-free browser</p></header>
<main><section><h2>Open original PRIVATE owner workroom</h2>
<p class="notice"><strong>Historical HUMAN suggestions, not authenticated decisions.</strong>
This local software does not authenticate a proposed HUMAN owner or client,
grant permission, perform a scan, schedule a task, prove findings or remediation,
or share original customer data. Move resulting CSV to 0600 PRIVATE custody
and run the native strict <code>portfolio_owner_reply.py</code> finalizer.</p>
<label for="source">Choose original 0600 PRIVATE-HUMAN-owner.json (max 1 MiB)
<input id="source" type="file" accept=".json,application/json"></label>
<p id="status" class="status" role="status" aria-live="polite"></p></section>
<section id="workroom" hidden><h2 id="owner"></h2><p id="totals"></p>
<div class="controls">
<label for="search">Local original HUMAN text search
<input id="search" type="search" placeholder="Search only in-memory"></label>
<label for="stageFilter">Local proposed HUMAN reply stage
<select id="stageFilter"><option value="">All original rows</option>
<option value="needs_discussion">Needs discussion</option>
<option value="proposed_followup">Proposed follow-up</option>
<option value="hold">HOLD</option></select></label>
</div><p id="visible"></p>
<label for="restore">Optional: restore original complete same-owner HUMAN reply CSV
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>Restore requires the exact original owner packet SHA-256, all
original row identities/order, and valid HUMAN-only fields. All proposals
are applied together only after explicit HUMAN confirmation. The native
original source admission remains mandatory.</small></p>
<div class="actions">
<button id="download" type="button">Export ALL original owner rows as PRIVATE HUMAN CSV</button>
<button id="clear" type="button" class="secondary">Clear selected PRIVATE data</button>
</div><p><small>Visual filters do not remove original source rows from export.
Downloaded CSV may be public within the host's Downloads folder; native
finalization requires trusted 0600 custody and original file bytes.</small></p>
<div id="cards" aria-label="Original owner HUMAN reply items"></div>
</section></main><footer>Offline browser only. No network, storage, model,
scan, grant, notification, scheduled action or authenticated HUMAN decision.</footer>
<script>""" + script + """</script></body></html>
"""
    return html.replace("LOCAL_EXACT_SHA256_CSP", csp)


def build(args):
    path = Path(args.output)
    if not path.is_absolute() or path.suffix.lower() != ".html":
        reject("PRIVATE HOLD: explicit new absolute .html output required")
    private_parent(str(path.parent))
    if path == ROOT or ROOT in path.parents:
        reject("PRIVATE HOLD: generated browser output cannot be inside source tree")
    raw = render().encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        count = 0
        while count < len(raw):
            count += os.write(fd, raw[count:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE REVIEW_ONLY: original-source-free CSP-pinned HUMAN owner Studio created")
    print("Byte length:", len(raw), "unsigned SHA256:", hashlib.sha256(raw).hexdigest())
    print(str(path))
    return 2


def main():
    parser = argparse.ArgumentParser(
        description="Produce source-free offline PRIVATE HUMAN owner reply Studio"
    )
    parser.add_argument("--output", required=True,
                        help="New .html file inside existing owner-private 0700 parent")
    args = parser.parse_args()
    try:
        return build(args)
    except (Hold, OSError, ValueError, UnicodeError):
        print("PRIVATE HOLD: original source-free HUMAN owner browser not built", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
