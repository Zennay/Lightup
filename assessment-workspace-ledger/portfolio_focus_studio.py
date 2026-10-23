#!/usr/bin/env python3
"""Build the standalone, source-free offline HUMAN focus browser editor.

Ships only software; chosen PRIVATE meeting data is never embedded, stored or
transmitted by this source-only renderer. The native source-bound finalizer
remains mandatory after local browser editing.
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

ROOT = Path(__file__).resolve().parent
JS_NAME = "portfolio_focus_studio.js"
MAX_SOURCE = 262144


def source_script():
    file = ROOT / JS_NAME
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_SOURCE:
            reject("PRIVATE HOLD: invalid original offline browser software source")
        raw = bytearray()
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            raw.extend(part)
            if len(raw) > MAX_SOURCE:
                reject("PRIVATE HOLD: browser software byte limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            reject("PRIVATE HOLD: original browser software changed during render")
        return bytes(raw).decode("utf-8")
    finally:
        os.close(fd)


STYLE = """body{margin:0;background:#edf3f8;color:#10233a;font:16px/1.55 system-ui,sans-serif}
header{padding:1.3rem max(1rem,calc((100vw - 1180px)/2));background:#112b46;color:#fff}
main{max-width:1180px;margin:1.2rem auto;padding:0 1rem 4rem}
h1,h2,h3{line-height:1.2}h1{margin:.2rem 0}h3{font-size:1.1rem}
section,.card{background:white;border:1px solid #afc0d0;border-radius:13px;padding:1.1rem;margin:1rem 0}
.notice{border-left:5px solid #a65316;padding:.9rem;background:#fff5e5}
.controls,.edit,.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.8rem}
.fact{display:grid;align-content:start;padding:.5rem;border-radius:8px;background:#f0f5fa;overflow-wrap:anywhere}
.fact strong{font-size:.85rem;color:#3b5569}.fact span{margin-top:.2rem}
label{display:grid;gap:.3rem;font-weight:600}input,select,textarea,button{font:inherit}
input,select,textarea{width:100%;box-sizing:border-box;border:1px solid #8e9fac;border-radius:7px;padding:.6rem}
textarea{resize:vertical;min-height:4rem}input:focus-visible,textarea:focus-visible,select:focus-visible,button:focus-visible{outline:3px solid #ed9700;outline-offset:2px}
button{padding:.7rem 1.1rem;border:0;border-radius:7px;background:#11557d;color:white;font-weight:700;cursor:pointer}
button.secondary{background:#365068}button:hover{filter:brightness(1.12)}
.actions{display:flex;flex-wrap:wrap;gap:.7rem}.status{padding:.7rem;background:#e1eef7;border-radius:7px;overflow-wrap:anywhere}
.card{border-left:5px solid #1b668f}.card h3{margin-top:0}
small{color:#465c6d}#summary{font-weight:700}#visibility{font-weight:600}
footer{max-width:1180px;padding:1rem;margin:auto;color:#31475a}
@media print{header,.controls,.actions,#source,.notice{display:none!important}
body{background:white}.card{page-break-inside:avoid;border:1px solid #888}}
"""


def render():
    script = source_script()
    # Script never contains a closing SCRIPT tag; protect composition from
    # accidental HTML breakout before hashing the exact shipped JS bytes.
    if "</script" in script.casefold() or "\x00" in script:
        reject("PRIVATE HOLD: browser source cannot be embedded safely")
    sha = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    css = base64.b64encode(hashlib.sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; "
        "connect-src 'none'; img-src 'none'; frame-src 'none'; "
        "style-src 'sha256-" + css + "'; "
        "script-src 'sha256-" + sha + "'"
    )
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="CSP_POLICY">
<title>LightUp · PRIVATE HUMAN Focus Studio</title><style>""" + STYLE + """</style>
</head><body>
<header><h1>LightUp · PRIVATE HUMAN Focus Studio</h1>
<p>Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · Offline HUMAN editor</p></header>
<main>
<section aria-labelledby="intro"><h2 id="intro">Open an original private meeting</h2>
<p class="notice"><strong>Local proposal editor only.</strong> Original assessment
source bytes are NOT reopened in this browser, and the source JSON is unsigned.
This preview does not authenticate reviewers, confirm consent, authorize a scan,
schedule a meeting, issue a grant, verify any finding or prove remediation.
Do not load unapproved client data. After export, use the native fail-closed
<code>portfolio_focus_review.py</code> finalizer with original source files.</p>
<label for="source">Choose owner-private PRIVATE-HUMAN-meeting.json (≤1 MiB)
<input id="source" type="file" accept=".json,application/json"></label>
<p id="status" class="status" role="status" aria-live="polite"></p></section>
<section id="workspace" hidden>
<h2 id="meetingTitle"></h2><p id="summary"></p>
<div class="controls">
<label for="query">Search original local human labels and notes
<input id="query" type="search" placeholder="Search only in memory"></label>
<label for="priority">Original HUMAN priority filter
<select id="priority"><option value="">All original priorities</option>
<option value="human_urgent">human urgent</option>
<option value="near_term">near term</option>
<option value="routine">routine</option><option value="unset">unset</option></select></label>
<label for="stage">New local meeting stage filter
<select id="stage"><option value="">All local stages</option>
<option value="needs_discussion">needs discussion</option>
<option value="proposed_followup">proposed follow-up</option>
<option value="hold">hold</option></select></label>
</div><p id="visibility"></p>
<label for="restore">Optional: restore original same-meeting HUMAN-review.csv
<input id="restore" type="file" accept=".csv,text/csv"></label>
<p><small>The whole original CSV must match source SHA and EVERY original
row in order; otherwise no local edits are applied. No native authentication
is claimed by this browser-only convenience.</small></p>
<div class="actions">
<button id="download" type="button">Export ALL rows as source-bound HUMAN CSV</button>
<button class="secondary" id="clear" type="button">Clear original local data</button></div>
<p><small>All original historical HUMAN entries export even when filtered
from the display. Downloads may be publicly readable; move the edited CSV
to owner-only 0600 custody before native original-source validation.</small></p>
<div id="rows" aria-label="Original local HUMAN proposals"></div>
</section></main><footer>Offline original human proposal draft. No network, storage,
target execution, authorization, consent, real scheduling or external sharing.</footer>
<script>""" + script + """</script></body></html>
""").replace("CSP_POLICY", policy)


def build(args):
    path = Path(args.output)
    if not path.is_absolute() or path.suffix.lower() != ".html":
        reject("PRIVATE HOLD: require absolute new .html software output path")
    private_parent(str(path.parent))
    if ROOT == path or ROOT in path.parents:
        reject("PRIVATE HOLD: source-only generated software stays outside checkout")
    body = render().encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(body):
            offset += os.write(fd, body[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("PRIVATE REVIEW_ONLY: source-free CSP-hash-pinned offline HUMAN editor built")
    print("Original software bytes:", len(body), "unsigned SHA256:", hashlib.sha256(body).hexdigest())
    print(str(path))
    return 2


def main():
    parser = argparse.ArgumentParser(description="Build original-source-free offline HUMAN focus browser studio")
    parser.add_argument("--output", required=True, help="New absolute local .html path in existing 0700 parent")
    args = parser.parse_args()
    try:
        return build(args)
    except (Hold, OSError, UnicodeError, ValueError):
        print("PRIVATE HOLD: offline HUMAN studio not built", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
