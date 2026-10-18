#!/usr/bin/env python3
"""Publish owner-private self-contained browser workspace for a validated archive.

Reads a single existing local manifest FD snapshot; never opens lab target
files or calls any model, scope, grant, handler, executor or network service.
"""
from __future__ import annotations

import argparse
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import sys

from archive import Hold, MAX_MANIFEST, _manifest, decode_json, publish, read_regular


TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-__JS_HASH__'; style-src 'sha256-__CSS_HASH__'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
<title>LightUp — Offline Assessment Archive Studio</title>
<style>__STYLES__</style></head><body>
<div class="shell">
<header class="header"><div class="brand">LIGHT<span>UP</span> / Lab Archive</div>
<span class="flag">PRIVATE · LAB ONLY · DRAFT/HOLD</span></header>
<section class="hero"><div class="eyebrow">ASSESSMENT-RUNTIME / SOURCE-BOUND WORKSPACE</div>
<h1>One place for every completed lab source.</h1>
<p>Review an existing offline archive snapshot, compare claimed source classes and plan human follow-up.
Nothing here scans, re-evaluates findings, authenticates a client, grants consent or clears a release.</p>
<span class="flag">ORIGINAL STATUS: __STATUS__ · NOT AUTHORIZED</span></section>
<div class="metrics" aria-label="Private archive inventory totals">
<div class="metric"><span class="eyebrow">Source slots</span><span class="value" id="total-count">—</span></div>
<div class="metric"><span class="eyebrow">Pending original</span><span class="value" id="pending-count">—</span></div>
<div class="metric"><span class="eyebrow">Needs review</span><span class="value" id="attention-count">—</span></div>
<div class="metric"><span class="eyebrow">Source classes</span><span class="value" id="source-class-count">—</span></div>
</div>
<section class="surface" id="history-panel" hidden>
<div class="eyebrow">Previous source archive · local bytes only</div>
<h2>Archive change overview</h2><p class="intro">A new source file is not a new vulnerability. An absent one is not fixed or cleared.</p>
<div class="metrics">
<div class="metric"><span class="eyebrow">New source bytes</span><span id="history-new" class="value">—</span></div>
<div class="metric"><span class="eyebrow">Not in current archive</span><span id="history-absent" class="value">—</span></div>
<div class="metric"><span class="eyebrow">Retained byte sources</span><span id="history-retained" class="value">—</span></div>
<div class="metric"><span class="eyebrow">Previous claimed state</span><span id="history-previous-state" class="value">—</span></div>
</div></section>
<div class="grid"><main class="surface">
<div class="eyebrow">Owner-private source index</div><h2>Source-by-source human review</h2>
<p class="intro">All source labels are generic and local. Original SHA-256 fingerprints are private byte-integrity hints, never independent authenticity proof.</p>
<div class="controls no-print">
<label>Find source slot or category<input id="search" type="search" placeholder="e.g. source 3 or cohort" autocomplete="off"></label>
<label>Claimed source class<select id="type-filter"><option value="">All source classes</option></select></label>
<label>Human stage<select id="stage-filter"><option value="">All stages</option></select></label>
<label id="history-filter-wrapper" hidden>Source history<select id="history-filter">
<option value="">All source bytes</option>
<option value="NEW_SOURCE_BYTES">New bytes</option>
<option value="RETAINED">Retained byte source</option>
</select></label>
</div>
<div class="button-row no-print">
<label>Follow-up role<select id="role-filter"><option value="">All roles</option></select></label>
<button id="clear-filter" class="action ghost" type="button">Clear filters</button>
</div>
<p class="small" id="shown-count" aria-live="polite"></p>
<section class="surface no-print" aria-label="Bulk human review coordination">
<div class="eyebrow">Batch follow-up · explicit confirmation required</div>
<h3>Coordinate all currently visible source slots</h3>
<p class="intro">Updates local human planning only, not original metrics, approval or permission. Filter the source list first.</p>
<div class="fields">
<label>Set human stage<select id="bulk-stage"><option value="">Keep current stage</option></select></label>
<label>Set next role<select id="bulk-role"><option value="">Keep current role</option></select></label>
<label>Proposed review date<input id="bulk-date" type="date" min="2020-01-01" max="2100-12-31"></label>
</div>
<div class="button-row"><button id="bulk-apply" class="action" type="button">Apply to visible sources</button>
<button id="bulk-undo" class="action ghost" type="button" disabled>Undo last batch update</button></div>
</section>
<div id="cards" class="list" aria-label="Original source review slots"></div>
</main>
<aside class="overview"><section class="surface">
<div class="eyebrow">Human coordination · never approval</div>
<h2>Local review stages</h2><ul id="stage-summary"></ul>
<div class="notice"><p>These stages describe a human conversation. None means PASS, clearance, remediation success, source ownership, valid customer consent or GO.</p></div>
</section><section class="surface no-print">
<h2>Private browser handoff</h2><p>Everything is held only in this tab’s memory. Save a local form and re-open it through the original Python CLI, which checks all source fingerprints.</p>
<div class="button-row">
<button class="action main" id="export-draft" type="button">Export private follow-up JSON</button>
<button class="action" id="export-summary" type="button">Export anonymous counts</button>
</div>
<label>Import matching human draft<input id="import-choices" type="file" accept=".json,application/json"></label>
<div class="button-row"><button id="print" class="action" type="button">Print current review</button>
<button id="reset-plan" class="action ghost" type="button">Discard local changes</button></div>
<p class="help">Browser downloads may not have private 0600 permissions. Store them in a secure directory and process with followup.py render before sharing. No original source records are included.</p>
</section></aside></div>
<footer class="surface"><div class="eyebrow">AUTHORITY FENCE</div><p>No model, network, browser persistence, lab target, scanner, execution capability, grant, certification or deployment is supplied by this studio.
Exact-head CI, original human source owners, independent privacy/security review, genuine separate client/operator consent,
revocation and explicit HUMAN GO remain outside and mandatory.</p>
<div class="status" role="status" aria-live="polite" id="status"></div></footer>
</div>
<script type="application/json" id="archive-seed">__SEED__</script>
<script>__SCRIPT__</script>
</body></html>
"""


def render_bytes(raw: bytes, original: dict, previous: dict | None = None) -> bytes:
    """Render from ONE original validated manifest byte snapshot."""
    assets = Path(__file__).resolve().parent
    script = (assets / "studio.js").read_text(encoding="utf-8")
    styles = (assets / "studio.css").read_text(encoding="utf-8")
    if not 0 < len(script) <= 80_000 or not 0 < len(styles) <= 30_000:
        raise Hold("invalid original local studio assets")
    seed = {
        "schema": "lightup.archive_studio_seed.v1",
        "status": original["status"],
        "manifest_sha256": sha256(raw).hexdigest(),
        "entries": original["entries"],
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    if previous is not None:
        before_hashes = {row["sha256"] for row in previous["entries"]}
        current_hashes = {row["sha256"] for row in original["entries"]}
        seed["entries"] = [{**row,
            "history": "RETAINED" if row["sha256"] in before_hashes else "NEW_SOURCE_BYTES"}
                           for row in original["entries"]]
        seed["history"] = {
            "previous_count": previous["source_count"],
            "new_count": len(current_hashes - before_hashes),
            "absent_count": len(before_hashes - current_hashes),
            "retained_count": len(before_hashes & current_hashes),
            "previous_status": previous["status"]
        }
    data = json.dumps(seed, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).replace("<", "\\u003c").replace("&", "\\u0026").replace(">", "\\u003e")
    hash_js = b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    hash_css = b64encode(sha256(styles.encode("utf-8")).digest()).decode("ascii")
    page = TEMPLATE
    for needle, value in (
        ("__JS_HASH__", hash_js), ("__CSS_HASH__", hash_css),
        ("__STYLES__", styles), ("__SCRIPT__", script),
        ("__SEED__", data), ("__STATUS__", original["status"])
    ):
        if page.count(needle) != 1:
            raise Hold("invalid local template")
        page = page.replace(needle, value)
    result = page.encode("utf-8")
    if len(result) > 512_000:
        raise Hold("rendered studio too large")
    return result


def build(manifest_path, output_path, previous_path=None):
    raw = read_regular(manifest_path, MAX_MANIFEST)
    original = _manifest(decode_json(raw))
    previous = (_manifest(decode_json(read_regular(previous_path, MAX_MANIFEST)))
                if previous_path is not None else None)
    publish(output_path, render_bytes(raw, original, previous))
    print("PRIVATE_ARCHIVE_STUDIO_CREATED — HISTORICAL SOURCE ONLY; NOT AUTHORIZED")
    return 3 if (original["status"] == "HOLD" or
                 previous is not None and previous["status"] == "HOLD") else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Render a private offline human-review studio from one existing local source archive.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--previous", help="Optional original previous private archive, read-only history")
    parser.add_argument("--output", required=True, help="New private self-contained HTML; never overwrite")
    args = parser.parse_args(argv)
    try:
        return build(args.manifest, args.output, args.previous)
    except (Hold, OSError, ValueError, TypeError, UnicodeError,
            RecursionError, OverflowError):
        print("ARCHIVE_STUDIO_HOLD — invalid or inaccessible original local manifest", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
