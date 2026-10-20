#!/usr/bin/env python3
"""Bounded PRIVATE HUMAN review revision history of the same ORIGINAL source bytes.

No network, grant, scan, consent inference, verified fix, source mutation,
or automatic owner routing. Human statements remain human-only.
"""
from __future__ import annotations

import html
import json
from pathlib import Path
import sys

from change_brief import AUTHORITY, source, require_fresh_private_directory, write_private
from human_followup import FIELDS, STAGES, expected_files, human_text, worksheet

MAX_ROWS = 256

def admit_human(source_old, source_new, source_sha_old, source_sha_new, selected_rows):
    original = expected_files(source_old, source_new)
    if len(original) != len(selected_rows) or len(original) > MAX_ROWS:
        raise ValueError("Source-bound original HUMAN worksheet has wrong row count")
    result = []
    for i, (actual, identity) in enumerate(zip(selected_rows, original), start=1):
        if (actual[0], actual[1]) != (source_sha_old, source_sha_new) or tuple(actual[2:6]) != identity:
            raise ValueError("Source original identity/order drift at HUMAN row " + str(i))
        if actual[6] not in STAGES:
            raise ValueError("Unexpected HUMAN review phase")
        result.append((*identity, actual[6], human_text(actual[7], 80), human_text(actual[8], 500)))
    return result

def make_html(previous, latest, old_digest, new_digest):
    changes = []
    work = []
    for a, b in zip(previous, latest):
        stage_change = a[4] != b[4]
        team_change = a[5] != b[5]
        note_change = a[6] != b[6]
        if stage_change or team_change or note_change:
            changes.append((a, b, stage_change, team_change, note_change))
        if b[4] != "documented" or b[1] != "unchanged":
            work.append(b)
    def escape(x):
        return html.escape(x, quote=True)
    def row(before, after, sc, tc, nc):
        return ("<tr><td>" + escape(after[0]) + "</td><td>" + escape(after[1]) +
                "</td><td>" + escape(before[4]) + " → " + escape(after[4]) +
                "</td><td>" + escape(before[5]) + " → " + escape(after[5]) +
                "</td><td>" + ("Changed" if nc else "Unchanged") + "</td></tr>")
    def priority(b):
        return ("<tr><td>" + escape(b[0]) + "</td><td>" + escape(b[1]) +
                "</td><td>" + escape(b[4]) + "</td><td>" + escape(b[5]) +
                "</td><td>" + escape(b[6]) + "</td></tr>")
    styles = ("body{font:15px/1.6 system-ui;max-width:1200px;padding:24px;margin:auto;"
              "background:#0b1727;color:#f6f9ff}a{color:#a4d7ff}section{padding:18px;"
              "background:#1b2c42;border-radius:12px;margin:16px 0}table{width:100%;"
              "border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #526578;"
              "text-align:left;overflow-wrap:anywhere}th{background:#29415c}"
              "p{max-width:100ch}.hold{font-weight:700;color:#f8d38e}")
    content = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'none'; object-src 'none'; base-uri 'none'\">"
        "<title>PRIVATE ORIGINAL HUMAN revision desk — HOLD</title><style>" + styles + "</style>"
        "<main><h1>LightUp · PRIVATE HUMAN review history</h1>"
        "<p class='hold'>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN-ONLY, NOT a client/operator grant, "
        "release, source authentication, remediation or revoked/fixed finding.</p>"
        "<p>The same two original source manifests were re-admitted with exact byte identities. "
        "HUMAN revisions never establish authenticity of original records or real permissions. "
        "A locally absent file never implies fixed, revoked or authorized.</p>"
        "<p>Original source manifests: " + old_digest + " and " + new_digest + "</p>"
        "<section><h2>Human-only changed review fields (" + str(len(changes)) + ")</h2>"
        "<table><thead><tr><th>Original PRIVATE file</th><th>File change class</th>"
        "<th>Human phase before → now</th><th>Team before → now</th>"
        "<th>Private note</th></tr></thead><tbody>" +
        "".join(row(*r) for r in changes) +
        "</tbody></table></section><section><h2>Needs independent HUMAN attention (" +
        str(len(work)) + ")</h2><p>Items appear here when their source file is added/changed/absent "
        "or HUMAN stage is not yet documented. This is not a risk or remediation PASS/FAIL.</p>"
        "<table><thead><tr><th>Original PRIVATE file</th><th>File change</th>"
        "<th>HUMAN stage</th><th>HUMAN team</th><th>PRIVATE HUMAN notes</th>"
        "</tr></thead><tbody>" + "".join(priority(r) for r in work) +
        "</tbody></table></section><p class='hold'>No security work is authorized by this page.</p></main></html>"
    )
    return content.encode("utf-8"), changes, work

def main(argv):
    if len(argv) != 6:
        raise ValueError("usage: review_history.py PREVIOUS-SOURCE-MANIFEST.json CURRENT-SOURCE-MANIFEST.json EARLIER-HUMAN.csv LATEST-HUMAN.csv NEW-PRIVATE-OUT-DIR")
    old, old_heads, old_digest = source(Path(argv[1]))
    new, new_heads, new_digest = source(Path(argv[2]))
    before = admit_human(old, new, old_digest, new_digest, worksheet(Path(argv[3])))
    latest = admit_human(old, new, old_digest, new_digest, worksheet(Path(argv[4])))
    rendered, changes, attention = make_html(before, latest, old_digest, new_digest)
    anonymous = {
        "format": "lightup.private_human_revision_counts.v1",
        "posture": "INCUBATE_M3_M7_DRAFT_HOLD",
        "authority": {k: False for k in sorted(AUTHORITY)},
        "changed_human_rows": len(changes),
        "requiring_human_attention_rows": len(attention),
        # Private counts-only is not formal anonymity. Suppress categories of
        # one/two source rows to reduce small-cohort singling-out.
        "human_stage_transitions": {
            f"{a}->{b}": count for a in sorted(STAGES) for b in sorted(STAGES)
            if (count := sum(1 for prev, cur in zip(before, latest)
                             if prev[4] == a and cur[4] == b)) >= 3
        } if len(latest) >= 5 else {},
        "small_cohort": len(latest) < 5,
        "low_frequency_transitions_suppressed": True,
        "note": "Source-minimized aggregate only; a small cohort is NOT anonymous. Not validated security progress, fix proof, consent or client authority."
    }
    path = Path(argv[5])
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("New PRIVATE output requires ordinary existing parent directory")
    require_fresh_private_directory(path)
    write_private(path / "index.html", rendered)
    write_private(path / "anonymous-counts.json", (json.dumps(anonymous, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    print("PRIVATE HUMAN revisions:", path / "index.html")

if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError) as exc:
        print("HOLD:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(3)
