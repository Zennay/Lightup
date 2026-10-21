#!/usr/bin/env python3
"""Render private offline original-owner HUMAN proposal decisions.

Only human stage, team and notes exist here. Explicitly selected stage
proposals produce a fresh private original-format HUMAN CSV; no actual
authorization, scan, revocation, client consent or original data mutation.
"""
from __future__ import annotations
import base64
import hashlib
import html
from pathlib import Path

MAX_SCRIPT = 24000
STAGES = {"unreviewed","investigating","escalated","documented"}
CSS = """
:root{color-scheme:dark}*{box-sizing:border-box}body{font:15px/1.6 system-ui,sans-serif;background:#111b2b;color:#eef6ff;max-width:1300px;margin:auto;padding:24px}h1{font-size:clamp(1.6rem,3.5vw,2.4rem)}h2{font-size:1.2rem}p{max-width:108ch}.warning{padding:16px;background:#332a18;border:1px solid #9d8859;border-radius:8px;color:#ffe3a7}section{background:#1c2b40;padding:16px;border-radius:12px;margin:16px 0}.tools{display:flex;flex-wrap:wrap;gap:12px;align-items:center}table{width:100%;min-width:1050px;border-collapse:collapse}th,td{padding:10px;vertical-align:top;border-bottom:1px solid #415974;text-align:left;overflow-wrap:anywhere}th{position:sticky;top:0;background:#2b435c}tr:nth-child(2n){background:#23354a}tr[hidden]{display:none}small{font-size:12px;color:#b8d2eb}code{overflow-wrap:anywhere}select,textarea,button{font:inherit;background:#283f57;color:#f1faff;border:1px solid #7196b7;border-radius:7px;padding:8px}textarea{min-width:160px;width:100%;min-height:65px}button{cursor:pointer;background:#3e678e;font-weight:600}button:hover{background:#4279a9}select:focus-visible,textarea:focus-visible,button:focus-visible{outline:3px solid #97d0ff}.table-wrap{overflow:auto;max-height:76vh}.hold{font-weight:700;color:#ffd494}output{display:block;margin-top:8px;white-space:pre-wrap}
"""


def escaped(value: str) -> str:
    return html.escape(value, quote=True)


def original_owner_desk(originals, source_hashes, proposals) -> bytes:
    if len(source_hashes) != 2 or not 1 <= len(originals) <= 256:
        raise ValueError("Malformed original owner HUMAN source batch")
    for v in source_hashes:
        if type(v) is not str or len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("Malformed original owner source SHA")
    proposal_map = {}
    for item in proposals:
        ordinal, original_path, change, stage, suggested, team, note = item
        if not str(ordinal).isdigit() or not 1 <= int(ordinal) <= len(originals):
            raise ValueError("Unexpected original ordinal in HUMAN proposal")
        idx = int(ordinal)
        if idx in proposal_map:
            raise ValueError("Duplicate HUMAN proposal for original source slot")
        if suggested not in STAGES or stage not in STAGES or                 (originals[idx-1][0], originals[idx-1][1], originals[idx-1][4], originals[idx-1][5]) !=                 (original_path, change, stage, team):
            raise ValueError("Recipient HUMAN proposal conflicts with original source assignment")
        proposal_map[idx] = (suggested, note)
    script_path = Path(__file__).with_name("owner_decision.js")
    if script_path.is_symlink() or not script_path.is_file() or script_path.stat().st_size > MAX_SCRIPT:
        raise ValueError("Missing or unsafe original HUMAN owner offline script")
    script = script_path.read_bytes().decode("utf-8","strict")
    if "</script" in script.lower():
        raise ValueError("Untrusted script-close sequence")
    rows = []
    for idx, item in enumerate(originals,1):
        path, changed, before, after, stage, team, note = item
        has_proposal=idx in proposal_map
        suggestion, reply=proposal_map.get(idx, (stage,""))
        if stage not in STAGES or suggestion not in STAGES:
            raise ValueError("Unknown proposed/original HUMAN status")
        props = (
            ' data-proposed="' + escaped(suggestion) + '"' if has_proposal else ""
        )
        select = ('<select class="review-choice" aria-label="Choose HUMAN owner decision">'
                  '<option value="retain">Retain original HUMAN stage</option>' +
                  ('<option value="accept">Adopt proposed HUMAN stage only</option>' if has_proposal else '') +
                  '</select>')
        rows.append(
            f'<tr data-path="{escaped(path)}" data-change="{escaped(changed)}" '
            f'data-old="{escaped(before)}" data-new="{escaped(after)}" '
            f'data-original="{escaped(stage)}" data-team="{escaped(team)}"{props}>'
            f'<td><strong>{escaped(path)}</strong><small>old SHA-256 {escaped(before or "—")}<br>'
            f'new SHA-256 {escaped(after or "—")}</small></td>'
            f'<td>{escaped(changed.upper())}</td><td>{escaped(team)}</td>'
            f'<td>{escaped(stage)}</td>'
            f'<td>{escaped(suggestion) if has_proposal else "—"}'
            f'<small>{escaped(reply) if has_proposal else "No supplied HUMAN proposal"}</small></td>'
            f'<td>{select}</td>'
            f'<td><label><span>PRIVATE original HUMAN notes</span>'
            f'<textarea class="original-note" maxlength="500">{escaped(note)}</textarea>'
            f'</label></td></tr>'
        )
    style_hash = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    script_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; script-src 'sha256-" + script_hash + "'; style-src 'sha256-" +
              style_hash + "'; connect-src 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; "
              "form-action 'none'; base-uri 'none'")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + escaped(policy) + "\">"
        "<title>LightUp original-owner PRIVATE HUMAN decision workroom · DRAFT/HOLD</title>"
        "<style>" + CSS + "</style></head><body><main id='owner' data-previous='" +
        escaped(source_hashes[0]) + "' data-current='" + escaped(source_hashes[1]) + "'>"
        "<h1>LightUp · original-owner PRIVATE HUMAN decisions</h1>"
        "<p class='warning'><strong>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN REVIEW ONLY.</strong> "
        "This private room includes original path labels/hashes and recipient HUMAN self-reports. "
        "No recipient actor, tenant, client/operator consent, fix, revocation, execution, scan or grant is verified. "
        "All original authorizations and source files remain unchanged.</p>"
        "<p>This workroom starts with every existing original HUMAN stage retained. "
        "An owner must select adoption of each proposal explicitly, with the right to retain the prior HUMAN stage. "
        "The resulting CSV is a PRIVATE new HUMAN DRAFT, never an actual authorization decision. "
        "Original notes are carried unchanged unless locally edited explicitly. "
        "Source-missing is NOT source-fixed.</p>"
        "<p>Previous original manifest: <code>" + source_hashes[0] +
        "</code><br>Current original manifest: <code>" + source_hashes[1] + "</code></p>"
        "<section><div class='tools'><label>Show: <select id='show'>"
        "<option value='all'>All original sources</option>"
        "<option value='proposals'>Rows with recipient HUMAN proposals</option>"
        "<option value='pending'>Proposals pending owner selection</option>"
        "<option value='accepted'>Owner-selected HUMAN stage updates</option></select></label>"
        "<button id='export' type='button'>Export PRIVATE HUMAN decision draft CSV</button>"
        "</div><p id='summary'></p><output id='status' aria-live='polite'>"
        "Unsaved local HUMAN owner choices are only in memory. No real permissions are changed."
        "</output></section><section class='table-wrap'><table><thead><tr>"
        "<th>Original PRIVATE file</th><th>Source change</th><th>HUMAN team</th>"
        "<th>Existing stage</th><th>Reviewer proposal & private reply</th>"
        "<th>Owner HUMAN decision</th><th>Original PRIVATE notes</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
        "<p class='hold'>No approval, grant, remediation proof, authenticated actor or release claim is produced here.</p>"
        "</main><script>" + script + "</script></body></html>"
    ).encode("utf-8")
