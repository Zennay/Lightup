#!/usr/bin/env python3
"""Generate an OFFLINE, source-minimized HUMAN recipient editor.

The source-owner controls which already-validated original ordinal belongs to
a team. Output has no source path, grant, client, target, evidence or source
digest. Local source row pseudonyms are NOT identity authentication.
"""
from __future__ import annotations

import base64
import hashlib
import html
from pathlib import Path
import re

MAX_SCRIPT = 24_000
STAGES = ("unreviewed", "investigating", "escalated", "documented")
HEX = re.compile(r"[0-9a-f]{32}\Z")
CSS = """
:root{color-scheme:dark}*{box-sizing:border-box}body{font:15px/1.55 system-ui;background:#101929;color:#edf5ff;max-width:1250px;margin:auto;padding:25px}h1{font-size:clamp(1.5rem,3.5vw,2.3rem)}section{background:#1b2e44;padding:17px;border-radius:12px;margin:15px 0}.warning{background:#302a19;border:1px solid #8c8052;padding:14px;border-radius:8px;color:#ffe3aa}p{max-width:100ch}.controls{display:flex;gap:15px;align-items:end;flex-wrap:wrap}label{display:block;margin-top:10px}label span{display:block;margin-bottom:4px}button,select,textarea,input{font:inherit;padding:8px;border:1px solid #7890ac;border-radius:7px;background:#263d55;color:#f6faff}button{background:#41628a;cursor:pointer}button:hover{background:#4775a5}button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #8dcfff}textarea{width:100%;min-height:72px;resize:vertical}table{border-collapse:collapse;width:100%;min-width:750px}th,td{border-bottom:1px solid #46607d;padding:10px;vertical-align:top;text-align:left}th{background:#273f57}tr:nth-child(even){background:#20354b}tr[hidden]{display:none}.scroll{overflow:auto;max-height:70vh}.muted{color:#b6cce3}.attention{font-weight:bold;color:#f4d39f}output{display:block;white-space:pre-wrap;margin-top:10px}
"""


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def render_recipient(team: str, slot: str, session: str, rows: list[dict]) -> bytes:
    if not team or not slot.isdecimal() or not HEX.fullmatch(session):
        raise ValueError("Malformed PRIVATE recipient assignment")
    if not 1 <= len(rows) <= 256:
        raise ValueError("Too many or missing source-minimized review rows")
    script_file = Path(__file__).with_name("recipient_browser.js")
    if script_file.is_symlink() or not script_file.is_file() or script_file.stat().st_size > MAX_SCRIPT:
        raise ValueError("Missing or unsafe original recipient offline UI source")
    script = script_file.read_bytes().decode("utf-8", "strict")
    if "</script" in script.lower():
        raise ValueError("Unexpected executable script delimiter")
    parts = []
    for entry in rows:
        token, ordinal, kind, stage = entry["row_token"], entry["ordinal"], entry["change"], entry["stage"]
        if type(ordinal) is not int or not 1 <= ordinal <= 256 or not HEX.fullmatch(token) or kind not in ("unchanged","changed","added","absent") or stage not in STAGES:
            raise ValueError("Invalid recipient review claim")
        choices = "".join(f'<option value="{esc(s)}"'+(' selected' if s==stage else '')+f'>{esc(s)}</option>' for s in STAGES)
        parts.append(
            f'<tr data-row="{ordinal}" data-token="{esc(token)}" '
            f'data-change="{esc(kind)}" data-original="{esc(stage)}">'
            f'<td>Review slot {ordinal} <small class="muted">source identity withheld</small></td>'
            f'<td class="attention">{esc(kind.upper())}</td>'
            f'<td>{esc(stage)}</td>'
            f'<td><label><span>Proposed HUMAN stage</span><select>{choices}</select></label></td>'
            f'<td><label><span>PRIVATE reply (no credentials or client IDs)</span>'
            f'<textarea maxlength="400" placeholder="HUMAN-only question, acknowledgement or proposed follow-up"></textarea></label></td></tr>'
        )
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    js_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; script-src 'sha256-" + js_hash +
              "'; style-src 'sha256-" + css_hash +
              "'; connect-src 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + esc(policy) + "\">"
        "<title>LightUp PRIVATE source-minimized HUMAN recipient</title><style>" + CSS + "</style></head>"
        "<body><main id='review' data-token='" + esc(session) +
        "' data-slot='" + esc(slot) + "'>"
        "<header><h1>LightUp · PRIVATE HUMAN recipient desk</h1>"
        "<p class='warning'><strong>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN ONLY.</strong> "
        "No original source paths, target names, hashes or findings are included in this page. "
        "An ordinal is a local HUMAN question slot, not a verified security risk or permission. "
        "No scan, grant, revocation, client/operator consent or production action is possible.</p>"
        "<p>Self-declared reviewer team: <strong>" + esc(team) + "</strong> · recipient slot " +
        esc(slot) + ". Team identity is NOT authenticated by this locally exported file. "
        "Treat notes as confidential, avoid inserting private customer identifiers.</p></header>"
        "<section><h2>HUMAN reply</h2><div class='controls'>"
        "<label><span>Source change class</span><select id='filter'><option value=''>All</option>"
        "<option value='changed'>Changed</option><option value='added'>Added</option>"
        "<option value='absent'>Absent locally (not fixed)</option><option value='unchanged'>Unchanged</option>"
        "</select></label><button id='export' type='button'>Export PRIVATE HUMAN reply CSV</button>"
        "<label><span>Resume source-exact PRIVATE reply CSV</span>"
        "<input id='import' type='file' accept='.csv,text/csv'></label></div>"
        "<p id='summary' class='muted'></p><output id='status' aria-live='polite'>"
        "Unsaved HUMAN replies exist only in browser memory. Export explicitly for a private recipient return."
        "</output></section><section class='scroll'><table><thead><tr>"
        "<th>Local source slot</th><th>Source change</th><th>Prior HUMAN stage</th>"
        "<th>Proposed HUMAN stage</th><th>PRIVATE HUMAN reply</th></tr></thead><tbody>" +
        "".join(parts) +
        "</tbody></table></section><p class='attention'>"
        "A source owner must independently verify actual original sources, tenant authority and "
        "fresh separately authenticated client/operator permissions. This page never does.</p>"
        "</main><script>" + script + "</script></body></html>"
    ).encode("utf-8")
