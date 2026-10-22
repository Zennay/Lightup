"""PRIVATE, offline, source-minimal HUMAN next-action desk.

HUMAN status suggestions only; no endpoint URLs, notes, identities, execution.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json

from launchpad import Hold
from review_desk import ROLES, STAGES

NAME = "lightup-lab-human-next-actions-private.html"
NEXT = ("REQUEST_HUMAN_ROLE_REPLY", "COLLECT_MISSING_HUMAN_INPUT",
        "SCHEDULE_HUMAN_REVIEW", "FOLLOW_UP_WITH_HUMAN_OWNER")
STATUSES = ("ROLE_REPLY_RECEIVED", "AWAITING_HUMAN_ROLE_REPLY")
NOTES = ("YES", "NO", "NOT_RETURNED")
STYLE = (
    "*{box-sizing:border-box}body{margin:0;background:#f3f6fb;"
    "font:15px/1.55 system-ui,sans-serif;color:#162b41}"
    "header,main,footer{max-width:1100px;margin:0 auto;padding:1.2rem}"
    "h1{font-size:clamp(1.7rem,4vw,2.6rem);margin:.2rem 0}"
    ".hold{background:#fff1df;border-left:6px solid #9b5811;padding:1rem;font-weight:750}"
    ".panel{background:white;border:1px solid #cedbe8;border-radius:.7rem;"
    "padding:1rem;margin:1rem 0}"
    ".filters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem}"
    "label{display:block;font-weight:700}select{font:inherit;width:100%;padding:.55rem;"
    "border:1px solid #7d91a8;border-radius:.3rem;background:white}"
    "select:focus-visible,button:focus-visible{outline:3px solid #e0a940;outline-offset:2px}"
    "button{font:inherit;background:#1a426d;color:white;border:0;border-radius:.4rem;"
    "padding:.65rem 1rem;font-weight:700;cursor:pointer}"
    "table{width:100%;border-collapse:collapse}th,td{border:1px solid #c1d0de;"
    "padding:.65rem;text-align:left}th{background:#e8f0fa}"
    "tr[hidden]{display:none}small{color:#435970}"
    "@media(max-width:690px){.filters{grid-template-columns:1fr}"
    ".tablewrap{overflow-x:auto}table{min-width:800px}}"
    "@media print{.filters,button{display:none}header,main{max-width:none}"
    "tr[hidden]{display:none}#printScope{display:block;font-weight:700}}"
)
SCRIPT = r'''(() => {
"use strict";
const source = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(
  Uint8Array.from(atob(__ROWS64__),x=>x.charCodeAt(0))));
const root = document.getElementById("actionRows");
const roleFilter = document.getElementById("role");
const replyFilter = document.getElementById("reply");
const nextFilter = document.getElementById("next");
const progress = document.getElementById("progress");
const printButton = document.getElementById("print");
if (!Array.isArray(source) || source.length < 1 || source.length > 16) {
  progress.textContent = "No bounded original HUMAN action rows admitted.";
  return;
}
const lookup = [];
function option(select, value, label) {
  const item = document.createElement("option");
  item.value = value;
  item.textContent = label;
  select.append(item);
}
option(roleFilter,"ALL","All suggested HUMAN roles");
option(replyFilter,"ALL","All recipient return statuses");
option(nextFilter,"ALL","All HUMAN next steps");
for (const value of [...new Set(source.map(r=>r[1]))].sort()) {
  option(roleFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[2]))].sort()) {
  option(replyFilter,value,value.replaceAll("_"," "));
}
for (const value of [...new Set(source.map(r=>r[4]))].sort()) {
  option(nextFilter,value,value.replaceAll("_"," "));
}
for (const row of source) {
  if (!Array.isArray(row) || row.length !== 6) {
    progress.textContent = "Invalid bounded local HUMAN action row.";
    root.replaceChildren();
    return;
  }
  const tr = document.createElement("tr");
  for (const value of row) {
    const td = document.createElement("td");
    td.textContent = String(value).replaceAll("_"," ");
    tr.append(td);
  }
  root.append(tr);
  lookup.push({values:row,element:tr});
}
function apply() {
  let visible = 0, awaiting = 0;
  for (const {values,element} of lookup) {
    const keep = (roleFilter.value === "ALL" || roleFilter.value === values[1]) &&
      (replyFilter.value === "ALL" || replyFilter.value === values[2]) &&
      (nextFilter.value === "ALL" || nextFilter.value === values[4]);
    element.hidden = !keep;
    if (keep) {
      visible++;
      if (values[2] === "AWAITING_HUMAN_ROLE_REPLY") awaiting++;
    }
  }
  progress.textContent = visible + " of " + lookup.length +
    " original local HUMAN slots displayed · " + awaiting +
    " awaiting an original role reply in the selected view.";
}
for (const item of [roleFilter,replyFilter,nextFilter]) {
  item.addEventListener("change",apply);
}
printButton.addEventListener("click",()=>window.print());
apply();
})();'''


def render(work):
    if not 1 <= len(work) <= 16:
        raise Hold("HUMAN next-action browser accepts 1-16 original local slots")
    seen = set()
    for row in work:
        if (not isinstance(row, tuple) or len(row) != 6 or
                type(row[0]) is not int or row[0] < 1 or row[0] > 16 or
                row[0] in seen or row[1] not in ROLES or
                row[2] not in STATUSES or row[3] not in STAGES or
                row[4] not in NEXT or row[5] not in NOTES):
            raise Hold("HUMAN action browser source is not fixed original metadata")
        seen.add(row[0])
    encoded = base64.b64encode(json.dumps(work, ensure_ascii=True,
                                          separators=(",", ":")).encode("utf-8")).decode("ascii")
    script = SCRIPT.replace("__ROWS64__", json.dumps(encoded))
    css_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    js_hash = base64.b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        + "style-src 'sha256-" + css_hash + "'; script-src 'sha256-" +
        js_hash + "'; connect-src 'none'; img-src 'none'; object-src 'none';"
        " frame-src 'none'; worker-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN next-action desk</title><style>" + STYLE +
        "</style></head><body><header><p>LIGHTUP / OFFLINE HUMAN-ONLY</p>"
        "<h1>PRIVATE HUMAN next-action desk</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD ·"
        " REVIEW_ONLY · NO AUTHORIZATION</p></header>"
        "<main><p>All original local HUMAN slots; filter proposed actions by "
        "voluntarily suggested role, received source-bound packet and HUMAN "
        "stage. Priority is operator-selected, not authenticated time."
        " No endpoint URLs, note text or reviewer identities are loaded."
        " Browser filters exist in memory only.</p>"
        "<section class='panel filters'>"
        "<label for='role'>Suggested HUMAN role<select id='role'></select></label>"
        "<label for='reply'>Role return<select id='reply'></select></label>"
        "<label for='next'>Suggested HUMAN action<select id='next'></select></label>"
        "</section><section class='panel'>"
        "<p id='progress' role='status' aria-live='polite'></p>"
        "<button type='button' id='print'>Print source-minimal PRIVATE list</button>"
        "<div class='tablewrap'><table><thead><tr><th>Original slot</th>"
        "<th>Suggested role</th><th>Returned packet</th><th>Last HUMAN stage</th>"
        "<th>Suggested next HUMAN action</th><th>PRIVATE note changed?</th>"
        "</tr></thead><tbody id='actionRows'></tbody></table></div></section>"
        "<small>These are self-reported HUMAN planning labels, NOT verified "
        "security findings, reviewer authentication, remediation proof,"
        " client/operator consent, scope grant, or HUMAN GO. Do not host or"
        " forward this PRIVATE report publicly.</small></main>"
        "<footer>No browser storage, network access, scanning or target execution.</footer>"
        "<script>" + script + "</script></body></html>"
    ).encode("utf-8")
