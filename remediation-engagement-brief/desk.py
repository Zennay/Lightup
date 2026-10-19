"""Standalone, original-source-only PRIVATE HUMAN finding review desk.

This module performs no authentication itself. The owner CLI MUST first obtain
a fresh, authorized LightUp source and validate the exact original CSV.
No persistence, scripts from other sources, target requests or security claims.
"""
from __future__ import annotations

import hashlib
from html import escape
from pathlib import Path

LIMIT = 2 * 1024 * 1024
SEVERITY = ("critical", "high", "medium", "low", "info")
STATUS = ("not_tested", "fix_pending", "fixed", "regression")

CSS = r"""
:root{color-scheme:light;--ink:#152438;--muted:#4b5c6b;--card:#fff;--line:#cbd9e4;--accent:#153d68}
*{box-sizing:border-box}html{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif}
body{margin:0;background:#f1f6fa;color:var(--ink);line-height:1.55}
main,header{max-width:1240px;margin:auto;padding:1.2rem}
header{padding-block:2rem 1rem}
h1{font-size:clamp(1.6rem,3vw,2.5rem);letter-spacing:-.025em;margin:.4rem 0}
h2{font-size:1.22rem}h3{font-size:1.12rem;margin:.25rem 0 .7rem}
p{margin:.35rem 0 .8rem}.muted{color:var(--muted)}small{color:var(--muted)}
.notice{border:2px solid #ac7535;border-radius:14px;padding:1rem;background:#fff8ed}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(146px,1fr));gap:.7rem;margin:1.1rem 0}
.metric{padding:1rem;background:var(--card);border:1px solid var(--line);border-radius:14px}
.metric b{font-size:1.65rem;display:block;font-variant-numeric:tabular-nums}
.controls{position:sticky;top:0;background:#f1f6fa;padding:1rem 0;z-index:2;border-bottom:1px solid var(--line);display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:.65rem}
label{display:flex;flex-direction:column;font-weight:650;font-size:.89rem}
input,select{font:inherit;background:#fff;border:1px solid #859fb4;border-radius:9px;color:#13283c;padding:.65rem;min-width:0}
input:focus-visible,select:focus-visible{outline:3px solid #557bc7;outline-offset:2px}
section{margin-top:1.5rem}.cards{display:grid;gap:.7rem}
article{background:var(--card);border-radius:13px;border:1px solid var(--line);padding:1rem;border-left:5px solid #4077a4;overflow-wrap:anywhere}
article[data-severity=critical]{border-left-color:#b43a3a}
article[data-severity=high]{border-left-color:#c47d2c}
article[data-state=absent]{background:#fff7ed}
.article-head{display:flex;flex-wrap:wrap;justify-content:space-between;gap:.7rem;align-items:start}
.pills{display:flex;gap:.3rem;flex-wrap:wrap}
.pill{padding:.13rem .48rem;border-radius:9px;background:#e9f1f7;color:#163755;font-weight:650;font-size:.8rem}
dl{display:grid;grid-template-columns:135px 1fr;gap:.2rem .9rem;margin:.7rem 0}
dt{font-weight:650;color:var(--muted)}dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
.changed{border-top:1px dashed #b9c9d6;padding-top:.55rem;margin-top:.6rem}
.empty{padding:1.5rem;border:1px dashed #b2c5d4;border-radius:12px}
footer{margin:2rem 0;padding:1rem;border-top:1px solid var(--line);color:var(--muted)}
@media(max-width:850px){.controls{position:static;grid-template-columns:1fr 1fr}}
@media(max-width:560px){.controls{grid-template-columns:1fr}dl{grid-template-columns:1fr;gap:.1rem}dd{margin-bottom:.5rem}}
@media print{body{background:#fff}.controls{display:none}article{break-inside:avoid}header,main{max-width:none}.notice{border:1px solid #999}}
"""
JS = r"""
"use strict";
(function(){
const q=document.getElementById("search");
const sev=document.getElementById("severity");
const state=document.getElementById("state");
const retest=document.getElementById("retest");
const cards=[...document.querySelectorAll("article[data-id]")];
const visible=document.getElementById("visible");
const noMatch=document.getElementById("no-match");
function apply(){
  const needle=q.value.toLocaleLowerCase().trim();
  let count=0;
  for(const row of cards){
    const matches=(!needle||row.textContent.toLocaleLowerCase().includes(needle))
       &&(!sev.value||row.dataset.severity===sev.value)
       &&(!state.value||row.dataset.state===state.value)
       &&(!retest.value||row.dataset.retest===retest.value);
    row.hidden=!matches;
    if(matches)count++;
  }
  visible.textContent=String(count);
  noMatch.hidden=count!==0;
}
for(const el of [q,sev,state,retest])el.addEventListener("input",apply);
apply();
})();
"""

def _a(s: str) -> str:
    if type(s) is not str:
        raise ValueError("Noncanonical original source text")
    return escape(s, quote=True)


def _badge(value: str) -> str:
    return '<span class="pill">' + _a(value) + "</span>"


def _field(title: str, value: str) -> str:
    return "<dt>" + _a(title) + "</dt><dd>" + _a(value) + "</dd>"


def _finding(row: dict[str, str], state: str, previous: dict[str, str] | None = None) -> str:
    if state not in ("new", "changed", "unchanged", "absent", "current"):
        raise ValueError("Unknown original-source difference classification")
    if row["severity"] not in SEVERITY or row["retest_status"] not in STATUS:
        raise ValueError("Unknown original source labels")
    content = [
        '<article data-id="' + _a(row["finding_id"]) + '" data-severity="' + _a(row["severity"]) +
        '" data-state="' + state + '" data-retest="' + _a(row["retest_status"]) + '">',
        '<div class="article-head"><div><small>Original finding ID (unverified)</small><h3>' +
        _a(row["finding_id"]) + "</h3></div><div class=\"pills\">" +
        _badge(state.upper()) + _badge(row["severity"]) + _badge(row["retest_status"]) +
        "</div></div><dl>",
        _field("Original title", row["title"]),
        _field("Source remediation", row["remediation"]),
        _field("Original retest label", row["retest_status"]),
        "</dl>",
    ]
    if state == "absent":
        content.append("<p><strong>HUMAN HOLD:</strong> ID is absent from current source. This is NOT a fixed finding.</p>")
    elif state in ("changed", "new"):
        content.append("<p><strong>HUMAN follow-up:</strong> original source requires fresh review, never automatic closure.</p>")
    if previous is not None:
        delta = []
        for key, label in (
            ("title", "Title"), ("severity", "Severity"), ("retest_status", "Retest label"),
            ("remediation", "Suggested remediation"),
        ):
            if previous[key] != row[key]:
                delta.extend((_field("Previous " + label, previous[key]),
                              _field("Current " + label, row[key])))
        if delta:
            content.append('<div class="changed"><strong>Original source fields changed</strong><dl>' +
                           "".join(delta) + "</dl></div>")
    content.append("</article>")
    return "".join(content)


def build_desk(current: list[dict[str, str]], previous: list[dict[str, str]] | None = None) -> bytes:
    """Create the entire private operator document in memory, with CSP hash pins."""
    if not 1 <= len(current) <= 350 or (previous is not None and not 1 <= len(previous) <= 350):
        raise ValueError("Invalid bounded authenticated source input")
    def canonical(records):
        observed=set()
        for row in records:
            if type(row) is not dict or set(row) != {
                "finding_id", "title", "severity", "retest_status", "remediation"
            } or any(type(v) is not str for v in row.values()):
                raise ValueError("Noncanonical original finding structure")
            if row["finding_id"] in observed:
                raise ValueError("Ambiguous original finding membership")
            observed.add(row["finding_id"])
        return {r["finding_id"]: r for r in records}
    now=canonical(current)
    old=canonical(previous) if previous is not None else {}
    allrows=[]
    for row in current:
        if previous is None:
            state="current"
            before=None
        elif row["finding_id"] not in old:
            state="new"
            before=None
        elif row != old[row["finding_id"]]:
            state="changed"
            before=old[row["finding_id"]]
        else:
            state="unchanged"
            before=None
        allrows.append((row,state,before))
    if previous is not None:
        allrows.extend((r,"absent",None) for r in previous if r["finding_id"] not in now)
    total={state:sum(1 for _,kind,_ in allrows if kind==state)
           for state in ("current","new","changed","unchanged","absent")}
    counts={sev:sum(1 for row,_,_ in allrows if row["severity"]==sev) for sev in SEVERITY}
    cards="".join(_finding(*entry) for entry in
                  sorted(allrows,key=lambda t: (SEVERITY.index(t[0]["severity"]),
                          t[1] not in ("new","changed","absent"),t[0]["finding_id"])))
    metrics = [("Original current rows", len(current))]
    if previous is not None:
        metrics.extend((label,total[key]) for key,label in (
            ("new","New IDs"),("changed","Changed"),("absent","Absent — HOLD"),("unchanged","Unchanged")
        ))
    metrics.extend(((sev.capitalize()+" source labels",counts[sev]) for sev in SEVERITY[:2]))
    tiles="".join('<div class="metric"><b>'+str(number)+"</b>"+_a(label)+"</div>"
                  for label,number in metrics)
    opts = lambda labels: '<option value="">All</option>' + "".join(
        '<option value="'+_a(label)+'">'+_a(label)+"</option>" for label in labels
    )
    style_digest=hashlib.sha256(CSS.encode("utf-8")).digest()
    script_digest=hashlib.sha256(JS.encode("utf-8")).digest()
    import base64
    csp = ("default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; "
           "form-action 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'; "
           "style-src 'sha256-"+base64.b64encode(style_digest).decode("ascii")+
           "'; script-src 'sha256-"+base64.b64encode(script_digest).decode("ascii")+"'")
    message = ("Compare prior encrypted source vs freshly authenticated current source."
               if previous is not None else
               "Freshly authenticated current original source (not an authorization to act).")
    html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="'+_a(csp)+'">'
            '<title>LightUp | PRIVATE HUMAN review</title>'
            '<style>'+CSS+'</style></head><body>'
            '<header><small>LIGHTUP / PRIVATE HUMAN SOURCE REVIEW / OFFLINE</small>'
            '<h1>Original Finding Review Desk</h1><p class="muted">'+_a(message)+'</p>'
            '<div class="notice"><strong>PLAN/LAB ONLY · NOT VERIFIED</strong><p>'
            'Original finding, severity, remediation and retest labels are unverified source claims. '
            'An absent or fixed label is NOT proof of repair. No client/operator consent, grant, '
            'scope approval, authorization to scan, remediation execution, verified retest or release.'
            '</p></div></header><main><div class="metrics">'+tiles+'</div>'
            '<section><h2>Human follow-up queue</h2><p class="muted">'
            'Original records only. Human owner, action, evidence and verification require separate review.</p>'
            '<div class="controls">'
            '<label>Search original finding content<input id="search" type="search" '
            'placeholder="Find by ID, title, source remediation..." autocomplete="off"></label>'
            '<label>Severity<select id="severity">'+opts(SEVERITY)+'</select></label>'
            '<label>Source change<select id="state">'+opts(("current","new","changed","absent","unchanged"))+'</select></label>'
            '<label>Original retest<select id="retest">'+opts(STATUS)+'</select></label>'
            '</div><p><strong id="visible">'+str(len(allrows))+'</strong> matching of '+
            str(len(allrows))+' original records</p>'
            '<div id="no-match" class="empty" hidden>No matching original records.</div>'
            '<div class="cards">'+cards+'</div></section><footer>'
            'This PRIVATE local copy contains confidential original findings and possibly historical source text. '
            'Close or securely destroy it after use. No network calls, browser persistence, or server services. '
            'Historical content and exact SHA matching do not establish authentic consent or verified outcomes.'
            '</footer></main><script>'+JS+'</script></body></html>')
    raw=html.encode("utf-8","strict")
    if not 1 <= len(raw) <= LIMIT:
        raise ValueError("PRIVATE finding review HTML exceeds bound")
    return raw
