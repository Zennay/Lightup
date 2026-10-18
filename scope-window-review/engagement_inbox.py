"""Original Casebook engagement attention inbox without synthetic grants.

Lists every actual, source-admitted engagement; especially engagements with NO
recorded grant and pending original risk decisions. Always human REVIEW_ONLY/HOLD.
"""
from __future__ import annotations

import base64
from datetime import datetime
from hashlib import sha256
from html import escape
import re

from window_review import ReviewHold

CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;color:#edf4f8;background:#101b29}
*{box-sizing:border-box}body{max-width:1180px;margin:0 auto;padding:30px 18px}
h1{font-size:clamp(1.6rem,3.5vw,2.6rem)}p{line-height:1.6}
.warning{border-left:5px solid #eab877;background:#273344;padding:16px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.stat{padding:16px 22px;border:1px solid #4b6275;border-radius:12px;flex:1;min-width:150px}
.stat strong{display:block;font-size:1.6rem;margin-top:8px}
.tools{display:flex;flex-wrap:wrap;gap:14px;margin:18px 0}.tools label{flex:1;min-width:220px}
input,select{display:block;width:100%;margin-top:8px;padding:12px;background:#203247;color:#f1f8ff;border:1px solid #7891a7;border-radius:8px;font:inherit}
article{border:1px solid #506679;border-left:5px solid #7babc7;border-radius:10px;margin:12px 0;padding:18px;overflow-wrap:anywhere}
article.urgent{border-left-color:#eda66b}article[hidden]{display:none}
h2{font-size:1.1rem;margin-top:0}dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 12px}
dt{color:#a7becc}dd{margin:0}.muted{color:#b4c4d2;font-size:.9rem}
@media(max-width:550px){dl{grid-template-columns:1fr}dd{margin-bottom:12px}}
@media print{body{background:white;color:black}.tools{display:none}.stat,article{break-inside:avoid}}
"""

JS = """
'use strict';
const q=document.getElementById('q'), filter=document.getElementById('priority');
const cards=[...document.querySelectorAll('article[data-priority]')];
function draw(){
 let shown=0;
 for(const card of cards){
  const show=(!q.value.trim()||card.dataset.search.includes(q.value.trim().toLocaleLowerCase()))
   &&(filter.value==='all'||card.dataset.priority===filter.value);
  card.hidden=!show;
  if(show)shown++;
 }
 document.getElementById('visible').textContent=String(shown);
}
q.addEventListener('input',draw);filter.addEventListener('input',draw);draw();
"""


def build(casebook: dict, agenda: dict) -> dict:
    """Original source counts already admitted by window_review.derive."""
    rows = casebook["case_overview"]
    stale = agenda["stale_source_over_24h"]
    cases = []
    for source in rows:
        eid = source.get("engagement_id")
        notice = source.get("attention")
        action = source.get("next_review_action")
        status = source.get("status")
        grants = source.get("grant_count")
        risks = source.get("risk_record_count")
        if (type(eid) is not str or not 1 <= len(eid) <= 180
                or type(notice) is not str or not re.fullmatch(r"[A-Z0-9_]{3,90}", notice)
                or type(action) is not str or not re.fullmatch(r"[A-Z0-9_]{3,120}", action)
                or type(status) is not str or not 1 <= len(status) <= 80
                or type(grants) is not int or type(risks) is not int
                or not 0 <= grants <= 200 or not 0 <= risks <= 200):
            raise ReviewHold("original engagement attention source malformed")
        # These are *human* review categories, not additional permissions.
        urgent = (stale or notice.startswith("HOLD_")
                  or notice in ("NO_GRANT_RECORDED",
                                "RISK_DECISION_PENDING_SOURCE_REVIEW"))
        cases.append({
            "engagement_id": eid, "source_status": status,
            "original_attention": notice, "original_next_action": action,
            "original_grant_records": grants, "original_risk_records": risks,
            "human_priority": "HOLD" if urgent else "REVIEW_ONLY",
        })
    cases.sort(key=lambda row: (row["human_priority"] != "HOLD",
                               row["original_attention"], row["engagement_id"]))
    stats = {
        "cases": len(cases),
        "human_hold": sum(c["human_priority"] == "HOLD" for c in cases),
        "without_recorded_grant": sum(c["original_grant_records"] == 0 for c in cases),
        "risk_source_pending": sum(
            c["original_attention"] == "RISK_DECISION_PENDING_SOURCE_REVIEW"
            for c in cases),
    }
    return {
        "schema": "lightup.original_engagement_human_inbox.v1",
        "status": "HOLD" if stats["human_hold"] else "REVIEW_ONLY",
        "original_source_sha256": agenda["original_source_sha256"],
        "as_of": agenda["as_of"],
        "cases": cases, "declared_counts": stats,
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
    }


def render(source: dict) -> bytes:
    """Private portable HTML with no network, scanners or browser storage."""
    stats = source["declared_counts"]
    totals = (
        ("Original engagements", stats["cases"]),
        ("Human HOLD attention", stats["human_hold"]),
        ("No original grant", stats["without_recorded_grant"]),
        ("Pending original risk", stats["risk_source_pending"]),
    )
    cards = []
    for item in source["cases"]:
        fields = (
            ("Original engagement", item["engagement_id"]),
            ("Original source status", item["source_status"]),
            ("Original attention", item["original_attention"]),
            ("Original review action", item["original_next_action"]),
            ("Original grant records", str(item["original_grant_records"])),
            ("Original risk records", str(item["original_risk_records"])),
        )
        details = "".join("<dt>" + escape(key) + "</dt><dd>" +
                          escape(str(value)) + "</dd>" for key, value in fields)
        search = " ".join(str(value) for _, value in fields).lower()
        cards.append(
            f'<article class="{"urgent" if item["human_priority"]=="HOLD" else ""}" '
            f'data-priority="{item["human_priority"]}" '
            f'data-search="{escape(search,quote=True)}">'
            f'<h2>{escape(item["human_priority"])} — '
            f'{escape(item["engagement_id"])}</h2>'
            f'<dl>{details}</dl>'
            '<p class="muted">Human source review only. No grant, consent,'
            ' current revocation or runtime authority is inferred.</p>'
            '</article>'
        )
    css_hash = base64.b64encode(sha256(CSS.encode()).digest()).decode()
    js_hash = base64.b64encode(sha256(JS.encode()).digest()).decode()
    policy = ("default-src 'none'; connect-src 'none'; base-uri 'none'; "
              "form-action 'none'; object-src 'none'; "
              f"style-src 'sha256-{css_hash}'; script-src 'sha256-{js_hash}'")
    summary = "".join(f'<div class="stat"><span>{escape(label)}</span>'
                      f'<strong>{number}</strong></div>' for label, number in totals)
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{policy}">
<title>LightUp · PRIVATE original engagement human inbox</title>
<style>{CSS}</style></head><body>
<header><p class="muted">LIGHTUP / ORIGINAL SOURCE / HUMAN INBOX</p>
<h1>Every original engagement — including no-grant cases</h1>
<p class="warning"><strong>{escape(source["status"])} · NEVER AN AUTHORIZATION.</strong>
This unsigned, retrospective original Casebook source may be stale or wrong.
No recorded grant is NOT a valid permission; recorded grants do not establish
actual consent or safe dispatch. Re-authenticate, inspect original source,
verify separate client/operator consent and at-use revocation before any work.</p>
<p>Original snapshot: {escape(source["as_of"])}</p></header>
<div class="stats">{summary}</div>
<div class="tools"><label>Find private original case
<input id="q" placeholder="Original engagement or attention"></label>
<label>Human priority<select id="priority"><option value="all">All original cases</option>
<option value="HOLD">HOLD attention</option>
<option value="REVIEW_ONLY">Review only</option></select></label></div>
<p class="muted"><span id="visible">{stats["cases"]}</span> original cases shown;
case attention is for humans, never a new grant/risk decision.</p>
<main>{"".join(cards) if cards else "<p>No original engagements in this selected Casebook. This does not authorize target work.</p>"}</main>
<footer class="warning">PRIVATE original IDs. Local-only dashboard, no storage,
remote assets, target contact, job launch, or original-domain mutation.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</footer>
<script>{JS}</script></body></html>"""
    return html.encode("utf-8")
