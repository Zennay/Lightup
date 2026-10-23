#!/usr/bin/env python3
"""PRIVATE offline HUMAN document overview browser, not a live assessment.

Source-identifier-minimized only; freeform notes may STILL identify clients.
Never calls a target, authenticates findings/respondents, or writes any source.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json

CSS = """
:root{font:16px/1.45 system-ui,-apple-system,sans-serif;color:#1b2d45;
background:#eef2f7}*{box-sizing:border-box}
body{max-width:1240px;margin:0 auto;padding:18px}
header,.controls,.metric,article,.pager{background:white;border:1px solid #cfdaea;
border-radius:14px;padding:18px;margin-bottom:14px}
h1{font-size:1.65rem;margin:0 0 6px}h2{font-size:1.15rem;margin:0 0 8px}
h3{font-size:1rem;margin:10px 0 6px}
.notice{font-weight:700;color:#85411a}.muted{color:#54687f}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
label{display:flex;flex-direction:column;gap:5px;font-size:.9rem;font-weight:650}
input,select,button{font:inherit;border-radius:8px;padding:10px}
input,select{border:1px solid #8195a8;min-width:130px}
button{border:0;background:#1d487c;color:white;cursor:pointer}
button.secondary{background:#536b85}button:disabled{opacity:.55;cursor:not-allowed}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.metric{margin-bottom:12px} .metric strong{display:block;font-size:1.75rem;color:#143b65}
article{border-left:5px solid #93abc3}
article[data-priority='urgent']{border-left-color:#b5583e}
article[data-priority='soon']{border-left-color:#b1842d}
.head{display:flex;gap:12px;justify-content:space-between;flex-wrap:wrap}
.tag{font-size:.78rem;padding:4px 8px;border-radius:9px;background:#e9f1f9;
color:#153f70;font-weight:700}
p{overflow-wrap:anywhere;margin:8px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f8fc;
border:1px solid #dce5f1;padding:10px;border-radius:8px}
.details{display:none}
article[data-open='yes'] .details{display:block}
.pager{display:flex;gap:16px;justify-content:space-between;align-items:center}
.pager span{font-weight:700}#filtered-count{font-weight:bold;margin:14px 0}
@media(max-width:600px){body{padding:9px}.pager{flex-wrap:wrap}}
@media print{.controls,.toolbar,.pager,button{display:none!important}
body{background:white}article{break-inside:avoid}
article[data-open='yes'] .details{display:block}
article[data-open='no'] .details{display:none}}
"""
JS = r"""
(function(){
"use strict";
const data=JSON.parse(document.getElementById("private-rows").content.textContent);
const state={page:0,pageSize:16,showAll:false};
const root=document.getElementById("cases");
const q=document.getElementById("q"),priority=document.getElementById("priority");
const severity=document.getElementById("severity"),humanStage=document.getElementById("human-stage");
const route=document.getElementById("route"),phase=document.getElementById("phase");
const summary=document.getElementById("filtered-count");
const ord=(r)=>String(r.original_ordinal);
function matches(r){
 const search=q.value.trim().toLowerCase();
 // Do not include hidden private notes in search: private questions and replies
 // are intentionally not revealed by search hit counts or snippets.
 return (!search||("#"+ord(r)).includes(search))&&
  (priority.value==="all"||r.human_priority===priority.value)&&
  (severity.value==="all"||r.source_reported_severity===severity.value)&&
  (humanStage.value==="all"||r.recipient_human_stage===humanStage.value)&&
  (route.value==="all"||r.sender_human_route===route.value)&&
  (phase.value==="all"||r.human_document_phase===phase.value);
}
function element(tag,text,cls){
 const x=document.createElement(tag);x.textContent=text;
 if(cls)x.className=cls;return x;
}
function addNote(root,label,value){
 root.append(element("h3",label));
 root.append(element("pre",value||"Not recorded"));
}
function card(r){
 const article=document.createElement("article");
 article.dataset.priority=r.human_priority;
 article.dataset.open=state.showAll?"yes":"no";
 const head=document.createElement("div");head.className="head";
 const title=element("h2","Original ordinal #"+ord(r));head.append(title);
 head.append(element("span","HUMAN "+r.human_priority,"tag"));
 article.append(head);
 article.append(element("p","Source-reported severity: "+r.source_reported_severity+
  " · original evidence reference count: "+r.original_evidence_reference_count,"muted"));
 article.append(element("p","Human-document phase: "+r.human_document_phase));
 article.append(element("p","Recipient HUMAN stage: "+r.recipient_human_stage+
  " · Sender HUMAN route: "+r.sender_human_route));
 article.append(element("p","Next HUMAN proposal (NOT executed): "+r.human_action));
 const reveal=document.createElement("button");reveal.type="button";
 reveal.className="secondary";
 function buttonText(){reveal.textContent=article.dataset.open==="yes"?
  "Hide PRIVATE questions/answers":"Reveal PRIVATE questions/answers";}
 buttonText();
 reveal.addEventListener("click",()=>{
  article.dataset.open=article.dataset.open==="yes"?"no":"yes";buttonText();});
 article.append(reveal);
 const details=document.createElement("div");details.className="details";
 addNote(details,"Original HUMAN question",r.human_question);
 addNote(details,"Recipient HUMAN answer — UNVERIFIED",r.recipient_human_reply);
 addNote(details,"Recipient HUMAN next question",r.recipient_human_next_question);
 addNote(details,"Sender HUMAN owner/group — NOT AUTHENTICATED",r.sender_human_owner_group);
 addNote(details,"Sender HUMAN next question",r.sender_human_next_question);
 article.append(details);
 return article;
}
function countMetric(id,value){document.getElementById(id).textContent=String(value);}
function draw(){
 const all=data.filter(matches);
 const total=Math.max(1,Math.ceil(all.length/state.pageSize));
 state.page=Math.min(Math.max(0,state.page),total-1);
 root.replaceChildren();
 for(const r of all.slice(state.page*state.pageSize,(state.page+1)*state.pageSize))
  root.append(card(r));
 summary.textContent=all.length+" source-bound HUMAN records visible of "+data.length+
  " selected ORIGINAL ordinals. HUMAN labels are never proven findings.";
 document.getElementById("page").textContent="Page "+(state.page+1)+" of "+total;
 document.getElementById("prev").disabled=state.page===0;
 document.getElementById("next").disabled=state.page>=total-1;
 countMetric("shown",all.length);
 countMetric("awaiting",all.filter(r=>r.recipient_human_stage==="no_human_response").length);
 countMetric("claimed",all.filter(r=>r.recipient_human_stage==="responded_claimed").length);
 countMetric("routing",all.filter(r=>r.sender_human_route!=="unreviewed").length);
}
for(const x of [q,priority,severity,humanStage,route,phase])
 x.addEventListener(x===q?"input":"change",()=>{state.page=0;draw();});
document.getElementById("prev").addEventListener("click",()=>{state.page--;draw();});
document.getElementById("next").addEventListener("click",()=>{state.page++;draw();});
document.getElementById("reveal-all").addEventListener("click",()=>{
 if(!state.showAll&&!window.confirm("Reveal HUMAN freeform text on screen? It may contain confidential client names, targets or details."))return;
 state.showAll=!state.showAll;draw();
 document.getElementById("reveal-all").textContent=state.showAll?
  "Hide all PRIVATE notes":"Reveal all PRIVATE notes";});
document.getElementById("print").addEventListener("click",()=>{
 if(!window.confirm("Print this current PRIVATE browser page only (not all records)? Any notes you explicitly revealed may expose confidential customer information. For a full private print use the separate scriptless report."))return;
 window.print();});
draw();
})();
"""

def render_browser(records: list[dict], original_count: int,
                   document_stage: str) -> bytes:
    # Original targets, report IDs, evidence contents and file paths are NOT
    # sent into the browser. HUMAN freeform questions/replies may still reveal
    # customer identifiers and are kept strictly PRIVATE.
    rows = [{
        "original_ordinal": row["original_ordinal"],
        "source_reported_severity": row["source_reported_severity"],
        "original_evidence_reference_count": row["original_evidence_reference_count"],
        "human_priority": row["human_priority"],
        "human_document_phase": row["human_document_phase"],
        "recipient_human_stage": row["recipient_human_stage"],
        "sender_human_route": row["sender_human_route"],
        "human_question": row["human_question"],
        "recipient_human_reply": row["recipient_human_reply"],
        "recipient_human_next_question": row["recipient_human_next_question"],
        "sender_human_owner_group": row["sender_human_owner_group"],
        "sender_human_next_question": row["sender_human_next_question"],
        "human_action": row["human_action"],
    } for row in records]
    payload = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    js_pin = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + css_pin +
           "'; script-src 'sha256-" + js_pin +
           "'; connect-src 'none'; img-src 'none'; frame-src 'none'; "
           "form-action 'none'; base-uri 'none'; object-src 'none'")
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" +
        html.escape(csp, quote=True) + "\">"
        "<title>PRIVATE LightUp HUMAN Assessment Workroom</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN workroom</h1>"
        "<p class='notice'>REVIEW ONLY / NOT AUTHORIZED. Original source identity,"
        " findings, evidence, recipient identity, consent, revocation, retest,"
        " remediation, owner assignment and runtime activity are NOT verified."
        " Nothing is dispatched or scheduled.</p>"
        "<p>Source-identifier-minimized only. HUMAN notes may STILL contain confidential"
        " names/targets. The default hidden-note view is NOT encryption: private text"
        " remains embedded in this local HTML. Share through separately approved"
        " PRIVATE channels only.</p>"
        "<p>Original source-reported finding count: " + str(original_count) +
        " · HUMAN local documents: " + html.escape(document_stage) + "</p></header>"
        "<section class='controls'><div class='filters'>"
        "<label>Original ordinal <input id='q' type='search' placeholder='#12' autocomplete='off'></label>"
        "<label>HUMAN priority <select id='priority'><option value='all'>All</option>"
        "<option value='urgent'>Urgent</option><option value='soon'>Soon</option>"
        "<option value='routine'>Routine</option></select></label>"
        "<label>Source-reported severity <select id='severity'><option value='all'>All</option>"
        "<option value='critical'>Critical</option><option value='high'>High</option>"
        "<option value='medium'>Medium</option><option value='low'>Low</option>"
        "<option value='info'>Info</option></select></label>"
        "<label>Recipient HUMAN stage <select id='human-stage'><option value='all'>All</option>"
        "<option value='no_human_response'>No response</option>"
        "<option value='responded_claimed'>Responded — claimed</option>"
        "<option value='needs_more_information'>Needs more information</option>"
        "<option value='blocked_human'>Blocked HUMAN</option></select></label>"
        "<label>Sender HUMAN route <select id='route'><option value='all'>All</option>"
        "<option value='unreviewed'>Unreviewed</option>"
        "<option value='needs_human_review'>Needs HUMAN review</option>"
        "<option value='request_clarification'>Request clarification</option>"
        "<option value='route_to_owner'>Route to owner (claimed)</option>"
        "<option value='documented_for_followup'>Documented for follow-up</option></select></label>"
        "<label>HUMAN document phase <select id='phase'><option value='all'>All</option>"
        "<option value='awaiting_human_recipient'>Awaiting recipient</option>"
        "<option value='recipient_self_reported'>Recipient self-reported</option>"
        "<option value='sender_human_followup_recorded'>Sender HUMAN follow-up</option>"
        "</select></label></div><div class='toolbar'>"
        "<button id='reveal-all' class='secondary' type='button'>Reveal all PRIVATE notes</button>"
        "<button id='print' class='secondary' type='button'>Print PRIVATE view</button>"
        "</div><p id='filtered-count' aria-live='polite'></p></section>"
        "<section class='metrics'>"
        "<div class='metric'>Filtered HUMAN records<strong id='shown'>0</strong></div>"
        "<div class='metric'>No HUMAN recipient reply<strong id='awaiting'>0</strong></div>"
        "<div class='metric'>Responded (claimed)<strong id='claimed'>0</strong></div>"
        "<div class='metric'>HUMAN routing proposed<strong id='routing'>0</strong></div>"
        "</section><main id='cases'></main>"
        "<nav class='pager'><button class='secondary' id='prev' type='button'>Previous</button>"
        "<span id='page'></span><button class='secondary' id='next' type='button'>Next</button></nav>"
        "<template id='private-rows'>" + payload + "</template>"
        "<script>" + JS + "</script></body></html>\n"
    )
    return document.encode("utf-8")
