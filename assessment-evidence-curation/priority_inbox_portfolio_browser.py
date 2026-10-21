#!/usr/bin/env python3
"""Self-contained CSP-pinned, entirely offline HUMAN aggregate interval explorer.

Only receives already normalized numeric metrics and fixed HUMAN vocabulary.
No private finding, identifier, endpoint, free text, consent or authority.
"""
from __future__ import annotations

import base64
import hashlib

from curate import Hold
from briefing import h


CSS = """body{font:16px/1.55 system-ui,sans-serif;margin:0 auto;padding:1.5rem;max-width:1100px;background:#f5f6f8;color:#15202b}h1{line-height:1.25}header,section{background:white;padding:1.2rem;border:1px solid #c9d1d9;border-radius:8px;margin-bottom:1rem}.notice{border-left:5px solid #a7521b;padding:.8rem;background:#fff5e6}.controls{display:flex;gap:1rem;flex-wrap:wrap}.controls label{display:grid;gap:.25rem;font-weight:600}select{font:inherit;padding:.55rem;background:#fff;border:1px solid #64748b;border-radius:4px}table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{padding:.6rem;border-bottom:1px solid #cdd3da;text-align:left;vertical-align:top}th{background:#edf1f5}p{max-width:90ch}[hidden]{display:none!important}#empty{font-weight:700}@media(max-width:720px){table{font-size:.8rem}th,td{padding:.3rem}body{padding:.65rem}}@media print{body{background:white;padding:0}section,header{break-inside:avoid}select{border:none}.notice{background:white}}"""
JS = """'use strict';
(()=>{
const from=document.getElementById('from');
const to=document.getElementById('to');
const priority=document.getElementById('priority');
const output=document.getElementById('summary');
const empty=document.getElementById('empty');
const rows=Array.from(document.querySelectorAll('tr[data-from]'));
function update(){
 const start=Number(from.value),end=Number(to.value),group=priority.value;
 if(!Number.isInteger(start)||!Number.isInteger(end)||start>=end){
  rows.forEach(row=>{row.hidden=true;});
  output.textContent='Select two different rounds in ascending manually supplied order.';
  empty.hidden=true;return;
 }
 let visible=0,changed=0,reverted=0,reply=0,follow=0;
 rows.forEach(row=>{
  const ok=Number(row.dataset.from)===start&&Number(row.dataset.to)===end&&
   (group==='all'||row.dataset.priority===group);
  row.hidden=!ok;
  if(ok){visible++;changed+=Number(row.dataset.stageChanged);
    reverted+=Number(row.dataset.reverted);reply+=Number(row.dataset.replyChanged);
    follow+=Number(row.dataset.followChanged);}
 });
 output.textContent='HUMAN group summaries: '+visible+
  ' · changed end-stage rows: '+changed+
  ' · reverted interim HUMAN stages: '+reverted+
  ' · edited reply fields: '+reply+
  ' · edited follow-up fields: '+follow+
  '. These are self-reports, not verified progress.';
 empty.hidden=visible!==0;
}
[from,to,priority].forEach(el=>el.addEventListener('change',update));
update();
})();"""


def b64_sha(source: str) -> str:
    return base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")


def build(rows: list[dict], rounds: int) -> bytes:
    if not 2 <= rounds <= 8 or len(rows) > 100:
        raise Hold("HOLD: aggregate HUMAN interval viewer refuses unbounded data")
    allowed = {"urgent", "soon", "routine"}
    required_keys = {
        "operator_ordered_from_round", "operator_ordered_to_round",
        "human_priority", "stage_changed_rows", "reply_changed_rows",
        "next_question_changed_rows", "intermediate_stage_reverted_rows",
        "human_rows_in_priority",
    }
    for item in rows:
        if (type(item) is not dict or set(item) != required_keys or
            item["human_priority"] not in allowed or
            type(item["operator_ordered_from_round"]) is not int or
            type(item["operator_ordered_to_round"]) is not int or
            not 1 <= item["operator_ordered_from_round"] <
            item["operator_ordered_to_round"] <= rounds or
            any(type(item[key]) is not int or not 0 <= item[key] <= 64
                for key in required_keys - {
                    "human_priority", "operator_ordered_from_round",
                    "operator_ordered_to_round"})):
            raise Hold("HOLD: HUMAN browser data is not canonical bounded aggregate")
    def selector(name: str, selected: int) -> str:
        return "<select id='" + name + "'>" + "".join(
            "<option value='" + str(i) + "'" +
            (" selected" if i == selected else "") + ">" + str(i) + "</option>"
            for i in range(1, rounds+1)) + "</select>"

    table = "".join(
        "<tr data-from='" + str(item["operator_ordered_from_round"]) +
        "' data-to='" + str(item["operator_ordered_to_round"]) +
        "' data-priority='" + h(item["human_priority"]) +
        "' data-stage-changed='" + str(item["stage_changed_rows"]) +
        "' data-reverted='" + str(item["intermediate_stage_reverted_rows"]) +
        "' data-reply-changed='" + str(item["reply_changed_rows"]) +
        "' data-follow-changed='" + str(item["next_question_changed_rows"]) +
        "'><td>" + str(item["operator_ordered_from_round"]) + " → " +
        str(item["operator_ordered_to_round"]) + "</td><td>" +
        h(item["human_priority"]) + "</td><td>" +
        str(item["human_rows_in_priority"]) + "</td><td>" +
        str(item["stage_changed_rows"]) + "</td><td>" +
        str(item["intermediate_stage_reverted_rows"]) + "</td><td>" +
        str(item["reply_changed_rows"]) + "</td><td>" +
        str(item["next_question_changed_rows"]) + "</td></tr>"
        for item in rows)
    policy = ("default-src 'none'; style-src 'sha256-" + b64_sha(CSS) +
              "'; script-src 'sha256-" + b64_sha(JS) +
              "'; connect-src 'none'; img-src 'none'; font-src 'none'; " +
              "media-src 'none'; form-action 'none'; object-src 'none'; " +
              "base-uri 'none'; frame-src 'none'")
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" +
        h(policy) + "\"><title>PRIVATE HUMAN interval explorer</title>"
        "<style>" + CSS + "</style></head><body>"
        "<header><h1>LightUp · PRIVATE HUMAN interval explorer</h1>"
        "<p class='notice'>REVIEW ONLY · all HUMAN responses are self-reports. "
        "Round order was manually supplied; no real chronology, finding "
        "resolution, authorization, consent, disclosure or task assignment "
        "is authenticated.</p><p>Only counts and fixed HUMAN labels appear "
        "in this page. It contains no original endpoints, row ordinals, "
        "identifiers, evidence, notes or replies. Small counts can identify "
        "a client: keep PRIVATE. No browser storage, network or export.</p></header>"
        "<section><h2>Compare any two manually ordered rounds</h2>"
        "<div class='controls'><label>From round " + selector("from", 1) +
        "</label><label>To round " + selector("to", rounds) + "</label>"
        "<label>HUMAN priority<select id='priority'>"
        "<option value='all'>All priorities</option>"
        "<option value='urgent'>Urgent</option>"
        "<option value='soon'>Soon</option>"
        "<option value='routine'>Routine</option>"
        "</select></label></div><p id='summary' role='status'></p>"
        "<p id='empty' hidden>No recorded HUMAN group selected.</p>"
        "<table><thead><tr><th>Selected rounds</th><th>Priority</th>"
        "<th>Original HUMAN rows</th><th>End-stage changed</th>"
        "<th>Interim stage reverted</th><th>Reply changed</th>"
        "<th>Follow-up changed</th></tr></thead><tbody>" +
        table + "</tbody></table></section><section><h2>Interpretation</h2>"
        "<p>End-stage changes are the difference between selected first/last "
        "round status. Interim reversion counts mean at least one intermediate "
        "status differed although the endpoint status returned to its starting "
        "value. These categories can overlap with edited replies/next questions. "
        "No stage change proves improvement or remediation.</p></section>"
        "<script>" + JS + "</script></body></html>\n")
    return page.encode("utf-8")
