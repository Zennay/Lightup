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
const stage=document.getElementById('stage');
const historyRows=Array.from(document.querySelectorAll('tr[data-stage-count]'));
const output=document.getElementById('summary');
const empty=document.getElementById('empty');
const rows=Array.from(document.querySelectorAll('tr[data-interval-summary]'));
const movements=Array.from(document.querySelectorAll('tr[data-movement]'));
function update(){
 const start=Number(from.value),end=Number(to.value),group=priority.value;
 if(!Number.isInteger(start)||!Number.isInteger(end)||start>=end){
  rows.forEach(row=>{row.hidden=true;});
  historyRows.forEach(row=>{row.hidden=true;});
  movements.forEach(row=>{row.hidden=true;});
  output.textContent='Select two different rounds in ascending manually supplied order.';
  empty.hidden=true;return;
 }
 let visible=0,changed=0,reverted=0,reply=0,follow=0;
 let pending=0,entered=0,exited=0,continuous=0,unanswered=0;
 rows.forEach(row=>{
  const ok=Number(row.dataset.from)===start&&Number(row.dataset.to)===end&&
   (group==='all'||row.dataset.priority===group);
  row.hidden=!ok;
  if(ok){visible++;changed+=Number(row.dataset.stageChanged);
    reverted+=Number(row.dataset.reverted);reply+=Number(row.dataset.replyChanged);
    follow+=Number(row.dataset.followChanged);
    pending+=Number(row.dataset.pending);
    entered+=Number(row.dataset.entered);
    exited+=Number(row.dataset.exited);
    continuous+=Number(row.dataset.continuous);
    unanswered+=Number(row.dataset.unanswered);}
 });
 output.textContent='HUMAN group summaries: '+visible+
  ' · changed end-stage rows: '+changed+
  ' · reverted interim HUMAN stages: '+reverted+
  ' · edited reply fields: '+reply+
  ' · edited follow-up fields: '+follow+
  ' · attention at both endpoints: '+pending+
  ' · newly awaiting HUMAN discussion: '+entered+
  ' · no longer awaiting HUMAN discussion (self-reported): '+exited+
  ' · attention in ALL selected intermediate rounds: '+continuous+
  ' · no HUMAN response in ALL selected rounds: '+unanswered+
  '. These are self-reports, not verified progress.';
 empty.hidden=visible!==0;
 movements.forEach(row=>{
  row.hidden=Number(row.dataset.from)!==start||Number(row.dataset.to)!==end||
   (group!=='all'&&row.dataset.priority!==group);
 });
 historyRows.forEach(row=>{
  row.hidden=Number(row.dataset.round)<start||Number(row.dataset.round)>end||
   (group!=='all'&&row.dataset.priority!==group)||
   (stage.value!=='all'&&row.dataset.stage!==stage.value);
 });
}
[from,to,priority,stage].forEach(el=>el.addEventListener('change',update));
update();
})();"""


def b64_sha(source: str) -> str:
    return base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")


def build(rows: list[dict], rounds: int, stage_counts: list[dict],
          attention: list[dict]) -> bytes:
    if not 2 <= rounds <= 8 or len(rows) > 100:
        raise Hold("HOLD: aggregate HUMAN interval viewer refuses unbounded data")
    allowed = {"urgent", "soon", "routine"}
    required_keys = {
        "operator_ordered_from_round", "operator_ordered_to_round",
        "human_priority", "stage_changed_rows", "reply_changed_rows",
        "next_question_changed_rows", "intermediate_stage_reverted_rows",
        "human_rows_in_priority", "human_stage_movements",
        "human_attention_before_rows", "human_attention_after_rows",
        "human_attention_entered_rows", "human_attention_exited_rows",
        "human_attention_persisted_rows",
        "human_attention_continuous_rows",
        "human_unanswered_continuous_rows",
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
                    "operator_ordered_to_round", "human_stage_movements"})):
            raise Hold("HOLD: HUMAN browser data is not canonical bounded aggregate")
    stages = {"blocked_human", "needs_more_information",
              "no_human_response", "responded_claimed"}
    for item in rows:
        flows = item["human_stage_movements"]
        if type(flows) is not list or len(flows) > 16:
            raise Hold("HOLD: unbounded HUMAN direction pairs")
        seen = set()
        for flow in flows:
            if (type(flow) is not dict or
                set(flow) != {"from_stage", "to_stage", "human_rows"} or
                flow["from_stage"] not in stages or
                flow["to_stage"] not in stages or
                type(flow["human_rows"]) is not int or
                not 1 <= flow["human_rows"] <= 64 or
                (flow["from_stage"], flow["to_stage"]) in seen):
                raise Hold("HOLD: invalid HUMAN directional movement")
            seen.add((flow["from_stage"], flow["to_stage"]))
        if (item["human_unanswered_continuous_rows"] >
                item["human_attention_continuous_rows"] or
            item["human_attention_continuous_rows"] >
                item["human_attention_persisted_rows"]):
            raise Hold("HOLD: HUMAN all-round attention continuity inconsistent")
        if (item["human_attention_entered_rows"] +
                item["human_attention_persisted_rows"] !=
                item["human_attention_after_rows"] or
            item["human_attention_exited_rows"] +
                item["human_attention_persisted_rows"] !=
                item["human_attention_before_rows"] or
            item["human_attention_before_rows"] >
                item["human_rows_in_priority"] or
            item["human_attention_after_rows"] >
                item["human_rows_in_priority"]):
            raise Hold("HOLD: unbalanced HUMAN attention report")
        if (sum(f["human_rows"] for f in flows) !=
                item["human_rows_in_priority"] or
            sum(f["human_rows"] for f in flows
                if f["from_stage"] != f["to_stage"]) !=
                item["stage_changed_rows"]):
            raise Hold("HOLD: HUMAN movement totals do not reconcile")
    if (type(stage_counts) is not list or len(stage_counts) != rounds * 12 or
        type(attention) is not list or len(attention) != 9):
        raise Hold("HOLD: incomplete HUMAN status trend is not canonical")
    count_keys = {"operator_ordered_round", "human_priority", "human_stage",
                  "human_rows"}
    for item in stage_counts:
        if (type(item) is not dict or set(item) != count_keys or
            item["human_priority"] not in allowed or
            item["human_stage"] not in stages or
            type(item["operator_ordered_round"]) is not int or
            not 1 <= item["operator_ordered_round"] <= rounds or
            type(item["human_rows"]) is not int or
            not 0 <= item["human_rows"] <= 64):
            raise Hold("HOLD: unexpected HUMAN status trend")
    for item in attention:
        if (type(item) is not dict or
            set(item) != {"human_priority", "human_stage", "human_rows"} or
            item["human_priority"] not in allowed or
            item["human_stage"] not in
            {"blocked_human", "needs_more_information", "no_human_response"} or
            type(item["human_rows"]) is not int or
            not 0 <= item["human_rows"] <= 64):
            raise Hold("HOLD: unexpected HUMAN attention summary")
    def selector(name: str, selected: int) -> str:
        return "<select id='" + name + "'>" + "".join(
            "<option value='" + str(i) + "'" +
            (" selected" if i == selected else "") + ">" + str(i) + "</option>"
            for i in range(1, rounds+1)) + "</select>"

    table = "".join(
        "<tr data-interval-summary='yes' data-from='" + str(item["operator_ordered_from_round"]) +
        "' data-to='" + str(item["operator_ordered_to_round"]) +
        "' data-priority='" + h(item["human_priority"]) +
        "' data-stage-changed='" + str(item["stage_changed_rows"]) +
        "' data-reverted='" + str(item["intermediate_stage_reverted_rows"]) +
        "' data-reply-changed='" + str(item["reply_changed_rows"]) +
        "' data-pending='" + str(item["human_attention_persisted_rows"]) +
        "' data-continuous='" + str(item["human_attention_continuous_rows"]) +
        "' data-unanswered='" + str(item["human_unanswered_continuous_rows"]) +
        "' data-entered='" + str(item["human_attention_entered_rows"]) +
        "' data-exited='" + str(item["human_attention_exited_rows"]) +
        "' data-follow-changed='" + str(item["next_question_changed_rows"]) +
        "'><td>" + str(item["operator_ordered_from_round"]) + " → " +
        str(item["operator_ordered_to_round"]) + "</td><td>" +
        h(item["human_priority"]) + "</td><td>" +
        str(item["human_rows_in_priority"]) + "</td><td>" +
        str(item["stage_changed_rows"]) + "</td><td>" +
        str(item["intermediate_stage_reverted_rows"]) + "</td><td>" +
        str(item["reply_changed_rows"]) + "</td><td>" +
        str(item["next_question_changed_rows"]) + "</td><td>" +
        str(item["human_attention_persisted_rows"]) + "</td><td>" +
        str(item["human_attention_entered_rows"]) + "</td><td>" +
        str(item["human_attention_exited_rows"]) + "</td><td>" +
        str(item["human_attention_continuous_rows"]) + "</td><td>" +
        str(item["human_unanswered_continuous_rows"]) + "</td></tr>"
        for item in rows)
    movement_table = "".join(
        "<tr data-movement='yes' data-from='" +
        str(item["operator_ordered_from_round"]) +
        "' data-to='" + str(item["operator_ordered_to_round"]) +
        "' data-priority='" + h(item["human_priority"]) +
        "'><td>" + h(item["human_priority"]) + "</td><td>" +
        h(flow["from_stage"]) + "</td><td>" + h(flow["to_stage"]) +
        "</td><td>" + str(flow["human_rows"]) + "</td></tr>"
        for item in rows for flow in item["human_stage_movements"])
    trend_table = "".join(
        "<tr data-stage-count='yes' data-round='" +
        str(item["operator_ordered_round"]) +
        "' data-priority='" + h(item["human_priority"]) +
        "' data-stage='" + h(item["human_stage"]) +
        "'><td>" + str(item["operator_ordered_round"]) + "</td><td>" +
        h(item["human_priority"]) + "</td><td>" +
        h(item["human_stage"]) + "</td><td>" +
        str(item["human_rows"]) + "</td></tr>"
        for item in stage_counts)
    attention_table = "".join(
        "<tr><td>" + h(item["human_priority"]) + "</td><td>" +
        h(item["human_stage"]) + "</td><td>" +
        str(item["human_rows"]) + "</td></tr>"
        for item in attention)
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
        "</select></label>"
        "<label>Filter stage history<select id='stage'>"
        "<option value='all'>All HUMAN stages</option>"
        "<option value='blocked_human'>Blocked (HUMAN)</option>"
        "<option value='needs_more_information'>Needs more information</option>"
        "<option value='no_human_response'>No HUMAN response</option>"
        "<option value='responded_claimed'>Responded (claimed)</option>"
        "</select></label></div><p id='summary' role='status'></p>"
        "<p id='empty' hidden>No recorded HUMAN group selected.</p>"
        "<table><thead><tr><th>Selected rounds</th><th>Priority</th>"
        "<th>Original HUMAN rows</th><th>End-stage changed</th>"
        "<th>Interim stage reverted</th><th>Reply changed</th>"
        "<th>Follow-up changed</th><th>Still awaiting HUMAN discussion</th>"
        "<th>New HUMAN attention</th><th>No longer needing HUMAN attention "
        "(claimed)</th><th>Attention in every selected round</th>"
        "<th>No reply in any selected round</th></tr></thead><tbody>" +
        table + "</tbody></table></section>"
        "<section><h2>Directional HUMAN stage movements</h2>"
        "<p>Earlier-to-later self-reported status counts for the selected "
        "HUMAN rounds and original priority, including unchanged statuses. "
        "These categories are not proven remediation or progress.</p>"
        "<table><thead><tr><th>Priority</th><th>Earlier HUMAN stage</th>"
        "<th>Later HUMAN stage</th><th>HUMAN rows</th></tr></thead>"
        "<tbody>" + movement_table + "</tbody></table></section>"
        "<section><h2>HUMAN stage history within selected interval</h2>"
        "<p>The stage filter above applies here. Counts are self-reported; "
        "no verified findings, consent or assignments.</p><table><thead><tr>"
        "<th>Manually supplied round</th><th>Priority</th><th>HUMAN stage</th>"
        "<th>Rows</th></tr></thead><tbody>" + trend_table +
        "</tbody></table></section>"
        "<section><h2>Latest HUMAN attention counts (no task dispatch)</h2>"
        "<p>Blocked, unanswered, and needing information are self-reported "
        "states, not independent verification. Displayed across all priorities "
        "regardless of the selectors.</p><table><thead><tr><th>Priority</th>"
        "<th>HUMAN stage</th><th>Rows</th></tr></thead><tbody>" +
        attention_table + "</tbody></table></section>"
        "<section><h2>Interpretation</h2>"
        "<p>End-stage changes are the difference between selected first/last "
        "round status. Interim reversion counts mean at least one intermediate "
        "status differed although the endpoint status returned to its starting "
        "value. These categories can overlap with edited replies/next questions. "
        "No stage change proves improvement or remediation.</p></section>"
        "<script>" + JS + "</script></body></html>\n")
    return page.encode("utf-8")
