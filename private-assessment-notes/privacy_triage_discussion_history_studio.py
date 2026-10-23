#!/usr/bin/env python3
"""Offline PRIVATE HUMAN action trajectory navigator without original note text.

This HTML is read-only. It cannot attest privacy, source authenticity,
remediation or reviewer identity. All source/review admission remains native.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import json


def render(items: list[dict], originals: int, rounds: int) -> bytes:
    if not 1 <= originals <= 12 or not 2 <= rounds <= 8:
        raise ValueError("unsupported PRIVATE HUMAN chronology shape")
    expected = originals * rounds
    if len(items) != expected:
        raise ValueError("incomplete original HUMAN chronology")
    records = [{
        "ordinal": item["ordinal"],
        "round": item["round"],
        "stage": item["step"],
        "stepChanged": item["stage_changed"],
        "questionPresent": item["question_present"],
        "questionChanged": item["question_changed"],
    } for item in items]
    encoded = json.dumps(records, ensure_ascii=True, separators=(",", ":")).replace("<", r"\u003c")
    script = """'use strict';
const history = """ + encoded + """;
const stages=['PENDING','DISCUSS','REQUEST_OWNER_CONTEXT','WITHHOLD'];
const roundsCount = """ + str(rounds) + """;
const originalCount = """ + str(originals) + """;
const root=document.getElementById('rows');
const only=document.getElementById('only');
const round=document.getElementById('round');
const find=document.getElementById('find');
const stage=document.getElementById('stage');
const status=document.getElementById('summary');
const empty=document.getElementById('empty');
function make(tag,text){
 const e=document.createElement(tag);
 if(text!==undefined)e.textContent=text;
 return e;
}
for(let n=1;n<=roundsCount;n++){
 const o=make('option','HUMAN round '+n);
 o.value=String(n);round.append(o);
}
for(const choice of stages){
 const o=make('option',choice.replaceAll('_',' '));
 o.value=choice;stage.append(o);
}
const cells=[];
for(const item of history){
 const line=make('tr');
 const flags=[];
 if(item.stepChanged)flags.push('HUMAN stage changed');
 if(item.questionChanged)flags.push('PRIVATE question content changed (withheld)');
 if(!flags.length)flags.push('No literal stage/question change; NOT a fix');
 for(const value of [
   '#'+item.ordinal,'HUMAN '+item.round,item.stage,
   item.questionPresent?'Present; text withheld':'Blank',
   flags.join('; ')]){
    line.append(make('td',value));
 }
 root.append(line);cells.push({item,line});
}
function visible(x){
 const o=only.value;
 if(round.value!=='ALL'&&String(x.round)!==round.value)return false;
 if(stage.value!=='ALL'&&x.stage!==stage.value)return false;
 if(find.value.trim()&&!String(x.ordinal).includes(find.value.trim()))return false;
 return o==='ALL' || (o==='STEPS'&&x.stepChanged) ||
   (o==='QUESTIONS'&&x.questionChanged) ||
   (o==='ANY'&&(x.stepChanged||x.questionChanged)) ||
   (o==='WITHHOLD'&&x.stage==='WITHHOLD');
}
function update(){
 let shown=0,stepChanges=0,questionChanges=0;
 for(const {item,line} of cells){
  const yes=visible(item);line.hidden=!yes;
  if(yes)shown++;
  if(item.stepChanged)stepChanges++;
  if(item.questionChanged)questionChanges++;
 }
 empty.hidden=shown!==0;
 status.textContent=shown+' of '+history.length+' PRIVATE HUMAN round/source rows visible; '+
  stepChanges+' literal HUMAN stage transitions and '+
  questionChanges+' PRIVATE question-change indications overall. '+
  'No status represents a verified security fix or authenticated reviewer.';
}
for(const element of [only,round,find,stage]){
 element.addEventListener(element===find?'input':'change',update);
}
update();
document.getElementById('download').addEventListener('click',()=>{
 const selected=history.filter(visible);
 if(!selected.length){
  status.textContent='No visible HUMAN rows; no local selected-only export.';
  return;
 }
 if(!window.confirm('Download selected PRIVATE ordinal-only HUMAN history? Not approved for disclosure.'))return;
 const headers=['original_ordinal','human_round','human_step','human_stage_changed','private_question_present','private_question_changed'];
 const lines=[headers.join(',')];
 const quote=v=>'"'+String(v).replaceAll('"','""')+'"';
 for(const item of selected){
  lines.push([item.ordinal,item.round,item.stage,item.stepChanged,item.questionPresent,item.questionChanged]
    .map(x=>quote(typeof x==='boolean'?(x?'TRUE':'FALSE'):x)).join(','));
 }
 const blob=new Blob([lines.join('\\r\\n')+'\\r\\n'],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob),link=make('a');
 link.href=url;link.download='PRIVATE-HUMAN-selected-action-history.csv';
 document.body.append(link);link.click();link.remove();
 setTimeout(()=>URL.revokeObjectURL(url),15000);
 status.textContent='Saved PRIVATE local selected-only discussion CSV; not a full ORIGINAL review or an authorization.';
});
"""
    pin = b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'sha256-""" +
            pin + """';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN action chronology browser</title>
<style>
body{font:16px/1.6 system-ui;color:#193348;max-width:1100px;margin:2rem auto;padding:1rem}
aside{border-left:5px solid #b34624;background:#fff1e9;padding:1rem}
.controls{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}
.controls label{display:grid;gap:4px}
select,input{padding:9px}button{padding:12px;margin:9px 0}
table{width:100%;border-collapse:collapse}td,th{padding:10px;border:1px solid #ccd;text-align:left}
thead{background:#ebf1f6}tr[hidden]{display:none}
:focus-visible{outline:3px solid #c77d1d}
@media print{button,.controls{display:none}}
</style>
<h1>Original-bound PRIVATE HUMAN action timeline</h1>
<aside><b>INCUBATE · HUMAN ONLY · DRAFT/HOLD.</b>
This private viewer contains original ordinal-only HUMAN follow-up stages
and Boolean PRIVATE question-change indicators, never question text, source
hashes, targets, original evidence or reviewer identity. A changed status or
question is not a verified fix, permission, consent, authentic chronology or
release clearance. All filters are LOCAL and visual. Do not publish any export.</aside>
<div class="controls">
<label>HUMAN round <select id="round"><option value="ALL">All rounds</option></select></label>
<label>Follow-up status <select id="stage"><option value="ALL">All HUMAN stages</option></select></label>
<label>Focus <select id="only">
<option value="ALL">All original positions</option>
<option value="ANY">Any HUMAN change</option>
<option value="STEPS">HUMAN stage changed</option>
<option value="QUESTIONS">PRIVATE question changed</option>
<option value="WITHHOLD">Current HUMAN WITHHOLD</option>
</select></label>
<label>Original ordinal <input id="find" placeholder="Original position" inputmode="numeric"></label>
</div><p id="summary" role="status" aria-live="polite"></p>
<table><thead><tr><th scope="col">Original position</th><th scope="col">Declared round</th>
<th scope="col">HUMAN next step</th><th scope="col">PRIVATE question</th>
<th scope="col">Literal change</th></tr></thead><tbody id="rows"></tbody></table>
<p id="empty" hidden>No source rounds match the local filter.</p>
<button id="download" type="button">Download visible PRIVATE HUMAN ordinal history</button>
<p>Exporting only visible rows does not replace full original source-bound packets
or independently verified consent. No model, network, assessment, grant, scan,
identity check, dispatch, customer disclosure or live release.</p>
<script>""" + script + """</script></html>""").encode("utf-8")
