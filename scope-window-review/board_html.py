"""Private, script-hash-CSP, offline LightUp human window review board.

This is presentation of an already-validated retrospective agenda. No source
queries, permissions, model calls, target access, or browser persistence.
"""
from __future__ import annotations

from collections import Counter
from datetime import date
import base64
import hashlib
from html import escape
import json


CSS = """
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#e9f1f5;background:#0e1722}
*{box-sizing:border-box}body{max-width:1260px;margin:auto;padding:24px}
h1{font-size:clamp(1.6rem,3vw,2.7rem);margin:.2em 0}h2{font-size:1.2rem}
p{line-height:1.6}.muted{color:#a2b6c7}.caution{border-left:4px solid #edbe73;padding:12px 18px;background:#25291f}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:22px 0}
.metric{border:1px solid #35495a;background:#172638;border-radius:12px;padding:18px}
.metric strong{display:block;font-size:1.7rem;margin-top:8px}label{display:block;font-weight:600}
.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:end;padding:18px 0}
.controls>*{flex:1;min-width:165px}input,select,button{border:1px solid #506677;border-radius:8px;padding:10px 12px;background:#182735;color:#f8fafc;font:inherit}
button{cursor:pointer;flex:initial;background:#28445c}button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #e7bc77}
.group{margin:24px 0;border:1px solid #3b4e62;border-radius:12px;overflow:hidden}
.group>h2{margin:0;background:#1b3143;padding:14px 18px}
.entry{padding:18px;border-top:1px solid #354759;display:grid;grid-template-columns:minmax(250px,1fr) minmax(170px,220px);gap:22px}
.entry[hidden],.group[hidden]{display:none}
.entry p{margin:6px 0}.small{font-size:.9rem}.private{overflow-wrap:anywhere}
.held{border-left:5px solid #e69f78}.review{border-left:5px solid #86b2ca}
.badge{display:inline-block;border:1px solid #8299aa;border-radius:30px;padding:3px 12px;margin-bottom:8px}
.held .badge{color:#ffceae}.foot{margin:36px 0;font-size:.9rem}
@media(max-width:650px){body{padding:14px}.entry{grid-template-columns:1fr}}
@media print{body{background:white;color:black}.controls,button{display:none!important}.entry,.metric{background:white;color:black;border:1px solid #888}.group>h2{background:#eee;color:black}}
"""

JS = """
'use strict';
const rows = [...document.querySelectorAll('.entry')];
const groups = [...document.querySelectorAll('.group')];
const search = document.getElementById('query');
const priority = document.getElementById('priority');
const phase = document.getElementById('phase');
function refresh(){
  const q=search.value.trim().toLocaleLowerCase();
  let visible=0;
  for(const row of rows){
    const ok=(!q||row.dataset.find.includes(q)) &&
      (priority.value==='all'||row.dataset.priority===priority.value) &&
      (phase.value==='all'||row.dataset.phase===phase.value);
    row.hidden=!ok;
    if(ok)visible++;
  }
  for(const group of groups)group.hidden=![...group.querySelectorAll('.entry')].some(r=>!r.hidden);
  document.getElementById('shown').textContent=String(visible);
}
for(const el of [search,priority,phase])el.addEventListener('input',refresh);
const stages=new Map();
for(const row of rows){
 const selector=row.querySelector('.stage');
 selector.addEventListener('change',()=>{stages.set(row.dataset.key,selector.value);});
}
function emit(name,text,type){
 const blob=new Blob([text],{type});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.download=name;a.href=url;a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
document.getElementById('save').addEventListener('click',()=>{
 const changes=rows.filter(r=>stages.has(r.dataset.key)).map(r=>({
  grant_id:r.dataset.grant,engagement_id:r.dataset.engagement||null,
  human_stage:stages.get(r.dataset.key)
 }));
 const packet={
   schema:'lightup.scope_window_human_handoff.v1',status:'REVIEW_ONLY',
   source_digest:document.body.dataset.digest,
   note:'Human-only local stages; neither authenticated consent nor action-time grant.',
   authorization_granted:false,execution_allowed:false,release_approved:false,
   entries:changes
 };
 emit('lightup-private-human-followup.json',JSON.stringify(packet,null,2)+'\\n','application/json');
});
document.getElementById('aggregate').addEventListener('click',()=>{
 let map=new Map();
 for(const row of rows){
  const k=row.dataset.day+'|'+row.dataset.priority;
  map.set(k,(map.get(k)||0)+1);
 }
 const csv=['review_day_utc,source_attention,count'];
 for(const [key,count] of [...map].sort((a,b)=>a[0].localeCompare(b[0]))){
  const [day,status]=key.split('|');csv.push(day+','+status+','+count);
 }
 emit('lightup-anonymous-human-review-counts.csv',csv.join('\\r\\n')+'\\r\\n','text/csv');
});
const restoreInput=document.getElementById('restore');
const approveInput=document.getElementById('approve-restore');
const applyButton=document.getElementById('apply-restore');
const preview=document.getElementById('restore-preview');
const rowByOriginal=new Map(rows.map(row=>[
  JSON.stringify([row.dataset.grant,row.dataset.engagement||null]),row
]));
const legalStages=new Set(['unreviewed','investigating','escalated','documented']);
const requiredTop=['schema','status','source_digest','note','authorization_granted',
  'execution_allowed','release_approved','entries'];
const requiredEntry=['grant_id','engagement_id','human_stage'];
const exactKeys=(obj,fields)=>obj!==null && typeof obj==='object' &&
  !Array.isArray(obj) && Object.keys(obj).sort().join('|')===[...fields].sort().join('|');
let proposed=null;
const clearProposal=(message)=>{
 proposed=null;approveInput.checked=false;applyButton.disabled=true;
 preview.textContent=message;
};
restoreInput.addEventListener('change',async()=>{
 clearProposal('Reading local private human follow-up. No network request.');
 const file=restoreInput.files && restoreInput.files[0];
 if(!file){clearProposal('No local private file selected.');return;}
 try{
  if(file.size<1||file.size>131072)throw Error('Source note size exceeds 128 KiB.');
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
  const data=JSON.parse(raw);
  // Canonical serialization: duplicate keys, unexpected alternative spellings,
  // hidden extra whitespace and nonstandard JSON cannot survive this boundary.
  if(raw!==JSON.stringify(data,null,2)+'\n')
   throw Error('Non-canonical or duplicate-key private handoff.');
  if(!exactKeys(data,requiredTop) ||
     data.schema!=='lightup.scope_window_human_handoff.v1' ||
     data.status!=='REVIEW_ONLY' ||
     data.source_digest!==document.body.dataset.digest ||
     typeof data.note!=='string' || data.note.length>500 ||
     data.authorization_granted!==false || data.execution_allowed!==false ||
     data.release_approved!==false || !Array.isArray(data.entries) ||
     data.entries.length>rows.length)
   throw Error('Original source digest, schema, or safety flags differ.');
  const chosen=new Map();
  for(const entry of data.entries){
   if(!exactKeys(entry,requiredEntry) || typeof entry.grant_id!=='string' ||
      !legalStages.has(entry.human_stage) ||
      (entry.engagement_id!==null && typeof entry.engagement_id!=='string'))
    throw Error('Unknown private human-stage row.');
   const key=JSON.stringify([entry.grant_id,entry.engagement_id]);
   const matched=rowByOriginal.get(key);
   if(!matched || chosen.has(matched.dataset.key))
    throw Error('Duplicate, missing, or mismatching original case.');
   chosen.set(matched.dataset.key,entry.human_stage);
  }
  const expected=new Map(rows.map(row=>[
   row.dataset.key,row.querySelector('.stage').value
  ]));
  const changed=[...chosen].filter(([key,value])=>value!==expected.get(key));
  proposed={chosen,expected};
  const sample=changed.slice(0,8).map(([key,value])=>{
    const row=rows.find(r=>r.dataset.key===key);
    return (row?.dataset.grant||'')+': '+expected.get(key)+' → '+value;
  });
  preview.textContent='Private source-bound human preview: '+
    changed.length+' proposed stage change(s), '+chosen.size+
    ' total returned row(s). '+(sample.length?sample.join(' | '):'No stage changes.')+
    ' Only these local human fields can change. Verify sender and exact tenant externally.';
  applyButton.disabled=!changed.length;
 }catch(error){
  clearProposal('HOLD — private follow-up not imported: '+error.message);
 }
});
approveInput.addEventListener('change',()=>{
 if(!proposed)applyButton.disabled=true;
});
applyButton.addEventListener('click',()=>{
 if(!proposed||!approveInput.checked){
  preview.textContent='HOLD — verify the source and sender separately and tick the confirmation.';
  return;
 }
 if([...proposed.expected].some(([key,before])=>
    rows.find(row=>row.dataset.key===key)?.querySelector('.stage').value!==before)){
  clearProposal('HOLD — local human stages changed since preview; reselect the private file.');
  return;
 }
 const modified=[...proposed.chosen].filter(([key,stage])=>
   stage!==proposed.expected.get(key));
 for(const [key,stage] of modified){
  const row=rows.find(r=>r.dataset.key===key);
  row.querySelector('.stage').value=stage;
  if(stage==='unreviewed')stages.delete(key);
  else stages.set(key,stage);
 }
 clearProposal('Applied '+modified.length+' locally reviewed human stage(s). No original data, grant, STOP, consent or scanner changed.');
 restoreInput.value='';
});
refresh();
"""


def _attr(value: object) -> str:
    return escape(str(value), quote=True)


def _text(value: object) -> str:
    return escape(str(value), quote=False)


def render(agenda: dict) -> bytes:
    """Render only data pre-admitted by window_review. Browser does not re-read files."""
    rows = []
    by_day = {}
    for idx, item in enumerate(agenda["items"]):
        by_day.setdefault(item["review_date_utc"], []).append((idx, item))
    for day in sorted(by_day):
        elements = [f'<section class="group"><h2>Human review · {_text(day)} UTC</h2>']
        for idx, item in by_day[day]:
            held = item["human_priority"] == "HOLD"
            title = "Source requires HUMAN HOLD review" if held else "Recorded window follow-up"
            search = ' '.join(str(item[key]) for key in (
                "grant_id","engagement_id","phase","original_link_observation")).lower()
            elements.append(
                f'<article class="entry {"held" if held else "review"}" '
                f'data-day="{_attr(day)}" data-priority="{_attr(item["human_priority"])}" '
                f'data-phase="{_attr(item["phase"])}" data-find="{_attr(search)}" '
                f'data-key="{idx}" data-grant="{_attr(item["grant_id"])}" '
                f'data-engagement="{_attr(item["engagement_id"] or "")}">'
                '<div>'
                f'<span class="badge">{_text(item["human_priority"])}</span>'
                f'<h3>{_text(title)}</h3>'
                f'<p><strong>Original engagement:</strong> <span class="private">{_text(item["engagement_id"] or "SOURCE HOLD: detached")}</span></p>'
                f'<p><strong>Original grant:</strong> <span class="private">{_text(item["grant_id"])}</span></p>'
                f'<p><strong>Observed:</strong> {_text(item["phase"])}</p>'
                f'<p><strong>Human target:</strong> {_text(item["human_target_date_utc"])} UTC</p>'
                f'<p><strong>Capacity delay:</strong> {_text(item["capacity_shift_days"])} day(s) — delay is never permission to extend a grant</p>'
                f'<p><strong>Source link:</strong> {_text(item["original_link_observation"])}</p>'
                f'<p><strong>Original recorded window:</strong> {_text(item["original_valid_from"])} → {_text(item["original_valid_until"])}</p>'
                f'<p class="muted small">{_text(item["next_action"])}</p>'
                '</div><div>'
                f'<label for="stage-{idx}">Local human follow-up (not original status)</label>'
                f'<select class="stage" id="stage-{idx}">'
                '<option value="unreviewed">Not reviewed</option>'
                '<option value="investigating">Investigating</option>'
                '<option value="escalated">Escalate to original owner</option>'
                '<option value="documented">Documented for human follow-up</option>'
                '</select><p class="muted small">Selection stays in this tab only. Export is an unsigned human note.</p>'
                '</div></article>'
            )
        elements.append('</section>')
        rows.append(''.join(elements))
    counts = agenda["declared_counts"]
    metrics = [
        ("Review entries", counts["items"]),
        ("HOLD follow-ups", counts["hold"]),
        ("Review-only entries", counts["review_only"]),
        ("Source age warning", "YES" if agenda["stale_source_over_24h"] else "No"),
        ("Capacity-overflow HOLD", agenda["capacity_shifted_items"]),
    ]
    panels = ''.join(
        f'<div class="metric"><span>{_text(label)}</span><strong>{_text(value)}</strong></div>'
        for label, value in metrics
    )
    digest = hashlib.sha256(
        json.dumps(agenda, ensure_ascii=True, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    script_hash = base64.b64encode(hashlib.sha256(JS.encode()).digest()).decode()
    policy = (f"default-src 'none'; style-src 'sha256-{css_hash}'; "
              f"script-src 'sha256-{script_hash}'; connect-src 'none'; "
              "img-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{policy}">
<title>LightUp · human-only window reviews (PRIVATE)</title>
<style>{CSS}</style></head>
<body data-digest="{digest}">
<header><p class="muted">LIGHTUP / HUMAN REVIEW / PRIVATE ORIGINAL SOURCE</p>
<h1>Recorded grant-window follow-up</h1>
<p class="caution"><strong>{_text(agenda["status"])} — NO AUTHORIZATION.</strong>
Historic unsigned Casebook data, not current consent, grant validity, verified revocation, target permission or release.
Re-authenticate with the original client/operator and inspect live status before ANY real work.</p>
<p class="muted">Original recorded snapshot: {_text(agenda["as_of"])}.
Local planning preparation: {_text(agenda["prepared_at"])}.
Private selected tenant: <span class="private">{_text(agenda["client_id"])}</span>.</p></header>
<div class="grid">{panels}</div>
<div class="controls"><label>Find original private case or source observation
<input id="query" autocomplete="off" placeholder="Search local private identifiers"></label>
<label>Attention<select id="priority"><option value="all">All attention</option>
<option value="HOLD">HOLD only</option><option value="REVIEW_ONLY">Review only</option></select></label>
<label>Recorded boundary<select id="phase"><option value="all">All</option>
<option value="INVALID_WINDOW">Invalid window</option>
<option value="RECORDED_WINDOW_PASSED">Window passed</option>
<option value="RECORDED_START_UPCOMING">Start upcoming</option>
<option value="RECORDED_END_UPCOMING">End upcoming</option></select></label></div>
<p aria-live="polite" class="muted"><span id="shown">{counts["items"]}</span> visible items.
Review dates are capacity-adjusted HUMAN suggestions only, not original authorization deadlines.</p>
<section class="group" aria-label="Private human follow-up import">
<h2>Import original-source-bound PRIVATE human follow-up</h2>
<div class="controls"><label>Original private human JSON note
<input type="file" id="restore" accept=".json,application/json"></label></div>
<p id="restore-preview" class="muted" aria-live="polite">Only locally exported canonical notes for this exact source are accepted.</p>
<div class="controls"><label><input id="approve-restore" type="checkbox">
I independently verified the correct client, sender, source and proposed human changes (not consent)</label>
<button id="apply-restore" type="button" disabled>Apply human stage changes locally</button></div>
</section>
<div class="controls"><button id="save" type="button">Export PRIVATE human stage note</button>
<button id="aggregate" type="button">Export anonymous daily counts CSV</button></div>
<main>{''.join(rows) or '<p>No upcoming original grant-window records for this selected horizon.</p>'}</main>
<footer class="foot caution">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.
No network, browser persistence, model, scanner, grant or source modification. The private HTML and human stage note contain original opaque identifiers;
do not publish them. Calendar output omits them but retains potentially sensitive dates.</footer>
<script>{JS}</script></body></html>"""
    return html.encode("utf-8")
