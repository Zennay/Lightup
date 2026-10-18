"""Self-contained PRIVATE browser workbench for original operator request snapshots.

HTML is produced exclusively after genuine source authentication. The original
snapshot remains unsigned/stale; all browser states are human-only preparations.
No authority, network request, handler, grant, consent or persistence.
"""
from __future__ import annotations
from html import escape
from pathlib import Path
import base64
import hashlib
import json

from .request_binding_readiness_cli import AUTHORITY
from .request_binding_handoff import QUESTIONS

STYLE = """
:root{font:15px/1.5 system-ui,sans-serif;color:#edf4ff;background:#0c1424;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1390px;margin:auto;padding:30px 22px 90px}
header{border-bottom:1px solid #344b68;padding-bottom:20px}h1{font-size:clamp(1.9rem,4vw,3rem);letter-spacing:-.035em;margin:5px 0}
h2{font-size:1.35rem;margin:0 0 12px}h3{font-size:1.1rem;margin:0}
p{color:#c2d3e7;max-width:1050px}small,.hint{font-size:.85rem;color:#adbed4}
.overline{color:#97c9fa;font-size:.73rem;letter-spacing:.15em;font-weight:800}
section{padding:23px;margin:22px 0;background:#182940;border:1px solid #405979;border-radius:15px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin:22px 0}
.stat{border:1px solid #3a5677;border-radius:12px;padding:16px;background:#102137}
.stat strong{display:block;font-size:1.8rem;color:#a4e5d6}.stat span{color:#bdd0e2}
.controls{display:flex;flex-wrap:wrap;align-items:end;gap:14px;margin:15px 0}
.controls label,.case label{display:grid;gap:6px;font-weight:600;font-size:.9rem}
input,select,textarea{font:inherit;background:#0b182a;color:#e9f4ff;border:1px solid #607c9c;padding:9px;border-radius:8px;max-width:100%}
input[type=search]{min-width:270px}input[type=date]{width:180px}
textarea{width:100%;min-height:65px;resize:vertical;font-weight:400}
button,.fileButton{font:inherit;font-weight:650;border:1px solid #79aff0;background:#204a74;padding:9px 16px;border-radius:9px;color:#fff;cursor:pointer}
button:hover,.fileButton:hover{background:#38658f}button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #afe0ff;outline-offset:2px}
.fileButton{position:relative;display:inline-block;overflow:hidden}.fileButton input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:15px}
.case{border:1px solid #486381;background:#122137;padding:17px;border-radius:12px;display:grid;gap:13px}
.casehead{display:flex;justify-content:space-between;gap:12px;align-items:start;flex-wrap:wrap}
.pill{font-size:.78rem;border:1px solid #7791b0;padding:3px 9px;border-radius:999px}
.pill.match{color:#f1c88d;border-color:#ad8652}
.pill.miss{color:#ffbcb5;border-color:#a76869}
.pill.unreviewed{color:#aed9f1}
.flags{font-size:.85rem;color:#cbdceb;overflow-wrap:anywhere;line-height:1.65}
.flags span{border:1px solid #455f7a;padding:3px 6px;border-radius:5px;margin-right:4px}
.fieldgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}
.fieldgrid select,.fieldgrid input{width:100%}
.notice{border-left:4px solid #d2ac76;background:#352e29;padding:12px;border-radius:7px;color:#f9e2c1}
.footer{color:#b7c7dc;border-top:1px solid #49617d;padding-top:24px;margin-top:26px}
.empty{color:#c4d4e8;padding:16px}code{overflow-wrap:anywhere}
@media(max-width:600px){body{padding:12px}.fieldgrid{grid-template-columns:1fr}section{padding:15px}input[type=search]{min-width:100%}.controls button,.fileButton{width:100%;text-align:center}}
@media print{body,section,.case,.stat{background:white;color:black}section,.case{break-inside:avoid}.controls,button,select,input,textarea,.fileButton{display:none!important}p,.footer,.hint{color:black}}
"""

SCRIPT = r"""
(()=>{'use strict';
const $=id=>document.getElementById(id), allowedStatus=['unreviewed','question_prepared','escalated','discussed_unverified'];
const allowedOwner=['unassigned','client_liaison','operator','security_source_owner','privacy'];
const flagPattern=/^[A-Z][A-Z0-9_]{1,85}$/;
const dateValid=v=>v===''||(/^20[2-9]\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/.test(v)&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v);
const exact=(obj,required)=>obj!==null&&typeof obj==='object'&&!Array.isArray(obj)&&
 required.every(k=>Object.prototype.hasOwnProperty.call(obj,k))&&Object.keys(obj).length===required.length;
const source=JSON.parse($('sourceData').textContent);
const questions=JSON.parse($('questionsData').textContent);
const flagsFalse=['client_consent_verified','operator_consent_verified','authorization_granted','execution_allowed','release_approved'];
const fixedAuthority=Object.fromEntries(flagsFalse.map(k=>[k,false]));
const approved=source.disposition==='REVIEW_ONLY_SCENARIOS';
const scopes=approved?source.scenarios.map((entry,i)=>({index:i+1,label:entry.label,report:entry.original_source})):
 [{index:1,label:'Single original proposal',report:source}];
const planFingerprint=$('sourceData').dataset.fingerprint;
const readOnly=Object.freeze(scopes.flatMap(scope=>scope.report.candidates.map(row=>Object.freeze({
 key:scope.index+':'+row.private_reference,slot:scope.index,ordinal:row.ordinal,
 status:row.request_source_status,stored:row.stored_status,risk:row.requested_risk,
 flags:Object.freeze(row.review_flags_non_authorizing.slice()),
 prior:row.previously_bound_grant_rows,
 token:row.private_reference
}))));
const recordKeys=new Set(readOnly.map(r=>r.key));if(recordKeys.size!==readOnly.length)
 throw Error('HOLD: ambiguous duplicated source tokens');
if(!/^[a-f0-9]{64}$/.test(planFingerprint)||!exact(source.authority,flagsFalse)||flagsFalse.some(k=>source.authority[k]!==false))
 throw Error('HOLD: source authority envelope invalid');
const drafts=new Map(readOnly.map(r=>[r.key,{stage:'unreviewed',owner:'unassigned',due:'',note:''}]));
const text=(tag,value,cl)=>{const v=document.createElement(tag);if(value!==undefined)v.textContent=String(value);if(cl)v.className=cl;return v;};
const setMsg=m=>{$('message').textContent=m;};
const allCases=()=>readOnly.map(r=>({...r,local:drafts.get(r.key)}));
const filtered=()=>{
 const q=$('query').value.toUpperCase().trim();
 return allCases().filter(r=>
  ($('scopeFilter').value==='all'||Number($('scopeFilter').value)===r.slot)&&
  ($('kindFilter').value==='all'||r.status===$('kindFilter').value)&&
  ($('ownerFilter').value==='all'||r.local.owner===$('ownerFilter').value)&&
  ($('stageFilter').value==='all'||r.local.stage===$('stageFilter').value)&&
  (!q||r.flags.join(' ').includes(q)||r.status.toUpperCase().includes(q)||
    r.token.toUpperCase().includes(q))
 );
};
function drawStats(){
 const rows=allCases(),review=rows.filter(r=>r.status==='candidate_review_only');
 $('total').textContent=rows.length;$('matches').textContent=review.length;
 $('unreviewed').textContent=rows.filter(r=>r.local.stage==='unreviewed').length;
 $('escalations').textContent=rows.filter(r=>r.local.stage==='escalated').length;
 const other=rows.filter(r=>r.local.due&&r.local.due<new Date().toISOString().slice(0,10)&&r.local.stage!=='discussed_unverified');
 $('pastDue').textContent=other.length;
}
function selectControl(values,current,onChange){
 const select=text('select');for(const v of values){const option=text('option',v.replaceAll('_',' '));option.value=v;option.selected=v===current;select.append(option);}
 select.addEventListener('change',()=>onChange(select.value));return select;
}
function draw(){
 drawStats();drawThemes();const cases=filtered(),root=$('cases');root.replaceChildren();
 $('count').textContent=cases.length+' original request rows in the selected human view';
 for(const r of cases.slice(0,500)){
  const row=text('article',undefined,'case'),top=text('div',undefined,'casehead');
  const title=text('div');title.append(text('h3','Scope '+r.slot+' · request #'+r.ordinal));
  title.append(text('small','Private pseudonym '+r.token+' · stored status '+r.stored));
  top.append(title);
  top.append(text('span',r.status.replaceAll('_',' '),'pill '+(r.status==='candidate_review_only'?'match':'miss')));
  row.append(top);
  const info=text('p','Requested stored risk: '+(r.risk??'invalid')+' · historical linked grant rows: '+r.prior+' (not current consent)');
  row.append(info);
  const flag=text('div',undefined,'flags');if(r.flags.length){for(const f of r.flags)flag.append(text('span',f.replaceAll('_',' ')));}else flag.append(text('span','No listed source mismatch; not approved for execution.'));
  row.append(flag);
  const fields=text('div',undefined,'fieldgrid');
  const stateLabel=text('label','Human discussion stage (unverified)');
  stateLabel.append(selectControl(allowedStatus,r.local.stage,v=>{r.local.stage=v;drawStats();drawThemes();setMsg('Local review stage updated; not saved unless explicitly exported.');}));
  const ownerLabel=text('label','Human follow-up channel (unverified)');
  ownerLabel.append(selectControl(allowedOwner,r.local.owner,v=>{r.local.owner=v;drawStats();setMsg('Locally assigned channel; no real notification sent.');}));
  const dueLabel=text('label','Tentative follow-up date (UTC)');
  const date=text('input');date.type='date';date.min='2020-01-01';date.max='2099-12-31';date.value=r.local.due;
  date.addEventListener('change',()=>{if(!dateValid(date.value)){date.value=r.local.due;setMsg('HOLD: invalid date.');return;}r.local.due=date.value;drawStats();});
  dueLabel.append(date);fields.append(stateLabel,ownerLabel,dueLabel);row.append(fields);
  const noteLabel=text('label','Private operator note · not included in aggregate exports');
  const note=text('textarea');note.maxLength=400;note.value=r.local.note;note.placeholder='Optional human coordination; do not paste credentials or customer secrets.';
  note.addEventListener('input',()=>{if(note.value.length>400){setMsg('HOLD: note too long');return;}r.local.note=note.value;});
  noteLabel.append(note);row.append(noteLabel);root.append(row);
 }
 if(cases.length>500)root.append(text('p','First 500 cases displayed; use filters. All records remain available in private draft.','notice'));
 if(!cases.length)root.append(text('p','No matching human review cases.','empty'));
}
function drawThemes(){
 const root=$('themes');root.replaceChildren();
 const totals=new Map();
 for(const r of allCases())for(const code of r.flags){
  const original=questions[code];if(!original)continue;
  const record=totals.get(code)||{occurrences:0,keys:new Set(),unreviewed:0,escalated:0};
  record.occurrences++;record.keys.add(r.token);
  if(r.local.stage==='unreviewed')record.unreviewed++;
  if(r.local.stage==='escalated')record.escalated++;
  totals.set(code,record);
 }
 const order={security_owner:0,client:1,operator:2};
 const sorted=[...totals].sort((a,b)=>
  order[questions[a[0]][0]]-order[questions[b[0]][0]]||
  b[1].unreviewed-a[1].unreviewed||a[0].localeCompare(b[0]));
 $('themeCount').textContent=sorted.length+' source-reported reason categories, not verified vulnerabilities';
 for(const [reason,tot] of sorted){
  const box=text('article',undefined,'case');
  box.append(text('h3',reason.replaceAll('_',' ')));
  box.append(text('p','Human follow-up: '+questions[reason][0].replaceAll('_',' ')+
   ' · '+tot.occurrences+' across alternatives · '+tot.keys.size+
   ' distinct original pseudonymous records · '+tot.unreviewed+' unreviewed · '+
   tot.escalated+' locally escalated (NOT sourceowner action)'));
  box.append(text('p',questions[reason][1],'hint'));
  const actions=text('div',undefined,'controls');
  for(const [stage,label] of [['question_prepared','Prepare unanswered'],
                               ['escalated','Escalate unanswered']]){
   const button=text('button',label);button.addEventListener('click',()=>{
    const affected=allCases().filter(row=>row.flags.includes(reason)&&row.local.stage==='unreviewed');
    if(!affected.length){setMsg('No unreviewed original rows for this category.');return;}
    if(!confirm('Change '+affected.length+' local, unreviewed case stages to '+
      stage.replaceAll('_',' ')+'? This does NOT notify a client/operator or approve/revoke a grant.'))return;
    for(const row of affected)drafts.get(row.key).stage=stage;
    draw();setMsg('Changed '+affected.length+' local HUMAN-ONLY stages; no backend, scan, consent or grant was touched.');
   });actions.append(button);
  }
  box.append(actions);root.append(box);
 }
 if(!sorted.length)root.append(text('p','No recorded mismatch reason. This does not certify permission.','hint'));
}
function download(filename,payload,type){
 const data=new Blob([payload],{type});const url=URL.createObjectURL(data),a=text('a');
 a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
const MAX_EXPORT=2_000_000;
function savePrivate(){
 const entries=allCases().map(r=>({key:r.key,stage:r.local.stage,owner:r.local.owner,due:r.local.due,note:r.local.note}));
 const data={format:'lightup.private_request_binding_review_draft_v1',disposition:'REVIEW_ONLY',
  authority:{...fixedAuthority},plan_fingerprint_unsigned:planFingerprint,entries};
 const wire=JSON.stringify(data,null,2)+'\n';
 if(wire.length>MAX_EXPORT){setMsg('HOLD: private draft exceeds size limit');return;}
 download('lightup-private-request-binding-working-draft.json',wire,'application/json');
 setMsg('PRIVATE source-bound draft downloaded. Keep it confidential; never treat as consent or grant.');
}
function canonicalParser(str){
 let i=0,n=0;const fail=()=>{throw Error('Duplicate, malformed or unsupported JSON.');};
 const ws=()=>{while(/[ \n\r\t]/.test(str[i]||'')&&i<str.length)i++;};
 const parseString=()=>{if(str[i]!=='"')fail();const start=i++;let escapeNext=false;
   while(i<str.length){const c=str[i++];if(!escapeNext&&c==='"'){try{return JSON.parse(str.slice(start,i));}catch{fail();}}
   if(c.charCodeAt(0)<32&&!escapeNext)fail();if(!escapeNext&&c==='\\')escapeNext=true;else escapeNext=false;}fail();};
 const value=depth=>{if(depth>25||++n>50000)fail();ws();const c=str[i];if(c==='"')return parseString();
  if(c==='{'){i++;ws();const obj=Object.create(null),seen=new Set();if(str[i]==='}'){i++;return obj;}
   for(;;){ws();const key=parseString();if(seen.has(key))fail();seen.add(key);ws();if(str[i++]!==':')fail();
    Object.defineProperty(obj,key,{value:value(depth+1),enumerable:true,configurable:true,writable:true});
    ws();if(str[i]==='}'){i++;return obj;}if(str[i++]!==',')fail();}}
  if(c==='['){i++;ws();const out=[];if(str[i]===']'){i++;return out;}
   for(;;){out.push(value(depth+1));ws();if(str[i]===']'){i++;return out;}if(str[i++]!==',')fail();}}
  const tail=str.slice(i);const num=tail.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
  if(num){i+=num[0].length;const v=Number(num[0]);if(!Number.isFinite(v))fail();return v;}
  for(const [k,v] of [['true',true],['false',false],['null',null]])if(tail.startsWith(k)){i+=k.length;return v;}
  fail();};
 const doc=value(0);ws();if(i!==str.length)fail();return doc;
}
async function restore(file){
 if(!file||file.size<1||file.size>MAX_EXPORT)throw Error('Private draft missing or oversized');
 const doc=canonicalParser(new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()));
 if(!exact(doc,['format','disposition','authority','plan_fingerprint_unsigned','entries'])||
 doc.format!=='lightup.private_request_binding_review_draft_v1'||doc.disposition!=='REVIEW_ONLY'||
 !exact(doc.authority,flagsFalse)||flagsFalse.some(k=>doc.authority[k]!==false)||
 doc.plan_fingerprint_unsigned!==planFingerprint||!Array.isArray(doc.entries)||doc.entries.length!==recordKeys.size)throw Error('HOLD: original source or private draft schema changed');
 const next=new Map();
 for(const r of doc.entries){
  if(!exact(r,['key','stage','owner','due','note'])||typeof r.key!=='string'||!recordKeys.has(r.key)||
   next.has(r.key)||!allowedStatus.includes(r.stage)||!allowedOwner.includes(r.owner)||
   typeof r.due!=='string'||!dateValid(r.due)||typeof r.note!=='string'||r.note.length>400||
   /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(r.note))throw Error('HOLD: invalid private row; none restored');
  next.set(r.key,{stage:r.stage,owner:r.owner,due:r.due,note:r.note});
 }
 drafts.clear();for(const [key,value] of next)drafts.set(key,value);draw();
 setMsg('Original-byte source-bounded local human notes restored. No authority, grants, consent or revocation were restored.');
}
function aggregate(){
 const counts={},themes={};
 for(const r of allCases())for(const reason of r.flags){
  if(!Object.hasOwn(questions,reason))continue;
  if(!themes[reason])themes[reason]={source_reason:reason,source_occurrences:0,local_unreviewed:0,
    human_owner:questions[reason][0]};
  themes[reason].source_occurrences++;
  if(r.local.stage==='unreviewed')themes[reason].local_unreviewed++;
 }
 for(const r of allCases()){
  const key=r.slot+':'+r.local.owner+':'+r.local.stage+':'+r.status;
  if(!counts[key])counts[key]={slot:r.slot,owner:r.local.owner,stage:r.local.stage,source_match:r.status,count:0};
  counts[key].count++;
 }
 return {format:'lightup.binding_human_coordination_aggregate_v1',disposition:'REVIEW_ONLY',
  authority:{...fixedAuthority},source_is_unsigned:true,may_contain_multiple_alternatives:true,
  summary:Object.values(counts).sort((a,b)=>a.slot-b.slot||a.owner.localeCompare(b.owner)||a.stage.localeCompare(b.stage)),
  human_source_reason_themes:Object.values(themes).sort((a,b)=>a.source_reason.localeCompare(b.source_reason))};
}
function exportAggregate(kind){
 const data=aggregate();if(kind==='json')download('lightup-binding-human-aggregate.json',
  JSON.stringify(data,null,2)+'\n','application/json');
 else{
  const quoted=v=>'"'+String(v).replaceAll('"','""')+'"';
  const lines=[['proposal_slot','human_owner','local_stage_unverified','source_admin_match_only','original_rows','review_only','client_consent_verified','operator_consent_verified','authorization_granted','execution_allowed','release_approved']];
  for(const r of data.summary)lines.push([r.slot,r.owner,r.stage,r.source_match,r.count,'REVIEW_ONLY',false,false,false,false,false]);
  download('lightup-binding-human-aggregate.csv',lines.map(row=>row.map(quoted).join(',')).join('\r\n')+'\r\n','text/csv');
 }
 setMsg('Anonymous aggregate exported: no original source tokens, request IDs, notes or customer labels.');
}
for(const s of scopes){const item=text('option','Scenario '+s.index+' · '+s.label);item.value=s.index;$('scopeFilter').append(item);}
for(const id of ['query','scopeFilter','kindFilter','ownerFilter','stageFilter'])$(id).addEventListener(id==='query'?'input':'change',draw);
$('clearLocal').addEventListener('click',()=>{if(!confirm('Forget all private, unsaved operator notes and local stages?'))return;for(const value of drafts.values())Object.assign(value,{stage:'unreviewed',owner:'unassigned',due:'',note:''});draw();setMsg('Forgot all local human state; original imported read-only source remains.');});
$('saveDraft').addEventListener('click',savePrivate);
$('restoreDraft').addEventListener('change',async event=>{
 try{await restore(event.target.files[0]);}catch(err){setMsg('HOLD: '+(err instanceof Error?err.message:'Private restore rejected'));}finally{event.target.value='';}
});
$('downloadAggregate').addEventListener('click',()=>exportAggregate('json'));
$('downloadCsv').addEventListener('click',()=>exportAggregate('csv'));
draw();
})();
"""

def _safe_payload(report: dict) -> str:
    # Original report was constructed by the authenticated source CLI.
    # Do not put literal markup terminators in script data.
    return (json.dumps(report, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def render(report: dict) -> str:
    if report.get("format") not in (
        "lightup.request_binding_preparation.v1",
        "lightup.request_binding_scenarios_review.v1",
    ) or report.get("authority") != AUTHORITY:
        raise ValueError("non-authorizing original report required")
    if report["format"] == "lightup.request_binding_scenarios_review.v1":
        scopes = [entry["original_source"] for entry in report["scenarios"]]
    else:
        scopes = [report]
    if len(scopes) > 8 or any(item.get("authority") != AUTHORITY for item in scopes):
        raise ValueError("invalid scope report boundary")
    source_payload = _safe_payload(report)
    question_payload = json.dumps(QUESTIONS, sort_keys=True, ensure_ascii=True)
    if len(source_payload) > 1_500_000:
        raise ValueError("source too large for private interactive offline view")
    fingerprint = hashlib.sha256(json.dumps(
        [["lightup.private-binding-workspace.v1"],
         [item["source"]["source_revision_sha256_unsigned"] for item in scopes],
         [item["source"]["request_selection_digest_unsigned"] for item in scopes],
         [item["disposition"] for item in scopes]],
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")).hexdigest()
    def sha(script: str) -> str:
        return base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; base-uri 'none'; form-action 'none'; "
           "img-src 'none'; connect-src 'none'; frame-src 'none'; "
           "object-src 'none'; worker-src 'none'; "
           f"style-src 'sha256-{sha(STYLE)}'; script-src 'sha256-{sha(SCRIPT)}'")
    title = "Original request-bound human operator desk"
    summaries = "".join(
        "<div class='stat'><span>Original scenario " + str(i) +
        " · administrative matches (NOT consent)</span><strong>" +
        str(item["summary"]["approved_candidate_matches"]) + "</strong></div>"
        for i, item in enumerate(scopes, 1)
    )
    total = sum(len(item["candidates"]) for item in scopes)
    if total > 4000:
        raise ValueError("offline human queue limit exceeded")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + escape(csp, quote=True) + '">'
        '<title>' + escape(title) + '</title><style>' + STYLE + '</style></head><body>'
        '<header><p class="overline">LIGHTUP · SOURCE-BOUND OFFLINE OPERATOR WORKSPACE</p>'
        '<h1>' + escape(title) + '</h1><p class="notice">REVIEW_ONLY / DRAFT-HOLD. '
        'These are administratively matched original rows, NOT client or operator consent, '
        'actual authorization, a grant, revocation, release or permission to touch targets. '
        'A browser copy can be stale. Real source-owner and human approvals remain required.</p>'
        '</header><main><div class="stats"><div class="stat"><span>Original request rows</span><strong id="total"></strong></div>'
        '<div class="stat"><span>Administratively matching rows*</span><strong id="matches"></strong></div>'
        '<div class="stat"><span>Locally unreviewed</span><strong id="unreviewed"></strong></div>'
        '<div class="stat"><span>Human escalations (unverified)</span><strong id="escalations"></strong></div>'
        '<div class="stat"><span>Past tentative dates</span><strong id="pastDue"></strong></div>'
        + summaries +
        '</div><p class="hint">*Multiple human alternatives can refer to the same original stored requests; '
        'these counts are NOT distinct permissions or approved actions. '
        'Original source revision SHA-256 (unsigned, not verified): <code>' +
        escape(scopes[0]["source"]["source_revision_sha256_unsigned"]) + '</code></p>'
        '<section><h2>Original source problems · human follow-up queue</h2>'
        '<p>The current canonical source owner remains responsible for actual grants and request integrity. '
        'These groups show fixed human questions and the number of original source rows affected. '
        'Bulk buttons modify only previously UNREVIEWED local discussion stages after confirmation, '
        'never actual request or consent status. Original scope alternatives can duplicate records.</p>'
        '<p id="themeCount" class="hint"></p><div id="themes" class="cards"></div></section>'
        '<section><h2>Original request source · private local human triage</h2>'
        '<p>Source fields are read-only. Human assignments and notes exist in memory only until explicitly '
        'exported to a PRIVATE file; no browser storage or network sync occurs.</p>'
        '<div class="controls"><label>Source token or review reason<br><input id="query" type="search" autocomplete="off" placeholder="Filter pseudonym, reason, status"></label>'
        '<label>Human alternative<br><select id="scopeFilter"><option value="all">All original alternatives</option></select></label>'
        '<label>Original administrative match<br><select id="kindFilter">'
        '<option value="all">All</option><option value="candidate_review_only">Compatible for human review only</option>'
        '<option value="approved_but_not_compatible">Approved but mismatched</option>'
        '<option value="not_administratively_approved">Not approved</option></select></label>'
        '<label>Human follow-up owner<br><select id="ownerFilter"><option value="all">All</option>'
        + "".join('<option value="' + owner + '">' + owner.replace('_', ' ') + '</option>'
                  for owner in ('unassigned','client_liaison','operator','security_source_owner','privacy'))
        + '</select></label>'
        '<label>Human stage<br><select id="stageFilter"><option value="all">All</option>'
        '<option value="unreviewed">Unreviewed</option><option value="question_prepared">Question prepared</option>'
        '<option value="escalated">Escalated</option><option value="discussed_unverified">Discussed unverified</option></select></label>'
        '</div><p id="count" class="hint"></p><div id="cases" class="cards"></div></section>'
        '<section><h2>Private resumption and anonymous human handoff</h2>'
        '<p>A source-bound working draft contains the original-source fingerprint, per-row private pseudonym, '
        'operator notes and human statuses. Keep it PRIVATE. Aggregate exports NEVER contain source IDs, '
        'tokens, original labels, free-text notes, exact source hashes, client details or asset literals.</p>'
        '<div class="controls"><button id="saveDraft">Save PRIVATE human working draft</button>'
        '<label class="fileButton">Restore PRIVATE draft<input type="file" id="restoreDraft" accept=".json,application/json"></label>'
        '<button id="downloadAggregate">Export anonymous aggregate JSON</button>'
        '<button id="downloadCsv">Export anonymous aggregate CSV</button>'
        '<button id="clearLocal">Forget local human notes</button></div>'
        '<p id="message" aria-live="polite" role="status" class="hint">No local notes yet. '
        'Exports are only generated after deliberate clicks.</p></section></main>'
        '<footer class="footer">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. '
        'Zero verified client/operator consent, grants, execution, active scans or release. '
        'Human decisions in this browser do not change original LightUp records. '
        'Original exact-head hosted+named VPS CI, security/privacy, independent real consent '
        'and at-use revocation and HUMAN GO remain required.</footer>'
        '<script type="application/json" id="sourceData" data-fingerprint="' + fingerprint +
        '">' + source_payload + '</script>'
        '<script type="application/json" id="questionsData">' + question_payload + '</script>'
        '<script>' + SCRIPT + '</script></body></html>'
    )
