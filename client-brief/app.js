/* LightUp Client Security Brief: offline presentation of *previously authenticated* exports.
   No authority, target interaction, data persistence, API, network or backend access. */
(() => {
'use strict';
const $ = id => document.getElementById(id);
const H = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEVERITIES = LightUpCasework.SEVERITY, RETEST = LightUpCasework.RETEST;
const FLAGS = Object.freeze({authenticated:false,tenant_verified:false,client_consent:false,operator_consent:false,grant:false,assessment_authorized:false,execution:false,scan:false,retest_verified:false,release:false});
const GROUPS = [
 {label:'Immediate risk discussion',key:'urgent',severities:['critical','high'],dayId:'urgent-days',reason:'Identify an accountable remediation owner and agree which high-risk items need human attention first.'},
 {label:'Planned remediation discussion',key:'medium',severities:['medium'],dayId:'medium-days',reason:'Review proposed mitigations and possible dependencies with the authorised owner.'},
 {label:'Backlog and hygiene discussion',key:'low',severities:['low','info'],dayId:'low-days',reason:'Record lower-risk follow-ups without inventing an assessment window or completion guarantee.'}
];
let state = null;
function caseworkSummaryHTML(){
 if(!state?.casework)return '<p>No matching existing Casework planning packet attached.</p>';
 const x=state.casework;
 const cells=Object.entries(x.counts).map(([k,v])=>'<div class="mini-stat"><b>'+v+'</b>'+H(k.replaceAll('_',' '))+'</div>').join('');
 return '<p><strong>Separate, unverified local planning only:</strong> '+x.overdue+' locally overdue and '+x.urgentBlocked+' critical/high locally blocked. No verified remediation or retest.</p><div class="change-grid">'+cells+'</div>';
}
function renderCasework(){
 $('casework-metrics').innerHTML=state?.casework?Object.entries(state.casework.counts).map(([k,v])=>'<div class="mini-stat"><b>'+v+'</b>'+H(k.replaceAll('_',' '))+'</div>').join(''):'';
}
async function importCasework(){
 if(!state)return note('Import a current findings CSV first.',true);
 if(!$('casework-confirm').checked)return note('Confirm the original Casework belongs to the same client and engagement.',true);
 const f=$('casework-file').files[0];if(!f)return note('Select the existing Casework draft JSON.',true);
 $('casework-load').disabled=true;
 try{
  const summary=await LightUpBriefCasework.readAndSummarize(f,state.fresh.rows);
  state.casework=summary;render();$('casework-status').textContent='Exact source fields match; planning stages are self-reported only.';
  note('Matching Casework counts attached locally. No remediation, retest or consent inferred.');
 }catch(e){$('casework-status').textContent='Import rejected; existing summary unchanged.';note('Casework rejected: '+String(e.message||'Unsupported packet'),true);}
 finally{$('casework-load').disabled=false;}
}
function clearCasework(){
 if(state)state.casework=null;
 $('casework-file').value='';$('casework-confirm').checked=false;
 $('casework-status').textContent='No Casework loaded.';renderCasework();if(state)render();
}
function readinessSummaryHTML(){
 if(!state?.readiness)return '<p>No verified operator readiness attached. No scope or grant authority established.</p>';
 const r=state.readiness;
 const groups=r.risk_groups.map(g=>'<div class="mini-stat"><b>'+g.count+'</b>'+H(g.name)+'</div>').join('');
 const active=r.issue_codes.slice(0,16);
 return '<p><strong>Unsigned scope blockers:</strong> '+r.records+' stored grant row(s); '+r.pending_client_wide+' pending client-wide requests (not linked to this engagement). Even zero reported issues is NOT authorization.</p><div class="change-grid">'+groups+'</div><ul>'+active.map(x=>'<li>'+x.count+' × '+H(x.label)+'</li>').join('')+(active.length?'':'<li>No reported flags in this snapshot; authentication and authorization still required.</li>')+'</ul>';
}
function renderReadiness(){ $('readiness-summary').innerHTML=state?.readiness?readinessSummaryHTML():''; }
async function importReadiness(){
 if(!state)return note('Import a current findings CSV first.',true);
 if(!$('readiness-confirm').checked)return note('Separately confirm the exact same client and engagement.',true);
 const file=$('readiness-file').files[0];if(!file)return note('Select the operator readiness JSON.',true);
 $('readiness-load').disabled=true;
 try{const candidate=await LightUpBriefReadiness.readAndSummarize(file);
  state.readiness=candidate;render();
  $('readiness-status').textContent='Single-engagement source shape accepted; blockers are historical only.';
  note('Unsigned operator blockers imported. No current consent or grant inferred.');
 }catch(e){$('readiness-status').textContent='Import rejected; previous snapshot preserved.';note('Readiness rejected: '+String(e.message||'Invalid source'),true);}
 finally{$('readiness-load').disabled=false;}
}
function clearReadiness(){
 if(state)state.readiness=null;
 $('readiness-file').value='';$('readiness-confirm').checked=false;
 $('readiness-status').textContent='No operator snapshot loaded.';
 renderReadiness();if(state)render();
}
function note(text, bad=false) { $('message').textContent=text; $('message').style.color=bad?'#ff9fac':'#b6e3d9'; }
async function sha256(bytes) {
 if (!globalThis.crypto || !crypto.subtle) return null;
 const result=await crypto.subtle.digest('SHA-256',bytes);
 return [...new Uint8Array(result)].map(v=>v.toString(16).padStart(2,'0')).join('');
}
async function readSource(file) {
 if (!file || file.size<10 || file.size>LightUpCasework.MAX_BYTES) throw Error('Expected a nonempty findings CSV no larger than 1 MiB.');
 const bytes=await file.arrayBuffer();
 if (bytes.byteLength!==file.size) throw Error('Source read changed during import.');
 const source=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const rows=LightUpCasework.parseCSV(source);
 return {rows, sha:await sha256(bytes), byteLength:bytes.byteLength};
}
async function load() {
 const current=$('current').files[0], previous=$('previous').files[0];
 if (!current) return note('Choose the current findings CSV.',true);
 if (state && !confirm('Opening new sources replaces the current in-memory report and its local discussion stages. Export first if needed. Continue?')) return;
 if (previous&&!$('same-scope').checked) return note('Confirm the independently checked same-client and same-engagement context before loading an earlier CSV.',true);
 $('load').disabled=true;
 try {
  const [fresh,older]=await Promise.all([readSource(current),previous?readSource(previous):Promise.resolve(null)]);
  // Publish only after *both* original exports are fully parsed and bounded.
  const changes=older?LightUpCasework.compareSource(older.rows,fresh.rows):null;
  state={fresh,older,changes,sameScopeAcknowledged:!!older,casework:null,readiness:null};
  $('casework-file').value='';$('casework-confirm').checked=false;$('casework-status').textContent='No Casework loaded.';
  $('readiness-file').value='';$('readiness-confirm').checked=false;$('readiness-status').textContent='No operator snapshot loaded.';
  ['urgent','medium','low'].forEach(key=>$(key+'-decision').value='discussion_pending');
  $('details').checked=false;
  $('workspace').hidden=false;
  render();
  note('Current'+(older?' and earlier':'')+' report loaded locally. No permissions inferred.');
 }catch(e){ note('Import rejected. '+String(e.message||'Invalid source'),true); }
 finally {$('load').disabled=false;}
}
function counts(key, categories) {
 const out={};
 for (const v of categories) out[v]=state.fresh.rows.filter(r=>r[key]===v).length;
 return out;
}
function chart(where, data) {
 const total=state.fresh.rows.length;
 $(where).replaceChildren();
 for(const [label,amount] of Object.entries(data)){
  const line=document.createElement('div');line.className='chart-row';
  const text=document.createElement('span');text.textContent=label.replaceAll('_',' ');
  const track=document.createElement('progress');track.className='severity-'+label;track.max=total;track.value=amount;track.setAttribute('aria-label',label+': '+amount+' of '+total);
  const number=document.createElement('span');number.className='count';number.textContent=amount;
  line.append(text,track,number);$(where).append(line);
 }
}
function kpis(severity,retest) {
 const cards=[
  ['Findings in source',state.fresh.rows.length],
  ['Critical / high',severity.critical+severity.high],
  ['Source-reported regressions',retest.regression],
  ['Still untested in source',retest.not_tested]
 ];
 $('kpis').replaceChildren();
 cards.forEach(([label,count])=>{
  const card=document.createElement('div');card.className='kpi';
  const n=document.createElement('strong');n.textContent=count;
  const t=document.createElement('span');t.textContent=label;
  card.append(n,t);$('kpis').append(card);
 });
}
function historicalHTML() {
 if (!state.changes) return '';
 const d=state.changes;
 return '<div class="change-grid">'+[
 ['Newly present',d.added.length],['Changed source records',d.changed.length],
 ['Absent / unverified',d.missing.length],['Unchanged',d.unchanged.length]
 ].map(([l,v])=>'<div class="mini-stat"><b>'+v+'</b>'+H(l)+'</div>').join('')+'</div>';
}
function dateFromInput() {
 const s=$('anchor').value;
 if(!s) return null;
 if(!/^\d{4}-\d{2}-\d{2}$/.test(s))throw Error('Invalid planning start.');
 const ms=Date.parse(s+'T00:00:00Z');
 if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==s)throw Error('Invalid planning date.');
 return ms;
}
const STAGES=Object.freeze(['discussion_pending','client_question_outstanding','operator_question_outstanding','joint_discussion_recorded']);
function discussion(key){const stage=$(key+'-decision').value;if(!STAGES.includes(stage))throw Error('Invalid discussion stage.');return stage;}
function plan() {
 const anchor=dateFromInput();
 return GROUPS.map(g=>{
  const days=Number($(g.dayId).value);
  if(!Number.isInteger(days)||days<1||days>365)throw Error('Planning horizons must be whole calendar days from 1 to 365.');
  const subset=state.fresh.rows.filter(r=>g.severities.includes(r.severity));
  const due=anchor===null?'Not specified':new Date(anchor+days*86400000).toISOString().slice(0,10);
  return {...g,days,amount:subset.length,regressions:subset.filter(r=>r.retest_status==='regression').length,due,discussion:discussion(g.key)};
 });
}
function planHTML(items) {
 return items.map(g=>'<article class="roadmap-item"><h3>'+H(g.label)+'</h3><p><strong>'+g.amount+'</strong> source findings'+(g.regressions?', including '+g.regressions+' source-reported regression(s)':'')+'</p><p>Suggested follow-up: '+H(g.days)+' calendar days'+(g.due==='Not specified'?' (no reference date)':' · '+H(g.due))+'</p><p>Local follow-up stage: '+H(g.discussion.replaceAll('_',' '))+' (self-reported)</p><p>'+H(g.reason)+'</p></article>').join('');
}
function sourceSummary() {
 return 'Current input '+state.fresh.byteLength+' bytes; SHA-256: '+(state.fresh.sha||'unavailable in this browser')+'. '+(state.older?'Earlier input '+state.older.byteLength+' bytes; SHA-256: '+(state.older.sha||'unavailable')+'. ':'')+'Fingerprints are NOT signatures, authentication, or consent receipts.';
}
function detailsHTML() {
 if (!$('details').checked) return '<p>Record-level titles and remediation are withheld by default. Enable the sensitive-data option only for a private, approved recipient.</p>';
 const sorted=state.fresh.rows.slice().sort((a,b)=>SEVERITIES.indexOf(a.severity)-SEVERITIES.indexOf(b.severity));
 return '<h3>Source findings — sensitive detail</h3>'+sorted.map((f,i)=>'<article class="sensitive"><span class="label">Record '+(i+1)+' / '+H(f.severity)+' / source status '+H(f.retest_status)+'</span><strong> '+H(f.title)+'</strong><p>Suggested remediation from source: '+H(f.remediation)+'</p></article>').join('');
}
function narrative(severity,retest,change) {
 const total=state.fresh.rows.length,urgent=severity.critical+severity.high;
 return '<p>The imported source lists <strong>'+total+'</strong> findings. <strong>'+urgent+'</strong> are reported as critical or high and warrant prioritised human discussion. The source labels <strong>'+retest.regression+'</strong> as regression, and <strong>'+retest.fixed+'</strong> as fixed; neither label has been independently verified by this local report.</p>'+
 (change?'<p>Compared with an earlier separately same-scope-acknowledged file, '+change.added.length+' records are newly present, '+change.changed.length+' changed, and '+change.missing.length+' are now absent. These changes do not independently establish resolution or an authorised retest.</p>':'<p>No historical source was supplied; there is no trend or verification conclusion.</p>');
}
function render() {
 if(!state) return;
 try {
 const severity=counts('severity',SEVERITIES),retest=counts('retest_status',RETEST),road=plan();
 kpis(severity,retest);chart('severity-chart',severity);chart('retest-chart',retest);
 $('changes-panel').hidden=!state.changes;
 $('changes').innerHTML=historicalHTML();
 $('roadmap').innerHTML=planHTML(road);
 renderCasework();
 renderReadiness();
 $('source-info').textContent=sourceSummary();
 const heading=$('report-title').value.trim().slice(0,100)||'Security findings — executive brief';
 $('preview').innerHTML='<p class="eyebrow">LOCAL PREVIEW / UNSIGNED</p><h3>'+H(heading)+'</h3>'+narrative(severity,retest,state.changes)+
 '<h3>Human follow-up plan</h3><div class="roadmap">'+planHTML(road)+'</div><h3>Matching local Casework summary (unverified)</h3>'+caseworkSummaryHTML()+'<h3>Operator scope readiness (unsigned)</h3>'+readinessSummaryHTML()+'<h3>Original source detail</h3>'+detailsHTML()+
 '<p class="hint">Client/operator consent, actual execution authority, approved scope, live revocation and verified retest must be established separately through genuine authenticated systems. This document is DRAFT/HOLD only.</p>';
 }catch(e){note(String(e.message),true);$('preview').textContent='Cannot render until planning inputs are corrected.';}
}
function reportData() {
 if(!state)throw Error('Import a source first.');
 const severity=counts('severity',SEVERITIES),retest=counts('retest_status',RETEST),road=plan(),diff=state.changes;
 return {kind:'lightup.client_security_brief_review',schema_version:1,disposition:'REVIEW_ONLY_DRAFT_HOLD',...FLAGS,
  source_contract:'lightup.finding_export._COLUMNS_v1',scope_identity_authenticated:false,
  source_fingerprint_signed:false,same_scope_acknowledgement_self_reported:!!state.sameScopeAcknowledged,
  imported_findings:state.fresh.rows.length,source_sha256:state.fresh.sha,
  earlier_sha256:state.older?.sha??null,severity_counts:severity,source_retest_counts:retest,
  source_changes:diff?{added:diff.added.length,changed:diff.changed.length,absent_unverified:diff.missing.length,unchanged:diff.unchanged.length}:null,
  operator_readiness_review:state.readiness?{grant_rows:state.readiness.records,pending_client_wide_requests:state.readiness.pending_client_wide,groups:state.readiness.risk_groups.map(x=>({name:x.name,count:x.count})),issue_counts:state.readiness.issue_codes.map(x=>({label:x.label,count:x.count})),authenticated_now:false,permission_inferred:false}:null,
  local_casework_summary:state.casework?{counts:{...state.casework.counts},locally_overdue:state.casework.overdue,critical_high_locally_blocked:state.casework.urgentBlocked,exact_source_fields_match:true,digest_checked:state.casework.sourceDigestChecked,remediation_verified:false}:null,
  planning:road.map(g=>({group:g.key,findings:g.amount,suggested_days:g.days,suggested_follow_up:g.due,self_reported_discussion_stage:g.discussion,not_an_sla:true})),
  caveat:'Local summary of untrusted CSV bytes. Never a grant, consent, permission, scan or verified retest.'};
}
function staticHTML(data) {
 const title=$('report-title').value.trim().slice(0,100)||'Security findings — executive brief';
 const sev=data.severity_counts,ret=data.source_retest_counts,road=plan();
 const printCSS='body{font:16px/1.55 system-ui,Arial,sans-serif;color:#142331;max-width:890px;margin:45px auto;padding:0 22px}h1{font-size:2.2rem}h2{margin-top:2rem;border-bottom:2px solid #cad4dc}p{max-width:80ch}small,.muted{color:#566578}.tag{display:inline-block;border:1px solid #697d89;border-radius:10px;padding:3px 10px}table{width:100%;border-collapse:collapse;margin:16px 0}td,th{border:1px solid #b9c8d3;padding:9px;text-align:left}th{background:#eef2f6}article{border-left:3px solid #6796a2;padding:8px 15px;margin:12px 0;break-inside:avoid}.sensitive{border-color:#c36e42;background:#fff9f2}pre{white-space:pre-wrap;overflow-wrap:anywhere}.notice{border:2px solid #bd8d52;padding:12px;margin-top:20px}.meta{overflow-wrap:anywhere;font-size:.84rem}@media print{body{margin:0}.notice{break-inside:avoid}}';
 const rows=SEVERITIES.map(k=>'<tr><td>'+H(k)+'</td><td>'+sev[k]+'</td></tr>').join('');
 const sourceRows=RETEST.map(k=>'<tr><td>'+H(k)+'</td><td>'+ret[k]+'</td></tr>').join('');
 const changes=state.changes?'<h2>Source comparison (unverified)</h2><p>'+H(state.changes.added.length)+' newly present; '+H(state.changes.changed.length)+' changed; '+H(state.changes.missing.length)+' absent (not resolved); '+H(state.changes.unchanged.length)+' unchanged. Same-scope provenance was acknowledged by the local reviewer, not verified by this file.</p>':'';
 const casework=state.casework?'<h2>Existing self-reported Casework planning</h2>'+caseworkSummaryHTML():'<p>No matching local Casework packet attached.</p>';
 const readiness=state.readiness?'<h2>Historical operator readiness blockers (unsigned)</h2>'+readinessSummaryHTML():'<p>No current authorization evidence has been attached or checked.</p>';
 const details=$('details').checked?'<h2>Sensitive source detail — private recipients only</h2>'+detailsHTML():'<p>Individual finding identifiers, titles and remediation text are intentionally excluded from this redacted brief.</p>';
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; connect-src \'none\'; img-src \'none\'; script-src \'none\'; object-src \'none\'"><title>'+H(title)+'</title><style>'+printCSS+'</style></head><body><small>LIGHTUP / REVIEW_ONLY / DRAFT-HOLD</small><h1>'+H(title)+'</h1><p class="tag">Audience: '+H($('audience').value)+'</p><div class="notice"><strong>Not an authorisation or verification document.</strong> This static, unsigned report is derived from a locally provided file. It does not establish client identity, scope, client/operator consent, live revocation, grant validity, execution authority, a scan outcome or verified remediation.</div><h2>Executive overview</h2>'+narrative(sev,ret,state.changes)+
 '<h2>Severity distribution</h2><table><thead><tr><th>Source severity</th><th>Count</th></tr></thead><tbody>'+rows+'</tbody></table>'+
 '<h2>Source-reported retest states</h2><table><thead><tr><th>Source state</th><th>Count</th></tr></thead><tbody>'+sourceRows+'</tbody></table>'+changes+
 '<h2>Illustrative follow-up roadmap</h2>'+road.map(g=>'<article><strong>'+H(g.label)+'</strong><p>'+g.amount+' findings; discuss within '+g.days+' calendar days'+(g.due==='Not specified'?' (no reference date)':' from the reference date, by '+H(g.due))+'. Not an SLA, order or booked activity.</p><p>Local follow-up stage: '+H(g.discussion.replaceAll('_',' '))+' (self-reported)</p><p>'+H(g.reason)+'</p></article>').join('')+
 casework+readiness+details+'<h2>Evidence and provenance caveat</h2><p class="meta">'+H(sourceSummary())+'</p><p class="muted">Original report values are untrusted unless authenticated separately. This file contains no live permissions and has not checked current grants or independently verified remediation.</p></body></html>';
}
function download(content,name,mime) {
 const blob=new Blob([content],{type:mime}),url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function exportHTML() {
 try{
  const data=reportData();
  if($('details').checked&&!confirm('This HTML will contain original finding titles and remediation text. Have you approved the recipient and secure transfer method?'))return;
  download(staticHTML(data),'lightup-client-security-brief-DRAFT-HOLD.html','text/html;charset=utf-8');note('Static HTML downloaded; it is unsigned and must be human reviewed.');
 }catch(e){note('HTML export refused: '+e.message,true);}
}
function exportJSON() {
 try {download(JSON.stringify(reportData(),null,2)+'\n','lightup-security-brief-aggregate-REVIEW-ONLY.json','application/json');note('Aggregate-only JSON exported. No source finding identifiers or descriptions included.');}
 catch(e){note('JSON export refused: '+e.message,true);}
}
function forget() {
 state=null;$('readiness-file').value='';$('readiness-confirm').checked=false;$('readiness-status').textContent='No operator snapshot loaded.';$('readiness-summary').replaceChildren();$('casework-file').value='';$('casework-confirm').checked=false;$('casework-status').textContent='No Casework loaded.';$('current').value='';$('previous').value='';$('same-scope').checked=false;$('details').checked=false;
 $('workspace').hidden=true;['urgent','medium','low'].forEach(key=>$(key+'-decision').value='discussion_pending');$('kpis').replaceChildren();$('changes').replaceChildren();$('preview').replaceChildren();
 note('In-memory findings forgotten. Previously downloaded files must be deleted separately.');
}
$('load').addEventListener('click',load);
$('casework-load').addEventListener('click',importCasework);
$('casework-clear').addEventListener('click',clearCasework);
$('readiness-load').addEventListener('click',importReadiness);
$('readiness-clear').addEventListener('click',clearReadiness);
$('forget').addEventListener('click',forget);
$('html-export').addEventListener('click',exportHTML);
$('json-export').addEventListener('click',exportJSON);
$('print').addEventListener('click',()=>{if(state){try{reportData();window.print();}catch(e){note(e.message,true);}}});
['anchor','urgent-days','medium-days','low-days','details','report-title','audience','urgent-decision','medium-decision','low-decision'].forEach(id=>$(id).addEventListener('input',render));
})();