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
function sessionFields(){
 return {title:$('report-title').value.trim(),anchor:$('anchor').value,
  urgent_days:Number($('urgent-days').value),medium_days:Number($('medium-days').value),
  low_days:Number($('low-days').value),discussion:{urgent:$('urgent-decision').value,
  medium:$('medium-decision').value,low:$('low-decision').value}};
}
function saveSession(){
 try{
  if(!state)throw Error('Open a current findings CSV first.');
  const packet=LightUpBriefDraft.make(state.fresh.sha,state.older?.sha??null,sessionFields());
  if(!confirm('Save a private unsigned working draft containing the brief heading and source hashes? It never includes grants, consent or findings.'))return;
  download(JSON.stringify(packet,null,2)+'\n','lightup-client-brief-local-review-DRAFT.json','application/json;charset=utf-8');
  $('session-status').textContent='Working draft downloaded; store privately.';
 }catch(e){$('session-status').textContent='Not saved: '+e.message;}
}
async function restoreSession(){
 if(!state)return note('Reopen the original current findings CSV before restoring.',true);
 const file=$('session-file').files[0];if(!file)return note('Select a saved source-bound review draft.',true);
 $('session-load').disabled=true;
 try{
  const fields=await LightUpBriefDraft.read(file,state.fresh.sha,state.older?.sha??null);
  if(!confirm('Restore human planning inputs from this unsigned file, replacing current local edits? This is NOT scope or permission restoration.'))return;
  $('report-title').value=fields.title;$('anchor').value=fields.anchor;
  ['urgent','medium','low'].forEach(k=>{$(k+'-days').value=fields[k+'_days'];$(k+'-decision').value=fields.discussion[k];});
  // Never carry over internal operator report sharing or sensitive source details.
  $('internal-readiness').checked=false;$('details').checked=false;
  $('audience').value='Client and operator';render();
  $('session-status').textContent='Exact-source human draft restored; consent and authorization remain absent.';
  note('Local human follow-up settings restored only. Operator/source documents were not restored.');
 }catch(e){$('session-status').textContent='Draft rejected, existing settings unchanged.';note('Restore refused: '+e.message,true);}
 finally{$('session-load').disabled=false;}
}
function studioSummaryHTML(){
 if(!state?.studio)return '<p>No scope proposal is attached. This is not evidence of missing or granted permission.</p>';
 const d=state.studio;
 const safeH=H(d.proposed_window_status.replaceAll('_',' '));
 const bands=[['Proposed assets',d.requested_assets_count],['Proposed exclusions',d.excluded_assets_count],['Effective hostnames',d.effective_hostnames_count],['Studio review warnings',d.original_human_warning_count]];
 return '<div class="change-grid">'+bands.map(([name,n])=>'<div class="mini-stat"><b>'+n+'</b>'+H(name)+'</div>').join('')+'</div>'+
 '<p><strong>Proposed mode:</strong> '+H(d.requested_mode.replaceAll('_',' '))+' · <strong>proposed risk:</strong> '+d.requested_risk+' / 4 · <strong>UTC planning:</strong> '+safeH+'.</p>'+
 '<p>Proposed effective numeric coverage: '+H(d.effective_ipv4_address_count)+' IPv4 addresses and '+H(d.effective_ipv6_address_count)+' IPv6 addresses. These are proposal arithmetic, not authorized targets.</p>'+
 (d.proposed_window_utc?'<p>Unapproved UTC: '+H(d.proposed_window_utc.start)+' → '+H(d.proposed_window_utc.end)+'</p>':'')+
 '<ul>'+d.notes.map(n=>'<li>'+H(n)+'</li>').join('')+'</ul>';
}
function renderStudio(){ $('studio-summary').innerHTML=state?.studio?studioSummaryHTML():''; }
async function importStudio(){
 if(!state)return note('Import the original findings CSV before adding a proposal.',true);
 if(!$('studio-confirm').checked)return note('Check exact client and engagement independently before attaching a proposal.',true);
 const file=$('studio-file').files[0];if(!file)return note('Choose the original Studio v1 JSON.',true);
 $('studio-load').disabled=true;
 try{
  const candidate=await LightUpBriefStudio.importOriginal(file);
  state.studio=candidate;state.studioChange=null;
  $('studio-previous').value='';$('studio-previous-confirm').checked=false;$('studio-compare-status').textContent='No earlier version compared.';render();
  $('studio-status').textContent='Untrusted proposal summary attached for local human discussion.';
  note('Original Studio proposal summarized offline. No authority or asset ownership inferred.');
 }catch(e){$('studio-status').textContent='Import rejected; prior proposal unchanged.';note('Studio proposal rejected: '+String(e.message),true);}
 finally{$('studio-load').disabled=false;}
}
function clearStudio(){
 if(state){state.studio=null;state.studioChange=null;}
 $('studio-previous').value='';$('studio-previous-confirm').checked=false;$('studio-compare-status').textContent='No earlier version compared.';renderStudioChanges();
 $('studio-file').value='';$('studio-confirm').checked=false;
 $('studio-status').textContent='No scope proposal imported.';renderStudio();if(state)render();
}
function studioChangesHTML(){
 const d=state?.studioChange;
 if(!d)return '<p>No previous proposal compared; an absence of difference data is NOT an unchanged permission or scope.</p>';
 const stats=[['Added range fragments',d.added_coverage_fragments],['Removed range fragments',d.removed_coverage_fragments],['New activities',d.new_activities.length],['Risk increased',d.elevated_risk?'YES':'No']];
 return '<p><strong>Human scope review: '+(d.changes_require_human_review?'ACTION NEEDED':'Review source manually')+'</strong>. Original scope proposals are untrusted; changed effective ranges or time never imply approved scope.</p><div class="change-grid">'+stats.map(([label,val])=>'<div class="mini-stat"><b>'+H(val)+'</b>'+H(label)+'</div>').join('')+'</div>'+
 '<p>Mode increased: '+H(d.mode_escalated?'yes':'no')+' · Window changed: '+H(d.window_changed?'yes':'no')+' · Coverage truncated: '+H(d.coverage_truncated?'yes':'no')+'</p>';
}
function renderStudioChanges(){$('studio-change-summary').innerHTML=state?.studioChange?studioChangesHTML():'';}
async function compareStudio(){
 if(!state?.studio)return note('Import a current Studio proposal first.',true);
 if(!$('studio-previous-confirm').checked)return note('Separately check both proposals refer to the exact same client and engagement.',true);
 const file=$('studio-previous').files[0];if(!file)return note('Choose the older original Studio proposal.',true);
 $('studio-compare').disabled=true;
 try{
  const previous=await LightUpBriefStudio.importOriginal(file);
  const diff=LightUpBriefStudio.compareOriginals(previous,state.studio);
  state.studioChange=diff;render();
  $('studio-compare-status').textContent='Human-only original Studio revision differences attached.';
  note('Proposed scope revisions compared offline; fresh authenticated approvals remain necessary.');
 }catch(e){$('studio-compare-status').textContent='Comparison refused; previous change view preserved.';note('Studio comparison refused: '+e.message,true);}
 finally{$('studio-compare').disabled=false;}
}
function clearStudioChanges(){
 if(state)state.studioChange=null;
 $('studio-previous').value='';$('studio-previous-confirm').checked=false;
 $('studio-compare-status').textContent='No earlier version compared.';
 renderStudioChanges();if(state)render();
}
function humanPlan(){return LightUpBriefActions.fromState(state,{includeOperator:canExportReadiness()});}
function humanActionsHTML(plan=humanPlan()){
 const actions=plan.actions;
 if(!actions.length)return '<p>No source-driven actions have been proposed yet. This does not establish authorization or completed remediation.</p>';
 return '<p>'+actions.length+' source-derived human follow-up categories (not individual assignments).</p><div class="action-grid">'+actions.map(x=>
 '<article class="action-row"><strong>'+H(x.level.toUpperCase())+' · '+H(x.title)+'</strong><p>Source records: '+x.source_count+' · '+H(x.origin.replaceAll('_',' '))+'</p><p>'+H(x.next_human_step)+'</p></article>').join('')+'</div>';
}
function renderActions(){$('human-actions').innerHTML=state?humanActionsHTML():'';}
function exportHumanActions(){
 try{
  if(!state)throw Error('Import a current findings CSV first.');
  const plan=humanPlan();if(!approveInternalExport())return;
  download(LightUpBriefActions.toCSV(plan),'lightup-human-followup-REVIEW-ONLY.csv','text/csv;charset=utf-8');
  note('Human-only actions exported as formula-safe CSV. No permission or remediation performed.');
 }catch(e){note('Human action export refused: '+e.message,true);}
}
let followupRecords={},followupTag=null;
function followupInfo(){
 const x=LightUpFollowup.source(state,LightUpBriefActions.fromState(state,{includeOperator:false}));
 const tag=JSON.stringify([x.fingerprint,x.previous,x.studioRevision,x.studioPrevious,x.actions.map(a=>[a.origin,a.title,a.level,a.source_count,a.next_human_step])]);
 if(followupTag!==tag){followupTag=tag;followupRecords={};}
 return x;
}
function followupSummary(){
 if(!state)return null;
 try{return LightUpFollowup.overview(followupInfo(),followupRecords);}catch(_){return null;}
}
function followupOverviewHTML(){
 const x=followupSummary();if(!x)return '<p>Source hash unavailable: tracking requires original source CSV and WebCrypto.</p>';
 return '<p>'+x.categories+' original source-derived conversation categories (human notes only). '+Object.entries(x.counts).map(([k,v])=>H(k.replaceAll('_',' '))+': '+v).join(' · ')+'. No verified approval or remediation.</p>';
}
function followupUI(){
 const host=$('followup-board');if(!state){host.textContent='Load source findings first.';return;}
 let info;try{info=followupInfo();}catch(e){host.textContent=e.message;return;}
 const select=(values,current)=>values.map(k=>'<option value="'+H(k)+'"'+(k===current?' selected':'')+'>'+H(k.replaceAll('_',' '))+'</option>').join('');
 host.innerHTML=followupOverviewHTML()+'<div class="action-grid">'+info.actions.map((a,i)=>{
  const row=followupRecords[info.keys[i]]||LightUpFollowup.blank();
  const filter=$('followup-filter').value;
  if(filter==='urgent'&&a.level!=='urgent')return '';
  if(filter==='unanswered'&&!['awaiting_client_question','awaiting_operator_question'].includes(row.phase))return '';
  if(filter==='dated'&&!row.date)return '';
  return '<article class="action-row" data-index="'+i+'"><strong>'+H(a.level.toUpperCase())+' · '+H(a.title)+'</strong><p>'+a.source_count+' source records · '+H(a.next_human_step)+'</p><div class="followup-controls"><label>Discussion role<select data-field="role" data-index="'+i+'">'+select(LightUpFollowup.roles,row.role)+'</select></label><label>Self-reported discussion phase<select data-field="phase" data-index="'+i+'">'+select(LightUpFollowup.phases,row.phase)+'</select></label><label>Tentative follow-up date<input data-field="date" data-index="'+i+'" type="date" value="'+H(row.date)+'"></label></div></article>';
 }).join('')+'</div>';
}
async function saveFollowup(){
 if(!state)return note('Open current source findings first.',true);
 try{const info=followupInfo(),draft=await LightUpFollowup.make(info,followupRecords);
  if(!confirm('Save private unsigned conversation planning only? This never records consent, grant, remediation or actual authorization.'))return;
  download(JSON.stringify(draft,null,2)+'\n','lightup-human-discussion-source-bound-DRAFT.json','application/json;charset=utf-8');
  $('followup-status').textContent='Private human discussion plan saved to your device.';
 }catch(e){$('followup-status').textContent='Not saved: '+e.message;}
}
function exportFollowupCSV(){
 if(!state)return note('Open original source findings first.',true);
 try{const info=followupInfo();
  if(!confirm('Download a PRIVATE agenda with category titles, self-reported discussion status, roles and dates? No permissions or scans are authorized. Verify the intended recipient.'))return;
  download(LightUpFollowup.toCSV(info,followupRecords),'lightup-human-discussion-PRIVATE-REVIEW-ONLY.csv','text/csv;charset=utf-8');
  $('followup-status').textContent='Private human meeting agenda exported. No actions performed.';
 }catch(e){$('followup-status').textContent='Agenda export refused: '+e.message;}
}
async function exportFollowupCalendar(){
 if(!state)return note('Open original source findings first.',true);
 try{const info=followupInfo(),calendar=await LightUpFollowup.toCalendar(info,followupRecords);
  if(!confirm('Export '+calendar.events+' TENTATIVE ALL-DAY human discussion reminders? Importing .ics into a synchronized calendar may share category labels with its provider. These are NOT authorized scan windows or real bookings.'))return;
  download(calendar.content,'lightup-human-discussions-TENTATIVE-PRIVATE.ics','text/calendar;charset=utf-8');
  $('followup-status').textContent=calendar.events+' tentative human-only calendar dates exported; do not treat them as approval.';
 }catch(e){$('followup-status').textContent='Calendar export refused: '+e.message;}
}
async function loadFollowup(){
 if(!state)return note('Open original source findings before restoring.',true);
 const f=$('followup-file').files[0];if(!f)return note('Choose a saved human discussion draft.',true);
 $('followup-load').disabled=true;
 try{const info=followupInfo(),incoming=await LightUpFollowup.read(f,info);
  if(!confirm('Restore human discussion choices for the exact same source action categories? This does not restore permission or approvals.'))return;
  followupRecords=incoming;render();$('followup-status').textContent='Private human-only discussion stages restored.';
 }catch(e){$('followup-status').textContent='Source-bound draft rejected; previous choices retained.';note('Discussion restore refused: '+e.message,true);}
 finally{$('followup-load').disabled=false;}
}
function historySummary(){
 if(!state?.history?.length)return null;
 const base={kind:'lightup.client_security_brief_review',schema_version:1,
 disposition:'REVIEW_ONLY_DRAFT_HOLD',source_contract:'lightup.finding_export._COLUMNS_v1',
 ...FLAGS,scope_identity_authenticated:false,source_fingerprint_signed:false,
 imported_findings:state.fresh.rows.length,source_sha256:state.fresh.sha,
 severity_counts:counts('severity',SEVERITIES),source_retest_counts:counts('retest_status',RETEST),
 proposed_scope_review:state.studio};
 return LightUpBriefHistoryView.redact(LightUpBriefHistory.timeline(state.history,base));
}
function renderHistory(){
 $('history-results').innerHTML=LightUpBriefHistoryView.display(historySummary());
}
async function loadHistory(){
 if(!state)return note('Open current findings CSV first.',true);
 if(!$('history-confirm').checked)return note('Confirm every prior briefing concerns the exact same client and engagement.',true);
 const files=[...$('history-files').files];if(!files.length)return note('Select earlier original aggregate JSON briefings.',true);
 $('history-load').disabled=true;
 try{const previous=await LightUpBriefHistory.importAll(files,reportData());
  state.history=previous;render();
  $('history-status').textContent=previous.length+' unsigned prior briefings compared in reviewer-declared order.';
  note('Source-reported count history imported; no repaired findings or consent inferred.');
 }catch(e){$('history-status').textContent='Import refused; previous comparison retained.';note('Historical briefing refused: '+e.message,true);}
 finally{$('history-load').disabled=false;}
}
function clearHistory(){
 if(state)state.history=[];
 $('history-files').value='';$('history-confirm').checked=false;
 $('history-status').textContent='No earlier aggregate briefings imported.';
 if(state)render();else $('history-results').replaceChildren();
}
function exportHistory(){
 if(!state?.history?.length)return note('Import redacted briefing history first.',true);
 try{const base=LightUpBriefHistory.timeline(state.history,reportData());
  download(LightUpBriefHistory.csv(base),'lightup-redacted-report-history-REVIEW-ONLY.csv','text/csv;charset=utf-8');
  note('Privacy-minimal briefing history exported; reported changes are not verified remediation.');
 }catch(e){note('Export refused: '+e.message,true);}
}
function renderWorkflowStatus(){
 if(!state)return;
 const parts=[state.fresh.rows.length+' current findings',
  state.older?'earlier findings imported':'no earlier findings CSV',
  state.history?.length?state.history.length+' earlier aggregate briefs':'no aggregate history',
  state.casework?'Casework planning attached':'no Casework',
  state.studio?'scope proposal attached':'no Studio proposal',
  state.readiness?'private operator review attached':'no operator readiness snapshot'];
 $('workflow-status').textContent='Offline sources: '+parts.join(' · ')+'. All identity, consent, grant and revocation checks remain external.';
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
  state={fresh,older,changes,sameScopeAcknowledged:!!older,casework:null,readiness:null,studio:null,studioChange:null,history:[]};
  followupTag=null;followupRecords={};
  $('casework-file').value='';$('casework-confirm').checked=false;$('casework-status').textContent='No Casework loaded.';
  $('readiness-file').value='';$('readiness-confirm').checked=false;$('readiness-status').textContent='No operator snapshot loaded.';
  $('studio-file').value='';$('studio-confirm').checked=false;$('studio-status').textContent='No scope proposal imported.';
  $('studio-previous').value='';$('studio-previous-confirm').checked=false;$('studio-compare-status').textContent='No earlier version compared.';
  $('session-file').value='';$('session-status').textContent='No working draft restored.';
  ['urgent','medium','low'].forEach(key=>$(key+'-decision').value='discussion_pending');
  $('details').checked=false;$('internal-readiness').checked=false;
  $('workspace').hidden=false;
  $('workflow-nav').hidden=false;
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
 renderStudio();
 renderStudioChanges();
 renderActions();
 renderHistory();
 renderWorkflowStatus();
 followupUI();
 $('internal-readiness').disabled=$('audience').value!=='Internal operators only';
 $('source-info').textContent=sourceSummary();
 const heading=$('report-title').value.trim().slice(0,100)||'Security findings — executive brief';
 $('preview').innerHTML='<p class="eyebrow">LOCAL PREVIEW / UNSIGNED</p><h3>'+H(heading)+'</h3>'+narrative(severity,retest,state.changes)+
 '<h3>Human follow-up plan</h3><div class="roadmap">'+planHTML(road)+'</div><h3>Matching local Casework summary (unverified)</h3>'+caseworkSummaryHTML()+'<h3>Operator scope readiness (unsigned)</h3>'+(canExportReadiness()?readinessSummaryHTML():'<p>Operator details are omitted from client-facing copies. Select Internal operators only and opt in to include an internal aggregate.</p>')+'<h3>Unsigned earlier briefing counts</h3>'+LightUpBriefHistoryView.display(historySummary())+'<h3>Human follow-up queue, not orders</h3>'+humanActionsHTML()+'<h3>Self-reported human discussion status, not approval</h3>'+followupOverviewHTML()+'<h3>Original source detail</h3>'+detailsHTML()+
 '<p class="hint">Client/operator consent, actual execution authority, approved scope, live revocation and verified retest must be established separately through genuine authenticated systems. This document is DRAFT/HOLD only.</p>';
 }catch(e){note(String(e.message),true);$('preview').textContent='Cannot render until planning inputs are corrected.';}
}
function canExportReadiness(){return Boolean(state?.readiness)&&$('audience').value==='Internal operators only'&&$('internal-readiness').checked;}
function approveInternalExport(){return !canExportReadiness()||confirm('Include private operator integrity flags in this INTERNAL ONLY exported copy? Verify the recipient and use secure transfer.');}
function reportData() {
 if(!state)throw Error('Import a source first.');
 const severity=counts('severity',SEVERITIES),retest=counts('retest_status',RETEST),road=plan(),diff=state.changes;
 return {kind:'lightup.client_security_brief_review',schema_version:1,disposition:'REVIEW_ONLY_DRAFT_HOLD',...FLAGS,
  source_contract:'lightup.finding_export._COLUMNS_v1',scope_identity_authenticated:false,
  source_fingerprint_signed:false,same_scope_acknowledgement_self_reported:!!state.sameScopeAcknowledged,
  imported_findings:state.fresh.rows.length,source_sha256:state.fresh.sha,
  earlier_sha256:state.older?.sha??null,severity_counts:severity,source_retest_counts:retest,
  source_changes:diff?{added:diff.added.length,changed:diff.changed.length,absent_unverified:diff.missing.length,unchanged:diff.unchanged.length}:null,
  human_action_register:humanPlan(),
  human_discussion_aggregate:followupSummary(),
  redacted_report_history:historySummary(),
  proposed_scope_change_review:state.studioChange?{...state.studioChange,changes_are_authorized:false}:null,
  proposed_scope_review:state.studio?{...state.studio,notes:[...state.studio.notes],ownership_verified:false,permission_inferred:false}:null,
  operator_readiness_review:canExportReadiness()?{grant_rows:state.readiness.records,pending_client_wide_requests:state.readiness.pending_client_wide,groups:state.readiness.risk_groups.map(x=>({name:x.name,count:x.count})),issue_counts:state.readiness.issue_codes.map(x=>({label:x.label,count:x.count})),authenticated_now:false,permission_inferred:false}:null,
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
 const studio=state.studio?'<h2>Original proposed scope, not approved</h2>'+studioSummaryHTML():'<p>No original Studio proposed scope attached. No authority inferred.</p>';
 const studioChanges=state.studioChange?'<h2>Original proposed scope revision change</h2>'+studioChangesHTML():'<p>No older Studio proposal compared.</p>';
 const humanActions='<h2>Proposed human follow-up actions (not assignments)</h2>'+humanActionsHTML();
 const humanDiscussion='<h2>Human-only discussion progress (unverified)</h2>'+followupOverviewHTML();
 const history=data.redacted_report_history?'<h2>Reviewer-declared aggregate report history</h2>'+LightUpBriefHistoryView.display(data.redacted_report_history):'';
 const casework=state.casework?'<h2>Existing self-reported Casework planning</h2>'+caseworkSummaryHTML():'<p>No matching local Casework packet attached.</p>';
 const readiness=canExportReadiness()?'<h2>INTERNAL ONLY: unsigned operator scope-readiness blockers</h2>'+readinessSummaryHTML():'<p>Internal operator readiness details withheld from this exported report.</p>';
 const details=$('details').checked?'<h2>Sensitive source detail — private recipients only</h2>'+detailsHTML():'<p>Individual finding identifiers, titles and remediation text are intentionally excluded from this redacted brief.</p>';
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; connect-src \'none\'; img-src \'none\'; script-src \'none\'; object-src \'none\'"><title>'+H(title)+'</title><style>'+printCSS+'</style></head><body><small>LIGHTUP / REVIEW_ONLY / DRAFT-HOLD</small><h1>'+H(title)+'</h1><p class="tag">Audience: '+H($('audience').value)+'</p><div class="notice"><strong>Not an authorisation or verification document.</strong> This static, unsigned report is derived from a locally provided file. It does not establish client identity, scope, client/operator consent, live revocation, grant validity, execution authority, a scan outcome or verified remediation.</div><h2>Executive overview</h2>'+narrative(sev,ret,state.changes)+
 '<h2>Severity distribution</h2><table><thead><tr><th>Source severity</th><th>Count</th></tr></thead><tbody>'+rows+'</tbody></table>'+
 '<h2>Source-reported retest states</h2><table><thead><tr><th>Source state</th><th>Count</th></tr></thead><tbody>'+sourceRows+'</tbody></table>'+changes+
 '<h2>Illustrative follow-up roadmap</h2>'+road.map(g=>'<article><strong>'+H(g.label)+'</strong><p>'+g.amount+' findings; discuss within '+g.days+' calendar days'+(g.due==='Not specified'?' (no reference date)':' from the reference date, by '+H(g.due))+'. Not an SLA, order or booked activity.</p><p>Local follow-up stage: '+H(g.discussion.replaceAll('_',' '))+' (self-reported)</p><p>'+H(g.reason)+'</p></article>').join('')+
 studio+studioChanges+history+casework+readiness+humanActions+humanDiscussion+details+'<h2>Evidence and provenance caveat</h2><p class="meta">'+H(sourceSummary())+'</p><p class="muted">Original report values are untrusted unless authenticated separately. This file contains no live permissions and has not checked current grants or independently verified remediation.</p></body></html>';
}
function download(content,name,mime) {
 const blob=new Blob([content],{type:mime}),url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function exportHTML() {
 try{
  const data=reportData();
  if(!approveInternalExport())return;
  if($('details').checked&&!confirm('This HTML will contain original finding titles and remediation text. Have you approved the recipient and secure transfer method?'))return;
  download(staticHTML(data),'lightup-client-security-brief-DRAFT-HOLD.html','text/html;charset=utf-8');note('Static HTML downloaded; it is unsigned and must be human reviewed.');
 }catch(e){note('HTML export refused: '+e.message,true);}
}
function exportJSON() {
 try {if(!approveInternalExport())return;download(JSON.stringify(reportData(),null,2)+'\n','lightup-security-brief-aggregate-REVIEW-ONLY.json','application/json');note('Aggregate-only JSON exported. No source finding identifiers or descriptions included.');}
 catch(e){note('JSON export refused: '+e.message,true);}
}
function forget() {
 state=null;$('history-files').value='';$('history-confirm').checked=false;$('history-results').replaceChildren();$('history-status').textContent='No earlier aggregate briefings imported.';followupTag=null;followupRecords={};$('followup-filter').value='all';$('followup-board').replaceChildren();$('followup-file').value='';$('followup-status').textContent='No local discussion plan saved.';$('studio-previous').value='';$('studio-previous-confirm').checked=false;$('studio-compare-status').textContent='No earlier version compared.';$('studio-change-summary').replaceChildren();$('human-actions').replaceChildren();$('studio-file').value='';$('studio-confirm').checked=false;$('studio-status').textContent='No scope proposal imported.';$('studio-summary').replaceChildren();$('session-file').value='';$('session-status').textContent='No working draft restored.';$('readiness-file').value='';$('readiness-confirm').checked=false;$('readiness-status').textContent='No operator snapshot loaded.';$('readiness-summary').replaceChildren();$('casework-file').value='';$('casework-confirm').checked=false;$('casework-status').textContent='No Casework loaded.';$('current').value='';$('previous').value='';$('same-scope').checked=false;$('details').checked=false;
 $('workspace').hidden=true;$('workflow-nav').hidden=true;$('workflow-status').textContent='Offline review only — no permission established.';$('internal-readiness').checked=false;['urgent','medium','low'].forEach(key=>$(key+'-decision').value='discussion_pending');$('kpis').replaceChildren();$('changes').replaceChildren();$('preview').replaceChildren();
 note('In-memory findings forgotten. Previously downloaded files must be deleted separately.');
}
$('load').addEventListener('click',load);
$('history-load').addEventListener('click',loadHistory);
$('history-clear').addEventListener('click',clearHistory);
$('history-export').addEventListener('click',exportHistory);
$('casework-load').addEventListener('click',importCasework);
$('casework-clear').addEventListener('click',clearCasework);
$('readiness-load').addEventListener('click',importReadiness);
$('readiness-clear').addEventListener('click',clearReadiness);
$('session-save').addEventListener('click',saveSession);
$('session-load').addEventListener('click',restoreSession);
$('studio-load').addEventListener('click',importStudio);
$('studio-clear').addEventListener('click',clearStudio);
$('studio-compare').addEventListener('click',compareStudio);
$('studio-compare-clear').addEventListener('click',clearStudioChanges);
$('human-actions-export').addEventListener('click',exportHumanActions);
$('followup-save').addEventListener('click',saveFollowup);
$('followup-csv').addEventListener('click',exportFollowupCSV);
$('followup-calendar').addEventListener('click',exportFollowupCalendar);
$('followup-load').addEventListener('click',loadFollowup);
$('followup-filter').addEventListener('change',followupUI);
$('followup-board').addEventListener('change',event=>{
 const input=event.target,field=input.dataset?.field,index=Number(input.dataset?.index);
 if(!['role','phase','date'].includes(field)||!Number.isInteger(index))return;
 try{
  const info=followupInfo();if(index<0||index>=info.keys.length)throw Error('Unknown original action category.');
  const key=info.keys[index],before=followupRecords[key]||LightUpFollowup.blank();
  const candidate={...before,[field]:input.value};
  // All edits use the same strict source-bound record validator as private export.
  followupRecords[key]=LightUpFollowup.collect(info,{...followupRecords,[key]:candidate})[key];
  render();
  $('followup-status').textContent='Local conversation updated only. Save privately if needed; nothing is automatically approved.';
 }catch(e){note('Discussion edit refused: '+e.message,true);followupUI();}
});
$('audience').addEventListener('change',()=>{if($('audience').value!=='Internal operators only')$('internal-readiness').checked=false;render();});
$('forget').addEventListener('click',forget);
$('html-export').addEventListener('click',exportHTML);
$('json-export').addEventListener('click',exportJSON);
$('print').addEventListener('click',()=>{if(state){try{reportData();if(!approveInternalExport())return;window.print();}catch(e){note(e.message,true);}}});
['anchor','urgent-days','medium-days','low-days','details','report-title','audience','internal-readiness','urgent-decision','medium-decision','low-decision'].forEach(id=>$(id).addEventListener('input',render));
})();