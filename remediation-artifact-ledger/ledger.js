/* LightUp Artifact Ledger: PRIVATE offline human filing, not proof of authorization, scan or remediation. */
(function () {
'use strict';
const MAX_FILE = 16 * 1024 * 1024, MAX_DOCS = 120, MAX_IMPORT = 1024 * 1024;
const MAX_NATIVE_CASEWORK = 4 * MAX_IMPORT, MAX_NATIVE_EVIDENCE = 2 * MAX_IMPORT;
const STAGES = ['unreviewed', 'human_review', 'follow_up', 'archived'];
const AUTH_FLAGS = ['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const $ = id => document.getElementById(id);
const state = {findings:[], sha:'', rows:[], client:'', engagement:'', filter:'', verify:null, pending:null, selected:new Set(), bulk:null, undo:[], casework:null, evidence:null};
const encoder = new TextEncoder();
const ESCAPE = '\uFEFF';
function fail(message) { throw new Error(message); }
function message(s, bad) { $('notice').textContent=s; $('notice').className=bad?'alert':'notice'; }
function bounded(s,max,name,required) {
 if (typeof s!=='string'||s.length>max||s.includes('\u0000')||(required&&!s.trim())) fail('Invalid '+name+'.');
 return s;
}
function hex(buffer) { return Array.from(new Uint8Array(buffer), v=>v.toString(16).padStart(2,'0')).join(''); }
function cryptoReady(){if(typeof crypto==='undefined'||!crypto.subtle)fail('This browser context has no WebCrypto SHA-256. Use a supported local browser.');}
async function digest(buffer){cryptoReady();return hex(await crypto.subtle.digest('SHA-256',buffer));}
function utf8(text) { return encoder.encode(text); }
function download(name, content, mime) {
 const blob=new Blob([content],{type:mime});
 const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function sourceFingerprint(findings){return JSON.stringify(findings.slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));}
function strictJSON(text,cap=MAX_IMPORT){
 if(typeof text!=='string'||utf8(text).length>cap)fail('PRIVATE import exceeds 1 MiB.');
 const data=JSON.parse(text);
 // Duplicate JSON property keys must not silently replace previously declared values.
 const stack=[];let quoted=false,start=0,escaped=false;
 for(let i=0;i<text.length;i++){
   const ch=text[i];
   if(quoted){
     if(escaped){escaped=false;continue;}
     if(ch==='\\'){escaped=true;continue;}
     if(ch==='"'){
       quoted=false;
       let next=i+1;while(/\s/.test(text[next]||''))next++;
       if(text[next]===':'){
         const frame=stack[stack.length-1];
         if(!frame||frame.type!=='{')fail('Malformed JSON object key.');
         const key=JSON.parse(text.slice(start,i+1));
         if(frame.keys.has(key))fail('Duplicate PRIVATE JSON key: '+key.slice(0,80));
         frame.keys.add(key);
       }
     }
     continue;
   }
   if(ch==='"'){quoted=true;start=i;continue;}
   if(ch==='{'||ch==='['){stack.push({type:ch,keys:new Set()});if(stack.length>40)fail('JSON is nested too deeply.');}
   if(ch==='}'||ch===']'){
     const frame=stack.pop();if(!frame||frame.type!==(ch==='}'?'{':'['))fail('Malformed JSON structure.');
   }
 }
 if(quoted||stack.length)fail('Malformed JSON input.');
 return data;
}
function validateRow(x, ids) {
 if(!x||typeof x!=='object'||Array.isArray(x))fail('Malformed attachment record.');
 const keys=['finding_id','file_name','byte_length','sha256','mime','added_utc','human_reviewer','human_stage','human_note'];
 if(Object.keys(x).length!==keys.length||keys.some(k=>!Object.prototype.hasOwnProperty.call(x,k)))fail('Unknown or missing private attachment fields.');
 if(!ids.has(x.finding_id))fail('Attachment references an unknown original finding.');
 bounded(x.file_name,240,'file name',true);
 if(/[\/\\\u0000-\u001f]/.test(x.file_name))fail('Unsafe file name.');
 if(!Number.isSafeInteger(x.byte_length)||x.byte_length<0||x.byte_length>MAX_FILE)fail('Invalid original file size.');
 if(typeof x.sha256!=='string'||!/^[a-f0-9]{64}$/.test(x.sha256))fail('Invalid original SHA-256.');
 bounded(x.mime,120,'MIME label',false);
 bounded(x.added_utc,32,'local timestamp',true);
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x.added_utc)||Number.isNaN(Date.parse(x.added_utc)))fail('Invalid local timestamp.');
 bounded(x.human_reviewer,120,'reviewer',false);
 bounded(x.human_note,1200,'human note',false);
 if(!STAGES.includes(x.human_stage))fail('Invalid human-only stage.');
 return {...x};
}
function privatePacket(){
 return {kind:'lightup.private_artifact_ledger',schema_version:1,disposition:'PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY',
 ...Object.fromEntries(AUTH_FLAGS.map(k=>[k,false])),
 source_contract:'lightup.finding_export._COLUMNS_v1',source_sha256:state.sha,
 source_count:state.findings.length,client_reference:state.client,engagement_reference:state.engagement,
 attachments:state.rows.map(x=>({...x})),
 warning:'Locally selected file bytes and human notes are NOT proof of security remediation, authenticated source, client consent, valid retest, or release.'};
}
async function fileReader(file,max){
 if(!file||file.size>max)fail('File exceeds permitted size: '+max+' bytes.');
 return new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
}
function render(){
 const root=$('rows');root.replaceChildren();
 const byId=new Map(state.findings.map(f=>[f.finding_id,f]));
 let shown=0;
 state.rows.forEach((row,i)=>{
  const source=byId.get(row.finding_id);if(!source)return;
  const terms=(source.finding_id+' '+source.title+' '+row.file_name+' '+row.human_note).toLowerCase();
  if(state.filter&&!terms.includes(state.filter))return;
  shown++;
  const tr=document.createElement('tr');
  function cell(str){let td=document.createElement('td');td.textContent=str;tr.append(td);return td;}
  const pick=document.createElement('input');pick.type='checkbox';pick.checked=state.selected.has(rowKey(row));
  pick.setAttribute('aria-label','Select private record '+row.finding_id+' / '+row.sha256.slice(0,12));
  pick.addEventListener('change',()=>{if(pick.checked)state.selected.add(rowKey(row));else state.selected.delete(rowKey(row));state.bulk=null;renderSelection();});
  const pickCell=document.createElement('td');pickCell.append(pick);tr.append(pickCell);
  cell(source.finding_id+' · '+source.severity);
  cell(row.file_name+' · '+row.byte_length+' bytes');
  let checksum=cell(row.sha256.slice(0,16)+'…');checksum.title=row.sha256;
  const st=document.createElement('select');
  for(const s of STAGES){const op=document.createElement('option');op.value=s;op.textContent=s.replaceAll('_',' ');st.append(op);}
  st.value=row.human_stage;st.addEventListener('change',()=>{row.human_stage=st.value;renderSummary();});
  const sc=document.createElement('td');sc.append(st);tr.append(sc);
  const rv=document.createElement('input');rv.value=row.human_reviewer;rv.maxLength=120;rv.setAttribute('aria-label','Human reviewer for '+row.file_name);
  rv.addEventListener('change',()=>{row.human_reviewer=bounded(rv.value,120,'reviewer',false);});
  const rc=document.createElement('td');rc.append(rv);tr.append(rc);
  const note=document.createElement('textarea');note.value=row.human_note;note.maxLength=1200;note.rows=2;note.setAttribute('aria-label','Human note for '+row.file_name);
  note.addEventListener('change',()=>{row.human_note=bounded(note.value,1200,'note',false);});
  const nc=document.createElement('td');nc.append(note);tr.append(nc);
  const actions=document.createElement('td'),verify=document.createElement('button');verify.textContent='Recheck local file';
  verify.type='button';verify.addEventListener('click',()=>{state.verify={key:rowKey(row),row,source:state.sha};$('verify').click();message('Choose the SAME local file. The content stays in your browser.',false);});
  const remove=document.createElement('button');remove.type='button';remove.textContent='Remove';
  remove.addEventListener('click',()=>{if(confirm('Remove this local human record? This cannot remove external source evidence.')){state.selected.delete(rowKey(row));state.rows.splice(i,1);state.bulk=null;state.undo=[];render();}});
  actions.append(verify,remove);tr.append(actions);
  root.append(tr);
 });
 $('tableSection').hidden=!state.findings.length;
 $('shown').textContent=shown+' shown / '+state.rows.length+' private artifact records';
 renderSummary();renderSelection();
}
function renderSummary(){
 const counts=Object.fromEntries(STAGES.map(x=>[x,0]));
 for(const x of state.rows)counts[x.human_stage]++;
 $('summary').textContent=state.findings.length+' original findings · '+state.rows.length+' local file fingerprints · '+STAGES.map(s=>s+': '+counts[s]).join(' · ');
 $('source').textContent=state.sha?'Original canonical source SHA-256: '+state.sha:'No original CSV loaded.';
 for(const id of ['addFiles','export','aggregate','privateImport','forget','verify'])$(id).disabled=!state.sha;
 $('coverageExport').disabled=!state.sha;
 $('caseworkImport').disabled=!state.sha;$('detachCasework').disabled=!state.casework;
 $('evidenceImport').disabled=!state.sha;$('detachEvidence').disabled=!state.evidence;
 $('evidenceState').textContent=state.evidence?'Native original Evidence Review v2: '+state.evidence.size+' HUMAN records (READ-ONLY)':'No native Evidence Review imported.';
 $('caseworkState').textContent=state.casework ? 'Native original Casework v1: '+state.casework.size+' HUMAN records (READ-ONLY)' : 'No native Casework imported.';
 renderCoverage();$('actionExport').disabled=!state.sha;renderActions();
}
async function loadSource(){
 const file=$('original').files[0];if(!file)fail('Select an original findings CSV.');
 const client=bounded($('client').value.trim(),120,'client reference',true);
 const engagement=bounded($('engagement').value.trim(),120,'engagement reference',true);
 const sourceAtStart=state.sha,rowsAtStart=JSON.stringify(state.rows);
 const txt=await fileReader(file,LightUpCasework.MAX_BYTES);
 const findings=LightUpCasework.parseCSV(txt);
 const hash=await digest(utf8(sourceFingerprint(findings)));
 if(state.sha!==sourceAtStart||JSON.stringify(state.rows)!==rowsAtStart||$('client').value.trim()!==client||$('engagement').value.trim()!==engagement)fail('Source or notes changed during import; retry.');
 const oldSource=state.sha,oldClient=state.client,oldEngagement=state.engagement;
 if(state.sha && (hash!==state.sha||state.client!==client||state.engagement!==engagement)){
   if(!confirm('New original source or context. Discard ALL existing private notes and attachments?'))return;
 }
 state.findings=findings;state.sha=hash;state.client=client;state.engagement=engagement;
 state.selected.clear();state.bulk=null;state.undo=[];state.casework=null;state.evidence=null;
 if(state.rows.length && (oldSource !== hash || oldClient !== client || oldEngagement !== engagement))state.rows=[];state.verify=null;
 $('finding').replaceChildren();
 for(const f of findings){const op=document.createElement('option');op.value=f.finding_id;op.textContent=f.finding_id+' · '+f.severity+' · '+f.title.slice(0,75);$('finding').append(op);}
 $('original').value='';state.pending=null;$('migrationResult').hidden=true;render();message('Original five-column source loaded as unverified. File bytes are not stored.',false);
}
async function addFiles(){
 if(!state.sha)fail('Load original source first.');
 const files=Array.from($('addFiles').files),fid=$('finding').value;
 const sourceAtStart=state.sha,clientAtStart=state.client,engagementAtStart=state.engagement;
 if(files.length<1||files.length+state.rows.length>MAX_DOCS)fail('Select files; ledger maximum is 120 records.');
 const staged=[];
 for(const f of files){
   if(f.size>MAX_FILE)fail('Each file must be at most 16 MiB.');
   if(/[\/\\\u0000-\u001f]/.test(f.name)||!f.name||f.name.length>240)fail('Invalid local filename.');
   const hash=await digest(await f.arrayBuffer());
   if(state.rows.some(x=>x.finding_id===fid&&x.sha256===hash)||
      staged.some(x=>x.finding_id===fid&&x.sha256===hash))fail('Duplicate file fingerprint under the selected finding.');
   staged.push(validateRow({finding_id:fid,file_name:f.name,byte_length:f.size,sha256:hash,
    mime:(f.type||'').slice(0,120),added_utc:new Date().toISOString(),human_reviewer:'',
    human_stage:'unreviewed',human_note:''},new Set(state.findings.map(x=>x.finding_id))));
 }
 if(state.sha!==sourceAtStart||state.client!==clientAtStart||state.engagement!==engagementAtStart||!state.findings.some(f=>f.finding_id===fid)||state.rows.length+staged.length>MAX_DOCS||staged.some(v=>state.rows.some(x=>x.finding_id===v.finding_id&&x.sha256===v.sha256)))fail('Original source or local inventory changed while hashing; retry.');
 state.rows.push(...staged);state.bulk=null;state.undo=[];$('addFiles').value='';render();
 message(staged.length+' local file fingerprint(s) filed. Original file content was not retained.',false);
}
async function verifyFile(){
 const file=$('verify').files[0];$('verify').value='';
 const ref=state.verify;state.verify=null;
 if(!ref||!file)return;
 const x=state.rows.find(r=>rowKey(r)===ref.key);
 if(!x||x!==ref.row||state.sha!==ref.source)
  fail('Original source or selected fingerprint changed before local recheck; retry.');
 if(file.size>MAX_FILE)fail('File larger than permitted local size.');
 const got=await digest(await file.arrayBuffer());
 if(state.sha!==ref.source||!state.rows.includes(x)||rowKey(x)!==ref.key)
  fail('Original fingerprint changed during local recheck; retry.');
 message(got===x.sha256&&file.size===x.byte_length?
  'Byte digest and length MATCH locally. This does not validate content truth, chronology, authenticity or remediation.':
  'MISMATCH: the selected file differs from the recorded bytes. No record was changed.',
  got!==x.sha256||file.size!==x.byte_length);
}
async function importPrivate(){
 if(!state.sha)fail('Load independently checked original CSV first.');
 const txt=await fileReader($('privateImport').files[0],MAX_IMPORT);
 const packet=strictJSON(txt);
 if(!packet||Array.isArray(packet)||packet.kind!=='lightup.private_artifact_ledger'||
 packet.schema_version!==1||packet.disposition!=='PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY'||
 packet.source_contract!=='lightup.finding_export._COLUMNS_v1'||
 AUTH_FLAGS.some(k=>packet[k]!==false)||
 Object.keys(packet).some(k=>!['kind','schema_version','disposition',...AUTH_FLAGS,'source_contract','source_sha256','source_count','client_reference','engagement_reference','attachments','warning'].includes(k))||
 packet.source_sha256!==state.sha||packet.source_count!==state.findings.length||
 packet.client_reference!==state.client||packet.engagement_reference!==state.engagement)
  fail('PRIVATE ledger source, client, engagement or non-authority flags do not match exactly.');
 if(!Array.isArray(packet.attachments)||packet.attachments.length>MAX_DOCS)fail('PRIVATE ledger attachment count exceeds limit.');
 const ids=new Set(state.findings.map(f=>f.finding_id)),seen=new Set();
 const staged=packet.attachments.map(x=>{
   const v=validateRow(x,ids),key=v.finding_id+'|'+v.sha256;
   if(seen.has(key))fail('Duplicate PRIVATE attachment fingerprint.');seen.add(key);return v;
 });
 if(!confirm('Restore '+staged.length+' PRIVATE local notes and REPLACE the current '+state.rows.length+' notes? Review client/engagement separately.'))return;
 state.rows=staged;state.selected.clear();state.bulk=null;state.undo=[];state.pending=null;$('migrationResult').hidden=true;$('privateImport').value='';render();message('Complete source-bound PRIVATE human draft restored; no authority inferred.',false);
}

/* Original-source migration is HUMAN data reconciliation, NEVER a remediation verdict.
   Original Casework.compareSource is immutable source-owner code. */
function populateOriginalIds(){
 $('finding').replaceChildren();
 for(const f of state.findings){
  const op=document.createElement('option');op.value=f.finding_id;
  op.textContent=f.finding_id+' · '+f.severity+' · '+f.title.slice(0,75);
  $('finding').append(op);
 }
}
async function previewMigration(){
 if(!state.sha)fail('Load an original CSV first.');
 const file=$('newSource').files[0];
 if(!file)fail('Select a separately obtained new original CSV.');
 if(!$('sameEngagement').checked)fail('Explicitly confirm separately verified same client/engagement first.');
 const sourceAtStart=state.sha,rowsAtStart=JSON.stringify(state.rows),clientAtStart=state.client,engagementAtStart=state.engagement;
 const newFindings=LightUpCasework.parseCSV(await fileReader(file,LightUpCasework.MAX_BYTES));
 const newSha=await digest(utf8(sourceFingerprint(newFindings)));
 if(state.sha!==sourceAtStart||JSON.stringify(state.rows)!==rowsAtStart||state.client!==clientAtStart||state.engagement!==engagementAtStart||!$('sameEngagement').checked)fail('Source or notes changed during migration preview; retry.');
 if(newSha===state.sha)fail('The new canonical source is identical; there is nothing to migrate.');
 const delta=LightUpCasework.compareSource(state.findings,newFindings);
 const keep=new Set(delta.unchanged);
 const retained=state.rows.filter(r=>keep.has(r.finding_id)).map(r=>({...r}));
 const quarantined=state.rows.filter(r=>!keep.has(r.finding_id));
 state.pending={oldSha:state.sha,oldRows:JSON.stringify(state.rows),
  client:state.client,engagement:state.engagement,newSha,newFindings,delta,retained,
  dropped:quarantined.length};
 const lines=[
  'HUMAN SOURCE-MIGRATION PREVIEW — not a fix/retest determination',
  'Old original SHA-256: '+state.sha,
  'New original SHA-256: '+newSha,
  'Unchanged original rows: '+delta.unchanged.length,
  'New original rows: '+delta.added.length,
  'Changed original rows: '+delta.changed.length,
  'Absent original rows: '+delta.missing.length+' (NOT proof of fixed)',
  'Retained human local fingerprints: '+retained.length,
  'Quarantined fingerprints: '+quarantined.length+' (ONLY in old PRIVATE backup)',
  'Changed original IDs: '+delta.changed.map(x=>x.finding_id).join(', ').slice(0,1400),
  'Absent original IDs: '+delta.missing.join(', ').slice(0,1400),
  'No original remediation status or security authority is copied into this tool.'
 ];
 $('migrationPreview').textContent=lines.join('\n');
 $('migrationResult').hidden=false;$('ackBackup').checked=false;
 $('applyMigration').disabled=false;
 $('newSource').value='';
 message('Migration preview staged in browser memory. Export the OLD private ledger first.',false);
}
function applyMigration(){
 const staged=state.pending;
 if(!staged)fail('Stage a new original source preview first.');
 if(!$('sameEngagement').checked||!$('ackBackup').checked)
  fail('Separately confirm the same original engagement and the OLD private backup.');
 if(state.sha!==staged.oldSha||state.client!==staged.client||
 state.engagement!==staged.engagement||JSON.stringify(state.rows)!==staged.oldRows)
  fail('Original human source or notes changed after preview; re-preview required.');
 if(!confirm('Replace this HUMAN workspace with the new unverified original source? '+
   staged.dropped+' non-identical/absent-source records are removed from current memory; keep your separate OLD private backup. Missing is NEVER proven fixed.'))return;
 state.findings=staged.newFindings;state.sha=staged.newSha;state.rows=staged.retained;
 state.selected.clear();state.bulk=null;state.undo=[];state.casework=null;
 state.pending=null;state.verify=null;state.filter='';$('filter').value='';
 $('migrationResult').hidden=true;$('migrationPreview').textContent='';
 $('sameEngagement').checked=false;$('ackBackup').checked=false;
 populateOriginalIds();render();
 message('New original source loaded; exact unchanged finding records retain HUMAN fingerprints only. '+
 staged.dropped+' nonmatching local fingerprints remain only in the separately saved OLD PRIVATE backup; NOT fixed.',false);
}


function rowKey(r){return r.finding_id+'|'+r.sha256;}
function renderSelection(){
 const matched=state.rows.filter(r=>{
  const f=state.findings.find(f=>f.finding_id===r.finding_id);
  return f&&(!state.filter||(r.file_name+' '+r.human_note+' '+f.finding_id+' '+f.title).toLowerCase().includes(state.filter));
 });
 const selected=state.rows.filter(r=>state.selected.has(rowKey(r)));
 $('selectedCount').textContent=selected.length+' selected / '+matched.length+' matching';
 $('applyBulk').disabled=!state.bulk;$('undoBulk').disabled=!state.undo.length;
 $('bulkPreview').hidden=!state.bulk;
}
function selectVisible(){
 for(const r of state.rows){
  const f=state.findings.find(f=>f.finding_id===r.finding_id);
  if(f&&(!state.filter||(r.file_name+' '+r.human_note+' '+f.finding_id+' '+f.title).toLowerCase().includes(state.filter)))
   state.selected.add(rowKey(r));
 }
 state.bulk=null;render();
}
function previewBulk(){
 const chosen=state.rows.filter(r=>state.selected.has(rowKey(r)));
 if(!chosen.length)fail('Select at least one original evidence fingerprint.');
 const stage=$('bulkStage').value,changeReviewer=$('bulkReviewerEnabled').checked;
 if(stage!=='keep'&&!STAGES.includes(stage))fail('Invalid HUMAN stage proposal.');
 const reviewer=bounded($('bulkReviewer').value,120,'bulk reviewer',false);
 if(stage==='keep'&&!changeReviewer)fail('Choose a stage or explicitly enable a reviewer change.');
 const entries=chosen.map(r=>({
  key:rowKey(r),beforeStage:r.human_stage,afterStage:stage==='keep'?r.human_stage:stage,
  beforeReviewer:r.human_reviewer,afterReviewer:changeReviewer?reviewer:r.human_reviewer
 }));
 state.bulk={source:state.sha,snapshot:JSON.stringify(state.rows),
  selected:JSON.stringify([...state.selected].sort()),entries};
 $('bulkPreview').textContent=[
  'Human-only PRIVATE bulk preview · '+entries.length+' exact artifact records',
  'Original source SHA: '+state.sha,
  ...entries.map(v=>v.key.slice(0,185)+' · stage: '+v.beforeStage+' → '+v.afterStage+
   ' · reviewer: '+v.beforeReviewer.slice(0,30)+' → '+v.afterReviewer.slice(0,30)),
  'No source finding, fingerprint bytes, scan, grant or security verification changes.'
 ].join('\n');
 renderSelection();message('Preview ready. Review exact original records before applying HUMAN-only changes.',false);
}
function applyBulk(){
 const p=state.bulk;
 if(!p)fail('No HUMAN-only batch preview.');
 if(state.sha!==p.source||JSON.stringify(state.rows)!==p.snapshot||
  JSON.stringify([...state.selected].sort())!==p.selected)
  fail('Source, selected records or human baselines changed since preview; preview again.');
 if(!confirm('Apply HUMAN-only stage/reviewer changes to '+p.entries.length+' exact records? This is NOT verified remediation.'))return;
 state.undo.push({sha:state.sha,rows:JSON.stringify(state.rows)});
 if(state.undo.length>20)state.undo.shift();
 const changes=new Map(p.entries.map(x=>[x.key,x]));
 for(const r of state.rows){const x=changes.get(rowKey(r));if(x){r.human_stage=x.afterStage;r.human_reviewer=x.afterReviewer;}}
 state.undo[state.undo.length-1].applied=JSON.stringify(state.rows);
 state.bulk=null;render();message('Applied '+p.entries.length+' PRIVATE human status changes. Undo is available.',false);
}
function undoBulk(){
 const previous=state.undo[state.undo.length-1];
 if(!previous)return;
 if(previous.sha!==state.sha||JSON.stringify(state.rows)!==previous.applied)
  fail('Human notes or source changed since the last batch; undo refused to prevent lost edits.');
 state.undo.pop();
 state.rows=JSON.parse(previous.rows);state.bulk=null;render();
 message('Restored previous private human-review fields in memory only.',false);
}



/* ORIGINAL native Casework v1 is imported READ-ONLY for human coordination.
   An accepted original source digest is not a proof of customer authorization. */
async function importCasework(){
 if(!state.sha)fail('Load original independently checked findings CSV first.');
 const file=$('caseworkImport').files[0];
 const sourceAtStart=state.sha,context=state.client+'|'+state.engagement;
 const raw=strictJSON(await fileReader(file,MAX_NATIVE_CASEWORK),MAX_NATIVE_CASEWORK);
 const packet=LightUpCasework.loadPacket(raw);
 if(packet.source_sha256!==sourceAtStart)
  fail('Native Casework source digest absent or different from this ORIGINAL findings source.');
 if(sourceFingerprint(packet.findings)!==sourceFingerprint(state.findings))
  fail('Native Casework original findings content differs. Human notes cannot cross source.');
 if(state.sha!==sourceAtStart||state.client+'|'+state.engagement!==context)
  fail('Original source or declared context changed during Casework import; retry.');
 const cases=packet.cases.map(c=>LightUpCasework.cleanCase(c,new Set(state.findings.map(f=>f.finding_id))));
 if(cases.length!==state.findings.length||new Set(cases.map(c=>c.finding_id)).size!==cases.length)
  fail('Incomplete native Casework original finding coverage.');
 if(!confirm('Attach native PRIVATE Casework human planning READ-ONLY for this locally declared engagement? The source digest cannot authenticate a client or prove remediation.'))return;
 state.casework=new Map(cases.map(c=>[c.finding_id,c]));
 $('caseworkImport').value='';
 render();
 message('Original Casework v1 attached read-only to '+cases.length+' exact ORIGINAL findings. No planning, status, grants or source claims were changed.',false);
}
function detachCasework(){
 if(!state.casework)return;
 if(!confirm('Detach read-only imported PRIVATE Casework context from the current browser memory?'))return;
 state.casework=null;render();message('Native Casework human overlay detached. Original source and local artifact ledger remain unchanged.',false);
}


/* Original Evidence Review v2 is separately produced private human planning;
   import read-only, never infer a grant, a retest, or a verified remediation. */
const EVIDENCE_STAGES=['missing','submitted','needs_changes','ready_for_authorized_retest'];
const EVIDENCE_FIELD_LIMITS={
 change_reference:240,deployment_reference:240,rollback_reference:240,
 retest_request_reference:240,review_question:700
};
function parseEvidenceRow(v,ids){
 if(!v||Object.getPrototypeOf(v)!==Object.prototype||!ids.has(v.finding_id)||
  Object.keys(v).sort().join('|')!=='evidence|finding_id|next_step|reference|reviewer|stage')
  fail('Malformed original Evidence Review v2 finding or field names.');
 if(!EVIDENCE_STAGES.includes(v.stage))fail('Unknown original human evidence stage.');
 for(const [field,max] of [['reference',240],['reviewer',120],['next_step',500]]){
  bounded(v[field],max,'native evidence '+field,false);
 }
 if(!v.evidence||Object.getPrototypeOf(v.evidence)!==Object.prototype||
   Object.keys(v.evidence).sort().join('|')!==Object.keys(EVIDENCE_FIELD_LIMITS).sort().join('|'))
  fail('Invalid original Evidence Review v2 reference fields.');
 for(const [k,max] of Object.entries(EVIDENCE_FIELD_LIMITS))
  bounded(v.evidence[k],max,'native evidence '+k,false);
 const values=[v.reference,v.reviewer,v.next_step,...Object.values(v.evidence)];
 if(values.some(x=>/[\u202a-\u202e\u2066-\u2069]/.test(x)))
  fail('Ambiguous directional control in imported original human notes.');
 return {finding_id:v.finding_id,stage:v.stage,reference:v.reference,
  reviewer:v.reviewer,next_step:v.next_step,evidence:{...v.evidence}};
}
async function importEvidenceV2(){
 if(!state.sha)fail('Load original independently checked findings CSV first.');
 const sourceAtStart=state.sha,contextAtStart=state.client+'|'+state.engagement;
 const data=strictJSON(await fileReader($('evidenceImport').files[0],MAX_NATIVE_EVIDENCE),MAX_NATIVE_EVIDENCE);
 if(!data||Object.getPrototypeOf(data)!==Object.prototype||
 data.kind!=='lightup.remediation_evidence_coordination'||data.schema_version!==2||
 data.disposition!=='UNVERIFIED_OFFLINE_HUMAN_COORDINATION'||
 data.source_contract!=='lightup.finding_export._COLUMNS_v1'||
 data.source_sha256!==sourceAtStart||AUTH_FLAGS.some(k=>data[k]!==false)||
 Object.keys(data).some(k=>!['kind','schema_version','disposition','source_contract','source_sha256','review','revision_register','warning',...AUTH_FLAGS].includes(k))||
 !Array.isArray(data.review)||data.review.length!==state.findings.length||
 !Array.isArray(data.revision_register)||data.revision_register.length>350)
  fail('Native original Evidence Review v2 source, non-authority flags or full original review differ.');
 const ids=new Set(state.findings.map(f=>f.finding_id));
 const reviews=data.review.map(x=>parseEvidenceRow(x,ids));
 if(new Set(reviews.map(x=>x.finding_id)).size!==ids.size)
  fail('Incomplete or repeated original Evidence Review finding ID.');
 // Original source-owner revision fields are *untrusted historical annotations*;
 // reject suspicious oversized structure, but never use them to authorize/fix.
 const revisions=JSON.stringify(data.revision_register);
 if(revisions.length>200000)fail('Original human revision register exceeds local metadata bound.');
 if(state.sha!==sourceAtStart||state.client+'|'+state.engagement!==contextAtStart)
  fail('Original source/context changed during Evidence Review import.');
 if(!confirm('Attach original PRIVATE Evidence Review v2 READ-ONLY to exact original source? Human references are NOT proof of remediation or authorization.'))return;
 state.evidence=new Map(reviews.map(x=>[x.finding_id,x]));
 $('evidenceImport').value='';render();
 message('Original Evidence Review v2 attached read-only for '+reviews.length+' exact original findings. No external evidence, client consent or security approval changed.',false);
}
function detachEvidence(){
 if(!state.evidence)return;
 if(!confirm('Detach original PRIVATE Evidence Review human context from local memory?'))return;
 state.evidence=null;render();message('Native Evidence Review context detached; original source and evidence fingerprints are unchanged.',false);
}

function coverageRows(){
 const counts=new Map();
 for(const r of state.rows){
  let c=counts.get(r.finding_id);
  if(!c){c={count:0,review:0,followup:0};counts.set(r.finding_id,c);}
  c.count++;if(r.human_stage==='human_review')c.review++;
  if(r.human_stage==='follow_up')c.followup++;
 }
 return state.findings.map(f=>({...f,...(counts.get(f.finding_id)||{count:0,review:0,followup:0})}));
}
function renderCoverage(){
 const body=$('coverageRows');body.replaceChildren();
 const data=coverageRows(),filter=$('coverageFilter').value;
 const unlinked=data.filter(x=>!x.count);
 const urgent=unlinked.filter(x=>x.severity==='critical'||x.severity==='high');
 $('coverageSummary').textContent=data.length+' original findings · '+unlinked.length+
 ' without a LOCAL file fingerprint · '+urgent.length+' critical/high without a LOCAL fingerprint. '+
 'Unregistered here does NOT mean no evidence exists elsewhere.';
 const severityRank=s=>LightUpCasework.SEVERITY.indexOf(s);
 const visible=data.filter(x=>filter==='all'||filter==='unlinked'&&!x.count||
   filter==='critical_unlinked'&&!x.count&&severityRank(x.severity)<=1||
   filter==='follow_up'&&x.followup>0).sort((a,b)=>severityRank(a.severity)-severityRank(b.severity)||
   a.finding_id.localeCompare(b.finding_id));
 for(const f of visible){
  const tr=document.createElement('tr');
  const cw=state.casework&&state.casework.get(f.finding_id);
  const ev=state.evidence&&state.evidence.get(f.finding_id);
  for(const value of [f.finding_id,f.severity,
   f.retest_status+' (source claim only)',String(f.count),
   String(f.review),String(f.followup),
   cw ? cw.status+' · '+(cw.owner||'unassigned')+' · '+(cw.due_date||'no human date') : 'not imported',
   ev ? ev.stage+' · '+(ev.evidence.retest_request_reference?'request noted':'no retest request reference') : 'not imported']){
   const td=document.createElement('td');td.textContent=value;tr.append(td);
  }
  const td=document.createElement('td'),open=document.createElement('button');
  open.type='button';open.textContent='Open original finding';
  open.addEventListener('click',()=>{
   $('finding').value=f.finding_id;$('filter').value=f.finding_id;
   state.filter=f.finding_id.toLowerCase();render();
   $('addFiles').focus();message('Selected original finding '+f.finding_id+' for human evidence filing.',false);
  });
  td.append(open);tr.append(td);body.append(tr);
 }
 $('coverageShown').textContent=visible.length+' original findings shown (private local view)';
}
function exportCoverage(){
 if(!state.sha)fail('Load the original findings source first.');
 if(!confirm('Export PRIVATE original IDs and LOCAL fingerprint coverage to this device? Verify your recipient separately.'))return;
 const rows=[['finding_id','severity','source_retest_claim','local_fingerprint_count','human_review_count','follow_up_count'],
 ...coverageRows().map(f=>[f.finding_id,f.severity,f.retest_status,String(f.count),String(f.review),String(f.followup)])];
 download('LightUp-PRIVATE-original-evidence-coverage.csv',ESCAPE+
   rows.map(r=>r.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
}


/* Derived PRIVATE human work queue. Never a target/execution queue or remediation verdict. */
function actionItems(){
 const counts=new Map();
 for(const r of state.rows){
  const n=counts.get(r.finding_id)||{files:0,followUp:0};
  n.files++;if(r.human_stage==='follow_up')n.followUp++;
  counts.set(r.finding_id,n);
 }
 const today=new Date().toISOString().slice(0,10);
 return state.findings.map(f=>{
  const cw=state.casework&&state.casework.get(f.finding_id);
  const ev=state.evidence&&state.evidence.get(f.finding_id);
  const n=counts.get(f.finding_id)||{files:0,followUp:0};
  const reasons=[];
  if(!n.files)reasons.push('No LOCAL fingerprint recorded');
  if(n.followUp)reasons.push('Local HUMAN follow-up recorded');
  if(cw){
   if(!cw.owner.trim())reasons.push('Casework HUMAN owner not assigned');
   if(cw.status==='blocked'||cw.blocker.trim())reasons.push('Casework HUMAN blocker');
   if(cw.due_date&&cw.due_date<today&&cw.status!=='completed'&&cw.status!=='deferred')
    reasons.push('Tentative Casework HUMAN date passed');
   if(!cw.next_action.trim()&&cw.status!=='completed')reasons.push('Casework HUMAN next action missing');
  }
  if(ev){
   if(ev.stage==='missing'||ev.stage==='needs_changes')reasons.push('Evidence Review HUMAN follow-up');
   if(!ev.evidence.retest_request_reference.trim())reasons.push('No local HUMAN retest request reference');
  }
  const base={critical:5,high:4,medium:3,low:2,info:1}[f.severity]||1;
  const score=base*10+(reasons.includes('Casework HUMAN blocker')?5:0)+
    (reasons.includes('Tentative Casework HUMAN date passed')?4:0)+
    (n.files?0:2)+(n.followUp?3:0);
  return {finding_id:f.finding_id,severity:f.severity,
    casework_status:cw?cw.status:'not imported',owner:cw?cw.owner:'',due_date:cw?cw.due_date||'':'',
    evidence_stage:ev?ev.stage:'not imported',local_files:n.files,local_followup:n.followUp,
    reasons,score};
 }).sort((a,b)=>b.score-a.score||a.finding_id.localeCompare(b.finding_id));
}
function filteredActionItems(){
 const mode=$('actionFilter').value;
 return actionItems().filter(x=>mode==='all'||
  mode==='critical_high'&&['critical','high'].includes(x.severity)&&x.reasons.length||
  mode==='missing_file'&&!x.local_files||
  mode==='blocked'&&x.reasons.some(r=>r.includes('blocker')||r.includes('date passed'))||
  mode==='human_followup'&&(x.local_followup||x.reasons.includes('Evidence Review HUMAN follow-up')));
}
function renderActions(){
 const body=$('actionRows');body.replaceChildren();
 const original=actionItems(),visible=filteredActionItems();
 $('actionSummary').textContent=original.length+' original findings · '+
 original.filter(x=>x.reasons.length).length+' with LOCAL HUMAN follow-up signals. '+
 'Priorities are illustrative and based only on unverified source/HUMAN notes; no security severity has been validated.';
 for(const item of visible){
  const tr=document.createElement('tr');
  const values=[item.finding_id,item.severity,item.owner||'unassigned',
   item.casework_status+(item.due_date?' · '+item.due_date:''),
   item.evidence_stage,String(item.local_files),
   item.reasons.join(' · ')||'No LOCAL action gap identified'];
  for(const value of values){const td=document.createElement('td');td.textContent=value;tr.append(td);}
  const td=document.createElement('td'),go=document.createElement('button');go.type='button';go.textContent='File local evidence';
  go.addEventListener('click',()=>{
   $('finding').value=item.finding_id;$('filter').value=item.finding_id;state.filter=item.finding_id.toLowerCase();
   render();$('addFiles').focus();message('Prepared LOCAL evidence filing for original ID '+item.finding_id+'. No scan or remediation action issued.',false);
  });
  td.append(go);tr.append(td);body.append(tr);
 }
 $('actionShown').textContent=visible.length+' LOCAL HUMAN source-bound action rows';
}
function exportHumanQueue(){
 if(!state.sha)fail('Load the independently checked original CSV first.');
 const work=filteredActionItems();
 if(!work.length)fail('No original HUMAN action rows match current filter.');
 if(!confirm('Download PRIVATE original finding IDs, source digest, local human owners and HUMAN follow-up gaps? Verify recipient and storage separately. No authorization is created.'))return;
 const heads=['source_sha256','original_finding_id','source_severity_claim','human_casework_owner','human_casework_stage',
 'human_tentative_due_date','human_evidence_review_stage','local_fingerprint_count','local_human_followup_count','local_human_followup_reasons'];
 const rows=work.map(x=>[state.sha,x.finding_id,x.severity,x.owner,x.casework_status,x.due_date,
  x.evidence_stage,String(x.local_files),String(x.local_followup),x.reasons.join('; ')]);
 download('LightUp-PRIVATE-original-human-evidence-action-queue.csv',ESCAPE+
 [heads,...rows].map(x=>x.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
}

function csvCell(raw){
 let s=String(raw);
 // Force text treatment for Unicode-obscured spreadsheet formulas.
 const probe=s.replace(/^[\p{Z}\p{C}\p{M}\s]+/gu,'');
 if(/^[=+\-@]/.test(probe))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
function exportAggregate(){
 const counts={};for(const f of state.findings)counts[f.severity]=0;
 for(const row of state.rows){
  const f=state.findings.find(f=>f.finding_id===row.finding_id);
  const key=f.severity+' / '+row.human_stage;counts[key]=(counts[key]||0)+1;
 }
 const rows=[['severity / human stage','count'],...Object.entries(counts).sort((a,b)=>a[0].localeCompare(b[0]))];
 download('lightup-anonymous-evidence-counts.csv',ESCAPE+rows.map(r=>r.map(csvCell).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
}
function exportPrivate(){
 if(!confirm('Download PRIVATE source-bound attachment names, hashes, human notes and client references to this device? Verify the recipient and storage policy separately.'))return;
 download('LightUp-PRIVATE-artifact-ledger.json',JSON.stringify(privatePacket(),null,2)+'\n','application/json');
}
function bind(id,event,fn){$(id).addEventListener(event,async()=>{try{await fn();}catch(e){message(e.message||'Invalid input.',true);}});}
bind('load','click',loadSource);bind('add','click',addFiles);
bind('export','click',exportPrivate);bind('aggregate','click',exportAggregate);
bind('restore','click',importPrivate);bind('verify','change',verifyFile);
bind('evidenceImportButton','click',importEvidenceV2);
bind('detachEvidence','click',detachEvidence);
bind('actionFilter','change',renderActions);
bind('actionExport','click',exportHumanQueue);
bind('caseworkImportButton','click',importCasework);
bind('detachCasework','click',detachCasework);
bind('coverageFilter','change',renderCoverage);
bind('coverageExport','click',exportCoverage);
bind('selectVisible','click',selectVisible);
bind('clearSelection','click',()=>{state.selected.clear();state.bulk=null;render();});
bind('previewBulk','click',previewBulk);
bind('applyBulk','click',applyBulk);
bind('undoBulk','click',undoBulk);
bind('previewMigration','click',previewMigration);
bind('applyMigration','click',applyMigration);
bind('filter','input',()=>{state.filter=$('filter').value.toLowerCase().trim();render();});
bind('forget','click',()=>{if(confirm('Forget all original findings and local human notes in memory?')){
 state.findings=[];state.sha='';state.rows=[];state.client='';state.engagement='';state.verify=null;state.filter='';state.pending=null;state.selected.clear();state.bulk=null;state.undo=[];state.casework=null;$('migrationResult').hidden=true;
 for(const id of ['client','engagement','filter','original','newSource','addFiles','privateImport','caseworkImport','evidenceImport','verify'])$(id).value='';
 $('finding').replaceChildren();render();message('Local workspace forgotten. Previously downloaded files are not deleted.',false);
}});
render();
})();