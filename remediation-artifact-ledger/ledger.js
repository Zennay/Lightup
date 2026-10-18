/* LightUp Artifact Ledger: PRIVATE offline human filing, not proof of authorization, scan or remediation. */
(function () {
'use strict';
const MAX_FILE = 16 * 1024 * 1024, MAX_DOCS = 120, MAX_IMPORT = 1024 * 1024;
const STAGES = ['unreviewed', 'human_review', 'follow_up', 'archived'];
const AUTH_FLAGS = ['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const $ = id => document.getElementById(id);
const state = {findings:[], sha:'', rows:[], client:'', engagement:'', filter:'', verify:null, pending:null, selected:new Set(), bulk:null, undo:[]};
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
function strictJSON(text){
 if(typeof text!=='string'||utf8(text).length>MAX_IMPORT)fail('PRIVATE import exceeds 1 MiB.');
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
  verify.type='button';verify.addEventListener('click',()=>{$('verify').click();state.verify=i;message('Choose the SAME local file. The content stays in your browser.',false);});
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
}
async function loadSource(){
 const file=$('original').files[0];if(!file)fail('Select an original findings CSV.');
 const client=bounded($('client').value.trim(),120,'client reference',true);
 const engagement=bounded($('engagement').value.trim(),120,'engagement reference',true);
 const txt=await fileReader(file,LightUpCasework.MAX_BYTES);
 const findings=LightUpCasework.parseCSV(txt);
 const hash=await digest(utf8(sourceFingerprint(findings)));
 const oldSource=state.sha,oldClient=state.client,oldEngagement=state.engagement;
 if(state.sha && (hash!==state.sha||state.client!==client||state.engagement!==engagement)){
   if(!confirm('New original source or context. Discard ALL existing private notes and attachments?'))return;
 }
 state.findings=findings;state.sha=hash;state.client=client;state.engagement=engagement;
 state.selected.clear();state.bulk=null;state.undo=[];
 if(state.rows.length && (oldSource !== hash || oldClient !== client || oldEngagement !== engagement))state.rows=[];state.verify=null;
 $('finding').replaceChildren();
 for(const f of findings){const op=document.createElement('option');op.value=f.finding_id;op.textContent=f.finding_id+' · '+f.severity+' · '+f.title.slice(0,75);$('finding').append(op);}
 $('original').value='';state.pending=null;$('migrationResult').hidden=true;render();message('Original five-column source loaded as unverified. File bytes are not stored.',false);
}
async function addFiles(){
 if(!state.sha)fail('Load original source first.');
 const files=Array.from($('addFiles').files),fid=$('finding').value;
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
 state.rows.push(...staged);state.bulk=null;state.undo=[];$('addFiles').value='';render();
 message(staged.length+' local file fingerprint(s) filed. Original file content was not retained.',false);
}
async function verifyFile(){
 const file=$('verify').files[0];$('verify').value='';
 const idx=state.verify;state.verify=null;
 if(idx===null||idx>=state.rows.length||!file)return;
 if(file.size>MAX_FILE)fail('File larger than permitted local size.');
 const got=await digest(await file.arrayBuffer()),x=state.rows[idx];
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
 const newFindings=LightUpCasework.parseCSV(await fileReader(file,LightUpCasework.MAX_BYTES));
 const newSha=await digest(utf8(sourceFingerprint(newFindings)));
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
 state.selected.clear();state.bulk=null;state.undo=[];
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
bind('selectVisible','click',selectVisible);
bind('clearSelection','click',()=>{state.selected.clear();state.bulk=null;render();});
bind('previewBulk','click',previewBulk);
bind('applyBulk','click',applyBulk);
bind('undoBulk','click',undoBulk);
bind('previewMigration','click',previewMigration);
bind('applyMigration','click',applyMigration);
bind('filter','input',()=>{state.filter=$('filter').value.toLowerCase().trim();render();});
bind('forget','click',()=>{if(confirm('Forget all original findings and local human notes in memory?')){
 state.findings=[];state.sha='';state.rows=[];state.client='';state.engagement='';state.verify=null;state.filter='';state.pending=null;state.selected.clear();state.bulk=null;state.undo=[];$('migrationResult').hidden=true;
 for(const id of ['client','engagement','filter','original','newSource','addFiles','privateImport','verify'])$(id).value='';
 $('finding').replaceChildren();render();message('Local workspace forgotten. Previously downloaded files are not deleted.',false);
}});
render();
})();