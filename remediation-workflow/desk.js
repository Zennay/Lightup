/* Source-bound local human editor; NO authentication, evidence verification, retest, scan or dispatch. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const FIELDS=['change_reference','deployment_reference','rollback_reference','retest_request_reference','review_question'];
const MAX={reference:240,reviewer:120,next_step:500,change_reference:240,deployment_reference:240,rollback_reference:240,retest_request_reference:240,review_question:700};
const LABELS={change_reference:'Patch/change reference',deployment_reference:'Rollout/deployment reference',rollback_reference:'Rollback/recovery reference',retest_request_reference:'Separately authorized retest REQUEST reference',review_question:'Open question to the human reviewer'};
const STAGES=['missing','submitted','needs_changes','ready_for_authorized_retest'];
const BAD=/[\u202a-\u202e\u2066-\u2069]/;
let source=[],digest='',drafts=new Map(),onChange=null,current='',unsaved=false;
function msg(message,error=false){$('editorStatus').textContent=message;$('editorStatus').dataset.error=error?'true':'false';}
function validate(str,max,label){
 if(typeof str!=='string'||str.length>max||str.includes('\u0000')||BAD.test(str))
  throw Error('Invalid '+label+': too long or contains unsafe direction/control characters.');
 return str;
}
function sanitize(row){
 if(!row||!STAGES.includes(row.stage))throw Error('Invalid local review stage.');
 const result={finding_id:validate(row.finding_id,160,'finding ID'),stage:row.stage,
  reference:validate(row.reference,240,'review reference'),
  reviewer:validate(row.reviewer,120,'reviewer'),
  next_step:validate(row.next_step,500,'human next step'),evidence:{}};
 if(!row.evidence||typeof row.evidence!=='object'||Array.isArray(row.evidence))
  throw Error('Incomplete human evidence dossier.');
 for(const name of FIELDS)result.evidence[name]=validate(row.evidence[name],MAX[name],name);
 return result;
}
function pristine(id){return sanitize({finding_id:id,stage:'missing',reference:'',reviewer:'',next_step:'',
 evidence:Object.fromEntries(FIELDS.map(name=>[name,'']))});}
function clearForm(){
 for(const name of ['reference','reviewer','next_step',...FIELDS])$('editor_'+name).value='';
 $('editor_stage').value='missing';
}
function show(id){
 if(!drafts.has(id))return;
 current=id;
 const row=drafts.get(id);$('editorFinding').value=id;
 $('editor_stage').value=row.stage;
 for(const name of ['reference','reviewer','next_step',...FIELDS])
  $('editor_'+name).value=name in row?row[name]:row.evidence[name];
 $('editorCount').textContent=source.length+' original source findings · '+[...drafts.values()].filter(r=>FIELDS.slice(0,4).some(k=>!r.evidence[k].trim())).length+' human reference gaps.';
 msg('Editing only unsigned human notes for original finding '+id+'. No source or retest status will change.');
}
function collect(){
 if(!current||!drafts.has(current))throw Error('Load original findings before editing.');
 const row={finding_id:current,stage:$('editor_stage').value};
 for(const name of ['reference','reviewer','next_step'])row[name]=$('editor_'+name).value;
 row.evidence=Object.fromEntries(FIELDS.map(name=>[name,$('editor_'+name).value]));
 return sanitize(row);
}
function apply(id,row){
 drafts.set(id,row);unsaved=true;onChange?.(id,row);$('editorCount').textContent=
 source.length+' original findings · '+[...drafts.values()].filter(r=>FIELDS.slice(0,4).some(k=>!r.evidence[k].trim())).length+' incomplete human evidence dossiers.';
}
function save(){
 const row=collect();apply(current,row);
 msg('Local HUMAN notes saved for '+current+'. Export PRIVATE Evidence Review draft before closing; nothing is persisted in the browser.');
}
function isLoaded(){if(!digest||!source.length||drafts.size!==source.length)throw Error('Import original findings before creating private drafts.');}
function snapshot(){
 isLoaded();
 return {kind:'lightup.remediation_evidence_coordination',schema_version:2,
  disposition:'UNVERIFIED_OFFLINE_HUMAN_COORDINATION',
  source_contract:'lightup.finding_export._COLUMNS_v1',source_sha256:digest,
  authenticated:false,tenant_verified:false,source_authorized:false,assessment_authorized:false,
  grant:false,client_consent:false,operator_consent:false,execution:false,scan:false,
  audit_verdict:false,retest_verified:false,release:false,
  review:source.map(f=>sanitize(drafts.get(f.finding_id))),
  revision_register:[],
  warning:'References and local stages are unverified human notes, not evidence authenticity, remediation proof or retest results. Source revision history from prior Evidence Review imports is NOT re-exported by the Cockpit; preserve the original private draft separately.'};
}
function download(data){
 const file=new Blob([data],{type:'application/json;charset=utf-8'});
 const url=URL.createObjectURL(file),link=document.createElement('a');
 link.href=url;link.download='lightup-evidence-coordination-PRIVATE.json';link.click();
 setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function exportDraft(){
 try{
  isLoaded();
  // Read the visible form first, but do not silently drop unsaved user edits.
  const candidate=collect(),old=drafts.get(current);
  const modified=JSON.stringify(candidate)!==JSON.stringify(old);
  if(modified)throw Error('Your visible finding has unsaved form changes. Save its notes first.');
  const packet=snapshot(),data=JSON.stringify(packet,null,2)+'\n';
  if(new TextEncoder().encode(data).length>2097152)throw Error('Private evidence export exceeds upstream 2 MiB size limit.');
  if(!confirm('Export PRIVATE unsigned original-source-bound review JSON with source finding IDs and human notes? Verify a separately authorized confidential recipient. This grants NO authority.'))return;
  download(data);unsaved=false;
  msg('Private evidence draft exported for ORIGINAL Evidence Review Board. Keep it confidential. Local edits are not uploaded or verified.');
 }catch(err){msg(err.message,true);}
}
function bulk(){
 try{
  isLoaded();
  if(current&&JSON.stringify(collect())!==JSON.stringify(drafts.get(current)))
   throw Error('Save your current finding form first, before bulk changes.');
  const stage=$('editorBulkStage').value,reviewer=$('editorBulkReviewer').value.trim();
  if(!stage&&!reviewer)throw Error('Select a local human stage or reviewer.');
  if(stage&&!STAGES.includes(stage))throw Error('Unknown local bulk human stage.');
  validate(reviewer,120,'bulk reviewer');
  const severity=$('editorBulkSeverity').value;
  const chosen=source.filter(f=>!severity||f.severity===severity);
  if(!chosen.length)throw Error('No original findings in the requested severity.');
  if(!confirm('Update '+chosen.length+' HUMAN-ONLY review rows? Existing individual evidence and original finding/retest status will NOT be changed.'))return;
  // Prepare all modifications before mutating any local review state.
  const candidate=chosen.map(f=>{
   const old=drafts.get(f.finding_id);
   return [f.finding_id,sanitize({...old,stage:stage||old.stage,reviewer:reviewer||old.reviewer})];
  });
  for(const [id,row] of candidate)apply(id,row);
  if(current)show(current);
  msg('Updated '+candidate.length+' local human review entries; original source and evidence references unchanged. Export a private draft to preserve notes.');
 }catch(err){msg(err.message,true);}
}
function forget(){
 source=[];digest='';drafts=new Map();onChange=null;current='';unsaved=false;
 $('editorPanel').hidden=true;$('editorFinding').replaceChildren();clearForm();$('editorCount').textContent='No source loaded.';
 msg('No human coordination notes are retained after clearing this page.');
}
function mount({original,hash,review,onReviewChange}){
 forget();
 if(!Array.isArray(original)||!original.length||original.length>350||typeof hash!=='string'||!/^[0-9a-f]{64}$/.test(hash)||!(review instanceof Map))
  throw Error('Expected original bounded source and exact source digest.');
 const staged=new Map();
 for(const finding of original){
  const id=validate(finding.finding_id,160,'finding ID');
  if(staged.has(id))throw Error('Duplicate original finding identifier.');
  const existing=review.get(id);
  if(!existing)throw Error('Missing original review row.');
  staged.set(id,sanitize({...existing,finding_id:id,reference:existing.reference??'',
    reviewer:existing.reviewer??'',next_step:existing.next_step??''}));
 }
 source=original.slice();drafts=staged;digest=hash;onChange=onReviewChange;
 const select=$('editorFinding');
 for(const finding of source){
  const opt=document.createElement('option');opt.value=finding.finding_id;
  opt.textContent=finding.finding_id+' · '+finding.severity;select.append(opt);
 }
 $('editorPanel').hidden=false;show(source[0].finding_id);unsaved=false;
}
$('editorFinding').addEventListener('change',()=>{
 try{
  if(current&&JSON.stringify(collect())!==JSON.stringify(drafts.get(current))){
   if(!confirm('Discard unsaved human notes for the current finding?')){$('editorFinding').value=current;return;}
  }
  show($('editorFinding').value);
 }catch(err){msg(err.message,true);}
});
$('editorSave').addEventListener('click',()=>{try{save();}catch(err){msg(err.message,true);}});
$('editorExport').addEventListener('click',exportDraft);
$('editorBulkApply').addEventListener('click',bulk);
window.addEventListener('beforeunload',event=>{
 if(unsaved){event.preventDefault();event.returnValue='';}
});
window.LightUpEvidenceEditor=Object.freeze({mount,forget,select:show,snapshot});
})();