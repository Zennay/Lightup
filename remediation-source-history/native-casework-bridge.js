/* Original PRIVATE Casework v1 import; strictly local, non-authorizing. */
(()=>{
'use strict';
const $=id=>document.getElementById(id),H=window.LightUpHistory;
const MAX=2097152;
function status(message,fail=false){$('message').textContent=message;$('message').className=fail?'error':'info';}
/* Bounded JSON grammar parser that rejects duplicate keys at every depth, including escaped aliases. */
function uniqueJSON(raw){
 if(typeof raw!=='string'||raw.length>MAX||!raw.length)throw Error('Unsupported PRIVATE original Casework JSON size.');
 let i=0,nodes=0;
 const ws=()=>{while(i<raw.length&&/[\x20\t\r\n]/.test(raw[i]))i++;};
 function str(){
  if(raw[i]!=='"')throw Error('Expected canonical JSON string.');
  const start=i++;let ended=false;
  while(i<raw.length){
   const c=raw[i++];
   if(c==='"'){ended=true;break;}
   if(c==='\\'){if(i>=raw.length)break;i++;}
  }
  if(!ended)throw Error('Unclosed JSON string.');
  return JSON.parse(raw.slice(start,i));
 }
 function value(depth){
  if(++nodes>100000||depth>20)throw Error('PRIVATE Casework nesting/structure exceeds accepted limits.');
  ws();const ch=raw[i];
  if(ch==='{'){
   i++;ws();const obj=Object.create(null),seen=new Set();
   if(raw[i]==='}'){i++;return obj;}
   while(true){
    ws();const key=str();if(seen.has(key))throw Error('Duplicate JSON object key: original Casework HOLD.');seen.add(key);
    ws();if(raw[i++]!==':')throw Error('Expected JSON property separator.');
    obj[key]=value(depth+1);ws();
    if(raw[i]==='}'){i++;break;}
    if(raw[i++]!==',')throw Error('Expected JSON object separator.');
   }return obj;
  }
  if(ch==='['){
   i++;ws();const a=[];if(raw[i]===']'){i++;return a;}
   while(true){a.push(value(depth+1));ws();if(raw[i]===']'){i++;break;}if(raw[i++]!==',')throw Error('Expected JSON list separator.');}
   return a;
  }
  if(ch==='"')return str();
  const start=i;
  while(i<raw.length&&!/[\s,\]}]/.test(raw[i]))i++;
  const t=raw.slice(start,i);
  if(!/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+\-]?\d+)?)$/.test(t))throw Error('Unsupported JSON literal.');
  return JSON.parse(t);
 }
 const result=value(0);ws();if(i!==raw.length)throw Error('Trailing or malformed JSON content.');
 return result;
}
async function load(){
 const file=$('nativeCaseworkFile').files[0];
 if(!file||file.size===0||file.size>MAX)throw Error('Select original PRIVATE Casework v1 JSON of 2 MiB or less.');
 if(!H.view().length)throw Error('Import the exact original source CSV first.');
 H.privateAllowed();
 const revision=H.revision();
 const raw=await file.text(),packet=uniqueJSON(raw);
 if(H.revision()!==revision)throw Error('Original source or HUMAN notes changed while loading; no mutation.');
 const needsOverwrite=H.noteSummary();
 const allow=$('replaceHumanNotes').checked;
 if((needsOverwrite.bound+needsOverwrite.held)>0){
  if(!allow)throw Error('Existing notes stay unchanged. Acknowledge replacement of all existing private HUMAN notes to import original Casework.');
  if(!window.confirm('PRIVATE HUMAN DATA: Replace all current in-memory HUMAN notes with original source-matched Casework v1 notes? Export an encrypted checkpoint first to preserve old notes. No security permission or verdict is granted.'))return;
 }
 const outcome=H.importCasework(packet,revision,allow);
 status('Imported '+outcome.imported+' HUMAN Casework records for exact current original source ('+outcome.original+' findings). Original Casework statuses and blockers are unverified human statements; no scan/retest/authorization.');
 $('nativeCaseworkFile').value='';$('replaceHumanNotes').checked=false;
}
/* Selective, original-source-bound HUMAN collaboration: preview first; no implicit overwrite. */
let staged=null,stagedRevision=-1,checked=new Set(),fieldChoices=new Map();
const safe=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const FIELDS=['owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
function resetStage(){
 staged=null;stagedRevision=-1;checked.clear();fieldChoices.clear();
 $('mergeReview').hidden=true;$('mergeHumanAck').checked=false;$('mergeReason').value='';
 $('mergeSource').textContent='No original source-bound Casework review staged.';
 $('mergeRows').innerHTML='';$('mergeFields').textContent='';
 $('mergeAccept').disabled=true;
}
function viewReview(){
 const review=staged&&H.reviewCasework(staged,stagedRevision);
 if(!review){resetStage();return;}
 $('mergeReview').hidden=false;
 const totals=Object.fromEntries(['NEW_HUMAN_NOTES','REVIEW_CONFLICT','IDENTICAL_HUMAN_NOTES','INCOMING_EMPTY','HOLD_SOURCE_CHANGED'].map(k=>[k,review.rows.filter(x=>x.classification===k).length]));
 $('mergeSource').textContent='Exact original canonical SHA256: '+review.sourceHash.slice(0,18)+'… · '+review.rows.length+
  ' original source rows · '+totals.NEW_HUMAN_NOTES+' NEW HUMAN · '+totals.REVIEW_CONFLICT+' human conflicts · '+
  totals.HOLD_SOURCE_CHANGED+' HOLD · '+totals.INCOMING_EMPTY+' blank incoming · '+totals.IDENTICAL_HUMAN_NOTES+' unchanged';
 $('mergeRows').innerHTML=review.rows.map(row=>{
  const allowed=['NEW_HUMAN_NOTES','REVIEW_CONFLICT'].includes(row.classification);
  return '<tr><td><label class="check"><input type="checkbox" data-merge-id="'+safe(row.id)+'" '+(checked.has(row.id)?'checked ':'')+
   (allowed?'':'disabled ')+'aria-label="Import HUMAN notes from original Casework for finding '+safe(row.id)+'"></label>'+
   '<button type="button" class="link" data-inspect-id="'+safe(row.id)+'">'+safe(row.id)+'</button><small>'+safe(row.title.slice(0,110))+'</small></td>'+
   '<td>'+safe(row.classification.replaceAll('_',' '))+'</td>'+
   '<td>'+safe(row.changedFields.join(', ')||'None')+'</td>'+
   '<td>'+safe((row.incoming.owner||'unassigned').slice(0,110))+'<small>'+safe(row.incoming.status)+'</small></td>'+
   '<td>'+safe((row.current.owner||'unassigned').slice(0,110))+'<small>'+safe(row.current.status)+'</small></td></tr>';
 }).join('');
 $('mergeCount').textContent=checked.size+' original HUMAN records explicitly selected to import; all other existing notes retained.';
 $('mergeAccept').disabled=!checked.size;
 return review;
}
function showFields(id){
 const row=viewReview()?.rows.find(r=>r.id===id);
 if(!row)throw Error('No current original review row found.');
 $('mergeFields').innerHTML='<h3>PRIVATE exact HUMAN Casework fields · '+safe(id)+'</h3><p>Source classification: '+safe(row.classification)+'; only HUMAN metadata is compared, never proof of remediation.</p>'+
 '<div class="revisions"><article class="snapshot"><h4>Incoming original HUMAN draft</h4>'+
  FIELDS.map(k=>'<p><b>'+safe(k)+':</b> '+safe(row.incoming[k]??'')+'</p>').join('')+'</article>'+
  '<article class="snapshot"><h4>Existing local HUMAN draft</h4>'+
  FIELDS.map(k=>'<p><b>'+safe(k)+':</b> '+safe(row.current[k]??'')+'</p>').join('')+'</article></div>'+ 
 (checked.has(id)?'<h4>Choose exactly which incoming HUMAN fields to import; other fields stay local</h4>'+ 
  row.changedFields.map(k=>'<label class="check"><input type="checkbox" data-field-id="'+safe(id)+'" data-field-key="'+safe(k)+'" '+((fieldChoices.get(id)||new Set()).has(k)?'checked':'')+'> Import incoming HUMAN '+safe(k)+'</label>').join(''):
  '<p>Select this original finding above to choose incoming HUMAN fields.</p>');
}
async function stageReview(){
 const file=$('nativeCaseworkFile').files[0];
 if(!file||!file.size||file.size>MAX)throw Error('Select PRIVATE original native Casework v1 JSON of 2 MiB or less.');
 H.privateAllowed();
 resetStage();
 const revision=H.revision();
 const packet=uniqueJSON(await file.text());
 const review=H.reviewCasework(packet,revision);
 if(H.revision()!==revision)throw Error('Original source or HUMAN notes changed while opening PRIVATE merge review.');
 staged=packet;stagedRevision=revision;
 viewReview();
 status('Original Casework preview opened locally. No notes changed; select exact incoming HUMAN rows and review conflicts before import.');
 return review;
}
function selectNew(){
 if(!staged)throw Error('Preview original Casework before selecting newly imported HUMAN notes.');
 const review=H.reviewCasework(staged,stagedRevision);
 checked=new Set(review.rows.filter(r=>r.classification==='NEW_HUMAN_NOTES').map(r=>r.id));
 fieldChoices=new Map(review.rows.filter(r=>checked.has(r.id)).map(r=>[r.id,new Set(r.changedFields)]));
 viewReview();
}
function applyReview(){
 if(!staged||stagedRevision!==H.revision())throw Error('Original source or HUMAN notes changed. Re-preview incoming native Casework before import.');
 H.privateAllowed();
 if(!checked.size)throw Error('Select at least one exact original incoming HUMAN row.');
 if(!$('mergeHumanAck').checked)throw Error('Acknowledge that replacing chosen HUMAN notes is a local private planning action, not a security decision.');
 const review=H.reviewCasework(staged,stagedRevision);
 const selected=review.rows.filter(r=>checked.has(r.id));
 if(selected.length!==checked.size||selected.some(r=>!['NEW_HUMAN_NOTES','REVIEW_CONFLICT'].includes(r.classification)))
  throw Error('Invalid or source-HOLD selection; no HUMAN notes were changed.');
 const overwrite=selected.filter(r=>r.classification==='REVIEW_CONFLICT').length;
 if(!window.confirm('Import '+selected.length+' exact-source HUMAN notes, replacing '+overwrite+
   ' existing conflicting HUMAN notes? All other local notes and original findings remain unchanged. Save encrypted PRIVATE backup before merging. No grants/retests/fixes are confirmed.'))return;
 const decisions=[...checked].map(id=>({id,fields:[...(fieldChoices.get(id)||new Set())]}));
 if(decisions.some(d=>!d.fields.length))throw Error('Choose at least one changed incoming HUMAN field for every selected original record.');
 const result=H.mergeCasework(staged,stagedRevision,decisions,$('mergeReason').value);
 resetStage();
 $('nativeCaseworkFile').value='';
 status('Reconciled '+result.fieldsMerged+' selected HUMAN fields on '+result.accepted+' exact-source records, retained '+result.retained+
  ' other original source rows. Save encrypted PRIVATE checkpoint/native Casework export to preserve local changes.');
}
$('nativePreview').addEventListener('click',()=>stageReview().catch(e=>status(e.message,true)));
$('mergeSelectNew').addEventListener('click',()=>{try{selectNew();}catch(e){status(e.message,true);}});
$('mergeClear').addEventListener('click',()=>{checked.clear();fieldChoices.clear();if(staged)viewReview();});
$('mergeRows').addEventListener('click',event=>{
 const b=event.target.closest('button[data-inspect-id]');
 if(b)try{showFields(b.dataset.inspectId);}catch(e){status(e.message,true);}
});
$('mergeRows').addEventListener('change',event=>{
 const b=event.target.closest('input[data-merge-id]');if(!b)return;
 if(b.checked){checked.add(b.dataset.mergeId);const row=H.reviewCasework(staged,stagedRevision).rows.find(r=>r.id===b.dataset.mergeId);fieldChoices.set(b.dataset.mergeId,new Set(row?.changedFields||[]));}
 else{checked.delete(b.dataset.mergeId);fieldChoices.delete(b.dataset.mergeId);}
 try{viewReview();}catch(e){status(e.message,true);resetStage();}
});
$('mergeFields').addEventListener('change',event=>{
 const box=event.target.closest('input[data-field-id]');
 if(!box||!staged||!checked.has(box.dataset.fieldId))return;
 const fields=fieldChoices.get(box.dataset.fieldId)||new Set();
 if(box.checked)fields.add(box.dataset.fieldKey);else fields.delete(box.dataset.fieldKey);
 fieldChoices.set(box.dataset.fieldId,fields);
 $('mergeCount').textContent=checked.size+' original HUMAN records, '+[...fieldChoices.values()].reduce((n,set)=>n+set.size,0)+' selected incoming HUMAN fields.';
});
$('mergeAccept').addEventListener('click',()=>{try{applyReview();}catch(e){status(e.message,true);}});
$('nativeCaseworkFile').addEventListener('change',resetStage);
window.addEventListener('lightup-history-changed',()=>{
 if(staged&&stagedRevision!==H.revision())resetStage();
});

$('mergeHistoryExport').addEventListener('click',()=>{try{H.exportMergeHistory();}catch(e){status(e.message,true);}});
$('nativeImport').addEventListener('click',()=>load().catch(e=>status(e.message,true)));
})();
