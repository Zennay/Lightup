/* Local source refresh planning; prepares unsigned private Evidence Review v2, never mutates real findings. */
(()=>{'use strict';
const $=id=>document.getElementById(id);
const C=window.LightUpCasework, editor=window.LightUpEvidenceEditor, bridge=window.LightUpRemediationSource;
const CAP_CSV=1048576,CAP_DRAFT=2097152;
let pending=null;
function fail(msg){throw Error(msg);}
function status(msg,bad=false){$('refreshStatus').textContent=msg;$('refreshStatus').dataset.error=bad?'true':'false';}
function assertSame(){if(!$('refreshSame').checked)fail('Independently confirm the exact SAME client and engagement for both ORIGINAL, separately authorized exports.');}
function clear(){pending=null;$('refreshApply').disabled=true;$('refreshSummary').textContent='No source refresh has been previewed.'; }
async function read(file){
 if(!file||file.size<1||file.size>CAP_CSV)fail('Select a bounded, separately authorized original findings CSV (max 1 MiB).');
 const raw=await file.arrayBuffer();
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
 if(!text||text.charCodeAt(0)===0xfeff)fail('Empty or BOM-prefixed original source denied.');
 return text;
}
function newHuman(id){
 return {finding_id:id,stage:'missing',reference:'',reviewer:'',next_step:'',
  evidence:{change_reference:'',deployment_reference:'',rollback_reference:'',retest_request_reference:'',review_question:''}};
}
async function preview(){
 clear();
 assertSame();
 const origin=bridge.current();
 if(!origin||typeof origin.csv!=='string'||!origin.hash)fail('Load an original LightUp source into the central Cockpit first.');
 if(editor.hasFormChanges())fail('Save or discard visible human form edits before preparing a source refresh.');
 const file=$('refreshFile').files[0];
 const text=await read(file),next=C.parseCSV(text);
 const digest=await bridge.sha(next);
 if(!/^[0-9a-f]{64}$/.test(digest)||digest===origin.hash)
  fail('The newer original source must have a different valid canonical source fingerprint.');
 const previous=C.parseCSV(origin.csv),diff=C.compareSource(previous,next);
 // The current human draft can be saved separately; never re-interpret it as a source verdict.
 const old=editor.snapshot();
 if(old.source_sha256!==origin.hash||old.review.length!==previous.length)
  fail('Existing human notes no longer match the original source; HOLD.');
 const oldById=new Map(old.review.map(r=>[r.finding_id,r]));
 const exact=new Set(diff.unchanged);
 const review=next.map(f=>exact.has(f.finding_id)?oldById.get(f.finding_id):newHuman(f.finding_id));
 if(review.some(v=>!v))fail('Missing exact-unchanged review record: HOLD.');
 // Native Evidence Review accepts a single valid source transition and recognizes absence as unverified.
 const revision={from_sha256:origin.hash,to_sha256:digest,
  added:diff.added,missing:diff.missing,unchanged:diff.unchanged,changed:diff.changed};
 const packet={...old,source_sha256:digest,review,revision_register:[revision],
  warning:'Unsigned PRIVATE human source-refresh draft. Only exact unchanged original findings retain local notes. New and changed records reset. Absent is not fixed. This is not evidence of consent, auth, repair or approved retest.'};
 const payload=JSON.stringify(packet,null,2)+'\n';
 if(new TextEncoder().encode(payload).byteLength>CAP_DRAFT)fail('Updated private handoff would exceed original Evidence Review intake size.');
 pending={file,oldHash:origin.hash,newHash:digest,payload,diff};
 $('refreshSummary').textContent='Preview: '+diff.added.length+' newly listed, '+diff.changed.length+
  ' changed originals (human notes RESET), '+diff.unchanged.length+' exact unchanged (human notes PRESERVED), '+
  diff.missing.length+' ABSENT/UNVERIFIED (not fixed). Private source hash '+digest+
  '. Both source documents must be independently authenticated for the exact same engagement.';
 $('refreshApply').disabled=false;
 status('Source refresh prepared. The active Cockpit and original source have NOT changed. Export a fresh private draft, then load that draft with the newer original CSV.');
}
function exportPrivate(){
 try{
  if(!pending)fail('Preview the separately authorized new original CSV first.');
  assertSame();
  if($('refreshFile').files[0]!==pending.file)fail('Selected source changed since preview.');
  const current=bridge.current();
  if(!current||current.hash!==pending.oldHash)fail('Active source changed since preview: repeat preparation.');
  if(editor.hasFormChanges()||editor.hasUnsaved())
   if(!confirm('Your current page has unsigned local human changes. Export the ORIGINAL private human review draft separately before replacing your source elsewhere. Continue with a fresh-source handoff?'))return;
  if(!confirm('Export PRIVATE NEW-SOURCE review JSON? New/changed original findings RESET, only exactly unchanged retain HUMAN notes; ABSENT findings are NOT fixed. You must load the new ORIGINAL CSV and this draft together.'))return;
  const url=URL.createObjectURL(new Blob([pending.payload],{type:'application/json;charset=utf-8'}));
  const a=document.createElement('a');a.href=url;a.download='lightup-evidence-refresh-PRIVATE.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
  status('Private refreshed Evidence Review v2 handoff downloaded. Active source unchanged. Independently import the NEW original CSV first, then this PRIVATE draft.');
 }catch(err){status(err.message,true);}
}
$('refreshFile').addEventListener('change',clear);
$('refreshSame').addEventListener('change',()=>{if(!$('refreshSame').checked)clear();});
$('refreshPreview').addEventListener('click',()=>preview().catch(err=>{clear();status(err.message,true);}));
$('refreshApply').addEventListener('click',exportPrivate);
window.LightUpSourceRefresh=Object.freeze({clear});
})();