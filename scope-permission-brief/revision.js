/* LightUp: privacy-minimal source revision reissue board.
   This board compares ONLY safe metadata and byte fingerprints. NOT scope equality. */
(() => {
'use strict';
const $=id=>document.getElementById(id);
const LIMIT=12, FIELDS=[
 ['requested_mode','Mode'],
 ['requested_risk','Risk'],
 ['proposed_assets_count','Proposed asset count'],
 ['excluded_assets_count','Exclusion count'],
 ['window_status','Window status']
];
let history=[], counter=0, active=null;
function digest(v){return typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);}
function record(from,to){
 if(!from||!to||!digest(from.source_sha256)||!digest(to.source_sha256))return null;
 if(from.source_sha256===to.source_sha256)return null;
 if(!Object.values(from.flags||{}).every(v=>v===false)||!Object.values(to.flags||{}).every(v=>v===false))return null;
 const changed=FIELDS.filter(([key])=>from[key]!==to[key]).map(([key,title])=>({
  field:key,description:title,
  previous:String(from[key]),current:String(to[key])
 }));
 return {
  sequence:++counter,
  previous_source_sha256:from.source_sha256,
  current_source_sha256:to.source_sha256,
  source_bytes_changed:true,
  semantic_asset_comparison_performed:false,
  asset_identity_equivalence_unknown:true,
  previous_human_notes_invalidated:true,
  previously_returned_review_notes_invalidated:true,
  client_reply_required_again:true,operator_reply_required_again:true,
  summaries_changed:changed,
  all_current_permissions_false:true,
  disposition:'REVIEW_ONLY_HOLD'
 };
}
function buildModel(){
 return {
  kind:'lightup.scope_review_revision_reissue',
  schema_version:1,
  disposition:'REVIEW_ONLY_HOLD',
  history:history.map(x=>structuredClone(x)),
  current_source_sha256:active?.source_sha256||null,
  flags:{authorization:false,client_consent:false,operator_consent:false,
   grant:false,revocation_checked:false,execution:false,scan:false,deploy:false,release:false},
  notice:'Raw scope identities are not compared; even equal counts cannot establish unchanged membership. Reissue all preparation replies for new source bytes. No permission follows a revision.'
 };
}
function download(name,mime,body){
 const url=URL.createObjectURL(new Blob([body],{type:mime})),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function csvCell(v){
 let s=String(v);if(/^[=+\-@\t\r\n]/.test(s))s="'"+s;
 return '"'+s.replaceAll('"','""')+'"';
}
function toCSV(){
 const rows=[['sequence','previous_source_sha256','current_source_sha256','summary_changed_categories','review_disposition','reissue_client','reissue_operator']];
 for(const h of history)rows.push([h.sequence,h.previous_source_sha256,h.current_source_sha256,
  h.summaries_changed.map(x=>x.field).join(';'),h.disposition,'yes','yes']);
 return rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
function render(){
 const root=$('revisionHistory');root.replaceChildren();
 $('revisionJSON').disabled=history.length===0;
 $('revisionCSV').disabled=history.length===0;
 $('revisionForget').disabled=history.length===0;
 if(!active){
  $('revisionStatus').textContent=history.length?
   'Earlier source fingerprints remain only in this local tab; no current draft loaded · HOLD':
   'Load a Studio-v1 source to begin. Import another revision to see changes.';
 }else{
  $('revisionStatus').textContent=history.length?
   history.length+' source-byte revision(s) in volatile local history · ALL PREVIOUS REPLIES REQUIRE REISSUE · HOLD':
   'Current source SHA-256: '+active.source_sha256+' · No prior revision compared · HOLD';
 }
 for(const item of [...history].reverse()){
  const section=document.createElement('section');section.className='revision-entry';
  const title=document.createElement('h3');title.textContent='Revision '+item.sequence+' · SOURCE BYTES CHANGED';
  const p=document.createElement('p');p.textContent='Before SHA-256 '+item.previous_source_sha256+' → After SHA-256 '+item.current_source_sha256;
  section.append(title,p);
  const m=document.createElement('p');
  m.textContent=item.summaries_changed.length?
   'Changed summary categories: '+item.summaries_changed.map(c=>c.description).join(', '):
   'All shown counts/mode/risk/window match, BUT exact scope or notes may still differ. No semantic equality is asserted.';
  section.append(m);
  const warn=document.createElement('strong');warn.textContent='Both roles must review the new source and issue fresh UNVERIFIED preparation replies. No prior answers, consent, approval or grant can be transferred.';
  section.append(warn);
  root.append(section);
 }
}
document.addEventListener('lightup:brief-revision',event=>{
 const detail=event.detail;
 if(!detail||!detail.after)return;
 active={source_sha256:detail.after.source_sha256};
 const item=record(detail.before,detail.after);
 if(item){
  history.push(item);
  if(history.length>LIMIT)history.shift();
 }
 render();
});
document.addEventListener('lightup:brief-source-change',()=>{
 active=null;
 // A new import may follow. Keep only non-sensitive historical fingerprints in this tab.
 render();
});
document.addEventListener('lightup:brief-forget',()=>{
 history=[];active=null;counter=0;render();
});
$('revisionJSON').addEventListener('click',()=>{
 if(history.length)download('lightup-source-revision-reissue-HOLD.json','application/json',JSON.stringify(buildModel(),null,2)+'\n');
});
$('revisionCSV').addEventListener('click',()=>{
 if(history.length)download('lightup-source-revision-timeline-HOLD.csv','text/csv;charset=utf-8',toCSV());
});
$('revisionForget').addEventListener('click',()=>{history=[];counter=0;render();});
render();
})();