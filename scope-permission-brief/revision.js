/* LightUp: privacy-minimal source revision reissue board.
   This board compares ONLY safe metadata and byte fingerprints. NOT scope equality. */
(() => {
'use strict';
const $=id=>document.getElementById(id);
const runtime=window.LightUpBriefRuntime;
const LIMIT=12, FIELDS=[
 ['requested_mode','Mode'],
 ['requested_risk','Risk'],
 ['proposed_assets_count','Proposed asset count'],
 ['excluded_assets_count','Exclusion count'],
 ['window_status','Window status']
];
let history=[], counter=0, active=null;
const ATTENTION_LABELS=Object.freeze({
 literal_scope_entries_added:'Additional literal asset entries proposed — check exact coverage and ownership',
 literal_exclusions_removed:'Previously excluded literal entries removed — review effective access',
 requested_risk_raised:'Requested risk level increased — independent escalation',
 requested_active_assessment_mode:'Mode changed to authorized assessment proposal — never direct execution',
 private_lab_activity_proposed:'New private-lab network activity requested — independently validate lab provenance',
 planning_window_changed:'Proposed time or offset changed — agree new UTC window and STOP',
 scope_restriction_review:'Potential literal narrowing — confirm exact scope and exclusion handling',
 safety_notes_changed:'Private safety instructions changed — re-read source in authorized channel'
});
function digest(v){return typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);}
function record(from,to,impact){
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
  literal_change_impact:impact||null,
  human_review_level:impact?.human_review_level||'REVIEW_REQUIRED',
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
/* A reissue template is a NEW, unanswered, role-labelled coordination note.
   Never copy stale statuses from the prior scope. */
function reissue(role){
 const current=runtime?.snapshot();
 if(!current)return;
 const fresh={
  ...current,
  audience:role,
  question_states:current.question_states.map(q=>({code:q.code,role:q.role,status:'unanswered'})),
  outstanding_questions:current.question_states.length,
  flags:Object.fromEntries(Object.keys(current.flags).map(key=>[key,false]))
 };
 download('lightup-'+role+'-fresh-preparation-HOLD.json','application/json',JSON.stringify(fresh,null,2)+'\\n');
}

/* Script-free standalone document for handover; only bounded counts and fixed
   review guidance. Never render client identities, host literals or notes. */
function escapeHTML(value){
 return String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function impactPack(item){
 const e=escapeHTML,impact=item.literal_change_impact;
 const summary=impact?
  '<section><h2>Literal proposed asset identity changes</h2><p>Proposed assets: +'+e(impact.proposed_assets.added)+
   ' / −'+e(impact.proposed_assets.removed)+'; exclusions: +'+e(impact.exclusions.added)+
   ' / −'+e(impact.exclusions.removed)+'.</p><p>Human attention: '+
   e(impact.human_review_level.replaceAll('_',' '))+'</p></section>':
  '<section><h2>Source review needed</h2><p>Detailed literal differences unavailable. No equivalence is asserted.</p></section>';
 const attention=impact?.attention_codes.length?
  '<ol>'+impact.attention_codes.map(code=>'<li>'+e(ATTENTION_LABELS[code]||'Review revised source')+'</li>').join('')+'</ol>':
  '<p>There is still a byte-level revision; both roles must review the exact new source.</p>';
 const adjustments=item.summaries_changed.length?
  '<ul>'+item.summaries_changed.map(a=>'<li>'+e(a.description)+': '+e(a.previous)+
   ' → '+e(a.current)+'</li>').join('')+'</ul>':
  '<p>Summary fields unchanged; individual literals or private notes may still differ.</p>';
 return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
  '<meta name="viewport" content="width=device-width,initial-scale=1">'+
  '<meta name="referrer" content="no-referrer">'+
  '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; object-src &#39;none&#39;; form-action &#39;none&#39;">'+
  '<title>LightUp source revision · HOLD</title>'+
  '<style>body{font:16px/1.5 system-ui,sans-serif;color:#142536;max-width:890px;margin:auto;padding:24px}h1{font-size:30px}h2{font-size:20px;border-bottom:1px solid #ccd5df}section{margin-top:24px;break-inside:avoid}li{margin:8px 0}.hold{border:2px solid #a44730;background:#fff6ed;padding:16px}.meta{font:12px/1.6 ui-monospace,monospace;overflow-wrap:anywhere}footer{border-top:1px solid #ccc;margin-top:30px;font-size:12px}@media print{body{padding:4px}section{break-inside:auto}}</style></head><body>'+
  '<p>LIGHTUP / PRIVACY-MINIMAL OFFLINE HUMAN HANDOFF</p><h1>Revised scope · REVIEW ONLY / HOLD</h1>'+
  '<div class="hold"><strong>Both parties must start fresh.</strong> Client and operator must independently review the NEW exact source, restore genuine identity and authorization gates and issue new authenticated decisions in the protected system. This document never approves, consents, issues a grant or permits an assessment.</div>'+
  '<p class="meta">Previous SHA-256: '+e(item.previous_source_sha256)+'<br>Current SHA-256: '+e(item.current_source_sha256)+'</p>'+
  summary+'<section><h2>Category differences</h2>'+adjustments+'</section>'+
  '<section><h2>Human follow-up queue</h2>'+attention+'</section>'+
  '<section><h2>Required recipient handoff</h2><ol><li>Client: reopen full revised proposal and independently re-confirm owned assets, exclusions and intended limits in authenticated workflow.</li><li>Operator: review exact effective scope, permissions, risk, UTC window and revocation independently.</li><li>Reject all prior-version human replies as current authorization evidence.</li></ol></section>'+
  '<footer>No raw targets, contacts, client identities, notes or per-asset hashes. Literal string comparison does NOT establish equivalent CIDR coverage, DNS identity, owned scope or effective policy. All consent, authorization, grant, scan, deploy and release claims are FALSE.</footer></body></html>';
}

function toCSV(){
 const rows=[['sequence','previous_source_sha256','current_source_sha256','summary_changed_categories','literal_assets_added','literal_assets_removed','literal_exclusions_added','literal_exclusions_removed','human_review_level','attention_codes','review_disposition','reissue_client','reissue_operator']];
 for(const h of history)rows.push([h.sequence,h.previous_source_sha256,h.current_source_sha256,
  h.summaries_changed.map(x=>x.field).join(';'),
  h.literal_change_impact?.proposed_assets.added??'unknown',
  h.literal_change_impact?.proposed_assets.removed??'unknown',
  h.literal_change_impact?.exclusions.added??'unknown',
  h.literal_change_impact?.exclusions.removed??'unknown',
  h.human_review_level,h.literal_change_impact?.attention_codes.join(';')||'',h.disposition,'yes','yes']);
 return rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
function render(){
 const root=$('revisionHistory');root.replaceChildren();
 $('revisionJSON').disabled=history.length===0;
 $('revisionCSV').disabled=history.length===0;
 $('revisionPack').disabled=history.length===0;
 $('revisionForget').disabled=history.length===0;
 $('revisionClient').disabled=!active;
 $('revisionOperator').disabled=!active;
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
  const impact=item.literal_change_impact;
  if(impact){
   const summary=document.createElement('p');
   summary.textContent='Literal proposed asset entries: +'+impact.proposed_assets.added+' / -'+impact.proposed_assets.removed+
    '; exclusions: +'+impact.exclusions.added+' / -'+impact.exclusions.removed+
    '. '+impact.human_review_level.replaceAll('_',' ')+'.';
   section.append(summary);
   if(impact.attention_codes.length){
    const list=document.createElement('ul');
    for(const code of impact.attention_codes){
     const li=document.createElement('li');li.textContent=ATTENTION_LABELS[code]||'Review source change';list.append(li);
    }
    section.append(list);
   }else{
    const note=document.createElement('p');
    note.textContent='No elevated literal-delta category; bytes still changed, and the new exact source requires fresh review.';
    section.append(note);
   }
   const caveat=document.createElement('p');
   caveat.textContent='Only exact case-insensitive literal strings were counted. Equivalent CIDR coverages, hostname aliases, ownership and effective grants have NOT been compared.';
   section.append(caveat);
  }
  const warn=document.createElement('strong');warn.textContent='Both roles must review the new source and issue fresh UNVERIFIED preparation replies. No prior answers, consent, approval or grant can be transferred.';
  section.append(warn);
  root.append(section);
 }
}
document.addEventListener('lightup:brief-revision',event=>{
 const detail=event.detail;
 if(!detail||!detail.after)return;
 active={source_sha256:detail.after.source_sha256};
 const item=record(detail.before,detail.after,detail.impact);
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
$('revisionPack').addEventListener('click',()=>{
 const last=history.at(-1);
 if(last)download('lightup-scope-change-impact-HOLD.html','text/html;charset=utf-8',impactPack(last));
});
$('revisionClient').addEventListener('click',()=>reissue('client'));
$('revisionOperator').addEventListener('click',()=>reissue('operator'));
$('revisionForget').addEventListener('click',()=>{history=[];counter=0;render();});
render();
})();