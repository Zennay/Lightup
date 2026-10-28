
(function(){'use strict';
const $=id=>document.getElementById(id);
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const HK=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','recipient_alias','rows','warning',...FLAGS];
const RK=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','recipient_alias','handoff_rows','responses','warning',...FLAGS];
const SK=['step_id','kind','description','precondition','responsible_alias','rollback_discussion','verification_question','tentative_date','human_stage'];
const KINDS=['human_prepare','human_implementation_discussion','human_dependency_coordination','human_rollback_discussion','human_review_request'];
const STAGES=['draft_human','needs_human_input','await_human_review','human_handoff_prepared'];
const ACK=['not_responded_human','received_human','clarification_needed_human','discussion_prepared_human'];
const LIMIT=8388608;let current=null,edited=0,saved=0,review=null;
const fail=s=>{throw Error('HOLD: '+s);};
function exact(x,keys){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype&&Object.keys(x).length===keys.length&&Object.keys(x).every(k=>keys.includes(k));}
function str(v,max,label,required=false){if(typeof v!=='string'||v.length>max||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/.test(v)||(required&&!v.trim()))fail('noncanonical '+label);return v;}
function date(v){if(v==='')return v;if(typeof v!=='string'||! /^\d{4}-\d\d-\d\d$/.test(v)||!Number.isFinite(Date.parse(v+'T00:00:00Z'))||new Date(v+'T00:00:00Z').toISOString().slice(0,10)!==v)fail('tentative human date');return v;}
function msg(s,bad=false){$('notice').textContent=s;$('notice').dataset.error=String(bad);}
function element(tag,value){const x=document.createElement(tag);x.textContent=String(value);return x;}
function strictJson(text){
 if(!text||text.length>LIMIT)fail('JSON too large/empty');
 let i=0;
 function ws(){while(i<text.length&&/\s/.test(text[i]))i++;}
 function quoted(){let b=i;if(text[i++]!=='"')fail('JSON member string expected');let escaped=false;
  while(i<text.length){let c=text[i++];if(c==='"'&&!escaped)return JSON.parse(text.slice(b,i));
   if(c==='\\'&&!escaped){escaped=true;continue;}if(c.charCodeAt(0)<32&&!escaped)fail('JSON control byte');escaped=false;}
  fail('unterminated JSON member');
 }
 function val(depth){if(depth>15)fail('oversized JSON depth');ws();let c=text[i];
  if(c==='{'){i++;ws();let keys=new Set();if(text[i]==='}'){i++;return;}while(true){
   ws();let k=quoted();if(keys.has(k))fail('duplicate JSON key');keys.add(k);ws();if(text[i++]!==':')fail('JSON separator');val(depth+1);ws();
   if(text[i]==='}'){i++;return;}if(text[i++]!==',')fail('JSON object delimiter');
  }}
  if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){val(depth+1);ws();if(text[i]===']'){i++;return;}if(text[i++]!==',')fail('JSON list delimiter');}}
  if(c==='"'){quoted();return;}
  let m=/^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));if(!m)fail('invalid JSON literal');i+=m[0].length;
 }
 try{val(0);ws();if(i!==text.length)fail('JSON trailing data');return JSON.parse(text);}
 catch(e){if(String(e?.message||'').startsWith('HOLD:'))throw e;fail('invalid PRIVATE JSON syntax (source data hidden)');}
}
async function read(f){if(!f||f.size<1||f.size>LIMIT)fail('choose PRIVATE JSON 1 byte–8 MiB');let t;
 try{t=new TextDecoder('utf-8',{fatal:true}).decode(await f.arrayBuffer());}
 catch(_){fail('malformed UTF-8 in PRIVATE JSON (source data hidden)');}
 return strictJson(t);
}
function verifyStep(s,alias){
 if(!exact(s,SK)||!Number.isInteger(s.step_id)||s.step_id<1||s.step_id>8||!KINDS.includes(s.kind)||!STAGES.includes(s.human_stage))fail('noncanonical original HUMAN step');
 if(str(s.responsible_alias,120,'human owner alias',true)!==alias)fail('foreign HUMAN owner step');
 str(s.description,1000,'human proposed action',true);str(s.precondition,600,'human prerequisite');
 str(s.rollback_discussion,750,'human rollback question');str(s.verification_question,600,'human review question');date(s.tentative_date);
}
function verifyRows(rows,alias){
 if(!Array.isArray(rows)||!rows.length||rows.length>350)fail('incomplete or oversized HUMAN recipient finding list');
 const ids=new Set();let total=0;
 for(const row of rows){
  if(!exact(row,['finding_id','steps']))fail('noncanonical HUMAN handoff row');
  let id=str(row.finding_id,200,'original finding ID',true);if(ids.has(id))fail('duplicate original finding');ids.add(id);
  if(!Array.isArray(row.steps)||!row.steps.length||row.steps.length>8)fail('empty/oversized human finding steps');
  let seen=new Set();for(const s of row.steps){verifyStep(s,alias);if(seen.has(s.step_id))fail('duplicate human step ID');seen.add(s.step_id);total++;}
 }
 if(total>1600)fail('too many proposed HUMAN steps');
}
function admitHandoff(p){
 if(!exact(p,HK)||p.kind!=='lightup.private_human_owner_runbook_handoff'||p.schema_version!==1||
 p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||FLAGS.some(k=>p[k]!==false)||!Number.isInteger(p.source_count)||
 p.source_count<1||p.source_count>350)fail('not original owner-specific PRIVATE HUMAN handoff');
 str(p.source_contract,200,'original declared contract',true);
 if(typeof p.source_sha256!=='string'||! /^[0-9a-f]{64}$/.test(p.source_sha256))fail('original declared SHA256');
 str(p.client_reference,200,'original client',true);str(p.engagement_reference,200,'original engagement',true);
 str(p.warning,500,'original HUMAN warning',true);let a=str(p.recipient_alias,120,'PRIVATE owner alias',true);
 verifyRows(p.rows,a);if(p.rows.length>p.source_count)fail('owner packet exceeds original source finding count');
 return p;
}
function key(p){return JSON.stringify([p.source_contract,p.source_sha256,p.client_reference,p.engagement_reference,p.source_count,p.recipient_alias]);}
function stepKey(id,n){return JSON.stringify([id,n]);}
function empty(){return {human_ack:'not_responded_human',private_human_note:'',tentative_follow_up:''};}
function responses(){return current.original.rows.map(row=>({finding_id:row.finding_id,steps:row.steps.map(s=>Object.assign({step_id:s.step_id},current.edits.get(stepKey(row.finding_id,s.step_id))||empty()))}));}
function outgoing(){let o=current.original;return Object.assign({
 kind:'lightup.private_human_owner_runbook_return',schema_version:1,disposition:'UNVERIFIED_HUMAN_PLANNING_ONLY',
 source_contract:o.source_contract,source_sha256:o.source_sha256,client_reference:o.client_reference,engagement_reference:o.engagement_reference,
 source_count:o.source_count,recipient_alias:o.recipient_alias,
 handoff_rows:o.rows,responses:responses(),
 warning:'SELF-DECLARED PRIVATE HUMAN follow-up, NOT authentic original owner reply, approved remediation, grant, execution, retest, scope, consent or release.'
 },Object.fromEntries(FLAGS.map(k=>[k,false])));}
function admitReturn(r,o){
 if(!exact(r,RK)||r.kind!=='lightup.private_human_owner_runbook_return'||r.schema_version!==1||
 r.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||FLAGS.some(k=>r[k]!==false)||key(r)!==key(o))fail('received HUMAN response source/authority envelope mismatch');
 str(r.warning,500,'HUMAN return warning',true);
 verifyRows(r.handoff_rows,o.recipient_alias);
 // Bind to every exact original step and original text. No partial/missing answers.
 if(JSON.stringify(r.handoff_rows)!==JSON.stringify(o.rows))fail('received HUMAN return contains changed original steps');
 if(!Array.isArray(r.responses)||r.responses.length!==o.rows.length)fail('received HUMAN return omitted original finding');
 let all=new Map();
 for(let i=0;i<r.responses.length;i++){
  let res=r.responses[i],orig=o.rows[i];
  if(!exact(res,['finding_id','steps'])||res.finding_id!==orig.finding_id||
     !Array.isArray(res.steps)||res.steps.length!==orig.steps.length)fail('missing/foreign HUMAN response finding');
  for(let j=0;j<res.steps.length;j++){
   let x=res.steps[j],s=orig.steps[j];
   if(!exact(x,['step_id','human_ack','private_human_note','tentative_follow_up'])||x.step_id!==s.step_id||
     !ACK.includes(x.human_ack))fail('foreign/reordered HUMAN response step');
   str(x.private_human_note,800,'unverified human reply');date(x.tentative_follow_up);
   all.set(stepKey(orig.finding_id,s.step_id),Object.assign({},x));
  }
 }
 return all;
}
function dirty(){if(!current){$('dirty').textContent='No PRIVATE source loaded. Nothing stored.';return;}
 $('dirty').textContent=edited!==saved?'UNSAVED PRIVATE HUMAN responses · export a private backup before closing.':'PRIVATE HUMAN responses locally unchanged since last export.';}
function update(id,step,field,value){
 let k=stepKey(id,step.step_id),next=Object.assign({},current.edits.get(k)||empty(),{[field]:value});
 if(!ACK.includes(next.human_ack))fail('invalid human acknowledgement');
 str(next.private_human_note,800,'private human note');date(next.tentative_follow_up);
 current.edits.set(k,next);edited++;review=null;$('review').replaceChildren();$('compareSummary').textContent='Received HUMAN return preview invalidated by local editing.';render();dirty();
 msg('Local HUMAN response updated. No original planning, security status, grant or verified retest changed.');
}
function render(){
 if(!current)return;
 let q=$('search').value.toLowerCase().trim(),f=$('filter').value,output=$('steps');output.replaceChildren();
 let shown=0,total=0,replied=0;
 for(const row of current.original.rows){
  for(const s of row.steps){
   let id=row.finding_id,r=current.edits.get(stepKey(id,s.step_id))||empty();total++;if(r.human_ack!=='not_responded_human')replied++;
   if(q&&![id,s.description,s.kind,s.human_stage,s.precondition].join(' ').toLowerCase().includes(q))continue;
   if(f==='missing'&&r.human_ack!=='not_responded_human')continue;
   if(f==='responded'&&r.human_ack==='not_responded_human')continue;
   if(f==='clarify'&&r.human_ack!=='clarification_needed_human')continue;
   shown++;
   let card=document.createElement('article');card.className='card';card.append(element('h3','ORIGINAL '+id+' · HUMAN step '+s.step_id));
   card.append(element('strong','Proposed HUMAN work ('+s.kind+' · '+s.human_stage+')'));
   card.append(element('pre',s.description));
   let detail=document.createElement('details'),head=document.createElement('summary');head.textContent='Original HUMAN preconditions / rollback / questions';detail.append(head);
   for(const [label,text] of [['Self-declared recipient',s.responsible_alias],['Original HUMAN prerequisites',s.precondition],['Original rollback discussion',s.rollback_discussion],
    ['Original review question',s.verification_question],['Original tentative date',s.tentative_date||'unset']]){
    detail.append(element('strong',label));detail.append(element('pre',text));
   }card.append(detail);
   let grid=document.createElement('div');grid.className='grid';
   let ack=document.createElement('label');ack.textContent='Unverified HUMAN response stage';
   let sel=document.createElement('select');
   for(const x of ACK){let opt=document.createElement('option');opt.value=x;opt.textContent=x.replaceAll('_',' ');sel.append(opt);}
   sel.value=r.human_ack;sel.addEventListener('change',()=>{try{update(id,s,'human_ack',sel.value);}catch(e){msg(e.message,true);}});ack.append(sel);grid.append(ack);
   let due=document.createElement('label');due.textContent='Tentative HUMAN follow-up date';
   let dateEl=document.createElement('input');dateEl.type='date';dateEl.value=r.tentative_follow_up;dateEl.addEventListener('change',()=>{try{update(id,s,'tentative_follow_up',dateEl.value);}catch(e){msg(e.message,true);}});due.append(dateEl);grid.append(due);card.append(grid);
   let note=document.createElement('label');note.textContent='PRIVATE HUMAN clarification or question (not verified evidence)';
   let area=document.createElement('textarea');area.maxLength=800;area.value=r.private_human_note;
   area.addEventListener('change',()=>{try{update(id,s,'private_human_note',area.value);}catch(e){msg(e.message,true);}});note.append(area);card.append(note);
   output.append(card);
  }
 }
 $('summary').textContent=shown+' displayed / '+total+' original owner-only HUMAN steps · '+replied+' locally responded. Declared original source: '+current.original.source_sha256+' · recipient '+current.original.recipient_alias+' (unverified).';
 $('source').textContent='DECLARED ORIGINAL SHA '+current.original.source_sha256+' · self-declared client '+current.original.client_reference+' / engagement '+current.original.engagement_reference+' · PRIVATE HUMAN recipient '+current.original.recipient_alias+'.';
}
function forget(force=false){if(!force&&current&&edited!==saved&&!window.confirm('Discard UNSAVED PRIVATE human replies? Export your return first.'))return false;
 current=null;review=null;edited=0;saved=0;
 for(const x of ['handoffFile','replyFile','search'])$(x).value='';
 $('filter').value='all';for(const x of ['steps','review'])$(x).replaceChildren();
 $('desk').classList.add('hidden');$('out').classList.add('hidden');
 $('source').textContent='No PRIVATE owner packet selected.';$('summary').textContent='';$('compareSummary').textContent='No external HUMAN return compared.';dirty();msg('PRIVATE human handoff and received return cleared from browser memory. Prior downloads remain on disk.');return true;
}
async function load(){
 let f=$('handoffFile').files[0];if(!f)fail('choose private owner handoff');
 let baseline=edited,anchor=current?key(current.original):null,p=admitHandoff(await read(f));
 if(f!==$('handoffFile').files[0]||edited!==baseline||(current?key(current.original):null)!==anchor)fail('PRIVATE source or local changes occurred while loading');
 if(current&&edited!==saved&&!window.confirm('Replace UNSAVED PRIVATE local HUMAN answers? Export a return first.'))return;
 current={original:p,edits:new Map()};edited=0;saved=0;review=null;$('replyFile').value='';$('review').replaceChildren();$('compareSummary').textContent='No external HUMAN return compared.';
 $('desk').classList.remove('hidden');$('out').classList.remove('hidden');$('search').value='';$('filter').value='all';render();dirty();
 msg('Loaded strict ORIGINAL one-owner HUMAN handoff. No sender identity or original source authenticity has been independently verified.');
}
function download(name,s,mime){if(new TextEncoder().encode(s).byteLength>LIMIT)fail('PRIVATE output exceeds 8 MiB; no incomplete backup produced');
 let url=URL.createObjectURL(new Blob([s],{type:mime})),a=document.createElement('a');a.download=name;a.href=url;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);}
function save(){
 if(!current)fail('load HUMAN owner handoff');
 if(!window.confirm('Export PRIVATE HUMAN return for '+current.original.recipient_alias+' only? Verify confidential destination/recipient identity; this is NOT an authenticated original owner reply, fix or consent.'))return;
 download('LightUp-PRIVATE-owner-HUMAN-return.json',JSON.stringify(outgoing(),null,2)+'\n','application/json');
 saved=edited;dirty();msg('PRIVATE HUMAN return exported. Retain original handoff for separate operator matching.');
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}
function printable(){
 if(!current)fail('load private HUMAN handoff');
 if(!window.confirm('Create scriptless PRIVATE HUMAN briefing? Verify recipient and printer confidentiality, and avoid sharing private original IDs outside an authenticated human channel.'))return;
 let o=current.original,preview=review?.entries||current.edits;
 let doc=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
 '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;; img-src &#39;none&#39;">',
 '<title>LightUp PRIVATE HUMAN owner reply brief</title></head><body>',
 '<h1>LightUp · PRIVATE HUMAN owner reply brief</h1>',
 '<p><strong>DRAFT/HOLD, UNVERIFIED HUMAN COORDINATION ONLY.</strong> No authenticated owner, execution, fix verification, retest, grant, consent or release.</p>',
 '<p>Declared original source SHA: '+escapeHtml(o.source_sha256)+'</p>',
 '<p>Self-declared recipient: '+escapeHtml(o.recipient_alias)+'; client '+escapeHtml(o.client_reference)+'; engagement '+escapeHtml(o.engagement_reference)+'</p>'];
 for(const row of o.rows){doc.push('<section><h2>Original finding '+escapeHtml(row.finding_id)+'</h2><ol>');
  for(const s of row.steps){let r=preview.get(stepKey(row.finding_id,s.step_id))||empty();
   doc.push('<li><strong>Original human step '+s.step_id+'</strong><pre>'+escapeHtml(s.description)+'</pre>'+
   '<p>Human response: '+escapeHtml(r.human_ack)+'</p><pre>'+escapeHtml(r.private_human_note)+'</pre><p>Tentative follow-up: '+escapeHtml(r.tentative_follow_up||'none')+'</p></li>');}
  doc.push('</ol></section>');
 }
 doc.push('<p>No original evidence was generated or security result verified. Verify all claims and real permissions independently.</p></body></html>\n');
 download('LightUp-PRIVATE-owner-HUMAN-response-brief.html',doc.join('\n'),'text/html;charset=utf-8');
 msg('Scriptless PRIVATE human-owner briefing exported (no third-party source content executed).');
}
function counts(){
 if(!current)fail('load original PRIVATE owner handoff');
 if(!window.confirm('Export HUMAN response-stage counts only, without original IDs, SHA, clients, aliases, notes or individual step content? Small cohorts may still disclose patterns.'))return;
 let c=new Map(),m=review?.entries||current.edits;
 for(const row of current.original.rows)for(const s of row.steps){let k=(m.get(stepKey(row.finding_id,s.step_id))||empty()).human_ack;c.set(k,1+(c.get(k)||0));}
 let lines=['human_response_stage,count'];for(const [k,v] of [...c].sort((a,b)=>a[0].localeCompare(b[0])))lines.push('"'+k+'",'+v);
 download('LightUp-anonymous-HUMAN-owner-response-counts.csv',lines.join('\r\n')+'\r\n','text/csv;charset=utf-8');
 msg('Only grouped HUMAN stage counts exported; no verified remediation or permission.');
}
async function preview(){
 if(!current)fail('load exact ORIGINAL private owner packet first');
 let f=$('replyFile').files[0];if(!f)fail('choose human reply');
 let baseline=edited,src=key(current.original),data=await read(f);
 let m=admitReturn(data,current.original);
 if(edited!==baseline||src!==key(current.original)||f!==$('replyFile').files[0])fail('HUMAN source/file/local revision changed while reading return');
 review={file:f,entries:m};$('review').replaceChildren();
 let replied=0,needs=0;
 for(const row of current.original.rows)for(const s of row.steps){
  let r=m.get(stepKey(row.finding_id,s.step_id));if(r.human_ack!=='not_responded_human')replied++;
  if(r.human_ack==='clarification_needed_human')needs++;
  let card=document.createElement('article');card.className='card';card.append(element('h3','Original finding '+row.finding_id+' · HUMAN step '+s.step_id));
  card.append(element('strong','Source-proposed HUMAN work (unverified)'));card.append(element('pre',s.description));
  card.append(element('strong','Returned HUMAN acknowledgement: '+r.human_ack));
  card.append(element('pre',r.private_human_note||'(no private owner note)'));
  card.append(element('small','Tentative HUMAN follow-up '+(r.tentative_follow_up||'unset')));
  $('review').append(card);
 }
 $('compareSummary').textContent=replied+' owner-declared HUMAN responses · '+needs+' asking clarification · '+m.size+' exactly source-bound original steps. No ownership, transport authenticity or actual remediation verified.';
 msg('Original-owner handoff and PRIVATE HUMAN return matched exactly by declared source, complete original step snapshots and false-only authority flags. This is not proof of authenticated sender or fix.');
}
function clearPreview(){review=null;$('review').replaceChildren();$('replyFile').value='';$('compareSummary').textContent='No external HUMAN return compared.';msg('External HUMAN return preview discarded; editable local replies untouched.');}
function bind(id,event,fn){$(id).addEventListener(event,e=>{try{Promise.resolve(fn(e)).catch(err=>msg(err?.message||'HOLD: private action failed',true));}catch(err){msg(err?.message||'HOLD: private action failed',true);}});}
bind('open','click',load);bind('forget','click',()=>forget());bind('search','input',render);bind('filter','change',render);
bind('save','click',save);bind('brief','click',printable);bind('csv','click',counts);
bind('preview','click',preview);bind('clearPreview','click',clearPreview);
bind('handoffFile','change',()=>{if(current){msg('Source file changed. Explicitly open it before it replaces the current PRIVATE owner review.');}});
bind('replyFile','change',()=>{review=null;$('review').replaceChildren();$('compareSummary').textContent='Selected PRIVATE reply changed; inspect the chosen file to compare its original human source.';});
window.addEventListener('beforeunload',e=>{if(current&&edited!==saved){e.preventDefault();e.returnValue='';}});
dirty();
})();
