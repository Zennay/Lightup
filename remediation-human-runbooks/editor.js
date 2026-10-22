
(function(){
'use strict';
var $=function(id){return document.getElementById(id);};
var FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
var PKEYS=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','rows','warning'].concat(FLAGS);
var RKEYS=['finding_id','stage','owner_alias','tentative_due','next_action','private_note','updated_utc'];
var STAGES=['unplanned','request_evidence_human','clarify_human_reply','coordinate_human_change','await_human_review','human_handoff_prepared'];
var KINDS=['human_prepare','human_implementation_discussion','human_dependency_coordination','human_rollback_discussion','human_review_request'];
var SKEYS=['step_id','kind','description','precondition','responsible_alias','rollback_discussion','verification_question','tentative_date','human_stage'];
var RBKEYS=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','finding_ids','runbooks','warning'].concat(FLAGS);
var BKEYS=['finding_id','steps'];
var MAX=1048576, MAX_BACKUP=8388608, MAX_ROWS=350, MAX_STEPS=8, MAX_TOTAL=1600;
var state=null, revision=0, exported=0, pendingMerge=null, mergeUndo=null, ownerReturns=new Map(), followup=new Map(), actionRevision=0, actionSavedRevision=0, actionSelected=new Set(), actionBatchUndo=null;
var fail=function(s){throw Error('HOLD: '+s);};
function exact(obj,keys){return obj!==null&&typeof obj==='object'&&!Array.isArray(obj)&&Object.getPrototypeOf(obj)===Object.prototype&&Object.keys(obj).length===keys.length&&Object.keys(obj).every(function(k){return keys.indexOf(k)>=0;});}
function string(v,max,label,required){
 if(typeof v!=='string'||v.length>max||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/.test(v)||(required&&!v.trim()))fail('invalid '+label);
 return v;
}
function date(v){if(v==='')return v;if(typeof v!=='string'||! /^\d{4}-\d{2}-\d{2}$/.test(v)||!Number.isFinite(Date.parse(v+'T00:00:00Z'))||new Date(v+'T00:00:00Z').toISOString().slice(0,10)!==v)fail('invalid tentative date');return v;}
function iso(v){if(typeof v!=='string'||! /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)fail('invalid original HUMAN update instant');}
function sourceData(p){
 if(!exact(p,PKEYS)||p.kind!=='lightup.private_human_original_finding_workplan'||p.schema_version!==1||p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||!Array.isArray(p.rows)||p.rows.length!==p.source_count||p.rows.length<1||p.rows.length>MAX_ROWS||!Number.isInteger(p.source_count)||FLAGS.some(function(k){return p[k]!==false;}))fail('original workplan contract or false authority flags');
 string(p.source_contract,200,'source contract',true);
 if(typeof p.source_sha256!=='string'||! /^[0-9a-f]{64}$/.test(p.source_sha256))fail('canonical declared source SHA');
 string(p.client_reference,200,'client label',true);string(p.engagement_reference,200,'engagement label',true);string(p.warning,500,'warning',true);
 var ids=new Set();
 p.rows.forEach(function(r){
  if(!exact(r,RKEYS)||!STAGES.includes(r.stage))fail('noncanonical original finding row');
  var id=string(r.finding_id,200,'original finding ID',true);if(ids.has(id))fail('duplicate original finding ID');ids.add(id);
  string(r.owner_alias,120,'original owner alias');date(r.tentative_due);
  string(r.next_action,1000,'original next action');string(r.private_note,600,'original note');iso(r.updated_utc);
 });
 return {source_contract:p.source_contract,source_sha256:p.source_sha256,client_reference:p.client_reference,engagement_reference:p.engagement_reference,ids:Array.from(ids),original:p.rows,runbooks:new Map(p.rows.map(function(r){return [r.finding_id,[]];}))};
}
// Reject duplicate JSON keys, including escaped aliases, before built-in JSON decoding.
function parseStrict(text,limit){
 if(text.length>limit||!text.length)fail('JSON empty or oversized');
 var i=0;
 function white(){while(i<text.length&&/\s/.test(text[i]))i++;}
 function qstr(){var start=i;if(text[i]!=='"')fail('JSON string expected');i++;var esc=false;
  while(i<text.length){var c=text[i++];if(c==='"'&&!esc){return JSON.parse(text.slice(start,i));}if(c==='\\'&&!esc){esc=true;continue;}if(c.charCodeAt(0)<32&&!esc)fail('raw control in JSON string');esc=false;}
  fail('unfinished JSON string');
 }
 function value(depth){
  if(depth>16)fail('nested JSON beyond safe limit');white();var c=text[i];
  if(c==='{'){i++;white();var keys=new Set();if(text[i]==='}'){i++;return;}while(true){
   white();var key=qstr();if(keys.has(key))fail('duplicate JSON member');keys.add(key);white();if(text[i++]!==':')fail('missing key separator');
   value(depth+1);white();if(text[i]==='}'){i++;return;}if(text[i++]!==',')fail('invalid object separator');
  }}
  if(c==='['){i++;white();if(text[i]===']'){i++;return;}while(true){value(depth+1);white();if(text[i]===']'){i++;return;}if(text[i++]!==',')fail('invalid array separator');}}
  if(c==='"'){qstr();return;}
  var rest=text.slice(i),m=/^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(rest);
  if(!m)fail('invalid JSON value');i+=m[0].length;
 }
 value(0);white();if(i!==text.length)fail('trailing JSON text');
 return JSON.parse(text);
}
async function read(file,limit){limit=limit||MAX;if(!file||file.size<1||file.size>limit)fail('select a nonempty JSON within configured size limit');
 try{return parseStrict(new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()),limit);}
 catch(e){if(e.message&&e.message.startsWith('HOLD:'))throw e;fail('invalid JSON syntax or UTF-8 (private source content withheld)');}}
function message(s,bad){$('notice').textContent=s;$('notice').dataset.error=String(!!bad);}
function dirty(){if(!state){$('dirty').textContent='No local storage. Import an original PRIVATE source first.';return;}
 $('dirty').textContent=revision!==exported?'UNSAVED PRIVATE runbooks: download a complete backup before closing or refreshing.':'PRIVATE runbooks locally unchanged since last export/restore.';}
function confirmDiscard(){return (revision===exported&&actionRevision===actionSavedRevision)||window.confirm('UNSAVED PRIVATE runbook / HUMAN follow-up notes will be discarded. Download both PRIVATE backups first if needed. Continue?');}
function reset(){clearReceivedReplies();$('ownerReplies').hidden=true;pendingMerge=null;mergeUndo=null;clearMerge();$('mergeUndo').disabled=true;$('mergeFile').value='';$('collab').hidden=true;state=null;revision=0;exported=0;$('workFile').value='';$('restoreFile').value='';$('source').textContent='No PRIVATE source loaded.';$('editor').hidden=true;$('io').hidden=true;$('finding').replaceChildren();$('steps').replaceChildren();$('details').replaceChildren();$('summary').textContent='';dirty();}
function touch(){revision++;pendingMerge=null;mergeUndo=null;clearMerge();$('mergeUndo').disabled=true;clearReceivedReplies();dirty();}
function binding(s){return JSON.stringify([s.source_contract,s.source_sha256,s.client_reference,s.engagement_reference,s.ids.slice().sort()]);}
function opt(label,value){var el=document.createElement('option');el.value=value;el.textContent=label;return el;}
function element(tag,text){var el=document.createElement(tag);el.textContent=String(text);return el;}
function field(title,value,max,onChange,kind){
 var box=document.createElement('label');box.textContent=title;
 var inp=document.createElement(kind==='area'?'textarea':kind==='select'?'select':'input');
 if(kind==='date')inp.type='date';if(kind==='select'){value.options.forEach(function(x){inp.append(opt(x.replaceAll('_',' '),x));});inp.value=value.current;}
 else {inp.value=value;inp.maxLength=max;}
 inp.addEventListener('change',function(){try{onChange(inp.value);}catch(e){message(e.message,true);render();}});
 box.append(inp);return box;
}
function selected(){if(!state)fail('original PRIVATE source not loaded');var id=$('finding').value;if(!state.runbooks.has(id))fail('select exact original finding');return id;}
function current(){return state.runbooks.get(selected());}
function validateStep(s){if(!exact(s,SKEYS)||!Number.isInteger(s.step_id)||s.step_id<1||s.step_id>MAX_STEPS||!KINDS.includes(s.kind)||!['draft_human','needs_human_input','await_human_review','human_handoff_prepared'].includes(s.human_stage))fail('invalid HUMAN step shape or stage');
 string(s.description,1000,'human step description',true);string(s.precondition,600,'human precondition');string(s.responsible_alias,120,'self-declared owner');string(s.rollback_discussion,750,'rollback discussion');string(s.verification_question,600,'human verification question');date(s.tentative_date);
}
function validateBooks(books,ctx){if(!Array.isArray(books)||books.length!==ctx.ids.length)fail('incomplete exact original finding set');var seen=new Set(),out=new Map(),total=0;
 books.forEach(function(book){if(!exact(book,BKEYS)||!ctx.ids.includes(book.finding_id)||seen.has(book.finding_id)||!Array.isArray(book.steps)||book.steps.length>MAX_STEPS)fail('noncanonical or duplicate original runbook');
  seen.add(book.finding_id);var nums=new Set();book.steps.forEach(function(s){validateStep(s);if(nums.has(s.step_id))fail('duplicate human step ID');nums.add(s.step_id);});total+=book.steps.length;out.set(book.finding_id,book.steps.map(function(s){return Object.assign({},s);}));});
 if(total>MAX_TOTAL)fail('too many human steps');return out;
}
function render(){
 if(!state)return;
 var old=$('finding').value,filter=$('filter').value,ids=state.ids.filter(function(id){
  var steps=state.runbooks.get(id);
  if(filter==='missing')return steps.length===0;
  if(filter==='blocked')return steps.some(function(s){return s.human_stage==='needs_human_input';});
  if(filter==='handoff')return steps.some(function(s){return s.human_stage==='human_handoff_prepared';});
  return true;
 });
 $('finding').replaceChildren();ids.forEach(function(id){$('finding').append(opt(id+' ('+state.runbooks.get(id).length+' steps)',id));});
 if(ids.includes(old))$('finding').value=old;
 var count=state.ids.reduce(function(n,id){return n+state.runbooks.get(id).length;},0);
 $('summary').textContent=state.ids.length+' original finding IDs · '+count+' HUMAN steps · '+state.ids.filter(function(id){return state.runbooks.get(id).length===0;}).length+' without runbook · All security/authority flags false.';
 $('source').textContent='DECLARED ORIGINAL SHA: '+state.source_sha256+' · client: '+state.client_reference+' · engagement: '+state.engagement_reference+' · '+state.ids.length+' original HUMAN findings. No authenticity verification.';
 var priorOwner=$('ownerSelect').value;
 var owners=new Set();state.ids.forEach(function(f){state.runbooks.get(f).forEach(function(step){if(step.responsible_alias.trim())owners.add(step.responsible_alias);});});
 var orderedOwners=Array.from(owners).sort(function(a,b){return a.localeCompare(b);});
 $('ownerSelect').replaceChildren(opt('Choose self-declared HUMAN recipient',''));
 orderedOwners.forEach(function(name){$('ownerSelect').append(opt(name,name));});
 $('ownerSelect').value=orderedOwners.includes(priorOwner)?priorOwner:'';
 $('ownerExport').disabled=!$('ownerSelect').value;
 $('ownerPrint').disabled=!$('ownerSelect').value;
 var id=$('finding').value;
 $('steps').replaceChildren();
 $('add').disabled=!id||count>=MAX_TOTAL||state.runbooks.get(id).length>=MAX_STEPS;
 $('removeAll').disabled=!id||!state.runbooks.get(id).length;
 $('print').disabled=!id;
 if(!id){$('details').textContent='No findings match the filter.';renderReceivedReplies();return;}
 var r=state.original.find(function(x){return x.finding_id===id;});
 $('details').textContent='ORIGINAL (UNVERIFIED) HUMAN plan: stage '+r.stage+', declared owner '+(r.owner_alias||'none')+', tentative date '+(r.tentative_due||'none')+'. Original next action: '+(r.next_action||'none')+'.';
 state.runbooks.get(id).forEach(function(s,index){
  var box=document.createElement('article');box.className='step';box.append(element('h3','Step '+s.step_id+' · proposed HUMAN work'));
  var row=document.createElement('div');row.className='actions';
  [['Move ↑',function(){swap(index,-1);}],['Move ↓',function(){swap(index,1);}],['Delete proposed step',function(){remove(index);}]].forEach(function(action){
   var b=document.createElement('button');b.textContent=action[0];b.addEventListener('click',action[1]);row.append(b);
  });box.append(row);
  function update(key,v){var next=Object.assign({},s);next[key]=v;validateStep(next);guardReviewLoss();Object.assign(s,next);touch();render();message('Updated LOCAL HUMAN runbook. No original evidence or verified status changed.');}
  var g=document.createElement('div');g.className='two';
  g.append(field('Human step type',{options:KINDS,current:s.kind},0,function(v){update('kind',v);},'select'));
  g.append(field('HUMAN stage',{options:['draft_human','needs_human_input','await_human_review','human_handoff_prepared'],current:s.human_stage},0,function(v){update('human_stage',v);},'select'));
  g.append(field('Self-declared human owner',s.responsible_alias,120,function(v){update('responsible_alias',v);}));
  g.append(field('Tentative planning date',s.tentative_date,10,function(v){update('tentative_date',v);},'date'));
  box.append(g);
  box.append(field('Proposed HUMAN coordination step (not a command)',s.description,1000,function(v){update('description',v);},'area'));
  box.append(field('Preconditions to discuss with authenticated humans',s.precondition,600,function(v){update('precondition',v);},'area'));
  box.append(field('Rollback preparation discussion (not executed)',s.rollback_discussion,750,function(v){update('rollback_discussion',v);},'area'));
  box.append(field('Human evidence/retest question (not a verified result)',s.verification_question,600,function(v){update('verification_question',v);},'area'));
  $('steps').append(box);
 });
 renderReceivedReplies();
}
function renumber(steps){steps.forEach(function(s,i){s.step_id=i+1;});}
function add(){var steps=current();if(steps.length>=MAX_STEPS||state.ids.reduce(function(n,id){return n+state.runbooks.get(id).length;},0)>=MAX_TOTAL)fail('HUMAN runbook cap reached');guardReviewLoss();
 var sourceOwner=state.original.find(function(r){return r.finding_id===selected();});
 steps.push({step_id:steps.length+1,kind:'human_prepare',description:'Describe the proposed HUMAN follow-up',precondition:'',responsible_alias:sourceOwner?sourceOwner.owner_alias:'',rollback_discussion:'',verification_question:'',tentative_date:'',human_stage:'draft_human'});touch();render();message('New draft HUMAN coordination step added (no execution).');}
function remove(index){var a=current();if(!window.confirm('Delete this LOCAL HUMAN step? Export private backup before destructive editing.'))return;guardReviewLoss();a.splice(index,1);renumber(a);touch();render();}
function swap(index,d){var a=current(),to=index+d;if(to<0||to>=a.length)return;guardReviewLoss();var temp=a[index];a[index]=a[to];a[to]=temp;renumber(a);touch();render();}
function packet(){return Object.assign({kind:'lightup.private_human_remediation_runbooks',schema_version:1,disposition:'UNVERIFIED_HUMAN_PLANNING_ONLY',source_contract:state.source_contract,source_sha256:state.source_sha256,client_reference:state.client_reference,engagement_reference:state.engagement_reference,source_count:state.ids.length,finding_ids:state.ids.slice(),runbooks:state.ids.map(function(id){return {finding_id:id,steps:state.runbooks.get(id).map(function(s){return Object.assign({},s);})};}),warning:'PRIVATE HUMAN planning ONLY; not authenticated source, customer approval, authorized remediation, verified retest, grant or release.'},Object.fromEntries(FLAGS.map(function(k){return [k,false];})));}
function download(name,data,type){var u=URL.createObjectURL(new Blob([data],{type:type})),a=document.createElement('a');a.download=name;a.href=u;document.body.append(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(u);},1600);}
function save(){if(!state)fail('import original source first');if(!window.confirm('Save PRIVATE full original-ID runbook data to this device? Independently verify confidential storage and recipient.'))return;
 var body=JSON.stringify(packet(),null,2)+'\n';if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('PRIVATE backup exceeds safe restore maximum');
 download('LightUp-PRIVATE-HUMAN-runbooks.json',body,'application/json');exported=revision;dirty();message('Full PRIVATE HUMAN runbook saved. No original source/authorization changed.');}
async function importWork(){
 var f=$('workFile').files[0];if(!f)fail('choose ORIGINAL PRIVATE HUMAN workplan first');
 var old=f,prior=revision,priorSource=state?binding(state):null,data=await read(f), next=sourceData(data);
 if($('workFile').files[0]!==old||revision!==prior||(state?binding(state):null)!==priorSource)fail('original workplan picker or UNSAVED local work changed while importing');
 var retained=false;
 if(state&&binding(next)===binding(state)){
  if(!window.confirm('The NEW ORIGINAL HUMAN workplan claims the SAME exact source SHA/client/engagement and original finding IDs. KEEP existing PRIVATE local runbook steps and refresh original self-declared owner/stage context? Verify both source documents independently. The merge Undo will reset. Cancel to retain everything untouched.'))return;
  if(revision!==prior||binding(state)!==priorSource)fail('local HUMAN planning changed before safe context refresh');
  next.runbooks=new Map(state.ids.map(function(id){return [id,state.runbooks.get(id).map(function(step){return Object.assign({},step);})];}));
  retained=true;
 }else if(state&&!confirmDiscard())return;
 if(revision!==prior||(state?binding(state):null)!==priorSource)fail('PRIVATE local HUMAN state changed before source switch confirmation');
 guardReviewLoss();state=next;clearReceivedReplies();if(retained){revision++;}else{revision=0;exported=0;}
 pendingMerge=null;mergeUndo=null;clearMerge();$('mergeUndo').disabled=true;$('mergeFile').value='';$('filter').value='all';$('restoreFile').value='';
 $('editor').hidden=false;$('io').hidden=false;$('collab').hidden=false;render();dirty();
 message(retained?'Original HUMAN context refreshed for exact DECLARED source binding: all own PRIVATE steps retained, reviewer merge Undo cleared. Independently authenticate source before handoff.':'Opened original source-declared PRIVATE HUMAN workplan. Draft runbooks below; no client authority or security outcome created.');
}
async function restore(){
 if(!state)fail('load original workplan first');var f=$('restoreFile').files[0];if(!f)fail('choose exported PRIVATE runbooks JSON');
 var before=revision,ref=binding(state),p=await read(f,MAX_BACKUP);
 if(!exact(p,RBKEYS)||p.kind!=='lightup.private_human_remediation_runbooks'||p.schema_version!==1||p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||FLAGS.some(function(k){return p[k]!==false;})||p.source_count!==state.ids.length)fail('invalid PRIVATE runbook envelope or authority flags');
 ['source_contract','source_sha256','client_reference','engagement_reference'].forEach(function(k){if(p[k]!==state[k])fail('private runbook '+k+' mismatches original');});
 string(p.warning,500,'warning',true);
 if(!Array.isArray(p.finding_ids)||JSON.stringify(p.finding_ids)!==JSON.stringify(state.ids))fail('original finding IDs/order mismatch');
 var rows=validateBooks(p.runbooks,state);
 if(before!==revision||ref!==binding(state)||$('restoreFile').files[0]!==f)fail('PRIVATE source, file or local revision changed while restoring');
 if(!window.confirm('REPLACE all local HUMAN runbooks with the exact-original-source-bound PRIVATE backup? Export current work first. No original evidence, owners or grants will be updated.'))return;
 if(before!==revision||ref!==binding(state))fail('stale local state during confirmation');
 guardReviewLoss();state.runbooks=rows;clearReceivedReplies();revision++;exported=revision;pendingMerge=null;mergeUndo=null;clearMerge();$('mergeUndo').disabled=true;$('restoreFile').value='';render();dirty();message('Restored complete HUMAN-only runbooks for exact original finding set.');
}
function esc(s){return String(s).replace(/[&<>"']/g,function(ch){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];});}
function printOne(){
 var id=selected(),steps=current();if(!window.confirm('Download PRIVATE scriptless HUMAN briefing for original finding '+id+'? Check independently authenticated confidential recipient, storage and printer.'))return;
 var html=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
 '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; connect-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; img-src &#39;none&#39;">',
 '<title>LightUp PRIVATE HUMAN runbook</title></head><body><h1>LightUp · PRIVATE HUMAN runbook</h1>',
 '<p><strong>HUMAN DRAFT/HOLD:</strong> no client consent, scope permission, verified fix, approved change, retest or release.</p>',
 '<p>Self-declared source SHA '+esc(state.source_sha256)+'</p>',
 '<p>Self-declared client '+esc(state.client_reference)+' / engagement '+esc(state.engagement_reference)+'</p>',
 '<h2>Original finding '+esc(id)+' (unverified)</h2><ol>'];
 steps.forEach(function(s){html.push('<li><strong>'+esc(s.kind)+'</strong> · '+esc(s.human_stage)+'<dl>'+
 '<dt>Human proposal</dt><dd><pre>'+esc(s.description)+'</pre></dd>'+
 '<dt>Human preconditions</dt><dd><pre>'+esc(s.precondition)+'</pre></dd>'+
 '<dt>Declared human owner</dt><dd>'+esc(s.responsible_alias)+'</dd>'+
 '<dt>Tentative date</dt><dd>'+esc(s.tentative_date)+'</dd>'+
 '<dt>Rollback discussion</dt><dd><pre>'+esc(s.rollback_discussion)+'</pre></dd>'+
 '<dt>Human verification question (not a verdict)</dt><dd><pre>'+esc(s.verification_question)+'</pre></dd></dl></li>');});
 html.push('</ol><p>No scripts, external resources, active actions or source changes.</p></body></html>\n');
 download('LightUp-PRIVATE-HUMAN-runbook.html',html.join('\n'),'text/html;charset=utf-8');
 message('Scriptless PRIVATE human briefing downloaded; no grant or actual remediation.');
}
function ownerHandoff(){
 if(!state)fail('load original HUMAN source first');
 var owner=$('ownerSelect').value;if(!owner)fail('choose an existing declared HUMAN owner');
 var rows=state.ids.map(function(id){return {finding_id:id,steps:state.runbooks.get(id).filter(function(s){return s.responsible_alias===owner;}).map(function(s){return Object.assign({},s);})};}).filter(function(r){return r.steps.length>0;});
 if(!rows.length)fail('no HUMAN steps for chosen declared recipient');
 if(!window.confirm('Download PRIVATE HUMAN step packet for only '+owner+' ('+rows.length+' original finding(s))? Identity and transport are NOT authenticated. All other declared owners and their steps will be excluded.'))return;
 var out=Object.assign({kind:'lightup.private_human_owner_runbook_handoff',schema_version:1,
 disposition:'UNVERIFIED_HUMAN_PLANNING_ONLY',
 source_contract:state.source_contract,source_sha256:state.source_sha256,
 client_reference:state.client_reference,engagement_reference:state.engagement_reference,
 source_count:state.ids.length,recipient_alias:owner,rows:rows,
 warning:'PRIVATE HUMAN proposal only, not an original owner reply, current consent, grant, approved fix or verified retest.'},
 Object.fromEntries(FLAGS.map(function(k){return [k,false];})));
 var body=JSON.stringify(out,null,2)+'\n';
 if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('PRIVATE owner handoff exceeds safe export limit');
 download('LightUp-PRIVATE-one-owner-HUMAN-runbooks.json',body,'application/json');
 message('PRIVATE owner-only HUMAN runbooks downloaded; no other owner steps included. Verify recipient independently.');
}
function ownerPrintable(){
 if(!state)fail('load original PRIVATE HUMAN workplan');
 var alias=$('ownerSelect').value;if(!alias)fail('choose locally declared HUMAN recipient');
 var owned=state.ids.map(function(id){return {id:id,steps:state.runbooks.get(id).filter(function(s){return s.responsible_alias===alias;})};}).filter(function(x){return x.steps.length;});
 if(!owned.length)fail('no steps for chosen HUMAN recipient');
 if(!window.confirm('Download PRIVATE printable briefing for human alias '+alias+' covering '+owned.length+' original findings? Verify recipient identity, local storage and printer confidentiality through separate trusted channels.'))return;
 var html=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
 '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;; img-src &#39;none&#39;; form-action &#39;none&#39;">',
 '<title>LightUp PRIVATE one-owner HUMAN runbook brief</title></head><body>',
 '<h1>LightUp · PRIVATE one-owner HUMAN preparation</h1>',
 '<p><strong>UNVERIFIED DRAFT/HOLD:</strong> not an authorized scope, verified fix, safe rollback guarantee, authenticated owner reply, grant or retest approval.</p>',
 '<p>Recipient self-declared HUMAN alias: '+esc(alias)+'</p>',
 '<p>Declared original source digest: '+esc(state.source_sha256)+'</p>',
 '<p>Self-declared client: '+esc(state.client_reference)+' / engagement: '+esc(state.engagement_reference)+'</p>'];
 owned.forEach(function(group){
  html.push('<article><h2>Original source finding '+esc(group.id)+'</h2><ol>');
  group.steps.forEach(function(t){
   html.push('<li><strong>'+esc(t.kind)+'</strong> · '+esc(t.human_stage)+'<dl>'+
    '<dt>Proposed human work</dt><dd><pre>'+esc(t.description)+'</pre></dd>'+
    '<dt>Human prerequisites</dt><dd><pre>'+esc(t.precondition)+'</pre></dd>'+
    '<dt>Self-declared responsible alias</dt><dd>'+esc(t.responsible_alias)+'</dd>'+
    '<dt>Tentative planning date</dt><dd>'+esc(t.tentative_date)+'</dd>'+
    '<dt>Rollback preparation discussion</dt><dd><pre>'+esc(t.rollback_discussion)+'</pre></dd>'+
    '<dt>Human review question (not a verdict)</dt><dd><pre>'+esc(t.verification_question)+'</pre></dd></dl></li>');
  });html.push('</ol></article>');
 });
 html.push('<p>Other self-declared owners and their private steps were excluded. Independently verify source identity and confidential recipient.</p></body></html>\n');
 var body=html.join('\n');if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('private owner HTML exceeds safe export limit');
 download('LightUp-PRIVATE-one-owner-HUMAN-readable-runbooks.html',body,'text/html;charset=utf-8');
 message('Scriptless PRIVATE owner-only HTML downloaded; no other owner steps, active content, grant or verification.');
}
function counts(){
 if(!state)fail('load original source');
 if(!window.confirm('Download HUMAN stage counts only (no finding/source/customer/owner/note IDs)? Small groups may still disclose patterns.'))return;
 var c=new Map();state.ids.forEach(function(id){var steps=state.runbooks.get(id);if(!steps.length)c.set('unplanned_human',1+(c.get('unplanned_human')||0));steps.forEach(function(s){c.set(s.human_stage,1+(c.get(s.human_stage)||0));});});
 var csv='human_stage,count\r\n'+Array.from(c.keys()).sort().map(function(k){return '"'+k+'",'+c.get(k);}).join('\r\n')+'\r\n';
 download('LightUp-HUMAN-runbook-counts.csv',csv,'text/csv;charset=utf-8');message('Anonymous stage counts exported; no verified remediation assertions.');
}

/* Exact-source independent human-reviewer runbook collaboration.
   No source/admission/provenance authority or original records are modified. */
function clearMerge(){
 $('mergePanel').hidden=true;$('mergeChoices').replaceChildren();$('mergeSummary').textContent='';$('mergeApply').disabled=true;
}
function verifyMergePacket(p,ctx){
 if(!exact(p,RBKEYS)||p.kind!=='lightup.private_human_remediation_runbooks'||p.schema_version!==1||
 p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||p.source_count!==ctx.ids.length||
 FLAGS.some(function(k){return p[k]!==false;}))fail('other reviewer packet is not an exact original-source HUMAN runbook');
 ['source_contract','source_sha256','client_reference','engagement_reference'].forEach(function(k){if(p[k]!==ctx[k])fail('other reviewer '+k+' mismatches original');});
 if(!Array.isArray(p.finding_ids)||JSON.stringify(p.finding_ids)!==JSON.stringify(ctx.ids))fail('other reviewer original finding-ID membership/order differs');
 string(p.warning,500,'other reviewer private warning',true);
 return validateBooks(p.runbooks,ctx);
}
function compareMerge(incoming){
 var changes=[];
 state.ids.forEach(function(id){
  var old=state.runbooks.get(id),other=incoming.get(id);
  if(JSON.stringify(old)===JSON.stringify(other)||other.length===0)return; // Blank incoming must not erase private local work
  changes.push({id:id,local:old.map(function(s){return Object.assign({},s);}),other:other.map(function(s){return Object.assign({},s);}),
   conflict:old.length>0,choice:old.length>0?'':'incoming'});
 });
 return changes;
}
function refreshMergeChoices(){
 if(!pendingMerge)return;var panel=$('mergeChoices');panel.replaceChildren();$('mergePanel').hidden=false;
 var ch=pendingMerge.changes,conflicts=ch.filter(function(x){return x.conflict;});
 $('mergeSummary').textContent=ch.length+' nonempty proposed HUMAN changes · '+conflicts.length+
 ' conflicting original findings. Resolve every conflict; no verified fix or authority is involved.';
 ch.forEach(function(change){
  var box=document.createElement('article');box.className='step';box.append(element('h3','Original finding '+change.id+(change.conflict?' · HUMAN conflict':' · new HUMAN proposal')));
  box.append(element('p','LOCAL steps ('+change.local.length+'): '+change.local.map(function(s){return s.description+' ['+s.human_stage+']';}).join(' | ')));
  box.append(element('p','OTHER REVIEWER proposed steps ('+change.other.length+'): '+change.other.map(function(s){return s.description+' ['+s.human_stage+']';}).join(' | ')));
  if(change.conflict){
   var label=document.createElement('label');label.textContent='Resolve HUMAN-only change for original '+change.id;
   var sel=document.createElement('select');sel.append(opt('Choose an explicit HUMAN resolution',''),opt('KEEP current local HUMAN steps','local'),opt('APPLY other reviewer HUMAN steps','incoming'));
   sel.value=change.choice;sel.addEventListener('change',function(){change.choice=sel.value;$('mergeApply').disabled=ch.some(function(c){return c.conflict&&!['local','incoming'].includes(c.choice);});});
   label.append(sel);box.append(label);
  }
  panel.append(box);
 });
 $('mergeApply').disabled=!ch.length||conflicts.some(function(c){return !c.choice;});
}
async function previewMerge(){
 if(!state)fail('load original full HUMAN source');
 var file=$('mergeFile').files[0];if(!file)fail('choose other reviewer complete PRIVATE runbook');
 var prior=revision,anchor=binding(state),parsed=await read(file,MAX_BACKUP);
 var incoming=verifyMergePacket(parsed,state);
 if(prior!==revision||anchor!==binding(state)||$('mergeFile').files[0]!==file)fail('PRIVATE HUMAN reviewer file or local state changed while importing');
 pendingMerge={revision:prior,source:anchor,file:file,packet:parsed,changes:compareMerge(incoming)};
 refreshMergeChoices();message(pendingMerge.changes.length?'Other reviewer HUMAN plan differences ready for explicit local review.':'No new nonblank HUMAN proposals to merge.');
}
function applyMerge(){
 var draft=pendingMerge;if(!draft)fail('preview another exact-source PRIVATE HUMAN runbook first');
 if(revision!==draft.revision||binding(state)!==draft.source||$('mergeFile').files[0]!==draft.file)fail('reviewer merge preview stale');
 var input=verifyMergePacket(draft.packet,state),fresh=compareMerge(input);
 if(JSON.stringify(fresh.map(function(c){return [c.id,c.local,c.other,c.conflict];}))!==
 JSON.stringify(draft.changes.map(function(c){return [c.id,c.local,c.other,c.conflict];})))fail('PRIVATE runbook differences changed since preview');
 if(draft.changes.some(function(c){return c.conflict&&!['local','incoming'].includes(c.choice);}))fail('unresolved HUMAN conflict');
 var applies=draft.changes.filter(function(c){return c.choice==='incoming';});
 if(!applies.length){pendingMerge=null;clearMerge();message('No HUMAN runbook was overwritten. Local proposals preserved.');return;}
 if(!window.confirm('Replace LOCAL HUMAN steps for '+applies.length+' exact original finding(s) with selected other-reviewer proposals? This is a PRIVATE human edit, not an original source change or approved fix.'))return;
 if(revision!==draft.revision||binding(state)!==draft.source)fail('local HUMAN work changed during confirmation');
 guardReviewLoss();var old=new Map(state.ids.map(function(id){return [id,state.runbooks.get(id).map(function(v){return Object.assign({},v);})];}));
 applies.forEach(function(c){state.runbooks.set(c.id,c.other.map(function(v){return Object.assign({},v);}));});
 revision++;clearReceivedReplies();mergeUndo={prior:old,revision:revision,source:draft.source};pendingMerge=null;clearMerge();$('mergeUndo').disabled=false;render();dirty();
 message('Merged '+applies.length+' exact-source HUMAN runbooks. Undo available until another local edit.');
}
function undoMerge(){
 var entry=mergeUndo;if(!entry||entry.revision!==revision||entry.source!==binding(state))fail('last HUMAN merge no longer safe to undo');
 if(!window.confirm('Undo only the last PRIVATE local reviewer runbook merge? External PRIVATE downloads are unaffected.'))return;
 guardReviewLoss();state.runbooks=new Map(Array.from(entry.prior,function(pair){return [pair[0],pair[1].map(function(s){return Object.assign({},s);})];}));
 revision++;clearReceivedReplies();mergeUndo=null;pendingMerge=null;clearMerge();$('mergeUndo').disabled=true;render();dirty();message('Previous local HUMAN runbooks restored. No original findings or approvals were changed.');
}


/* PRIVATE HUMAN return coordination: informational, all sources self-declared.
   This overlay NEVER updates original runbooks, source findings, replies or grants. */

/* PRIVATE, self-declared, HUMAN-only coordination derived from exact local owner returns. */
const ACTION_STAGES=['untriaged_human','needs_human_input','human_contact_planned','human_review_prepared','human_discussion_closed'];
const ACTION_FIELDS=['human_stage','coordinator_alias','tentative_due','next_action','private_note'];
const ACTION_PACKET=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','original_ids','owner_return_snapshots','rows','warning',...FLAGS];
function actionKey(a,id,n){return JSON.stringify([a,id,n]);}
function blankAction(){return {human_stage:'untriaged_human',coordinator_alias:'',tentative_due:'',next_action:'',private_note:''};}
function actionSources(){
 const rows=[];for(const [alias,p] of ownerReturns)for(const item of p.records)rows.push({
  recipient_alias:alias,finding_id:item.finding_id,step_id:item.step_id,human_ack:item.human_ack});
 return rows.sort((a,b)=>a.recipient_alias.localeCompare(b.recipient_alias)||state.ids.indexOf(a.finding_id)-state.ids.indexOf(b.finding_id)||a.step_id-b.step_id);
}
function actionSnapshot(){return [...ownerReturns].sort((a,b)=>a[0].localeCompare(b[0])).map(([recipient_alias,p])=>({
 recipient_alias,records:p.records.map(x=>({...x}))}));}
function validateAction(a){if(!exact(a,ACTION_FIELDS)||!ACTION_STAGES.includes(a.human_stage))fail('noncanonical HUMAN operator action');
 string(a.coordinator_alias,120,'human coordinator');date(a.tentative_due);string(a.next_action,1000,'human next action');string(a.private_note,800,'private human note');return {...a};}
function guardReviewLoss(){
 if(actionRevision!==actionSavedRevision&&!window.confirm('UNSAVED PRIVATE HUMAN follow-up notes will be lost when original steps/replies change. Export complete PRIVATE follow-up JSON first if needed. Continue and discard?'))
 fail('Unexported PRIVATE HUMAN notes retained; original source edit cancelled');
}
function clearHumanActions(){
 followup=new Map();actionRevision=0;actionSavedRevision=0;actionSelected=new Set();actionBatchUndo=null;$('actionUndoBatch').disabled=true;
 $('actionRows').replaceChildren();$('actionSummary').textContent='';
 $('actionSearch').value='';$('actionFilter').value='all';$('actionRestoreFile').value='';$('actionCoordinator').replaceChildren(opt('Choose locally declared coordinator',''));$('actionCoordinatorBrief').disabled=true;
 $('humanReviewDesk').hidden=true;actionSavedStatus();
}
function actionSavedStatus(){$('actionSaved').textContent=actionRevision!==actionSavedRevision?
 'UNSAVED PRIVATE HUMAN follow-up notes · export source-bound JSON before closing or changing original plans. No browser persistence.':
 'PRIVATE HUMAN follow-up locally unchanged since last complete export or restore. No browser persistence.';}
function actionRows(){return actionSources().map(r=>({source:r,action:followup.get(actionKey(r.recipient_alias,r.finding_id,r.step_id))||blankAction()}));}

function visibleHumanActionRows(rows){
 const q=$('actionSearch').value.toLowerCase().trim(),mode=$('actionFilter').value,today=new Date().toISOString().slice(0,10);
 return rows.filter(({source:r,action:a})=>{
  if(q&&![r.recipient_alias,r.finding_id,r.human_ack,a.coordinator_alias,a.next_action,a.private_note].join(' ').toLowerCase().includes(q))return false;
  if(mode==='no_owner')return !a.coordinator_alias;
  if(mode==='overdue')return !!a.tentative_due&&a.tentative_due<today;
  return mode==='all'||a.human_stage===mode;
 });
}
function renderHumanActions(){
 $('humanReviewDesk').hidden=!state||!ownerReturns.size;
 if(!state||!ownerReturns.size){$('actionRows').replaceChildren();$('actionSummary').textContent='No current HUMAN owner returns.';actionSavedStatus();return;}
 const all=actionRows(),filtered=visibleHumanActionRows(all);
 $('actionSummary').textContent=all.length+' unverified human-reply steps · '+filtered.length+' shown · '+
 all.filter(x=>x.action.human_stage==='needs_human_input').length+' HUMAN clarification assignments · '+
 all.filter(x=>x.action.tentative_due&&x.action.tentative_due<today).length+' tentative UTC human dates passed (not authorized windows).';
 const coordinatorSelect=$('actionCoordinator'),previousCoordinator=coordinatorSelect.value;
 const localCoordinators=[...new Set(all.map(x=>x.action.coordinator_alias).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
 coordinatorSelect.replaceChildren(opt('Choose locally declared coordinator',''));
 localCoordinators.forEach(alias=>coordinatorSelect.append(opt(alias,alias)));
 coordinatorSelect.value=localCoordinators.includes(previousCoordinator)?previousCoordinator:'';
 $('actionCoordinatorBrief').disabled=!coordinatorSelect.value;
 const holder=$('actionRows');holder.replaceChildren();
 $('actionSelection').textContent=actionSelected.size+' exact-current HUMAN steps selected. Selection is local, not an execution request.';
 $('actionBatchApply').disabled=!actionSelected.size;
 for(const {source:r,action:a} of filtered){
  const key=actionKey(r.recipient_alias,r.finding_id,r.step_id),card=document.createElement('article');card.className='step';
  card.append(element('h3','ORIGINAL '+r.finding_id+' · HUMAN step '+r.step_id+' · '+r.recipient_alias));
  const choose=document.createElement('label');choose.textContent='Select original HUMAN step for local-only batch assignment';
  const tick=document.createElement('input');tick.type='checkbox';tick.checked=actionSelected.has(key);
  tick.setAttribute('aria-label','Select original '+r.finding_id+' HUMAN step '+r.step_id+' for local-only batch');
  tick.addEventListener('change',()=>{tick.checked?actionSelected.add(key):actionSelected.delete(key);renderHumanActions();});
  choose.append(tick);card.append(choose);
  card.append(element('p','Original unverified HUMAN reply: '+r.human_ack));
  const row=document.createElement('div');row.className='two';
  const status=document.createElement('label');status.textContent='Local HUMAN follow-up stage';
  const select=document.createElement('select');ACTION_STAGES.forEach(v=>select.append(opt(v.replaceAll('_',' '),v)));select.value=a.human_stage;
  select.addEventListener('change',()=>editHumanAction(key,'human_stage',select.value));status.append(select);row.append(status);
  for(const [label,field,type,max] of [['Self-declared HUMAN coordinator','coordinator_alias','text',120],['Tentative HUMAN follow-up date','tentative_due','date',10]]){
   const box=document.createElement('label');box.textContent=label;const input=document.createElement('input');
   input.type=type;input.maxLength=max;input.value=a[field];input.addEventListener('change',()=>editHumanAction(key,field,input.value));box.append(input);row.append(box);
  }card.append(row);
  for(const [label,field,max] of [['Next HUMAN-only coordination action','next_action',1000],['PRIVATE HUMAN operator note','private_note',800]]){
   const box=document.createElement('label');box.textContent=label;const input=document.createElement('textarea');input.rows=2;input.maxLength=max;input.value=a[field];
   input.addEventListener('change',()=>editHumanAction(key,field,input.value));box.append(input);card.append(box);
  }
  const go=document.createElement('button');go.textContent='Open original HUMAN finding';go.addEventListener('click',()=>{
   $('filter').value='all';render();$('finding').value=r.finding_id;render();$('editor').scrollIntoView({block:'start'});
  });card.append(go);holder.append(card);
 }actionSavedStatus();
}
function editHumanAction(key,field,v){
 try{
  if(!ACTION_FIELDS.includes(field)||!actionSources().some(x=>actionKey(x.recipient_alias,x.finding_id,x.step_id)===key))fail('stale HUMAN action identity');
  const next=validateAction({...followup.get(key)||blankAction(),[field]:v});followup.set(key,next);actionRevision++;actionBatchUndo=null;$('actionUndoBatch').disabled=true;renderHumanActions();
  message('PRIVATE HUMAN coordination '+field+' saved in browser memory only. No original reply or security status changed.');
 }catch(e){message(e.message,true);renderHumanActions();}
}

function selectVisibleHumanActions(){
 if(!state||!ownerReturns.size)fail('import exact-original HUMAN reply packets first');
 for(const {source:r} of visibleHumanActionRows(actionRows()))actionSelected.add(actionKey(r.recipient_alias,r.finding_id,r.step_id));
 renderHumanActions();message('Selected filtered source-bound HUMAN steps for local-only coordination. No execution or grant.');
}
function clearHumanActionSelection(){actionSelected.clear();renderHumanActions();}
function applyHumanActionBatch(){
 if(!state||!ownerReturns.size||!actionSelected.size)fail('select ORIGINAL HUMAN steps for local planning');
 const source=binding(state),snap=JSON.stringify(actionSnapshot()),baseline=actionRevision,
 stage=$('actionBatchStage').value,owner=string($('actionBatchOwner').value.trim(),120,'local HUMAN batch coordinator'),
 due=date($('actionBatchDue').value);
 if(!ACTION_STAGES.includes(stage))fail('unsupported HUMAN planning stage');
 const all=new Map(actionRows().map(({source:r,action:a})=>[actionKey(r.recipient_alias,r.finding_id,r.step_id),a]));
 const keys=[...actionSelected];
 if(keys.some(k=>!all.has(k)))fail('stale original HUMAN action selection');
 const previous=new Map(keys.map(k=>[k,{...all.get(k)}]));
 const proposed=new Map(keys.map(k=>[k,validateAction({...all.get(k),human_stage:stage,
  ...(owner?{coordinator_alias:owner}:{}),...(due?{tentative_due:due}:{})})]));
 const preview=keys.slice(0,8).map(k=>{const v=JSON.parse(k);return v[1]+' · HUMAN step '+v[2]+' · '+v[0];}).join('\n');
 const explanation='Apply '+keys.length+' LOCAL HUMAN stage assignments ('+stage+')?'+
  (owner?' Set coordinator '+owner+'.':' Keep individual coordinators.')+
  (due?' Set tentative date '+due+'.':' Keep individual dates.')+
  '\nORIGINAL selections:\n'+preview+(keys.length>8?'\n... and '+(keys.length-8)+' more.':'')+
  '\nNo original HUMAN replies, security verdicts, consent or grants change. PRIVATE notes remain intact.';
 if(!window.confirm(explanation))return;
 if(baseline!==actionRevision||source!==binding(state)||snap!==JSON.stringify(actionSnapshot())||
 keys.some(k=>!actionSources().some(r=>actionKey(r.recipient_alias,r.finding_id,r.step_id)===k)))fail('stale exact-source HUMAN batch or old original selection');
 for(const [k,v] of proposed)followup.set(k,v);
 actionRevision++;actionBatchUndo={before:previous,source,snap,revision:actionRevision};
 actionSelected.clear();$('actionUndoBatch').disabled=false;renderHumanActions();
 message('Applied '+proposed.size+' local PRIVATE HUMAN stage assignments. Reversible until another local action edit, import or source change.');
}
function undoHumanActionBatch(){
 const u=actionBatchUndo;
 if(!u||u.revision!==actionRevision||u.source!==binding(state)||u.snap!==JSON.stringify(actionSnapshot()))
  fail('last local HUMAN batch is not safe to undo after source, reply or note changes');
 if(!window.confirm('Undo the last PRIVATE HUMAN-only batch assignment for '+u.before.size+' original reply steps? No original source or grant changes.'))return;
 for(const [k,v] of u.before)followup.set(k,{...v});
 actionRevision++;actionBatchUndo=null;$('actionUndoBatch').disabled=true;renderHumanActions();
 message('Previous local HUMAN annotations restored for last bulk assignment. Already downloaded files remain outside this browser.');
}

function actionPacket(){
 if(!state||!ownerReturns.size)fail('no original source-bound owner returns');
 return {kind:'lightup.private_human_owner_return_followup',schema_version:1,disposition:'UNVERIFIED_HUMAN_PLANNING_ONLY',
 source_contract:state.source_contract,source_sha256:state.source_sha256,client_reference:state.client_reference,
 engagement_reference:state.engagement_reference,source_count:state.ids.length,original_ids:state.ids.slice(),
 owner_return_snapshots:actionSnapshot(),
 rows:actionSources().map(r=>({...r,local_human_action:{...(followup.get(actionKey(r.recipient_alias,r.finding_id,r.step_id))||blankAction())}})),
 ...Object.fromEntries(FLAGS.map(k=>[k,false])),
 warning:'PRIVATE HUMAN coordination only. NOT authenticated source, owner consent, authorized execution, verified remediation, retest or release.'};
}
function saveHumanActions(){
 if(!state||!ownerReturns.size)fail('import current owner HUMAN replies first');if(!window.confirm('Download FULL PRIVATE HUMAN actions including self-declared source labels, recipient identities, original reply snapshot and local private notes? Store and deliver confidentially.'))return;
 const body=JSON.stringify(actionPacket(),null,2)+'\n';if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('PRIVATE human follow-up backup exceeds 8 MiB');
 download('LightUp-PRIVATE-HUMAN-return-followup.json',body,'application/json');actionSavedRevision=actionRevision;actionSavedStatus();
 message('Complete original-source-bound PRIVATE HUMAN follow-up backup exported; original owner replies unmodified.');
}
async function restoreHumanActions(){
 if(!state||!ownerReturns.size)fail('import original HUMAN source and owner returns first');
 const file=$('actionRestoreFile').files[0];if(!file)fail('choose PRIVATE human follow-up JSON');
 const revisionBefore=revision,actionBefore=actionRevision,origin=binding(state),snap=JSON.stringify(actionSnapshot()),p=await read(file,MAX_BACKUP);
 if(!exact(p,ACTION_PACKET)||p.kind!=='lightup.private_human_owner_return_followup'||p.schema_version!==1||
 p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||FLAGS.some(k=>p[k]!==false)||p.source_count!==state.ids.length||
 ['source_contract','source_sha256','client_reference','engagement_reference'].some(k=>p[k]!==state[k])||
 JSON.stringify(p.original_ids)!==JSON.stringify(state.ids)||JSON.stringify(p.owner_return_snapshots)!==snap)
  fail('PRIVATE HUMAN follow-up not exactly bound to current original source AND unverified original owner replies');
 string(p.warning,500,'human follow-up warning',true);
 const expected=actionSources();if(!Array.isArray(p.rows)||p.rows.length!==expected.length)fail('incomplete follow-up records');
 const rows=new Map();
 p.rows.forEach((row,i)=>{
  const base=expected[i];
  if(!exact(row,['recipient_alias','finding_id','step_id','human_ack','local_human_action'])||
   row.recipient_alias!==base.recipient_alias||row.finding_id!==base.finding_id||
   row.step_id!==base.step_id||row.human_ack!==base.human_ack)fail('foreign or stale HUMAN original reply');
  const key=actionKey(row.recipient_alias,row.finding_id,row.step_id);if(rows.has(key))fail('duplicate HUMAN reply identity');
  rows.set(key,validateAction(row.local_human_action));
 });
 if(revision!==revisionBefore||actionRevision!==actionBefore||binding(state)!==origin||snap!==JSON.stringify(actionSnapshot())||
 $('actionRestoreFile').files[0]!==file)fail('PRIVATE human source changed while restoring');
 if(!window.confirm('REPLACE local PRIVATE HUMAN follow-up annotations with this EXACT-source / exact owner-reply snapshot backup? Save unsaved notes before replacement. No original evidence or grants changed.'))return;
 if(revision!==revisionBefore||actionRevision!==actionBefore||binding(state)!==origin||snap!==JSON.stringify(actionSnapshot()))fail('stale HUMAN restore confirmation');
 followup=rows;actionRevision++;actionSavedRevision=actionRevision;actionSelected.clear();actionBatchUndo=null;$('actionUndoBatch').disabled=true;$('actionRestoreFile').value='';renderHumanActions();
 message('Complete PRIVATE HUMAN follow-up restored against current original source and owner replies.');
}
function humanEsc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function printHumanAgenda(){
 if(!window.confirm('Download scriptless PRIVATE HUMAN follow-up agenda containing original IDs, owner aliases, tentative dates and notes? Use independently authenticated confidential delivery and printing.'))return;
 const values=actionRows().filter(x=>x.action.human_stage!=='untriaged_human'||x.action.next_action||x.action.private_note);
 values.sort((a,b)=>(a.action.tentative_due||'9999').localeCompare(b.action.tentative_due||'9999')||a.source.finding_id.localeCompare(b.source.finding_id));
 const lines=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
  '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;">',
  '<title>LightUp PRIVATE HUMAN agenda</title></head><body><h1>LightUp · PRIVATE HUMAN follow-up</h1>',
  '<p>UNVERIFIED HUMAN COORDINATION ONLY: no execution, client consent, authorization, remediation proof, verified retest or release.</p>',
  '<p>Declared source SHA '+humanEsc(state.source_sha256)+' · client '+humanEsc(state.client_reference)+' · engagement '+humanEsc(state.engagement_reference)+'</p><ol>'];
 for(const {source:r,action:a} of values)lines.push('<li><h2>Original '+humanEsc(r.finding_id)+' · HUMAN step '+r.step_id+'</h2>'+
  '<p>Self-declared recipient '+humanEsc(r.recipient_alias)+' · original unverified reply '+humanEsc(r.human_ack)+'</p>'+
  '<p>Local HUMAN stage '+humanEsc(a.human_stage)+' · coordinator '+humanEsc(a.coordinator_alias)+' · tentative UTC date '+humanEsc(a.tentative_due)+'</p>'+
  '<h3>Next HUMAN coordination</h3><pre>'+humanEsc(a.next_action)+'</pre><h3>PRIVATE operator note</h3><pre>'+humanEsc(a.private_note)+'</pre></li>');
 lines.push('</ol><p>No original HUMAN reply, finding, evidence or grant altered.</p></body></html>\n');
 const body=lines.join('\n');if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('PRIVATE human agenda too large');
 download('LightUp-PRIVATE-HUMAN-discussion-agenda.html',body,'text/html;charset=utf-8');
 message('Scriptless confidential HUMAN agenda exported; this is not authorization or verified remediation.');
}

function exportOneCoordinatorBrief(){
 if(!state||!ownerReturns.size)fail('load source-bound HUMAN owner replies first');
 const coordinator=$('actionCoordinator').value;if(!coordinator)fail('choose a locally declared HUMAN coordinator');
 const rows=actionRows().filter(x=>x.action.coordinator_alias===coordinator);
 if(!rows.length)fail('no private HUMAN follow-ups assigned to coordinator');
 if(!window.confirm('Create PRIVATE scriptless HUMAN coordination brief for locally declared '+coordinator+' only ('+rows.length+' original HUMAN steps)? Other coordinators and their actions/notes are excluded. Verify recipient identity, transport and confidential printing separately.'))return;
 const lines=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
 '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;; form-action &#39;none&#39;">',
 '<title>LightUp PRIVATE HUMAN coordinator briefing</title></head><body>',
 '<h1>LightUp · PRIVATE one-coordinator HUMAN follow-up</h1>',
 '<p><strong>INCUBATE DRAFT/HOLD · UNVERIFIED HUMAN-ONLY.</strong> No authenticated source/recipient, client consent, grant, authorized execution, verified remediation, retest or release.</p>',
 '<p>Locally declared coordinator '+humanEsc(coordinator)+'</p>',
 '<p>Self-declared original source SHA '+humanEsc(state.source_sha256)+
 ' · client '+humanEsc(state.client_reference)+' · engagement '+humanEsc(state.engagement_reference)+'</p><ol>'];
 rows.sort((a,b)=>(a.action.tentative_due||'9999').localeCompare(b.action.tentative_due||'9999')||a.source.finding_id.localeCompare(b.source.finding_id));
 for(const {source:r,action:a} of rows){
  lines.push('<li><h2>Original '+humanEsc(r.finding_id)+' · HUMAN step '+r.step_id+'</h2>'+
   '<p>Original declared HUMAN recipient '+humanEsc(r.recipient_alias)+' · human reply '+humanEsc(r.human_ack)+'</p>'+
   '<p>Local HUMAN follow-up stage '+humanEsc(a.human_stage)+' · tentative human date '+humanEsc(a.tentative_due||'not set')+'</p>'+
   '<h3>Proposed human next action</h3><pre>'+humanEsc(a.next_action)+'</pre>'+
   '<h3>PRIVATE coordinator-specific note</h3><pre>'+humanEsc(a.private_note)+'</pre></li>');
 }
 lines.push('</ol><p>All other local HUMAN coordinators, their notes and actions are deliberately excluded. No original evidence or grant is changed.</p></body></html>\n');
 const body=lines.join('\n');if(new TextEncoder().encode(body).byteLength>MAX_BACKUP)fail('PRIVATE HUMAN one-recipient briefing exceeds 8 MiB');
 download('LightUp-PRIVATE-one-coordinator-HUMAN-followup.html',body,'text/html;charset=utf-8');
 message('Scriptless PRIVATE one-coordinator HUMAN follow-up brief exported, with other coordinators excluded. Recipient remains unverified.');
}

function exportHumanActionCounts(){
 if(!window.confirm('Export HUMAN follow-up counts only, excluding owner aliases, source, original IDs, notes, names, dates and customer context? Small cohorts may reveal patterns.'))return;
 const counts=new Map();for(const {action:a} of actionRows())counts.set(a.human_stage,1+(counts.get(a.human_stage)||0));
 const csv='human_only_followup_stage,count\r\n'+[...counts].sort((a,b)=>a[0].localeCompare(b[0])).map(x=>'"'+x[0]+'",'+x[1]).join('\r\n')+'\r\n';
 download('LightUp-anonymous-HUMAN-followup-counts.csv',csv,'text/csv;charset=utf-8');
 message('Anonymous HUMAN-only planning counts exported, no original ID or private note.');
}
function forgetHumanActions(){
 if(actionRevision!==actionSavedRevision&&!window.confirm('Discard UNSAVED PRIVATE operator annotations? Export source-bound JSON first. The original runbooks and owner returns remain unchanged.'))return;
 followup=new Map();actionRevision++;actionSavedRevision=actionRevision;actionSelected.clear();actionBatchUndo=null;$('actionUndoBatch').disabled=true;$('actionRestoreFile').value='';renderHumanActions();
 message('Local HUMAN follow-up annotations forgotten without changing source, grants or incoming owner replies.');
}

function clearReceivedReplies(){
 clearHumanActions();
 ownerReturns=new Map();$('returnFile').value='';$('returnFilter').value='all';
 $('returnRows').replaceChildren();$('returnCoverage').replaceChildren();$('returnSummary').textContent='No owner returns imported.';
 $('ownerReplies').hidden=!state;
}
function expectedOwnerSteps(alias){
 return state.ids.map(id=>({finding_id:id,steps:state.runbooks.get(id).filter(s=>s.responsible_alias===alias).map(s=>({...s}))})).filter(r=>r.steps.length);
}
function admitReceivedReply(p){
 var fields=['kind','schema_version','disposition','source_contract','source_sha256','client_reference','engagement_reference','source_count','recipient_alias','handoff_rows','responses','warning',...FLAGS];
 if(!exact(p,fields)||p.kind!=='lightup.private_human_owner_runbook_return'||p.schema_version!==1||
 p.disposition!=='UNVERIFIED_HUMAN_PLANNING_ONLY'||FLAGS.some(k=>p[k]!==false)||p.source_count!==state.ids.length||
 p.source_contract!==state.source_contract||p.source_sha256!==state.source_sha256||
 p.client_reference!==state.client_reference||p.engagement_reference!==state.engagement_reference)fail('PRIVATE HUMAN return source or authority contract differs');
 var alias=string(p.recipient_alias,120,'self-declared human recipient',true);
 string(p.warning,500,'unverified HUMAN warning',true);
 var original=expectedOwnerSteps(alias);
 if(!original.length||!Array.isArray(p.handoff_rows)||!Array.isArray(p.responses)||
 original.length!==p.handoff_rows.length||p.responses.length!==original.length||
 JSON.stringify(original)!==JSON.stringify(p.handoff_rows))fail('PRIVATE owner return differs from CURRENT exact original HUMAN steps (stale plan or wrong recipient)');
 var seen=new Set(),records=[];
 for(var i=0;i<original.length;i++){
  var source=original[i],reply=p.responses[i];
  if(!exact(reply,['finding_id','steps'])||reply.finding_id!==source.finding_id||
   seen.has(reply.finding_id)||!Array.isArray(reply.steps)||reply.steps.length!==source.steps.length)
   fail('missing or repeated original finding HUMAN reply');seen.add(reply.finding_id);
  for(var j=0;j<reply.steps.length;j++){
   var received=reply.steps[j],step=source.steps[j];
   if(!exact(received,['step_id','human_ack','private_human_note','tentative_follow_up'])||
      received.step_id!==step.step_id||
      !['not_responded_human','received_human','clarification_needed_human','discussion_prepared_human'].includes(received.human_ack))
      fail('missing, altered or duplicated ORIGINAL owner-specific HUMAN step reply');
   string(received.private_human_note,800,'private human reply');date(received.tentative_follow_up);
   records.push({finding_id:source.finding_id,step_id:step.step_id,owner_alias:alias,source_action:step.description,
     human_ack:received.human_ack,private_human_note:received.private_human_note,tentative_follow_up:received.tentative_follow_up});
  }
 }
 if(records.length>1600)fail('oversized PRIVATE human reply dataset');
 return {alias,records};
}
function renderReceivedReplies(){
 renderHumanActions();
 $('ownerReplies').hidden=!state;if(!state)return;
 var selected=$('returnFilter').value,view=[],groups=[];
 var humanExpected=new Map();
 for(const id of state.ids)for(const step of state.runbooks.get(id)){
  if(step.responsible_alias)humanExpected.set(step.responsible_alias,(humanExpected.get(step.responsible_alias)||0)+1);
 }
 var coverage=$('returnCoverage');coverage.replaceChildren();
 if(humanExpected.size){
  coverage.append(element('h3','PRIVATE HUMAN owner response coverage (self-declared, not verified)'));
  for(const [alias,count] of [...humanExpected].sort((a,b)=>a[0].localeCompare(b[0]))){
   var packet=ownerReturns.get(alias),ack=packet?.records.filter(r=>r.human_ack!=='not_responded_human').length||0;
   var clarification=packet?.records.filter(r=>r.human_ack==='clarification_needed_human').length||0;
   var row=document.createElement('div');row.className='listrow';
   row.append(element('strong',alias));
   row.append(element('span',packet?('PRIVATE packet imported · '+ack+'/'+count+' HUMAN replies · '+clarification+' clarification needed'):
       ('NO PRIVATE owner-return packet · '+count+' proposed HUMAN steps')));
   coverage.append(row);
  }
 }else coverage.append(element('p','No locally declared HUMAN owners; assign tentative roles to proposed original steps first.'));
 for(const [alias,data] of ownerReturns){
  groups.push(alias+': '+data.records.length+' HUMAN steps');
  view.push(...data.records.filter(row=>selected==='all'||row.human_ack===selected));
 }
 view.sort((a,b)=>state.ids.indexOf(a.finding_id)-state.ids.indexOf(b.finding_id)||a.step_id-b.step_id);
 $('returnSummary').textContent=ownerReturns.size+' PRIVATE self-declared HUMAN recipients · '+view.length+' matching response steps · '+groups.join(' / ')+'. ALL UNVERIFIED. Original runbooks untouched.';
 var dest=$('returnRows');dest.replaceChildren();
 for(const row of view){
  var item=document.createElement('article');item.className='step';
  item.append(element('h3','ORIGINAL '+row.finding_id+' · HUMAN step '+row.step_id+' · '+row.human_ack));
  item.append(element('p','Self-declared HUMAN owner: '+row.owner_alias+' (NOT authenticated)'));
  item.append(element('p','Original proposed HUMAN work: '+row.source_action));
  item.append(element('p','PRIVATE HUMAN response: '+(row.private_human_note||'(no private reply note)')));
  item.append(element('p','Tentative HUMAN follow-up: '+(row.tentative_follow_up||'not set')));
  var button=document.createElement('button');button.textContent='Open original HUMAN finding in runbook editor';
  button.addEventListener('click',()=>{$('filter').value='all';render();$('finding').value=row.finding_id;render();$('editor').scrollIntoView({block:'start'});});
  item.append(button);dest.append(item);
 }
}

function exportTeamHumanCoverage(){
 if(!state)fail('load exact original HUMAN plan first');
 var proposed=0,expectedOwners=new Set(),received=0,clarify=0,humanAck=0,unanswered=0;
 for(const id of state.ids)for(const step of state.runbooks.get(id)){if(step.responsible_alias){proposed++;expectedOwners.add(step.responsible_alias);}}
 for(const [alias,data] of ownerReturns){
  received+=data.records.length;
  for(const r of data.records){
   if(r.human_ack==='clarification_needed_human')clarify++;
   if(r.human_ack==='not_responded_human')unanswered++;else humanAck++;
  }
 }
 if(!window.confirm('Download HUMAN team response COUNTS ONLY, without original finding IDs, private source SHA, customer, owner aliases, notes, steps or dates? Small cohorts may reveal patterns. These counts never mean verified fixes or authenticated permission.'))return;
 var measures=[['local_original_human_steps_with_owner',proposed],
  ['local_self_declared_human_owner_aliases',expectedOwners.size],
  ['owner_return_packets_in_memory',ownerReturns.size],
  ['human_steps_in_received_packets',received],
  ['unverified_human_responses',humanAck],
  ['unanswered_steps_within_received_packets',unanswered],
  ['unverified_human_clarification_requests',clarify]];
 var csvValue='human_only_metric,count\r\n'+measures.map(x=>'"'+x[0]+'",'+x[1]).join('\r\n')+'\r\n';
 download('LightUp-anonymous-HUMAN-team-return-coverage.csv',csvValue,'text/csv;charset=utf-8');
 message('Privacy-minimal HUMAN return coverage counts downloaded. No owner or original source has been authenticated.');
}

async function importReceivedReply(){
 if(!state)fail('load the complete original HUMAN workplan first');
 var f=$('returnFile').files[0];if(!f)fail('choose a one-owner HUMAN return packet');
 var before=revision,source=binding(state);
 var packet=await read(f,MAX_BACKUP);
 var incoming=admitReceivedReply(packet);
 if(before!==revision||source!==binding(state)||$('returnFile').files[0]!==f)fail('PRIVATE source, local plan or reply input changed while importing');
 var replacing=ownerReturns.has(incoming.alias);
 if(!window.confirm((replacing?'REPLACE existing':'Add new')+' PRIVATE reply from self-declared HUMAN alias '+incoming.alias+' ('+incoming.records.length+' exact original steps)? This is not authenticated owner consent, a verified fix or a source mutation.'))return;
 if(before!==revision||source!==binding(state))fail('current original PRIVATE human planning changed during confirmation');
 if(ownerReturns.has(incoming.alias))guardReviewLoss();
 for(const key of [...followup.keys()]){try{if(JSON.parse(key)[0]===incoming.alias)followup.delete(key);}catch(_){followup.delete(key);}}
 ownerReturns.set(incoming.alias,incoming);actionRevision++;actionBatchUndo=null;$('actionUndoBatch').disabled=true;actionSelected.clear();$('returnFile').value='';renderReceivedReplies();
 message('PRIVATE HUMAN return imported as READ-ONLY self-declared follow-up; original findings, stages, source evidence and grants unchanged.');
}

var bind=function(id,event,fn){$(id).addEventListener(event,function(){try{Promise.resolve(fn()).catch(function(e){message(e.message,true);});}catch(e){message(e.message,true);}});};
bind('loadWork','click',importWork);bind('restore','click',restore);bind('save','click',save);bind('print','click',printOne);bind('counts','click',counts);bind('add','click',add);
bind('removeAll','click',function(){if(!current().length)return;if(!window.confirm('Delete all LOCAL human steps for this finding?'))return;state.runbooks.set(selected(),[]);touch();render();});
bind('forget','click',function(){if(!confirmDiscard())return;reset();message('All loaded PRIVATE source and HUMAN planning content cleared from this page. Existing downloads remain on disk.');});
bind('mergePreview','click',previewMerge);bind('mergeCancel','click',function(){pendingMerge=null;clearMerge();message('Other reviewer preview discarded; local HUMAN planning unchanged.');});bind('mergeApply','click',applyMerge);bind('mergeUndo','click',undoMerge);
bind('mergeFile','change',function(){pendingMerge=null;clearMerge();message('Other-reviewer PRIVATE file changed. Generate a fresh exact-source preview.');});
bind('returnImport','click',importReceivedReply);
bind('returnForget','click',function(){guardReviewLoss();clearReceivedReplies();message('All locally imported PRIVATE HUMAN replies forgotten. Original runbook steps and external downloads unchanged.');});
bind('returnFilter','change',renderReceivedReplies);
bind('returnAggregate','click',exportTeamHumanCoverage);
bind('actionFilter','change',renderHumanActions);
bind('actionSearch','input',renderHumanActions);
bind('actionSelectVisible','click',selectVisibleHumanActions);
bind('actionDeselect','click',clearHumanActionSelection);
bind('actionBatchApply','click',applyHumanActionBatch);
bind('actionUndoBatch','click',undoHumanActionBatch);
bind('actionSave','click',saveHumanActions);
bind('actionBrief','click',printHumanAgenda);
bind('actionCounts','click',exportHumanActionCounts);
bind('actionCoordinator','change',()=>{$('actionCoordinatorBrief').disabled=!$('actionCoordinator').value;});
bind('actionCoordinatorBrief','click',exportOneCoordinatorBrief);
bind('actionRestore','click',()=>restoreHumanActions().catch(e=>message(e.message,true)));
bind('actionForget','click',forgetHumanActions);

bind('returnFile','change',function(){message('New one-owner PRIVATE HUMAN reply selected. Import validates it against CURRENT exact original plan before displaying anything.');});
bind('filter','change',render);bind('finding','change',render);
bind('ownerSelect','change',function(){$('ownerExport').disabled=!$('ownerSelect').value;$('ownerPrint').disabled=!$('ownerSelect').value;});bind('ownerExport','click',ownerHandoff);bind('ownerPrint','click',ownerPrintable);
window.addEventListener('beforeunload',function(e){if(state&&(revision!==exported||actionRevision!==actionSavedRevision)){e.preventDefault();e.returnValue='';}});
dirty();
})();
