/* LightUp offline source-bound coordination: no authorization, scanning, verification or remote I/O. */
(()=>{'use strict';
const C=window.LightUpCasework,P=window.LightUpCapacity,D=window.LightUpDraft;
if(!C||!P||!D)throw Error('Pinned original Casework and Capacity modules are required.');
const $=id=>document.getElementById(id);
const FIELDS=['finding_id','title','severity','retest_status','remediation'];
const LEVELS=['critical','high','medium','low','info'];
const STAGES=['missing','submitted','needs_changes','ready_for_authorized_retest'];
const EVIDENCE=['change_reference','deployment_reference','rollback_reference','retest_request_reference','review_question'];
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const REFMAX={change_reference:240,deployment_reference:240,rollback_reference:240,retest_request_reference:240,review_question:700};
const BIDI=/[\u202a-\u202e\u2066-\u2069]/;
let joined=null;
const size=text=>new TextEncoder().encode(text).byteLength;
function status(message,error=false){$('status').textContent=message;$('status').dataset.error=error?'true':'false';}
function fail(message){throw Error(message);}
function keysExact(obj,allowed,required=allowed){
 if(!obj||typeof obj!=='object'||Array.isArray(obj)||Object.getPrototypeOf(obj)!==Object.prototype)fail('Expected plain private JSON object.');
 const ks=Object.keys(obj);
 if(ks.some(k=>!allowed.includes(k))||required.some(k=>!Object.prototype.hasOwnProperty.call(obj,k)))fail('Unexpected or missing private fields.');
}
function human(value,max){
 if(typeof value!=='string'||value.length>max||/[\u0000-\u001f\u007f]/.test(value)||BIDI.test(value))fail('Invalid local review text.');
 return value;
}
async function readFile(file,max){
 if(!file||file.size<1||file.size>max)fail('Choose a bounded private source file.');
 const buffer=await file.arrayBuffer();
 if(buffer.byteLength>max)fail('Private source exceeds size limit.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer);
 if(!text||text.charCodeAt(0)===0xfeff)fail('Unsupported BOM or empty private source.');
 return text;
}
/* No duplicate JSON object keys, unsafe JSON structure or trailing fragments. */
function strictJSON(text){
 let i=0,nodes=0;const N=text.length,MAX_DEPTH=25;
 const skip=()=>{while(i<N&&/[ \t\n\r]/.test(text[i]))i++;};
 function quote(){
  if(text[i]!=='"')fail('Expected JSON string.');
  const start=i++;let escape=false;
  while(i<N){const c=text[i++];
   if(escape){escape=false;continue;}
   if(c==='\\'){escape=true;continue;}
   if(c==='"')return JSON.parse(text.slice(start,i));
   if(c<' ')fail('Invalid raw JSON string control.');
  }fail('Unclosed JSON string.');
 }
 function value(depth){
  if(++nodes>30000||depth>MAX_DEPTH)fail('Private JSON exceeds structural limit.');
  skip();const c=text[i];
  if(c==='{'){
   i++;skip();const fields=new Set();if(text[i]==='}'){i++;return;}
   for(;;){
    skip();const k=quote();
    if(k==='__proto__'||k==='constructor'||k==='prototype'||fields.has(k))fail('Unsafe or duplicate JSON property.');
    fields.add(k);skip();if(text[i++]!==':')fail('Missing JSON colon.');
    value(depth+1);skip();const d=text[i++];
    if(d==='}')return;if(d!==',')fail('Malformed JSON object.');skip();
   }
  }
  if(c==='['){
   i++;skip();if(text[i]===']'){i++;return;}
   for(;;){value(depth+1);skip();const d=text[i++];if(d===']')return;if(d!==',')fail('Malformed JSON array.');skip();}
  }
  if(c==='"'){quote();return;}
  const m=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
  if(!m)fail('Invalid JSON value.');i+=m[0].length;
 }
 value(0);skip();if(i!==N)fail('Trailing JSON text.');
 return JSON.parse(text);
}
function reviewDocument(packet,source,hash){
 const top=['kind','schema_version','disposition','source_contract','source_sha256','review','revision_register','warning',...FLAGS];
 keysExact(packet,top,['kind','schema_version','disposition','source_contract','source_sha256','review',...FLAGS]);
 if(packet.kind!=='lightup.remediation_evidence_coordination'||![1,2].includes(packet.schema_version)||
    packet.disposition!=='UNVERIFIED_OFFLINE_HUMAN_COORDINATION'||
    packet.source_contract!=='lightup.finding_export._COLUMNS_v1'||
    packet.source_sha256!==hash||FLAGS.some(k=>packet[k]!==false))
  fail('Evidence is not a source-bound, false-authority original review draft.');
 if(packet.revision_register!==undefined&&(!Array.isArray(packet.revision_register)||packet.revision_register.length>12))
  fail('Unexpected evidence revision register.');
 if(packet.warning!==undefined)human(packet.warning,1600);
 if(!Array.isArray(packet.review)||packet.review.length!==source.length)fail('Evidence draft has incomplete original finding coverage.');
 const ids=new Set(source.map(x=>x.finding_id)),found=new Map();
 for(const raw of packet.review){
  const fields=['finding_id','stage','reference','reviewer','next_step','evidence'];
  keysExact(raw,fields,fields.slice(0,5).concat(packet.schema_version===2?['evidence']:[]));
  if(typeof raw.finding_id!=='string'||!ids.has(raw.finding_id)||found.has(raw.finding_id))fail('Unknown or duplicate original finding ID.');
  if(!STAGES.includes(raw.stage))fail('Unknown local review stage.');
  human(raw.reference,240);human(raw.reviewer,120);human(raw.next_step,500);
  const evidence={};
  if(raw.evidence!==undefined&&raw.evidence!==null){
   keysExact(raw.evidence,EVIDENCE);
   for(const name of EVIDENCE)evidence[name]=human(raw.evidence[name],REFMAX[name]);
  }else{
   if(packet.schema_version===2)fail('Missing v2 human evidence dossier.');
   for(const name of EVIDENCE)evidence[name]='';
  }
  found.set(raw.finding_id,{stage:raw.stage,evidence});
 }
 if(found.size!==source.length)fail('Evidence has incomplete exact original source coverage.');
 return found;
}
function wipe(){
 joined=null;$('results').hidden=true;$('digest').textContent='';
 $('csv').value='';$('evidence').value='';$('capacity').value='';$('same').checked=false;
 $('severity').value='';$('kind').value='';$('agenda').replaceChildren();$('matrix').replaceChildren();
}
const checkSame=()=>{if(!$('same').checked)fail('Independently confirm the SAME original client and exact engagement before joining sources.');};
async function load(){
 joined=null;$('results').hidden=true;$('digest').textContent='';status('Checking original source and private draft links …');
 checkSame();
 const file=$('csv').files[0];
 const csv=await readFile(file,1048576);
 const source=C.parseCSV(csv),sha=await C.digest(source);
 if(!sha||!/^[a-f0-9]{64}$/.test(sha))fail('Canonical original source SHA-256 is unavailable; no unsafe fallback.');
 const evidence=reviewDocument(strictJSON(await readFile($('evidence').files[0],2097152)),source,sha);
 let capacity=null, summary=null;
 if($('capacity').files.length){
  const capacityText=await readFile($('capacity').files[0],D.MAX_DRAFT_BYTES);
  const capacityRows=P.parseCSV(csv);
  const rawSha=await D.fingerprint(file);
  const draft=D.importDraft(capacityText,rawSha,source.length,capacityRows,P);
  capacity=draft.plan;summary=P.summary(capacity);
  if(!summary||summary.source_count!==source.length)fail('Capacity source count mismatch.');
 }
 const records=source.map(f=>{
  const rev=evidence.get(f.finding_id), missing=EVIDENCE.slice(0,4).filter(k=>!rev.evidence[k].trim());
  const urgent=LEVELS.indexOf(f.severity);
  return {id:f.finding_id,severity:f.severity,regression:f.retest_status==='regression',
   stage:rev.stage,missing,priority:(5-urgent)*30+(f.retest_status==='regression'?45:0)+missing.length*7+(rev.stage==='needs_changes'?25:0)};
 }).sort((a,b)=>b.priority-a.priority||a.id.localeCompare(b.id));
 joined={records,sha,summary};
 $('results').hidden=false;$('digest').textContent='Unsigned canonical findings fingerprint: '+sha+
   (summary?' · capacity assumptions bound to the original raw CSV SHA-256':' · no optional staffing draft loaded');
 render();status('Loaded '+source.length+' original findings with original review notes'+(summary?' and exact-CSV capacity estimates':'')+'. No permissions, retests or repairs inferred.');
}
function render(){
 if(!joined)return;
 const {records,summary}=joined;
 $('count').textContent=records.length;
 $('urgent').textContent=records.filter(r=>r.severity==='critical'||r.severity==='high').length;
 $('gaps').textContent=records.filter(r=>r.missing.length).length;
 $('regressions').textContent=records.filter(r=>r.regression).length;
 $('backlog').textContent=summary?String(summary.backlog_hours)+' h':'—';
 $('available').textContent=summary?String(summary.sprint_weeks.reduce((n,w)=>n+w.available_hours,0))+' h':'—';
 const tbody=$('matrix');tbody.replaceChildren();
 for(const severity of LEVELS){
  const rs=records.filter(r=>r.severity===severity),b=summary?.priority_bands?.[severity];
  const cells=[severity,rs.length,rs.filter(r=>r.regression).length,
   rs.filter(r=>r.missing.length).length,rs.filter(r=>r.stage==='needs_changes').length,
   b?b.estimated_hours+' h':'not modelled'];
  const tr=document.createElement('tr');
  for(const cell of cells){const td=document.createElement('td');td.textContent=String(cell);tr.append(td);}
  tbody.append(tr);
 }
 const filtered=records.filter(r=>(!$('severity').value||r.severity===$('severity').value)&&
   (!$('kind').value||($('kind').value==='missing'&&r.missing.length)||
   ($('kind').value==='changes'&&r.stage==='needs_changes')||
   ($('kind').value==='regression'&&r.regression)));
 $('queueCount').textContent=filtered.length;
 const holder=$('agenda');holder.replaceChildren();
 for(const r of filtered.slice(0,36)){
  const card=document.createElement('article');card.className='item';
  const heading=document.createElement('h3');heading.textContent=r.id;
  const short=document.createElement('small');short.textContent=r.severity.toUpperCase()+(r.regression?' · SOURCE REGRESSION':'');
  const detail=document.createElement('p');detail.textContent='Local stage: '+r.stage+' · Missing human references: '+r.missing.length+'/4';
  const note=document.createElement('p');note.textContent=r.missing.length?'Follow up on '+r.missing.join(', ')+'.':'All four references present (unverified).';
  card.append(short,heading,detail,note);holder.append(card);
 }
 if(filtered.length>36){const p=document.createElement('p');p.textContent='Showing the first 36 local human follow-up records. Filter by severity or export a private agenda.';holder.append(p);}
}
function download(filename,value,type){
 const u=URL.createObjectURL(new Blob([value],{type}));
 const a=document.createElement('a');a.href=u;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function csvCell(value){return '"'+String(value).replace(/"/g,'""')+'"';}
function aggregateCSV(){
 const lines=[['severity','source_findings','source_regressions','local_evidence_reference_gaps','human_changes_needed','estimated_hours','estimated_unscheduled_hours']];
 for(const s of LEVELS){
  const rs=joined.records.filter(r=>r.severity===s),band=joined.summary?.priority_bands?.[s];
  lines.push([s,rs.length,rs.filter(x=>x.regression).length,rs.filter(x=>x.missing.length).length,
   rs.filter(x=>x.stage==='needs_changes').length,band?band.estimated_hours:'',band?band.unscheduled_hours:'']);
 }
 return lines.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}
function privateMarkdown(){
 const escape=s=>human(s,200).replace(/[\\`*_{}\[\]()#+!|<>~]/g,'\\$&').replace(/\r?\n/g,' ');
 const lines=['# LightUp — private human remediation coordination handoff','',
  '**PRIVATE · UNSIGNED · PLAN/LAB ONLY · DRAFT/HOLD. NOT a verified security outcome, approval, scan permit or retest authorization.**','',
  'Canonical original source SHA-256 (content correlation only): '+joined.sha,
  'Original records: '+joined.records.length,'','## Human follow-up by original source severity',''];
 if(joined.summary)lines.push('Modelled backlog: '+joined.summary.backlog_hours+' hours; estimated staffing is not an assignment or SLA.','');
 for(const s of LEVELS){
  lines.push('### '+s);
  for(const r of joined.records.filter(x=>x.severity===s)){
   lines.push('- '+escape(r.id)+' · local: '+r.stage+' · source regression: '+(r.regression?'YES':'no')+
    ' · missing descriptive references: '+(r.missing.length?r.missing.join(', '):'none reported (UNVERIFIED)'));
  }
  lines.push('');
 }
 lines.push('Human recipient must independently confirm original engagement, current permissions, referenced records, remediation, consent, revocation, and any separately permitted retest. No automatic action was taken.','');
 return lines.join('\n');
}
$('load').addEventListener('click',()=>{load().catch(e=>{joined=null;$('results').hidden=true;status(e.message,true);});});
$('clear').addEventListener('click',()=>{wipe();status('Original and private drafts cleared from this page memory.');});
$('severity').addEventListener('change',render);$('kind').addEventListener('change',render);
$('aggregate').addEventListener('click',()=>{if(!joined)return;download('lightup-remediation-aggregate.csv',aggregateCSV(),'text/csv;charset=utf-8');});
$('private').addEventListener('click',()=>{
 try{if(!joined)return;checkSame();
  if(!confirm('PRIVATE original finding IDs will be exported. Have you independently checked the secure recipient and exact engagement?'))return;
  download('lightup-private-remediation-coordination.md',privateMarkdown(),'text/markdown;charset=utf-8');
 }catch(e){status(e.message,true);}
});
})();