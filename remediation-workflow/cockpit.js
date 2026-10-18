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
let joined=null,preloadedSource=null;
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
/* Exact original five-field source plus complete original local Casework.
 * A self-reported owner/date/status never proves remediation or approval. */
function caseworkDocument(packet,source,sha){
 const permitted=['kind','schema_version','disposition',...FLAGS,'source_contract',
   'source_sha256','findings','cases','instructions'];
 keysExact(packet,permitted);
 if(packet.source_sha256!==sha||FLAGS.some(k=>packet[k]!==false))
  fail('Casework has a missing/different canonical source fingerprint or claims authority.');
 const loaded=C.loadPacket(packet);
 if(loaded.findings.length!==source.length||loaded.cases.length!==source.length)
  fail('Incomplete original Casework records.');
 const reference=new Map(source.map(x=>[x.finding_id,x]));
 for(const f of loaded.findings){
  const original=reference.get(f.finding_id);
  if(!original||FIELDS.some(k=>f[k]!==original[k]))
   fail('Original Casework source fields mismatch current CSV.');
 }
 const cases=new Map();
 const today=new Date().toISOString().slice(0,10);
 for(const c of loaded.cases){
  if(cases.has(c.finding_id))fail('Duplicate local Casework record.');
  const active=c.status!=='completed'&&c.status!=='deferred';
  cases.set(c.finding_id,{
   stage:c.status,blocked:c.status==='blocked',overdue:active&&!!c.due_date&&c.due_date<today,
   unowned:!c.owner.trim()
  });
 }
 if(cases.size!==source.length)fail('Incomplete Casework plan.');
 return cases;
}
function wipe(){
 joined=null;$('results').hidden=true;$('digest').textContent='';
 preloadedSource=null;$('csv').value='';$('previous').value='';$('evidence').value='';$('casework').value='';$('capacity').value='';$('same').checked=false;
 $('severity').value='';$('kind').value='';$('agenda').replaceChildren();$('matrix').replaceChildren();
}
/* Original authenticated interactive export embeds passive data, not credentials.
 * This saved HTML can never prove current permission or source freshness. */
function localSha256(text){
 const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const bytes=new TextEncoder().encode(text),len=bytes.length;
 const padded=new Uint8Array(Math.ceil((len+9)/64)*64);padded.set(bytes);padded[len]=0x80;
 const bits=BigInt(len)*8n;for(let j=0;j<8;j++)padded[padded.length-1-j]=Number((bits>>BigInt(j*8))&255n);
 const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
 const rotate=(x,n)=>(x>>>n)|(x<<(32-n)),w=new Uint32Array(64);
 for(let off=0;off<padded.length;off+=64){
  for(let i=0;i<16;i++){const j=off+4*i;w[i]=((padded[j]<<24)|(padded[j+1]<<16)|(padded[j+2]<<8)|padded[j+3])>>>0;}
  for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2],s0=rotate(a,7)^rotate(a,18)^(a>>>3),s1=rotate(b,17)^rotate(b,19)^(b>>>10);
   w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}
  let [a,b,c,d,e,f,g,h]=H;
  for(let i=0;i<64;i++){const S1=rotate(e,6)^rotate(e,11)^rotate(e,25),ch=(e&f)^(~e&g);
   const t1=(h+S1+ch+K[i]+w[i])>>>0;
   const S0=rotate(a,2)^rotate(a,13)^rotate(a,22),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)>>>0;
   h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
  }
  const end=[a,b,c,d,e,f,g,h];for(let i=0;i<8;i++)H[i]=(H[i]+end[i])>>>0;
 }
 return H.map(x=>x.toString(16).padStart(8,'0')).join('');
}

async function canonicalSourceHash(findings){
 const digest=await C.digest(findings);
 if(digest)return digest;
 const original=C.normalizeSource(findings);
 const canonical=JSON.stringify(original.slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));
 return localSha256(canonical);
}
async function sourceRawHash(csv){
 if(typeof csv!=='string'||size(csv)>1048576)
  fail('Exact raw source SHA-256 is unavailable.');
 if(!window.crypto?.subtle)return localSha256(csv);
 const result=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(csv));
 return Array.from(new Uint8Array(result),x=>x.toString(16).padStart(2,'0')).join('');
}
async function importPreloadedSource(){
 const node=$('preloadedCsv');
 if(!node)return;
 try{
  if(size(node.textContent)>1400200)fail('Embedded original source envelope too large.');
  const packet=strictJSON(node.textContent);
  keysExact(packet,['format','csv_base64']);
  if(packet.format!=='lightup.authenticated_findings_handoff_v1'||
     typeof packet.csv_base64!=='string'||packet.csv_base64.length>1400000||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(packet.csv_base64))
   fail('Malformed original private handoff envelope.');
  const bytes=Uint8Array.from(atob(packet.csv_base64),c=>c.charCodeAt(0));
  if(!bytes.length||bytes.length>1048576)fail('Private findings exceed original source bound.');
  const csv=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  C.parseCSV(csv);
  preloadedSource=csv;
  await load();
  status('Original summary imported from the login-protected export at creation time. Saved HTML is PRIVATE and does not prove current authentication, consent, revocation or retest.');
 }catch(error){preloadedSource=null;status('Private source rejected: '+error.message,true);}
 finally{node.remove();}
}
const checkSame=()=>{if(!$('same').checked)fail('Independently confirm the SAME original client and exact engagement before joining sources.');};
async function load(){
 joined=null;$('results').hidden=true;$('digest').textContent='';status('Checking original source and private draft links …');
 const file=$('csv').files[0];
 const extra=$('previous').files.length||$('evidence').files.length||$('casework').files.length||$('capacity').files.length;
 if(extra)checkSame();
 const csv=file?await readFile(file,1048576):preloadedSource;
 if(!csv)fail('First select an original authorized CSV or create the private authenticated handoff CLI export.');
 const source=C.parseCSV(csv),sha=await canonicalSourceHash(source);
 if(!sha||!/^[a-f0-9]{64}$/.test(sha))fail('Canonical original source SHA-256 is unavailable; no unsafe fallback.');
 const evidence=$('evidence').files.length?
  reviewDocument(strictJSON(await readFile($('evidence').files[0],2097152)),source,sha):
  new Map(source.map(f=>[f.finding_id,{stage:'missing',evidence:Object.fromEntries(EVIDENCE.map(name=>[name,'']))}]));
 let capacity=null, summary=null, casework=null, revision=null;
 if($('previous').files.length){
  const previous=C.parseCSV(await readFile($('previous').files[0],1048576));
  const oldSha=await canonicalSourceHash(previous);
  if(!oldSha||oldSha===sha)fail('Older original source must be a distinct, canonical original snapshot.');
  revision={original:C.compareSource(previous,source),oldSha};
 }
 if($('casework').files.length){
  const packet=strictJSON(await readFile($('casework').files[0],2097152));
  casework=caseworkDocument(packet,source,sha);
 }
 if($('capacity').files.length){
  const capacityText=await readFile($('capacity').files[0],D.MAX_DRAFT_BYTES);
  const capacityRows=P.parseCSV(csv);
  const rawSha=file&&window.crypto?.subtle?await D.fingerprint(file):await sourceRawHash(csv);
  const draft=D.importDraft(capacityText,rawSha,source.length,capacityRows,P);
  capacity=draft.plan;summary=P.summary(capacity);
  if(!summary||summary.source_count!==source.length)fail('Capacity source count mismatch.');
 }
 const records=source.map(f=>{
  const rev=evidence.get(f.finding_id), missing=EVIDENCE.slice(0,4).filter(k=>!rev.evidence[k].trim());
  const urgent=LEVELS.indexOf(f.severity);
  const c=casework?.get(f.finding_id)||{stage:'none',blocked:false,overdue:false,unowned:false};
  const changed=revision&&new Set(revision.original.changed.map(x=>x.finding_id)).has(f.finding_id);
  const isNew=revision?.original.added.includes(f.finding_id)||false;
  return {id:f.finding_id,severity:f.severity,regression:f.retest_status==='regression',sourceChanged:!!changed,sourceNew:!!isNew,
   stage:rev.stage,caseStage:c.stage,blocked:c.blocked,overdue:c.overdue,unowned:c.unowned,missing,
   priority:(5-urgent)*30+(f.retest_status==='regression'?45:0)+missing.length*7+
    (rev.stage==='needs_changes'?25:0)+(c.blocked?35:0)+(c.overdue?25:0)+(changed?20:0)+(isNew?25:0)};
 }).sort((a,b)=>b.priority-a.priority||a.id.localeCompare(b.id));
 joined={records,sha,summary,revision};
 $('results').hidden=false;$('digest').textContent='Unsigned canonical findings fingerprint: '+sha+
   (summary?' · capacity assumptions bound to the original raw CSV SHA-256':' · no optional staffing draft loaded');
 render();status('Loaded '+source.length+' original findings with '+($('evidence').files.length?'private review notes':'empty local review notes')+(summary?' and exact-CSV capacity estimates':'')+'. No permissions, retests or repairs inferred.');
}
function render(){
 if(!joined)return;
 const {records,summary,revision}=joined;
 renderRevision();
 $('count').textContent=records.length;
 $('urgent').textContent=records.filter(r=>r.severity==='critical'||r.severity==='high').length;
 $('gaps').textContent=records.filter(r=>r.missing.length).length;
 $('regressions').textContent=records.filter(r=>r.regression).length;
 $('blocked').textContent=records.filter(r=>r.blocked).length;
 $('overdue').textContent=records.filter(r=>r.overdue).length;
 $('backlog').textContent=summary?String(summary.backlog_hours)+' h':'—';
 $('available').textContent=summary?String(summary.sprint_weeks.reduce((n,w)=>n+w.available_hours,0))+' h':'—';
 const tbody=$('matrix');tbody.replaceChildren();
 for(const severity of LEVELS){
  const rs=records.filter(r=>r.severity===severity),b=summary?.priority_bands?.[severity];
  const cells=[severity,rs.length,rs.filter(r=>r.regression).length,
   rs.filter(r=>r.missing.length).length,rs.filter(r=>r.stage==='needs_changes').length,
   rs.filter(r=>r.blocked).length,rs.filter(r=>r.overdue).length,
   b?b.estimated_hours+' h':'not modelled'];
  const tr=document.createElement('tr');
  for(const cell of cells){const td=document.createElement('td');td.textContent=String(cell);tr.append(td);}
  tbody.append(tr);
 }
 const filtered=records.filter(r=>(!$('severity').value||r.severity===$('severity').value)&&
   (!$('kind').value||($('kind').value==='missing'&&r.missing.length)||
   ($('kind').value==='changes'&&r.stage==='needs_changes')||
   ($('kind').value==='regression'&&r.regression)||
   ($('kind').value==='blocked'&&r.blocked)||($('kind').value==='overdue'&&r.overdue)||
   ($('kind').value==='new'&&r.sourceNew)||($('kind').value==='changed'&&r.sourceChanged)));
 $('queueCount').textContent=filtered.length;
 const holder=$('agenda');holder.replaceChildren();
 for(const r of filtered.slice(0,36)){
  const card=document.createElement('article');card.className='item';
  const heading=document.createElement('h3');heading.textContent=r.id;
  const short=document.createElement('small');short.textContent=r.severity.toUpperCase()+(r.regression?' · SOURCE REGRESSION':'')+(r.sourceNew?' · NEW ORIGINAL ID':'')+(r.sourceChanged?' · SOURCE CHANGED':'');
  const detail=document.createElement('p');detail.textContent='Local review: '+r.stage+' · Local Casework: '+r.caseStage+
   (r.blocked?' (blocked)':'')+(r.overdue?' (overdue plan)':'')+' · Missing references: '+r.missing.length+'/4';
  const note=document.createElement('p');note.textContent=r.missing.length?'Follow up on '+r.missing.join(', ')+'.':'All four references present (unverified).';
  card.append(short,heading,detail,note);holder.append(card);
 }
 if(filtered.length>36){const p=document.createElement('p');p.textContent='Showing the first 36 local human follow-up records. Filter by severity or export a private agenda.';holder.append(p);}
}
function renderRevision(){
 const r=joined?.revision,box=$('absentList');box.replaceChildren();
 const counts={newCount:r?.original.added.length,changedCount:r?.original.changed.length,absentCount:r?.original.missing.length,sameCount:r?.original.unchanged.length};
 for(const [id,n] of Object.entries(counts))$(id).textContent=n===undefined?'—':String(n);
 $('revisionDigest').textContent=r?'Previous unsigned digest: '+r.oldSha+' · current: '+joined.sha:
  'No historical source selected. Comparison is optional and never evidence of verified remediation.';
 if(!r)return;
 for(const id of r.original.missing.slice(0,24)){
  const item=document.createElement('article');item.className='item';
  const name=document.createElement('h3');name.textContent=id;
  const message=document.createElement('p');message.textContent='ABSENT from current original export — NEVER automatically fixed or verified.';
  item.append(name,message);box.append(item);
 }
 if(r.original.missing.length>24){
  const note=document.createElement('p');note.textContent='Showing first 24 absent IDs; use private source follow-up JSON for full register.';
  box.append(note);
 }
}
function diffPayload(privateDetails){
 if(!joined?.revision)return null;
 const d=joined.revision.original;
 const envelope={kind:privateDetails?'lightup.private_original_source_followup':'lightup.source_revision_aggregate',
  schema_version:1,disposition:privateDetails?'UNVERIFIED_PRIVATE_HUMAN_REVIEW':'UNVERIFIED_OFFLINE_SOURCE_DELTA',
  source_sha256:joined.sha,previous_source_sha256:joined.revision.oldSha,
  authenticated:false,grant:false,retest_verified:false,release:false,
  warning:'Source absence/changes are not evidence of repair, consent, scope or retest.'};
 return privateDetails?{...envelope,added:d.added,changed:d.changed,absent_unverified:d.missing,unchanged:d.unchanged}:
  {...envelope,counts:{added:d.added.length,changed:d.changed.length,absent_unverified:d.missing.length,unchanged:d.unchanged.length}};
}
function download(filename,value,type){
 const u=URL.createObjectURL(new Blob([value],{type}));
 const a=document.createElement('a');a.href=u;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function csvCell(value){return '"'+String(value).replace(/"/g,'""')+'"';}
function aggregateCSV(){
 const lines=[['severity','source_findings','source_regressions','local_evidence_reference_gaps','human_changes_needed','casework_blocked','casework_overdue','new_original_ids','changed_original_records','estimated_hours','estimated_unscheduled_hours']];
 for(const s of LEVELS){
  const rs=joined.records.filter(r=>r.severity===s),band=joined.summary?.priority_bands?.[s];
  lines.push([s,rs.length,rs.filter(x=>x.regression).length,rs.filter(x=>x.missing.length).length,
   rs.filter(x=>x.stage==='needs_changes').length,rs.filter(x=>x.blocked).length,
   rs.filter(x=>x.overdue).length,rs.filter(x=>x.sourceNew).length,rs.filter(x=>x.sourceChanged).length,band?band.estimated_hours:'',band?band.unscheduled_hours:'']);
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
    ' · original change: '+(r.sourceNew?'new ID':r.sourceChanged?'changed fields':'no new change')+' · local Casework: '+r.caseStage+(r.blocked?' (BLOCKED)':'')+(r.overdue?' (OVERDUE)':'')+
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
$('fundingExport').addEventListener('click',()=>{
 try{
  if(!joined?.summary)fail('Import an exact-source Capacity Studio working draft before exporting its original aggregate summary.');
  checkSame();
  if(!confirm('Export the original unsigned aggregate Capacity Studio summary for offline Funding Studio? No client IDs, approval, fixes or permissions are included.'))return;
  const data=JSON.stringify(joined.summary,null,2)+'\n';
  if(size(data)>65536)fail('Aggregate exceeds original funding intake bound.');
  download('lightup-capacity-draft.json',data,'application/json;charset=utf-8');
  status('Original aggregate Capacity Studio JSON exported for separate offline Funding Studio review. No client source IDs included.');
 }catch(e){status(e.message,true);}
});
$('revisionAggregate').addEventListener('click',()=>{
 if(!joined?.revision){status('First load a previous original source CSV.',true);return;}
 download('lightup-original-source-delta-aggregate.json',
  JSON.stringify(diffPayload(false),null,2)+'\n','application/json;charset=utf-8');
});
$('revisionPrivate').addEventListener('click',()=>{
 try{
  if(!joined?.revision)fail('First load a previous original source CSV.');
  checkSame();
  if(!confirm('This PRIVATE file includes original finding IDs and changed field names. Independently confirm authorized recipient and same client/engagement.'))return;
  download('lightup-original-source-followup-PRIVATE.json',
   JSON.stringify(diffPayload(true),null,2)+'\n','application/json;charset=utf-8');
 }catch(e){status(e.message,true);}
});
$('aggregate').addEventListener('click',()=>{if(!joined)return;download('lightup-remediation-aggregate.csv',aggregateCSV(),'text/csv;charset=utf-8');});
$('private').addEventListener('click',()=>{
 try{if(!joined)return;checkSame();
  if(!confirm('PRIVATE original finding IDs will be exported. Have you independently checked the secure recipient and exact engagement?'))return;
  download('lightup-private-remediation-coordination.md',privateMarkdown(),'text/markdown;charset=utf-8');
 }catch(e){status(e.message,true);}
});
void importPreloadedSource();
})();