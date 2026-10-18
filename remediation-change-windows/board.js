/* LightUp Change Window Board: untrusted human planning only, never a security authority. */
(()=>{'use strict';
const C=window.LightUpCasework;
if(!C)throw Error('Original pinned Casework module is required.');
const $=id=>document.getElementById(id);
const FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const FIELDS=['finding_id','title','severity','retest_status','remediation'];
const EVIDENCE=['change_reference','deployment_reference','rollback_reference','retest_request_reference','review_question'];
const STAGES=['missing','submitted','needs_changes','ready_for_authorized_retest'];
const MAX={change_reference:240,deployment_reference:240,rollback_reference:240,retest_request_reference:240,review_question:700};
const bidi=/[\u202a-\u202e\u2066-\u2069]/;
const HOURS=4;
let state=null,lastBulkSnapshot=null;
const setStatus=(value,error=false)=>{$('status').textContent=value;$('status').dataset.error=error?'true':'false';};
function fail(s){throw Error(s);}
function keys(o,allowed,required=allowed){
 if(!o||typeof o!=='object'||Array.isArray(o)||Object.getPrototypeOf(o)!==Object.prototype)fail('Invalid private JSON object.');
 if(Object.keys(o).some(k=>!allowed.includes(k))||required.some(k=>!Object.prototype.hasOwnProperty.call(o,k)))fail('Unexpected, ambiguous or missing private fields.');
}
function human(s,max){
 if(typeof s!=='string'||s.length>max||/[\u0000-\u001f\u007f]/.test(s)||bidi.test(s))fail('Invalid human note.');
 return s;
}
async function read(file,max){
 if(!file||file.size<1||file.size>max)fail('Private input missing or exceeds limit.');
 const buffer=await file.arrayBuffer();if(buffer.byteLength>max)fail('Private input exceeds limit.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer);
 if(!text||text.charCodeAt(0)===0xfeff)fail('UTF-8 BOM or empty private input.');
 return text;
}
/* Reject repeated keys BEFORE native JSON.parse; JSON.parse alone silently accepts them. */
function strictJSON(s){
 let i=0,count=0;const limit=40000;
 const ws=()=>{while(i<s.length&&/[ \t\n\r]/.test(s[i]))i++;};
 function str(){
  if(s[i]!=='"')fail('Malformed JSON string.');
  const start=i++;let escaped=false;
  while(i<s.length){const c=s[i++];
   if(escaped){escaped=false;continue;}
   if(c==='\\'){escaped=true;continue;}
   if(c==='"')return JSON.parse(s.slice(start,i));
   if(c<' ')fail('Malformed JSON control.');
  }fail('Unclosed JSON string.');
 }
 function val(depth){
  if(++count>limit||depth>26)fail('JSON structure too deep or large.');
  ws();const c=s[i];
  if(c==='{'){
   i++;ws();const found=new Set();if(s[i]==='}'){i++;return;}
   while(true){ws();const k=str();
    if(['__proto__','constructor','prototype'].includes(k)||found.has(k))fail('Duplicate or unsafe JSON key.');
    found.add(k);ws();if(s[i++]!==':')fail('Malformed JSON colon.');
    val(depth+1);ws();const next=s[i++];if(next==='}')return;
    if(next!==',')fail('Malformed JSON object.');ws();
   }
  }
  if(c==='['){i++;ws();if(s[i]===']'){i++;return;}
   while(true){val(depth+1);ws();const next=s[i++];if(next===']')return;
    if(next!==',')fail('Malformed JSON array.');ws();
   }
  }
  if(c==='"'){str();return;}
  const m=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!m)fail('Malformed JSON scalar.');i+=m[0].length;
 }
 val(0);ws();if(i!==s.length)fail('Trailing JSON content.');return JSON.parse(s);
}
/* Offline file:// fallback: SHA-256 on canonical original five-field source, no network. */
function localSha256(str){
 const bytes=new TextEncoder().encode(str),K=[
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
 const length=bytes.length,padded=new Uint8Array(Math.ceil((length+9)/64)*64);
 padded.set(bytes);padded[length]=0x80;
 const bits=length*8,offset=padded.length-8;
 for(let i=0;i<8;i++)padded[offset+i]=Math.floor(bits/2**(8*(7-i)))&255;
 const rotate=(n,k)=>(n>>>k)|(n<<(32-k));
 for(let off=0;off<padded.length;off+=64){
  const w=new Uint32Array(64);
  for(let i=0;i<16;i++){const j=off+4*i;w[i]=((padded[j]<<24)|(padded[j+1]<<16)|(padded[j+2]<<8)|padded[j+3])>>>0;}
  for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2];w[i]=(w[i-16]+(rotate(a,7)^rotate(a,18)^(a>>>3))+w[i-7]+(rotate(b,17)^rotate(b,19)^(b>>>10)))>>>0;}
  let [a,b,c,d,e,f,g,h]=H;
  for(let i=0;i<64;i++){const S1=rotate(e,6)^rotate(e,11)^rotate(e,25),ch=(e&f)^(~e&g);
   const t1=(h+S1+ch+K[i]+w[i])>>>0;const S0=rotate(a,2)^rotate(a,13)^rotate(a,22),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)>>>0;
   h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
  }
  const end=[a,b,c,d,e,f,g,h];for(let i=0;i<8;i++)H[i]=(H[i]+end[i])>>>0;
 }
 return H.map(n=>n.toString(16).padStart(8,'0')).join('');
}
async function digest(source){
 const canonical=JSON.stringify(C.normalizeSource(source).slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));
 const value=(await C.digest(source))||localSha256(canonical);
 if(!/^[a-f0-9]{64}$/.test(value)||value!==localSha256(canonical))fail('Original canonical source fingerprint mismatch.');
 return value;
}
function reviewFile(o,src,hash){
 keys(o,['kind','schema_version','disposition','source_contract','source_sha256','review','revision_register','warning',...FLAGS],
  ['kind','schema_version','disposition','source_contract','source_sha256','review',...FLAGS]);
 if(o.kind!=='lightup.remediation_evidence_coordination'||![1,2].includes(o.schema_version)||
    o.disposition!=='UNVERIFIED_OFFLINE_HUMAN_COORDINATION'||o.source_contract!=='lightup.finding_export._COLUMNS_v1'||
    o.source_sha256!==hash||FLAGS.some(k=>o[k]!==false))fail('Review is not bound to this exact original source or claims authority.');
 if(o.warning!==undefined)human(o.warning,1600);
 if(o.revision_register!==undefined&&(!Array.isArray(o.revision_register)||o.revision_register.length>12))fail('Invalid source revision length.');
 if(!Array.isArray(o.review)||o.review.length!==src.length)fail('Original review has incomplete finding coverage.');
 const ids=new Set(src.map(x=>x.finding_id)),seen=new Set(),result=new Map();
 for(const r of o.review){
  keys(r,['finding_id','stage','reference','reviewer','next_step','evidence'],
    ['finding_id','stage','reference','reviewer','next_step',...(o.schema_version===2?['evidence']:[])]);
  if(typeof r.finding_id!=='string'||!ids.has(r.finding_id)||seen.has(r.finding_id)||!STAGES.includes(r.stage))fail('Ambiguous, missing or duplicate original review row.');
  seen.add(r.finding_id);human(r.reference,240);human(r.reviewer,120);human(r.next_step,500);
  const ev={};
  if(r.evidence===undefined||r.evidence===null){
   if(o.schema_version===2)fail('Review v2 evidence fields missing.');
   EVIDENCE.forEach(k=>ev[k]='');
  }else{
   keys(r.evidence,EVIDENCE);
   for(const k of EVIDENCE)ev[k]=human(r.evidence[k],MAX[k]);
  }
  result.set(r.finding_id,{stage:r.stage,reviewer:r.reviewer,next_step:r.next_step,evidence:ev});
 }
 if(seen.size!==src.length)fail('Missing original review record.');
 return result;
}
function emptyReview(){
 return {stage:'missing',reviewer:'',next_step:'',evidence:Object.fromEntries(EVIDENCE.map(k=>[k,'']))};
}
function currentWindows(){
 const w=[];
 for(let i=0;i<HOURS;i++){
  const date=$('date'+i).value,duration=Number($('duration'+i).value),label=$('label'+i).value.trim();
  human(label,70);
  if(!date){if(label)fail('Named window has no UTC date.');w.push(null);continue;}
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(date))fail('Invalid proposed UTC time.');
  const stamp=new Date(date+'Z');
  if(Number.isNaN(stamp.getTime())||stamp.toISOString().slice(0,16)!==date)fail('Impossible proposed UTC date.');
  if(!Number.isInteger(duration)||duration<30||duration>480)fail('Window must be 30–480 minutes.');
  w.push({slot:i+1,label:label||'Human review '+(i+1),start_utc:stamp.toISOString(),minutes:duration});
 }
 return w;
}
function readiness(f,r){
 const lack=EVIDENCE.slice(0,4).filter(k=>!r.evidence[k]);
 const concerns=[];
 if(r.stage==='missing'||r.stage==='needs_changes')concerns.push('Local review '+r.stage);
 if(lack.length)concerns.push(lack.length+' missing local references');
 if(f.retest_status==='regression')concerns.push('Source reports regression');
 if(f.retest_status==='fixed')concerns.push('Source says fixed; not independently verified');
 if(r.stage==='ready_for_authorized_retest')concerns.push('Retest still requires separate authority');
 return concerns.length?concerns.join(' · '):'Human notes present; no verified remediation or approval';
}
function el(tag,txt){const n=document.createElement(tag);if(txt!==undefined)n.textContent=String(txt);return n;}

function hasHumanHold(f,r){
 return r.stage==='missing'||r.stage==='needs_changes'||EVIDENCE.slice(0,4).some(k=>!r.evidence[k]);
}
function visibleFinding(f,r){
 const severity=$('filter').value,human=$('humanFilter').value;
 if(severity&&severity!==f.severity)return false;
 if(human==='gaps'&&!hasHumanHold(f,r))return false;
 if(human==='complete'&&hasHumanHold(f,r))return false;
 if(human==='regression'&&f.retest_status!=='regression')return false;
 if(human==='critical'&&!['critical','high'].includes(f.severity))return false;
 return true;
}
function bulkApply(){
 if(!state)fail('Original source is not loaded.');
 const chosen=Number($('bulkWindow').value);
 if(!Number.isInteger(chosen)||chosen<0||chosen>HOURS)fail('Invalid human window slot.');
 const cohort=state.source.filter(f=>visibleFinding(f,state.review.get(f.finding_id)));
 if(!cohort.length)fail('Current human filter has no source findings.');
 if(!confirm('Apply a HUMAN-ONLY proposed window to '+cohort.length+' visible original finding(s)? This never changes source findings, notes, grants or retest statuses.'))return;
 lastBulkSnapshot=new Map(state.assignments);
 for(const f of cohort)state.assignments.set(f.finding_id,chosen);
 $('bulkUndo').disabled=false;
 render();setStatus('Applied one private human slot to '+cohort.length+' source records. No authorization or verified change.');
}
function bulkUndo(){
 if(!state||!lastBulkSnapshot)fail('No previous local bulk assignment to undo.');
 state.assignments=lastBulkSnapshot;lastBulkSnapshot=null;$('bulkUndo').disabled=true;
 render();setStatus('Most recent private bulk window selection undone. Original source and review notes unchanged.');
}

function render(){
 if(!state)return;
 const src=state.source,rows=$('findings');rows.replaceChildren();
 let unassigned=0,holds=0;
 for(const f of src){
  const r=state.review.get(f.finding_id);
  if(!state.assignments.has(f.finding_id))state.assignments.set(f.finding_id,0);
  if(!state.assignments.get(f.finding_id))unassigned++;
  if(r.stage==='missing'||r.stage==='needs_changes'||EVIDENCE.slice(0,4).some(k=>!r.evidence[k]))holds++;
  if(!visibleFinding(f,r))continue;
  const tr=el('tr'),id=el('td',f.finding_id),severity=el('td',f.severity),source=el('td',f.retest_status),
    stage=el('td',r.stage+' (human only)'),caveat=el('td',readiness(f,r)),slot=el('td');
  if(r.stage==='needs_changes'||r.stage==='missing')caveat.className='hold';
  const sel=el('select');sel.setAttribute('aria-label','Proposed human window for finding '+f.finding_id);
  sel.appendChild(new Option('Unassigned',0));
  for(let i=1;i<=HOURS;i++)sel.appendChild(new Option('Human window '+i,i));
  sel.value=String(state.assignments.get(f.finding_id)||0);
  sel.addEventListener('change',()=>{lastBulkSnapshot=null;$('bulkUndo').disabled=true;state.assignments.set(f.finding_id,Number(sel.value));render();});
  slot.appendChild(sel);
  for(const cell of [id,severity,source,stage,caveat,slot])tr.appendChild(cell);
  rows.appendChild(tr);
 }
 $('total').textContent=src.length;
 $('urgent').textContent=src.filter(f=>['critical','high'].includes(f.severity)).length;
 $('unassigned').textContent=unassigned;$('holds').textContent=holds;
 const board=$('summary');board.replaceChildren();
 try{
  const windows=currentWindows();for(let i=0;i<HOURS;i++){
   const assigned=src.filter(f=>state.assignments.get(f.finding_id)===i+1);
   const risky=assigned.filter(f=>{const r=state.review.get(f.finding_id);return r.stage==='missing'||r.stage==='needs_changes'||EVIDENCE.slice(0,4).some(k=>!r.evidence[k]);}).length;
   const card=el('div');const head=el('h3','Window '+(i+1)+(windows[i]?' · '+windows[i].label:' · not scheduled'));
   const detail=el('p',assigned.length+' source finding(s); '+risky+' human-reference HOLD(s); '+assigned.filter(f=>['critical','high'].includes(f.severity)).length+' critical/high. '+(windows[i]?windows[i].start_utc+' / '+windows[i].minutes+' min':'No UTC time.'));
   card.append(head,detail);board.appendChild(card);
  }
 }catch(e){const warn=el('p',e.message);warn.className='hold';board.appendChild(warn);}
}
async function load(){
 /* Atomic import: always discard old state on a new attempt, never keep stale source on error. */
 state=null;lastBulkSnapshot=null;$('bulkUndo').disabled=true;$('results').hidden=true;$('digest').textContent='';
 const file=$('csv').files[0],review=$('review').files[0];
 if(review&&!$('same').checked)fail('Independent exact client/engagement confirmation required for review join.');
 const src=C.parseCSV(await read(file,1048576)),hash=await digest(src);
 let notes=new Map(src.map(f=>[f.finding_id,emptyReview()]));
 if(review)notes=reviewFile(strictJSON(await read(review,2097152)),src,hash);
 state={source:src,hash,review:notes,assignments:new Map()};
 $('digest').textContent='Original canonical source SHA-256: '+hash+' · unsigned content correlation only; NOT identity or consent.';
 $('results').hidden=false;render();
 setStatus('Source loaded for private, unverified human planning. No permissions or retest inferred.');
}
function output(name,text,type){
 const blob=new Blob([text],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function plan(){
 if(!state)fail('Load original source before export.');
 const windows=currentWindows();
 for(const f of state.source){const slot=state.assignments.get(f.finding_id)||0;
  if(slot&&!windows[slot-1])fail('Assigned finding has no fully specified UTC window.');}
 const active=windows.filter(Boolean).sort((a,b)=>a.start_utc.localeCompare(b.start_utc));
 for(let i=1;i<active.length;i++){
  const end=Date.parse(active[i-1].start_utc)+active[i-1].minutes*60000;
  if(Date.parse(active[i].start_utc)<end)fail('Proposed UTC windows overlap: hold until human planning is corrected.');
 }
 human($('note').value,600);
 return windows;
}
function stats(windows){
 return windows.map((w,i)=>{
  const findings=state.source.filter(f=>state.assignments.get(f.finding_id)===i+1);
  const holds=findings.filter(f=>{const r=state.review.get(f.finding_id);
   return r.stage==='missing'||r.stage==='needs_changes'||EVIDENCE.slice(0,4).some(k=>!r.evidence[k]);}).length;
  return {slot:i+1,window:w,findings:findings.length,critical_high:findings.filter(f=>['critical','high'].includes(f.severity)).length,local_review_holds:holds};
 });
}

/* Private plan resume: full source, review and complete original membership,
 * count/authority integrity checked BEFORE any in-memory state/UI mutations. */
async function resumePlan(){
 if(!state)fail('Load original source before resuming a private plan.');
 if(!$('same').checked)fail('Independently confirm same original client and exact engagement.');
 const raw=strictJSON(await read($('planFile').files[0],2097152));
 const top=['kind','schema_version','disposition','source_contract','source_sha256','warning','windows','meeting_note','assignments',...FLAGS];
 keys(raw,top,top.filter(x=>x!=='warning'));
 if(raw.kind!=='lightup.remediation_human_change_windows'||raw.schema_version!==1||
    raw.disposition!=='DRAFT_UNVERIFIED_HUMAN_COORDINATION'||
    raw.source_contract!=='lightup.finding_export._COLUMNS_v1'||
    raw.source_sha256!==state.hash||FLAGS.some(k=>raw[k]!==false))
  fail('Plan is not an exact non-authorizing original-source-bound draft.');
 if(raw.warning!==undefined)human(raw.warning,800);
 human(raw.meeting_note,600);
 if(!Array.isArray(raw.windows)||raw.windows.length!==HOURS||
    !Array.isArray(raw.assignments)||raw.assignments.length!==state.source.length)
  fail('Incomplete proposed windows or source finding membership.');
 const restoredWindows=[],scheduled=[];
 for(let i=0;i<HOURS;i++){
  const entry=raw.windows[i];
  keys(entry,['slot','window','findings','critical_high','local_review_holds']);
  if(entry.slot!==i+1||!['findings','critical_high','local_review_holds'].every(k=>Number.isSafeInteger(entry[k])&&entry[k]>=0&&entry[k]<=350))
   fail('Invalid private window summary.');
  const w=entry.window;
  if(w===null){restoredWindows.push(null);continue;}
  keys(w,['slot','label','start_utc','minutes']);
  if(w.slot!==i+1)fail('Window slot identity mismatch.');
  human(w.label,70);
  if(!w.label||typeof w.start_utc!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/.test(w.start_utc))
   fail('Non-canonical proposed UTC start.');
  const d=new Date(w.start_utc);
  if(Number.isNaN(d.getTime())||d.toISOString()!==w.start_utc||
     !Number.isInteger(w.minutes)||w.minutes<30||w.minutes>480)
   fail('Invalid proposed UTC window.');
  scheduled.push(w);restoredWindows.push(w);
 }
 scheduled.sort((a,b)=>a.start_utc.localeCompare(b.start_utc));
 for(let i=1;i<scheduled.length;i++)
  if(Date.parse(scheduled[i].start_utc)<Date.parse(scheduled[i-1].start_utc)+scheduled[i-1].minutes*60000)
   fail('Proposed private windows overlap; do not apply stale plan.');
 const idMap=new Map(state.source.map(f=>[f.finding_id,f]));
 const imported=new Map();
 for(const row of raw.assignments){
  keys(row,['finding_id','original_severity','original_retest_status','human_stage','human_reviewer',
   'human_next_step','human_review_sha256','human_reference_gaps','proposed_window']);
  const f=idMap.get(row.finding_id);
  if(typeof row.finding_id!=='string'||!f||imported.has(row.finding_id)||
     row.original_severity!==f.severity||row.original_retest_status!==f.retest_status)
   fail('Private plan source finding identity drift or duplicate.');
  const r=state.review.get(f.finding_id);
  if(row.human_stage!==r.stage||row.human_reviewer!==r.reviewer||
     row.human_next_step!==r.next_step||
     row.human_review_sha256!==localSha256(JSON.stringify(r)))
   fail('Private plan references stale or altered human review notes.');
  const gaps=EVIDENCE.slice(0,4).filter(k=>!r.evidence[k]);
  if(!Array.isArray(row.human_reference_gaps)||JSON.stringify(gaps)!==JSON.stringify(row.human_reference_gaps))
   fail('Human evidence-gap baseline changed.');
  if(!Number.isInteger(row.proposed_window)||row.proposed_window<0||row.proposed_window>HOURS||
     (row.proposed_window>0&&!restoredWindows[row.proposed_window-1]))
   fail('Invalid or unscheduled human window assignment.');
  imported.set(f.finding_id,row.proposed_window);
 }
 if(imported.size!==idMap.size)fail('Private plan lacks complete original source membership.');
 for(let i=0;i<HOURS;i++){
  const findings=state.source.filter(f=>imported.get(f.finding_id)===i+1);
  const holds=findings.filter(f=>{const r=state.review.get(f.finding_id);
   return r.stage==='missing'||r.stage==='needs_changes'||EVIDENCE.slice(0,4).some(k=>!r.evidence[k]);}).length;
  const entry=raw.windows[i];
  if(entry.findings!==findings.length||
     entry.critical_high!==findings.filter(f=>['critical','high'].includes(f.severity)).length||
     entry.local_review_holds!==holds)
   fail('Private window aggregate contradicts original source/review records.');
 }
 /* All admissions are complete; apply the whole human draft in one step. */
 state.assignments=imported;lastBulkSnapshot=null;$('bulkUndo').disabled=true;
 for(let i=0;i<HOURS;i++){
  const w=restoredWindows[i];$('date'+i).value=w?w.start_utc.slice(0,16):'';
  $('label'+i).value=w?w.label:'';$('duration'+i).value=String(w?w.minutes:60);
 }
 $('note').value=raw.meeting_note;render();
 setStatus('Private planning draft restored against exact original source and unchanged human review. No authority inferred.');
}

function privateExport(){
 if(!confirm('PRIVATE: export original finding IDs and unverified human notes for an independently approved confidential recipient?'))return;
 const windows=plan(),detail=stats(windows);
 const artifact={
  kind:'lightup.remediation_human_change_windows',schema_version:1,
  disposition:'DRAFT_UNVERIFIED_HUMAN_COORDINATION',source_contract:'lightup.finding_export._COLUMNS_v1',
  source_sha256:state.hash,warning:'Unsigned and non-authorizing; source absence or scheduled stage never means verified remediation.',
  windows:detail,meeting_note:human($('note').value,600),
  assignments:state.source.map(f=>{
   const r=state.review.get(f.finding_id);
   return {finding_id:f.finding_id,original_severity:f.severity,original_retest_status:f.retest_status,
    human_stage:r.stage,human_reviewer:r.reviewer,human_next_step:r.next_step,
    human_review_sha256:localSha256(JSON.stringify(r)),
    human_reference_gaps:EVIDENCE.slice(0,4).filter(k=>!r.evidence[k]),
    proposed_window:state.assignments.get(f.finding_id)||0};
  })
 };
 for(const k of FLAGS)artifact[k]=false;
 output('lightup-private-human-change-windows.json',JSON.stringify(artifact,null,2)+'\n','application/json');
}
function calendarExport(){
 const windows=plan(),v=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LightUp//Human Draft Only//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH'];
 const fmt=t=>t.toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
 windows.filter(Boolean).forEach(w=>{
  const date=new Date(w.start_utc),end=new Date(date.getTime()+w.minutes*60000);
  v.push('BEGIN:VEVENT','UID:lightup-human-proposal-slot-'+w.slot+'@offline.invalid','DTSTAMP:19700101T000000Z',
   'DTSTART:'+fmt(date),'DTEND:'+fmt(end),
   'SUMMARY:LightUp hypothetical human review slot '+w.slot,
   'DESCRIPTION:UNVERIFIED HUMAN PLANNING ONLY. No target data or permission. Confirm authorization and consent separately.',
   'STATUS:TENTATIVE','END:VEVENT');
 });
 v.push('END:VCALENDAR');
 output('lightup-identity-free-tentative-windows.ics',v.join('\r\n')+'\r\n','text/calendar');
}
function aggregateExport(){
 const windows=plan();
 const data=['window_slot,proposed_start_utc,minutes,source_findings,critical_high,local_reference_holds'];
 for(const row of stats(windows))data.push([row.slot,row.window?.start_utc||'',row.window?.minutes||0,row.findings,row.critical_high,row.local_review_holds].join(','));
 output('lightup-aggregate-human-windows.csv',data.join('\r\n')+'\r\n','text/csv');
}
function forget(){
 state=null;lastBulkSnapshot=null;$('bulkUndo').disabled=true;for(const id of ['csv','review','planFile'])$(id).value='';
 $('same').checked=false;$('note').value='';$('digest').textContent='';$('results').hidden=true;
 for(let i=0;i<HOURS;i++){$('date'+i).value='';$('label'+i).value='';$('duration'+i).value='60';}
 setStatus('All loaded original data and human window assignments forgotten from this tab.');
}
function init(){
 for(let i=0;i<HOURS;i++){
  const wrapper=el('div'),h=el('h3','Human window '+(i+1));
  const name=el('label','Optional discussion label'),text=el('input');text.id='label'+i;text.maxLength=70;text.placeholder='Optional private planning label';name.appendChild(text);
  const dateLabel=el('label','Proposed start (UTC)'),date=el('input');date.id='date'+i;date.type='datetime-local';dateLabel.appendChild(date);
  const minLabel=el('label','Duration minutes'),min=el('input');min.id='duration'+i;min.type='number';min.min='30';min.max='480';min.step='30';min.value='60';minLabel.appendChild(min);
  wrapper.append(h,name,dateLabel,minLabel);$('windows').appendChild(wrapper);
  for(const input of [text,date,min])input.addEventListener('change',()=>{if(state)render();});
 }
 $('load').addEventListener('click',()=>load().catch(e=>{state=null;$('results').hidden=true;setStatus(e.message,true);}));
 $('forget').addEventListener('click',forget);
 $('resume').addEventListener('click',()=>resumePlan().catch(e=>setStatus(e.message,true)));
 $('filter').addEventListener('change',render);
 $('humanFilter').addEventListener('change',render);
 $('bulkApply').addEventListener('click',()=>{try{bulkApply();}catch(e){setStatus(e.message,true);}});
 $('bulkUndo').addEventListener('click',()=>{try{bulkUndo();}catch(e){setStatus(e.message,true);}});
 $('recalculate').addEventListener('click',()=>{try{plan();render();setStatus('Hypothetical windows checked for overlap; original authority remains HOLD.');}catch(e){setStatus(e.message,true);}});
 for(const [id,fn] of [['private',privateExport],['calendar',calendarExport],['aggregate',aggregateExport]])
  $(id).addEventListener('click',()=>{try{fn();setStatus('Local unsigned planning export prepared; not authorization or verified evidence.');}catch(e){setStatus(e.message,true);}});
}
init();
})();