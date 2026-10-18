/* Offline human remediation-evidence coordination. NEVER a scanner, verifier or authorization source. */
(()=>{'use strict';
const engine=window.LightUpCasework;
if(!engine)throw Error('Original LightUp Casework source module required.');
const $=id=>document.getElementById(id);
const LIMIT_CSV=1048576, LIMIT_JSON=2097152;
const DECISIONS=Object.freeze(['missing','submitted','needs_changes','ready_for_authorized_retest']);
let source=null,casework=null,sourceHash=null,review=new Map(),changed=false,refreshCandidate=null,revisions=[];
const SEV=engine.SEVERITY;
const flags=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
function status(message,error=false){$('status').textContent=message;$('status').dataset.error=error?'true':'false';}
function bytes(str){return new TextEncoder().encode(str).length;}
async function read(file,cap){
 if(!file||file.size>cap)throw Error('File missing or exceeds private intake size limit.');
 const b=await file.arrayBuffer();const txt=new TextDecoder('utf-8',{fatal:true}).decode(b);
 if(bytes(txt)>cap||txt.charCodeAt(0)===0xfeff)throw Error('Invalid file size or UTF-8 BOM.');
 return txt;
}
/* Strict JSON syntax and duplicate object property rejection before normal JSON.parse. */
function strictJSON(s){
 let i=0,n=0;const maxDepth=24,maxNodes=40000;
 const ws=()=>{while(i<s.length&&/[ \t\r\n]/.test(s[i]))i++;};
 function quoted(){
  if(s[i]!=='"')throw Error('Expected JSON string.');
  const start=i++;let escaped=false,ended=false;
  while(i<s.length){const ch=s[i++];
   if(escaped){escaped=false;continue;}
   if(ch==='\\'){escaped=true;continue;}
   if(ch==='"'){ended=true;break;}
   if(ch<' ')throw Error('Invalid JSON string control.');
  }
  if(!ended)throw Error('Unclosed JSON string.');
  return JSON.parse(s.slice(start,i));
 }
 function value(depth){
  if(++n>maxNodes||depth>maxDepth)throw Error('JSON structure limit exceeded.');
  ws();const ch=s[i];
  if(ch==='{'){
   i++;ws();const names=new Set();if(s[i]==='}'){i++;return;}
   while(true){
    ws();const key=quoted();if(names.has(key))throw Error('Repeated JSON object key.');
    names.add(key);ws();if(s[i++]!==':')throw Error('Expected JSON colon.');
    value(depth+1);ws();const end=s[i++];if(end==='}')return;
    if(end!==',')throw Error('Expected JSON comma.');ws();
   }
  }
  if(ch==='['){i++;ws();if(s[i]===']'){i++;return;}while(true){
   value(depth+1);ws();const end=s[i++];if(end===']')return;
   if(end!==',')throw Error('Expected array comma.');ws();
  }}
  if(ch==='"'){quoted();return;}
  const matched=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
  if(!matched)throw Error('Invalid JSON value.');
  i+=matched[0].length;
 }
 value(0);ws();if(i!==s.length)throw Error('Trailing JSON content.');
 return JSON.parse(s);
}
function exactFields(a,b){return ['finding_id','title','severity','retest_status','remediation'].every(k=>a[k]===b[k]);}
function safeText(v,max){return typeof v==='string'&&v.length<=max&&![...v].some(c=>c==='\u0000') ? v : null;}
function validReview(row,ids){
 if(!row||Object.getPrototypeOf(row)!==Object.prototype||!ids.has(row.finding_id))throw Error('Unknown review finding.');
 if(!DECISIONS.includes(row.stage))throw Error('Unsupported review stage.');
 const reference=safeText(row.reference,240),reviewer=safeText(row.reviewer,120),next=safeText(row.next_step,500);
 if(reference===null||reviewer===null||next===null)throw Error('Invalid review text.');
 return {finding_id:row.finding_id,stage:row.stage,reference,reviewer,next_step:next};
}
function stageStart(id){return {finding_id:id,stage:'missing',reference:'',reviewer:'',next_step:''};}
function snapshot(){
 if(!source)return null;
 return {kind:'lightup.remediation_evidence_coordination',schema_version:1,
  disposition:'UNVERIFIED_OFFLINE_HUMAN_COORDINATION',source_contract:'lightup.finding_export._COLUMNS_v1',
  source_sha256:sourceHash,authenticated:false,tenant_verified:false,source_authorized:false,
  assessment_authorized:false,grant:false,client_consent:false,operator_consent:false,
  execution:false,scan:false,audit_verdict:false,retest_verified:false,release:false,
  review:source.map(f=>review.get(f.finding_id)),
  revision_register:revisions,
  warning:'References and local stages are unverified human notes, not evidence authenticity, remediation proof or retest results.'};
}
function download(name,data,type){
 const blob=new Blob([data],{type});const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);
}
function updateSource(newSource,matchedCases){
 source=newSource;casework=matchedCases;review=new Map(newSource.map(f=>[f.finding_id,stageStart(f.finding_id)]));
 changed=false;refreshCandidate=null;revisions=[];render();
}

/* Original-source revision register is human archival context, never source proof.
 * This persists missing/changed IDs from an explicitly acknowledged refresh. */
const SOURCE_FIELDS=['finding_id','title','severity','retest_status','remediation'];
function checkedIds(values){
 if(!Array.isArray(values)||values.length>350)throw Error('Revision list outside bounds.');
 const ids=new Set();
 for(const id of values){
  if(typeof id!=='string'||!id.trim()||id.length>160||ids.has(id))throw Error('Invalid source revision finding identity.');
  ids.add(id);
 }
 return values.slice();
}
function validRevision(entry){
 const sha=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
 if(!entry||Object.getPrototypeOf(entry)!==Object.prototype||
    !sha(entry.from_sha256)||!sha(entry.to_sha256)||entry.from_sha256===entry.to_sha256)
  throw Error('Malformed original source revision envelope.');
 const added=checkedIds(entry.added),missing=checkedIds(entry.missing),
  unchanged=checkedIds(entry.unchanged);
 if(!Array.isArray(entry.changed)||entry.changed.length>350)throw Error('Invalid source change list.');
 const changed=entry.changed.map(x=>{
  if(!x||typeof x!=='object'||Array.isArray(x)||
     typeof x.finding_id!=='string'||!x.finding_id.trim()||x.finding_id.length>160||
     !Array.isArray(x.changed_fields)||!x.changed_fields.length||x.changed_fields.length>5||
     new Set(x.changed_fields).size!==x.changed_fields.length||
     x.changed_fields.some(k=>!SOURCE_FIELDS.includes(k)))throw Error('Invalid changed source record.');
  return {finding_id:x.finding_id,changed_fields:x.changed_fields.slice()};
 });
 const all=[...added,...missing,...unchanged,...changed.map(x=>x.finding_id)];
 if(all.length>700)throw Error('Source revision exceeds safe bounds.');
 if(new Set(all).size!==all.length)throw Error('Overlapping source revision categories.');
 return {from_sha256:entry.from_sha256,to_sha256:entry.to_sha256,
  added,missing,unchanged,changed};
}
function restoreRevisions(raw,currentHash){
 if(raw===undefined)return []; /* original unmodified v1 review packets */
 if(!Array.isArray(raw)||raw.length>12)throw Error('Invalid revision register length.');
 const parsed=raw.map(validRevision);
 for(let j=1;j<parsed.length;j++){
  if(parsed[j].from_sha256!==parsed[j-1].to_sha256)throw Error('Discontinuous original source revision register.');
 }
 if(parsed.length&&parsed[parsed.length-1].to_sha256!==currentHash)
  throw Error('Source revision register does not match current original CSV.');
 return parsed;
}
function renderRevisions(){
 const parent=$('revisionList');parent.replaceChildren();
 $('revisionCount').textContent=String(revisions.length);
 if(!revisions.length){parent.append(el('p','detail','No original source revision has been acknowledged in this local session.'));return;}
 for(let i=revisions.length-1;i>=0;i--){
  const x=revisions[i],card=el('details','panel'),summary=el('summary','',
    'Revision '+(i+1)+': '+x.added.length+' added · '+x.changed.length+' changed · '+
    x.missing.length+' absent (NOT fixed) · '+x.unchanged.length+' unchanged');
  card.append(summary);
  card.append(el('p','detail','Previous SHA-256 '+x.from_sha256+' → new '+x.to_sha256+' (unsigned content correlation)'));
  const list=el('ul','cues');
  const changes=[...x.added.map(id=>['Added',id]),...x.changed.map(y=>['Changed: '+y.changed_fields.join('/'),y.finding_id]),
    ...x.missing.map(id=>['ABSENT, not fixed',id])];
  for(const [state,id] of changes)list.append(el('li','',state+' · '+id));
  if(!changes.length)list.append(el('li','','No added, changed or absent rows; original record order or representation changed.'));
  card.append(list);parent.append(card);
 }
}
function localDay(date){
 return String(date.getFullYear()).padStart(4,'0')+'-'+String(date.getMonth()+1).padStart(2,'0')+'-'+String(date.getDate()).padStart(2,'0');
}
function localWindow(){
 const now=new Date(),end=new Date(now.getFullYear(),now.getMonth(),now.getDate()+7);
 return {today:localDay(now),next7:localDay(end)};
}
function count(){
 const metrics={total:source.length,urgent:0,no_reference:0,needs_changes:0,retest:0,contradictions:0,blocked:0,overdue:0,next7:0};
 const window=localWindow();
 for(const f of source){
  const r=review.get(f.finding_id),c=casework?.get(f.finding_id);
  if(SEV.indexOf(f.severity)<=1)metrics.urgent++;
  if(c?.status==='blocked')metrics.blocked++;
  if(c?.due_date&&c.status!=='completed'&&c.status!=='deferred'){
   if(c.due_date<window.today)metrics.overdue++;
   else if(c.due_date<=window.next7)metrics.next7++;
  }
  if(!r.reference.trim())metrics.no_reference++;
  if(r.stage==='needs_changes')metrics.needs_changes++;
  if(r.stage==='ready_for_authorized_retest')metrics.retest++;
  if((r.stage==='ready_for_authorized_retest'&&!r.reference.trim())||
     (r.stage==='ready_for_authorized_retest'&&c?.status==='blocked')||
     (c?.status==='completed'&&f.retest_status!=='fixed')||
     (f.retest_status==='regression'&&c?.status==='completed'))metrics.contradictions++;
 }
 return metrics;
}
function humanQueue(f,c,r){
 const cues=[];
 if(f.retest_status==='regression')cues.push('Source reports regression: escalate to source owner.');
 if(c?.status==='blocked')cues.push('Casework is blocked: coordinate blocker with human owner.');
 const window=localWindow();
 if(c?.due_date&&c.status!=='completed'&&c.status!=='deferred'){
  if(c.due_date<window.today)cues.push('Local Casework planning date overdue; not an approved SLA.');
  else if(c.due_date<=window.next7)cues.push('Local planning date within seven days; coordinate with human owner.');
 }
 if(c?.status==='completed'&&f.retest_status!=='fixed')cues.push('Local completed is NOT a verified source fix.');
 if(f.retest_status==='fixed')cues.push('Source reports fixed; independently confirm current approved retest.');
 if(r.stage==='ready_for_authorized_retest'&&!r.reference.trim())cues.push('Retest requested locally without a reference.');
 if(r.stage==='ready_for_authorized_retest'&&c?.status==='blocked')cues.push('Review and casework status conflict.');
 if(!r.reference.trim())cues.push('Ask for an approved private evidence reference, not raw evidence.');
 return cues;
}
function el(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node;}
function formField(label,value,max,handler,multiline=false){
 const wrap=el('label','field'),ctrl=document.createElement(multiline?'textarea':'input');
 wrap.append(el('span','',label));ctrl.value=value;ctrl.maxLength=max;
 if(!multiline)ctrl.type='text';ctrl.addEventListener('input',e=>handler(e.target.value));
 if(max===120)ctrl.addEventListener('change',()=>render());
 wrap.append(ctrl);return wrap;
}
function included(f,c,r,filter){
 const query=$('boardSearch').value.trim().toLocaleLowerCase();
 if(query){
  const fields=[f.finding_id,f.title,f.remediation,f.severity,f.retest_status,
   c?.owner,c?.next_action,c?.blocker,r.reference,r.reviewer,r.next_step,r.stage];
  if(!fields.some(v=>String(v||'').toLocaleLowerCase().includes(query)))return false;
 }
 const selectedTeam=$('boardTeam').value;
 if(selectedTeam&&(teamFor(f)===null?'unassigned':'team:'+teamFor(f))!==selectedTeam)return false;
 const cues=humanQueue(f,c,r);
 if(filter==='urgent'&&SEV.indexOf(f.severity)>1)return false;
 if(filter==='gaps'&&r.reference.trim()&&cues.length===0)return false;
 if(filter==='retest'&&r.stage!=='ready_for_authorized_retest')return false;
 if(filter==='blocked'&&c?.status!=='blocked')return false;
 if(filter==='overdue'&&(!c?.due_date||c.status==='completed'||c.status==='deferred'||c.due_date>=localWindow().today))return false;
 if(filter==='contradictions'&&!cues.some(x=>/NOT|conflict|without/.test(x)))return false;
 return true;
}
function selectedFindings(){
 if(!source)return [];
 const filter=$('filter').value;
 return source.filter(f=>included(f,casework?.get(f.finding_id),review.get(f.finding_id),filter));
}

/* Explicit single-team private exports. No implicit all-tenant or all-team package. */
function teamFor(f){
 const localCase=casework?.get(f.finding_id),localReview=review.get(f.finding_id);
 return (localCase?.owner?.trim()||localReview?.reviewer?.trim()||'') || null;
}
function updateTeamChoices(){
 const box=$('packTeam'),previous=box.value,boardTeam=$('boardTeam'),priorBoardTeam=boardTeam.value,available=new Set();
 for(const f of source||[])available.add(teamFor(f));
 const sorted=[...available].sort((a,b)=>(a===null?-1:b===null?1:a.localeCompare(b)));
 box.replaceChildren();
 const initial=el('option','','Choose one locally declared team');initial.value='';box.append(initial);
 for(const t of sorted){
  const opt=el('option','',t===null?'Unassigned (private triage only)':t);
  opt.value=t===null?'unassigned':'team:'+t;box.append(opt);
 }
 box.value=sorted.some(t=>(t===null?'unassigned':'team:'+t)===previous)?previous:'';
 boardTeam.replaceChildren();const all=el('option','','All locally declared teams');all.value='';boardTeam.append(all);
 for(const t of sorted){const option=el('option','',t===null?'Unassigned':t);option.value=t===null?'unassigned':'team:'+t;boardTeam.append(option);}
 boardTeam.value=sorted.some(t=>(t===null?'unassigned':'team:'+t)===priorBoardTeam)?priorBoardTeam:'';
 updateTeamCount();
}
function selectedTeamRows(){
 const group=$('packTeam').value;
 if(!group)return [];
 return (source||[]).filter(f=>(teamFor(f)===null?'unassigned':'team:'+teamFor(f))===group).map(f=>({
  finding:f,plan:casework?.get(f.finding_id)||engine.newCase(f),coordination:review.get(f.finding_id)
 }));
}
function updateTeamCount(){
 $('packCount').textContent=$('packTeam').value?
  String(selectedTeamRows().length)+' source findings in this locally declared routing group':'Select a team to scope a private export.';
}
function teamPacket(rows){
 const selected=$('packTeam').value;
 if(!sourceHash||!selected||!rows.length)throw Error('Choose a populated local routing group.');
 const team=selected==='unassigned'?null:selected.slice(5);
 return {kind:'lightup.remediation_private_team_handoff',schema_version:1,
  disposition:'UNVERIFIED_PRIVATE_HUMAN_COORDINATION',
  source_contract:'lightup.finding_export._COLUMNS_v1',source_sha256:sourceHash,
  team_label:team,
  original_findings_total:source.length,selected_findings_total:rows.length,
  original_review_sha256:localSha256(JSON.stringify(rows.map(({finding:f,coordination:r})=>
   [f.finding_id,r.stage,r.reference,r.reviewer,r.next_step]))),
  ...Object.fromEntries(flags.map(k=>[k,false])),
  cases:rows.map(({finding:f,plan:c,coordination:r})=>({
   finding_id:f.finding_id,title:f.title,severity:f.severity,original_retest_status:f.retest_status,
   original_remediation:f.remediation,casework_status:c.status,due_date:c.due_date,
   local_owner:c.owner,next_action:c.next_action,verification_plan:c.verification_plan,
   blocker:c.blocker,review_stage:r.stage,evidence_reference:r.reference,
   local_reviewer:r.reviewer,human_follow_up:r.next_step,
   warnings:humanQueue(f,c,r)
  })),
  warning:'Private unsigned subset of original exported findings and local notes. Not verified, not an approved work order, not consent, not an authorized retest or grant.'
 };
}
function safeSpreadsheetCell(value){
 const raw=String(value??'').replace(/\u0000/g,'');
 /* Always prefix user-derived text so invisible/Unicode-spoofed formula prefixes
    cannot become spreadsheet formulas after trimming or normalization. */
 return '"'+("'"+raw).replace(/"/g,'""')+'"';
}
function teamCsv(packet){
 const keys=['finding_id','title','severity','original_retest_status','original_remediation',
  'casework_status','due_date','local_owner','next_action','verification_plan','blocker',
  'review_stage','evidence_reference','local_reviewer','human_follow_up'];
 const body=packet.cases.map(c=>keys.map(k=>c[k]));
 return '\ufeff'+keys.map(v=>'"'+v+'"').join(',')+'\r\n'+body.map(row=>row.map(safeSpreadsheetCell).join(',')).join('\r\n')+'\r\n';
}
function doTeamExport(kind){
 try{
  if(!sourceHash)throw Error('Load original source first.');
  const rows=selectedTeamRows(),packet=teamPacket(rows);
  const human=packet.team_label||'UNASSIGNED';
  if(!confirm('Export ONLY '+rows.length+' PRIVATE finding summaries for locally declared group "'+
    human+'"? This can expose sensitive client issue descriptions; confirm recipient independently in an approved channel. It does not grant access or authority.'))return;
  if(kind==='json')download('lightup-private-single-team-handoff.json',JSON.stringify(packet,null,2),'application/json');
  else download('lightup-private-single-team-handoff.csv',teamCsv(packet),'text/csv');
  status('Private single-team '+kind.toUpperCase()+' created for '+rows.length+' original records. Sender must verify recipient; no client authorization or retest is asserted.');
 }catch(err){status(err.message,true);}
}
function render(){
 const ready=!!source;$('dashboard').hidden=!ready;$('boardSection').hidden=!ready;$('actions').hidden=!ready;$('refreshPanel').hidden=!ready;$('teamPanel').hidden=!ready;
 if(!ready)return;
 const m=count();for(const [key,num] of Object.entries(m))$(key).textContent=String(num);
 updateTeamChoices();renderRevisions();
 $('fingerprint').textContent=sourceHash?'Local source SHA-256: '+sourceHash+' (NOT authentication)':'Source fingerprint unavailable. All exports disabled.';
 const filter=$('filter').value;
 const selectedSort=$('boardSort').value;
 const items=source.slice().sort((a,b)=>{
  const c1=casework?.get(a.finding_id),c2=casework?.get(b.finding_id),
   r1=review.get(a.finding_id),r2=review.get(b.finding_id);
  if(selectedSort==='due'){
   const date1=c1?.due_date||'9999-12-31',date2=c2?.due_date||'9999-12-31';
   if(date1!==date2)return date1<date2?-1:1;
  }
  if(selectedSort==='followup'){
   const score=(f,c,r)=>(f.retest_status==='regression'?20:0)+(c?.status==='blocked'?12:0)+
    (r.stage==='needs_changes'?8:0)+(!r.reference.trim()?4:0)+(SEV.indexOf(f.severity)<=1?5:0);
   const delta=score(b,c2,r2)-score(a,c1,r1);if(delta)return delta;
  }
  return SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||a.finding_id.localeCompare(b.finding_id);
 });
 const board=$('board');board.replaceChildren();
 for(const f of items){
  const c=casework?.get(f.finding_id),r=review.get(f.finding_id);
  const cues=humanQueue(f,c,r);
  if(!included(f,c,r,filter))continue;
  const section=el('article','finding');
  const heading=el('h3','',f.title);section.append(heading);
  section.append(el('p','detail',f.severity.toUpperCase()+' · Source retest: '+f.retest_status+' · Local casework: '+(c?.status||'not loaded')));
  section.append(el('p','detail','Finding '+f.finding_id));
  if(c) section.append(el('p','detail','Original local plan · owner: '+(c.owner||'unassigned')+' · due: '+(c.due_date||'not planned')));
  if(cues.length){const ul=el('ul','cues');for(const cue of cues)ul.append(el('li','',cue));section.append(ul);}
  const selectLabel=el('label','field'),select=document.createElement('select');
  selectLabel.append(el('span','','Human coordination stage'));
  for(const stage of DECISIONS){const o=el('option','',stage.replaceAll('_',' '));o.value=stage;select.append(o);}
  select.value=r.stage;select.addEventListener('change',e=>{r.stage=e.target.value;changed=true;render();});
  selectLabel.append(select);section.append(selectLabel);
  section.append(formField('Private evidence reference (no secrets or raw evidence)',r.reference,240,v=>{r.reference=v;changed=true;renderMetrics();}));
  section.append(formField('Human reviewer/team (local, unverified)',r.reviewer,120,v=>{r.reviewer=v;changed=true;updateTeamChoices();}));
  section.append(formField('Next evidence or retest coordination step',r.next_step,500,v=>{r.next_step=v;changed=true;},true));
  board.append(section);
 }
 $('shown').textContent=String(board.childElementCount);
 $('bulkCount').textContent=String(board.childElementCount);
}
function renderMetrics(){
 if(!source)return;
 const m=count();for(const [key,num] of Object.entries(m))$(key).textContent=String(num);
}
async function readCSV(file){return engine.parseCSV(await read(file,LIMIT_CSV));}

/* Offline file:// browsers may not expose WebCrypto; the same canonical SHA-256
 * remains available without weakening the exact-source binding. */
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

async function sourceDigest(findings){
 const normalized=engine.normalizeSource(findings);
 const canonical=JSON.stringify(normalized.slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));
 const h=await engine.digest(findings)||localSha256(canonical);
 if(!/^[a-f0-9]{64}$/.test(h))throw Error('Canonical source SHA-256 failed.');
 return h;
}
$('load').addEventListener('click',async()=>{
 try{
  if(changed&&!confirm('Discard unsaved local coordination notes?'))return;
  const f=$('sourceFile').files[0],draft=$('caseFile').files[0];
  const parsed=await readCSV(f),hash=await sourceDigest(parsed);
  let byId=null;
  if(draft){
   if(!$('sameEngagement').checked)throw Error('Confirm independently verified same-client and same-engagement source before loading a casework draft.');
   const packet=engine.loadPacket(strictJSON(await read(draft,LIMIT_JSON)));
   if(packet.source_sha256!==null&&packet.source_sha256!==hash)throw Error('Casework source fingerprint mismatch.');
   if(packet.source_sha256===null&&!$('allowHashlessCasework').checked)throw Error('Original Casework has no source fingerprint. Confirm the separate hashless-original import choice; all five source fields are still checked.');
   if(packet.findings.length!==parsed.length)throw Error('Casework source row count mismatch.');
   const fromPacket=new Map(packet.findings.map(row=>[row.finding_id,row]));
   if(parsed.some(row=>!fromPacket.has(row.finding_id)||!exactFields(row,fromPacket.get(row.finding_id))))throw Error('Casework source fields mismatch.');
   byId=new Map(packet.cases.map(c=>[c.finding_id,c]));
  }
  sourceHash=hash;updateSource(parsed,byId);
  status('Original LightUp CSV loaded locally ('+parsed.length+' rows). '+(draft?'Exact matching Casework draft loaded.':'No Casework notes loaded.')+' No identity or remediation verified.');
 }catch(err){status(err.message,true);}
});
$('restore').addEventListener('click',async()=>{
 try{
  if(!source)throw Error('First load original LightUp CSV.');
  if(changed&&!confirm('Replace current local coordination notes?'))return;
  const file=$('reviewFile').files[0],packet=strictJSON(await read(file,LIMIT_JSON));
  if(!packet||packet.kind!=='lightup.remediation_evidence_coordination'||packet.schema_version!==1||
     packet.disposition!=='UNVERIFIED_OFFLINE_HUMAN_COORDINATION'||
     packet.source_contract!=='lightup.finding_export._COLUMNS_v1'||
     flags.some(k=>packet[k]!==false)||packet.source_sha256!==sourceHash||
     !Array.isArray(packet.review)||packet.review.length!==source.length)throw Error('Invalid review file, unsafe authority claim or different source.');
  const ids=new Set(source.map(f=>f.finding_id)),next=new Map();
  const incomingRevisions=restoreRevisions(packet.revision_register,sourceHash);
  for(const raw of packet.review){const row=validReview(raw,ids);if(next.has(row.finding_id))throw Error('Duplicate review finding.');next.set(row.finding_id,row);}
  review=next;revisions=incomingRevisions;changed=false;render();status('Unverified review notes restored for exact original source; no current authorization implied.');
 }catch(err){status(err.message,true);}
});

/* Human-confirmed refresh is all-or-none, and only identical original source rows
 * may retain unverified local coordination or original Casework planning notes. */
$('previewRefresh').addEventListener('click',async()=>{
 try{
  if(!source)throw Error('Load original findings first.');
  refreshCandidate=null;$('applyRefresh').disabled=true;
  const incoming=await readCSV($('refreshFile').files[0]);
  const hash=await sourceDigest(incoming);
  if(hash===sourceHash)throw Error('New CSV has identical original source content; nothing to refresh.');
  const diff=engine.compareSource(source,incoming);
  refreshCandidate={incoming,hash,diff};
  $('refreshSummary').textContent='Preview only: '+diff.added.length+' added, '+
   diff.changed.length+' changed, '+diff.missing.length+' absent, '+diff.unchanged.length+
   ' unchanged. Absent findings are NEVER proof of repair. Only unchanged rows can retain your local notes.';
  $('applyRefresh').disabled=false;status('Source refresh preview ready. No current board data changed.');
 }catch(err){$('refreshSummary').textContent='No valid refresh preview.';status(err.message,true);}
});
$('applyRefresh').addEventListener('click',()=>{
 try{
  if(!refreshCandidate)throw Error('Preview a newer original CSV first.');
  if(!$('refreshConfirm').checked)throw Error('Independently confirm exact same client and engagement for both original exports.');
  if(!confirm('Save your previous private notes first. Apply this source refresh? Added/changed records reset; missing records leave the local board WITHOUT any finding of repair.'))return;
  const {incoming,hash,diff}=refreshCandidate,unchanged=new Set(diff.unchanged);
  const newReview=new Map(incoming.map(f=>[f.finding_id,unchanged.has(f.finding_id)?review.get(f.finding_id):stageStart(f.finding_id)]));
  const newCases=casework?new Map(incoming.map(f=>[f.finding_id,
   unchanged.has(f.finding_id)&&casework.has(f.finding_id)?casework.get(f.finding_id):engine.newCase(f)])):null;
  const revision=validRevision({from_sha256:sourceHash,to_sha256:hash,added:diff.added,missing:diff.missing,
   unchanged:diff.unchanged,changed:diff.changed});
  revisions=[...revisions,revision].slice(-12);
  source=incoming;sourceHash=hash;casework=newCases;review=newReview;changed=true;
  refreshCandidate=null;$('refreshFile').value='';$('refreshConfirm').checked=false;
  $('refreshSummary').textContent='Applied: '+diff.added.length+' new, '+diff.changed.length+' changed, '+
   diff.missing.length+' absent (not proven fixed); only '+diff.unchanged.length+' unchanged kept local notes.';
  render();status('Human-confirmed local source refresh applied. Historical source was NOT changed, retested or closed.');
 }catch(err){status(err.message,true);}
});


$('applyBulk').addEventListener('click',()=>{
 try{
  if(!source)throw Error('Import original findings first.');
  const stage=$('bulkStage').value,reviewer=$('bulkReviewer').value;
  if(stage&&!DECISIONS.includes(stage))throw Error('Invalid bulk human stage.');
  if(!stage&&!reviewer.trim())throw Error('Choose a review stage and/or human reviewer.');
  if(reviewer.length>120||reviewer.includes('\0'))throw Error('Reviewer label too long or invalid.');
  const selected=selectedFindings(),n=selected.length;
  if(!n)throw Error('No findings match the current filter.');
  if(!confirm('Update '+n+' currently visible local findings ONLY? Existing per-finding notes and original source/retest statuses remain unchanged. This is not approved remediation.'))return;
  for(const f of selected){const row=review.get(f.finding_id);if(stage)row.stage=stage;if(reviewer.trim())row.reviewer=reviewer.trim();}
  changed=true;render();status('Updated '+n+' LOCAL coordination records. Original findings, casework and retest statuses unchanged.');
 }catch(err){status(err.message,true);}
});



/* Explicit revision coordination exports: a private action register retaining original
   changed/absent IDs, or anonymous counts. Neither document verifies a fix. */
$('exportRevisionCSV').addEventListener('click',()=>{
 try{
  if(!sourceHash||!revisions.length)throw Error('No acknowledged original-source revision available.');
  const cols=['revision','previous_source_sha256','current_source_sha256','change','finding_id','changed_original_fields','human_follow_up'];
  const rows=[cols];
  revisions.forEach((x,i)=>{
   for(const id of x.added)rows.push([i+1,x.from_sha256,x.to_sha256,'added',id,'','Review original new finding']);
   for(const row of x.changed)rows.push([i+1,x.from_sha256,x.to_sha256,'changed',row.finding_id,
    row.changed_fields.join(';'),'Confirm original finding change and replan']);
   for(const id of x.missing)rows.push([i+1,x.from_sha256,x.to_sha256,'absent_unverified',id,'',
    'Investigate absence; do not mark repaired or retested']);
  });
  if(!confirm('Download a PRIVATE historical source-revision register containing original finding IDs? Never interpret an absent row as repaired. Verify approved recipient independently.'))return;
  download('lightup-private-source-revisions.csv','\ufeff'+cols.map(v=>'"'+v+'"').join(',')+'\r\n'+rows.slice(1).map(v=>v.map(safeSpreadsheetCell).join(',')).join('\r\n')+'\r\n','text/csv');
  status('Private historical source-difference register downloaded; absent findings remain unverified.');
 }catch(err){status(err.message,true);}
});
$('exportRevisionAggregate').addEventListener('click',()=>{
 try{
  if(!sourceHash||!revisions.length)throw Error('No original-source revision history to summarize.');
  const data={kind:'lightup.source_revision_aggregate',schema_version:1,
   disposition:'UNVERIFIED_OFFLINE_SOURCE_CHANGES',source_sha256:sourceHash,
   revision_count:revisions.length,
   history:revisions.map(x=>({added:x.added.length,changed:x.changed.length,
     absent_unverified:x.missing.length,unchanged:x.unchanged.length})),
   ...Object.fromEntries(flags.map(k=>[k,false])),
   warning:'Aggregates are private, unsigned and source self-reported. Source removal does not prove repair or retest.'};
  download('lightup-source-revision-aggregate.json',JSON.stringify(data,null,2),'application/json');
 }catch(err){status(err.message,true);}
});


/* Reintegrate only unverified returned human notes from a single original team
 * packet. All current original findings, original Casework, source and rights
 * are checked before one atomic replacement of local review notes. */
$('importTeamReturn').addEventListener('click',async()=>{
 try{
  if(!sourceHash||!source)throw Error('Import original authenticated findings summary first.');
  if(!$('sameTeamReturn').checked)throw Error('Independently verify the returned private packet belongs to the same client, engagement and intended original team.');
  const packet=strictJSON(await read($('teamReturnFile').files[0],LIMIT_JSON));
  const topFields=new Set(['kind','schema_version','disposition','source_contract','source_sha256',
   'team_label','original_findings_total','selected_findings_total','original_review_sha256',
   'cases','warning',...flags]);
  if(!packet||Object.getPrototypeOf(packet)!==Object.prototype||
   Object.keys(packet).some(k=>!topFields.has(k))||
   packet.kind!=='lightup.remediation_private_team_handoff'||packet.schema_version!==1||
   packet.disposition!=='UNVERIFIED_PRIVATE_HUMAN_COORDINATION'||
   packet.source_contract!=='lightup.finding_export._COLUMNS_v1'||
   packet.source_sha256!==sourceHash||packet.original_findings_total!==source.length||
   flags.some(k=>packet[k]!==false)||!Array.isArray(packet.cases)||
   packet.cases.length<1||packet.cases.length>350||
   packet.selected_findings_total!==packet.cases.length||
   (packet.team_label!==null&&(typeof packet.team_label!=='string'||!packet.team_label.trim()||
    packet.team_label.length>120))||
   typeof packet.original_review_sha256!=='string'||!/^[a-f0-9]{64}$/.test(packet.original_review_sha256))
   throw Error('Invalid private team packet, forged authority, incomplete source or wrong engagement.');
  const known=new Map(source.map(f=>[f.finding_id,f]));
  const expected=source.filter(f=>teamFor(f)===packet.team_label);
  if(expected.length!==packet.cases.length)throw Error('Local team membership changed since packet export; inspect changes before re-export.');
  const rowFields=new Set(['finding_id','title','severity','original_retest_status',
   'original_remediation','casework_status','due_date','local_owner','next_action',
   'verification_plan','blocker','review_stage','evidence_reference',
   'local_reviewer','human_follow_up','warnings']);
  const received=new Map();
  for(const row of packet.cases){
   if(!row||Object.getPrototypeOf(row)!==Object.prototype||
      Object.keys(row).some(k=>!rowFields.has(k))||
      typeof row.finding_id!=='string'||!known.has(row.finding_id)||
      received.has(row.finding_id))throw Error('Invalid, duplicate or foreign original finding in returned packet.');
   const src=known.get(row.finding_id),c=casework?.get(src.finding_id)||engine.newCase(src);
   if(teamFor(src)!==packet.team_label||
      row.title!==src.title||row.severity!==src.severity||
      row.original_retest_status!==src.retest_status||row.original_remediation!==src.remediation||
      row.casework_status!==c.status||row.due_date!==c.due_date||
      row.local_owner!==c.owner||row.next_action!==c.next_action||
      row.verification_plan!==c.verification_plan||row.blocker!==c.blocker)
    throw Error('Original source, local team route or original Casework changed; no returned edits applied.');
   if(!Array.isArray(row.warnings)||row.warnings.length>16||
      row.warnings.some(x=>typeof x!=='string'||x.length>240))
    throw Error('Malformed local human warning list.');
   const next=validReview({finding_id:src.finding_id,stage:row.review_stage,
    reference:row.evidence_reference,reviewer:row.local_reviewer,
    next_step:row.human_follow_up},new Set([src.finding_id]));
   received.set(src.finding_id,next);
  }
  const existing=expected.slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0);
  /* Use the exact original team-packet order, not sorting, for the baseline.
     Member count and identities have already been verified completely. */
  const baseline=localSha256(JSON.stringify(packet.cases.map(row=>{
   const r=review.get(row.finding_id);
   return [row.finding_id,r.stage,r.reference,r.reviewer,r.next_step];
  })));
  if(baseline!==packet.original_review_sha256)throw Error('Local notes changed since private team handoff; re-export rather than overwriting newer notes.');
  if(received.size!==expected.length)throw Error('Incomplete private team response; no local edits applied.');
  if(!confirm('Replace only '+received.size+' LOCAL HUMAN review notes using this unverified team return? Original Casework, findings, permissions, scan and actual retest remain unchanged. Confirm the team and recipient independently.'))return;
  const updated=new Map(review);
  for(const [id,row] of received)updated.set(id,row);
  review=updated;changed=true;render();
  $('teamReturnFile').value='';$('sameTeamReturn').checked=false;
  status('Returned private team review incorporated into '+received.size+' local records. No original source, casework, grant or verified retest changed.');
 }catch(err){status(err.message,true);}
});

$('packTeam').addEventListener('change',updateTeamCount);
$('exportTeamJSON').addEventListener('click',()=>doTeamExport('json'));
$('exportTeamCSV').addEventListener('click',()=>doTeamExport('csv'));
$('filter').addEventListener('change',render);
$('boardSearch').addEventListener('input',render);
$('boardTeam').addEventListener('change',render);
$('boardSort').addEventListener('change',render);
$('clear').addEventListener('click',()=>{
 if(changed&&!confirm('Discard unsaved local review notes?'))return;
 source=null;casework=null;sourceHash=null;review=new Map();changed=false;refreshCandidate=null;revisions=[];
 $('teamReturnFile').value='';$('sameTeamReturn').checked=false;
 $('boardSearch').value='';$('boardTeam').value='';$('boardSort').value='severity';$('filter').value='all';
 $('sourceFile').value='';$('caseFile').value='';$('reviewFile').value='';$('refreshFile').value='';$('allowHashlessCasework').checked=false;$('refreshConfirm').checked=false;$('refreshSummary').textContent='No refresh preview.';
 $('dashboard').hidden=true;$('boardSection').hidden=true;$('actions').hidden=true;$('refreshPanel').hidden=true;$('teamPanel').hidden=true;
 $('packTeam').replaceChildren();$('packCount').textContent='No original findings imported.';
 $('board').replaceChildren();renderRevisions();status('All source and local notes forgotten from this tab.');
});
$('save').addEventListener('click',()=>{if(!sourceHash)return;download('lightup-evidence-coordination-private.json',JSON.stringify(snapshot(),null,2),'application/json');changed=false;status('Private unsigned coordination notes downloaded; protect as sensitive data.');});
$('aggregate').addEventListener('click',()=>{
 if(!sourceHash)return;const m=count();
 const data={kind:'lightup.remediation_evidence_aggregate',schema_version:1,disposition:'UNVERIFIED_AGGREGATE_ONLY',
  source_sha256:sourceHash,counts:m,authenticated:false,grant:false,retest_verified:false,release:false};
 download('lightup-evidence-gaps-aggregate.json',JSON.stringify(data,null,2),'application/json');
});
$('brief').addEventListener('click',()=>{
 if(!sourceHash)return;
 const m=count(),rows=source.map(f=>({f,c:casework?.get(f.finding_id),r:review.get(f.finding_id)}));
 const escape=s=>String(s).replace(/[\x00-\x1f\x7f\r\n]/g,' ').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\/g,'\\\\').replace(/\|/g,'\\|').replace(/[\x60\[\]*_]/g,'\\$&').slice(0,800);
 const lines=['# Private LightUp remediation-evidence coordination','',
  '**UNVERIFIED, UNSIGNED HUMAN DRAFT.** No authentication, grant, remediation proof or approved retest.',
  'Source SHA-256: '+sourceHash+' (not a signature or authorization).','',
  'Original findings: '+m.total+'; critical/high: '+m.urgent+'; missing private references: '+m.no_reference+
  '; needs changes: '+m.needs_changes+'; local retest requests: '+m.retest+'; warning conditions: '+m.contradictions+'.','',
  '| Finding ID | Severity | Original retest | Local case stage | Evidence coordination | Reference (unverified) | Next action |',
  '| --- | --- | --- | --- | --- | --- | --- |'];
 for(const {f,c,r} of rows)lines.push('| '+[f.finding_id,f.severity,f.retest_status,c?.status||'not loaded',r.stage,r.reference,r.next_step].map(escape).join(' | ')+' |');
 lines.push('','Any real retest, evidence validation, closure or client/operator approval must occur in the separate authenticated original system.');
 download('lightup-evidence-coordination-private.md',lines.join('\n'),'text/markdown'); 
});
window.addEventListener('beforeunload',e=>{if(changed){e.preventDefault();e.returnValue='';}});
status('Load an originally authorized five-column LightUp findings CSV to start.');
/* A private, authenticated-at-export-time handoff contains a passive JSON data
 * block. It is never a credential, consent token, grant or live status check. */
async function preloadAuthorizedExport(){
 const embedded=$('preloadedCsv');
 if(!embedded)return;
 try{
  const payload=strictJSON(embedded.textContent);
  if(!payload||payload.format!=='lightup.authenticated_findings_handoff_v1'||
     typeof payload.csv_base64!=='string'||payload.csv_base64.length>1400000||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(payload.csv_base64))
   throw Error('Malformed private export envelope.');
  const binary=atob(payload.csv_base64);
  if(binary.length>LIMIT_CSV)throw Error('Preloaded export exceeds original CSV size.');
  const raw=Uint8Array.from(binary,ch=>ch.charCodeAt(0));
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);
  const parsed=engine.parseCSV(text),hash=await sourceDigest(parsed);
  sourceHash=hash;updateSource(parsed,null);
  status('Private original LightUp summary loaded from the interactive authenticated export. Authentication only occurred at export time; this HTML cannot verify current consent, source ownership, scope or retest.');
 }catch(err){
  status('Private handoff rejected: '+err.message,true);
 }finally{
  /* Avoid keeping a second DOM copy of selected client summaries after intake. */
  embedded.remove();
 }
}
void preloadAuthorizedExport();
})();