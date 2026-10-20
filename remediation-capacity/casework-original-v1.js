/* LightUp local casework. Parsing/presentation only; never authenticates source or authorizes assessments. */
(function(global){
'use strict';
const EXPECTED=['finding_id','title','severity','retest_status','remediation'];
const SEVERITY=['critical','high','medium','low','info'];
const RETEST=['not_tested','fix_pending','fixed','regression'];
const PROGRESS=['unassigned','planned','in_progress','blocked','ready_for_retest','deferred','completed'];
const MAX_BYTES=1048576,MAX_ROWS=350,MAX_CELL=6000;
function sizeOf(text){return new TextEncoder().encode(text).length;}
function parseCSV(text){
 if(typeof text!=='string'||sizeOf(text)>MAX_BYTES)throw Error('CSV exceeds 1 MiB.');
 if(text.charCodeAt(0)===0xfeff)text=text.slice(1);
 const rows=[];let row=[],field='',quoted=false,closed=false;
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(quoted){
   if(c==='"' && text[i+1]==='"'){field+='"';i++;}
   else if(c==='"') {quoted=false;closed=true;}
   else field+=c;
  }else if(c==='"'){
   if(field!==''||closed)throw Error('Malformed quoted CSV field.');
   quoted=true;
  }else if(c===','){
   row.push(field);field='';closed=false;
  }else if(c==='\r'||c==='\n'){
   if(c==='\r'&&text[i+1]==='\n')i++;
   row.push(field);field='';closed=false;
   if(row.length>1||row[0]!=='')rows.push(row);
   row=[];
   if(rows.length>MAX_ROWS+1)throw Error('Too many findings.');
  }else{
   if(closed)throw Error('Malformed CSV after closing quote.');
   field+=c;
  }
  if(field.length>MAX_CELL)throw Error('An imported CSV cell is too long.');
 }
 if(quoted)throw Error('Unclosed CSV quote.');
 if(row.length||field!==''||closed){row.push(field);if(row.length>1||row[0]!=='')rows.push(row);}
 if(!rows.length)throw Error('No CSV header found.');
 if(rows[0].length!==EXPECTED.length || rows[0].some((v,i)=>v!==EXPECTED[i]))
  throw Error('Expected the five-column LightUp findings summary CSV export.');
 if(rows.length===1)throw Error('CSV export contains no findings.');
 if(rows.length-1>MAX_ROWS)throw Error('Too many findings.');
 const seen=new Set();
 return rows.slice(1).map((values,index)=>{
  if(values.length!==EXPECTED.length)throw Error('Malformed CSV row '+(index+2)+'.');
  const [finding_id,title,severity,retest_status,remediation]=values;
  if(!finding_id.trim()||finding_id.length>160||seen.has(finding_id))
   throw Error('Invalid or duplicate finding ID at row '+(index+2)+'.');
  if(!title.trim()||!remediation.trim()||!SEVERITY.includes(severity)||!RETEST.includes(retest_status))
   throw Error('Malformed finding data at row '+(index+2)+'.');
  seen.add(finding_id);
  return {finding_id,title,severity,retest_status,remediation};
 });
}
function normalizeSource(findings){
 if(!Array.isArray(findings)||!findings.length||findings.length>MAX_ROWS)throw Error('Unsupported findings list.');
 const seen=new Set();
 return findings.map(x=>{
  if(!x||typeof x!=='object'||Array.isArray(x))throw Error('Malformed finding.');
  const y={};
  for(const col of EXPECTED){
   if(typeof x[col]!=='string'||x[col].length>MAX_CELL)throw Error('Invalid finding '+col+'.');
   y[col]=x[col];
  }
  if(!y.finding_id.trim()||y.finding_id.length>160||seen.has(y.finding_id)||
   !y.title.trim()||!y.remediation.trim()||!SEVERITY.includes(y.severity)||!RETEST.includes(y.retest_status))
   throw Error('Invalid source finding.');
  seen.add(y.finding_id);return y;
 });
}
function newCase(f){
 return {finding_id:f.finding_id,owner:'',status:f.retest_status==='fixed'?'completed':'unassigned',
   due_date:null,next_action:'',verification_plan:'',blocker:'',note:'',updated_utc:null};
}
function cleanCase(x,existingIds){
 if(!x||typeof x!=='object'||Array.isArray(x)||typeof x.finding_id!=='string'||
    !existingIds.has(x.finding_id))throw Error('Case refers to unknown finding.');
 const c={finding_id:x.finding_id};
 for(const [key,max] of [['owner',120],['next_action',1800],['verification_plan',1600],['blocker',1200],['note',1600]]){
  if(typeof x[key]!=='string'||x[key].length>max)throw Error('Invalid case field '+key+'.');
  c[key]=x[key];
 }
 if(!PROGRESS.includes(x.status))throw Error('Unknown remediation status.');
 c.status=x.status;
 if(x.due_date!==null && (typeof x.due_date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(x.due_date)||
  Number.isNaN(Date.parse(x.due_date+'T00:00:00Z'))||
  new Date(x.due_date+'T00:00:00Z').toISOString().slice(0,10)!==x.due_date))
   throw Error('Invalid case due date.');
 c.due_date=x.due_date;
 if(x.updated_utc!==null && (typeof x.updated_utc!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x.updated_utc)||
 Number.isNaN(Date.parse(x.updated_utc))))throw Error('Invalid case update timestamp.');
 c.updated_utc=x.updated_utc;return c;
}
async function digest(findings){
 const normalized=normalizeSource(findings);
 const canonical=JSON.stringify(normalized.slice().sort((a,b)=>a.finding_id<b.finding_id?-1:a.finding_id>b.finding_id?1:0));
 if(!global.crypto||!global.crypto.subtle)return null;
 const hash=await global.crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical));
 return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function makePacket(findings,cases,sourceHash){
 const source=normalizeSource(findings),ids=new Set(source.map(x=>x.finding_id));
 if(!Array.isArray(cases)||cases.length!==source.length)throw Error('Casework count mismatch.');
 const seen=new Set(),clean=cases.map(x=>{
  const y=cleanCase(x,ids);
  if(seen.has(y.finding_id))throw Error('Duplicate casework entry.');
  seen.add(y.finding_id);return y;
 });
 return {
  kind:'lightup.remediation_casework_draft',schema_version:1,disposition:'LOCAL_CLIENT_PLANNING',
  authenticated:false,tenant_verified:false,source_authorized:false,assessment_authorized:false,
  grant:false,client_consent:false,operator_consent:false,execution:false,scan:false,
  audit_verdict:false,retest_verified:false,release:false,
  source_contract:'lightup.finding_export._COLUMNS_v1',source_sha256:sourceHash||null,
  findings:source,cases:clean,
  instructions:'This file contains unverified local notes and exported summaries. Do not treat any row or status as proof of remediation, verified retest, authentication or grant.'
 };
}
function loadPacket(packet){
 if(!packet||typeof packet!=='object'||Array.isArray(packet)||packet.kind!=='lightup.remediation_casework_draft'||
   packet.schema_version!==1||packet.disposition!=='LOCAL_CLIENT_PLANNING'||
   packet.source_contract!=='lightup.finding_export._COLUMNS_v1'||
   !['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent',
     'operator_consent','execution','scan','audit_verdict','retest_verified','release']
      .every(k=>Object.prototype.hasOwnProperty.call(packet,k)&&packet[k]===false))
  throw Error('Not a supported non-authorizing LightUp casework draft.');
 const source=normalizeSource(packet.findings),ids=new Set(source.map(x=>x.finding_id));
 if(!Array.isArray(packet.cases)||packet.cases.length!==source.length)throw Error('Casework incomplete.');
 const seen=new Set(),cases=packet.cases.map(x=>{
  const y=cleanCase(x,ids);if(seen.has(y.finding_id))throw Error('Duplicate case.');seen.add(y.finding_id);return y;
 });
 if(packet.source_sha256!==null && (typeof packet.source_sha256!=='string'||!/^[0-9a-f]{64}$/.test(packet.source_sha256)))
  throw Error('Invalid source fingerprint.');
 return {findings:source,cases,source_sha256:packet.source_sha256||null};
}
function rank(x){return SEVERITY.indexOf(x.severity);}
function metrics(findings,cases,today){
 const byId=new Map(cases.map(x=>[x.finding_id,x]));
 const totals={findings:findings.length,critical_or_high:0,open:0,blocked:0,overdue:0,ready_for_retest:0,source_fixed:0};
 for(const finding of findings){
  const c=byId.get(finding.finding_id);
  if(rank(finding)<=1)totals.critical_or_high++;
  if(finding.retest_status==='fixed')totals.source_fixed++;
  if(c&&c.status!=='completed'&&c.status!=='deferred')totals.open++;
  if(c&&c.status==='blocked')totals.blocked++;
  if(c&&c.status==='ready_for_retest')totals.ready_for_retest++;
  if(c&&c.due_date&&c.due_date<today&&c.status!=='completed'&&c.status!=='deferred')totals.overdue++;
 }
 return totals;
}
function csvCell(raw){
 let s=String(raw??'');
 const probe=s.replace(/^[\s\x00-\x1f]+/,'');
 if(/^[=+\-@]/.test(probe))s="'"+s;
 return '"'+s.replace(/"/g,'""')+'"';
}
function exportActionsCSV(findings,cases){
 const byId=new Map(cases.map(c=>[c.finding_id,c]));
 const columns=['finding_id','severity','title','source_retest_status','casework_status','assigned_owner','due_date','next_action','verification_plan','blocker'];
 const rows=findings.map(f=>{
  const c=byId.get(f.finding_id);
  return [f.finding_id,f.severity,f.title,f.retest_status,c.status,c.owner,c.due_date||'',c.next_action,c.verification_plan,c.blocker];
 });
 return String.fromCharCode(0xFEFF)+[columns,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n';
}

/* Re-import review: changing finding payload is not automatically a confirmed retest.
 * The caller must explicitly confirm the same independently verified account/engagement.
 * Only byte-for-byte unchanged source findings retain unverified local casework notes. */
function compareSource(before,after){
 const old=normalizeSource(before),incoming=normalizeSource(after);
 const a=new Map(old.map(item=>[item.finding_id,item]));
 const b=new Map(incoming.map(item=>[item.finding_id,item]));
 const compare=(x,y)=>EXPECTED.every(k=>x[k]===y[k]);
 const added=[],missing=[],changed=[],unchanged=[];
 for(const item of incoming){
  const prev=a.get(item.finding_id);
  if(!prev)added.push(item.finding_id);
  else if(compare(prev,item))unchanged.push(item.finding_id);
  else changed.push({finding_id:item.finding_id,
    changed_fields:EXPECTED.filter(k=>prev[k]!==item[k])});
 }
 for(const item of old)if(!b.has(item.finding_id))missing.push(item.finding_id);
 return {added,missing,changed,unchanged,
  warning:'Missing findings are NOT proof of remediation; changed source findings reset their local plans. Independently verify same client and engagement first.'};
}
function reconcileSource(before,existingCases,after){
 const diff=compareSource(before,after);
 const oldCases=new Map(existingCases.map(c=>[c.finding_id,c]));
 const allowed=new Set(diff.unchanged);
 const source=normalizeSource(after);
 const merged=source.map(f=>allowed.has(f.finding_id)&&oldCases.has(f.finding_id) ?
  cleanCase(oldCases.get(f.finding_id),new Set(source.map(item=>item.finding_id))) : newCase(f));
 return {findings:source,cases:merged,change_summary:diff};
}

global.LightUpCasework=Object.freeze({compareSource,reconcileSource,parseCSV,normalizeSource,newCase,cleanCase,digest,makePacket,loadPacket,metrics,exportActionsCSV,SEVERITY,RETEST,PROGRESS,MAX_BYTES});
})(window);
