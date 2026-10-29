/* Offline human follow-up tracker; source-bound notes on conversations, never approval. */
(function(global){
'use strict';
const K='lightup.human_followup_draft', AUTH=['client_consent','operator_consent','grant','execution','scan','release','retest_verified'];
const ROLES=['unassigned','client_representative','operator_reviewer','joint_discussion'];
const PHASES=['pending_discussion','awaiting_client_question','awaiting_operator_question','conversation_recorded','deferred_for_review'];
const SHA=/^[a-f0-9]{64}$/;
const isObj=x=>!!x&&typeof x==='object'&&!Array.isArray(x);
function exactKeys(o,fields){return isObj(o)&&Object.keys(o).length===fields.length&&fields.every(x=>Object.hasOwn(o,x));}
function date(value){if(value==='')return true;if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value))return false;const d=new Date(value+'T00:00:00Z');return Number.isFinite(d.valueOf())&&d.toISOString().slice(0,10)===value;}
function cleanState(x){
 if(!exactKeys(x,['role','phase','date'])||!ROLES.includes(x.role)||!PHASES.includes(x.phase)||!date(x.date))throw Error('Invalid local human discussion record.');
 return {role:x.role,phase:x.phase,date:x.date};
}
function blank(){return {role:'unassigned',phase:'pending_discussion',date:''};}
function actionKey(x){
 if(!isObj(x)||!['urgent','attention','planning','context'].includes(x.level)
   ||typeof x.origin!=='string'||!/^[a-z_]+$/.test(x.origin)||typeof x.title!=='string'
   ||typeof x.next_human_step!=='string'||!Number.isSafeInteger(x.source_count))throw Error('Invalid original action.');
 return x.origin+' / '+x.title;
}
function actionsFrom(plan){
 if(!isObj(plan)||plan.kind!=='lightup.client_brief_human_followup_review'||!Array.isArray(plan.actions)||plan.actions.length>48)
  throw Error('Unsupported original follow-up source.');
 const a=plan.actions.filter(x=>x.origin!=='internal_operator_readiness'), keys=a.map(actionKey);
 if(new Set(keys).size!==keys.length)throw Error('Duplicate original follow-up categories.');
 return {actions:a,keys};
}
function source(state,plan){
 if(!state?.fresh||typeof state.fresh.sha!=='string'||!SHA.test(state.fresh.sha))throw Error('Original source fingerprint unavailable. Open source CSV in a secure local browser.');
 if(state.older&&!SHA.test(state.older.sha||''))throw Error('Earlier CSV source fingerprint unavailable.');
 const data=actionsFrom(plan);
 return {fingerprint:state.fresh.sha,previous:state.older?.sha??null,
  studioRevision:state.studio?.source_revision_sha256??null,
  studioPrevious:state.studioChange?.earlier_revision??null,...data};
}
async function signature(info){
 if(!crypto?.subtle)throw Error('WebCrypto required to bind this draft to original sources.');
 const raw=JSON.stringify([info.fingerprint,info.previous,info.studioRevision,info.studioPrevious,info.actions.map(x=>[x.origin,x.title,x.level,x.source_count,x.next_human_step])]);
 const result=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
 return [...new Uint8Array(result)].map(v=>v.toString(16).padStart(2,'0')).join('');
}
function collect(info,existing={}){
 const result={};
 for(const key of info.keys)result[key]=existing[key]?cleanState(existing[key]):blank();
 return result;
}
async function make(info,records){
 const key=await signature(info), safe=collect(info,records);
 return {kind:K,schema_version:1,disposition:'HUMAN_DISCUSSION_ONLY',
   source_digest:key,source_sha256:info.fingerprint,previous_sha256:info.previous,
   studio_revision_sha256:info.studioRevision,studio_earlier_sha256:info.studioPrevious,
   authority:Object.fromEntries(AUTH.map(x=>[x,false])),
   // Entries are positional. No source findings, client names or operator details are stored.
   records:info.keys.map(k=>safe[k]),source_count:info.keys.length,
   warning:'Local unsigned human discussions only. Not consent, approval, remediation, grant, scan, assignment or retest.'};
}
async function read(file,info){
 if(!file||file.size<20||file.size>32768)throw Error('Private human review draft must be ≤32 KiB.');
 const bytes=await file.arrayBuffer();if(bytes.byteLength!==file.size)throw Error('Source changed while reading.');
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(raw.charCodeAt(0)===0xfeff)throw Error('Unexpected file BOM.');
 const p=LightUpBriefCasework.strictJSON(raw);
 if(!exactKeys(p,['kind','schema_version','disposition','source_digest','source_sha256','previous_sha256','studio_revision_sha256','studio_earlier_sha256','authority','records','source_count','warning'])
    ||p.kind!==K||p.schema_version!==1||p.disposition!=='HUMAN_DISCUSSION_ONLY'
    ||!exactKeys(p.authority,AUTH)||!AUTH.every(x=>p.authority[x]===false)
    ||p.source_sha256!==info.fingerprint||p.previous_sha256!==info.previous
    ||p.studio_revision_sha256!==info.studioRevision||p.studio_earlier_sha256!==info.studioPrevious
    ||!Array.isArray(p.records)||p.records.length!==info.keys.length||p.source_count!==info.keys.length
    ||typeof p.warning!=='string'||p.warning.length>500)
  throw Error('Not an exact-source human-only private discussion draft.');
 if(p.source_digest!==await signature(info))throw Error('Original action source changed: reopen the matching source files.');
 const output={};info.keys.forEach((k,i)=>{output[k]=cleanState(p.records[i]);});
 return output;
}
function overview(info,records){
 const safe=collect(info,records),counts=Object.fromEntries(PHASES.map(k=>[k,0]));
 info.keys.forEach(k=>{counts[safe[k].phase]++;});
 return {categories:info.keys.length,counts,unverified:true,authorization_granted:false};
}
function csvEsc(x){
 const raw=String(x??''),safe=/^[\s\x00-\x1f]*[=+@-]/.test(raw)?"'"+raw:raw;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function toCSV(info,records){
 const data=collect(info,records);
 const head=['priority','human_discussion_category','original_record_count','suggested_human_step','role_to_contact','self_reported_discussion_phase','tentative_followup_date','action_completed_verified','permission_granted'];
 const rows=info.actions.map((a,i)=>{const v=data[info.keys[i]];
  return [a.level,a.title,a.source_count,a.next_human_step,v.role,v.phase,v.date,'FALSE','FALSE'];
 });
 return '\ufeff'+[head,...rows].map(row=>row.map(csvEsc).join(',')).join('\r\n')+'\r\n';
}
function icsDate(s){
 const d=new Date(s+'T00:00:00Z');if(!date(s))throw Error('Invalid planning date.');
 return d.toISOString().slice(0,10).replace(/-/g,'');
}
function nextDay(s){
 const dt=new Date(s+'T00:00:00Z');dt.setUTCDate(dt.getUTCDate()+1);
 return dt.toISOString().slice(0,10).replace(/-/g,'');
}
function icsEsc(s){return String(s).replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\r?\n/g,'\\n');}
function randomCalendarUID(){
 if(!global.crypto||typeof global.crypto.getRandomValues!=='function')
  throw Error('Secure random values unavailable; cannot create non-identifying calendar IDs.');
 const bytes=new Uint8Array(16);global.crypto.getRandomValues(bytes);
 const random=[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');
 return 'lightup-human-'+random+'@lightup.local';
}
async function toCalendar(info,records){
 const states=collect(info,records),lines=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LightUp//Human Offline Discussion Preview//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH','X-WR-CALNAME:LightUp tentative human discussions'];
 let count=0;
 info.actions.forEach((a,i)=>{
  const v=states[info.keys[i]];if(!v.date)return;
  // Source categories are derived from original offline display, not operator IDs.
  lines.push('BEGIN:VEVENT','UID:'+randomCalendarUID(),
   'DTSTAMP:'+new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,''),'DTSTART;VALUE=DATE:'+icsDate(v.date),
   'DTEND;VALUE=DATE:'+nextDay(v.date),'STATUS:TENTATIVE','CLASS:PRIVATE',
   'TRANSP:TRANSPARENT','SUMMARY:'+icsEsc('Tentative human security discussion: '+a.title),
   'DESCRIPTION:'+icsEsc('Self-reported planning: '+v.phase+'; role: '+v.role+'. NOT an authorized scan, grant, retest, consent, assignment or verified remediation.'),
   'END:VEVENT');count++;
 });
 lines.push('END:VCALENDAR');
 if(!count)throw Error('Set at least one tentative human discussion date before calendar export.');
 const enc=new TextEncoder();const folded=[];
 for(const line of lines){let chunk='',bytes=0;for(const ch of line){const width=enc.encode(ch).length;
   if(bytes+width>72){folded.push(chunk);chunk=' '+ch;bytes=1+width;}else{chunk+=ch;bytes+=width;}
  }folded.push(chunk);}
 return {content:folded.join('\r\n')+'\r\n',events:count};
}
global.LightUpFollowup=Object.freeze({source,blank,collect,make,read,overview,toCSV,toCalendar,roles:ROLES,phases:PHASES});
})(window);
