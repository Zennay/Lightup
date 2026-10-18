/* LightUp private human dependency planning — NEVER assessment or remediation authority. */
(function(g){'use strict';
const AUTH=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const SRC=['finding_id','title','severity','retest_status','remediation'];
const CASE=['finding_id','owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
const IN=['kind','schema_version','disposition','source_contract','source_sha256','findings','cases','instructions',...AUTH];
const DEP=['kind','schema_version','disposition','source_sha256','casework_sha256','links','efforts','instructions',...AUTH];
function stop(s){throw Error(s);}
function shape(x,fields,name){if(!x||typeof x!=='object'||Array.isArray(x))stop('Invalid '+name);const allowed=new Set(fields),keys=Object.keys(x);if(keys.length!==allowed.size||keys.some(k=>!allowed.has(k)))stop('Missing or unknown '+name+' field.');}
async function sha(s){if(!g.crypto||!g.crypto.subtle)stop('Secure SHA-256 unavailable. Private handoff HELD.');const a=new Uint8Array(await g.crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));return Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');}
function canonical(w){const sort=arr=>arr.slice().sort((a,b)=>a.finding_id.localeCompare(b.finding_id));return JSON.stringify([sort(w.findings),sort(w.cases)]);}
async function original(packet){
 shape(packet,IN,'original Casework');for(const k of AUTH)if(packet[k]!==false)stop('Casework claims authority.');
 if(!Array.isArray(packet.findings)||!Array.isArray(packet.cases))stop('Missing original findings and Casework.');
 for(const f of packet.findings)shape(f,SRC,'source finding');for(const c of packet.cases)shape(c,CASE,'source Casework');
 const clean=g.LightUpCasework.loadPacket(packet);
 const digest=await g.LightUpCasework.digest(clean.findings);
 if(!digest||clean.source_sha256&&clean.source_sha256!==digest)stop('Original source SHA mismatch.');
 const w={...clean,source_sha256:digest};
 w.casework_sha256=await sha(canonical(w));return w;
}
function clean(w,links,efforts){
 if(!w||!Array.isArray(w.findings)||!w.findings.length||w.findings.length>350||!Array.isArray(w.cases)||w.cases.length!==w.findings.length)stop('Incomplete original source.');
 const ids=new Set(w.findings.map(x=>x.finding_id));if(ids.size!==w.findings.length)stop('Duplicate original ID.');
 if(!Array.isArray(links)||links.length>1200)stop('Too many dependency links.');
 const seen=new Set(),out=new Map([...ids].map(id=>[id,[]])),indeg=new Map([...ids].map(id=>[id,0]));
 const edges=links.map(e=>{shape(e,['from','to','reason'],'dependency');if(!ids.has(e.from)||!ids.has(e.to)||e.from===e.to)stop('Unknown or self-dependent finding.');if(typeof e.reason!=='string'||e.reason.length>600||/[\x00-\x1f\x7f-\x9f]/.test(e.reason))stop('Invalid reason.');const k=JSON.stringify([e.from,e.to]);if(seen.has(k))stop('Duplicate dependency.');seen.add(k);out.get(e.from).push(e.to);indeg.set(e.to,indeg.get(e.to)+1);return {from:e.from,to:e.to,reason:e.reason};});
 if(!Array.isArray(efforts)||efforts.length!==ids.size)stop('Incomplete human effort estimates.');
 const durations=new Map();
 for(const e of efforts){shape(e,['finding_id','days'],'effort');if(!ids.has(e.finding_id)||durations.has(e.finding_id)||!Number.isInteger(e.days)||e.days<1||e.days>90)stop('Invalid human effort.');durations.set(e.finding_id,e.days);}
 const ready=[...ids].filter(id=>!indeg.get(id)).sort(),order=[];
 while(ready.length){const id=ready.shift();order.push(id);for(const next of out.get(id)){indeg.set(next,indeg.get(next)-1);if(indeg.get(next)===0){ready.push(next);ready.sort();}}}
 if(order.length!==ids.size)stop('Circular dependency — no change applied.');
 return {links:edges,efforts:[...durations].map(([finding_id,days])=>({finding_id,days})),order,durations};
}
function empty(w){return clean(w,[],w.findings.map(f=>({finding_id:f.finding_id,days:1})));}
function graph(w,links,efforts,start){
 const p=clean(w,links,efforts),find=new Map(w.findings.map(f=>[f.finding_id,f])),human=new Map(w.cases.map(c=>[c.finding_id,c]));
 const parents=new Map([...find.keys()].map(id=>[id,[]]));for(const e of p.links)parents.get(e.to).push(e.from);
 const finish=new Map(),longest=new Map(),rows=[];
 for(const id of p.order){let offset=0,prev=null;for(const from of parents.get(id)){if(finish.get(from)>offset){offset=finish.get(from);prev=from;}}const end=offset+p.durations.get(id);finish.set(id,end);longest.set(id,prev);const f=find.get(id),c=human.get(id);const waiting=parents.get(id).filter(ref=>human.get(ref).status!=='completed');rows.push({finding_id:id,title:f.title,severity:f.severity,original_retest:f.retest_status,owner:c.owner,human_status:c.status,human_due:c.due_date,waiting,prerequisites:parents.get(id),effort_days:p.durations.get(id),path_days:end,human_ready:!waiting.length&&!['completed','deferred'].includes(c.status)});}
 let end=0,tip=null;for(const [id,d] of finish){if(d>end){end=d;tip=id;}}
 const critical=[];while(tip){critical.unshift(tip);tip=longest.get(tip);}
 let dates=null;if(start){if(typeof start!=='string'||!/^20\d{2}-\d{2}-\d{2}$/.test(start))stop('Invalid optional human planning start.');const ms=Date.parse(start+'T00:00:00Z');if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==start||start>'2099-01-01')stop('Unsupported planning anchor.');dates={};for(const row of rows){const d=new Date(ms+row.path_days*86400000);if(d.getUTCFullYear()>2100)stop('Human estimate exceeds calendar range.');dates[row.finding_id]=d.toISOString().slice(0,10);}}
 return {rows,critical,estimated_days:end,dates,summary:{total:rows.length,links:p.links.length,waiting:rows.filter(x=>x.waiting.length).length,ready:rows.filter(x=>x.human_ready).length,critical_high_waiting:rows.filter(x=>x.waiting.length&&['critical','high'].includes(x.severity)).length}};
}
function packet(w,links,efforts){const p=clean(w,links,efforts);return {kind:'lightup.private_human_dependency_draft',schema_version:1,disposition:'LOCAL_HUMAN_PLANNING_ONLY',source_sha256:w.source_sha256,casework_sha256:w.casework_sha256,links:p.links,efforts:p.efforts,instructions:'Unverified private human estimates only; no verified remediation, consent, grant, scanner, retest, tenant or authorization.',...Object.fromEntries(AUTH.map(k=>[k,false]))};}
function restore(w,raw){shape(raw,DEP,'private dependencies');if(raw.kind!=='lightup.private_human_dependency_draft'||raw.schema_version!==1||raw.disposition!=='LOCAL_HUMAN_PLANNING_ONLY'||raw.source_sha256!==w.source_sha256||raw.casework_sha256!==w.casework_sha256||typeof raw.instructions!=='string'||raw.instructions.length>1500||AUTH.some(k=>raw[k]!==false))stop('Private human dependency packet conflicts with current original source or human notes.');return clean(w,raw.links,raw.efforts);}
g.LightUpHumanDependencies=Object.freeze({original,clean,empty,graph,packet,restore});
})(window);
