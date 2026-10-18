/* LightUp offline HUMAN-only owner allocation. No real identity, consent or permission. */
(function(global){
'use strict';
const MAX=350;
const ORDER=['critical','high','medium','low','info'];
function isOpen(c){return c.status!=='completed'&&c.status!=='deferred';}
function canonical(findings,cases){
 const engine=global.LightUpCasework;
 const accepted=engine.loadPacket(engine.makePacket(findings,cases,null));
 if(accepted.findings.length>MAX)throw Error('Owner work exceeds source bounds.');
 return accepted;
}
function report(findings,cases,today){
 const data=canonical(findings,cases),byId=new Map(data.findings.map(x=>[x.finding_id,x]));
 const groups=new Map();
 for(const c of data.cases){
  const f=byId.get(c.finding_id);if(!f||!isOpen(c))continue;
  const owner=c.owner.trim()||'(unassigned)';
  if(!groups.has(owner))groups.set(owner,{owner,total:0,criticalHigh:0,blocked:0,overdue:0,scheduled:0,readyForRetest:0});
  const g=groups.get(owner);g.total++;
  if(ORDER.indexOf(f.severity)<=1)g.criticalHigh++;
  if(c.status==='blocked')g.blocked++;
  if(c.due_date)g.scheduled++;
  if(c.due_date&&c.due_date<today)g.overdue++;
  if(c.status==='ready_for_retest')g.readyForRetest++;
 }
 return Array.from(groups.values()).sort((a,b)=>
  b.criticalHigh-a.criticalHigh||b.blocked-a.blocked||b.total-a.total||a.owner.localeCompare(b.owner));
}
function propose(findings,cases,ids,owner,onlyUnassigned){
 const data=canonical(findings,cases);
 if(typeof owner!=='string'||!owner.trim()||owner.length>120||
   /[\u0000-\u001f\u007f-\u009f]/.test(owner))
  throw Error('Human owner/team must be nonblank, at most 120 characters, without control characters.');
 if(!Array.isArray(ids)||ids.length>MAX||ids.length<1||new Set(ids).size!==ids.length)
  throw Error('Select one or more distinct original findings to assign.');
 const visible=new Set(ids),rows=[];
 for(const c of data.cases){
  if(!visible.has(c.finding_id)||!isOpen(c)||(onlyUnassigned&&c.owner.trim()))continue;
  rows.push({finding_id:c.finding_id,previous_owner:c.owner,next_owner:owner.trim()});
 }
 if(!rows.length)throw Error('No eligible open human cases in this selection.');
 return Object.freeze({rows,newOwner:owner.trim(),onlyUnassigned:!!onlyUnassigned});
}
function apply(findings,cases,proposal){
 const data=canonical(findings,cases),ids=new Set(data.findings.map(x=>x.finding_id));
 const prev=new Map(proposal.rows.map(x=>[x.finding_id,x]));
 if(prev.size!==proposal.rows.length)throw Error('Duplicate human assignment proposal.');
 const updated=data.cases.map(c=>{
  const change=prev.get(c.finding_id);
  if(!change)return c;
  if(!isOpen(c)||c.owner!==change.previous_owner||
     (proposal.onlyUnassigned&&c.owner.trim()))throw Error('Human assignment baseline changed; review again.');
  return global.LightUpCasework.cleanCase({...c,owner:change.next_owner,
    updated_utc:new Date().toISOString()},ids);
 });
 global.LightUpCasework.loadPacket(global.LightUpCasework.makePacket(data.findings,updated,null));
 return updated;
}
global.LightUpCalendarWorkload=Object.freeze({report,propose,apply});
})(window);
