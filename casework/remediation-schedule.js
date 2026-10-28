/* Local date suggestions for remediation planning. Not regulatory SLAs, approvals or scanner deadlines. */
(function(global){
'use strict';
const SEVERITIES=['critical','high','medium','low','info'];
const DAY=86400000;
function day(iso){
 if(typeof iso!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(iso))return null;
 const d=new Date(iso+'T00:00:00.000Z');
 if(!Number.isFinite(d.valueOf())||d.toISOString().slice(0,10)!==iso)return null;
 if(d.getUTCFullYear()<2020||d.getUTCFullYear()>2100)return null;
 return d.getTime();
}
function prepare(findings,cases,anchor,policy){
 const start=day(anchor);
 if(start===null)throw Error('Select a valid local planning start date (2020–2100).');
 if(!policy||typeof policy!=='object'||Array.isArray(policy))throw Error('Specify a per-severity planning policy.');
 for(const level of SEVERITIES)
  if(!Number.isInteger(policy[level])||policy[level]<1||policy[level]>365)
   throw Error('Planning days must be integers from 1 to 365 for every severity.');
 const byId=new Map(cases.map(c=>[c.finding_id,c]));
 const entries=[];
 for(const f of findings){
  const c=byId.get(f.finding_id);
  if(!c)throw Error('Missing finding casework for '+f.finding_id.slice(0,60)+'.');
  if(c.due_date||c.status==='completed'||c.status==='deferred')continue;
  const horizon=start+policy[f.severity]*DAY;
  const d=new Date(horizon);
  if(!Number.isFinite(d.valueOf())||d.getUTCFullYear()>2100)throw Error('Proposed deadline exceeds supported calendar.');
  entries.push({finding_id:f.finding_id,severity:f.severity,proposed_due_date:d.toISOString().slice(0,10),days:policy[f.severity]});
 }
 return {
  kind:'lightup.local_deadline_suggestions',disposition:'UNAPPROVED_PLANNING_ONLY',
  authority:false,contractual_sla:false,retention_enforced:false,grant:false,
  anchor_date:anchor,policy:{...policy},entries
 };
}
global.LightUpRemediationSchedule=Object.freeze({prepare});
})(window);
