/* LightUp Remediation Funding Studio: offline aggregate review only.
   No authorisation, identity, source findings, local persistence or network. */
(function(root) {
'use strict';
const SCHEMA='lightup.remediation_capacity_draft.v1';
const BANDS=['critical','high','medium','low','info'];
const DENIED=['authorization','consent','grant','scan','execute','dispatch','retest_verified','deploy','release'];
const fail=m=>{throw Error(m);};
const int=(x,min,max,label)=>{if(typeof x!=='number'||!Number.isSafeInteger(x)||x<min||x>max)fail('Invalid '+label);return x;};
const fields=(o,ks)=>{if(!o||typeof o!=='object'||Array.isArray(o)||Object.keys(o).length!==ks.length||ks.some(k=>!Object.prototype.hasOwnProperty.call(o,k)))fail('Unexpected or missing aggregate fields');};

/* Local bounded recursive parser rejects duplicate JSON keys including escaped aliases. */
function uniqueJSON(text){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>65536)fail('Aggregate report exceeds 64 KiB');
 let i=0;const maxDepth=14;
 const ws=()=>{while(/\s/.test(text[i]||'')&&i<text.length)i++;};
 function str(){
  const begin=i++;let escaped=false;
  for(;i<text.length;i++){
   const c=text[i];if(!escaped&&c==='"'){i++;try{return JSON.parse(text.slice(begin,i))}catch{fail('Malformed JSON string');}}
   if(!escaped&&c==='\\'){escaped=true;continue;}
   escaped=false;
  }fail('Unterminated JSON string');
 }
 function parse(depth){
  if(depth>maxDepth)fail('Excessive aggregate nesting');
  ws();let c=text[i];
  if(c==='"')return str();
  if(c==='{'){
   i++;const o=Object.create(null),seen=new Set();ws();
   if(text[i]==='}'){i++;return o;}
   while(i<text.length){
    ws();if(text[i]!=='"')fail('Expected JSON key');
    const k=str();if(seen.has(k))fail('Duplicate JSON key');seen.add(k);
    ws();if(text[i++]!==':')fail('Expected colon');
    o[k]=parse(depth+1);ws();
    if(text[i]==='}'){i++;return o;}if(text[i++]!==',')fail('Expected comma');
   }fail('Unclosed object');
  }
  if(c==='['){
   i++;const arr=[];ws();if(text[i]===']'){i++;return arr;}
   while(i<text.length){if(arr.length>1000)fail('Oversized array');arr.push(parse(depth+1));ws();if(text[i]===']'){i++;return arr;}if(text[i++]!==',')fail('Expected array comma');}
   fail('Unclosed array');
  }
  const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
  if(!match)fail('Invalid JSON value');i+=match[0].length;return JSON.parse(match[0]);
 }
 const value=parse(0);ws();if(i!==text.length)fail('Trailing JSON bytes');return value;
}
function intake(text){
 const data=uniqueJSON(text);
 if(data.schema!==SCHEMA||data.review_only!==true||DENIED.some(k=>data[k]!==false))
  fail('Wrong source schema or authority claim');
 int(data.source_count,1,350,'record count');
 int(data.proposed_completed,0,data.source_count,'estimated completed count');
 int(data.total_estimated_hours,1,70000,'estimated hours');
 int(data.assigned_hours,0,70000,'allocated hours');
 int(data.backlog_hours,0,70000,'unallocated hours');
 if(data.assigned_hours+data.backlog_hours!==data.total_estimated_hours)fail('Hours do not balance');
 int(data.backlog_findings,0,data.source_count,'backlog count');
 if(!Array.isArray(data.sprint_weeks)||!data.sprint_weeks.length||data.sprint_weeks.length>12)fail('Malformed sprint weeks');
 const risk=data.priority_bands;fields(risk,BANDS);
 let counts=0,hours=0,unallocated=0;
 for(const band of BANDS){
  const b=risk[band];
  const required=['source_count','source_regressions','estimated_hours','scheduled_hours','unscheduled_hours','fully_scheduled_estimates','all_estimates_scheduled','last_estimated_scheduling_week'];
  fields(b,required);
  int(b.source_count,0,350,'source severity count');
  int(b.source_regressions,0,b.source_count,'regressions');
  int(b.estimated_hours,0,70000,'severity estimated hours');
  int(b.scheduled_hours,0,b.estimated_hours,'severity scheduled hours');
  int(b.unscheduled_hours,0,b.estimated_hours,'severity remaining hours');
  int(b.fully_scheduled_estimates,0,b.source_count,'severity allocated records');
  if(b.scheduled_hours+b.unscheduled_hours!==b.estimated_hours)fail('Severity hours do not balance');
  if(typeof b.all_estimates_scheduled!=='boolean'||b.all_estimates_scheduled!==(b.unscheduled_hours===0))fail('Misleading severity completion');
  if(b.last_estimated_scheduling_week!==null)int(b.last_estimated_scheduling_week,1,data.sprint_weeks.length,'final week');
  counts+=b.source_count;hours+=b.estimated_hours;unallocated+=b.unscheduled_hours;
 }
 if(counts!==data.source_count||hours!==data.total_estimated_hours||unallocated!==data.backlog_hours)fail('Priority bands disagree with totals');
 let weekHours=0,prior='';
 const weeks=data.sprint_weeks.map((w,index)=>{
  fields(w,['week','start','availability_pct','available_hours','allocated_hours','severity_hours']);
  if(w.week!==index+1||typeof w.start!=='string'||!/^\d{4}-\d\d-\d\d$/.test(w.start))fail('Inconsistent week chronology');
  const ms=Date.parse(w.start+'T00:00:00Z');
  if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,10)!==w.start)fail('Invalid week start');
  if(prior&&ms-Date.parse(prior+'T00:00:00Z')!==7*86400000)fail('Non-weekly start dates');
  prior=w.start;
  int(w.availability_pct,0,100,'availability');
  int(w.available_hours,0,3000,'capacity');
  int(w.allocated_hours,0,w.available_hours,'weekly allocated hours');
  fields(w.severity_hours,BANDS);
  if(BANDS.reduce((sum,s)=>sum+int(w.severity_hours[s],0,3000,'severity hours'),0)!==w.allocated_hours)fail('Weekly risk hours inconsistent');
  weekHours+=w.allocated_hours;
  return Object.freeze({week:w.week,start:w.start,capacity:w.available_hours,hours:w.allocated_hours,
   risk_hours:Object.freeze(Object.fromEntries(BANDS.map(b=>[b,w.severity_hours[b]])))});
 });
 if(weekHours!==data.assigned_hours)fail('Aggregate weeks do not match source total');
 if(data.proposed_completed + data.backlog_findings !== data.source_count)
   fail('Reported finished estimates contradict source backlog');
 if(BANDS.reduce((sum,b)=>sum+risk[b].fully_scheduled_estimates,0)!==data.proposed_completed)
   fail('Risk-band completed estimates contradict source totals');
 for(const severity of BANDS) {
   const allocatedInWeeks=data.sprint_weeks.reduce((sum,week)=>sum+week.severity_hours[severity],0);
   if(allocatedInWeeks!==risk[severity].scheduled_hours)
     fail('Week and priority-band allocations contradict each other');
 }

 return Object.freeze({
  source_count:data.source_count,total_hours:hours,allocated_hours:weekHours,
  backlog_hours:data.backlog_hours,backlog_findings:data.backlog_findings,
  weeks:Object.freeze(weeks),risk:Object.freeze(Object.fromEntries(BANDS.map(b=>[b,Object.freeze({
   hours:risk[b].estimated_hours,backlog:risk[b].unscheduled_hours,regressions:risk[b].source_regressions
  })])))
 });
}
function settings(cfg){
 const keys=['internal_rate','external_rate','outsourced_pct','contingency_pct','fixed_cost','funding','currency'];
 fields(cfg,keys);
 if(!['EUR','GBP','USD'].includes(cfg.currency))fail('Unsupported display currency, no FX conversions offered');
 return Object.freeze({
  internal_rate:int(cfg.internal_rate,1,2000,'internal hourly rate'),
  external_rate:int(cfg.external_rate,1,3000,'external hourly rate'),
  outsourced_pct:int(cfg.outsourced_pct,0,100,'external fraction'),
  contingency_pct:int(cfg.contingency_pct,0,100,'contingency reserve'),
  fixed_cost:int(cfg.fixed_cost,0,1000000,'one-time tooling or setup expense'),
  funding:int(cfg.funding,0,100000000,'total available funding'),
  currency:cfg.currency
 });
}
function project(source,raw) {
 const cfg=settings(raw);
 if(!source||!Array.isArray(source.weeks))fail('Load original aggregate first');
 const perHour=cfg.internal_rate*(100-cfg.outsourced_pct)/100+cfg.external_rate*cfg.outsourced_pct/100;
 const costOf=hours=>Math.round(hours*perHour*(1+cfg.contingency_pct/100)*100)/100;
 const weekly=source.weeks.map(w=>({
  week:w.week,start:w.start,capacity_hours:w.capacity,proposed_hours:w.hours,
  proposed_cost:costOf(w.hours)+(w.week===1?cfg.fixed_cost:0),
  internal_hours:Math.round(w.hours*(100-cfg.outsourced_pct))/100,
  external_hours:Math.round(w.hours*cfg.outsourced_pct)/100
 }));
 const total=weekly.reduce((sum,w)=>sum+w.proposed_cost,0);
 const roundedTotal=Math.round(total*100)/100;
 let remaining=cfg.funding;
 const fundingSchedule=weekly.map(w=>{
  const startup=w.week===1?cfg.fixed_cost:0;
  const fundedSetup=Math.min(remaining,startup);remaining-=fundedSetup;
  const spend=Math.min(remaining,w.proposed_cost-startup);
  remaining-=spend;
  const hours=w.proposed_hours===0?0:Math.min(w.proposed_hours,spend/(costOf(1)||1));
  return Object.freeze({
    week:w.week,start:w.start,planned_cost:w.proposed_cost,
    funded_cost:Math.round((fundedSetup+spend)*100)/100,
    provisionally_funded_hours:Math.round(hours*10)/10,
    proposed_hours:w.proposed_hours
  });
 });
 // Funding allocation is a money bound, not an authenticated ordering of individual cases.
 // Report the pessimistic and optimistic urgent-hour coverage rather than inventing case order.
 const urgentWeekBounds=fundingSchedule.map((funded,i)=>{
   const severity=source.weeks[i].risk_hours;
   const urgent=severity.critical+severity.high;
   const ordinary=source.weeks[i].hours-urgent;
   const fundedHours=Math.min(source.weeks[i].hours,funded.provisionally_funded_hours);
   const minimum=Math.max(0,fundedHours-ordinary);
   const maximum=Math.min(urgent,fundedHours);
   return Object.freeze({
     week:funded.week,urgent_scheduled_hours:urgent,
     nominally_funded_urgent_minimum_hours:Math.round(minimum*10)/10,
     nominally_funded_urgent_maximum_hours:Math.round(maximum*10)/10,
     urgent_potentially_unfunded_minimum_hours:Math.round((urgent-maximum)*10)/10,
     urgent_potentially_unfunded_maximum_hours:Math.round((urgent-minimum)*10)/10
   });
 });
 const urgentTotal=urgentWeekBounds.reduce((sum,v)=>sum+v.urgent_scheduled_hours,0);
 const urgentAtRiskMin=urgentWeekBounds.reduce((sum,v)=>sum+v.urgent_potentially_unfunded_minimum_hours,0);
 const urgentAtRiskMax=urgentWeekBounds.reduce((sum,v)=>sum+v.urgent_potentially_unfunded_maximum_hours,0);
 const fundingGap=Math.max(0,Math.round((roundedTotal-cfg.funding)*100)/100);
 return Object.freeze({
  schema:'lightup.remediation_funding_discussion_v1',review_only:true,
  authorization:false,consent:false,grant:false,scan:false,execute:false,dispatch:false,
  retest_verified:false,deploy:false,release:false,
  currency:cfg.currency,source_count:source.source_count,
  capacity_backlog_hours:source.backlog_hours,
  estimated_plan_cost:roundedTotal,available_funding:cfg.funding,
  estimated_shortfall:fundingGap,estimated_funding_surplus:Math.max(0,Math.round((cfg.funding-roundedTotal)*100)/100),
  remaining_backlog_opportunity_cost:costOf(source.backlog_hours),
  modeled_internal_share_pct:100-cfg.outsourced_pct,modeled_external_share_pct:cfg.outsourced_pct,
  hourly_blended_rate:Math.round(perHour*100)/100,contingency_pct:cfg.contingency_pct,
  one_time_cost:cfg.fixed_cost,
  critical_high_proposed_hours:urgentTotal,
  critical_high_potential_unfunded_hours_minimum:Math.round(urgentAtRiskMin*10)/10,
  critical_high_potential_unfunded_hours_maximum:Math.round(urgentAtRiskMax*10)/10,
  critical_high_outside_source_plan_hours:source.risk.critical.backlog+source.risk.high.backlog,
  weekly_critical_high_funding_bounds:Object.freeze(urgentWeekBounds),
  weeks:Object.freeze(weekly.map(Object.freeze)),funding:Object.freeze(fundingSchedule)
 });
}
root.LightUpFunding=Object.freeze({intake,settings,project,SCHEMA,MAX_SIZE:65536});
})(window);