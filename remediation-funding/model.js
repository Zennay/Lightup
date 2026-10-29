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
 fields(data,['schema','review_only',...DENIED,'source_count','proposed_completed',
   'total_estimated_hours','assigned_hours','backlog_hours','backlog_findings',
   'priority_bands','sprint_weeks']);
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
  if((b.source_count===0 || b.unscheduled_hours>0) && b.last_estimated_scheduling_week!==null)
    fail('Source reports a completion week for absent or unfinished work');
  if(b.source_count>0 && b.unscheduled_hours===0 && b.last_estimated_scheduling_week===null)
    fail('Source omits the estimated last allocation week');
  counts+=b.source_count;hours+=b.estimated_hours;unallocated+=b.unscheduled_hours;
 }
 if(counts!==data.source_count||hours!==data.total_estimated_hours||unallocated!==data.backlog_hours)fail('Priority bands disagree with totals');
 if(data.proposed_completed > data.source_count || data.backlog_findings > data.source_count)fail('Inconsistent record totals');
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
    provisionally_funded_hours:Math.floor((hours+1e-10)*10)/10,
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
 const lastUrgentIndex=urgentWeekBounds.reduce((last,w,i)=>w.urgent_scheduled_hours>0?i:last,-1);
 const fullCostBeforeLastUrgent=lastUrgentIndex<0?0:weekly.slice(0,lastUrgentIndex)
   .reduce((sum,w)=>sum+w.proposed_cost,0);
 const lastUrgentWeek=lastUrgentIndex<0?null:weekly[lastUrgentIndex];
 const earliestPossibleBudget=lastUrgentIndex<0?0:Math.round(
   (fullCostBeforeLastUrgent+
    (lastUrgentIndex===0?cfg.fixed_cost:0)+
    costOf(urgentWeekBounds[lastUrgentIndex].urgent_scheduled_hours))*100)/100;
 const conservativeBudget=lastUrgentIndex<0?0:Math.round(
   (fullCostBeforeLastUrgent+lastUrgentWeek.proposed_cost)*100)/100;
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
  urgent_work_budget_best_case_minimum:earliestPossibleBudget,
  urgent_work_budget_conservative_threshold:conservativeBudget,
  additional_funding_for_conservative_urgent_coverage:Math.max(0,Math.round((conservativeBudget-cfg.funding)*100)/100),
  last_week_with_proposed_urgent_work:lastUrgentIndex<0?null:lastUrgentIndex+1,
  weekly_critical_high_funding_bounds:Object.freeze(urgentWeekBounds),
  weeks:Object.freeze(weekly.map(Object.freeze)),funding:Object.freeze(fundingSchedule)
 });
}
function stagedFunding(source,raw,percentages) {
 const cfg=settings(raw);
 const baseline=project(source,cfg);
 if(!Array.isArray(percentages)||percentages.length!==source.weeks.length)
  fail('Specify one funding release percentage per planning week');
 const values=percentages.map((p,i)=>int(p,0,100,'release percentage for week '+(i+1)));
 if(values.reduce((a,b)=>a+b,0)!==100)fail('Funding releases must total exactly 100 percent');
 const weeklyCost=baseline.weeks;
 let cash=0;
 let setupUnpaid=cfg.fixed_cost;
 let assignedTotal=0;
 let urgentGuaranteed=0,urgentPossible=0;
 const entries=[];
 let allocatedAmount=0;
 for(let i=0;i<values.length;i++){
  const deposit=i===values.length-1?cfg.funding-allocatedAmount:
   Math.floor(cfg.funding*values[i]/100);
  allocatedAmount+=deposit;
  cash+=deposit;
  const setupPaid=Math.min(cash,setupUnpaid);cash-=setupPaid;setupUnpaid-=setupPaid;
  const laborProposed=Math.max(0,weeklyCost[i].proposed_cost-(i===0?cfg.fixed_cost:0));
  const laborPaid=Math.min(cash,laborProposed);cash-=laborPaid;
  const unitLabor=weeklyCost[i].proposed_hours
   ?laborProposed/weeklyCost[i].proposed_hours:0;
  const fundedHours=unitLabor===0?0:Math.min(weeklyCost[i].proposed_hours,laborPaid/unitLabor);
  const roundedHours=Math.floor((fundedHours+1e-10)*10)/10;
  assignedTotal+=roundedHours;
  const risk=source.weeks[i].risk_hours;
  const urgent=risk.critical+risk.high;
  const regular=source.weeks[i].hours-urgent;
  const urgentMin=Math.max(0,roundedHours-regular);
  const urgentMax=Math.min(urgent,roundedHours);
  urgentGuaranteed+=urgentMin;urgentPossible+=urgentMax;
  entries.push(Object.freeze({
   week:i+1,start:weeklyCost[i].start,
   deposit:deposit,proposed_cost:weeklyCost[i].proposed_cost,
   paid_setup:setupPaid,paid_proposed_labor:Math.round(laborPaid*100)/100,
   proposed_hours:weeklyCost[i].proposed_hours,
   funded_hours:roundedHours,
   hours_not_funded:Math.round((weeklyCost[i].proposed_hours-roundedHours)*10)/10,
   cash_carried_forward:Math.round(cash*100)/100,
   remaining_setup_unpaid:Math.round(setupUnpaid*100)/100,
   critical_high_maybe_unfunded_minimum:Math.round((urgent-urgentMax)*10)/10,
   critical_high_maybe_unfunded_maximum:Math.round((urgent-urgentMin)*10)/10
  }));
 }
 const urgent=baseline.critical_high_proposed_hours;
 return Object.freeze({
  schema:'lightup.remediation_staged_funding_draft.v1',
  review_only:true,authorization:false,consent:false,grant:false,scan:false,
  execute:false,dispatch:false,retest_verified:false,deploy:false,release:false,
  currency:cfg.currency,total_funding:cfg.funding,
  planned_hours:source.allocated_hours,
  provisionally_funded_hours:Math.round(assignedTotal*10)/10,
  unpaid_planned_hours:Math.round((source.allocated_hours-assignedTotal)*10)/10,
  urgent_potentially_unfunded_lower_hours:Math.round((urgent-urgentPossible)*10)/10,
  urgent_potentially_unfunded_upper_hours:Math.round((urgent-urgentGuaranteed)*10)/10,
  unused_funds_end:Math.round(cash*100)/100,
  setup_cost_still_unpaid:Math.round(setupUnpaid*100)/100,
  release_percentages:Object.freeze(values),
  weeks:Object.freeze(entries)
 });
}
// REVIEW_ONLY funding envelopes: two explicitly hypothetical ways to divide
// the same funded weekly hours; neither mode identifies or assigns a real case.
function fundingPriorities(source,raw,percentages) {
 const cash=stagedFunding(source,raw,percentages);
 const order=BANDS;
 function distribute(week, fundedHours, mode) {
  const planned=week.risk_hours;
  const total=week.hours;
  const tenths=Math.min(total*10,Math.floor((fundedHours+1e-9)*10));
  const limits=Object.fromEntries(order.map(k=>[k,planned[k]*10]));
  const assigned=Object.fromEntries(order.map(k=>[k,0]));
  if(mode==='urgent_first') {
   let remaining=tenths;
   for(const key of order) {
    assigned[key]=Math.min(limits[key],remaining);
    remaining-=assigned[key];
   }
   if(remaining!==0)fail('Could not allocate the modelled funded hours');
  }else if(mode==='proportional') {
   if(total>0) {
    let remaining=tenths;
    const fractions=[];
    for(const key of order) {
      const numerator=tenths*limits[key];
      const portion=Math.floor(numerator/(total*10));
      assigned[key]=Math.min(portion,limits[key]);
      remaining-=assigned[key];
      fractions.push({key,frac:numerator%(total*10)});
    }
    fractions.sort((a,b)=>b.frac-a.frac || order.indexOf(a.key)-order.indexOf(b.key));
    while(remaining>0) {
      let granted=false;
      for(const candidate of fractions) {
        if(remaining===0)break;
        if(assigned[candidate.key]<limits[candidate.key]) {
          assigned[candidate.key]++; remaining--; granted=true;
        }
      }
      if(!granted)fail('Funding capacity is inconsistent with weekly severity');
    }
   }
  }else fail('Unknown modeled funding strategy');
  const perBand=Object.freeze(Object.fromEntries(order.map(key=>[key,Object.freeze({
    proposed_hours:limits[key]/10,
    tentatively_funded_hours:assigned[key]/10,
    unfinanced_hours:(limits[key]-assigned[key])/10
  })])));
  return Object.freeze({perBand,
    proposed_hours:total,
    tentatively_funded_hours:tenths/10,
    unfinanced_hours:(total*10-tenths)/10,
    critical_high_tentatively_funded_hours:(assigned.critical+assigned.high)/10});
 }
 function allocate(mode) {
  const totals=Object.fromEntries(order.map(k=>[k,{
    proposed_hours:0,tentatively_funded_hours:0,unfinanced_hours:0
  }]));
  const weeks=source.weeks.map((week,index)=>{
    const allocated=distribute(week,cash.weeks[index].funded_hours,mode);
    for(const key of order) {
      totals[key].proposed_hours+=allocated.perBand[key].proposed_hours;
      totals[key].tentatively_funded_hours+=allocated.perBand[key].tentatively_funded_hours;
      totals[key].unfinanced_hours+=allocated.perBand[key].unfinanced_hours;
    }
    return Object.freeze({week:week.week,start:week.start,
      deposited_amount:cash.weeks[index].deposit,
      modeled_labor_paid:cash.weeks[index].paid_proposed_labor,
      ...allocated});
  });
  const bySeverity=Object.freeze(Object.fromEntries(order.map(key=>[key,Object.freeze({
    proposed_hours:Math.round(totals[key].proposed_hours*10)/10,
    tentatively_funded_hours:Math.round(totals[key].tentatively_funded_hours*10)/10,
    unfinanced_hours:Math.round(totals[key].unfinanced_hours*10)/10
  })])));
  return Object.freeze({mode,by_severity:bySeverity,weeks:Object.freeze(weeks),
    critical_high_funded_hours:Math.round((
      totals.critical.tentatively_funded_hours+totals.high.tentatively_funded_hours)*10)/10,
    critical_high_unfinanced_hours:Math.round((
      totals.critical.unfinanced_hours+totals.high.unfinanced_hours)*10)/10});
 }
 const priority=allocate('urgent_first');
 const balanced=allocate('proportional');
 return Object.freeze({
  schema:'lightup.remediation_funding_priority_draft.v1',
  review_only:true,authorization:false,consent:false,grant:false,
  scan:false,execute:false,dispatch:false,retest_verified:false,deploy:false,release:false,
  currency:cash.currency,
  source_count:source.source_count,
  planned_weeks:source.weeks.length,
  total_modelled_budget:cash.total_funding,
  source_unscheduled_urgent_hours:source.risk.critical.backlog+source.risk.high.backlog,
  staged_weekly_releases:Object.freeze([...cash.release_percentages]),
  urgent_first:priority,proportional:balanced,
  modelled_urgent_funding_difference_hours:Math.round(
    (priority.critical_high_funded_hours-balanced.critical_high_funded_hours)*10)/10
 });
}
function priorityDiscussionMarkdown(model) {
 if(!model || model.schema!=='lightup.remediation_funding_priority_draft.v1')
  fail('Generate a private risk funding plan first');
 const text=[
  '# LightUp — funding priorities discussion (UNSIGNED DRAFT)',
  '',
  '**REVIEW_ONLY · DRAFT/HOLD · No real approval, consent, grant, dispatch, scan, retest, completed fix or release.**',
  '',
  'This unsigned financial illustration uses only earlier aggregate planning data. Severity-first is a hypothetical financing policy, not an actual source finding allocation.',
  '',
  '- Reporting currency: '+model.currency+' (no FX)',
  '- Total modelled funding: '+model.total_modelled_budget,
  '- Additional urgent funded hours under hypothetical urgent-first versus proportional: '+model.modelled_urgent_funding_difference_hours,
  '- Unplanned critical/high workload outside this source schedule: '+model.source_unscheduled_urgent_hours+' hours',
  '',
  '| Severity | Proposed hours | Urgent-first funded hours | Urgent-first unfunded hours | Proportional funded hours | Proportional unfunded hours |',
  '| --- | ---: | ---: | ---: | ---: | ---: |'
 ];
 for(const key of BANDS) {
  const a=model.urgent_first.by_severity[key];
  const b=model.proportional.by_severity[key];
  text.push('| '+[key,a.proposed_hours,a.tentatively_funded_hours,a.unfinanced_hours,
    b.tentatively_funded_hours,b.unfinanced_hours].join(' | ')+' |');
 }
 text.push('','**Human decisions needed:** independently confirm source client/engagement, original authorization and revocation, real budgets, repair owners, procurement and separately verified retests. This file cannot authorize any work.','');
 return text.join('\n');
}
function fundingTimingComparison(source,raw,selectedReleases) {
 const cfg=settings(raw);
 if(!source||!Array.isArray(source.weeks)||!source.weeks.length)
  fail('Choose a previously loaded aggregate source');
 const n=source.weeks.length;
 const upfront=[100,...Array(n-1).fill(0)];
 const even=Array(n).fill(Math.floor(100/n));
 even[n-1]+=100-even.reduce((sum,x)=>sum+x,0);
 const configs=[['all_upfront',upfront],['evenly_released',even],['selected_schedule',selectedReleases]];
 const records=configs.map(([name,releases])=>{
  const stages=stagedFunding(source,cfg,releases);
  const risks=fundingPriorities(source,cfg,releases);
  return Object.freeze({
   name,
   release_percentages:Object.freeze([...stages.release_percentages]),
   modeled_total_funding:stages.total_funding,
   planned_hours:stages.planned_hours,
   tentatively_funded_hours:stages.provisionally_funded_hours,
   hours_unfunded_at_original_weeks:stages.unpaid_planned_hours,
   critical_high_coverage_best_case_hours:
    Math.round((risks.urgent_first.critical_high_funded_hours)*10)/10,
   critical_high_coverage_proportional_hours:
    Math.round((risks.proportional.critical_high_funded_hours)*10)/10,
   critical_high_unfunded_best_case_hours:
    Math.round((risks.urgent_first.critical_high_unfinanced_hours)*10)/10,
   critical_high_unfunded_proportional_hours:
    Math.round((risks.proportional.critical_high_unfinanced_hours)*10)/10,
   unpaid_setup:stages.setup_cost_still_unpaid,
   unused_budget:stages.unused_funds_end,
   critical_high_outside_source_plan:risks.source_unscheduled_urgent_hours
  });
 });
 const earliest=records[0];
 return Object.freeze({
  schema:'lightup.remediation_release_timing_review.v1',
  review_only:true,authorization:false,consent:false,grant:false,
  scan:false,execute:false,dispatch:false,retest_verified:false,deploy:false,release:false,
  currency:cfg.currency,source_count:source.source_count,
  scenarios:Object.freeze(records),
  selected_versus_upfront_unfunded_extra_hours:Math.round(
   (records[2].hours_unfunded_at_original_weeks-earliest.hours_unfunded_at_original_weeks)*10)/10,
  selected_versus_upfront_critical_high_unfunded_extra_hours:Math.round(
   (records[2].critical_high_unfunded_best_case_hours-earliest.critical_high_unfunded_best_case_hours)*10)/10
 });
}
function timingDiscussionMarkdown(comparison){
 if(!comparison||comparison.schema!=='lightup.remediation_release_timing_review.v1')
  fail('Generate a local timing comparison first');
 const lines=[
  '# LightUp — timing-of-funds discussion (UNSIGNED DRAFT)',
  '',
  '**REVIEW_ONLY · INCUBATE M3/M7 · DRAFT/HOLD.** No client authentication, real consent, grant, remediation, retest, money transfer or release.',
  '',
  'These scenarios use exactly the same total hypothetical money and originally exported aggregate hours. Funding paid too late does not retroactively finance earlier planned work.',
  '',
  '| Cash release | Total model budget | Proposed hours | Funded hours | Unfunded hours at source weeks | Urgent-first critical/high unfunded | Proportional critical/high unfunded | Setup still unpaid | Cash left unused |',
  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'
 ];
 for(const scenario of comparison.scenarios)lines.push(
  '| '+[scenario.name,scenario.modeled_total_funding,scenario.planned_hours,
   scenario.tentatively_funded_hours,scenario.hours_unfunded_at_original_weeks,
   scenario.critical_high_unfunded_best_case_hours,
   scenario.critical_high_unfunded_proportional_hours,
   scenario.unpaid_setup,scenario.unused_budget].join(' | ')+' |'
 );
 lines.push('','- Currency: '+comparison.currency+' (no currency conversions).',
  '- Selected release versus all upfront — additional modeled original-week unfunded hours: '+comparison.selected_versus_upfront_unfunded_extra_hours,
  '- Selected release versus all upfront — additional modeled critical/high unfunded hours under urgent-first: '+comparison.selected_versus_upfront_critical_high_unfunded_extra_hours,
  '',
  'Human follow-up: confirm actual authorised source, engagement, contracts, procurement and payment calendar independently. All estimates are unverified proposals; never start a scan, grant, or retest from this brief.','');
 return lines.join('\n');
}
root.LightUpFunding=Object.freeze({intake,settings,project,stagedFunding,fundingPriorities,priorityDiscussionMarkdown,fundingTimingComparison,timingDiscussionMarkdown,SCHEMA,MAX_SIZE:65536});
})(window);