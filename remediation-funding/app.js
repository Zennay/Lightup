/* Local-only controller for LightUp's non-authorizing finance review */
(function () {
'use strict';
const core=window.LightUpFunding;
const el=id=>document.getElementById(id);
const mk=(tag,content,cls)=>{
 const e=document.createElement(tag);
 if(content!==undefined)e.textContent=String(content);
 if(cls)e.className=cls;
 return e;
};
const val=name=>el('settings').elements.namedItem(name).value;
const show=(str,isError=false)=>{
 const target=el('notice');target.textContent=str;target.classList.toggle('error',isError);
};
const currency=(code,value)=>{
 const locale=code==='EUR'?'nl-NL':code==='GBP'?'en-GB':'en-US';
 return new Intl.NumberFormat(locale,{style:'currency',currency:code,maximumFractionDigits:2}).format(value);
};
let source=null,forecast=null,settings=null,comparison=null,staged=null,priorityPlan=null,timingPlan=null;
function clearResults(){
 forecast=null;settings=null;comparison=null;staged=null;el('results').hidden=true;
 el('release-summary').replaceChildren();el('release-weeks').replaceChildren();el('release-export').hidden=true;
 clearFundingPriority();
 clearTimingPlan();
 el('kpis').replaceChildren();el('weeks').replaceChildren();el('scenario').replaceChildren();
 el('risk-exposure').replaceChildren();el('risk-weeks').replaceChildren();
}
function forget(){
 source=null;clearResults();el('input').value='';el('forecast').disabled=true;
 el('source-state').textContent='No aggregate source loaded. No browser data was saved.';
 show('The previously imported aggregate and local financial scenarios have been forgotten.');
}
el('forget').addEventListener('click',forget);
el('input').addEventListener('change',async()=>{
 const file=el('input').files?.[0];
 source=null;clearResults();el('forecast').disabled=true;
 el('source-state').textContent='No valid aggregate loaded.';
 if(!file)return;
 try {
  if(file.size===0||file.size>core.MAX_SIZE)throw Error('Source must be a nonempty aggregate JSON no larger than 64 KiB');
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
  const parsed=core.intake(raw);
  if(el('input').files?.[0]!==file)return;
  source=parsed;
  el('forecast').disabled=false;
  el('source-state').textContent=
   'Review-only aggregate: '+parsed.source_count+' records, '+parsed.weeks.length+
   ' weeks, '+parsed.allocated_hours+' tentatively scheduled hours and '+
   parsed.backlog_hours+' unscheduled hours. No original finding information loaded.';
  show('Aggregate accepted locally. Adjust your own private cost assumptions.');
 }catch(err){show('HOLD: '+(err instanceof Error?err.message:'Import rejected'),true);}
});
function modelInput(){
 const numeric={};
 for(const key of ['internal_rate','external_rate','outsourced_pct','contingency_pct','fixed_cost','funding']){
  const t=val(key);
  if(!/^(0|[1-9][0-9]*)$/.test(t))throw Error('Use integer amounts and percentages only');
  numeric[key]=Number(t);
 }
 return {...numeric,currency:val('currency')};
}
function stat(label,value){
 const card=mk('div',undefined,'stat');card.append(mk('strong',value),mk('span',label));return card;
}
function rows(model){
 const tbody=el('weeks');tbody.replaceChildren();
 for(const [i,w] of model.weeks.entries()){
  const tr=mk('tr');
  const funded=model.funding[i];
  for(const value of [w.week,w.start,w.proposed_hours+' h',currency(model.currency,w.proposed_cost),
   currency(model.currency,funded.funded_cost),funded.provisionally_funded_hours+' h']){
   tr.append(mk('td',value));
  }
  tbody.append(tr);
 }
}
function display(model){
 const kpis=el('kpis');kpis.replaceChildren();
 const stats=[
  ['Proposed plan cost',currency(model.currency,model.estimated_plan_cost)],
  ['Funding available',currency(model.currency,model.available_funding)],
  ['Estimated funding shortfall',currency(model.currency,model.estimated_shortfall)],
  ['Unplanned hours from source',model.capacity_backlog_hours+' h'],
  ['Unplanned work — indicative extra cost',currency(model.currency,model.remaining_backlog_opportunity_cost)],
  ['Blended labor cost / hour',currency(model.currency,model.hourly_blended_rate)]
 ];
 for(const [a,b] of stats)kpis.append(stat(a,b));
 const risk=el('risk-exposure');risk.replaceChildren();
 risk.append(stat('Proposed critical/high hours',model.critical_high_proposed_hours+' h'));
 risk.append(stat('Potential urgent funding gap (min)',model.critical_high_potential_unfunded_hours_minimum+' h'));
 risk.append(stat('Potential urgent funding gap (max)',model.critical_high_potential_unfunded_hours_maximum+' h'));
 risk.append(stat('Critical/high backlog outside proposed plan',model.critical_high_outside_source_plan_hours+' h'));
 risk.append(stat('Urgent work — optimistic minimum budget',currency(model.currency,model.urgent_work_budget_best_case_minimum)));
 risk.append(stat('Urgent work — conservative budget threshold',currency(model.currency,model.urgent_work_budget_conservative_threshold)));
 risk.append(stat('Additional funding toward conservative threshold',currency(model.currency,model.additional_funding_for_conservative_urgent_coverage)));
 const riskTable=el('risk-weeks');riskTable.replaceChildren();
 for(const riskWeek of model.weekly_critical_high_funding_bounds){
  const tr=mk('tr');
  for(const value of [riskWeek.week,riskWeek.urgent_scheduled_hours+' h',
    riskWeek.urgent_potentially_unfunded_minimum_hours+' h',
    riskWeek.urgent_potentially_unfunded_maximum_hours+' h'])
    tr.append(mk('td',value));
  riskTable.append(tr);
 }
 rows(model);el('results').hidden=false;renderScenario();
 renderReleaseEntries();
}
function renderScenario(){
 const target=el('scenario');target.replaceChildren();comparison=null;
 if(!forecast||!settings)return;
 try{
  const text=el('alternative-external').value;
  if(!/^(0|[1-9][0-9]*)$/.test(text))throw Error('Alternative share must be an integer between 0 and 100');
  const fraction=Number(text);
  const alt=core.project(source,{...settings,outsourced_pct:fraction});
  comparison=alt;
  target.append(stat('Current '+settings.outsourced_pct+'% external',currency(forecast.currency,forecast.estimated_plan_cost)));
  target.append(stat('Alternative '+fraction+'% external',currency(alt.currency,alt.estimated_plan_cost)));
  target.append(stat('Proposed cost difference',currency(alt.currency,alt.estimated_plan_cost-forecast.estimated_plan_cost)));
  show('This comparison is a cost estimate, not a contracting or workforce decision.');
 }catch(err){target.append(mk('p','Scenario held: '+(err instanceof Error?err.message:'Invalid share'),'error'));}
}
el('settings').addEventListener('submit',event=>{
 event.preventDefault();if(!source){show('Load the existing LightUp aggregate capacity export first.',true);return;}
 try{
  const cfg=core.settings(modelInput());
  const model=core.project(source,cfg);
  settings=cfg;forecast=model;display(model);
  show('Local, unsigned financial forecast prepared; no original source or customer data exported.');
 }catch(err){
  clearResults();show('Funding forecast held: '+(err instanceof Error?err.message:'Invalid model'),true);
 }
});
el('settings').addEventListener('input',()=>{
 if(forecast){
  clearResults();
  show('Cost assumptions changed. Recalculate the current proposal before sharing or exporting.');
 }
});
el('settings').addEventListener('change',()=>{
 if(forecast){
  clearResults();
  show('Cost assumptions changed. Recalculate the current proposal before sharing or exporting.');
 }
});
el('compare').addEventListener('click',renderScenario);
el('alternative-external').addEventListener('input',()=>{comparison=null;el('scenario').replaceChildren();});
function download(name,body,mime){
 const url=URL.createObjectURL(new Blob([body],{type:mime}));
 const a=document.createElement('a');a.href=url;a.download=name;a.rel='noopener';document.body.append(a);
 a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1600);
}

function releasePercentages() {
 const n=source.weeks.length,mode=el('releases-mode').value;
 if(mode==='upfront')return [100,...Array(n-1).fill(0)];
 if(mode==='equal'){
  const floor=Math.floor(100/n);
  const chunks=Array(n).fill(floor);chunks[n-1]+=100-floor*n;return chunks;
 }
 if(mode!=='custom')throw Error('Invalid funding release pattern');
 const controls=el('release-entries').querySelectorAll('input');
 if(controls.length!==n)throw Error('Custom releases incomplete');
 return Array.from(controls,control=>{
  if(!/^(0|[1-9][0-9]*)$/.test(control.value))throw Error('Enter whole-number percentages');
  return Number(control.value);
 });
}
function clearRelease() {
 staged=null;el('release-summary').replaceChildren();el('release-weeks').replaceChildren();el('release-export').hidden=true;
 clearFundingPriority();
 clearTimingPlan();
}
function renderReleaseEntries(){
 const section=el('release-entries');section.replaceChildren();clearRelease();
 if(!source||!forecast||el('releases-mode').value!=='custom')return;
 const values=Array(source.weeks.length).fill(0);values[0]=100;
 source.weeks.forEach((week,index)=>{
  const label=mk('label','Week '+week.week+' starting '+week.start+' (%)','input-label');
  const input=document.createElement('input');input.type='number';input.min='0';input.max='100';input.step='1';
  input.value=String(values[index]);input.setAttribute('aria-label','Week '+week.week+' released budget percentage');
  input.addEventListener('change',clearRelease);label.append(input);section.append(label);
 });
}
el('releases-mode').addEventListener('change',renderReleaseEntries);
el('release-calculate').addEventListener('click',()=>{
 clearRelease();
 if(!source||!forecast||!settings){show('Load a source and prepare a forecast first.',true);return;}
 try{
  const next=core.stagedFunding(source,settings,releasePercentages());
  staged=next;
  const info=el('release-summary');info.replaceChildren();
  for(const [title,value] of [
   ['Hours provisionally funded',next.provisionally_funded_hours+' h'],
   ['Hours without funding',next.unpaid_planned_hours+' h'],
   ['Urgent potentially unfunded (min)',next.urgent_potentially_unfunded_lower_hours+' h'],
   ['Urgent potentially unfunded (max)',next.urgent_potentially_unfunded_upper_hours+' h'],
   ['Cash left unused',currency(next.currency,next.unused_funds_end)],
   ['Setup still unfunded',currency(next.currency,next.setup_cost_still_unpaid)]])info.append(stat(title,value));
  const tbody=el('release-weeks');tbody.replaceChildren();
  for(const row of next.weeks){
   const tr=mk('tr');
   for(const v of [row.week,currency(next.currency,row.deposit),
     currency(next.currency,row.paid_setup),currency(next.currency,row.paid_proposed_labor),
     row.funded_hours+' h',row.hours_not_funded+' h',
     currency(next.currency,row.cash_carried_forward)])tr.append(mk('td',v));
   tbody.append(tr);
  }
  el('release-export').hidden=false;
  show('Private staged financial scenario calculated; nothing has been booked or executed.');
 }catch(err){show('Phased funding held: '+(err instanceof Error?err.message:'Invalid schedule'),true);}
});
el('release-export').addEventListener('click',()=>{
 if(!staged)return;
 if(!confirm('Export only a private unsigned CASH RELEASE scenario? This does not make or authorise a payment, grant, remediation or retest.'))return;
 download('lightup-remediation-staged-funding.json',JSON.stringify(staged,null,2)+'\n','application/json;charset=utf-8');
 show('Aggregate staged funding discussion exported.');
});


function clearFundingPriority(){
 priorityPlan=null;
 el('priority-kpis').replaceChildren();
 el('priority-rows').replaceChildren();
 el('priority-export-json').hidden=true;
 el('priority-export-md').hidden=true;
 el('priority-note').textContent='Unsigned financing models only. No tasks, consent, real work order or customer identity are imported or changed.';
}
function renderFundingPriorities(data){
 const stats=el('priority-kpis');stats.replaceChildren(
  stat('Urgent-first critical/high covered',data.urgent_first.critical_high_funded_hours+' h'),
  stat('Balanced critical/high covered',data.proportional.critical_high_funded_hours+' h'),
  stat('Estimated extra urgent coverage',data.modelled_urgent_funding_difference_hours+' h'),
  stat('Unscheduled source critical/high',data.source_unscheduled_urgent_hours+' h')
 );
 const rows=el('priority-rows');rows.replaceChildren();
 for(const key of ['critical','high','medium','low','info']){
  const x=data.urgent_first.by_severity[key];
  const y=data.proportional.by_severity[key];
  const row=mk('tr');
  for(const v of [key,x.proposed_hours+' h',x.tentatively_funded_hours+' h',
      x.unfinanced_hours+' h',y.tentatively_funded_hours+' h',y.unfinanced_hours+' h'])
   row.append(mk('td',v));
  rows.append(row);
 }
 el('priority-note').textContent='Both strategies use identical hypothetical weekly cash releases. Urgent-first may leave more medium/low/info work unfunded. No original finding is selected, assigned or repaired.';
 el('priority-export-json').hidden=false;
 el('priority-export-md').hidden=false;
}
el('priority-calculate').addEventListener('click',()=>{
 clearFundingPriority();
 if(!forecast||!source||!settings){
  show('Import an aggregate report and calculate its funding forecast before comparing strategies.',true);return;
 }
 try{
  priorityPlan=core.fundingPriorities(source,settings,releasePercentages());
  renderFundingPriorities(priorityPlan);
  show('Two aggregate financing strategies prepared for human discussion.');
 }catch(err){show('Priority funding held: '+(err instanceof Error?err.message:'Invalid model'),true);}
});
el('priority-export-json').addEventListener('click',()=>{
 if(!priorityPlan)return;
 if(!confirm('Export an unsigned AGGREGATE financing comparison? It is not approval, a contract, assigned cases or real remediation.'))return;
 download('lightup-remediation-funding-priorities.json',
  JSON.stringify(priorityPlan,null,2)+'\n','application/json;charset=utf-8');
 show('Private aggregate funding priorities exported.');
});
el('priority-export-md').addEventListener('click',()=>{
 if(!priorityPlan)return;
 if(!confirm('Export a private REVIEW_ONLY funding discussion brief, not authorisation or a signed work order?'))return;
 download('lightup-remediation-funding-discussion.md',
  core.priorityDiscussionMarkdown(priorityPlan),'text/markdown;charset=utf-8');
 show('Private funding discussion brief exported.');
});


function clearTimingPlan(){
 timingPlan=null;
 el('timing-stats').replaceChildren();
 el('timing-rows').replaceChildren();
 el('timing-export-json').hidden=true;
 el('timing-export-md').hidden=true;
 el('timing-note').textContent='Funding times are private financial hypotheses only, not a work, consent or security execution calendar.';
}
el('timing-calculate').addEventListener('click',()=>{
 clearTimingPlan();
 if(!forecast||!source||!settings){show('Load original aggregate funding data and prepare a forecast first.',true);return;}
 try{
  timingPlan=core.fundingTimingComparison(source,settings,releasePercentages());
  const cards=el('timing-stats');cards.replaceChildren(
   stat('Selected versus upfront: additional unfunded hours',
     timingPlan.selected_versus_upfront_unfunded_extra_hours+' h'),
   stat('Selected versus upfront: additional critical/high unfunded',
     timingPlan.selected_versus_upfront_critical_high_unfunded_extra_hours+' h')
  );
  const rows=el('timing-rows');rows.replaceChildren();
  const descriptions={all_upfront:'Full upfront',evenly_released:'Evenly released',selected_schedule:'Selected schedule'};
  for(const x of timingPlan.scenarios){
   const row=mk('tr');
   for(const v of [descriptions[x.name],x.planned_hours+' h',
    x.tentatively_funded_hours+' h',x.hours_unfunded_at_original_weeks+' h',
    x.critical_high_unfunded_best_case_hours+' h',
    x.critical_high_unfunded_proportional_hours+' h',currency(timingPlan.currency,x.unused_budget)])
     row.append(mk('td',v));
   rows.append(row);
  }
  el('timing-export-json').hidden=false;
  el('timing-export-md').hidden=false;
  el('timing-note').textContent='All three cases assume identical funding totals. Late money is not applied retroactively. Values are estimated and not a real procurement or security approval.';
  show('Private timing-of-funds comparison prepared without contacting any provider or target.');
 }catch(err){show('Release-timing review held: '+(err instanceof Error?err.message:'Invalid financing scenario'),true);}
});
el('timing-export-json').addEventListener('click',()=>{
 if(!timingPlan)return;
 if(!confirm('Export unsigned aggregate funding timing assumptions? Not a payment, consent, scan, remediation order or retest.'))return;
 download('lightup-remediation-funding-timing.json',
  JSON.stringify(timingPlan,null,2)+'\n','application/json;charset=utf-8');
 show('Private timing-of-funds JSON discussion exported.');
});
el('timing-export-md').addEventListener('click',()=>{
 if(!timingPlan)return;
 if(!confirm('Export a non-authorising private funding discussion brief with no target, finding ID or real permission?'))return;
 download('lightup-remediation-funding-timing.md',
  core.timingDiscussionMarkdown(timingPlan),'text/markdown;charset=utf-8');
 show('Private human funding timing discussion exported.');
});

el('json').addEventListener('click',()=>{
 if(!forecast)return;
 if(!confirm('Export only an unsigned, hypothetical AGGREGATE funding discussion? This is not authorization, a contract, customer invoice or verified remediation.'))return;
 download('lightup-remediation-funding-draft.json',JSON.stringify(forecast,null,2)+'\n','application/json;charset=utf-8');
 show('Private, aggregate-only budget forecast exported.');
});
el('csv').addEventListener('click',()=>{
 if(!forecast)return;
 if(!confirm('Export private weekly aggregate cost estimates? Review the recipient before sharing.'))return;
 const cols=['week','start_utc','proposed_hours','proposed_cost','funding_applied','provisionally_funded_hours','critical_high_proposed_hours','urgent_potentially_unfunded_min_hours','urgent_potentially_unfunded_max_hours'];
 const q=v=>'"'+String(v).replace(/"/g,'""')+'"';
 const lines=[cols.map(q).join(',')];
 forecast.weeks.forEach((w,index)=>{
  const funded=forecast.funding[index];
  lines.push([w.week,w.start,w.proposed_hours,w.proposed_cost,
   funded.funded_cost,funded.provisionally_funded_hours,
   forecast.weekly_critical_high_funding_bounds[index].urgent_scheduled_hours,
   forecast.weekly_critical_high_funding_bounds[index].urgent_potentially_unfunded_minimum_hours,
   forecast.weekly_critical_high_funding_bounds[index].urgent_potentially_unfunded_maximum_hours].map(q).join(','));
 });
 download('lightup-remediation-funding-weeks.csv',lines.join('\r\n')+'\r\n','text/csv;charset=utf-8');
 show('Private CSV of weekly aggregate financial assumptions exported.');
});
el('print').addEventListener('click',()=>{if(forecast)window.print();});
})();
