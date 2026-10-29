/* LightUp Remediation Capacity Studio — no persistence, no network, no execution. */
(function () {
  'use strict';
  const engine = window.LightUpCapacity;
  const el = id => document.getElementById(id);
  const $ = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  };
  let findings = null;
  let result = null;
  let lastOptions = null;
  let historyReview = null;
  let milestoneDraft = null;
  let contingencyDraft = null;
  let reviewedCasework = null;
  function clearContingency(){contingencyDraft=null;el('contingency-results').replaceChildren();el('export-contingency').hidden=true;}
  function clearMilestone() {
    milestoneDraft=null;
    el('milestone-result').replaceChildren();
    el('milestone-export').hidden=true;
  }
  const source = el('source');
  const feedback = el('feedback');
  const setFeedback = (msg, error=false) => {
    feedback.textContent = msg;
    feedback.classList.toggle('error',error);
  };
  function clearHistory() {
    historyReview = null;
    el('previous').value = '';
    el('same-engagement').checked = false;
    el('history-data').hidden = true;
    el('history-stats').replaceChildren();
    el('history-feedback').textContent = 'No earlier report compared.';
  }
  el('clear-history').addEventListener('click',clearHistory);
  el('previous').addEventListener('change',()=>{historyReview=null;el('history-data').hidden=true;el('same-engagement').checked=false;});
  function clearCasework() {
    reviewedCasework=null;
    el('casework-packet').value='';
    el('casework-ack').checked=false;
    el('casework-summary').hidden=true;
    el('casework-status-cards').replaceChildren();
    el('casework-risk-table').replaceChildren();
    el('casework-week-pressure').replaceChildren();
    el('casework-triage').replaceChildren();
    el('casework-feedback').textContent='No Casework record reviewed.';
  }
  el('clear-casework').addEventListener('click',clearCasework);
  el('casework-ack').addEventListener('change',()=>{
    reviewedCasework=null;
    el('casework-summary').hidden=true;
  });
  el('casework-packet').addEventListener('change',()=>{
    reviewedCasework=null;
    el('casework-summary').hidden=true;
  });
  function forget() {
    findings = null; result = null; lastOptions = null;
    clearMilestone();
    clearContingency();
    source.value = '';
    clearHistory();
    clearCasework();
    el('source-status').textContent = 'No report loaded. All files stay in this browser tab.';
    el('generate').disabled = true;
    el('save-working-draft').disabled = true;
    el('reopen-working-draft').value='';
    el('draft-status').textContent='No saved draft restored. Browsers store nothing for you.';
    el('results').hidden = true;
    el('stats').replaceChildren();
    el('weekly').replaceChildren();
    el('allocations').replaceChildren();
    el('priority-bands').replaceChildren();
    setFeedback('Imported source and proposed capacity plan discarded from this workspace.');
  }
  el('forget').addEventListener('click',forget);
  source.addEventListener('change',async () => {
    const file = source.files && source.files[0];
    findings = null; result = null; lastOptions = null;
    clearMilestone();
    clearContingency();
    el('generate').disabled = true;
    el('save-working-draft').disabled = true;
    el('draft-status').textContent='New source: older plans must be independently reviewed again.';
    el('results').hidden = true;
    clearHistory();
    clearCasework();
    if (!file) return;
    try {
      if (file.size > engine.MAX_BYTES || file.size === 0) throw new Error('Source must be a nonempty CSV no larger than 1 MiB.');
      // Strict decoding; malformed UTF-8 must not be silently replaced.
      const content = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      const prepared = engine.parseCSV(content);
      if (source.files?.[0] !== file) return;
      findings = prepared; result = null; lastOptions = null;
      el('generate').disabled = false;
      el('results').hidden = true;
      const counts = {};
      for (const f of findings) counts[f.severity] = (counts[f.severity]||0)+1;
      el('source-status').textContent = 'Loaded '+findings.length+' source records · severity counts: '+
        ['critical','high','medium','low','info'].map(s=>s+' '+(counts[s]||0)).join(', ')+'. Source identities and descriptions are not shown.';
      setFeedback('Report read locally. Review team estimates, then prepare a draft.');
    } catch (err) {
      setFeedback('Source held: '+(err instanceof Error?err.message:'Invalid report'),true);
    }
  });
  const input = name => el('settings').elements.namedItem(name).value;
  function renderWeekAvailability() {
    const count=Math.min(12,Math.max(1,Number(input('weeks'))||1));
    const previous=Array.from(el('week-availability').querySelectorAll('input'),x=>x.value);
    const start=input('start');
    const startMS=/^\d{4}-\d\d-\d\d$/.test(start) ? Date.parse(start+'T00:00:00Z') : NaN;
    const grid=el('week-availability');grid.replaceChildren();
    for(let i=0;i<count;i++) {
      const label=$('label',undefined,'availability-field');
      const day=Number.isFinite(startMS)?new Date(startMS+i*7*86400000).toISOString().slice(0,10):'date not set';
      label.append(document.createTextNode('Week '+(i+1)+' · '+day+' (%)'));
      const v=document.createElement('input');
      v.type='number';v.min='0';v.max='100';v.step='1';v.required=true;
      v.value=previous[i]===undefined?'100':previous[i];
      v.setAttribute('aria-label','Week '+(i+1)+' availability percentage');
      label.append(v);grid.append(label);
    }
  }
  el('settings').elements.namedItem('weeks').addEventListener('input',renderWeekAvailability);
  el('settings').elements.namedItem('start').addEventListener('change',renderWeekAvailability);
  el('settings').addEventListener('submit',event=>{
    event.preventDefault();
    if (!findings) {setFeedback('Load an authorised source export first.',true);return;}
    try {
      const hours = {};
      for (const severity of ['critical','high','medium','low','info']) hours[severity] = input(severity);
      lastOptions = {
        start:input('start'),weeks:input('weeks'),engineers:input('engineers'),
        workDays:input('workDays'),hoursPerDay:input('hoursPerDay'),
        reserve:input('reserve'),hours,
        weekAvailability:Array.from(el('week-availability').querySelectorAll('input'),v=>v.value)
      };
      result = engine.plan(findings,lastOptions);
      clearCasework();
      clearHistory();
      clearMilestone();
    clearContingency();
      render();
      renderComparison();
      el('results').hidden = false;
      el('save-working-draft').disabled = false;
      el('draft-status').textContent='Current computed plan can be saved after confirming a private local file.';
      setFeedback('Draft allocations prepared offline. Nothing has been assigned or executed.');
    } catch (err) {
      result = null; el('results').hidden=true;
      el('save-working-draft').disabled=true;
      setFeedback('Plan held: '+(err instanceof Error?err.message:'Invalid inputs'),true);
    }
  });
  function render() {
    const stats = el('stats'); stats.replaceChildren();
    const vals = [
      ['Source findings',result.sourceCount],
      ['Estimated effort',result.totalHours+' h'],
      ['Planned hours',result.assignedHours+' h'],
      ['Unplanned hours',result.backlogHours+' h'],
      ['Still partly/unplanned',result.backlogCount],
      ['Fully allocated estimates',result.completedProposals]
    ];
    for (const [label,value] of vals) {
      const card=$('div',undefined,'stat'); card.append($('strong',value),$('span',label));stats.append(card);
    }
    const riskRows=el('priority-bands');riskRows.replaceChildren();
    for (const severity of ['critical','high','medium','low','info']) {
      const band=result.priorityBands[severity];
      const tr=$('tr');
      const cutoff=band.last_estimated_scheduling_week===null
        ? (band.source_count===0?'No cases':'Not fully allocated')
        : 'Week '+band.last_estimated_scheduling_week+' (estimate)';
      for (const v of [severity,band.source_count,band.source_regressions,
        band.estimated_hours+' h',band.scheduled_hours+' h',
        band.unscheduled_hours+' h',cutoff])tr.append($('td',v));
      if(band.unscheduled_hours>0) tr.className='outstanding-row';
      riskRows.append(tr);
    }
    const weekly=el('weekly'); weekly.replaceChildren();
    for (const week of result.schedule) {
      const block=$('div',undefined,'week');
      const title=$('div',undefined,'week-header');
      title.append($('strong','Week '+week.week+' · '+week.start),
        $('span',week.assigned+' / '+week.capacity+' h'));
      const track=$('div',undefined,'track');
      track.setAttribute('role','meter');track.setAttribute('aria-valuemin','0');
      track.setAttribute('aria-valuemax',String(Math.max(week.capacity,1)));
      track.setAttribute('aria-valuenow',String(week.assigned));
      track.setAttribute('aria-label','Week '+week.week+' allocated hours');
      const fill=$('div',undefined,'fill');fill.style.width=String(week.capacity?100*week.assigned/week.capacity:0)+'%';
      track.append(fill);block.append(title,track);
      block.append($('p',week.availability+'% availability · '+week.portions.length+' planned allocations; '+week.remaining+' h free.','subtle'));
      weekly.append(block);
    }
    const rows=el('allocations');rows.replaceChildren();
    for (const week of result.schedule) {
      for (const portion of week.portions) {
        const tr=$('tr');
        for (const value of [week.week,'Finding '+String(portion.ordinal).padStart(3,'0'),
          portion.severity,portion.sourceRetest,portion.hours+' h',portion.finished?'Estimated effort allocated':'Continues']) {
          tr.append($('td',value));
        }
        rows.append(tr);
      }
    }
    if (!rows.children.length) {
      const tr=$('tr'),cell=$('td','No allocations within the available capacity.');cell.colSpan=6;tr.append(cell);rows.append(tr);
    }
  }

  function renderComparison() {
    const box=el('comparison');box.replaceChildren();
    if (!findings || !result || !lastOptions) return;
    try {
      const extra=Number(el('extra-engineers').value);
      if (!Number.isSafeInteger(extra) || extra < 0 || extra > 10) throw new Error('Use 0–10 additional engineers.');
      const n=Number(lastOptions.engineers)+extra;
      if (n > 30) throw new Error('The scenario supports at most 30 engineers.');
      const alternative=engine.plan(findings,{...lastOptions,engineers:n});
      const candidates=[];
      for (let count=1;count<=30;count++) {
        const candidate=engine.plan(findings,{...lastOptions,engineers:count});
        if (candidate.backlogHours===0) {candidates.push(count);break;}
      }
      const minTeam=candidates.length?candidates[0]:null;
      const cards=$('div',undefined,'scenario-grid');
      for (const [title,planned,team] of [
        ['Baseline',result,Number(lastOptions.engineers)],
        ['What-if +'+extra,alternative,n]
      ]) {
        const card=$('div',undefined,'scenario-card');
        card.append($('strong',title),$('p',team+' engineers · '+planned.assignedHours+' assigned h'),
          $('p',planned.backlogHours+' backlog h · '+planned.backlogCount+' unfinished estimates'));
        cards.append(card);
      }
      box.append(cards);
      const difference=result.backlogHours-alternative.backlogHours;
      const msg= difference>0
        ? 'Proposed additional capacity covers '+difference+' more estimated hours within the same time horizon.'
        : 'The extra staffing does not reduce backlog within these planning assumptions.';
      box.append($('p',msg,'subtle'));
      box.append($('p',minTeam===null
        ? 'Even a 30-person team would not fit all estimated work into these weeks.'
        : 'The smallest modeled team fitting all estimated hours in these weeks is '+minTeam+
        ' engineers. This is not a staffing recommendation, SLA or completion guarantee.','subtle'));
    } catch (error) {
      box.append($('p','Scenario held: '+(error instanceof Error?error.message:'Invalid scenario'),'feedback error'));
    }
  }

  async function decodeReport(file) {
    if (!file || !file.size || file.size > engine.MAX_BYTES) throw new Error('Choose a nonempty original CSV up to 1 MiB.');
    const bytes=await file.arrayBuffer();
    // Use the exact original bytes in memory; no server, hash persistence or hidden export.
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  }
  function showHistoricalChange(data) {
    const container=el('history-stats');container.replaceChildren();
    const vals=[
      ['Added source records',data.added],
      ['Changed source records',data.changed],
      ['Absent / not verified fixed',data.absent],
      ['Unchanged records',data.unchanged],
      ['Earlier estimated hours',data.previous_estimated_hours+' h'],
      ['Current estimated hours',data.current_estimated_hours+' h'],
      ['Estimated workload shift',(data.net_estimated_change_hours>0?'+':'')+data.net_estimated_change_hours+' h'],
      ['Added-case effort',data.added_hours+' h'],
      ['Absent-case estimate',data.absent_hours+' h']
    ];
    for (const [label,value] of vals) {
      const box=$('div',undefined,'stat');
      box.append($('strong',value),$('span',label));
      container.append(box);
    }
    el('history-data').hidden=false;
  }
  el('review-history').addEventListener('click',async()=>{
    const currentFile=source.files?.[0];
    const previousFile=el('previous').files?.[0];
    const confirmation=el('same-engagement').checked;
    historyReview=null;el('history-data').hidden=true;
    if(!findings || !result || !lastOptions || !currentFile || !previousFile || !confirmation) {
      el('history-feedback').textContent='HOLD: generate a current plan, select an earlier report and explicitly confirm the same client and engagement.';
      return;
    }
    try {
      const texts=await Promise.all([decodeReport(currentFile),decodeReport(previousFile)]);
      if (source.files?.[0]!==currentFile || el('previous').files?.[0]!==previousFile ||
          !el('same-engagement').checked) throw new Error('Input changed while comparing; review again.');
      const report=engine.compareReports(texts[0],texts[1],lastOptions.hours);
      if (engine.parseCSV(texts[0]).length!==findings.length) throw new Error('Current source is no longer the loaded planning source.');
      historyReview=report;
      showHistoricalChange(report);
      el('history-feedback').textContent='REVIEW_ONLY — comparison based on your human same-engagement assertion. No identity, fix, revocation or retest verified.';
    } catch(err) {
      el('history-feedback').textContent='HOLD: '+(err instanceof Error?err.message:'Comparison input rejected');
    }
  });
  el('export-history').addEventListener('click',()=>{
    if (!historyReview || !el('same-engagement').checked) return;
    if(!window.confirm('Export only untrusted aggregate workload differences? Not proof of repair, consent or identity.'))return;
    download('lightup-capacity-source-change.json',JSON.stringify({
      schema:'lightup.remediation_capacity_source_change_draft.v1',
      ...historyReview
    },null,2)+'\n','application/json;charset=utf-8');
    setFeedback('Aggregate historical workload differences exported as REVIEW_ONLY.');
  });

  el('compare').addEventListener('click',renderComparison);
  function download(name,content,mime) {
    // Deliberate user-initiated, local-only export. URL revoked immediately.
    const blob=new Blob([content],{type:mime});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;a.download=name;a.rel='noopener';document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
  }
  el('export-json').addEventListener('click',()=>{
    if (!result) return;
    const ok=window.confirm('Export aggregate planning counts only? This is an unsigned REVIEW_ONLY draft with no authorisation.');
    if (!ok) return;
    download('lightup-capacity-draft.json',JSON.stringify(engine.summary(result),null,2)+'\n','application/json;charset=utf-8');
    setFeedback('Redacted aggregate draft exported. No source details included.');
  });
  el('export-csv').addEventListener('click',()=>{
    if (!result) return;
    const ok=window.confirm('Export aggregate weekly hours only? Verify the intended private recipient before sharing.');
    if (!ok) return;
    download('lightup-capacity-weeks.csv',engine.csvReport(result),'text/csv;charset=utf-8');
    setFeedback('Weekly aggregate CSV exported. No individual findings included.');
  });
  el('export-md').addEventListener('click',()=>{
    if (!result) return;
    const ok=window.confirm('Export a private, aggregate-only Markdown planning brief for human discussion? It is NOT authorization or proof of completed work.');
    if (!ok) return;
    download('lightup-capacity-discussion.md',engine.markdownReport(result),'text/markdown;charset=utf-8');
    setFeedback('Unsigned aggregate discussion brief exported. No original finding details included.');
  });


  function showRiskMilestone(value) {
    const view=el('milestone-result');view.replaceChildren();
    const summary=$('div',undefined,'milestone-overview');
    const status=value.fit_by_target_week
      ? 'Fits the estimated risk workload by week '+value.target_week
      : 'Estimated '+value.remaining_estimated_hours+' hours still outside week '+value.target_week;
    summary.append($('strong',status),
      $('p','Original risk-band estimate: '+value.required_estimated_hours+' h · provisionally allocated by target week: '+value.provisionally_allocated_hours+' h.'),
      $('p',value.smallest_modelled_team===null
        ? 'No staffing level up to 30 engineers fits this risk milestone under these week-by-week capacity limits.'
        : 'Smallest modelled team for this milestone: '+value.smallest_modelled_team+' engineers.'),
      $('p','REVIEW_ONLY — estimates do not mean actual fixes, booked work, authorisation, verified retest or contractual dates.','subtle'));
    view.append(summary);
    el('milestone-export').hidden=false;
  }
  el('milestone-calculate').addEventListener('click',()=>{
    clearMilestone();
    if(!result||!findings||!lastOptions){
      el('milestone-result').append($('p','HOLD: generate a current plan first.','feedback error'));return;
    }
    try{
      milestoneDraft=engine.riskMilestone(
        findings,lastOptions,el('milestone-week').value,el('milestone-band').value
      );
      showRiskMilestone(milestoneDraft);
    }catch(err){
      el('milestone-result').append($('p','HOLD: '+(err instanceof Error?err.message:'Invalid risk milestone'),'feedback error'));
    }
  });
  for(const id of ['milestone-band','milestone-week']) el(id).addEventListener('change',clearMilestone);
  el('milestone-export').addEventListener('click',()=>{
    if(!milestoneDraft)return;
    if(!window.confirm('Export a private, unsigned AGGREGATE risk planning estimate, NOT a grant, SLA, completion claim or retest?'))return;
    const data={schema:'lightup.remediation_milestone_draft.v1',...milestoneDraft};
    download('lightup-risk-milestone-draft.json',JSON.stringify(data,null,2)+'\n','application/json;charset=utf-8');
    setFeedback('Non-authorising, privacy-minimal risk milestone exported for human review.');
  });


  function renderInterruptionSummary(draft) {
    const container=el('contingency-results');container.replaceChildren();
    const cards=$('div',undefined,'scenario-grid');
    for(const [title,value] of [
      ['Original planning baseline',draft.baseline],
      ['One-week interruption',draft.single_week_interruption],
      ['Sustained capacity reduction',draft.sustained_reduction]
    ]){
      const card=$('div',undefined,'scenario-card');
      card.append(
        $('strong',title),
        $('p',value.provisionally_allocated_hours+' h provisionally allocated'),
        $('p',value.unallocated_hours+' h unallocated across '+value.unallocated_findings+' finding estimates'),
        $('p',value.critical_high_unallocated_hours+' h critical/high backlog')
      );
      cards.append(card);
    }
    container.append(cards,$('p','This is not an actual outage forecast, authorisation to retest, staffing assignment or contractual promise. No original findings are included in these aggregate results.','subtle'));
    el('export-contingency').hidden=false;
  }
  el('run-contingency').addEventListener('click',()=>{
    clearContingency();
    if(!findings||!result||!lastOptions){
      el('contingency-results').append($('p','HOLD: generate a current capacity plan first.','feedback error'));
      return;
    }
    try{
      const data=engine.interruptionScenario(findings,lastOptions,
        el('outage-week').value,
        el('outage-availability').value,
        el('ongoing-reduction').value);
      contingencyDraft=data;
      renderInterruptionSummary(data);
    }catch(err){
      el('contingency-results').append($('p','HOLD: '+(err instanceof Error?err.message:'Invalid scenario'),'feedback error'));
    }
  });
  for(const id of ['outage-week','outage-availability','ongoing-reduction']){
    el(id).addEventListener('change',clearContingency);
  }
  el('export-contingency').addEventListener('click',()=>{
    if(!contingencyDraft)return;
    if(!window.confirm('Export only hypothetical aggregate hour and backlog changes? These are NOT real security work, consent, actual outage or proven fixes.'))return;
    download('lightup-capacity-interruption-draft.json',
      JSON.stringify(contingencyDraft,null,2)+'\n','application/json;charset=utf-8');
    setFeedback('Unsigned, aggregate-only contingency discussion exported.');
  });


  const CASEWORK_TRIAGE=Object.freeze([
    ['critical_high_blocked','Urgent cases blocked','Discuss recorded blockers with an independently authorised remediation owner.','urgent'],
    ['critical_high_unowned','Urgent cases without local owner labels','Obtain a human-only proposal for an accountable remediation contact.','urgent'],
    ['critical_high_undated','Urgent cases without proposed dates','Discuss a realistic, not yet committed remediation window.','urgent'],
    ['source_regression_locally_completed','Source regressions locally labelled completed','Resolve original source vs self-reported progress conflict; do not infer a fix.','urgent'],
    ['source_regression_deferred','Source regressions locally deferred','Discuss deferred regression risk and independently approved next steps.','urgent'],
    ['retest_coordination_without_owner','Proposed retest coordination lacks an owner label','Agree who will request separate real retest authorisation.','review'],
    ['blocked_without_note','Locally blocked cases without explanatory notes','Request private human clarification before treating estimates as achievable.','review']
  ]);
  function caseworkTriageRows(summary){
    return CASEWORK_TRIAGE.map(([code,label,nextStep,priority])=>({
      code,label,nextStep,priority,count:summary.human_review_flags[code]||0
    })).filter(item=>item.count>0);
  }
  function showCaseworkSummary(summary) {
    const cards=el('casework-status-cards');
    cards.replaceChildren();
    const stats=summary.source_casework_statuses;
    for(const [label,value] of [
      ['Original cases',summary.source_records],
      ['Self-reported blocked',stats.blocked],
      ['Owner labels present',summary.assigned_owner_labels],
      ['Locally dated plans',summary.source_casework_due_dates],
      ['Human retest coordination',stats.ready_for_retest],
      ['Self-reported completed (unverified)',stats.completed]
    ]) {
      const card=$('div',undefined,'stat');card.append($('strong',value),$('span',label));cards.append(card);
    }
    const rows=el('casework-risk-table');
    rows.replaceChildren();
    for(const severity of ['critical','high','medium','low','info']){
      const v=summary.severity_statuses[severity];
      const row=$('tr');
      if(v.blocked||v.missing_owner)row.className='outstanding-row';
      for(const value of [severity,v.total,v.blocked,v.missing_owner,
        v.undated,v.ready_for_retest,v.locally_completed_unverified])row.append($('td',value));
      rows.append(row);
    }
    const triage=el('casework-triage');triage.replaceChildren();
    const todo=caseworkTriageRows(summary);
    if(!todo.length)triage.append($('p','No source-linked local planning contradictions were reported in these categories. This is not verification of repairs, permission or release.','subtle'));
    for(const item of todo){
      const card=$('article',undefined,'triage-card');
      card.append($('strong',item.count+' · '+item.label),$('p',item.nextStep));
      triage.append(card);
    }
    const pressureRows=el('casework-week-pressure');pressureRows.replaceChildren();
    for(const week of summary.weekly_blocker_pressure){
      const row=$('tr');
      if(week.locally_blocked_critical_high_estimated_hours)row.className='outstanding-row';
      for(const value of [
        'Week '+week.week,
        week.provisionally_allocated_hours+' h',
        week.locally_blocked_estimated_hours+' h',
        week.locally_blocked_critical_high_estimated_hours+' h',
        week.source_regression_locally_completed_estimated_hours+' h'
      ])row.append($('td',value));
      pressureRows.append(row);
    }
    el('casework-summary').hidden=false;
  }
  el('review-casework').addEventListener('click',async()=>{
    reviewedCasework=null;
    el('casework-summary').hidden=true;
    const csv=source.files?.[0],packet=el('casework-packet').files?.[0];
    if(!csv||!findings||!result||!packet||!el('casework-ack').checked){
      el('casework-feedback').textContent='HOLD: load an original CSV, choose an original Casework JSON and manually confirm the same client and engagement.';
      return;
    }
    if(!window.confirm('Read the original Casework v1 as LOCAL UNSIGNED HUMAN NOTES only? This can reveal the report privately in this browser tab. No result is an actual consent, verified fix, assessment or retest.'))return;
    try{
      if(!packet.size||packet.size>window.LightUpCapacityCasework.MAX_BYTES)
        throw Error('Original Casework packet must be bounded to 2 MiB');
      if(!csv.size||csv.size>engine.MAX_BYTES)
        throw Error('Reopen the original bounded CSV');
      const [sourceBytes,packetBytes]=await Promise.all([csv.arrayBuffer(),packet.arrayBuffer()]);
      const originalText=new TextDecoder('utf-8',{fatal:true}).decode(sourceBytes);
      const packetText=new TextDecoder('utf-8',{fatal:true}).decode(packetBytes);
      if(source.files?.[0]!==csv||!el('casework-ack').checked||!findings)
        throw Error('Original CSV or acknowledgment changed during read');
      const planAtUse=result;
      const summary=await window.LightUpCapacityCasework.review(originalText,packetText,planAtUse);
      if(source.files?.[0]!==csv||!el('casework-ack').checked||!findings||result!==planAtUse)
        throw Error('Source or active capacity plan changed during source-digest validation');
      reviewedCasework=summary;
      showCaseworkSummary(summary);
      el('casework-feedback').textContent='Matched the Casework source digest and source fields locally. Client identity, active consent and retest are NOT authenticated here.';
      setFeedback('Local Casework planning overview read successfully. Source case notes were not retained.');
    }catch(err){
      el('casework-feedback').textContent='HOLD: '+(err instanceof Error?err.message:'Casework source could not be trusted');
    }finally{
      el('casework-packet').value='';
    }
  });
  el('export-casework-summary').addEventListener('click',()=>{
    if(!reviewedCasework||!el('casework-ack').checked)return;
    if(!window.confirm('Export aggregate, self-reported CASEWORK stages only? Not verified fixes, client identity, assignments, retest or consent.'))return;
    download('lightup-capacity-casework-review.json',
      JSON.stringify(reviewedCasework,null,2)+'\n','application/json;charset=utf-8');
    setFeedback('Only group-level unsigned Casework notes exported.');
  });


  el('export-casework-triage').addEventListener('click',()=>{
    if(!reviewedCasework||!el('casework-ack').checked)return;
    if(!window.confirm('Export the UNASSIGNED INTERNAL human discussion suggestions as aggregate counts only? This does not create a work order, retest, finding closure or permission.'))return;
    const quote=x=>'"'+String(x).replace(/"/g,'""')+'"';
    const columns=['severity','reason_code','count','suggested_human_discussion','authority'];
    const lines=[columns.map(quote).join(',')];
    for(const row of caseworkTriageRows(reviewedCasework)){
      lines.push([row.priority,row.code,row.count,row.nextStep,'REVIEW_ONLY'].map(quote).join(','));
    }
    download('lightup-casework-human-discussion.csv',lines.join('\r\n')+'\r\n',
      'text/csv;charset=utf-8');
    setFeedback('Private, static-label aggregate discussion register exported. No cases or identities included.');
  });


  el('export-casework-pressure').addEventListener('click',()=>{
    if(!reviewedCasework||!el('casework-ack').checked||!result)return;
    if(!window.confirm('Export private aggregate planned-hours-at-risk by week? These values are HUMAN NOTES only and do not create assignments, scan access, verified fixes or booked work.'))return;
    const quote=value=>'"'+String(value).replace(/"/g,'""')+'"';
    const keys=['week','week_start_utc','allocated_estimated_hours','locally_blocked_estimated_hours',
      'critical_high_locally_blocked_estimated_hours','source_regression_locally_completed_estimated_hours'];
    const rows=[keys.map(quote).join(',')];
    for(const week of reviewedCasework.weekly_blocker_pressure) {
      rows.push([
        week.week,week.start,week.provisionally_allocated_hours,
        week.locally_blocked_estimated_hours,
        week.locally_blocked_critical_high_estimated_hours,
        week.source_regression_locally_completed_estimated_hours
      ].map(quote).join(','));
    }
    download('lightup-casework-weekly-pressure.csv',rows.join('\r\n')+'\r\n',
      'text/csv;charset=utf-8');
    setFeedback('Anonymous, aggregate only weekly Casework coordination pressure exported for human review.');
  });


  el('export-combined-brief').addEventListener('click',()=>{
    if(!reviewedCasework||!el('casework-ack').checked||!result)return;
    if(!window.confirm('Create ONE internal, unsigned, aggregate-only remediation coordination brief from your current plan and source-matched original Casework? This does NOT authenticate consent, client identity, remediation, retest or staff assignments.'))return;
    try{
      const report=window.LightUpCapacityCasework.combinedBrief(result,reviewedCasework,engine);
      download('lightup-private-remediation-coordination.md',report,'text/markdown;charset=utf-8');
      setFeedback('A single private aggregate planning + Casework coordination brief was exported.');
    }catch(err){
      setFeedback('Combined handoff held: '+(err instanceof Error?err.message:'Invalid Casework/plan binding'),true);
    }
  });

  // Source-bound, user-controlled resume: no browser persistence or implicit restore.
  function numericWorkingOptions(options) {
    if(!options)throw new Error('Generate a current proposal before saving');
    const names=['weeks','engineers','workDays','hoursPerDay','reserve'];
    const normalized={start:options.start};
    for(const name of names) normalized[name]=Number(options[name]);
    normalized.hours=Object.fromEntries(['critical','high','medium','low','info']
      .map(severity=>[severity,Number(options.hours[severity])]));
    normalized.weekAvailability=options.weekAvailability.map(Number);
    return normalized;
  }
  el('save-working-draft').addEventListener('click',async()=>{
    const file=source.files?.[0];
    const planSnapshot=result, optionsSnapshot=lastOptions;
    if(!file||!planSnapshot||!optionsSnapshot){
      el('draft-status').textContent='HOLD: load an original CSV and generate a proposal first.';
      return;
    }
    if(!window.confirm('Save ONLY this proposed team/effort/availability configuration and an unsigned exact-source fingerprint? It grants no permission and remains a private file you control.'))return;
    el('save-working-draft').disabled=true;
    try {
      const digest=await window.LightUpDraft.fingerprint(file);
      if(source.files?.[0]!==file||result!==planSnapshot||lastOptions!==optionsSnapshot)
        throw new Error('Source or plan changed during export; review again');
      const packet=window.LightUpDraft.exportDraft(
        digest,planSnapshot.sourceCount,numericWorkingOptions(optionsSnapshot),
        Number(el('extra-engineers').value)
      );
      download('lightup-capacity-working-draft.json',packet,'application/json;charset=utf-8');
      el('draft-status').textContent='Private working draft downloaded. Reopen only with the exact same original CSV.';
    }catch(err){
      el('draft-status').textContent='HOLD: '+(err instanceof Error?err.message:'Draft export refused');
    }finally{
      el('save-working-draft').disabled=!result;
    }
  });
  el('reopen-working-draft').addEventListener('change',async()=>{
    const imported=el('reopen-working-draft').files?.[0];
    const original=source.files?.[0], currentFindings=findings;
    if(!imported)return;
    // File selection is cleared immediately after reading so re-selection works.
    if(!original||!currentFindings){
      el('draft-status').textContent='HOLD: first load the exact original authorised CSV.';
      el('reopen-working-draft').value='';
      return;
    }
    if(!window.confirm('Restore an unsigned private plan only after reopening the exact same CSV? This does not confirm current permission, identity, remediation, revocation or retest.')){
      el('reopen-working-draft').value='';
      return;
    }
    try{
      if(imported.size===0||imported.size>window.LightUpDraft.MAX_DRAFT_BYTES)
        throw new Error('Private draft size is invalid');
      const text=new TextDecoder('utf-8',{fatal:true}).decode(await imported.arrayBuffer());
      const digest=await window.LightUpDraft.fingerprint(original);
      if(original!==source.files?.[0]||currentFindings!==findings)
        throw new Error('CSV changed during restore');
      const restored=window.LightUpDraft.importDraft(
        text,digest,findings.length,findings,engine
      );
      // Only commit the new UI state after every schema/source/plan check.
      clearHistory();
      const opts=restored.options;
      for(const name of ['start','weeks','engineers','workDays','hoursPerDay','reserve'])
        el('settings').elements.namedItem(name).value=String(opts[name]);
      for(const severity of ['critical','high','medium','low','info'])
        el('settings').elements.namedItem(severity).value=String(opts.hours[severity]);
      renderWeekAvailability();
      Array.from(el('week-availability').querySelectorAll('input'))
        .forEach((input,index)=>{input.value=String(opts.weekAvailability[index]);});
      el('extra-engineers').value=String(restored.scenario);
      lastOptions=opts;result=restored.plan;
      clearCasework();
      clearMilestone();
      render();renderComparison();
      el('results').hidden=false;
      el('save-working-draft').disabled=false;
      el('draft-status').textContent='REVIEW_ONLY: same-source planning assumptions restored. No authorization, verified repair, or earlier source comparison carried over.';
      setFeedback('Private capacity proposal resumed; verify all assumptions before sharing.');
    }catch(err){
      el('draft-status').textContent='HOLD: '+(err instanceof Error?err.message:'Unsafe draft');
    }finally{
      el('reopen-working-draft').value='';
    }
  });

  el('print').addEventListener('click',()=>{if(result)window.print();});
  const now = new Date();
  el('settings').elements.namedItem('start').value = [
    now.getFullYear(),String(now.getMonth()+1).padStart(2,'0'),String(now.getDate()).padStart(2,'0')
  ].join('-');
  renderWeekAvailability();
})();
