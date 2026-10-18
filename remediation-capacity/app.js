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
  const source = el('source');
  const feedback = el('feedback');
  const setFeedback = (msg, error=false) => {
    feedback.textContent = msg;
    feedback.classList.toggle('error',error);
  };
  function forget() {
    findings = null; result = null; lastOptions = null;
    source.value = '';
    el('source-status').textContent = 'No report loaded. All files stay in this browser tab.';
    el('generate').disabled = true;
    el('results').hidden = true;
    el('stats').replaceChildren();
    el('weekly').replaceChildren();
    el('allocations').replaceChildren();
    setFeedback('Imported source and proposed capacity plan discarded from this workspace.');
  }
  el('forget').addEventListener('click',forget);
  source.addEventListener('change',async () => {
    const file = source.files && source.files[0];
    if (!file) return;
    try {
      if (file.size > engine.MAX_BYTES || file.size === 0) throw new Error('Source must be a nonempty CSV no larger than 1 MiB.');
      // Strict decoding; malformed UTF-8 must not be silently replaced.
      const content = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      const prepared = engine.parseCSV(content);
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
  el('settings').addEventListener('submit',event=>{
    event.preventDefault();
    if (!findings) {setFeedback('Load an authorised source export first.',true);return;}
    try {
      const hours = {};
      for (const severity of ['critical','high','medium','low','info']) hours[severity] = input(severity);
      lastOptions = {
        start:input('start'),weeks:input('weeks'),engineers:input('engineers'),
        workDays:input('workDays'),hoursPerDay:input('hoursPerDay'),
        reserve:input('reserve'),hours
      };
      result = engine.plan(findings,lastOptions);
      render();
      renderComparison();
      el('results').hidden = false;
      setFeedback('Draft allocations prepared offline. Nothing has been assigned or executed.');
    } catch (err) {
      result = null; el('results').hidden=true;
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
    const weekly=el('weekly'); weekly.replaceChildren();
    for (const week of result.schedule) {
      const block=$('div',undefined,'week');
      const title=$('div',undefined,'week-header');
      title.append($('strong','Week '+week.week+' · '+week.start),
        $('span',week.assigned+' / '+week.capacity+' h'));
      const track=$('div',undefined,'track');
      track.setAttribute('role','meter');track.setAttribute('aria-valuemin','0');
      track.setAttribute('aria-valuemax',String(week.capacity));
      track.setAttribute('aria-valuenow',String(week.assigned));
      track.setAttribute('aria-label','Week '+week.week+' allocated hours');
      const fill=$('div',undefined,'fill');fill.style.width=String(100*week.assigned/week.capacity)+'%';
      track.append(fill);block.append(title,track);
      block.append($('p',week.portions.length+' planned allocations; '+week.remaining+' h free.','subtle'));
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
  el('print').addEventListener('click',()=>{if(result)window.print();});
  const now = new Date();
  el('settings').elements.namedItem('start').value = [
    now.getFullYear(),String(now.getMonth()+1).padStart(2,'0'),String(now.getDate()).padStart(2,'0')
  ].join('-');
})();
