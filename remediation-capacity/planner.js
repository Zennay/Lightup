/* LightUp Remediation Capacity — disconnected, draft-only planning primitives.
 * No execution, network calls, credentials, durable storage or authorization.
 */
(function (root) {
  'use strict';
  const HEADERS = ['finding_id','title','severity','retest_status','remediation'];
  const SEVERITIES = ['critical','high','medium','low','info'];
  const STATUSES = ['not_tested','fix_pending','fixed','regression'];
  const MAX_BYTES = 1048576;
  const MAX_ROWS = 350;
  const DEFAULT_HOURS = Object.freeze({critical:20,high:12,medium:6,low:3,info:1});
  const SEVERITY_INDEX = new Map(SEVERITIES.map((name, index) => [name, index]));
  function fail(reason) { throw new Error(reason); }
  function exactInteger(value, min, max, label) {
    const n = typeof value === 'number' ? value : Number(value);
    if (!Number.isSafeInteger(n) || n < min || n > max) fail('Invalid ' + label);
    return n;
  }
  function csvRows(text) {
    if (typeof text !== 'string' || text.length > MAX_BYTES || text.includes('\u0000')) fail('CSV is not a bounded text report');
    const out = [], row = []; let field = '', quote = false, closed = false, atStart = true;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote) {
        if (c === '"') {
          if (text[i+1] === '"') {field += '"'; i++;}
          else { quote = false; closed = true; }
        } else field += c;
      } else if (c === ',' || c === '\n' || c === '\r') {
        row.push(field); field = ''; closed = false; atStart = true;
        if (c !== ',') {
          if (c === '\r' && text[i+1] === '\n') i++;
          out.push(row.splice(0));
          if (out.length > MAX_ROWS + 2) fail('Too many CSV records');
        }
      } else if (c === '"' && atStart && !closed) {
        quote = true; atStart = false;
      } else {
        if (closed || c === '"') fail('Malformed CSV quoting');
        field += c; atStart = false;
      }
      if (field.length > 8000) fail('Oversized CSV field');
    }
    if (quote) fail('Unclosed quoted CSV field');
    if (field !== '' || row.length) { row.push(field); out.push(row); }
    while (out.length && out[out.length-1].length === 1 && out[out.length-1][0] === '') out.pop();
    return out;
  }
  function parseCSV(text) {
    const rows = csvRows(text.replace(/^\uFEFF/, ''));
    if (!rows.length || rows[0].length !== 5 || rows[0].some((x,i)=>x!==HEADERS[i])) fail('Not the original LightUp five-column finding CSV');
    if (rows.length < 2 || rows.length > MAX_ROWS + 1) fail('Report must contain 1–350 findings');
    const seen = new Set();
    const findings = rows.slice(1).map((row, i) => {
      if (row.length !== 5 || !row[0] || row[0].length > 200 || !row[1] || row[1].length > 600 || row[4].length > 4000) fail('Invalid source finding record');
      if (!SEVERITIES.includes(row[2]) || !STATUSES.includes(row[3])) fail('Invalid severity or retest status');
      if (seen.has(row[0])) fail('Duplicate finding identity');
      seen.add(row[0]);
      // Never retain or expose title, ID, remediation or source filename in planning views/exports.
      return Object.freeze({ordinal:i+1,severity:row[2],retest:row[3]});
    });
    return Object.freeze(findings);
  }
  // Compare two originals only inside a single synchronous call. Original IDs and
  // descriptions never survive the comparison return boundary.
  function compareReports(currentCSV, previousCSV, estimateHours) {
    const current = parseCSV(currentCSV);
    const previous = parseCSV(previousCSV);
    if (!estimateHours || typeof estimateHours !== 'object') fail('Choose the same local effort estimates first');
    const hours = Object.create(null);
    for (const severity of SEVERITIES) hours[severity] =
      exactInteger(estimateHours[severity], 1, 200, 'estimated ' + severity + ' effort');
    const present = csvRows(currentCSV.replace(/^\uFEFF/, '')).slice(1);
    const earlier = csvRows(previousCSV.replace(/^\uFEFF/, '')).slice(1);
    // All rows passed canonical parser validation above. Internal maps are ephemeral.
    const baseline = new Map(earlier.map(row => [row[0], row]));
    const counted = {added:0, changed:0, unchanged:0, absent:0,
      added_hours:0, changed_current_hours:0, changed_previous_hours:0,
      absent_hours:0, current_estimated_hours:0, previous_estimated_hours:0,
      current_critical_high:0, previous_critical_high:0,
      current_regressions:0, previous_regressions:0};
    for (const f of current) {
      counted.current_estimated_hours += hours[f.severity];
      if (f.severity === 'critical' || f.severity === 'high') counted.current_critical_high++;
      if (f.retest === 'regression') counted.current_regressions++;
    }
    for (const f of previous) {
      counted.previous_estimated_hours += hours[f.severity];
      if (f.severity === 'critical' || f.severity === 'high') counted.previous_critical_high++;
      if (f.retest === 'regression') counted.previous_regressions++;
    }
    for (const row of present) {
      const old = baseline.get(row[0]);
      if (!old) {
        counted.added++;
        counted.added_hours += hours[row[2]];
      } else {
        baseline.delete(row[0]);
        if (row.every((value, i) => value === old[i])) counted.unchanged++;
        else {
          counted.changed++;
          counted.changed_current_hours += hours[row[2]];
          counted.changed_previous_hours += hours[old[2]];
        }
      }
    }
    for (const row of baseline.values()) {
      counted.absent++;
      counted.absent_hours += hours[row[2]];
    }
    counted.net_estimated_change_hours = counted.current_estimated_hours-counted.previous_estimated_hours;
    return Object.freeze({...counted,
      review_only:true, same_client_engagement_verified:false, retest_verified:false,
      authorization:false, consent:false, grant:false, scan:false, dispatch:false,
      deploy:false, release:false});
  }
  function utcStart(date) {
    if (typeof date !== 'string' || !/^\d{4}-\d\d-\d\d$/.test(date)) fail('Use an ISO calendar start date');
    const [y,m,d] = date.split('-').map(Number);
    const ms = Date.UTC(y,m-1,d);
    if (new Date(ms).toISOString().slice(0,10) !== date || y < 2020 || y > 2100) fail('Invalid planning date');
    return ms;
  }
  function iso(ms) { return new Date(ms).toISOString().slice(0,10); }
  function plan(findings, options) {
    if (!Array.isArray(findings) || findings.length < 1 || findings.length > MAX_ROWS) fail('Import findings first');
    const start = utcStart(options.start);
    const weeks = exactInteger(options.weeks,1,12,'sprint weeks');
    const engineers = exactInteger(options.engineers,1,30,'team size');
    const workDays = exactInteger(options.workDays,1,5,'working days');
    const hoursPerDay = exactInteger(options.hoursPerDay,1,10,'hours per day');
    const reserve = exactInteger(options.reserve,0,80,'reserved capacity percentage');
    const estimated = {};
    SEVERITIES.forEach(s => { estimated[s] = exactInteger(options.hours[s],1,200,'estimated '+s+' effort'); });
    const weekAvailability = options.weekAvailability === undefined ? Array(weeks).fill(100) : options.weekAvailability;
    if (!Array.isArray(weekAvailability) || weekAvailability.length !== weeks) fail('Availability must be supplied for every planning week');
    const availability = Object.freeze(weekAvailability.map((v,i)=>exactInteger(v,0,100,'week '+(i+1)+' availability percentage')));
    const gross = engineers * workDays * hoursPerDay;
    const capacity = Math.floor((gross * (100 - reserve)) / 100);
    if (capacity < 1) fail('No available capacity after reserve');
    const queue = findings.map((finding,i)=>{
      if (!finding || !SEVERITIES.includes(finding.severity) || !STATUSES.includes(finding.retest)) fail('Noncanonical finding');
      return {ordinal:finding.ordinal||i+1,severity:finding.severity,retest:finding.retest,
        remaining:estimated[finding.severity],effort:estimated[finding.severity]};
    });
    // All four original retest states remain work candidates; "fixed" is not proof.
    // Regressions and high severity first. This is a proposed queue, never an SLA.
    queue.sort((a,b) => Number(b.retest==='regression')-Number(a.retest==='regression') ||
      SEVERITY_INDEX.get(a.severity)-SEVERITY_INDEX.get(b.severity) || a.ordinal-b.ordinal);
    const schedule = [];
    for (let w=0;w<weeks;w++) {
      const weeklyCapacity = Math.floor(capacity * availability[w] / 100);
      let remaining = weeklyCapacity;
      const portions=[];
      for (const task of queue) {
        if (!remaining) break;
        if (!task.remaining) continue;
        const allocation = Math.min(remaining,task.remaining);
        task.remaining -= allocation;
        if(task.remaining===0) task.allocatedByWeek=w+1;
        remaining -= allocation;
        portions.push(Object.freeze({ordinal:task.ordinal,severity:task.severity,
          sourceRetest:task.retest,hours:allocation,finished:task.remaining===0}));
      }
      schedule.push(Object.freeze({week:w+1,start:iso(start+w*7*86400000),
        availability:availability[w],capacity:weeklyCapacity,
        assigned:weeklyCapacity-remaining,remaining,portions:Object.freeze(portions)}));
    }
    const outstanding = queue.filter(x=>x.remaining>0);
    const totalHours = queue.reduce((n,x)=>n+x.effort,0);
    const priorityBands = Object.freeze(Object.fromEntries(SEVERITIES.map(severity=>{
      const items=queue.filter(x=>x.severity===severity);
      const estimated=items.reduce((n,x)=>n+x.effort,0);
      const remaining=items.reduce((n,x)=>n+x.remaining,0);
      const fullyScheduled=items.filter(x=>x.remaining===0).length;
      return [severity,Object.freeze({
        source_count:items.length,
        source_regressions:items.filter(x=>x.retest==='regression').length,
        estimated_hours:estimated,scheduled_hours:estimated-remaining,
        unscheduled_hours:remaining,fully_scheduled_estimates:fullyScheduled,
        all_estimates_scheduled:remaining===0,
        last_estimated_scheduling_week:remaining===0&&items.length
          ? Math.max(...items.map(x=>x.allocatedByWeek)) : null
      })];
    })));
    return Object.freeze({schedule:Object.freeze(schedule),
      capacity, totalHours, assignedHours:totalHours-outstanding.reduce((n,x)=>n+x.remaining,0),
      backlogHours:outstanding.reduce((n,x)=>n+x.remaining,0),
      backlogCount:outstanding.length,
      completedProposals:queue.filter(x=>x.remaining===0).length,
      sourceCount:queue.length,priorityBands,
      reserve, start:options.start,daysPerWeek:workDays,weeklyAvailability:availability});
  }
  // Bounded hypothetical remediation milestone, not a due-date promise or authority.
  function riskMilestone(findings,rawOptions,targetWeek,targetBand) {
    if(targetBand!=='critical'&&targetBand!=='critical_high')
      fail('Select critical-only or critical-and-high milestone');
    const base=plan(findings,rawOptions);
    const cutoff=exactInteger(targetWeek,1,base.schedule.length,'milestone planning week');
    const severities=targetBand==='critical'?['critical']:['critical','high'];
    const required=severities.reduce((total,severity)=>total+base.priorityBands[severity].estimated_hours,0);
    const fundedThroughWeek=planOutput=>planOutput.schedule.slice(0,cutoff).reduce(
      (total,week)=>total+week.portions.filter(part=>severities.includes(part.severity))
        .reduce((sum,part)=>sum+part.hours,0),0);
    const planned=fundedThroughWeek(base);
    let minimumEngineers=null;
    for(let engineers=1;engineers<=30;engineers++){
      const candidate=plan(findings,{...rawOptions,engineers});
      if(fundedThroughWeek(candidate)===required){minimumEngineers=engineers;break;}
    }
    const unallocated=Math.max(0,required-planned);
    return Object.freeze({
      review_only:true,authorization:false,consent:false,grant:false,
      execute:false,dispatch:false,scan:false,retest_verified:false,deploy:false,release:false,
      target_band:targetBand,target_week:cutoff,
      required_estimated_hours:required,provisionally_allocated_hours:planned,
      remaining_estimated_hours:unallocated,fit_by_target_week:unallocated===0,
      smallest_modelled_team:minimumEngineers,search_max_engineers:30
    });
  }
  // Quantify resilience to an explicitly hypothetical staffing interruption.
  // Never mutates the baseline or reclassifies findings or permission.
  function interruptionScenario(findings,rawOptions,week,weekAvailability,globalReduction) {
    const base=plan(findings,rawOptions);
    const index=exactInteger(week,1,base.schedule.length,'interrupted week')-1;
    const capped=exactInteger(weekAvailability,0,100,'interrupted week availability');
    const reduction=exactInteger(globalReduction,0,100,'ongoing capacity reduction');
    const original=base.weeklyAvailability;
    const temporary=Array.from(original);
    temporary[index]=Math.min(temporary[index],capped);
    const reduced=original.map(value=>Math.floor(value*(100-reduction)/100));
    const isolated=plan(findings,{...rawOptions,weekAvailability:temporary});
    const ongoing=plan(findings,{...rawOptions,weekAvailability:reduced});
    const aggregate=(p)=>Object.freeze({
      estimated_hours:p.totalHours,provisionally_allocated_hours:p.assignedHours,
      unallocated_hours:p.backlogHours,unallocated_findings:p.backlogCount,
      critical_high_unallocated_hours:p.priorityBands.critical.unscheduled_hours+
        p.priorityBands.high.unscheduled_hours,
      weekly_capacity_hours:Object.freeze(p.schedule.map(w=>w.capacity)),
      weekly_allocated_hours:Object.freeze(p.schedule.map(w=>w.assigned))
    });
    return Object.freeze({
      schema:'lightup.remediation_capacity_interruption_draft.v1',
      review_only:true,authorization:false,consent:false,grant:false,scan:false,
      execute:false,dispatch:false,retest_verified:false,deploy:false,release:false,
      hypothetical_event_week:index+1,
      hypothetical_event_availability_pct:temporary[index],
      hypothetical_ongoing_reduction_pct:reduction,
      baseline:aggregate(base),single_week_interruption:aggregate(isolated),
      sustained_reduction:aggregate(ongoing)
    });
  }
  function summary(plan) {
    return {
      schema:'lightup.remediation_capacity_draft.v1',
      review_only:true, authorization:false, consent:false, grant:false, scan:false,
      execute:false, dispatch:false, retest_verified:false, deploy:false, release:false,
      source_count:plan.sourceCount, proposed_completed:plan.completedProposals,
      total_estimated_hours:plan.totalHours, assigned_hours:plan.assignedHours,
      backlog_hours:plan.backlogHours, backlog_findings:plan.backlogCount,
      priority_bands:plan.priorityBands,
      sprint_weeks:plan.schedule.map(week=>{
        const severity_hours=Object.fromEntries(SEVERITIES.map(s=>[s,week.portions.filter(p=>p.severity===s).reduce((a,p)=>a+p.hours,0)]));
        return {week:week.week,start:week.start,availability_pct:week.availability,available_hours:week.capacity,
          allocated_hours:week.assigned,severity_hours};
      })
    };
  }
  function csvReport(plan) {
    const escape = v => '"' + String(v).replace(/"/g,'""') + '"';
    const headers=['week','week_start','availability_pct','available_hours','allocated_hours',...SEVERITIES.map(s=>s+'_hours')];
    const rows=plan.schedule.map(w=>[w.week,w.start,w.availability,w.capacity,w.assigned,...SEVERITIES.map(s=>
      w.portions.filter(p=>p.severity===s).reduce((a,p)=>a+p.hours,0))]);
    return [headers.map(escape).join(','),...rows.map(row=>row.map(escape).join(','))].join('\r\n')+'\r\n';
  }
  function markdownReport(plan) {
    const data=summary(plan);
    const lines=[
      '# LightUp — remediation capacity discussion draft',
      '',
      '**REVIEW_ONLY · DRAFT/HOLD. No authentication, consent, grant, scan, execution, retest verification, deployment or release.**',
      '',
      'This is an unsigned aggregate planning estimate only; source-reported fixed does not mean verified repair.',
      '',
      '- Source records: '+data.source_count,
      '- Total estimated repair effort: '+data.total_estimated_hours+' h',
      '- Hours tentatively assigned to weekly buckets: '+data.assigned_hours+' h',
      '- Backlog beyond modelled capacity: '+data.backlog_hours+' h across '+data.backlog_findings+' records',
      '',
      '| Week | Week beginning (UTC) | Availability (%) | Capacity (h) | Planned (h) | Critical (h) | High (h) | Medium (h) | Low (h) | Info (h) |',
      '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'
    ];
    for(const w of data.sprint_weeks) lines.push(
      '| '+[w.week,w.start,w.availability_pct,w.available_hours,w.allocated_hours,...SEVERITIES.map(s=>w.severity_hours[s])].join(' | ')+' |'
    );
    lines.push('','## Priority bands (planning estimates only)','',
      '| Severity | Records | Source regressions | Estimated h | Tentatively planned h | Remaining h | Fully allocated within horizon | Latest allocation week |',
      '| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |');
    for(const severity of SEVERITIES) {
      const band=data.priority_bands[severity];
      lines.push('| '+[severity,band.source_count,band.source_regressions,band.estimated_hours,
        band.scheduled_hours,band.unscheduled_hours,
        band.all_estimates_scheduled?'YES (estimate only)':'NO',
        band.last_estimated_scheduling_week===null?'—':band.last_estimated_scheduling_week].join(' | ')+' |');
    }
    lines.push('','Human follow-up: confirm source client/engagement externally, review estimates and staffing, assign owners through existing authorised channels, verify repairs/retests separately.','');
    return lines.join('\n');
  }
  root.LightUpCapacity = Object.freeze({parseCSV,compareReports,plan,riskMilestone,interruptionScenario,summary,csvReport,markdownReport,DEFAULT_HOURS,MAX_BYTES,MAX_ROWS});
})(window);
