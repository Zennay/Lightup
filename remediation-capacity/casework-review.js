/* Private, non-authorizing read of an original Casework v1 export.
 * Requires independently reloaded exact original LightUp findings CSV.
 * Never saves original finding IDs, owners, descriptions or case notes.
 */
(function (root) {
  'use strict';
  const MAX_BYTES=2097152, FIELDS=['finding_id','title','severity','retest_status','remediation'];
  const STAGES=['unassigned','planned','in_progress','blocked','ready_for_retest','deferred','completed'];
  const SEVERITIES=['critical','high','medium','low','info'];

  // Strict UTF-8 string JSON parser rejects duplicate object keys before
  // conversion; JSON.parse with a reviver cannot reliably do that.
  function parseStrictJSON(input) {
    if(typeof input!=='string'||new TextEncoder().encode(input).length>MAX_BYTES)
      throw Error('Casework input exceeds the permitted 2 MiB');
    let i=0,nodes=0;
    const white=()=>{while(i<input.length&&/[ \r\n\t]/.test(input[i]))i++;};
    const fail=()=>{throw Error('Invalid or ambiguous Casework JSON');};
    function str(){
      if(input[i]!=='"')fail();
      const begin=i++;
      while(i<input.length){
        const c=input[i++];
        if(c==='"'){
          try{return JSON.parse(input.slice(begin,i));}catch{fail();}
        }
        if(c==='\\') {
          if(i>=input.length)fail();
          i++;
        } else if(c.charCodeAt(0)<32)fail();
      }
      fail();
    }
    function value(depth) {
      white();
      if(++nodes>16000||depth>12||i>=input.length)fail();
      const c=input[i];
      if(c==='"')return str();
      if(c==='{'){
        i++;white();
        const obj=Object.create(null),seen=new Set();
        if(input[i]==='}'){i++;return obj;}
        for(;;){
          white();const k=str();
          if(seen.has(k)||['__proto__','constructor','prototype'].includes(k))fail();
          seen.add(k);white();
          if(input[i++]!==':')fail();
          obj[k]=value(depth+1);white();
          const delim=input[i++];
          if(delim==='}')return obj;
          if(delim!==',')fail();
        }
      }
      if(c==='['){
        i++;white();const out=[];
        if(input[i]===']'){i++;return out;}
        for(;;){
          if(out.length>3500)fail();
          out.push(value(depth+1));white();
          const delim=input[i++];
          if(delim===']')return out;
          if(delim!==',')fail();
        }
      }
      for(const [literal,val] of [['true',true],['false',false],['null',null]])
        if(input.startsWith(literal,i)){i+=literal.length;return val;}
      const match=input.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      if(!match)fail();
      i+=match[0].length;
      const number=Number(match[0]);
      if(!Number.isFinite(number)||!Number.isSafeInteger(number))fail();
      return number;
    }
    const v=value(0);
    white();
    if(i!==input.length)fail();
    return v;
  }
  const exact=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  function assertShape(obj,keys){
    if(!obj||typeof obj!=='object'||Array.isArray(obj)||
      !exact(Object.keys(obj).sort(),keys.slice().sort()))
      throw Error('Unexpected Casework envelope fields');
  }
  async function review(currentCSV,caseworkText,capacityPlan) {
    const original=root.LightUpCasework;
    if(!original||!root.crypto?.subtle)throw Error('Original Casework parser or SHA-256 is unavailable');
    if(typeof currentCSV!=='string'||new TextEncoder().encode(currentCSV).length>1048576)
      throw Error('The original source CSV must be reloaded, not inferred from the Casework packet');
    const current=original.parseCSV(currentCSV);
    if(!capacityPlan||capacityPlan.sourceCount!==current.length||!Array.isArray(capacityPlan.schedule)||
      capacityPlan.schedule.length<1||capacityPlan.schedule.length>12)
      throw Error('Generate an exact current-source capacity plan before Casework review');
    const packet=parseStrictJSON(caseworkText);
    assertShape(packet,[
      'kind','schema_version','disposition','authenticated','tenant_verified','source_authorized',
      'assessment_authorized','grant','client_consent','operator_consent','execution','scan',
      'audit_verdict','retest_verified','release','source_contract','source_sha256',
      'findings','cases','instructions'
    ]);
    const loaded=original.loadPacket(packet);
    // The Casework digest is over its normalized, ID-sorted original source,
    // not over this capacity app's byte digest or an editable filename.
    const expected=await original.digest(current);
    if(!expected||!loaded.source_sha256||loaded.source_sha256!==expected)
      throw Error('Casework is not bound to the exact canonical current LightUp findings');
    const reference=new Map(current.map(f=>[f.finding_id,f]));
    if(loaded.findings.length!==current.length||loaded.cases.length!==current.length)
      throw Error('Incomplete original Casework handoff');
    for(const row of loaded.findings){
      const src=reference.get(row.finding_id);
      if(!src||FIELDS.some(k=>src[k]!==row[k]))
        throw Error('Casework source fields differ from original CSV');
    }
    const sourceOrdinal=new Map(current.map((record,index)=>[record.finding_id,index+1]));
    const blockedOrdinals=new Set();
    const sourceRegressionsMarkedComplete=new Set();
    const statuses=Object.fromEntries(STAGES.map(s=>[s,0]));
    const severity=Object.fromEntries(SEVERITIES.map(s=>[s,{
      total:0,blocked:0,missing_owner:0,undated:0,ready_for_retest:0,
      deferred:0,locally_completed_unverified:0
    }]));
    let assigned=0,withDueDate=0,blockedWithNotes=0;
    const advisories={critical_high_blocked:0,critical_high_unowned:0,
      critical_high_undated:0,source_regression_locally_completed:0,
      source_regression_deferred:0,retest_coordination_without_owner:0,
      blocked_without_note:0};
    for(const row of loaded.cases) {
      const originalRow=reference.get(row.finding_id);
      if(!originalRow)throw Error('Unknown Casework source ID');
      const segment=severity[originalRow.severity];
      statuses[row.status]++;segment.total++;
      if(row.owner.trim())assigned++;
      else segment.missing_owner++;
      if(row.due_date)withDueDate++;
      else segment.undated++;
      if(row.status==='blocked') {
        blockedOrdinals.add(sourceOrdinal.get(row.finding_id));
        segment.blocked++;
        if(row.blocker.trim())blockedWithNotes++;
      }
      if(row.status==='ready_for_retest')segment.ready_for_retest++;
      if(row.status==='deferred')segment.deferred++;
      if(row.status==='completed')segment.locally_completed_unverified++;
      const urgent=originalRow.severity==='critical'||originalRow.severity==='high';
      if(urgent&&row.status==='blocked')advisories.critical_high_blocked++;
      if(urgent&&!row.owner.trim())advisories.critical_high_unowned++;
      if(urgent&&!row.due_date)advisories.critical_high_undated++;
      if(originalRow.retest_status==='regression'&&row.status==='completed'){
        advisories.source_regression_locally_completed++;
        sourceRegressionsMarkedComplete.add(sourceOrdinal.get(row.finding_id));
      }
      if(originalRow.retest_status==='regression'&&row.status==='deferred')
        advisories.source_regression_deferred++;
      if(row.status==='ready_for_retest'&&!row.owner.trim())
        advisories.retest_coordination_without_owner++;
      if(row.status==='blocked'&&!row.blocker.trim())advisories.blocked_without_note++;
    }
    const weeklyRisk=capacityPlan.schedule.map(week=>{
      if(!Array.isArray(week.portions)||!Number.isSafeInteger(week.week)||
        !Number.isSafeInteger(week.assigned))
        throw Error('Capacity schedule was changed after source review');
      let held=0,urgent=0,sourceConflict=0;
      for(const portion of week.portions){
        if(!Number.isSafeInteger(portion.ordinal)||portion.ordinal<1||portion.ordinal>current.length||
           !Number.isSafeInteger(portion.hours)||portion.hours<1)
          throw Error('Invalid anonymous capacity source position');
        if(blockedOrdinals.has(portion.ordinal)){
          held+=portion.hours;
          if(portion.severity==='critical'||portion.severity==='high')urgent+=portion.hours;
        }
        if(sourceRegressionsMarkedComplete.has(portion.ordinal))sourceConflict+=portion.hours;
      }
      if(held>week.assigned||sourceConflict>week.assigned)
        throw Error('Contradictory anonymous capacity schedule');
      return Object.freeze({
        week:week.week,start:week.start,provisionally_allocated_hours:week.assigned,
        locally_blocked_estimated_hours:held,
        locally_blocked_critical_high_estimated_hours:urgent,
        source_regression_locally_completed_estimated_hours:sourceConflict
      });
    });
    // Discard all source identifiers, case notes, owners and expiry metadata;
    // the result is only aggregate, untrusted human self-report.
    return Object.freeze({
      schema:'lightup.capacity_casework_review_draft.v1',
      review_only:true,authenticated:false,source_authorized:false,
      authorization:false,consent:false,grant:false,scan:false,
      execute:false,dispatch:false,retest_verified:false,deploy:false,release:false,
      matched_original_source_locally:true,client_engagement_authenticated:false,
      source_records:current.length,assigned_owner_labels:assigned,
      source_casework_due_dates:withDueDate,blocked_with_local_notes:blockedWithNotes,
      source_casework_statuses:statuses,severity_statuses:severity,
      human_review_flags:advisories,
      weekly_blocker_pressure:weeklyRisk
    });
  }

  function combinedBrief(plan,sourceReview,planner) {
    if(!plan||!sourceReview||sourceReview.schema!=='lightup.capacity_casework_review_draft.v1'||
      sourceReview.review_only!==true||sourceReview.authorization!==false||
      !Array.isArray(sourceReview.weekly_blocker_pressure)||
      sourceReview.weekly_blocker_pressure.length!==plan.schedule.length||
      sourceReview.source_records!==plan.sourceCount)
      throw Error('Generate and review matching original capacity + Casework sources first');
    const summary=planner.summary(plan);
    const lines=[
      '# LightUp — private remediation coordination brief',
      '',
      '**INTERNAL HUMAN DISCUSSION · UNSIGNED · REVIEW_ONLY · DRAFT/HOLD.**',
      '',
      'This is not authentication, current consent, verified remediation, retest, a granted assessment scope, execution or deployment permission.',
      '',
      '## Current source and planning workload',
      '',
      '- Original source findings: '+plan.sourceCount,
      '- Estimated total remediation effort: '+plan.totalHours+' h',
      '- Proposed planning allocation: '+plan.assignedHours+' h',
      '- Unallocated work: '+plan.backlogHours+' h across '+plan.backlogCount+' source records',
      '- Proposed urgent (critical/high) backlog: '+
        (plan.priorityBands.critical.unscheduled_hours+plan.priorityBands.high.unscheduled_hours)+' h',
      '- Locally blocked Casework notes: '+sourceReview.source_casework_statuses.blocked,
      '- Casework owner labels absent: '+(plan.sourceCount-sourceReview.assigned_owner_labels),
      '- Local Casework status marked completed (UNVERIFIED): '+
        sourceReview.source_casework_statuses.completed,
      '',
      '## Week-by-week coordination risk',
      '',
      '| Week | Week beginning UTC | Planned h | Locally blocked h | Critical/high blocked h | Regressions locally called completed h |',
      '| --- | --- | ---: | ---: | ---: | ---: |'
    ];
    for(const row of sourceReview.weekly_blocker_pressure) {
      lines.push('| '+[row.week,row.start,row.provisionally_allocated_hours,
        row.locally_blocked_estimated_hours,row.locally_blocked_critical_high_estimated_hours,
        row.source_regression_locally_completed_estimated_hours].join(' | ')+' |');
    }
    lines.push('','## Human follow-up by risk classification','','| Risk class | Original records | Locally blocked | Missing owner labels | Proposed undated |',
      '| --- | ---: | ---: | ---: | ---: |');
    for(const severity of SEVERITIES) {
      const row=sourceReview.severity_statuses[severity];
      lines.push('| '+[severity,row.total,row.blocked,row.missing_owner,row.undated].join(' | ')+' |');
    }
    const questions=[
      ['critical_high_blocked','Discuss blockers delaying critical/high remediation.'],
      ['critical_high_unowned','Find a human point of contact for critical/high cases.'],
      ['critical_high_undated','Discuss tentative target dates for urgent source findings.'],
      ['source_regression_locally_completed','Resolve contradictory self-reported completed work vs source regressions.'],
      ['source_regression_deferred','Discuss a plan for deferred regressions.'],
      ['retest_coordination_without_owner','Agree who will separately request real, authorised retest.'],
      ['blocked_without_note','Request human clarification for missing blocker explanations.']
    ];
    lines.push('','## Open human discussion questions','');
    let any=false;
    for(const [key,description] of questions) {
      const count=sourceReview.human_review_flags[key];
      if(count) {lines.push('- '+count+' aggregate cases: '+description);any=true;}
    }
    if(!any)lines.push('- No flagged source-bound coordination contradictions in these specific categories. This is **not** proof of repair or consent.');
    lines.push('','## Mandatory operator boundaries','',
      'Independently authenticate the client and engagement, recheck current scope consent and revocation at use, and do not treat this review packet as a grant.',
      'Never infer a vulnerability was fixed from a missing source finding, a local Casework completion label or a planned allocation.',
      'Keep original authorisation, separate client/operator consent, source owner integration, security/privacy review, exact-head hosted/VPS CI and HUMAN GO intact.','');
    return lines.join('\n');
  }
  root.LightUpCapacityCasework=Object.freeze({review,combinedBrief,MAX_BYTES});
})(window);
