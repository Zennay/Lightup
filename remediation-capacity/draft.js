/* LightUp offline, user-controlled source-bound capacity working draft.
 * An exact source fingerprint binds a non-authorizing local planning proposal.
 * No storage, network, consent, secrets, credentials, grants or execution.
 */
(function (root) {
  'use strict';
  const SCHEMA='lightup.remediation_capacity_working_draft.v1';
  const FLAGS=['authorization','consent','grant','scan','execute','dispatch','retest_verified','deploy','release'];
  const OPTION_KEYS=['start','weeks','engineers','workDays','hoursPerDay','reserve','hours','weekAvailability'];
  const SEVERITIES=['critical','high','medium','low','info'];
  const MAX_DRAFT_BYTES=8192;
  const MAX_CSV_BYTES=1048576;
  const exactKeys=(obj,keys)=>{
    if(!obj||typeof obj!=='object'||Array.isArray(obj))throw new Error('Invalid private draft object');
    const actual=Object.keys(obj).sort();
    if(actual.length!==keys.length || actual.some((v,i)=>v!==keys.slice().sort()[i]))
      throw new Error('Unexpected or missing private draft fields');
  };
  const integer=(n,min,max)=>{
    if(typeof n!=='number'||!Number.isSafeInteger(n)||n<min||n>max)
      throw new Error('Invalid bounded planning assumption');
    return n;
  };
  async function fingerprint(file) {
    if(!file||!file.size||file.size>MAX_CSV_BYTES)throw new Error('First import the exact original findings CSV');
    if(!root.crypto?.subtle)throw new Error('Browser SHA-256 unavailable; cannot bind a draft to its source');
    const bytes=await file.arrayBuffer();
    if(bytes.byteLength>MAX_CSV_BYTES)throw new Error('Original source exceeds bound');
    const digest=await root.crypto.subtle.digest('SHA-256',bytes);
    return [...new Uint8Array(digest)].map(v=>v.toString(16).padStart(2,'0')).join('');
  }
  function normalizedOptions(raw) {
    exactKeys(raw,OPTION_KEYS);
    if(typeof raw.start!=='string'||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(raw.start))
      throw new Error('Invalid planning date');
    const weeks=integer(raw.weeks,1,12);
    exactKeys(raw.hours,SEVERITIES);
    const hours=Object.fromEntries(SEVERITIES.map(severity=>[severity,integer(raw.hours[severity],1,200)]));
    if(!Array.isArray(raw.weekAvailability)||raw.weekAvailability.length!==weeks)
      throw new Error('Inconsistent saved weekly availability');
    return {
      start:raw.start,
      weeks,engineers:integer(raw.engineers,1,30),
      workDays:integer(raw.workDays,1,5),
      hoursPerDay:integer(raw.hoursPerDay,1,10),
      reserve:integer(raw.reserve,0,80),
      hours,weekAvailability:raw.weekAvailability.map(value=>integer(value,0,100))
    };
  }
  function envelope(sourceSha,sourceCount,raw,staffScenario) {
    if(typeof sourceSha!=='string'||!/^[0-9a-f]{64}$/.test(sourceSha))
      throw new Error('Missing source SHA-256');
    const count=integer(sourceCount,1,350);
    const options=normalizedOptions(raw);
    const scenario=integer(staffScenario,0,10);
    return {
      schema:SCHEMA,review_only:true,
      authorization:false,consent:false,grant:false,scan:false,execute:false,
      dispatch:false,retest_verified:false,deploy:false,release:false,
      source_sha256:sourceSha,source_count:count,
      options,staff_scenario_additional_engineers:scenario
    };
  }
  function exportDraft(sourceSha,sourceCount,raw,staffScenario) {
    const packet=envelope(sourceSha,sourceCount,raw,staffScenario);
    // Canonical compact JSON means duplicate/confusable keys fail re-import.
    const serialized=JSON.stringify(packet);
    if(new TextEncoder().encode(serialized).byteLength>MAX_DRAFT_BYTES)
      throw new Error('Oversized working draft');
    return serialized+'\n';
  }
  function importDraft(text,sourceSha,sourceCount,findings,planner) {
    if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_DRAFT_BYTES)
      throw new Error('Oversized private draft');
    // Canonical-only JSON: duplicate keys, whitespace changes, unknown encodings,
    // decomposed aliases and number coercions cannot silently enter a draft.
    const stripped=text.endsWith('\n')?text.slice(0,-1):text;
    if(!stripped||stripped.includes('\n'))throw new Error('Noncanonical private draft');
    let parsed;
    try{parsed=JSON.parse(stripped);}catch{throw new Error('Malformed private draft JSON');}
    if(JSON.stringify(parsed)!==stripped)throw new Error('Noncanonical or duplicate-key draft');
    exactKeys(parsed,['schema','review_only',...FLAGS,'source_sha256','source_count',
      'options','staff_scenario_additional_engineers']);
    if(parsed.schema!==SCHEMA||parsed.review_only!==true||
      FLAGS.some(k=>parsed[k]!==false))throw new Error('Draft contains an authority claim or unsupported version');
    if(parsed.source_sha256!==sourceSha||parsed.source_count!==sourceCount)
      throw new Error('Draft does not belong to the exact re-imported findings CSV');
    const canonical=envelope(sourceSha,sourceCount,parsed.options,parsed.staff_scenario_additional_engineers);
    if(JSON.stringify(canonical)!==stripped)throw new Error('Noncanonical planning draft');
    // Planner validation is a prerequisite; caller only mutates UI after return.
    const plan=planner.plan(findings,canonical.options);
    return Object.freeze({options:canonical.options,scenario:canonical.staff_scenario_additional_engineers,plan});
  }
  root.LightUpDraft=Object.freeze({fingerprint,exportDraft,importDraft,MAX_DRAFT_BYTES});
})(window);
