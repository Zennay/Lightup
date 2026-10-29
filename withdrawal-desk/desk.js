/* LightUp Scope Withdrawal Desk: offline coordination only, no operational authority. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const MAX_FILES = 16, MAX_BYTES = 65536;
  const ACTIONS = Object.freeze([
    ['client_channel','Contact the client through an independently authenticated channel to request withdrawal.'],
    ['operator_channel','Notify an independent authenticated operator using the approved urgent channel.'],
    ['active_work','Ask operators to stop or pause in-flight work and independently confirm its state.'],
    ['grant_revoke','Ask grant owners to revoke affected authorizations and enforce revocation at action time.'],
    ['scope_schedule','Ask owners to reconcile approved scope and schedule with the requested change.'],
    ['evidence_privacy','Ask data owners to review evidence access, sharing and retention after withdrawal.'],
    ['human_ack','Seek a documented independently authenticated receipt and owner acknowledgment.'],
    ['incident_log','Record the operational incident decision in the real authoritative audit system.']
  ]);
  const FLAGS = Object.freeze({
    authenticated_client:false, authenticated_operator:false,
    approved:false, consent:false, authorization:false, grant:false,
    revoked:false, handler_stopped:false, dispatch:false,
    scan:false, deploy:false, release:false
  });
  let cases=[], selected=null;
  const intents=new Set(['stop_all','narrow_scope','postpone','withdraw_share']);
  const priorities=new Set(['urgent','normal']);
  const taskStates=new Set(['todo','drafted_local','requested_unverified']);
  const forbiddenKeys=new Set(['__proto__','constructor','prototype']);
  const setFeedback=(s,alert=false)=>{ $('feedback').textContent=s; $('feedback').classList.toggle('dangerText',alert); };
  function exactKeys(obj, keys) {
    return obj && typeof obj==='object' && !Array.isArray(obj) &&
      Object.keys(obj).every(k=>keys.includes(k) && !forbiddenKeys.has(k));
  }
  function textOf(v,max) {return typeof v==='string'&&v.length<=max&& !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(v);}
  function isSha(s){return typeof s==='string' && /^[a-f0-9]{64}$/.test(s);}
  function safeCount(arr) {
    return Array.isArray(arr)&&arr.length>0&&arr.length<=80 &&
      arr.every(x=>textOf(x,256)&&x.length>0) &&
      new Set(arr.map(x=>x.toLowerCase())).size===arr.length;
  }
  function parseSource(raw){
    if(typeof raw!=='string'||raw.length>MAX_BYTES)return null;
    let v; try {v=JSON.parse(raw);} catch {return null;}
    if(!exactKeys(v,[
      'kind','schema_version','state','authorization','client_consent',
      'operator_consent','grant','execution','revocation_checked','proposal_name',
      'client_label','requested_assets','excluded_assets','requested_mode','requested_risk',
      'notes','proposed_activities','proposed_window_local','proposed_window_utc',
      'exported_at_utc','scope_fingerprint_sha256'
    ]))return null;
    if(v.kind!=='lightup.scope_proposal_draft'||v.schema_version!==1||
       v.state!=='DRAFT_ONLY'||v.authorization!==false||v.client_consent!==false||
       v.operator_consent!==false||v.grant!==false||v.execution!==false||
       v.revocation_checked!==false)return null;
    if(!safeCount(v.requested_assets)||!Array.isArray(v.excluded_assets)||
       v.excluded_assets.length>80||
       !v.excluded_assets.every(x=>textOf(x,256)&&x.length>0))return null;
    if(!textOf(v.proposal_name,120)||!textOf(v.client_label,100)||
       !textOf(v.notes,3000)||!['analysis_only','authorized_assessment'].includes(v.requested_mode)||
       !Number.isInteger(v.requested_risk)||v.requested_risk<1||v.requested_risk>4)return null;
    if(!exactKeys(v.proposed_activities,['passive_analysis','configuration_review','private_lab_network_checks'])||
       !['passive_analysis','configuration_review','private_lab_network_checks'].every(k=>typeof v.proposed_activities[k]==='boolean'))return null;
    if(!exactKeys(v.proposed_window_local,['start','end'])||
       !['start','end'].every(k=>v.proposed_window_local[k]===null||textOf(v.proposed_window_local[k],40)))return null;
    if(typeof v.proposed_window_utc!=='object'||v.proposed_window_utc===null||
       Array.isArray(v.proposed_window_utc))return null;
    if(v.scope_fingerprint_sha256!==undefined&&!isSha(v.scope_fingerprint_sha256))return null;
    // Structural envelope checks cannot authenticate the author, timezone or scope.
    return {label:v.proposal_name.trim().slice(0,120)||'Unnamed draft',
      risk:v.requested_risk,mode:v.requested_mode,
      assets:v.requested_assets.length,excluded:v.excluded_assets.length,
      windowStatus:typeof v.proposed_window_utc.status==='string'
        ?v.proposed_window_utc.status.slice(0,40):'unknown'};
  }
  function newCase(hash,meta){return {...meta,sha:hash,bound:true,intent:'stop_all',
    urgency:'urgent',effective:'',reference:'',note:'',prepared:false,
    steps:Object.fromEntries(ACTIONS.map(([code])=>[code,'todo'])),
    events:[]};}
  function safeUTC(s){if(s==='')return true;return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)&&
    !Number.isNaN(Date.parse(s+'Z'))&&new Date(s+'Z').toISOString().slice(0,16)===s;}
  async function fingerprint(buffer){
    if(!globalThis.crypto?.subtle)throw Error('Browser cannot calculate local SHA-256. Use a secure, modern local browser.');
    const bytes=new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',buffer));
    return Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
  }
  async function readFile(f){
    if(!f||f.size===0||f.size>MAX_BYTES)throw Error('File size rejected (1–65536 bytes).');
    const buf=await f.arrayBuffer();
    const source=new TextDecoder('utf-8',{fatal:true}).decode(buf);
    const meta=parseSource(source);
    if(!meta)throw Error('Input is not a bounded Studio v1 DRAFT_ONLY proposal with false authority flags.');
    return {hash:await fingerprint(buf),meta};
  }
  function selectedCase(){return cases.find(c=>c.sha===selected)||null;}
  function touch(c,action){
    c.events.push({at:new Date().toISOString(),action});
    if(c.events.length>40)c.events.shift();
  }
  function el(tag,txt,css){
    const n=document.createElement(tag);
    if(txt!==undefined)n.textContent=txt;
    if(css)n.className=css;
    return n;
  }
  function button(txt,fn,css){
    const n=el('button',txt,css);n.type='button';n.addEventListener('click',fn);return n;
  }
  function stat(c){
    return c.steps?Object.values(c.steps).filter(s=>s==='todo').length:ACTIONS.length;
  }
  function render(){
    $('loaded').textContent=cases.length+' local draft(s)';
    const filter=$('caseSearch').value.trim().toLowerCase();
    $('cases').replaceChildren();
    for(const c of cases){
      if(filter&&!([c.label,c.reference,c.sha,c.intent,c.urgency].join(' ').toLowerCase().includes(filter)))continue;
      const n=button(c.label+' · Risk '+c.risk+' · '+c.intent.replaceAll('_',' '),()=>{selected=c.sha;render();});
      n.setAttribute('aria-current',String(selected===c.sha));
      n.append(el('small',(c.bound?'SOURCE ATTACHED':'SOURCE UNBOUND · REATTACH')+' · '+c.sha.slice(0,16)+'… · '+stat(c)+' steps open'));
      $('cases').append(n);
    }
    if(!$('cases').children.length)$('cases').append(el('p','No matching drafts.','muted'));
    const c=selectedCase();
    $('empty').hidden=!!c;$('editor').hidden=!c;
    if(c){
      $('source').textContent='Original input SHA-256: '+c.sha+'\n'+
        (c.bound?'Exact original source attached in tab':'SOURCE UNBOUND — exact file must be reattached')+
        '\nProposal label (self-reported): '+c.label+'\nRisk '+c.risk+' · '+c.mode+
        ' · '+c.assets+' proposed / '+c.excluded+' excluded · window: '+c.windowStatus;
      for(const k of ['intent','urgency','effective','reference','note'])$(k).value=c[k];
      const container=$('tasks');container.replaceChildren();
      if(!c.prepared)container.append(el('p','Prepare the follow-up list first.','muted'));
      else for(const [code,title] of ACTIONS){
        const row=el('div',undefined,'task');row.append(el('div',code.toUpperCase(),'code'),el('p',title));
        const label=el('label','Local paperwork status (not verified)');
        const input=document.createElement('select');input.setAttribute('aria-label',code+' paperwork status');
        for(const [value,display] of [['todo','Not started'],['drafted_local','Locally drafted'],['requested_unverified','Claimed requested — NOT VERIFIED']]){
          const opt=document.createElement('option');opt.value=value;opt.textContent=display;input.append(opt);
        }
        input.value=c.steps[code];
        input.addEventListener('change',()=>{c.steps[code]=input.value;touch(c,'paperwork_'+code);renderTotals();preview();});
        row.append(label,input);container.append(row);
      }
    }
    renderTotals();preview();
  }
  function renderTotals(){
    $('caseCount').textContent=String(cases.length);
    $('urgentCount').textContent=String(cases.filter(c=>c.urgency==='urgent').length);
    $('outstandingCount').textContent=String(cases.reduce((v,c)=>v+stat(c),0));
  }
  function brief(c){
    if(!c)return'Select an original Studio draft. No approval or revocation can be performed here.';
    const lines=[
      'LIGHTUP · WITHDRAWAL / STOP REQUEST PREPARATION',
      'REVIEW_ONLY · HUMAN CHANNEL REQUIRED · NEVER AUTHORITY',
      'Original source SHA-256: '+c.sha,
      'Source attached: '+(c.bound?'yes (local, untrusted)':'NO — HOLD'),
      'Self-reported proposal: '+c.label.slice(0,120),
      'Intent: '+c.intent.replaceAll('_',' '), 'Priority: '+c.urgency,
      'Requested UTC: '+(c.effective||'not specified'),
      'Paperwork: '+(c.prepared?'locally drafted':'not prepared'),
      'Local actions remaining: '+stat(c),
      ...ACTIONS.map(([k,t])=>'- '+k+': '+c.steps[k]+' / '+t),
      'MUST BE CONFIRMED OUTSIDE THIS TOOL: actual client/operator identity,',
      'current approved scope, live grant revocation, active job shutdown,',
      'effective time, evidence disposition and human acknowledgment.',
      'ALL AUTHORIZATION, GRANT, REVOCATION, SCAN AND RELEASE FLAGS: FALSE.'
    ];
    return lines.join('\n');
  }
  function preview(){ $('preview').textContent=brief(selectedCase());}
  function flagsOkay(x){return exactKeys(x,Object.keys(FLAGS))&&Object.entries(FLAGS).every(([k,v])=>x[k]===v);}
  function exportData(single=false){
    const inputs=single?(selectedCase()?[selectedCase()]:[]):cases;
    if(!inputs.length||inputs.some(c=>!c.bound))throw Error('HOLD: source-bound exports require each included original source to be attached.');
    return {kind:'lightup.scope_withdrawal_review_only',schema_version:1,
      disposition:'REVIEW_ONLY',flags:{...FLAGS},
      generated_at_utc:new Date().toISOString(),
      cases:inputs.map(c=>({source_sha256:c.sha,risk:c.risk,
        intent:c.intent,urgency:c.urgency,requested_effective_utc:c.effective||null,
        proposed_asset_count:c.assets,proposed_exclusion_count:c.excluded,
        paperwork_prepared:c.prepared,
        human_work_items:ACTIONS.map(([code])=>({code,status:c.steps[code]})),
        ...FLAGS
      }))};
  }
  function download(name,content,type){
    const blob=new Blob([content],{type});
    const url=URL.createObjectURL(blob);
    try{
      const a=document.createElement('a');a.href=url;a.download=name;
      document.body.append(a);a.click();a.remove();
    }finally{setTimeout(()=>URL.revokeObjectURL(url),1000);}
  }
  function escapeCSV(x){
    const v=String(x).replaceAll('"','""');
    return '"'+(/^[\s\u200B-\u200D\uFEFF]*[=+@\-\t\r]/u.test(v)?"'"+v:v)+'"';
  }
  async function ingest(files){
    if(!files.length)return;
    if(files.length>MAX_FILES)throw Error('HOLD: at most 16 source drafts in one selection.');
    const pending=[];
    for(const file of files){
      const {hash,meta}=await readFile(file);
      if(pending.some(x=>x.hash===hash))throw Error('HOLD: duplicate source files in selection.');
      pending.push({hash,meta});
    }
    if(cases.length+pending.filter(p=>!cases.some(c=>c.sha===p.hash)).length>MAX_FILES)
      throw Error('HOLD: at most 16 distinct source drafts in one workspace.');
    // Atomic import: apply only after all files have passed size, UTF-8, schema and digest preflight.
    for(const p of pending){
      const old=cases.find(x=>x.sha===p.hash);
      if(old){
        if(Object.entries(p.meta).some(([k,v])=>old[k]!==v))throw Error('HOLD: restored source metadata does not match exact bytes.');
      }
    }
    for(const p of pending){
      const old=cases.find(x=>x.sha===p.hash);
      if(old)old.bound=true;
      else cases.push(newCase(p.hash,p.meta));
    }
    if(!selected&&cases.length)selected=cases[0].sha;
    setFeedback('Locally attached '+pending.length+' exact Studio draft(s). This does not validate client identity, consent or grants.');
    render();
  }
  function readPrivate(s){
    let obj;try{obj=JSON.parse(s);}catch{throw Error('Malformed private session JSON.');}
    if(!exactKeys(obj,['kind','schema_version','flags','cases'])||
       obj.kind!=='lightup.scope_withdrawal_private_session'||obj.schema_version!==1||
       !flagsOkay(obj.flags)||!Array.isArray(obj.cases)||
       obj.cases.length>MAX_FILES)throw Error('HOLD: invalid private session envelope.');
    const parsed=[];
    for(const x of obj.cases){
      if(!exactKeys(x,['sha','label','risk','mode','assets','excluded','windowStatus',
          'intent','urgency','effective','reference','note','prepared','steps','events'])||
        !isSha(x.sha)||!textOf(x.label,120)||!textOf(x.reference,40)||
        !textOf(x.note,500)||!textOf(x.windowStatus,40)||
        !Number.isInteger(x.risk)||x.risk<1||x.risk>4||
        !['analysis_only','authorized_assessment'].includes(x.mode)||
        !Number.isInteger(x.assets)||x.assets<1||x.assets>80||
        !Number.isInteger(x.excluded)||x.excluded<0||x.excluded>80||
        !intents.has(x.intent)||!priorities.has(x.urgency)||!safeUTC(x.effective)||
        typeof x.prepared!=='boolean'||
        !exactKeys(x.steps,ACTIONS.map(a=>a[0]))||
        ACTIONS.some(([k])=>!taskStates.has(x.steps[k]))||
        !Array.isArray(x.events)||x.events.length>40||
        x.events.some(e=>!exactKeys(e,['at','action'])||!textOf(e.action,80)||
          !textOf(e.at,40)||!Number.isFinite(Date.parse(e.at)))||
        parsed.some(c=>c.sha===x.sha))throw Error('HOLD: invalid private case content.');
      parsed.push({...x,bound:false});
    }
    return parsed;
  }
  $('files').addEventListener('change',async ev=>{
    try{await ingest([...ev.target.files]);}
    catch(e){setFeedback(e.message||'HOLD: import refused.',true);}
    finally{ev.target.value='';}
  });
  $('caseSearch').addEventListener('input',render);
  $('clear').addEventListener('click',()=>{
    if(cases.length&&!confirm('Forget ALL in-memory withdrawal notes and source attachments? Unsaved work will be lost.'))return;
    cases=[];selected=null;$('caseSearch').value='';setFeedback('Local memory cleared.');render();
  });
  $('prepare').addEventListener('click',()=>{
    const c=selectedCase();if(!c)return;
    for(const k of ['intent','urgency','effective','reference','note'])c[k]=$(k).value;
    if(!safeUTC(c.effective)){setFeedback('HOLD: requested UTC must be a real canonical YYYY-MM-DDTHH:MM instant.',true);return;}
    c.prepared=true;touch(c,'followup_prepared');
    setFeedback('Follow-up list prepared locally. NO live stop or revocation occurred.');render();
  });
  $('resetCase').addEventListener('click',()=>{
    const c=selectedCase();if(!c||!confirm('Reset locally prepared paperwork for this case?'))return;
    const fresh=newCase(c.sha,{label:c.label,risk:c.risk,mode:c.mode,assets:c.assets,excluded:c.excluded,windowStatus:c.windowStatus});
    Object.assign(c,fresh);touch(c,'case_reset');render();
  });
  $('jsonExport').addEventListener('click',()=>{
    try{download('lightup-withdrawal-review-only.json',JSON.stringify(exportData(),null,2)+'\n','application/json');setFeedback('REVIEW_ONLY export created. Must still use real authenticated withdrawal channel.');}
    catch(e){setFeedback(e.message,true);}
  });
  $('stopExport').addEventListener('click',()=>{
    try {
      const c=selectedCase();
      if(!c)throw Error('HOLD: select a source-bound case first.');
      if(c.urgency!=='urgent')throw Error('HOLD: mark priority Urgent and prepare the follow-up list before using urgent handoff.');
      if(!c.prepared)throw Error('HOLD: prepare the local human follow-up list first.');
      if(!c.bound)throw Error('HOLD: exact original source is not attached.');
      if(!confirm('This only downloads paperwork. It DOES NOT stop live work or revoke a grant. Have you contacted the genuine authenticated incident channel?'))return;
      download('lightup-urgent-human-stop-request.json',
        JSON.stringify(exportData(true),null,2)+'\n','application/json');
      setFeedback('Single-case STOP paperwork downloaded. No live operation changed. Contact the real authenticated human channel.');
    } catch(e){setFeedback(e.message,true);}
  });
  $('csvExport').addEventListener('click',()=>{
    try{
      const d=exportData();const rows=[['source_sha256','intent','priority','action_code','local_status','authority','revoked']];
      for(const c of d.cases)for(const t of c.human_work_items)
        rows.push([c.source_sha256,c.intent,c.urgency,t.code,t.status,'FALSE','FALSE']);
      download('lightup-withdrawal-action-queue.csv',rows.map(row=>row.map(escapeCSV).join(',')).join('\r\n')+'\r\n','text/csv');
      setFeedback('Privacy-minimal human action queue exported. No operational effect.');
    }catch(e){setFeedback(e.message,true);}
  });
  $('privateExport').addEventListener('click',()=>{
    if(!cases.length){setFeedback('No private casework to export.',true);return;}
    if(!confirm('Private export contains local proposal labels, notes and case references. Save only in a protected location. Continue?'))return;
    const data={kind:'lightup.scope_withdrawal_private_session',schema_version:1,
      flags:{...FLAGS},cases:cases.map(({bound,...rest})=>rest)};
    download('lightup-withdrawal-private-session.json',JSON.stringify(data,null,2)+'\n','application/json');
    setFeedback('Private session downloaded. Source bytes are NOT stored; reattach originals after restore.');
  });
  $('restore').addEventListener('change',async ev=>{
    try{
      const file=ev.target.files[0];if(!file||file.size>131072||file.size===0)throw Error('HOLD: session input size invalid.');
      const data=readPrivate(new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()));
      if(cases.length&&!confirm('Replace current local workspace with restored UNBOUND paperwork?'))return;
      cases=data;selected=cases[0]?.sha||null;setFeedback('Restored private paperwork only. ALL sources UNBOUND until exact originals are reattached.');render();
    }catch(e){setFeedback(e.message||'HOLD: restore refused.',true);}
    finally{ev.target.value='';}
  });
  $('print').addEventListener('click',()=>{if(!selectedCase())return;window.print();});
  document.addEventListener('visibilitychange',()=>{if(document.hidden){$('note').value='';$('reference').value='';}});
  render();
})();
