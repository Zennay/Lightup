/* Offline review of two real but unsigned LightUp operator snapshots.
 * A missing row is not remediation, consent or execution approval. */
(function(global){
'use strict';
const SHA=/^[0-9a-f]{64}$/;
const FALSE=['authorization_granted','client_consent_verified','execution_allowed','operator_consent_verified','release_approved'];
const $=id=>document.getElementById(id);
const create=(tag,content)=>{const e=document.createElement(tag);e.textContent=String(content);return e;};
function records(data){
  if(!data || !Array.isArray(data.engagements)||!Array.isArray(data.request_history)||
     data.engagements.length>3000||data.request_history.length>3000)throw Error('Malformed or oversized snapshot');
  const out=new Map();
  function put(row,kind,client,engagement,flags,action){
    if(!row || typeof row!=='object'||!SHA.test(row.identity_key)||!SHA.test(row.source_key)||
       out.has(row.identity_key)||typeof client!=='string'||typeof engagement!=='string'||
       !Array.isArray(flags)||flags.length>40||
       flags.some(f=>typeof f!=='string'||f.length>100)||typeof action!=='string')
      throw Error('Malformed or duplicate source identity');
    out.set(row.identity_key,{id:row.identity_key,key:row.source_key,kind,
      client:client.slice(0,150),engagement:engagement.slice(0,150),
      flags:flags.slice(),action:action.slice(0,700)});
    if(out.size>9000)throw Error('Too many review records');
  }
  for(const engagement of data.engagements){
    if(!engagement || typeof engagement.client!=='string'||
       typeof engagement.engagement!=='string'||
       !Array.isArray(engagement.grant_findings)||engagement.grant_findings.length>3000)
      throw Error('Malformed engagement');
    if(engagement.grant_findings.length){
      for(const grant of engagement.grant_findings)
        put(grant,'grant',engagement.client,engagement.engagement,grant.flags,grant.next_action);
    } else put(engagement,'no_grant',engagement.client,engagement.engagement,
      ['NO_GRANT_RECORD'],'Check source independently. No grant implied.');
  }
  for(const request of data.request_history)
    put(request,'assessment_request',request.client,'Assessment request lifecycle',request.flags,request.next_action);
  return out;
}
function compare(oldRecords,currentRecords){
  const changes=[],totals={new:0,changed:0,absent:0,unchanged:0};
  for(const [id,now] of currentRecords){
    const previous=oldRecords.get(id);
    const state=!previous?'new':previous.key!==now.key?'changed':'unchanged';
    totals[state]++;changes.push({state,now,before:previous||null});
  }
  for(const [id,before] of oldRecords){
    if(currentRecords.has(id))continue;
    totals.absent++;changes.push({state:'absent',now:null,before});
  }
  const order={changed:0,new:1,absent:2,unchanged:3};
  changes.sort((a,b)=>order[a.state]-order[b.state]||
    (a.now||a.before).id.localeCompare((b.now||b.before).id));
  return {changes,totals};
}
function delta(e){
  if(e.state!=='changed')return '';
  const after=e.now.flags,before=e.before.flags;
  const added=after.filter(f=>!before.includes(f));
  const removed=before.filter(f=>!after.includes(f));
  return (added.length?'New flags: '+added.join(', ')+'. ':'')+
    (removed.length?'No longer in latest: '+removed.join(', ')+
      ' (NOT verified resolved).':'');
}
function init(snapshot){
  if(!snapshot||snapshot.disposition!=='REVIEW_ONLY'||!SHA.test(snapshot.scope_fingerprint)||!Array.isArray(snapshot.request_history))return;
  const current=records(snapshot);
  let result=null;
  const notice=value=>{$('snapshotCompareFeedback').textContent=value;};
  const draw=()=>{
    const root=$('snapshotCompareRows');root.replaceChildren();
    if(!result)return;
    $('snapshotCompareTotals').textContent=
      result.totals.new+' new · '+result.totals.changed+' changed · '+
      result.totals.absent+' absent (not verified fixed) · '+result.totals.unchanged+' unchanged';
    const filter=$('snapshotCompareFilter').value;
    const selected=result.changes.filter(e=>filter==='all'||e.state===filter);
    for(const entry of selected.slice(0,700)){
      const c=entry.now||entry.before,card=document.createElement('article');
      card.className='changeCard';
      card.append(create('strong',entry.state.toUpperCase()+' · '+c.kind+' · '+c.client+' / '+c.engagement));
      card.append(create('p','Record token '+c.id.slice(0,12)+' · Latest/last-seen flags: '+c.flags.join(', ')));
      if(entry.state==='changed')card.append(create('p',delta(entry)));
      if(entry.state==='absent')
        card.append(create('p','ABSENT FROM LATEST SOURCE. Not evidence of remediation, authorization or revocation.'));
      else if(entry.state!=='unchanged')card.append(create('p',c.action));
      root.append(card);
    }
    if(selected.length>700)root.append(create('p','First 700 displayed; export all changes for follow-up.'));
    if(!selected.length)root.append(create('p','No matches.'));
  };
  $('snapshotCompareImport').addEventListener('change',async event=>{
    const file=event.target.files[0];
    try{
      if(!file||file.size>2000000)throw Error('Select a local previous JSON report no larger than 2 MiB');
      const previous=JSON.parse(await file.text());
      if(!previous||previous.format!=='lightup.authorization_readiness_operator_v1'||!Array.isArray(previous.request_history)||
         previous.disposition!=='REVIEW_ONLY'||previous.scope_fingerprint!==snapshot.scope_fingerprint||
         !previous.authority||Object.keys(previous.authority).sort().join(',')!==FALSE.slice().sort().join(',')||
         FALSE.some(k=>previous.authority[k]!==false))
        throw Error('Prior report is not same-selection REVIEW_ONLY with false authority flags');
      result=compare(records(previous),current);
      $('snapshotCompareFilter').value='all';
      draw();
      notice('Unsigned local comparison loaded. Missing or changed rows never establish a fix or permission.');
    }catch(error){
      result=null;$('snapshotCompareRows').replaceChildren();
      $('snapshotCompareTotals').textContent='No comparison available';
      notice('HOLD: '+(error instanceof Error?error.message:'Invalid report'));
    }finally{event.target.value='';}
  });
  $('snapshotCompareFilter').addEventListener('change',draw);
  $('snapshotCompareExport').addEventListener('click',()=>{
    if(!result){notice('Import one same-selection prior report JSON first.');return;}
    const safe=value=>String(value).replace(/[\r\n\u0000-\u001f]/g,' ').slice(0,550);
    const lines=['# LightUp offline authorization change review','',
      'REVIEW_ONLY / FALSE CLIENT CONSENT / FALSE GRANT / FALSE EXECUTION / FALSE RELEASE','',
      'New '+result.totals.new+'; changed '+result.totals.changed+
      '; absent NOT verified fixed '+result.totals.absent+'; unchanged '+result.totals.unchanged,
      '','Prior/current report are unsigned local copies. No source truth is proven.',''];
    for(const entry of result.changes){
      if(entry.state==='unchanged')continue;
      const c=entry.now||entry.before;
      lines.push('## '+entry.state.toUpperCase()+' '+safe(c.kind)+' '+c.id.slice(0,12));
      lines.push('Client: '+safe(c.client)+'; engagement: '+safe(c.engagement));
      lines.push('Review flags: '+safe(c.flags.join(', ')));
      if(entry.state==='changed')lines.push('Differences: '+safe(delta(entry)));
      lines.push('Action: '+(entry.state==='absent'?
        'Confirm independently; absence is NOT remediation evidence.':safe(c.action)),'');
    }
    const output=lines.join('\n'),blob=new Blob([output],{type:'text/markdown;charset=utf-8'});
    if(blob.size>700000){notice('HOLD: report exceeds 700 KiB');return;}
    const url=URL.createObjectURL(blob),a=document.createElement('a');
    a.href=url;a.download='lightup-authorization-change-review.md';
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
    notice('Private change report exported; browser download folder permissions apply.');
  });
  $('snapshotCompareTotals').textContent='Import an older same-client/engagement operator JSON report.';
}
global.LightUpSnapshotReview=Object.freeze({init});
})(window);
