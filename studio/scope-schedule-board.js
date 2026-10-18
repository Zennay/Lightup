/* LightUp standalone, wholly offline, non-authorizing schedule workshop.
   Never sends requests, reads credentials, persists browser state or activates targets. */
(function () {
'use strict';
const $ = id => document.getElementById(id);
const MAX_FILES = 20, MAX_FILE_BYTES = 65536, MAX_BATCH_BYTES = 1048576;
const DAY = 86400000, MINUTE = 60000, BUFFER = 30 * MINUTE;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/;
const LOCAL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
const EMPTY_FLAGS = ['authorization','client_consent','operator_consent','grant','execution','revocation_checked'];
const TOP_KEYS = new Set(['schema_version','kind','state','authorization','client_consent','operator_consent',
  'grant','execution','revocation_checked','proposal_name','client_label','requested_assets','excluded_assets',
  'requested_mode','requested_risk','notes','proposed_activities','proposed_window_local',
  'proposed_window_utc','exported_at_utc','scope_fingerprint_sha256']);
const WINDOW_KEYS = new Set(['status','timezone','start','end','start_offset_minutes','end_offset_minutes']);
const own = (o,k) => Object.prototype.hasOwnProperty.call(o,k);
const record = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const exactKeys = (v,allowed) => Object.keys(v).every(k => allowed.has(k));
const validString = (s,n) => typeof s === 'string' && s.length <= n;
const str = s => String(s == null ? '' : s);
const minutes = v => Number.isInteger(v) && v >= -840 && v <= 840;
let entries = [], blackouts = [], scenarioShifts = new Map(), laneAssignments = new Map(), pinnedKeys = new Set(), anchorUTC = 0, anchorChangedByUser = false;

function validLocal(value) {
  if (value === null) return true;
  if (!validString(value,16)) return false;
  const m = LOCAL.exec(value);
  if (!m) return false;
  const n = m.slice(1).map(Number);
  if (n[0]<2020 || n[0]>2100 || n[4]>59 || n[3]>23) return false;
  const dt = new Date(Date.UTC(n[0],n[1]-1,n[2],n[3],n[4]));
  return dt.getUTCFullYear()===n[0] && dt.getUTCMonth()+1===n[1] && dt.getUTCDate()===n[2] &&
    dt.getUTCHours()===n[3] && dt.getUTCMinutes()===n[4];
}
function localToUTC(wall, offset) {
  const p = LOCAL.exec(wall).slice(1).map(Number);
  return new Date(Date.UTC(p[0],p[1]-1,p[2],p[3],p[4])+offset*MINUTE).toISOString();
}
function isoMillis(value) {
  if (typeof value !== 'string' || !ISO.test(value)) return null;
  const d = new Date(value);
  return Number.isFinite(d.getTime()) && d.toISOString()===value && d.getUTCFullYear()>=2020 &&
    d.getUTCFullYear()<=2100 ? d.getTime() : null;
}
function validateWindow(local,utc) {
  if (!record(local) || !exactKeys(local,new Set(['start','end'])) ||
      !own(local,'start') || !own(local,'end') ||
      !validLocal(local.start) || !validLocal(local.end)) return null;
  if (utc === undefined) return {state:'missing',start:null,end:null};
  if (!record(utc) || !exactKeys(utc,WINDOW_KEYS) ||
      !validString(utc.timezone,100) || !utc.timezone) return null;
  if (utc.status==='resolved') {
    if (!Object.keys(utc).length || !minutes(utc.start_offset_minutes) || !minutes(utc.end_offset_minutes) ||
        typeof local.start!=='string' || typeof local.end!=='string') return null;
    const a=isoMillis(utc.start),b=isoMillis(utc.end);
    if(a===null||b===null||a>=b || localToUTC(local.start,utc.start_offset_minutes)!==utc.start ||
        localToUTC(local.end,utc.end_offset_minutes)!==utc.end)return null;
    return {state:'resolved',start:a,end:b};
  }
  if(utc.status==='unscheduled' || utc.status==='incomplete') {
    const bothEmpty=local.start===null && local.end===null;
    if((utc.status==='unscheduled')!==bothEmpty ||
        (utc.status==='incomplete' && (local.start===null)===(local.end===null)) ||
        utc.start!==null||utc.end!==null) return null;
    if(own(utc,'start_offset_minutes')||own(utc,'end_offset_minutes'))return null;
    return {state:utc.status,start:null,end:null};
  }
  if(['invalid','nonexistent_local_time','ambiguous_dst_hour','reverse_window'].includes(utc.status)) {
    if(utc.start!==null||utc.end!==null || own(utc,'start_offset_minutes')||own(utc,'end_offset_minutes')) return null;
    return {state:utc.status,start:null,end:null};
  }
  return null;
}
function parseDraft(d) {
  if(!record(d)||!exactKeys(d,TOP_KEYS) || d.schema_version!==1 ||
      d.kind!=='lightup.scope_proposal_draft'||d.state!=='DRAFT_ONLY'||
      !EMPTY_FLAGS.every(k=>own(d,k)&&d[k]===false)||
      !validString(d.proposal_name,120)||!d.proposal_name.trim()||
      !validString(d.client_label,100)||!validString(d.notes,3000)||
      !['authorized_assessment','analysis_only'].includes(d.requested_mode)||
      !Number.isInteger(d.requested_risk)||d.requested_risk<1||d.requested_risk>4||
      !Array.isArray(d.requested_assets)||!d.requested_assets.length||d.requested_assets.length>80||
      !Array.isArray(d.excluded_assets)||d.excluded_assets.length>80||
      !d.requested_assets.concat(d.excluded_assets).every(a=>validString(a,253)&&a.length>0)||
      !record(d.proposed_activities)|| !exactKeys(d.proposed_activities,new Set([
        'passive_analysis','configuration_review','private_lab_network_checks']))||
      !['passive_analysis','configuration_review','private_lab_network_checks'].every(k=>
        typeof d.proposed_activities[k]==='boolean')) return null;
  if(own(d,'scope_fingerprint_sha256') &&
      (typeof d.scope_fingerprint_sha256!=='string' ||
       !/^[a-f0-9]{64}$/.test(d.scope_fingerprint_sha256)))return null;
  if(own(d,'exported_at_utc') && !validString(d.exported_at_utc,50))return null;
  const interval=validateWindow(d.proposed_window_local,d.proposed_window_utc);
  if(!interval)return null;
  return {name:d.proposal_name,mode:d.requested_mode,risk:d.requested_risk,
    interval,local:d.proposed_window_local,utc:d.proposed_window_utc||null};
}
function append(parent,tag,value,klass) {
  const node=document.createElement(tag);
  node.textContent=value;
  if(klass)node.className=klass;
  parent.append(node);
  return node;
}
function formatUTC(n){return new Date(n).toISOString().replace('.000Z',' UTC').replace('T',' ');}
function fmtDate(n){return new Date(n).toISOString().slice(0,10);}
function shown(){
  return entries.filter(e=>e.interval.state==='resolved').map(e=>{
    const shift=scenarioShifts.get(e.key),lane=laneAssignments.get(e.key)||1;
    return shift===undefined ? {...e,lane,scenario:false,original:e.interval} :
      {...e,lane,interval:{state:'resolved',start:shift,end:shift+(e.interval.end-e.interval.start)},
        scenario:true,original:e.interval};
  });
}
function timeClashes(list) {
  const pairs=[],active=new Set();
  for(let i=0;i<list.length;i++)for(let j=i+1;j<list.length;j++){
    const a=list[i].interval,b=list[j].interval;
    if(a.start<b.end && b.start<a.end && (list[i].lane||1)===(list[j].lane||1)){
      pairs.push([i,j]);active.add(i);active.add(j);
    }
  }
  return {pairs,active};
}
// Turnaround is only a local team-planning preference, not a safety clearance.
function blockedFor(block, entry){
  // Missing lane in historical JSON means global, not 'lane 1'.
  return (block.lane??0)===0 || block.lane===entry.lane;
}
function turnaroundIssues(items, unavailable){
  const between=[],blocks=[];
  for(let i=0;i<items.length;i++){
    for(let j=i+1;j<items.length;j++){
      const a=items[i],b=items[j];
      if((a.lane||1)!==(b.lane||1))continue;
      const overlap=a.interval.start<b.interval.end && b.interval.start<a.interval.end;
      const tooClose=a.interval.start<b.interval.end+BUFFER &&
        b.interval.start<a.interval.end+BUFFER;
      if(tooClose&&!overlap)between.push([i,j]);
    }
    for(let j=0;j<unavailable.length;j++){
      const a=items[i].interval,b=unavailable[j];
      if(!blockedFor(b,items[i]))continue;
      const overlap=a.start<b.end&&b.start<a.end;
      const tooClose=a.start<b.end+BUFFER&&b.start<a.end+BUFFER;
      if(tooClose&&!overlap)blocks.push([i,j]);
    }
  }
  return {between,blocks,count:between.length+blocks.length};
}
function selectedCalendarEvents(){
  const lane=$('icsLane').value;
  const events=shown();
  return lane==='all'?events:events.filter(e=>e.lane===Number(lane));
}
function readyForTentativeCalendar(active){
  const policy=workPolicy();
  return policy.valid && active.length>0 &&
    !active.some(e=>!withinWorkHours(e.interval,policy)) &&
    timeClashes(active).pairs.length===0 &&
    turnaroundIssues(active,blackouts).count===0 &&
    !active.some(e=>blackouts.some(b=>blockedFor(b,e)&&e.interval.start<b.end&&b.start<e.interval.end));
}
function parseUTCWallTime(value){
  if(!validLocal(value) || typeof value!=='string')return null;
  const millis=Date.parse(value+':00.000Z');
  return Number.isFinite(millis) && new Date(millis).toISOString().slice(0,16)===value ? millis : null;
}
function renderBlocks(){
  const box=$('blocks');box.replaceChildren();
  if(!blackouts.length){append(box,'p','No unavailable periods added.','muted');return;}
  blackouts.forEach((b,i)=>{
    const row=document.createElement('div');row.className='item';box.append(row);
    append(row,'span','Unavailable #'+(i+1)+' ['+((b.lane??0)===0?'All lanes':'Lane '+b.lane)+']: '+formatUTC(b.start)+' → '+formatUTC(b.end)+' ');
    const remove=append(row,'button','Remove');
    remove.type='button';remove.addEventListener('click',()=>{blackouts.splice(i,1);render();});
  });
}

const WORK_DAYS = Object.freeze([0,1,2,3,4,5,6]);
function minutesFromClock(raw){
  if(typeof raw!=='string'||!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(raw))return null;
  return Number(raw.slice(0,2))*60+Number(raw.slice(3,5));
}
function workPolicy(){
  const enabled=$('hoursEnabled').checked;
  const rawStart=$('hoursStart').value,rawEnd=$('hoursEnd').value;
  const rawDays=Array.from($('hoursDays').querySelectorAll('input[data-day]'))
    .filter(input=>input.checked).map(input=>Number(input.dataset.day)).sort();
  // Disabled policy always serializes to valid neutral defaults: local edits while disabled
  // must not make a saved private scenario unrecoverable.
  const start=enabled?rawStart:'09:00',end=enabled?rawEnd:'17:00';
  const days=enabled?rawDays:[1,2,3,4,5];
  const begin=minutesFromClock(start),finish=minutesFromClock(end);
  const valid=!enabled||(begin!==null&&finish!==null&&finish>begin&&days.length>0);
  return {enabled,start_utc:start,end_utc:end,weekdays:days,valid,
    reason:valid?'':'Choose a later UTC end time and at least one weekday.'};
}
function withinWorkHours(interval,policy){
  if(!policy.enabled)return true;
  if(!policy.valid||!interval||interval.end<=interval.start)return false;
  const midnight=Math.floor(interval.start/DAY)*DAY;
  if(interval.end>midnight+DAY)return false;
  return policy.weekdays.includes(new Date(midnight).getUTCDay()) &&
    interval.start>=midnight+minutesFromClock(policy.start_utc)*MINUTE &&
    interval.end<=midnight+minutesFromClock(policy.end_utc)*MINUTE;
}
function nextWorkStart(candidate,duration,policy){
  if(!policy.enabled)return candidate;
  if(!policy.valid||duration<=0||duration>(minutesFromClock(policy.end_utc)-
      minutesFromClock(policy.start_utc))*MINUTE)return null;
  const begin=minutesFromClock(policy.start_utc)*MINUTE;
  const finish=minutesFromClock(policy.end_utc)*MINUTE;
  for(let day=0;day<=33;day++){
    const midnight=(Math.floor(candidate/DAY)+day)*DAY;
    if(!policy.weekdays.includes(new Date(midnight).getUTCDay()))continue;
    const possible=Math.max(candidate,midnight+begin);
    if(possible+duration<=midnight+finish)return possible;
  }
  return null;
}
function activeWorkNote(policy){
  const node=$('hoursStatus');node.className=policy.valid?'muted':'hours-alert';
  node.textContent=!policy.enabled?'Work-hour limits disabled. All UTC days and hours remain planning candidates.':
    policy.valid ? 'Local preference active: '+policy.weekdays.map(day=>['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][day]).join(', ')+
      ' · '+policy.start_utc+'–'+policy.end_utc+' UTC. No grant or real staffing verified.':
      'HOLD: '+policy.reason+' The optimizer and source-bound exports are unavailable until corrected.';
}

function suggest(entry,list){
  const forbidden=list.filter(item=>item!==entry&&item.lane===entry.lane).map(item=>item.interval).concat(blackouts.filter(b=>blockedFor(b,entry)));
  return firstFit(entry.interval,forbidden,workPolicy());
}
function createAxis(days) {
  const head=$('axis');head.replaceChildren();
  append(head,'strong','Draft / risk');
  const axis=document.createElement('div');axis.className='days';axis.style.setProperty('--days',days);
  for(let i=0;i<days;i++)append(axis,'span',new Date(anchorUTC+i*DAY).toISOString().slice(5,10));
  head.append(axis);
}
function renderInventory(){
  const list=$('proposalInventory');list.replaceChildren();
  if(!entries.length){append(list,'p','No proposals imported. Select Studio v1 files above.','muted');return;}
  entries.forEach((entry,index)=>{
    const box=document.createElement('article');box.className='item';list.append(box);
    append(box,'strong','#'+(index+1)+' · '+entry.name);
    append(box,'small','Risk '+entry.risk+' · '+entry.mode+' · '+
      (entry.interval.state==='resolved'?'UTC interval resolved': 'HOLD: '+entry.interval.state));
    if(entry.sourceHash)append(box,'small',' · Source SHA-256 '+entry.sourceHash.slice(0,12)+'…');
    const controls=document.createElement('div');controls.className='row';box.append(controls);
    const laneSelect=document.createElement('select');laneSelect.setAttribute('aria-label','Local planning lane for draft #'+(index+1));
    for(let lane=1;lane<=4;lane++){
      const opt=append(laneSelect,'option','Planning lane '+lane);opt.value=String(lane);
    }
    laneSelect.value=String(laneAssignments.get(entry.key)||1);
    laneSelect.addEventListener('change',()=>{
      laneAssignments.set(entry.key,Number(laneSelect.value));
      $('status').textContent='Local resource lane changed. Only draft time conflicts within a lane are compared; this does not verify team availability.';
      render();
    });
    controls.append(laneSelect);
    if(entry.interval.state==='resolved'){
      const pinLabel=document.createElement('label');
      pinLabel.style.display='inline-flex';pinLabel.style.gap='8px';pinLabel.style.alignItems='center';
      const pin=document.createElement('input');pin.type='checkbox';pin.checked=pinnedKeys.has(entry.key);
      pin.style.width='auto';pin.setAttribute('aria-label','Keep current proposed time for draft #'+(index+1));
      pin.addEventListener('change',()=>{
        if(pin.checked)pinnedKeys.add(entry.key);else pinnedKeys.delete(entry.key);
        $('status').textContent=pin.checked?'Local planning time pinned for batch arrangement. This does not book any resource.':
          'Local planning time unpinned; batch arrangement may move it.';
        render();
      });
      pinLabel.append(pin,document.createTextNode('Pin proposed time in batch rearrangement'));
      controls.append(pinLabel);
      const focus=append(controls,'button','Focus UTC timeline');
      focus.type='button';focus.addEventListener('click',()=>{
        $('anchor').value=fmtDate(entry.interval.start);
        anchorChangedByUser=true;setAnchor();
        $('axis').scrollIntoView({behavior:'smooth',block:'nearest'});
      });
    }
    const remove=append(controls,'button','Remove this source draft');
    remove.type='button';
    remove.addEventListener('click',()=>{
      if(!window.confirm('Remove this imported proposal from the local board? Its original file will stay unchanged. Previously exported scenario ordinals may no longer match.'))return;
      const removed=entries.splice(index,1)[0];
      scenarioShifts.delete(removed.key);laneAssignments.delete(removed.key);pinnedKeys.delete(removed.key);
      $('status').textContent='One local proposal removed. Source file untouched. Re-export the private scenario if needed.';
      render();
    });
  });
}
function render(){
  const timed=shown(),unsafe=entries.filter(e=>e.interval.state!=='resolved');
  const {pairs,active}=timeClashes(timed);
  const policy=workPolicy();
  activeWorkNote(policy);
  const invalidHours=timed.filter(e=>!withinWorkHours(e.interval,policy));
  const spacing=turnaroundIssues(timed,blackouts);
  const blockHits=[];
  timed.forEach((e,i)=>blackouts.forEach((b,j)=>{
    if(blockedFor(b,e)&&e.interval.start<b.end && b.start<e.interval.end){blockHits.push([i,j]);active.add(i);}
  }));
  for(const e of invalidHours){const i=timed.findIndex(item=>item.key===e.key);if(i>=0)active.add(i);}
  $('hoursClashes').textContent=invalidHours.length;
  $('bufferIssues').textContent=spacing.count;
  for(const [i,j] of spacing.between){active.add(i);active.add(j);}
  for(const [i] of spacing.blocks)active.add(i);
  $('blocked').textContent=blackouts.length;
  $('changed').textContent=scenarioShifts.size;
  $('pinned').textContent=pinnedKeys.size;
  renderBlocks();
  renderInventory();
  $('total').textContent=entries.length;$('timed').textContent=timed.length;
  $('unscheduled').textContent=unsafe.length;$('clashes').textContent=pairs.length+blockHits.length;
  const original=entries.filter(e=>e.interval.state==='resolved').map(e=>({...e,lane:laneAssignments.get(e.key)||1}));
  const baseline=timeClashes(original).pairs.length+
    original.reduce((total,e)=>total+blackouts.filter(b=>blockedFor(b,e)&&e.interval.start<b.end&&b.start<e.interval.end).length,0)+
    original.filter(e=>!withinWorkHours(e.interval,policy)).length;
  const current=pairs.length+blockHits.length+invalidHours.length;
  $('baselineClashes').textContent=baseline;
  $('clashReduction').textContent=String(baseline-current);
  $('ics').disabled=!readyForTentativeCalendar(selectedCalendarEvents());
  $('print').disabled=!entries.length;
  const days=Number($('horizon').value),lo=anchorUTC,hi=anchorUTC+days*DAY;
  createAxis(days);
  const lanes=$('lanes');lanes.replaceChildren();
  const ordered=timed.map((entry,i)=>({entry,i})).sort((a,b)=>a.entry.interval.start-b.entry.interval.start);
  if(!ordered.length)append(lanes,'p','No validated UTC windows to place on the calendar.','muted');
  for(const {entry:e,i} of ordered){
    const row=document.createElement('div');row.className='lane';lanes.append(row);
    const label=document.createElement('div');label.className='label';row.append(label);
    append(label,'strong','Lane '+e.lane+' · '+e.name+(e.scenario?' · WHAT-IF':' '));
    append(label,'span','Risk '+e.risk+' · '+e.mode+(e.scenario?' · SHIFTED':''),'pill');
    const track=document.createElement('div');track.className='track';track.style.setProperty('--days',days);row.append(track);
    const start=Math.max(e.interval.start,lo),end=Math.min(e.interval.end,hi);
    if(start<end){
      const bar=document.createElement('div');
      bar.className='bar'+(e.risk===4?' high':'')+(e.scenario?' scenario':'')+(active.has(i)?' conflict':'');
      bar.style.left=100*(start-lo)/(days*DAY)+'%';
      bar.style.width=100*(end-start)/(days*DAY)+'%';
      bar.title=formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end)+'; DRAFT ONLY';
      track.append(bar);
    } else append(track,'span','Outside visible horizon','muted');
    append(label,'small',formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end));
    if(e.scenario)append(label,'small','Original: '+formatUTC(e.original.start));
  }
  blackouts.forEach((b,j)=>{
    const row=document.createElement('div');row.className='lane';lanes.append(row);
    const label=document.createElement('div');label.className='label';row.append(label);
    append(label,'strong','Unavailable #'+(j+1)+' · '+((b.lane??0)===0?'ALL':'Lane '+b.lane));append(label,'small',formatUTC(b.start)+' → '+formatUTC(b.end));
    const track=document.createElement('div');track.className='track';track.style.setProperty('--days',days);row.append(track);
    const start=Math.max(b.start,lo),end=Math.min(b.end,hi);
    if(start<end){
      const bar=document.createElement('div');bar.className='bar blocked';
      bar.style.left=100*(start-lo)/(days*DAY)+'%';
      bar.style.width=100*(end-start)/(days*DAY)+'%';
      bar.title='Locally unavailable only, not a verified resource booking';
      track.append(bar);
    } else append(track,'span','Outside visible horizon','muted');
  });
  const conflict=$('conflicts');conflict.replaceChildren();
  if(invalidHours.length){
    const box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong',invalidHours.length+' draft(s) violate current UTC working-day preference');
    append(box,'p','HOLD for calendar export until every current scenario window fits fully within allowed weekdays and hours. Adjust scenario or disable this optional local policy.');
    for(const e of invalidHours.slice(0,20))append(box,'div',e.name+' · '+formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end));
  }
  if(!pairs.length && !blockHits.length && !invalidHours.length && !spacing.count)
    append(conflict,'p','No local time collisions or turnaround issues detected. Actual availability and approval remain unverified.','muted');
  for(const [i,j] of pairs){
    const a=timed[i],b=timed[j],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong','Lane '+a.lane+': '+a.name+' ↔ '+b.name);
    append(box,'div','Overlap: '+formatUTC(Math.max(a.interval.start,b.interval.start))+' – '+formatUTC(Math.min(a.interval.end,b.interval.end)));
  }
  for(const [i,j] of blockHits){
    const e=timed[i],b=blackouts[j],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong',e.name+' ↔ Unavailable #'+(j+1)+' ('+((b.lane??0)===0?'all lanes':'lane '+b.lane)+')');
    append(box,'div','Local planning conflict: '+formatUTC(Math.max(e.interval.start,b.start))+' – '+formatUTC(Math.min(e.interval.end,b.end)));
  }
  for(const [i,j] of spacing.between){
    const a=timed[i],b=timed[j],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong','Insufficient 30-minute turnaround · lane '+a.lane);
    append(box,'div',a.name+' ↔ '+b.name+' · reschedule to add a 30-minute gap.');
  }
  for(const [i,j] of spacing.blocks){
    const e=timed[i],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong','Insufficient 30-minute gap to unavailable period #'+(j+1));
    append(box,'div',e.name+' · reschedule around local unavailability.');
  }
  const attention=$('attention');attention.replaceChildren();
  if(!entries.length)append(attention,'p','No imported proposals.');
  for(const e of unsafe){
    const box=document.createElement('div');box.className='item danger';attention.append(box);
    append(box,'strong',e.name);
    append(box,'div','HOLD: '+e.interval.state+'. Supply an unambiguous, source-consistent UTC start and end in the original Studio draft.');
  }
  for(const e of timed.filter(e=>e.risk===4)){
    const box=document.createElement('div');box.className='item';attention.append(box);
    append(box,'strong',e.name);
    append(box,'div','Risk 4 requires separate, independently reviewed risk approval.');
  }
  if(entries.length && !unsafe.length && !timed.some(e=>e.risk===4)){
    append(attention,'p','Time fields are internally consistent. All identities, consent, grants, and real-world resource availability still require independent review.');
  }
  const alt=$('alternatives');alt.replaceChildren();
  if(!timed.length)append(alt,'p','No valid UTC window available.');
  for(const e of timed){
    const proposed=suggest(e,timed),box=document.createElement('div');box.className='item';alt.append(box);
    append(box,'strong',e.name);
    const same=proposed&&proposed.start===e.interval.start;
    append(box,'p',!proposed?'No alternative within supported calendar range.':
      (same?'Original time has a 30-minute buffer from other proposed windows: ':'First candidate with 30-minute gap to other drafts: ')+
      formatUTC(proposed.start)+' → '+formatUTC(proposed.end));
    append(box,'small','Suggestion only; never modifies source request or authenticates resource ownership.');
    if(proposed && proposed.start!==e.interval.start &&
      Math.abs(proposed.start-e.original.start)<=31*DAY &&
      withinWorkHours(proposed,workPolicy())){
      const button=append(box,'button','Apply local what-if time for this proposal');
      button.type='button';
      button.addEventListener('click',()=>{
        const index=entries.findIndex(original=>original.key===e.key);
        if(index<0)return;
        $('scenarioSelect').value=String(index);
        $('scenarioStart').value=new Date(proposed.start).toISOString().slice(0,16);
        applyScenario(proposed.start);
      });
    }
  }
  renderScenarios();
}
function setAnchor(){
  const v=$('anchor').value;
  const m=/^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if(!m){$('status').textContent='Choose a valid UTC start day.';return false;}
  const n=Date.UTC(Number(m[1]),Number(m[2])-1,Number(m[3]));
  if(!Number.isFinite(n)||fmtDate(n)!==v){$('status').textContent='Invalid UTC day.';return false;}
  anchorUTC=n;render();return true;
}
$('anchor').value=new Date().toISOString().slice(0,10);
setAnchor();
$('anchor').addEventListener('change',()=>{anchorChangedByUser=true;setAnchor();});
$('horizon').addEventListener('change',render);
$('icsLane').addEventListener('change',render);
for(const id of ['hoursEnabled','hoursStart','hoursEnd'])$(id).addEventListener('change',render);
$('hoursDays').addEventListener('change',render);
function chosenScenario(){
  const index=Number($('scenarioSelect').value);
  return $('scenarioSelect').value!=='' && Number.isSafeInteger(index) && index>=0 &&
      index<entries.length && entries[index].interval.state==='resolved' ? entries[index] : null;
}
function renderScenarios(){
  const select=$('scenarioSelect'),old=select.value;
  select.replaceChildren();
  append(select,'option','Select a resolved draft').value='';
  entries.forEach((e,i)=>{
    if(e.interval.state!=='resolved')return;
    const option=append(select,'option',e.name+' · #'+(i+1)+(scenarioShifts.has(e.key)?' (shifted)':''));
    option.value=String(i);
  });
  select.value=Array.from(select.options).some(o=>o.value===old) ? old : '';
  const chosen=chosenScenario();
  const policy=workPolicy();
  $('scenarioApply').disabled=!chosen||!policy.valid;
  $('scenarioSuggest').disabled=!chosen||!policy.valid;
  $('scenarioRevert').disabled=!chosen||!scenarioShifts.has(chosen.key);
  $('scenarioClear').disabled=!scenarioShifts.size;
  $('scenarioArrange').disabled=!shown().length||!policy.valid;
  $('scenarioExport').disabled=!entries.length || !policy.valid || entries.some(e=>!e.sourceHash);
  $('briefExport').disabled=$('scenarioExport').disabled;
  const changes=$('scenarioChanges');changes.replaceChildren();
  if(!scenarioShifts.size)append(changes,'p','No time adjustments proposed.','muted');
  entries.forEach((e,i)=>{
    const shifted=scenarioShifts.get(e.key);
    if(shifted===undefined)return;
    const box=document.createElement('div');box.className='item';changes.append(box);
    append(box,'strong','Lane '+(laneAssignments.get(e.key)||1)+' · '+e.name+' · #'+(i+1));
    const duration=e.interval.end-e.interval.start;
    append(box,'div','Original: '+formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end));
    append(box,'div','What-if: '+formatUTC(shifted)+' → '+formatUTC(shifted+duration));
  });
  $('scenarioPreview').textContent=JSON.stringify(scenarioPacket(),null,2);
}
function scenarioPacket(){
  const current=shown();
  const {pairs}=timeClashes(current);
  const blockHits=current.reduce((n,e)=>n+blackouts.filter(b=>blockedFor(b,e)&&e.interval.start<b.end&&b.start<e.interval.end).length,0);
  const policy=workPolicy();
  return {
    kind:'lightup.scope_schedule_scenario',schema_version:1,
    disposition:'LOCAL_REVIEW_ONLY',source:'UNTRUSTED_USER_DRAFTS',
    authenticated:false,authorization:false,client_consent:false,
    operator_consent:false,grant:false,risk_approved:false,
    scan:false,execution:false,release:false,
    note:'Ordinal labels reference only this tab session. Exact source Studio proposals remain unchanged. No actual reservation or permission.',
    proposals:entries.map((e,i)=>{
      const proposed=scenarioShifts.get(e.key);
      const valid=e.interval.state==='resolved';
      const duration=valid ? e.interval.end-e.interval.start:0;
      return {local_ordinal:i+1,review_lane:laneAssignments.get(e.key)||1,pinned_time:pinnedKeys.has(e.key),source_file_sha256:e.sourceHash,requested_mode:e.mode,requested_risk:e.risk,state:valid?'DRAFT_PLANNED':'HOLD_MISSING_UTC',
        original_start_utc:valid?new Date(e.interval.start).toISOString():null,
        original_end_utc:valid?new Date(e.interval.end).toISOString():null,
        scenario_start_utc:valid?new Date(proposed===undefined?e.interval.start:proposed).toISOString():null,
        scenario_end_utc:valid?new Date((proposed===undefined?e.interval.start:proposed)+duration).toISOString():null,
        shifted:proposed!==undefined};
    }),
    unavailable_utc:blackouts.map(b=>({start:new Date(b.start).toISOString(),end:new Date(b.end).toISOString(),lane:b.lane??0})),
    workday_utc:{enabled:policy.enabled,start:policy.start_utc,end:policy.end_utc,weekdays:policy.weekdays},
    proposed_time_overlap_pairs:pairs.length,proposed_unavailability_overlap_pairs:blockHits,
    proposed_buffer_violation_count:turnaroundIssues(current,blackouts).count,
    proposed_outside_workday_count:current.filter(e=>!withinWorkHours(e.interval,policy)).length
  };
}
function firstFit(base,forbidden,policy){
  const duration=base.end-base.start,limit=Date.UTC(2100,0,1);
  if(!policy.valid||duration<=0)return null;
  let candidate=base.start;
  const busy=forbidden.slice().sort((a,b)=>a.start-b.start);
  for(let iteration=0;iteration<2048;iteration++){
    candidate=nextWorkStart(candidate,duration,policy);
    if(candidate===null||candidate+duration>limit||candidate-base.start>31*DAY)return null;
    const conflict=busy.find(item=>candidate<item.end+BUFFER &&
      candidate+duration+BUFFER>item.start);
    if(!conflict)return {start:candidate,end:candidate+duration};
    candidate=Math.max(candidate+MINUTE,conflict.end+BUFFER);
  }
  return null;
}
function arrangeAll(){
  const current=shown().sort((a,b)=>a.interval.start-b.interval.start||b.risk-a.risk||
    a.name.localeCompare(b.name));
  if(!current.length)return;
  const policy=workPolicy();
  if(!policy.valid){$('status').textContent='HOLD: correct UTC workday boundaries first.';return;}
  const perLane=new Map([1,2,3,4].map(lane=>[lane,blackouts.filter(b=>(b.lane??0)===0||b.lane===lane).map(b=>({start:b.start,end:b.end}))]));
  const proposals=new Map();
  // Before moving a single unpinned proposal, reserve all local pinned times.
  // If a pin clashes with another pin, work hours or global unavailability, HOLD atomically.
  for(const e of current.filter(entry=>pinnedKeys.has(entry.key))){
    const busy=perLane.get(e.lane);
    if(!withinWorkHours(e.interval,policy)||
        busy.some(b=>e.interval.start<b.end+BUFFER&&b.start<e.interval.end+BUFFER)){
      $('status').textContent='HOLD: pinned proposed times conflict with each other, unavailable blocks or UTC workday settings. Unpin/reschedule first. No changes applied.';
      return;
    }
    busy.push({start:e.interval.start,end:e.interval.end});
    proposals.set(e.key,e.interval.start);
  }
  for(const e of current.filter(entry=>!pinnedKeys.has(entry.key))){
    const busy=perLane.get(e.lane);
    const slot=firstFit(e.interval,busy,policy);
    if(!slot || Math.abs(slot.start-e.original.start)>31*DAY){
      $('status').textContent='HOLD: could not schedule all proposals within 31 days of their ORIGINAL UTC windows. No changes applied.';
      return;
    }
    busy.push(slot);
    proposals.set(e.key,slot.start);
  }
  const next=new Map(scenarioShifts);
  for(const e of current){
    if(proposals.get(e.key)===e.original.start)next.delete(e.key);
    else next.set(e.key,proposals.get(e.key));
  }
  scenarioShifts=next;
  $('status').textContent='A bounded first-fit what-if arrangement was built locally. Recheck all source identities and approvals.';
  render();
}
$('scenarioArrange').addEventListener('click',arrangeAll);
function decodeScenario(snapshot){
  const rootKeys=new Set(['kind','schema_version','disposition','source','authenticated',
    'authorization','client_consent','operator_consent','grant','risk_approved','scan',
    'execution','release','note','proposals','unavailable_utc','workday_utc',
    'proposed_time_overlap_pairs','proposed_unavailability_overlap_pairs','proposed_outside_workday_count',
    'proposed_buffer_violation_count']);
  const rowKeys=new Set(['local_ordinal','review_lane','pinned_time','source_file_sha256','requested_mode','requested_risk','state','original_start_utc',
    'original_end_utc','scenario_start_utc','scenario_end_utc','shifted']);
  const blockKeys=new Set(['start','end','lane']);
  if(!record(snapshot)||!exactKeys(snapshot,rootKeys) ||
     snapshot.kind!=='lightup.scope_schedule_scenario'||snapshot.schema_version!==1 ||
     snapshot.disposition!=='LOCAL_REVIEW_ONLY'||snapshot.source!=='UNTRUSTED_USER_DRAFTS' ||
     !['authenticated','authorization','client_consent','operator_consent','grant',
       'risk_approved','scan','execution','release'].every(k=>own(snapshot,k)&&snapshot[k]===false) ||
     !validString(snapshot.note,500)||
     !Array.isArray(snapshot.proposals)||snapshot.proposals.length!==entries.length ||
     !Array.isArray(snapshot.unavailable_utc)||snapshot.unavailable_utc.length>30 ||
     !Number.isSafeInteger(snapshot.proposed_time_overlap_pairs)||
     snapshot.proposed_time_overlap_pairs<0||
     !Number.isSafeInteger(snapshot.proposed_unavailability_overlap_pairs)||
     snapshot.proposed_unavailability_overlap_pairs<0)throw Error('invalid envelope');
  let policy={enabled:false,start:'09:00',end:'17:00',weekdays:[1,2,3,4,5]};
  if(own(snapshot,'workday_utc')){
    const p=snapshot.workday_utc;
    if(!record(p)||!exactKeys(p,new Set(['enabled','start','end','weekdays']))||
      typeof p.enabled!=='boolean'||minutesFromClock(p.start)===null||
      minutesFromClock(p.end)===null||!Array.isArray(p.weekdays)||
      p.weekdays.length>7||!p.weekdays.every((day,i)=>Number.isInteger(day)&&day>=0&&day<=6&&
        (i===0||day>p.weekdays[i-1]))||
      (p.enabled&&(p.weekdays.length===0||minutesFromClock(p.end)<=minutesFromClock(p.start))))
      throw Error('invalid UTC workday settings');
    policy={enabled:p.enabled,start:p.start,end:p.end,weekdays:p.weekdays};
  }
  if(own(snapshot,'proposed_outside_workday_count') &&
     (!Number.isInteger(snapshot.proposed_outside_workday_count) ||
      snapshot.proposed_outside_workday_count<0 ||
      snapshot.proposed_outside_workday_count>entries.length))throw Error('invalid workday count');
  const effectivePolicy={enabled:policy.enabled,valid:true,start_utc:policy.start,
    end_utc:policy.end,weekdays:policy.weekdays};
  const shifts=new Map(),assignedLanes=new Map(),restoredPins=new Set(),busy=[],resolvedIntervals=[];
  for(let i=0;i<entries.length;i++){
    const source=entries[i],row=snapshot.proposals[i],resolved=source.interval.state==='resolved';
    if(!record(row)||!exactKeys(row,rowKeys)||row.local_ordinal!==i+1||
       (own(row,'review_lane')&&(!Number.isInteger(row.review_lane)||row.review_lane<1||row.review_lane>4))||
       (own(row,'pinned_time')&&typeof row.pinned_time!=='boolean')||
       row.requested_mode!==source.mode||row.requested_risk!==source.risk||
       typeof row.source_file_sha256!=='string' ||
       !/^[a-f0-9]{64}$/.test(row.source_file_sha256) ||
       row.source_file_sha256!==source.sourceHash||
       row.state!==(resolved?'DRAFT_PLANNED':'HOLD_MISSING_UTC')||
       typeof row.shifted!=='boolean')throw Error('mismatched source');
    if(!resolved){
      if(row.original_start_utc!==null||row.original_end_utc!==null||
         row.scenario_start_utc!==null||row.scenario_end_utc!==null||row.shifted||
         row.pinned_time===true)throw Error('invalid hold');
      assignedLanes.set(source.key,own(row,'review_lane')?row.review_lane:1);
      continue;
    }
    if(row.original_start_utc!==new Date(source.interval.start).toISOString() ||
       row.original_end_utc!==new Date(source.interval.end).toISOString())throw Error('stale source');
    const a=isoMillis(row.scenario_start_utc),b=isoMillis(row.scenario_end_utc);
    if(a===null||b===null||a>=b||
       b-a!==source.interval.end-source.interval.start ||
       Math.abs(a-source.interval.start)>31*DAY ||
       row.shifted!==(a!==source.interval.start))throw Error('invalid proposed window');
    if(row.shifted)shifts.set(source.key,a);
    if(row.pinned_time===true)restoredPins.add(source.key);
    assignedLanes.set(source.key,own(row,'review_lane')?row.review_lane:1);
    resolvedIntervals.push({start:a,end:b});
  }
  if(own(snapshot,'proposed_outside_workday_count') &&
     snapshot.proposed_outside_workday_count!==resolvedIntervals.filter(t=>
       !withinWorkHours(t,effectivePolicy)).length)throw Error('inconsistent workday count');
  for(const block of snapshot.unavailable_utc){
    if(!record(block)||!exactKeys(block,blockKeys))throw Error('invalid block');
    const start=isoMillis(block.start),end=isoMillis(block.end);
    const lane=own(block,'lane')?block.lane:0;
    if(start===null||end===null||end<=start||end-start>31*DAY ||
       !Number.isInteger(lane)||lane<0||lane>4 ||
       busy.some(b=>b.start===start&&b.end===end&&b.lane===lane))
      throw Error('invalid unavailable window');
    busy.push({start,end,lane});
  }
  const restored=entries.filter(e=>e.interval.state==='resolved').map(e=>{
    const start=shifts.get(e.key)??e.interval.start;
    return {lane:assignedLanes.get(e.key)||1,
      interval:{start,end:start+(e.interval.end-e.interval.start)}};
  });
  if((own(snapshot,'proposed_buffer_violation_count')&&
       (!Number.isInteger(snapshot.proposed_buffer_violation_count) ||
        snapshot.proposed_buffer_violation_count!==turnaroundIssues(restored,busy).count))||
     timeClashes(restored).pairs.length!==snapshot.proposed_time_overlap_pairs||
     restored.reduce((count,e)=>count+busy.filter(b=>
       blockedFor(b,e)&&e.interval.start<b.end && b.start<e.interval.end).length,0)!==
       snapshot.proposed_unavailability_overlap_pairs)
    throw Error('inconsistent overlap claims');
  return {shifts,busy,policy,assignedLanes,restoredPins};
}
$('scenarioImport').addEventListener('change',async ev=>{
  const file=ev.target.files&&ev.target.files[0];ev.target.value='';
  if(!file)return;
  try{
    if(!entries.length||file.size<2||file.size>65536)throw Error('size/missing source');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
    const candidate=JSON.parse(text),next=decodeScenario(candidate);
    // The entire replacement is committed at once: no partial restoration on invalid input.
    scenarioShifts=next.shifts;laneAssignments=next.assignedLanes;pinnedKeys=next.restoredPins;blackouts=next.busy;
    $('hoursEnabled').checked=next.policy.enabled;
    $('hoursStart').value=next.policy.start;
    $('hoursEnd').value=next.policy.end;
    $('hoursDays').querySelectorAll('input[data-day]').forEach(input=>{
      input.checked=next.policy.weekdays.includes(Number(input.dataset.day));
    });
    $('status').textContent='Restored untrusted local planning scenario against source UTC windows and risk/mode. Never a grant or booking.';
    render();
  }catch(_){
    $('status').textContent='HOLD: scenario import rejected. Load matching original drafts in the same order and provide valid bounded UTC evidence.';
  }
});
function applyScenario(start){
  const selected=chosenScenario();
  if(!selected){$('status').textContent='Select a resolved original proposal first.';return;}
  const duration=selected.interval.end-selected.interval.start;
  const upper=Date.UTC(2100,0,1);
  if(start===null||start< Date.UTC(2020,0,1)||start+duration>upper||Math.abs(start-selected.interval.start)>31*DAY){
    $('status').textContent='Choose a valid UTC start within 31 days of the original proposal and preserve its duration.';return;
  }
  const policy=workPolicy();
  if(!policy.valid||!withinWorkHours({start,end:start+duration},policy)){
    $('status').textContent='HOLD: proposed window falls outside selected UTC weekdays/hours. Adjust working hours or choose a permitted time.';
    return;
  }
  if(start===selected.interval.start)scenarioShifts.delete(selected.key);
  else scenarioShifts.set(selected.key,start);
  $('status').textContent='Local what-if scenario updated; original Studio proposal unchanged. Review all collisions.';
  render();
}
$('scenarioSelect').addEventListener('change',()=>{
  const e=chosenScenario();
  $('scenarioStart').value=e?new Date(scenarioShifts.get(e.key)??e.interval.start).toISOString().slice(0,16):'';
  renderScenarios();
});
$('scenarioApply').addEventListener('click',()=>applyScenario(parseUTCWallTime($('scenarioStart').value)));
$('scenarioSuggest').addEventListener('click',()=>{
  const selected=chosenScenario(),current=shown();
  if(!selected)return;
  const e=current.find(item=>item.key===selected.key);
  if(!e)return;
  const candidate=suggest(e,current);
  if(!candidate){$('status').textContent='No supported alternative slot found.';return;}
  $('scenarioStart').value=new Date(candidate.start).toISOString().slice(0,16);
  applyScenario(candidate.start);
});
$('scenarioRevert').addEventListener('click',()=>{
  const selected=chosenScenario();if(!selected)return;
  scenarioShifts.delete(selected.key);
  $('scenarioStart').value=new Date(selected.interval.start).toISOString().slice(0,16);
  render();
});
$('scenarioClear').addEventListener('click',()=>{
  scenarioShifts.clear();$('scenarioStart').value='';
  $('status').textContent='All what-if shifts reverted. Original Studio drafts were always unchanged.';
  render();
});

function escapeReviewHtml(value) {
  return String(value===null?'—':value).replace(/[&<>"']/g,character=>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
}
function renderPrivateReviewBrief(packet) {
  const p=packet.workday_utc;
  const esc=escapeReviewHtml;
  const header=['#','Review lane','Pinned (local only)','Source file SHA-256 (unsigned)','Risk / mode','Original UTC','Proposed UTC','Shifted'];
  const rows=packet.proposals.map(row=>[
    row.local_ordinal,row.review_lane,row.pinned_time?'Yes':'No',row.source_file_sha256,
    'Risk '+row.requested_risk+' / '+row.requested_mode,
    row.original_start_utc===null?'No resolved UTC window':
      row.original_start_utc+' to '+row.original_end_utc,
    row.scenario_start_utc===null?'HOLD: no resolved UTC window':
      row.scenario_start_utc+' to '+row.scenario_end_utc,
    row.shifted?'Yes — new proposed time':'No'
  ]);
  const table=items=>items.map(list=>'<tr>'+list.map(value=>'<td>'+esc(value)+'</td>').join('')+'</tr>').join('');
  const busy=packet.unavailable_utc.length ?
    '<table><thead><tr><th>For</th><th>Unavailable from (UTC)</th><th>Until (UTC)</th></tr></thead><tbody>'+
      table(packet.unavailable_utc.map(b=>[(b.lane??0)===0?'All lanes':'Lane '+b.lane,b.start,b.end]))+'</tbody></table>':
    '<p>No locally unavailable windows.</p>';
  const names=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const weekdays=p.enabled?p.weekdays.map(day=>names[day]).join(', '):'Unrestricted';
  const total=packet.proposed_time_overlap_pairs+
    packet.proposed_unavailability_overlap_pairs+packet.proposed_outside_workday_count+
    packet.proposed_buffer_violation_count;
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
    '<meta name="viewport" content="width=device-width,initial-scale=1">'+
    '<meta name="referrer" content="no-referrer">'+
    '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'+
    '<title>LightUp · Private schedule review</title><style>'+
    'body{font:15px/1.55 system-ui,sans-serif;max-width:1080px;margin:30px auto;padding:0 22px;background:#f5f7fa;color:#152138}'+
    'h1{margin-bottom:0}.banner{padding:18px;background:#fff0d7;border:2px solid #9d7246;margin:20px 0;border-radius:8px}'+
    'table{width:100%;border-collapse:collapse;background:white;table-layout:fixed}td,th{padding:10px;border:1px solid #b9c5cf;word-wrap:break-word;text-align:left;vertical-align:top}'+
    'th{background:#dbe6ee}code{overflow-wrap:anywhere}section{margin:24px 0}small{color:#44546a}'+
    '@media print{body{background:white;margin:0}.banner{border:2px solid black}th{background:#eee}}'+
    '</style></head><body><h1>LightUp · Private schedule review</h1>'+
    '<p>Anonymous operator planning handoff · LOCAL_REVIEW_ONLY · Untrusted user-supplied proposal data.</p>'+
    '<div class="banner"><strong>NOT AUTHORIZATION / NOT A BOOKING.</strong> No verified target ownership, consent, scope approval, grant, scan, execution, or release. This offline document is unsigned and can be stale. Work must not begin from these proposals alone.</div>'+
    '<section><h2>Proposed UTC windows</h2><table><thead><tr>'+
      header.map(s=>'<th>'+esc(s)+'</th>').join('')+
      '</tr></thead><tbody>'+table(rows)+'</tbody></table></section>'+
    '<section><h2>Local planning constraints (not authenticated)</h2>'+
    '<p>UTC working hours: '+esc(p.enabled?p.start+'–'+p.end:'Unrestricted')+
      ' · UTC weekdays: '+esc(weekdays)+'</p>'+busy+'</section>'+
    '<section><h2>Review attention</h2><p>Time-only draft overlap pairs: '+
      esc(packet.proposed_time_overlap_pairs)+
      '. Proposed/unavailable overlaps: '+esc(packet.proposed_unavailability_overlap_pairs)+
      '. Drafts outside selected work hours: '+esc(packet.proposed_outside_workday_count)+
      '. 30-minute turnaround violations: '+esc(packet.proposed_buffer_violation_count)+
      '. Total local scheduling concerns: '+esc(total)+'.</p>'+
    '<p>No claim is made about resource availability, actual clients, risk clearance, revocation or authorizing rights. All draft identities are anonymized; the original-file digests are only unsigned content continuity hints and can still correlate documents.</p></section>'+
    '<footer><small>Source drafts were never changed. Review must use real authenticated client/operator systems and all existing security gates. No network, scripts, resources, embedded files or external fonts.</small></footer></body></html>';
}
$('briefExport').addEventListener('click',()=>{
  if(!entries.length||entries.some(e=>!e.sourceHash)||!workPolicy().valid){
    $('status').textContent='HOLD: unavailable source digests or invalid work-hour policy.';
    return;
  }
  const html=renderPrivateReviewBrief(scenarioPacket());
  const blob=new Blob([html],{type:'text/html;charset=utf-8'}),url=URL.createObjectURL(blob);
  const link=document.createElement('a');link.href=url;link.download='lightup-private-schedule-review.html';
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
  $('status').textContent='Private, script-free operator schedule brief downloaded. Nothing approved, booked or sent.';
});


// A Studio v1 revision is exported only after explicitly re-reading the matching original
// source bytes. UTC-to-local is computed in the *original* proposal IANA timezone, never
// from the operating machine's timezone or a guessed unchanged DST offset.
function wallFromUTC(instant,zone) {
  if(!Number.isFinite(instant)||instant%MINUTE!==0||typeof zone!=='string'||
      zone.length>100||!zone||!globalThis.Intl)throw Error('unsupported timezone');
  const formatter=new Intl.DateTimeFormat('en-GB',{
    timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',
    hour:'2-digit',minute:'2-digit',hourCycle:'h23'
  });
  function wallAt(when) {
    const parts=formatter.formatToParts(new Date(when));
    const values=Object.fromEntries(parts.filter(p=>
      ['year','month','day','hour','minute'].includes(p.type)).map(p=>[p.type,p.value]));
    if(!/^\d{4}$/.test(values.year||'')||
       !['month','day','hour','minute'].every(k=>/^\d{2}$/.test(values[k]||'')))
      throw Error('unsupported timezone wall');
    return values.year+'-'+values.month+'-'+values.day+'T'+values.hour+':'+values.minute;
  }
  const wall=wallAt(instant);
  if(!validLocal(wall))throw Error('invalid converted wall');
  const parts=LOCAL.exec(wall).slice(1).map(Number);
  const wallMillis=Date.UTC(parts[0],parts[1]-1,parts[2],parts[3],parts[4]);
  const offset=(instant-wallMillis)/MINUTE;
  if(!minutes(offset)||localToUTC(wall,offset)!==new Date(instant).toISOString())
    throw Error('invalid converted offset');
  // Reject repeated DST clock hours, including 30/60/90/120-minute rollbacks.
  // A local wall time must identify exactly one UTC instant for a Studio draft.
  for(let distance=30;distance<=180;distance+=30){
    if(wallAt(instant-distance*MINUTE)===wall||
       wallAt(instant+distance*MINUTE)===wall)
      throw Error('ambiguous local time');
  }
  return {wall,offset};
}
function downloadRevisedDraft(data, selected, raw){
  if(!selected||selected.interval.state!=='resolved'||
      !scenarioShifts.has(selected.key)||!selected.sourceHash||
      !globalThis.crypto||!crypto.subtle)throw Error('no eligible shift');
  if(!parseDraft(data))throw Error('invalid original');
  const previous=isoMillis(data.proposed_window_utc?.start);
  if(previous!==selected.interval.start||
      isoMillis(data.proposed_window_utc?.end)!==selected.interval.end||
      data.proposal_name!==selected.name||data.requested_mode!==selected.mode||
      data.requested_risk!==selected.risk)throw Error('source mismatch');
  const start=scenarioShifts.get(selected.key),duration=selected.interval.end-selected.interval.start;
  const end=start+duration;
  if(!Number.isFinite(start)||!Number.isFinite(end)||
      Math.abs(start-previous)>31*DAY||start===previous||
      !withinWorkHours({start,end},workPolicy()))throw Error('invalid shift');
  const zone=data.proposed_window_utc.timezone;
  const localStart=wallFromUTC(start,zone),localEnd=wallFromUTC(end,zone);
  // This only builds another Studio DRAFT_ONLY file; no approval, consent or grant
  // markers are updated or derived from the original source.
  const revised={...data,
    proposed_window_local:{start:localStart.wall,end:localEnd.wall},
    proposed_window_utc:{
      status:'resolved',timezone:zone,
      start:new Date(start).toISOString(),end:new Date(end).toISOString(),
      start_offset_minutes:localStart.offset,end_offset_minutes:localEnd.offset
    },
    exported_at_utc:new Date().toISOString()
  };
  delete revised.scope_fingerprint_sha256;
  if(!parseDraft(revised))throw Error('updated Studio schema mismatch');
  const fileName='lightup-revised-scope-draft-'+(entries.indexOf(selected)+1)+'.json';
  const blob=new Blob([JSON.stringify(revised,null,2)+'\n'],{type:'application/json'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=fileName;document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
}
$('revisionSource').addEventListener('change',async ev=>{
  const file=ev.target.files&&ev.target.files[0];ev.target.value='';
  if(!file)return;
  const selected=chosenScenario();
  if(!selected||!scenarioShifts.has(selected.key)||!selected.sourceHash){
    $('status').textContent='HOLD: select a draft with a changed UTC start and an available original-file digest.';
    return;
  }
  try{
    if(file.size<2||file.size>MAX_FILE_BYTES)throw Error('size');
    const raw=await file.arrayBuffer();
    if(!crypto||!crypto.subtle)throw Error('web crypto');
    const digest=await crypto.subtle.digest('SHA-256',raw);
    const hex=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
    if(hex!==selected.sourceHash)throw Error('different original');
    const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
    downloadRevisedDraft(data,selected,raw);
    $('status').textContent='Revised Studio v1 DRAFT_ONLY JSON downloaded from the exact original source. No fingerprint, consent, booking or grant carried forward.';
  }catch(_){
    $('status').textContent='HOLD: draft revision not exported. Select the exact imported source, a shifted window and a supported unambiguous IANA timezone; otherwise use the original Studio.';
  }
});

$('scenarioExport').addEventListener('click',()=>{
  if(!entries.length||entries.some(e=>!e.sourceHash)){
    $('status').textContent='HOLD: source SHA-256 is unavailable. This browser cannot export a source-bound scenario.';return;
  }
  const blob=new Blob([JSON.stringify(scenarioPacket(),null,2)+'\n'],{type:'application/json'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;a.download='lightup-schedule-review-only.json';
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
  $('status').textContent='Unsigned review-only scenario exported locally. No approved schedule or execution rights.';
});

function decodeUTCStamp(value){
  if(typeof value!=='string'||!/^\d{8}T\d{6}Z$/.test(value)||value.slice(13,15)!=='00')return null;
  const iso=value.slice(0,4)+'-'+value.slice(4,6)+'-'+value.slice(6,8)+'T'+
    value.slice(9,11)+':'+value.slice(11,13)+':00.000Z';
  return isoMillis(iso);
}
function parseRecurrenceRule(value,start){
  if(typeof value!=='string'||value.length>200)throw Error('oversized RRULE');
  const fields=new Map();
  for(const field of value.split(';')){
    const pos=field.indexOf('='),name=field.slice(0,pos),data=field.slice(pos+1);
    if(pos<1||fields.has(name)||!['FREQ','INTERVAL','COUNT','UNTIL','BYDAY'].includes(name)||
      !data)throw Error('unsupported recurrence term');
    fields.set(name,data);
  }
  const freq=fields.get('FREQ');
  if(freq!=='DAILY'&&freq!=='WEEKLY')throw Error('unsupported recurrence frequency');
  if(fields.has('COUNT')===fields.has('UNTIL'))throw Error('finite recurrence bound required');
  const interval=fields.has('INTERVAL')?Number(fields.get('INTERVAL')):1;
  if(!Number.isSafeInteger(interval)||interval<1||interval>12)throw Error('recurrence interval limit');
  let count=null,until=null;
  if(fields.has('COUNT')){
    const raw=fields.get('COUNT');
    if(!/^[1-9]\d?$/.test(raw))throw Error('unsupported event count');
    count=Number(raw);
    if(count>30)throw Error('recurrence count limit');
  }else{
    until=decodeUTCStamp(fields.get('UNTIL'));
    if(until===null||until<start||until-start>366*DAY)
      throw Error('recurrence outside one-year limit');
  }
  let weekdays=null;
  if(fields.has('BYDAY')){
    if(freq!=='WEEKLY')throw Error('BYDAY only for weekly events');
    const tokens=fields.get('BYDAY').split(',');
    const names=['SU','MO','TU','WE','TH','FR','SA'];
    if(!tokens.length||tokens.length>7||tokens.some(x=>!names.includes(x))||
        new Set(tokens).size!==tokens.length)throw Error('unsupported weekday list');
    weekdays=tokens.map(x=>names.indexOf(x));
  }
  return {freq,interval,count,until,weekdays};
}
function expandBusyEvent(event){
  const {start,end}=event,duration=end-start;
  if(!event.rrule){
    if(event.exdates.length)throw Error('exception without recurrence');
    return [{start,end}];
  }
  const rule=parseRecurrenceRule(event.rrule,start),days=[0,1,2,3,4,5,6];
  const sourceWeekday=new Date(start).getUTCDay();
  const wanted=rule.weekdays||[sourceWeekday];
  // RFC recurrence whose DTSTART is not in its BYDAY list has undefined
  // generated first-instance behavior. HOLD rather than silently dropping it.
  if(!wanted.includes(sourceWeekday))throw Error('BYDAY excludes DTSTART');
  const startDay=Math.floor(start/DAY);
  const weekAnchor=startDay-((new Date(start).getUTCDay()+6)%7);
  const result=[];
  for(let index=0;index<=366;index++){
    const day=startDay+index,at=start+index*DAY;
    if(rule.until!==null&&at>rule.until)break;
    const week=Math.floor((day-weekAnchor)/7);
    const isScheduled=rule.freq==='DAILY'?index%rule.interval===0:
      week%rule.interval===0&&wanted.includes(days[new Date(at).getUTCDay()]);
    if(!isScheduled)continue;
    if(rule.count!==null&&result.length===rule.count)break;
    if(result.length>=30||!Number.isFinite(at+duration)||
      isoMillis(new Date(at).toISOString())===null||
      isoMillis(new Date(at+duration).toISOString())===null)
      throw Error('recurrence bounds exceeded');
    result.push({start:at,end:at+duration});
  }
  if(rule.count!==null&&result.length!==rule.count)throw Error('recurrence too long');
  if(!result.length)throw Error('no finite recurrence occurrences');
  const excluded=new Set(event.exdates);
  if(event.exdates.some(x=>!result.some(item=>item.start===x)))
    throw Error('exception outside recurrence');
  return result.filter(item=>!excluded.has(item.start));
}
function readBusyCalendar(text){
  // Bounded *UTC-only* single and finite daily/weekly VEVENTs; never use event
  // text, identities, calendar links, timezone definitions, or remote services.
  if(typeof text!=='string'||text.length>131072||text.includes('\0') ||
      /(^|[^\r])\n/.test(text))throw Error('invalid line endings');
  const lines=text.replace(/\r\n[ \t]/g,'').split('\r\n');
  if(lines[lines.length-1]==='')lines.pop();
  if(lines.length<3||lines.length>1200||lines[0]!=='BEGIN:VCALENDAR'||
      lines[lines.length-1]!=='END:VCALENDAR')throw Error('invalid calendar');
  let event=null,events=0,fields=0;
  const blocked=[],unique=new Set();
  for(let i=1;i<lines.length-1;i++){
    const line=lines[i];
    if(line.length>4096||line.includes('\r')||line.includes('\n'))throw Error('invalid record');
    if(line==='BEGIN:VEVENT'){
      if(event!==null||events>=30)throw Error('nested/too many events');
      event={start:null,end:null,transparent:false,cancelled:false,rrule:null,exdates:[]};
      fields=0;continue;
    }
    if(line==='END:VEVENT'){
      if(event===null||event.start===null||event.end===null||event.start>=event.end||
          event.end-event.start>31*DAY)throw Error('invalid event time');
      events++;
      const occurrences=expandBusyEvent(event);
      if(!event.transparent&&!event.cancelled){
        for(const slot of occurrences){
          const key=String(slot.start)+':'+String(slot.end);
          if(!unique.has(key)){
            if(blocked.length>=30)throw Error('too many busy intervals');
            unique.add(key);blocked.push(slot);
          }
        }
      }
      event=null;continue;
    }
    if(line.startsWith('BEGIN:')||line.startsWith('END:'))throw Error('unsupported nested calendar');
    if(event===null)continue;
    if(/^(?:RDATE|RECURRENCE-ID|DURATION)(?:[;:])/.test(line))
      throw Error('unsupported recurrence override');
    if(line.startsWith('DTSTART')){
      if(event.start!==null||!/^DTSTART:\d{8}T\d{6}Z$/.test(line))
        throw Error('unsupported start timezone/precision');
      event.start=decodeUTCStamp(line.slice(8));
      if(event.start===null)throw Error('invalid start');
    }else if(line.startsWith('DTEND')){
      if(event.end!==null||!/^DTEND:\d{8}T\d{6}Z$/.test(line))
        throw Error('unsupported end timezone/precision');
      event.end=decodeUTCStamp(line.slice(6));
      if(event.end===null)throw Error('invalid end');
    }else if(line.startsWith('RRULE')){
      if(event.rrule!==null||!line.startsWith('RRULE:'))throw Error('invalid recurrence');
      event.rrule=line.slice(6);
    }else if(line.startsWith('EXDATE')){
      if(!line.startsWith('EXDATE:')||event.exdates.length>=30)throw Error('invalid exceptions');
      const values=line.slice(7).split(',');
      if(!values.length||values.length+event.exdates.length>30)throw Error('exception count limit');
      for(const value of values){
        const x=decodeUTCStamp(value);
        if(x===null||event.exdates.includes(x))throw Error('invalid exception');
        event.exdates.push(x);
      }
    }else if(line.startsWith('TRANSP')){
      if(!/^TRANSP:(?:OPAQUE|TRANSPARENT)$/.test(line)||(fields&1))
        throw Error('invalid transparency');
      event.transparent=line==='TRANSP:TRANSPARENT';fields|=1;
    }else if(line.startsWith('STATUS')){
      if(!/^STATUS:(?:CONFIRMED|TENTATIVE|CANCELLED)$/.test(line)||(fields&2))
        throw Error('invalid event status');
      event.cancelled=line==='STATUS:CANCELLED';fields|=2;
    }
  }
  if(event!==null||!events)throw Error('unfinished/no events');
  return blocked;
}
$('addBlock').addEventListener('click',()=>{
  if(blackouts.length>=30){$('status').textContent='Unavailable-period limit is 30 per tab.';return;}
  const start=parseUTCWallTime($('blockStart').value);
  const end=parseUTCWallTime($('blockEnd').value);
  if(start===null || end===null || end<=start || end-start>31*DAY){
    $('status').textContent='Enter valid ascending UTC start/end values, at most 31 days apart.';return;
  }
  const lane=Number($('blockLane').value);
  if(!Number.isInteger(lane)||lane<0||lane>4){$('status').textContent='Select an available planning lane.';return;}
  if(blackouts.some(b=>b.start===start&&b.end===end&&(b.lane??0)===lane)){
    $('status').textContent='That unavailable interval is already listed.';return;
  }
  blackouts.push({start,end,lane});
  $('blockStart').value='';$('blockEnd').value='';
  $('status').textContent='Unavailable period added locally. Alternatives have been recomputed; no actual booking created.';
  render();
});
$('clearBlocks').addEventListener('click',()=>{
  if(!blackouts.length)return;
  if(!window.confirm('Clear all local unavailable periods? No source drafts will be changed.'))return;
  blackouts=[];$('status').textContent='Local unavailable periods cleared. Source drafts remain unchanged.';render();
});
$('busyImport').addEventListener('change',async ev=>{
  const file=ev.target.files&&ev.target.files[0];ev.target.value='';
  if(!file)return;
  try{
    if(file.size<20||file.size>131072)throw Error('file limit');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
    const imported=readBusyCalendar(text);
    const lane=Number($('busyLane').value);
    if(!Number.isInteger(lane)||lane<0||lane>4)throw Error('lane');
    const updated=blackouts.slice();
    for(const slot of imported){
      if(!updated.some(b=>b.start===slot.start&&b.end===slot.end&&(b.lane??0)===lane))
        updated.push({...slot,lane});
    }
    if(updated.length>30)throw Error('limit');
    blackouts=updated;
    $('status').textContent=imported.length+' finite UTC busy interval(s) imported for '+(lane===0?'all lanes':'lane '+lane)+'. Calendar names, contacts and notes discarded; no resource booking or permission verified.';
    render();
  }catch(_){
    $('status').textContent='HOLD: calendar import refused. Use minute-accurate UTC VEVENTs, bounded DAILY/WEEKLY COUNT/UNTIL, optional BYDAY/EXDATE; no local TZ, override, unbounded series or over 30 busy intervals. Existing blocks unchanged.';
  }
});
$('files').addEventListener('change',async ev=>{
  const list=Array.from(ev.target.files||[]);ev.target.value='';
  if(!list.length)return;
  const total=list.reduce((a,f)=>a+f.size,0);
  if(list.length+entries.length>MAX_FILES || total>MAX_BATCH_BYTES){
    $('status').textContent='Import refused: maximum 20 drafts per tab and 1 MiB per selection.';return;
  }
  let accepted=0,rejected=0,duplicate=0;
  for(const file of list){
    try{
      if(file.size===0||file.size>MAX_FILE_BYTES)throw Error('size');
      const raw=await file.arrayBuffer();
      const decoded=new TextDecoder('utf-8',{fatal:true}).decode(raw);
      let sourceHash=null;
      if(globalThis.crypto && crypto.subtle && globalThis.TextEncoder){
        const digest=await crypto.subtle.digest('SHA-256',raw);
        sourceHash=Array.from(new Uint8Array(digest),byte=>byte.toString(16).padStart(2,'0')).join('');
      }
      const data=JSON.parse(decoded);
      const draft=parseDraft(data);
      if(!draft)throw Error('schema');
      // Duplicate elimination is only a local UX aid, never an identity signature.
      const key=JSON.stringify({name:draft.name,mode:draft.mode,risk:draft.risk,
        local:draft.local,utc:draft.utc,assets:data.requested_assets,excluded:data.excluded_assets});
      if(entries.some(x=>x.key===key)){duplicate++;continue;}
      entries.push({...draft,key,sourceHash});accepted++;
    }catch(_){rejected++;}
  }
  if(accepted && !anchorChangedByUser){
    const times=shown().map(e=>e.interval.start);
    if(times.length){
      const first=fmtDate(Math.min(...times));
      $('anchor').value=first;
      setAnchor();
    }
  }
  $('status').textContent=accepted+' draft(s) loaded, '+duplicate+' repeated draft(s) skipped, '+
      rejected+' held (invalid format/provenance/size). No network or database access.';
  render();
});
$('clear').addEventListener('click',()=>{
  if(!entries.length && !blackouts.length)return;
  if(!window.confirm('Clear all imported drafts and unavailable periods from this tab?'))return;
  entries=[];blackouts=[];scenarioShifts.clear();laneAssignments.clear();pinnedKeys.clear();$('scenarioStart').value='';$('status').textContent='Local drafts and scenarios cleared; no persisted history.';render();
});
$('print').addEventListener('click',()=>{if(entries.length)window.print();});
function icsTimestamp(n){return new Date(n).toISOString().replace(/[-:]/g,'').replace('.000Z','Z');}
function foldIcsLine(line){
  const chunks=[];
  for(let i=0;i<line.length;i+=73)chunks.push(line.slice(i,i+73));
  return chunks.join('\r\n ');
}
$('ics').addEventListener('click',()=>{
  const active=selectedCalendarEvents();
  if(!readyForTentativeCalendar(active)){
    $('status').textContent='HOLD: resolve time overlaps, 30-minute turnaround gaps, unavailable periods and UTC workdays before exporting a tentative calendar.';return;
  }
  // No client names, notes, assets, URLs, contacts, identifiers or original file text are exported.
  const stamp=icsTimestamp(Date.now());
  const entropy=new Uint32Array(2);
  if(globalThis.crypto && crypto.getRandomValues)crypto.getRandomValues(entropy);
  const nonce=String(Date.now())+'-'+entropy[0].toString(16)+'-'+entropy[1].toString(16);
  const lines=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LightUp//Non-Authorizing Offline Planning//EN','CALSCALE:GREGORIAN'];
  for(let i=0;i<active.length;i++){
    const e=active[i];
    lines.push('BEGIN:VEVENT','UID:offline-scope-'+nonce+'-'+(i+1)+'@lightup.invalid',
      'DTSTAMP:'+stamp,'DTSTART:'+icsTimestamp(e.interval.start),'DTEND:'+icsTimestamp(e.interval.end),
      'SUMMARY:LightUp draft planning '+(i+1)+' lane '+e.lane+' (unapproved)',
      'DESCRIPTION:Non-authorizing local draft. No booking consent risk approval grant or assessment permission.',
      'STATUS:TENTATIVE','TRANSP:TRANSPARENT','END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  const blob=new Blob([lines.map(foldIcsLine).join('\r\n')+'\r\n'],{type:'text/calendar;charset=utf-8'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;
  const lane=$('icsLane').value;
  link.download=lane==='all'?'lightup-unapproved-scope-plans.ics':
    'lightup-unapproved-lane-'+lane+'-plans.ics';
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
  $('status').textContent='Anonymous transparent TENTATIVE calendar exported for '+
    ($('icsLane').value==='all'?'all planning lanes':'lane '+$('icsLane').value)+
    '. No other lane was included; no permission or booking created.';
});
render();
})();