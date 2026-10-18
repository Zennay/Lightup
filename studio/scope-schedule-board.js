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
let entries = [], blackouts = [], scenarioShifts = new Map(), anchorUTC = 0, anchorChangedByUser = false;

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
    const shift=scenarioShifts.get(e.key);
    return shift===undefined ? {...e,scenario:false,original:e.interval} :
      {...e,interval:{state:'resolved',start:shift,end:shift+(e.interval.end-e.interval.start)},
        scenario:true,original:e.interval};
  });
}
function timeClashes(list) {
  const pairs=[],active=new Set();
  for(let i=0;i<list.length;i++)for(let j=i+1;j<list.length;j++){
    const a=list[i].interval,b=list[j].interval;
    if(a.start<b.end && b.start<a.end){pairs.push([i,j]);active.add(i);active.add(j);}
  }
  return {pairs,active};
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
    append(row,'span','Unavailable #'+(i+1)+': '+formatUTC(b.start)+' → '+formatUTC(b.end)+' ');
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
  const start=$('hoursStart').value,end=$('hoursEnd').value;
  const days=Array.from($('hoursDays').querySelectorAll('input[data-day]'))
    .filter(input=>input.checked).map(input=>Number(input.dataset.day)).sort();
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
  const forbidden=list.filter(item=>item!==entry).map(item=>item.interval).concat(blackouts);
  return firstFit(entry.interval,forbidden,workPolicy());
}
function createAxis(days) {
  const head=$('axis');head.replaceChildren();
  append(head,'strong','Draft / risk');
  const axis=document.createElement('div');axis.className='days';axis.style.setProperty('--days',days);
  for(let i=0;i<days;i++)append(axis,'span',new Date(anchorUTC+i*DAY).toISOString().slice(5,10));
  head.append(axis);
}
function render(){
  const timed=shown(),unsafe=entries.filter(e=>e.interval.state!=='resolved');
  const {pairs,active}=timeClashes(timed);
  const policy=workPolicy();
  activeWorkNote(policy);
  const invalidHours=timed.filter(e=>!withinWorkHours(e.interval,policy));
  const blockHits=[];
  timed.forEach((e,i)=>blackouts.forEach((b,j)=>{
    if(e.interval.start<b.end && b.start<e.interval.end){blockHits.push([i,j]);active.add(i);}
  }));
  for(const e of invalidHours){const i=timed.findIndex(item=>item.key===e.key);if(i>=0)active.add(i);}
  $('hoursClashes').textContent=invalidHours.length;
  $('blocked').textContent=blackouts.length;
  $('changed').textContent=scenarioShifts.size;
  renderBlocks();
  $('total').textContent=entries.length;$('timed').textContent=timed.length;
  $('unscheduled').textContent=unsafe.length;$('clashes').textContent=pairs.length+blockHits.length;
  const original=entries.filter(e=>e.interval.state==='resolved');
  const baseline=timeClashes(original).pairs.length+
    original.reduce((total,e)=>total+blackouts.filter(b=>e.interval.start<b.end&&b.start<e.interval.end).length,0)+
    original.filter(e=>!withinWorkHours(e.interval,policy)).length;
  const current=pairs.length+blockHits.length+invalidHours.length;
  $('baselineClashes').textContent=baseline;
  $('clashReduction').textContent=String(baseline-current);
  $('ics').disabled=!timed.length||invalidHours.length>0||!policy.valid;
  $('print').disabled=!entries.length;
  const days=Number($('horizon').value),lo=anchorUTC,hi=anchorUTC+days*DAY;
  createAxis(days);
  const lanes=$('lanes');lanes.replaceChildren();
  const ordered=timed.map((entry,i)=>({entry,i})).sort((a,b)=>a.entry.interval.start-b.entry.interval.start);
  if(!ordered.length)append(lanes,'p','No validated UTC windows to place on the calendar.','muted');
  for(const {entry:e,i} of ordered){
    const row=document.createElement('div');row.className='lane';lanes.append(row);
    const label=document.createElement('div');label.className='label';row.append(label);
    append(label,'strong',e.name+(e.scenario?' · WHAT-IF':' '));
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
    append(label,'strong','Unavailable #'+(j+1));append(label,'small',formatUTC(b.start)+' → '+formatUTC(b.end));
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
  if(!pairs.length && !blockHits.length && !invalidHours.length)append(conflict,'p','No collisions detected against other drafts or locally unavailable periods. This does not prove availability or approval.','muted');
  for(const [i,j] of pairs){
    const a=timed[i],b=timed[j],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong',a.name+' ↔ '+b.name);
    append(box,'div','Overlap: '+formatUTC(Math.max(a.interval.start,b.interval.start))+' – '+formatUTC(Math.min(a.interval.end,b.interval.end)));
  }
  for(const [i,j] of blockHits){
    const e=timed[i],b=blackouts[j],box=document.createElement('div');box.className='item danger';conflict.append(box);
    append(box,'strong',e.name+' ↔ Unavailable #'+(j+1));
    append(box,'div','Local planning conflict: '+formatUTC(Math.max(e.interval.start,b.start))+' – '+formatUTC(Math.min(e.interval.end,b.end)));
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
  const changes=$('scenarioChanges');changes.replaceChildren();
  if(!scenarioShifts.size)append(changes,'p','No time adjustments proposed.','muted');
  entries.forEach((e,i)=>{
    const shifted=scenarioShifts.get(e.key);
    if(shifted===undefined)return;
    const box=document.createElement('div');box.className='item';changes.append(box);
    append(box,'strong',e.name+' · #'+(i+1));
    const duration=e.interval.end-e.interval.start;
    append(box,'div','Original: '+formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end));
    append(box,'div','What-if: '+formatUTC(shifted)+' → '+formatUTC(shifted+duration));
  });
  $('scenarioPreview').textContent=JSON.stringify(scenarioPacket(),null,2);
}
function scenarioPacket(){
  const current=shown();
  const {pairs}=timeClashes(current);
  const blockHits=current.reduce((n,e)=>n+blackouts.filter(b=>e.interval.start<b.end&&b.start<e.interval.end).length,0);
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
      return {local_ordinal:i+1,source_file_sha256:e.sourceHash,requested_mode:e.mode,requested_risk:e.risk,state:valid?'DRAFT_PLANNED':'HOLD_MISSING_UTC',
        original_start_utc:valid?new Date(e.interval.start).toISOString():null,
        original_end_utc:valid?new Date(e.interval.end).toISOString():null,
        scenario_start_utc:valid?new Date(proposed===undefined?e.interval.start:proposed).toISOString():null,
        scenario_end_utc:valid?new Date((proposed===undefined?e.interval.start:proposed)+duration).toISOString():null,
        shifted:proposed!==undefined};
    }),
    unavailable_utc:blackouts.map(b=>({start:new Date(b.start).toISOString(),end:new Date(b.end).toISOString()})),
    workday_utc:{enabled:policy.enabled,start:policy.start_utc,end:policy.end_utc,weekdays:policy.weekdays},
    proposed_time_overlap_pairs:pairs.length,proposed_unavailability_overlap_pairs:blockHits,
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
  const busy=blackouts.map(b=>({start:b.start,end:b.end})),proposals=new Map();
  for(const e of current){
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
    'proposed_time_overlap_pairs','proposed_unavailability_overlap_pairs','proposed_outside_workday_count']);
  const rowKeys=new Set(['local_ordinal','source_file_sha256','requested_mode','requested_risk','state','original_start_utc',
    'original_end_utc','scenario_start_utc','scenario_end_utc','shifted']);
  const blockKeys=new Set(['start','end']);
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
  const shifts=new Map(),busy=[],resolvedIntervals=[];
  for(let i=0;i<entries.length;i++){
    const source=entries[i],row=snapshot.proposals[i],resolved=source.interval.state==='resolved';
    if(!record(row)||!exactKeys(row,rowKeys)||row.local_ordinal!==i+1||
       row.requested_mode!==source.mode||row.requested_risk!==source.risk||
       typeof row.source_file_sha256!=='string' ||
       !/^[a-f0-9]{64}$/.test(row.source_file_sha256) ||
       row.source_file_sha256!==source.sourceHash||
       row.state!==(resolved?'DRAFT_PLANNED':'HOLD_MISSING_UTC')||
       typeof row.shifted!=='boolean')throw Error('mismatched source');
    if(!resolved){
      if(row.original_start_utc!==null||row.original_end_utc!==null||
         row.scenario_start_utc!==null||row.scenario_end_utc!==null||row.shifted)throw Error('invalid hold');
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
    resolvedIntervals.push({start:a,end:b});
  }
  if(own(snapshot,'proposed_outside_workday_count') &&
     snapshot.proposed_outside_workday_count!==resolvedIntervals.filter(t=>
       !withinWorkHours(t,effectivePolicy)).length)throw Error('inconsistent workday count');
  for(const block of snapshot.unavailable_utc){
    if(!record(block)||!exactKeys(block,blockKeys))throw Error('invalid block');
    const start=isoMillis(block.start),end=isoMillis(block.end);
    if(start===null||end===null||end<=start||end-start>31*DAY ||
       busy.some(b=>b.start===start&&b.end===end))throw Error('invalid unavailable window');
    busy.push({start,end});
  }
  return {shifts,busy,policy};
}
$('scenarioImport').addEventListener('change',async ev=>{
  const file=ev.target.files&&ev.target.files[0];ev.target.value='';
  if(!file)return;
  try{
    if(!entries.length||file.size<2||file.size>65536)throw Error('size/missing source');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
    const candidate=JSON.parse(text),next=decodeScenario(candidate);
    // The entire replacement is committed at once: no partial restoration on invalid input.
    scenarioShifts=next.shifts;blackouts=next.busy;
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
function readBusyCalendar(text){
  // Strict one-shot UTC VEVENT import only. No network, no recurrence expansion,
  // calendar names, descriptions or attendee identity are retained.
  if(typeof text!=='string'||text.length>131072||text.includes('\0') ||
      /(^|[^\r])\n/.test(text))throw Error('invalid line endings');
  const lines=text.replace(/\r\n[ \t]/g,'').split('\r\n');
  if(lines[lines.length-1]==='')lines.pop();
  if(lines.length<3||lines.length>1200||lines[0]!=='BEGIN:VCALENDAR'||
      lines[lines.length-1]!=='END:VCALENDAR')throw Error('invalid calendar');
  const records=[],blocked=[],unique=new Set();
  let event=null,fields=0;
  for(let i=1;i<lines.length-1;i++){
    const line=lines[i];
    if(line.length>4096||line.includes('\r')||line.includes('\n'))throw Error('invalid record');
    if(line==='BEGIN:VEVENT'){
      if(event!==null)throw Error('nested events');
      if(records.length>=30)throw Error('too many events');
      event={start:null,end:null,transparent:false,cancelled:false};
      fields=0;continue;
    }
    if(line==='END:VEVENT'){
      if(event===null||event.start===null||event.end===null||event.start>=event.end||
          event.end-event.start>31*DAY)throw Error('invalid event time');
      records.push(event);
      if(!event.transparent&&!event.cancelled){
        const key=String(event.start)+':'+String(event.end);
        if(!unique.has(key)){unique.add(key);blocked.push({start:event.start,end:event.end});}
      }
      event=null;continue;
    }
    if(line.startsWith('BEGIN:')||line.startsWith('END:'))throw Error('unsupported nested calendar');
    if(event===null)continue;
    if(/^(?:RRULE|RDATE|EXDATE|RECURRENCE-ID|DURATION)(?:[;:])/.test(line))
      throw Error('recurring/relative events unsupported');
    if(line.startsWith('DTSTART')){
      if(event.start!==null||!/^DTSTART:\d{8}T\d{6}Z$/.test(line))throw Error('unsupported time');
      event.start=decodeUTCStamp(line.slice(8));if(event.start===null)throw Error('invalid start');
    }else if(line.startsWith('DTEND')){
      if(event.end!==null||!/^DTEND:\d{8}T\d{6}Z$/.test(line))throw Error('unsupported time');
      event.end=decodeUTCStamp(line.slice(6));if(event.end===null)throw Error('invalid end');
    }else if(line.startsWith('TRANSP')){
      if(!/^TRANSP:(?:OPAQUE|TRANSPARENT)$/.test(line)||fields&1)throw Error('invalid transparency');
      event.transparent=line==='TRANSP:TRANSPARENT';fields|=1;
    }else if(line.startsWith('STATUS')){
      if(!/^STATUS:(?:CONFIRMED|TENTATIVE|CANCELLED)$/.test(line)||fields&2)
        throw Error('invalid event status');
      event.cancelled=line==='STATUS:CANCELLED';fields|=2;
    }
  }
  if(event!==null||!records.length)throw Error('unfinished/no events');
  return blocked;
}

$('addBlock').addEventListener('click',()=>{
  if(blackouts.length>=30){$('status').textContent='Unavailable-period limit is 30 per tab.';return;}
  const start=parseUTCWallTime($('blockStart').value);
  const end=parseUTCWallTime($('blockEnd').value);
  if(start===null || end===null || end<=start || end-start>31*DAY){
    $('status').textContent='Enter valid ascending UTC start/end values, at most 31 days apart.';return;
  }
  if(blackouts.some(b=>b.start===start&&b.end===end)){
    $('status').textContent='That unavailable interval is already listed.';return;
  }
  blackouts.push({start,end});
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
    const updated=blackouts.slice();
    for(const slot of imported){
      if(!updated.some(b=>b.start===slot.start&&b.end===slot.end))updated.push(slot);
    }
    if(updated.length>30)throw Error('limit');
    blackouts=updated;
    $('status').textContent=imported.length+' opaque, non-cancelled UTC event interval(s) read locally. Titles, contacts and notes discarded. No actual booking imported as authority.';
    render();
  }catch(_){
    $('status').textContent='HOLD: calendar import refused. Supply a bounded .ics with single, minute-exact UTC VEVENTs, no recurrence or timezone-local timestamps. Existing blocks unchanged.';
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
  entries=[];blackouts=[];scenarioShifts.clear();$('scenarioStart').value='';$('status').textContent='Local drafts and scenarios cleared; no persisted history.';render();
});
$('print').addEventListener('click',()=>{if(entries.length)window.print();});
function icsTimestamp(n){return new Date(n).toISOString().replace(/[-:]/g,'').replace('.000Z','Z');}
function foldIcsLine(line){
  const chunks=[];
  for(let i=0;i<line.length;i+=73)chunks.push(line.slice(i,i+73));
  return chunks.join('\r\n ');
}
$('ics').addEventListener('click',()=>{
  const active=shown(),policy=workPolicy();
  if(!active.length||!policy.valid||active.some(e=>!withinWorkHours(e.interval,policy))){
    $('status').textContent='HOLD: fix time windows outside allowed UTC workdays before exporting tentative calendar events.';return;
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
      'SUMMARY:LightUp draft planning '+(i+1)+' (unapproved)',
      'DESCRIPTION:Non-authorizing local draft. No booking consent risk approval grant or assessment permission.',
      'STATUS:TENTATIVE','TRANSP:TRANSPARENT','END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  const blob=new Blob([lines.map(foldIcsLine).join('\r\n')+'\r\n'],{type:'text/calendar;charset=utf-8'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download='lightup-unapproved-scope-plans.ics';
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
  $('status').textContent='Anonymous transparent TENTATIVE calendar exported locally. This does not approve any request or reserve time.';
});
render();
})();