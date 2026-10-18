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
let entries = [], blackouts = [], anchorUTC = 0, anchorChangedByUser = false;

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
function shown(){return entries.filter(e=>e.interval.state==='resolved');}
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
function suggest(entry,list){
  let candidate=entry.interval.start,cycles=0;
  const duration=entry.interval.end-entry.interval.start;
  const others=list.filter(x=>x!==entry).concat(blackouts.map(b=>({interval:b}))).sort((a,b)=>a.interval.start-b.interval.start);
  while(cycles++<MAX_FILES+2) {
    const conflict=others.find(e=>candidate<e.interval.end+BUFFER &&
      candidate+duration+BUFFER>e.interval.start);
    if(!conflict) return {start:candidate,end:candidate+duration};
    candidate=Math.max(candidate,conflict.interval.end+BUFFER);
    if(!Number.isFinite(candidate+duration)||candidate+duration>Date.UTC(2100,0,1))break;
  }
  return null;
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
  const blockHits=[];
  timed.forEach((e,i)=>blackouts.forEach((b,j)=>{
    if(e.interval.start<b.end && b.start<e.interval.end){blockHits.push([i,j]);active.add(i);}
  }));
  $('blocked').textContent=blackouts.length;
  renderBlocks();
  $('total').textContent=entries.length;$('timed').textContent=timed.length;
  $('unscheduled').textContent=unsafe.length;$('clashes').textContent=pairs.length+blockHits.length;
  $('ics').disabled=!timed.length;$('print').disabled=!entries.length;
  const days=Number($('horizon').value),lo=anchorUTC,hi=anchorUTC+days*DAY;
  createAxis(days);
  const lanes=$('lanes');lanes.replaceChildren();
  const ordered=timed.map((entry,i)=>({entry,i})).sort((a,b)=>a.entry.interval.start-b.entry.interval.start);
  if(!ordered.length)append(lanes,'p','No validated UTC windows to place on the calendar.','muted');
  for(const {entry:e,i} of ordered){
    const row=document.createElement('div');row.className='lane';lanes.append(row);
    const label=document.createElement('div');label.className='label';row.append(label);
    append(label,'strong',e.name);
    append(label,'span','Risk '+e.risk+' · '+e.mode,'pill');
    const track=document.createElement('div');track.className='track';track.style.setProperty('--days',days);row.append(track);
    const start=Math.max(e.interval.start,lo),end=Math.min(e.interval.end,hi);
    if(start<end){
      const bar=document.createElement('div');
      bar.className='bar'+(e.risk===4?' high':'')+(active.has(i)?' conflict':'');
      bar.style.left=100*(start-lo)/(days*DAY)+'%';
      bar.style.width=100*(end-start)/(days*DAY)+'%';
      bar.title=formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end)+'; DRAFT ONLY';
      track.append(bar);
    } else append(track,'span','Outside visible horizon','muted');
    append(label,'small',formatUTC(e.interval.start)+' → '+formatUTC(e.interval.end));
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
  if(!pairs.length && !blockHits.length)append(conflict,'p','No collisions detected against other drafts or locally unavailable periods. This does not prove availability or approval.','muted');
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
      const decoded=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      const data=JSON.parse(decoded);
      const draft=parseDraft(data);
      if(!draft)throw Error('schema');
      // Duplicate elimination is only a local UX aid, never an identity signature.
      const key=JSON.stringify({name:draft.name,mode:draft.mode,risk:draft.risk,
        local:draft.local,utc:draft.utc,assets:data.requested_assets,excluded:data.excluded_assets});
      if(entries.some(x=>x.key===key)){duplicate++;continue;}
      entries.push({...draft,key});accepted++;
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
  entries=[];blackouts=[];$('status').textContent='Local drafts cleared; no persisted history.';render();
});
$('print').addEventListener('click',()=>{if(entries.length)window.print();});
function icsTimestamp(n){return new Date(n).toISOString().replace(/[-:]/g,'').replace('.000Z','Z');}
function foldIcsLine(line){
  const chunks=[];
  for(let i=0;i<line.length;i+=73)chunks.push(line.slice(i,i+73));
  return chunks.join('\r\n ');
}
$('ics').addEventListener('click',()=>{
  const active=shown();if(!active.length)return;
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