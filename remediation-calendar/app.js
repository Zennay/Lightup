/* LightUp private human Remediation Calendar. Browser-only; no authority or network. */
(function(global){
'use strict';
const $=id=>document.getElementById(id);
const MAX_FILE=2097152,FLAGS=['authenticated','tenant_verified','source_authorized','assessment_authorized','grant','client_consent','operator_consent','execution','scan','audit_verdict','retest_verified','release'];
const COLS=['finding_id','title','severity','retest_status','remediation'];
const CASE=['finding_id','owner','status','due_date','next_action','verification_plan','blocker','note','updated_utc'];
const PACKET=['kind','schema_version','disposition','source_contract','source_sha256','findings','cases','instructions',...FLAGS];
const PRIORITY=['critical','high','medium','low','info'];
let state=null,activeId=null,dirty=false,selectedDay=null;
function fail(message){throw Error(message);}
function bytes(s){return new TextEncoder().encode(s).length;}
function exactKeys(o,keys,what){
 if(!o||typeof o!=='object'||Array.isArray(o))fail('Invalid '+what+' object.');
 const allowed=new Set(keys);
 if(Object.keys(o).length!==allowed.size||Object.keys(o).some(k=>!allowed.has(k)))fail('Unexpected or missing '+what+' fields.');
}
function strictJSON(s){
 if(typeof s!=='string'||bytes(s)>MAX_FILE)fail('Private draft exceeds 2 MiB.');
 let i=0,nodes=0; const ws=()=>{while(i<s.length&&/[\x20\t\r\n]/.test(s[i]))i++;};
 function str(){
  const start=i;if(s[i++]!=='"')fail('Expected JSON string.');
  while(i<s.length){const c=s[i++];
   if(c==='"')return JSON.parse(s.slice(start,i));
   if(c==='\\'){const e=s[i++];if(e==='u'){if(!/^[a-fA-F0-9]{4}$/.test(s.slice(i,i+4)))fail('Bad Unicode escape.');i+=4;}else if(!'"\\/bfnrt'.includes(e))fail('Invalid JSON escape.');}
   else if(c.charCodeAt(0)<32)fail('Unescaped control character.');
  }fail('Unclosed JSON string.');
 }
 function read(depth){
  if(++nodes>50000||depth>40)fail('JSON structure exceeds bounds.');
  ws();let c=s[i];
  if(c==='"')return str();
  if(c==='{'){i++;const o=Object.create(null),seen=new Set();ws();if(s[i]==='}'){i++;return o;}
   while(true){ws();const k=str();if(seen.has(k))fail('Duplicate JSON property.');seen.add(k);ws();if(s[i++]!==':')fail('Expected JSON colon.');o[k]=read(depth+1);ws();if(s[i]==='}'){i++;return o;}if(s[i++]!==',')fail('Expected JSON comma.');}
  }
  if(c==='['){i++;const a=[];ws();if(s[i]===']'){i++;return a;}
   while(true){a.push(read(depth+1));ws();if(s[i]===']'){i++;return a;}if(s[i++]!==',')fail('Expected array comma.');}
  }
  for(const [word,val] of [['true',true],['false',false],['null',null]])if(s.startsWith(word,i)){i+=word.length;return val;}
  const m=s.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);if(m){i+=m[0].length;const v=Number(m[0]);if(!Number.isFinite(v))fail('Invalid JSON number.');return v;}
  fail('Invalid JSON value.');
 }
 const v=read(0);ws();if(i!==s.length)fail('Trailing JSON data.');return v;
}
function safeDate(day){
 if(typeof day!=='string'||!/^20\d\d-\d\d-\d\d$/.test(day))return false;
 const ms=Date.parse(day+'T00:00:00Z');
 return Number.isFinite(ms)&&new Date(ms).toISOString().slice(0,10)===day&&day<='2100-12-30';
}
function dayAfter(day){return new Date(Date.parse(day+'T00:00:00Z')+86400000).toISOString().slice(0,10);}
function dateCompact(day){return day.replace(/-/g,'');}
function isOpen(c){return !['completed','deferred'].includes(c.status);}
function eligible(x){return isOpen(x.case)&&safeDate(x.case.due_date);}
function todayUTC(){return new Date().toISOString().slice(0,10);}
function classify(x){
 if(!eligible(x))return 'not_scheduled';
 if(x.case.due_date<todayUTC())return 'overdue';
 if(x.case.status==='blocked')return 'blocked';
 if(!x.case.owner.trim())return 'unassigned';
 if(x.case.status==='ready_for_retest')return 'retest';
 return 'scheduled';
}
function allRows(){
 if(!state)return [];
 const byId=new Map(state.cases.map(c=>[c.finding_id,c]));
 return state.findings.map(f=>({finding:f,case:byId.get(f.finding_id)})).sort((a,b)=>
  (a.case.due_date||'9999').localeCompare(b.case.due_date||'9999')||
  PRIORITY.indexOf(a.finding.severity)-PRIORITY.indexOf(b.finding.severity)||
  a.finding.finding_id.localeCompare(b.finding.finding_id));
}
function filtered(){
 const text=$('search').value.trim().toLowerCase(),scope=$('filter').value,sev=$('severity').value;
 return allRows().filter(x=>{
  const c=x.case,f=x.finding;
  if(selectedDay&&(!eligible(x)||c.due_date!==selectedDay))return false;
  if(sev!=='all'&&f.severity!==sev)return false;
  if(text&&!((f.finding_id+' '+c.owner).toLowerCase().includes(text)))return false;
  if(scope==='all')return true;
  if(scope==='urgent')return ['critical','high'].includes(f.severity);
  if(scope==='blocked')return c.status==='blocked';
  if(scope==='unassigned')return !c.owner.trim();
  if(scope==='retest')return c.status==='ready_for_retest';
  if(scope==='overdue')return eligible(x)&&c.due_date<todayUTC();
  return true;
 });
}
function openEdit(id){
 if(!state||!$('source-ack').checked)fail('Source confirmation required.');
 const c=state.cases.find(x=>x.finding_id===id);
 if(!c)fail('Original finding is not in this private workspace.');
 activeId=id;
 $('edit-label').textContent='Editing human notes for original finding '+id+'. The original finding and source retest state remain read-only.';
 $('edit-owner').value=c.owner;$('edit-status').value=c.status;
 $('edit-date').value=c.due_date||'';$('edit-action').value=c.next_action;$('edit-blocker').value=c.blocker;
 $('edit-panel').hidden=false;$('edit-panel').scrollIntoView({block:'nearest'});
}
function saveEdit(event){
 event.preventDefault();
 if(!state||!$('source-ack').checked||!activeId)fail('No editable human case selected.');
 const index=state.cases.findIndex(x=>x.finding_id===activeId);
 if(index<0)fail('Original finding no longer present.');
 const old=state.cases[index],date=$('edit-date').value;
 if(date&&!safeDate(date))fail('Human follow-up date must be within 2020–2100.');
 const next=global.LightUpCasework.cleanCase({
  ...old,owner:$('edit-owner').value,status:$('edit-status').value,
  due_date:date||null,next_action:$('edit-action').value,
  blocker:$('edit-blocker').value,updated_utc:new Date().toISOString()
 },new Set(state.findings.map(f=>f.finding_id)));
 const cases=state.cases.slice();cases[index]=next;state={...state,cases};
 dirty=true;activeId=null;$('edit-panel').hidden=true;render();
 $('export-message').textContent='Human-only local change saved in memory. Export a PRIVATE Casework v1 draft before closing.';
}
function exportDraft(){
 if(!state||!$('source-ack').checked||!$('draft-ack').checked)
  fail('Private Casework export requires separately confirmed source and handoff.');
 const packet=global.LightUpCasework.makePacket(state.findings,state.cases,state.digest);
 saveFile('lightup-PRIVATE-updated-casework.json',JSON.stringify(packet,null,2)+'\n','application/json;charset=utf-8');
 dirty=false;$('export-message').textContent='Updated PRIVATE human Casework draft saved. Return via a separately approved secure channel, never as proof of remediation.';
}
function textEl(tag,text,cls){const e=document.createElement(tag);e.textContent=String(text);if(cls)e.className=cls;return e;}
function renderMonth(){
 const grid=$('month-grid');grid.replaceChildren();
 const value=$('month').value,valid=/^\\d{4}-\\d{2}$/.test(value)&&value>='2020-01'&&value<='2100-12';
 if(!valid){$('month-message').textContent='Choose a month within 2020–2100.';return;}
 const first=Date.parse(value+'-01T00:00:00Z');if(!Number.isFinite(first))return;
 for(const name of ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'])grid.append(textEl('span',name,'month-head'));
 const offset=(new Date(first).getUTCDay()+6)%7;
 const counts=new Map();
 for(const x of allRows()){
  if(!eligible(x))continue;
  const day=x.case.due_date,existing=counts.get(day)||{total:0,urgent:0,blocked:0};
  existing.total++;if(['critical','high'].includes(x.finding.severity))existing.urgent++;
  if(x.case.status==='blocked')existing.blocked++;counts.set(day,existing);
 }
 for(let i=0;i<42;i++){
  const d=new Date(first+(i-offset)*86400000),day=d.toISOString().slice(0,10);
  const inMonth=day.slice(0,7)===value,metric=counts.get(day)||{total:0,urgent:0,blocked:0};
  const b=document.createElement('button');b.type='button';b.className='month-day'+(metric.total&&inMonth?' has-work':'')+(selectedDay===day?' selected':'');
  b.disabled=!inMonth;b.setAttribute('aria-pressed',selectedDay===day?'true':'false');
  b.setAttribute('aria-label',day+': '+metric.total+' human deadlines, '+metric.urgent+' critical/high, '+metric.blocked+' blocked. Filter this date.');
  b.append(textEl('span',d.getUTCDate(),'date-number'));
  if(metric.total&&inMonth){
   b.append(textEl('span',metric.total+' planned','day-count'));
   if(metric.urgent)b.append(textEl('span',metric.urgent+' critical/high','day-critical'));
   if(metric.blocked)b.append(textEl('span',metric.blocked+' blocked','day-critical'));
  }
  b.addEventListener('click',()=>{selectedDay=selectedDay===day?null:day;render();});
  grid.append(b);
 }
 $('month-message').textContent=selectedDay?'Date filter: '+selectedDay+'. Select it again or choose Clear day filter.':'Select a day to filter the human work queue. No deadlines are automatically scheduled.';
}
function adjustMonth(delta){
 const value=$('month').value;
 if(!/^\\d{4}-\\d{2}$/.test(value))return;
 const d=new Date(value+'-01T00:00:00Z');d.setUTCMonth(d.getUTCMonth()+delta);
 const next=d.toISOString().slice(0,7);if(next<'2020-01'||next>'2100-12')return;
 $('month').value=next;selectedDay=null;render();
}
function render(){
 if(!state)return;
 renderMonth();
 const rows=filtered(),body=$('rows');body.replaceChildren();
 for(const x of rows){
  const f=x.finding,c=x.case,tr=document.createElement('tr');
  const id=document.createElement('td');id.append(textEl('strong',f.severity.toUpperCase(),['critical','high'].includes(f.severity)?'urgent':''));
  id.append(textEl('small',f.finding_id));tr.append(id);
  tr.append(textEl('td',f.retest_status));
  tr.append(textEl('td',c.status));
  tr.append(textEl('td',c.owner||'Unassigned'));
  tr.append(textEl('td',c.due_date||'No human date',!c.due_date?'muted':undefined));
  const next=document.createElement('td');next.append(textEl('span',c.next_action||'No human action'));if(c.blocker.trim())next.append(textEl('small','BLOCKED: '+c.blocker));tr.append(next);const action=document.createElement('td'),button=textEl('button','Edit','muted-button');button.type='button';button.addEventListener('click',()=>{try{openEdit(f.finding_id);}catch(e){$('export-message').textContent='HOLD: '+e.message;}});action.append(button);tr.append(action);body.append(tr);
 }
 if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.textContent='No matching original findings.';tr.append(td);body.append(tr);}
 const all=allRows(),counts=[
  ['Original findings',all.length],['Scheduled human dates',all.filter(eligible).length],
  ['Past-due human dates',all.filter(x=>eligible(x)&&x.case.due_date<todayUTC()).length],
  ['Human blockers',all.filter(x=>x.case.status==='blocked').length],
  ['Awaiting separate retest',all.filter(x=>x.case.status==='ready_for_retest').length],
  ['Missing a human due date',all.filter(x=>isOpen(x.case)&&!x.case.due_date).length]
 ];
 const m=$('metrics');m.replaceChildren();for(const [label,count] of counts){const d=textEl('div','', 'metric');d.append(textEl('strong',count),textEl('span',label));m.append(d);}
 $('scope-info').textContent=rows.length+' matching original findings; '+rows.filter(eligible).length+' with eligible human follow-up dates. Missing dates are NOT assumed resolved.';
 $('download').disabled=!$('calendar-ack').checked||!$('source-ack').checked;
 $('casework-save').disabled=!$('draft-ack').checked||!$('source-ack').checked;
}
async function shaHex(s){
 if(!global.crypto||!global.crypto.subtle)fail('This browser cannot calculate SHA-256 offline; calendar export held.');
 const out=await global.crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
 return Array.from(new Uint8Array(out),x=>x.toString(16).padStart(2,'0')).join('');
}
function packetStructure(packet){
 exactKeys(packet,PACKET,'Casework packet');
 for(const k of FLAGS)if(packet[k]!==false)fail('Casework packet claims '+k+' authority.');
 if(typeof packet.instructions!=='string'||packet.instructions.length>2000)fail('Invalid source instructions.');
 if(!Array.isArray(packet.findings)||!Array.isArray(packet.cases))fail('Missing original findings/casework.');
 for(const row of packet.findings)exactKeys(row,COLS,'finding');
 for(const row of packet.cases)exactKeys(row,CASE,'case');
 return global.LightUpCasework.loadPacket(packet);
}
async function openFile(file){
 if(!file||file.size>MAX_FILE)fail('Select a Casework v1 JSON of 2 MiB or less.');
 if(!$('source-ack').checked)fail('Confirm the independently authorized original client and engagement before import.');
 const packet=strictJSON(await file.text());
 const clean=packetStructure(packet);
 const digest=await global.LightUpCasework.digest(clean.findings);
 if(clean.source_sha256&&(!digest||clean.source_sha256!==digest))fail('Original source fingerprint mismatch or browser digest unavailable.');
 const newState={...clean,digest};
 state=newState;dirty=false;activeId=null;selectedDay=null;$('month').value=todayUTC().slice(0,7);$('edit-panel').hidden=true;$('draft-ack').checked=false;
 $('workspace').hidden=false;$('calendar-ack').checked=false;$('export-message').textContent='';
 render();
 $('message').textContent=clean.findings.length+' original findings loaded locally. Source is a historical unsigned draft; no current identity or consent checked.';
}
function icalEscape(s){
 return String(s).replace(/\r\n?/g,'\n').replace(/\\/g,'\\\\').replace(/\n/g,'\\n').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g,'');
}
function fold(line){
 let out='',length=0;
 for(const ch of line){const n=bytes(ch);if(length+n>75){out+='\r\n ';length=1;}out+=ch;length+=n;}
 return out;
}
function stamp(){return new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');}
function saveFile(name,content,type){
 const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function exportCalendar(){
 if(!state||!$('source-ack').checked||!$('calendar-ack').checked)fail('Private-calendar acknowledgment and source confirmation required.');
 const candidates=$('export-scope').value==='all'?allRows():filtered();
 const selected=candidates.filter(eligible),invalid=candidates.filter(x=>isOpen(x.case)&&x.case.due_date&&!safeDate(x.case.due_date));
 if(invalid.length)fail('One or more human dates cannot be represented safely in the calendar (2020–2100).');
 if(!selected.length)fail('No eligible human deadlines in the selected queue.');
 if(selected.length>350)fail('Calendar exceeds source bounds.');
 const privateMode=$('detail').value==='private',seen=new Set(),now=stamp();
 const base=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//LightUp//Offline Human Remediation Calendar//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH'];
 for(const x of selected){
  const f=x.finding,c=x.case,uid=(await shaHex('lightup-human-due-v1\\0'+state.digest+'\\0'+f.finding_id)).slice(0,48)+'@local.lightup.invalid';
  if(seen.has(uid))fail('Calendar UID collision; export held.');seen.add(uid);
  const title=privateMode?('LightUp HUMAN PLAN: '+f.title):('LightUp human follow-up ('+f.severity+')');
  const description=privateMode?'UNVERIFIED HUMAN CASEWORK; NOT RETEST OR APPROVAL.\\nFinding: '+f.finding_id+'\\nOwner: '+(c.owner||'unassigned')+'\\nNext action: '+c.next_action+'\\nOriginal retest: '+f.retest_status+'\\nHuman stage: '+c.status:'UNVERIFIED HUMAN FOLLOW-UP; NOT RETEST OR APPROVAL.';
  base.push('BEGIN:VEVENT','UID:'+uid,'DTSTAMP:'+now,'DTSTART;VALUE=DATE:'+dateCompact(c.due_date),
   'DTEND;VALUE=DATE:'+dateCompact(dayAfter(c.due_date)),'SUMMARY:'+icalEscape(title),
   'DESCRIPTION:'+icalEscape(description),'STATUS:TENTATIVE','TRANSP:TRANSPARENT','CLASS:PRIVATE','END:VEVENT');
 }
 base.push('END:VCALENDAR');
 const result=base.map(fold).join('\r\n')+'\r\n';
 if(bytes(result)>1048576)fail('Calendar exceeds safe export size.');
 saveFile(privateMode?'lightup-PRIVATE-human-followup.ics':'lightup-redacted-human-followup.ics',result,'text/calendar;charset=utf-8');
 $('export-message').textContent=selected.length+' local tentative calendar events exported. They are NOT proof of current consent, remediation or retest.';
}
function exportAggregate(){
 if(!state)fail('Open original Casework first.');
 const list=allRows(),out=['severity,open,blocked,scheduled,overdue,ready_for_separate_retest,missing_due_date'];
 for(const sev of PRIORITY){
  const rows=list.filter(x=>x.finding.severity===sev);
  out.push([sev,rows.filter(x=>isOpen(x.case)).length,rows.filter(x=>x.case.status==='blocked').length,
    rows.filter(eligible).length,rows.filter(x=>eligible(x)&&x.case.due_date<todayUTC()).length,
    rows.filter(x=>x.case.status==='ready_for_retest').length,rows.filter(x=>isOpen(x.case)&&!x.case.due_date).length].join(','));
 }
 saveFile('lightup-anonymous-human-workload.csv',out.join('\r\n')+'\r\n','text/csv;charset=utf-8');
 $('export-message').textContent='Anonymous category counts exported. This is neither a retest outcome nor proof of a safe public disclosure.';
}
function reset(){
 state=null;activeId=null;dirty=false;selectedDay=null;$('file').value='';$('source-ack').checked=false;$('calendar-ack').checked=false;$('draft-ack').checked=false;$('edit-panel').hidden=true;
 $('workspace').hidden=true;$('message').textContent='Private workspace cleared from app state. Already exported files and calendar imports remain under your control.';
}
$('file').addEventListener('change',async e=>{
 if(dirty&&!global.confirm('Discard in-memory human changes? Export your PRIVATE Casework draft first.')){e.target.value='';return;}
 if(state&&!global.confirm('Replace the previous source? Independently verify the newly selected client and exact engagement first.')){e.target.value='';return;}
 state=null;activeId=null;dirty=false;$('edit-panel').hidden=true;$('workspace').hidden=true;
 try{await openFile(e.target.files[0]);}catch(err){$('message').textContent='HOLD: '+err.message;}
});
for(const id of ['filter','severity','search'])$(id).addEventListener('input',render);
$('calendar-ack').addEventListener('change',render);
$('draft-ack').addEventListener('change',render);
$('month').addEventListener('change',()=>{selectedDay=null;render();});
$('month-prev').addEventListener('click',()=>adjustMonth(-1));
$('month-next').addEventListener('click',()=>adjustMonth(1));
$('day-clear').addEventListener('click',()=>{selectedDay=null;render();});
$('edit-form').addEventListener('submit',e=>{try{saveEdit(e);}catch(err){e.preventDefault();$('export-message').textContent='HOLD: '+err.message;}});
$('edit-cancel').addEventListener('click',()=>{activeId=null;$('edit-panel').hidden=true;});
$('casework-save').addEventListener('click',()=>{try{exportDraft();}catch(err){$('export-message').textContent='HOLD: '+err.message;}});
$('source-ack').addEventListener('change',()=>{if(state)render();});
$('download').addEventListener('click',async()=>{try{await exportCalendar();}catch(e){$('export-message').textContent='HOLD: '+e.message;}});
$('aggregate').addEventListener('click',()=>{try{exportAggregate();}catch(e){$('export-message').textContent='HOLD: '+e.message;}});
$('clear').addEventListener('click',()=>{if(dirty&&!global.confirm('Discard unsaved human notes?'))return;reset();});
global.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
})(window);