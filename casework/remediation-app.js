/* LightUp remediation casework UI. No network, persisted browser state, or elevated capabilities. */
(function(){
'use strict';
const $=id=>document.getElementById(id);
const workflow=LightUpCasework.PROGRESS;
for(const status of workflow){const opt=document.createElement('option');opt.value=status;opt.textContent=status.replaceAll('_',' ');$('workflow').append(opt);}
let findings=[],cases=[],fingerprint=null,sourceLabel='',edited=false;
const byId=()=>new Map(cases.map(c=>[c.finding_id,c]));
const ids=()=>new Set(findings.map(f=>f.finding_id));
function inform(message){$('status').textContent=message;}
function safeText(parent,tag,text,cls){
 const el=document.createElement(tag);el.textContent=String(text??'');
 if(cls)el.className=cls;
 parent.append(el);return el;
}
function makeInput(container,label,key,selected,options){
 const wrap=document.createElement('label');wrap.textContent=label;container.append(wrap);
 let el;
 if(options){el=document.createElement('select');for(const [value,title] of options){
  const opt=document.createElement('option');opt.value=value;opt.textContent=title;el.append(opt);
 }}
 else if(key==='due_date'){el=document.createElement('input');el.type='date';}
 else if(['next_action','verification_plan','blocker','note'].includes(key)){el=document.createElement('textarea');el.rows=2;}
 else {el=document.createElement('input');el.type='text';}
 el.id='case-'+key+'-'+selected.finding_id;
 const max={owner:120,next_action:1800,verification_plan:1600,blocker:1200,note:1600};
 if(max[key])el.maxLength=max[key];
 el.value=selected[key]??'';
 wrap.append(el);
 el.addEventListener('change',()=>{
  const next={...selected,[key]:key==='due_date'?(el.value||null):el.value,updated_utc:new Date().toISOString()};
  try{
   const validated=LightUpCasework.cleanCase(next,ids());
   const index=cases.findIndex(c=>c.finding_id===selected.finding_id);
   cases[index]=validated;edited=true;
   inform('Unsaved local changes. Export casework JSON to keep your plan.');
   render();
  }catch(_){inform('Invalid case field; change not saved.');el.value=selected[key]??'';}
 });
 return el;
}
function render(){
 const available=findings.length>0,by=byId();
 const totals=LightUpCasework.metrics(findings,cases,new Date().toISOString().slice(0,10));
 for(const [ui,key] of [['total','findings'],['urgent','critical_or_high'],['open','open'],['blocked','blocked'],['overdue','overdue'],['retest','ready_for_retest']])
  $(ui).textContent=totals[key];
 for(const id of ['save','exportCSV','exportMD','print'])$(id).disabled=!available;
 $('reference').textContent=available?'Source: '+sourceLabel+' · unverified content SHA-256: '+(fingerprint||'unavailable in this browser')+
   ' · '+findings.length+' findings · '+(edited?'unsaved local changes':'no unsaved changes')+'.':'No source imported.';
 $('empty').style.display=available?'none':'block';
 const needle=$('search').value.trim().toLowerCase(),severity=$('severity').value,work=$('workflow').value;
 const listed=findings.filter(f=>{
  const c=by.get(f.finding_id);
  return (!severity||f.severity===severity)&&(!work||c.status===work)&&
   (!needle||[f.finding_id,f.title,f.remediation,c.owner,c.next_action,c.blocker].some(s=>s.toLowerCase().includes(needle)));
 });
 const kind=$('sort').value;
 listed.sort((a,b)=>{
  const ca=by.get(a.finding_id),cb=by.get(b.finding_id);
  if(kind==='title')return a.title.localeCompare(b.title);
  if(kind==='due')return (ca.due_date||'9999').localeCompare(cb.due_date||'9999')||
    LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity);
  return LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity)||
   (a.retest_status==='regression'?-1:0)-(b.retest_status==='regression'?-1:0)||
   a.finding_id.localeCompare(b.finding_id);
 });
 const board=$('board');board.replaceChildren();
 if(available&&!listed.length)safeText(board,'p','No cases match the current filter.','small');
 for(const f of listed){
  const c=by.get(f.finding_id),card=document.createElement('article');card.className='finding';board.append(card);
  const meta=document.createElement('div');meta.className='meta';card.append(meta);
  safeText(meta,'span',f.severity,'badge '+(f.severity==='critical'||f.severity==='high'?f.severity:''));
  safeText(meta,'span',f.retest_status.replaceAll('_',' '),'badge '+(f.retest_status==='fixed'?'fixed':''));
  safeText(meta,'span',c.status.replaceAll('_',' '),'badge '+(c.status==='blocked'?'blocked':''));
  safeText(card,'h3',f.title);safeText(card,'p','Finding ID: '+f.finding_id,'small');
  const details=document.createElement('details');card.append(details);
  safeText(details,'summary','Recommended source remediation');safeText(details,'div',f.remediation,'inline');
  const two=document.createElement('div');two.className='grid';card.append(two);
  makeInput(two,'Responsible owner / team','owner',c);
  makeInput(two,'Target due date','due_date',c);
  makeInput(card,'Planning stage','status',c,workflow.map(t=>[t,t.replaceAll('_',' ')]));
  makeInput(card,'Next repair action','next_action',c);
  makeInput(card,'Retest coordination / verification plan','verification_plan',c);
  makeInput(card,'Blocker / dependency','blocker',c);
  makeInput(card,'Private local planning notes','note',c);
  const msg=c.status==='completed'&&f.retest_status!=='fixed'
   ? 'Completed in local plan only: the original LightUp finding is not marked fixed. Independent evidence and authenticated retest are required.'
   : 'This assignment remains a local planning note. It does not modify LightUp domain findings or certify a repaired issue.';
  safeText(card,'p',msg,'note');
 }
 const packet=available?LightUpCasework.makePacket(findings,cases,fingerprint):null;
 const preview=available?{
  kind:packet.kind,disposition:packet.disposition,authority:{authenticated:false,grant:false,execution:false},
  summary:totals,source_sha256:fingerprint,
  actions:cases.slice(0,8).map(c=>({finding_id:c.finding_id,status:c.status,owner:c.owner,due_date:c.due_date})),
  additional_actions_hidden:Math.max(0,cases.length-8)
 }:null;
 $('preview').textContent=preview?JSON.stringify(preview,null,2):'Nothing to preview.';
}
function download(name,mime,content){
 const file=new Blob([content],{type:mime}),url=URL.createObjectURL(file),link=document.createElement('a');
 link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),500);
}
async function withCsv(file){
 if(!file||file.size>LightUpCasework.MAX_BYTES)throw Error('CSV exceeds 1 MiB.');
 const source=LightUpCasework.parseCSV(await file.text());
 const hash=await LightUpCasework.digest(source);
 if(findings.length && !window.confirm('Replace current unsaved casework with imported findings?'))return false;
 findings=source;cases=source.map(LightUpCasework.newCase);fingerprint=hash;sourceLabel='LightUp CSV: '+file.name.slice(0,100);
 edited=true;return true;
}
async function withPacket(file){
 if(!file||file.size>2097152)throw Error('Saved casework exceeds 2 MiB.');
 const payload=JSON.parse(await file.text(),(k,v)=>['__proto__','constructor','prototype'].includes(k)?undefined:v);
 const loaded=LightUpCasework.loadPacket(payload),actual=await LightUpCasework.digest(loaded.findings);
 if(loaded.source_sha256 && (!actual||loaded.source_sha256!==actual))throw Error('Finding source revision does not match saved casework.');
 if(findings.length && !window.confirm('Replace current unsaved casework with this saved draft?'))return false;
 findings=loaded.findings;cases=loaded.cases;fingerprint=actual;sourceLabel='Saved local casework: '+file.name.slice(0,100);
 edited=false;return true;
}
for(const [id,load] of [['csvSource',withCsv],['caseworkSource',withPacket]]){
 $(id).addEventListener('change',async event=>{
  const file=event.target.files[0];event.target.value='';if(!file)return;
  try{
   const changed=await load(file);
   if(changed){inform('Imported '+findings.length+' finding(s) into a local repair plan. Save your changes to JSON.');render();}
   else inform('Import cancelled; existing local plan unchanged.');
  }catch(err){inform('Import rejected: '+(err.message||'invalid or unsupported file')+'. Current plan unchanged.');}
 });
}
for(const id of ['search','severity','workflow','sort'])$(id).addEventListener(id==='search'?'input':'change',render);
$('save').addEventListener('click',()=>{
 if(!findings.length)return;
 const packet=LightUpCasework.makePacket(findings,cases,fingerprint);
 download('lightup-remediation-casework.json','application/json',JSON.stringify(packet,null,2)+'\n');
 edited=false;inform('Local JSON casework draft exported; it is not signed or submitted to LightUp.');render();
});
$('exportCSV').addEventListener('click',()=>{
 if(!findings.length)return;
 download('lightup-remediation-actions.csv','text/csv',LightUpCasework.exportActionsCSV(findings,cases));
 inform('Local action CSV exported; planning statuses are not real retest outcomes.');
});
function safeMD(s){
 return String(s??'').replace(/[\x60\\*_{}\[\]<>#!|]/g,'\\$&').replace(/\r/g,'').replace(/\n/g,' ');
}
function brief(){
 const by=byId(),totals=LightUpCasework.metrics(findings,cases,new Date().toISOString().slice(0,10));
 const out=['# LightUp client remediation coordination draft','',
 'Local planning only: not authenticated evidence, permission, grant, verified retest, or remediation closure.','',
 'Source SHA-256 (unsigned): '+(fingerprint||'unavailable'),'',
 '## Portfolio overview','',
 '- Findings: '+totals.findings,'- Critical/high: '+totals.critical_or_high,
 '- Blocked: '+totals.blocked,'- Overdue: '+totals.overdue,'- Ready for retest coordination: '+totals.ready_for_retest,''];
 for(const f of findings.slice().sort((a,b)=>LightUpCasework.SEVERITY.indexOf(a.severity)-LightUpCasework.SEVERITY.indexOf(b.severity))){
  const c=by.get(f.finding_id);
  out.push('## '+safeMD(f.title),'','- ID: '+safeMD(f.finding_id),
   '- Severity: '+f.severity,'- Source retest status (unverified here): '+f.retest_status,
   '- Local work stage: '+c.status,'- Assigned team: '+safeMD(c.owner||'unassigned'),
   '- Due date: '+(c.due_date||'unplanned'),'','### Source remediation recommendation','',
   safeMD(f.remediation),'','### Action / retest / dependency','',
   'Action: '+safeMD(c.next_action||'not planned'),'',
   'Verification approach: '+safeMD(c.verification_plan||'not planned'),'',
   'Blocker: '+safeMD(c.blocker||'none recorded'),'');
 }
 out.push('---','All entries require independent owner and authorization checks and genuine authenticated retest before closure.','');
 return out.join('\n');
}
$('exportMD').addEventListener('click',()=>{
 if(!findings.length)return;
 download('lightup-remediation-brief.md','text/markdown',brief());
 inform('Local Markdown remediation brief exported.');
});
$('print').addEventListener('click',()=>{if(findings.length)window.print();});
$('reset').addEventListener('click',()=>{
 if(!findings.length)return;
 if(!window.confirm('Erase all imported findings and unsaved edits from this tab?'))return;
 findings=[];cases=[];fingerprint=null;sourceLabel='';edited=false;
 $('search').value='';$('severity').value='';$('workflow').value='';
 inform('Workspace cleared; no browser storage or server request was used.');render();
});
render();
})();