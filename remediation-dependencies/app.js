/* LightUp human dependency board UI: all local, source-bound, no execution authority. */
(function(g){'use strict';
const $=id=>document.getElementById(id),E=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);return n;};
const SEV=['critical','high','medium','low','info'],LIMIT=2097152;
let state=null,links=[],efforts=[],dirty=false,revision=0,ownerLabels=[];
function stop(s){throw Error(s);}
function parseStrict(raw){
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>LIMIT)stop('PRIVATE JSON exceeds 2 MiB.');
 let i=0,steps=0;
 const ws=()=>{while(/[ \t\r\n]/.test(raw[i]||'!')&&i<raw.length)i++;};
 function string(){
  const begin=i;if(raw[i++]!=='"')stop('Expected JSON string.');
  while(i<raw.length){let c=raw[i++];if(c==='"')return JSON.parse(raw.slice(begin,i));
   if(c==='\\'){let e=raw[i++];if(e==='u'){if(!/^[0-9a-fA-F]{4}$/.test(raw.slice(i,i+4)))stop('Invalid Unicode escape.');i+=4;}else if(!'"\\/bfnrt'.includes(e))stop('Invalid escape.');}
   else if(c.charCodeAt(0)<32)stop('Invalid JSON control.');}
  stop('Unterminated JSON string.');
 }
 function value(depth){
  if(++steps>60000||depth>40)stop('JSON exceeds bounds.');ws();const c=raw[i];
  if(c==='"')return string();
  if(c==='{'){i++;const result=Object.create(null),seen=new Set();ws();if(raw[i]==='}'){i++;return result;}
   while(true){ws();const key=string();if(seen.has(key))stop('Duplicate JSON field.');seen.add(key);ws();if(raw[i++]!==':')stop('Expected colon.');result[key]=value(depth+1);ws();if(raw[i]==='}'){i++;return result;}if(raw[i++]!==',')stop('Expected comma.');}
  }
  if(c==='['){i++;const result=[];ws();if(raw[i]===']'){i++;return result;}while(true){result.push(value(depth+1));ws();if(raw[i]===']'){i++;return result;}if(raw[i++]!==',')stop('Expected comma.');}}
  for(const [k,v] of [['true',true],['false',false],['null',null]])if(raw.startsWith(k,i)){i+=k.length;return v;}
  const match=raw.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
  if(match){i+=match[0].length;const n=Number(match[0]);if(!Number.isFinite(n))stop('Invalid JSON numeric field.');return n;}
  stop('Malformed JSON value.');
 }
 const result=value(0);ws();if(i!==raw.length)stop('Unexpected trailing JSON.');return result;
}
function saveFile(name,data,type){const blob=new Blob([data],{type}),url=URL.createObjectURL(blob),a=E('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function findById(id){return state.findings.find(f=>f.finding_id===id);}
function humanById(id){return state.cases.find(c=>c.finding_id===id);}
function putSelect(select){select.replaceChildren();for(const f of state.findings){let option=E('option',f.finding_id+' — '+f.title.slice(0,56));option.value=f.finding_id;select.append(option);}}
function renderOwnerFilter(){
 const select=$('owner-filter'),old=select.value;
 ownerLabels=[...new Set(state.cases.map(c=>c.owner).filter(x=>typeof x==='string'&&x.trim().length))].sort();
 select.replaceChildren();
 const add=(value,title)=>{const option=E('option',title);option.value=value;select.append(option);};
 add('all','All original human owners');add('unassigned','(Unassigned human work)');
 ownerLabels.forEach((owner,i)=>add('id:'+i,owner));
 if([...select.options].some(x=>x.value===old))select.value=old;
}
function visibleRow(row,critical){
 const owner=$('owner-filter').value;
 if(owner==='unassigned'&&row.owner.trim())return false;
 if(owner.startsWith('id:')&&ownerLabels[Number(owner.slice(3))]!==row.owner)return false;
 const filter=$('filter').value;
 if(filter==='waiting'&&!row.waiting.length)return false;
 if(filter==='ready'&&!row.human_ready)return false;
 if(filter==='critical'&&!critical.has(row.finding_id))return false;
 if(filter==='urgent'&&!['critical','high'].includes(row.severity))return false;
 return true;
}
function metrics(graph){
 const data=[['Original findings',graph.summary.total],['Human dependency links',graph.summary.links],['Waiting on human work',graph.summary.waiting],['Human work potentially ready',graph.summary.ready],['Critical/high waiting',graph.summary.critical_high_waiting],['Longest estimated chain (days)',graph.estimated_days]];
 const host=$('stats');host.replaceChildren();for(const [label,n] of data){const card=E('div');card.className='stat';card.append(E('strong',n),E('span',label));host.append(card);}
}
function td(row,value){row.append(E('td',value));}
function drawLinks(){
 const body=$('links');body.replaceChildren();
 for(const l of links){const tr=E('tr');td(tr,l.from);td(tr,l.to);td(tr,l.reason);
  const cell=E('td'),button=E('button','Remove');button.type='button';button.className='secondary';
  button.addEventListener('click',()=>{const next=links.filter(x=>x!==l);try{g.LightUpHumanDependencies.clean(state,next,efforts);links=next;dirty=true;revision++;render();$('link-message').textContent='Human dependency removed locally.';}catch(e){$('link-message').textContent='HOLD: '+e.message;}});
  cell.append(button);tr.append(cell);body.append(tr);
 }
 if(!links.length){const tr=E('tr'),cell=E('td','No human dependency links recorded.');cell.colSpan=4;tr.append(cell);body.append(tr);}
}
function drawEfforts(){
 const body=$('efforts');body.replaceChildren();
 for(const f of state.findings){const tr=E('tr'),c=humanById(f.finding_id);
  td(tr,f.finding_id);td(tr,f.severity);td(tr,(c.owner||'Unassigned')+' / '+c.status);
  const cell=E('td'),input=E('input');input.type='number';input.min='1';input.max='90';input.step='1';input.value=efforts.find(e=>e.finding_id===f.finding_id).days;
  input.setAttribute('aria-label','Human estimated days for '+f.finding_id);
  input.addEventListener('change',()=>{
   const n=Number(input.value);const candidate=efforts.map(e=>e.finding_id===f.finding_id?{finding_id:e.finding_id,days:n}:e);
   try{g.LightUpHumanDependencies.clean(state,links,candidate);efforts=candidate;dirty=true;revision++;drawGraph();$('review-message').textContent='Human effort updated locally; not an SLA.';}
   catch(err){input.value=efforts.find(e=>e.finding_id===f.finding_id).days;$('review-message').textContent='HOLD: '+err.message;}
  });cell.append(input);tr.append(cell);body.append(tr);
 }
}
function renderGuidance(view,critical){
 const body=$('bottlenecks');body.replaceChildren();
 const shown=view.bottlenecks.filter(x=>visibleRow(x,critical)).slice(0,20);
 for(const item of shown){
  const tr=E('tr');td(tr,item.finding_id+' / '+item.severity);td(tr,item.downstream_count);
  td(tr,item.human_ready?'Potentially ready for HUMAN planning':'Needs prerequisite / on hold');
  td(tr,item.owner||'(unassigned)');body.append(tr);
 }
 if(!shown.length){const row=E('tr'),cell=E('td','No open human plans.');cell.colSpan=4;row.append(cell);body.append(row);}
 const blocked=$('contradictions');blocked.replaceChildren();
 for(const x of view.contradictions){
  const row=E('tr');td(row,x.from);td(row,x.to);td(row,x.human_prerequisite_due);td(row,x.human_dependent_due);blocked.append(row);
 }
 if(!view.contradictions.length){const row=E('tr'),cell=E('td','No contradiction among existing human due dates.');cell.colSpan=4;row.append(cell);blocked.append(row);}
 const scenarios=$('late-scenarios');scenarios.replaceChildren();
 for(const x of view.hypotheticalLate){
  const row=E('tr');td(row,x.finding_id);td(row,x.existing_human_due);td(row,x.indicative_chain_date);scenarios.append(row);
 }
 if(!view.hypotheticalLate.length){const row=E('tr'),cell=E('td','No indicative conflict, or no human planning start date selected.');cell.colSpan=3;row.append(cell);scenarios.append(row);}
}
function drawGraph(){
 const graph=g.LightUpHumanDependencies.graph(state,links,efforts,$('start').value||null);metrics(graph);renderGuidance(g.LightUpHumanDependencies.guidance(state,links,efforts,$('start').value||null),new Set(graph.critical));
 const body=$('results');body.replaceChildren();const filter=$('filter').value,critical=new Set(graph.critical);
 let n=0;
 for(const item of graph.rows){
  if(!visibleRow(item,critical))continue;
  const tr=E('tr');td(tr,item.finding_id+' / '+item.severity);td(tr,item.human_status+(critical.has(item.finding_id)?' · longest path':''));
  td(tr,item.waiting.length?item.waiting.join(', '):'None');td(tr,item.path_days+' calendar days');
  td(tr,graph.dates?graph.dates[item.finding_id]:'Not proposed');body.append(tr);n++;
 }
 if(!n){const tr=E('tr'),cell=E('td','No original findings match this human filter.');cell.colSpan=5;tr.append(cell);body.append(tr);}
 $('review-message').textContent='Local planning only: '+graph.summary.waiting+' human tasks waiting, '+graph.critical.length+' on longest estimated chain. No original finding or human Casework was changed.';
 $('export-json').disabled=!$('export-ack').checked;$('export-csv').disabled=!$('export-ack').checked;
 return graph;
}
function render(){if(!state)return;drawLinks();drawEfforts();drawGraph();}
async function importOriginal(file){
 if(!file||file.size>LIMIT||!$('source-ack').checked)stop('Choose ≤2 MiB original Casework and confirm private client/engagement.');
 const token=revision,packet=parseStrict(await file.text()),work=await g.LightUpHumanDependencies.original(packet);
 if(token!==revision)stop('Private workspace changed during import.');
 state=work;const blank=g.LightUpHumanDependencies.empty(state);links=blank.links;efforts=blank.efforts;dirty=false;revision++;
 $('workspace').hidden=false;$('export-ack').checked=false;$('start').value='';$('filter').value='all';
 putSelect($('from'));putSelect($('to'));renderOwnerFilter();render();
 $('source-message').textContent=state.findings.length+' original findings loaded from PRIVATE historical Casework. Current consent and identity are unverified.';
}
function clear(){state=null;links=[];efforts=[];dirty=false;revision++;$('workspace').hidden=true;for(const name of ['source','reopen'])$(name).value='';$('source-ack').checked=false;$('export-ack').checked=false;$('source-message').textContent='Private workspace cleared from memory. Previously downloaded files remain outside this browser.';}
$('source').addEventListener('change',async e=>{
 if(dirty&&!g.confirm('Discard unsaved PRIVATE human graph? Export privately before replacing the original Casework.')){e.target.value='';return;}
 try{await importOriginal(e.target.files[0]);}catch(err){$('source-message').textContent='HOLD: '+err.message;}
});
$('link-add').addEventListener('click',()=>{
 if(!state||!$('source-ack').checked)return;
 const next=[...links,{from:$('from').value,to:$('to').value,reason:$('reason').value}];
 try{g.LightUpHumanDependencies.clean(state,next,efforts);links=next;dirty=true;revision++;$('reason').value='';render();$('link-message').textContent='Original-ID human prerequisite recorded in memory.';}
 catch(err){$('link-message').textContent='HOLD: '+err.message;}
});
for(const name of ['filter','start','owner-filter'])$(name).addEventListener('change',()=>{if(state){try{drawGraph();}catch(err){$('review-message').textContent='HOLD: '+err.message;}}});
$('review').addEventListener('click',()=>{if(state){try{drawGraph();}catch(err){$('review-message').textContent='HOLD: '+err.message;}}});
$('export-ack').addEventListener('change',()=>{const ok=!!state&&$('source-ack').checked&&$('export-ack').checked;$('export-json').disabled=!ok;$('export-csv').disabled=!ok;});
$('source-ack').addEventListener('change',()=>{if(!$('source-ack').checked)$('export-ack').checked=false;$('export-json').disabled=!$('source-ack').checked||!$('export-ack').checked;$('export-csv').disabled=$('export-json').disabled;});
$('export-json').addEventListener('click',()=>{
 if(!state||!$('source-ack').checked||!$('export-ack').checked)return;
 try{const data=g.LightUpHumanDependencies.packet(state,links,efforts);
 if(!g.confirm('Export PRIVATE original finding IDs and human dependencies to the independently approved destination? No permission or remediation is verified.'))return;
 saveFile('lightup-PRIVATE-human-dependencies.json',JSON.stringify(data,null,2)+'\n','application/json;charset=utf-8');
 dirty=false;$('export-message').textContent='PRIVATE source-bound human dependency draft exported.';}
 catch(e){$('export-message').textContent='HOLD: '+e.message;}
});
function safeCsv(value){
 let s=String(value??'');
 const invisible=/^[\s\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]*/u;
 if(/^[=+\-@]/.test(s.replace(invisible,'')))s="'"+s;
 return '"'+s.replace(/"/g,'""')+'"';
}
$('export-csv').addEventListener('click',()=>{
 if(!state||!$('source-ack').checked||!$('export-ack').checked)return;
 try{const v=g.LightUpHumanDependencies.graph(state,links,efforts,$('start').value||null);
 if(!g.confirm('Export PRIVATE original finding IDs and HUMAN status/effort/waiting dependencies to the approved destination?'))return;
 const table=[['finding_id','source_severity','source_retest','human_stage','human_owner','human_due','waiting_for_human_ids','estimated_chain_days','indicative_local_date']];
 for(const x of v.rows){if($('csv-scope').value==='filtered'&&!visibleRow(x,new Set(v.critical)))continue;table.push([x.finding_id,x.severity,x.original_retest,x.human_status,x.owner,x.human_due||'',x.waiting.join('; '),x.path_days,v.dates?.[x.finding_id]||'']);}if(table.length<2)stop('No original human tasks match the selected PRIVATE CSV handoff scope.');
 saveFile('lightup-PRIVATE-human-dependency-board.csv',table.map(r=>r.map(safeCsv).join(',')).join('\r\n')+'\r\n','text/csv;charset=utf-8');
 $('export-message').textContent='PRIVATE tentative human action CSV exported. No verified fix, SLA or authorized retest.';}
 catch(e){$('export-message').textContent='HOLD: '+e.message;}
});
$('reopen').addEventListener('change',async e=>{
 try{if(!state||!$('source-ack').checked)stop('Open original Casework first.');
 const current=state,token=revision,file=e.target.files[0];if(!file||file.size>LIMIT)stop('Private dependency draft exceeds 2 MiB.');
 const packet=parseStrict(await file.text());if(token!==revision||state!==current)stop('Source changed while reading private graph.');
 const clean=g.LightUpHumanDependencies.restore(state,packet);
 if(!g.confirm('Replace local HUMAN estimates and prerequisite links from an unsigned, source-bound PRIVATE draft?'))return;
 links=clean.links;efforts=clean.efforts;dirty=true;revision++;render();$('export-message').textContent='Private human dependency draft reopened. Original findings untouched.';}
 catch(err){$('export-message').textContent='HOLD: '+err.message;}
 e.target.value='';
});
$('clear').addEventListener('click',()=>{if(dirty&&!g.confirm('Discard unsaved PRIVATE human dependencies?'))return;clear();});
g.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
})(window);