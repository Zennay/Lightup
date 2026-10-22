"use strict";
// LightUp standalone offline authoring. No fetch, web workers, network or scanner.
(() => {
  const $=id=>document.getElementById(id);
  const KEYS=["schema","status","authorized","consent_verified","dispatch_allowed","release_allowed","scenarios"];
  const SCENARIO_KEYS=["scenario_id","name","description","targets","expected_findings"];
  const FINDING_KEYS=["identifier","title","capability_id","severity"];
  const LEVELS=["critical","high","medium","low","info"];
  const FLAGS=()=>({authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false});
  const RE_TOKEN=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  let items=[],editing=-1,fictional=false,staged=null;
  let catalogReadGeneration=0;
  const invalidateCatalogReads=()=>++catalogReadGeneration;
  const selectedStage=new Set();
  const fail=condition=>{if(!condition)throw Error("Invalid or incompatible PRIVATE lab catalog");};
  const exact=(x,keys)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&
    Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
  const textValue=(x,min,max)=>typeof x==="string"&&x.length>=min&&x.length<=max&&
    x===x.trim()&&/^[\x20-\x7e]*$/.test(x);
  function privateIP(value){
    fail(typeof value==="string"&&value.length<=45&&value===value.trim()&&
      value.length>0&&!/[/%\s]/.test(value));
    if(value.includes(".")){
      fail(!value.includes(":"));
      const groups=value.split(".");
      fail(groups.length===4&&groups.every(n=>/^(?:0|[1-9][0-9]{0,2})$/.test(n)&&Number(n)<=255));
      const [a,b]=groups.map(Number);
      fail(a===127||a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168));
      return value;
    }
    fail(value.includes(":")&&/^[0-9A-Fa-f:]+$/.test(value));
    let parsed;
    try{parsed=new URL("http://["+value+"]/");}catch(_){fail(false);}
    fail(parsed.hostname.startsWith("[")&&parsed.hostname.endsWith("]")&&
      parsed.port===""&&parsed.pathname==="/");
    const first=value.split(":").find(Boolean)||"0";
    const firstNum=parseInt(first,16);
    fail(value==="::1"||value==="0:0:0:0:0:0:0:1"||
      (firstNum>=0xfc00&&firstNum<=0xfdff)||
      (firstNum>=0xfe80&&firstNum<=0xfebf));
    return parsed.hostname.slice(1,-1).toLowerCase();
  }
  function validateScenario(s){
    fail(exact(s,SCENARIO_KEYS)&&RE_TOKEN.test(s.scenario_id)&&
      textValue(s.name,1,160)&&textValue(s.description,0,500)&&
      Array.isArray(s.targets)&&s.targets.length>=1&&s.targets.length<=16);
    const targets=s.targets.map(privateIP);
    fail(new Set(targets).size===targets.length);
    fail(s.expected_findings===null||(Array.isArray(s.expected_findings)&&
      s.expected_findings.length<=64));
    const ids=new Set();
    if(s.expected_findings!==null){
      for(const f of s.expected_findings){
        fail(exact(f,FINDING_KEYS)&&RE_TOKEN.test(f.identifier)&&
          RE_TOKEN.test(f.capability_id)&&textValue(f.title,1,160)&&
          LEVELS.includes(f.severity)&&!ids.has(f.identifier));
        ids.add(f.identifier);
      }
    }
    return {scenario_id:s.scenario_id,name:s.name,description:s.description,
      targets,expected_findings:s.expected_findings===null?null:
        s.expected_findings.map(f=>({...f}))};
  }
  function validateCatalog(data){
    fail(exact(data,KEYS)&&data.schema==="lightup.lab_design_catalog.v1"&&
      data.status==="DRAFT_ONLY"&&
      ["authorized","consent_verified","dispatch_allowed","release_allowed"]
        .every(k=>data[k]===false)&&Array.isArray(data.scenarios)&&
      data.scenarios.length>=1&&data.scenarios.length<=32);
    const seen=new Set(),out=[];
    for(const row of data.scenarios){
      const next=validateScenario(row);
      fail(!seen.has(next.scenario_id));
      seen.add(next.scenario_id);out.push(next);
    }
    return out;
  }
  function parseJSON(raw){
    let pos=0,nodes=0;
    const ws=()=>{while(pos<raw.length&&/\s/.test(raw[pos]))pos++;};
    function quote(){
      fail(raw[pos]==='"');const begin=pos++;let escape=false;
      while(pos<raw.length){const c=raw[pos++];
        if(c==='"'&&!escape)return JSON.parse(raw.slice(begin,pos));
        if(c==="\\"&&!escape)escape=true;else escape=false;
      }fail(false);
    }
    function val(depth){
      fail(depth<24&&++nodes<25000);ws();const c=raw[pos];
      if(c==='"')return quote();
      if(c==="{"){
        pos++;ws();const obj=Object.create(null),seen=new Set();
        if(raw[pos]==="}"){pos++;return obj;}
        for(;;){ws();const key=quote();fail(!seen.has(key));seen.add(key);
          ws();fail(raw[pos++]===":");obj[key]=val(depth+1);ws();
          if(raw[pos]==="}"){pos++;return obj;}fail(raw[pos++]===",");
        }
      }
      if(c==="["){
        pos++;ws();const out=[];if(raw[pos]==="]"){pos++;return out;}
        for(;;){out.push(val(depth+1));fail(out.length<=5000);ws();
          if(raw[pos]==="]"){pos++;return out;}fail(raw[pos++]===",");}
      }
      for(const [lit,v] of [["true",true],["false",false],["null",null]]){
        if(raw.startsWith(lit,pos)){pos+=lit.length;return v;}
      }
      const match=raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      fail(!!match);pos+=match[0].length;
      const v=Number(match[0]);fail(Number.isFinite(v));return v;
    }
    const result=val(0);ws();fail(pos===raw.length);return result;
  }
  function documentCatalog(scenarios=items){
    return {schema:"lightup.lab_design_catalog.v1",status:"DRAFT_ONLY",...FLAGS(),
      scenarios:scenarios.map(s=>({scenario_id:s.scenario_id,name:s.name,
        description:s.description,targets:[...s.targets],
        expected_findings:s.expected_findings===null?null:
          s.expected_findings.map(f=>({...f}))}))};
  }
  function notify(id,msg,bad=false){$(id).textContent=msg;$(id).style.color=bad?"#ff9a9a":"";}
  function resetEditor(){
    editing=-1;$("editor").reset();$("save").textContent="Add scenario";
    $("delete").disabled=true;toggleFindingMode();notify("editorStatus","");
  }
  function toggleFindingMode(){
    $("findingsWrap").hidden=$("groundMode").value!=="planted";
  }
  function edit(index){
    const s=items[index];if(!s)return;
    editing=index;$("scenarioId").value=s.scenario_id;$("scenarioName").value=s.name;
    $("targets").value=s.targets.join("\n");$("description").value=s.description;
    $("groundMode").value=s.expected_findings===null?"unscored":
      s.expected_findings.length?"planted":"zero";
    $("findings").value=(s.expected_findings||[]).map(f=>
      [f.identifier,f.title,f.capability_id,f.severity].join(" | ")).join("\n");
    toggleFindingMode();$("save").textContent="Save changes";
    $("delete").disabled=false;notify("editorStatus","Editing private catalog scenario "+(index+1));
    $("composer").scrollIntoView({behavior:"smooth",block:"start"});
  }
  function formScenario(){
    const ground=$("groundMode").value;
    const raw=$("findings").value.trim();
    let expected=null;
    if(ground==="zero")expected=[];
    if(ground==="planted"){
      const lines=raw.split(/\r?\n/);fail(lines.length>=1&&lines.length<=64);
      expected=lines.map(line=>{
        const parts=line.split("|").map(v=>v.trim());fail(parts.length===4);
        const [identifier,title,capability_id,severity]=parts;
        return {identifier,title,capability_id,severity};
      });
    }
    const targets=$("targets").value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
    return validateScenario({scenario_id:$("scenarioId").value.trim(),
      name:$("scenarioName").value.trim(),description:$("description").value.trim(),
      targets,expected_findings:expected});
  }
  function catalogSummary(){
    let targets=0,scored=0,unscored=0,planted=0,ipsv6=0;
    const counts=Object.fromEntries(LEVELS.map(n=>[n,0]));
    for(const s of items){
      targets+=s.targets.length;ipsv6+=s.targets.filter(t=>t.includes(":")).length;
      if(s.expected_findings===null)unscored++;
      else{scored++;planted+=s.expected_findings.length;
        for(const f of s.expected_findings)counts[f.severity]++;}
    }
    return {scenarios:items.length,targets,ipv6_targets:ipsv6,
      scored_scenarios:scored,unscored_scenarios:unscored,
      planted_findings:planted,findings_by_severity:counts};
  }
  function renderCoverage(){
    const view=$("coverage");view.innerHTML="";
    const entries=new Map();let unscored=0,zero=0;
    items.forEach((row,index)=>{
      if(row.expected_findings===null){unscored++;return;}
      if(row.expected_findings.length===0)zero++;
      for(const f of row.expected_findings){
        if(!entries.has(f.capability_id))entries.set(f.capability_id,
          {count:0,scenarios:new Set(),severity:Object.fromEntries(LEVELS.map(n=>[n,0]))});
        const state=entries.get(f.capability_id);
        state.count++;state.scenarios.add(index+1);state.severity[f.severity]++;
      }
    });
    const p=document.createElement("p");
    p.textContent=entries.size+" declared capability IDs · "+unscored+
      " unscored scenarios · "+zero+" explicitly zero-ground-truth scenarios. "+
      "No inference about missing or real-world coverage.";
    view.append(p);
    if(!entries.size)return;
    const table=document.createElement("table");
    table.innerHTML="<thead><tr><th>Private capability ID</th><th>Planted findings</th>"+
      "<th>Human scenario slots</th><th>Declared severity mix</th></tr></thead>";
    const body=document.createElement("tbody");
    for(const [key,value] of [...entries].sort(([a],[b])=>a.localeCompare(b))){
      const row=document.createElement("tr");
      const vals=[key,String(value.count),[...value.scenarios].sort((a,b)=>a-b).join(", "),
        LEVELS.filter(n=>value.severity[n]).map(n=>n+" "+value.severity[n]).join(" · ")];
      for(const val of vals){const td=document.createElement("td");
        td.textContent=val;row.append(td);}
      body.append(row);
    }
    table.append(body);view.append(table);
  }
  function visibleCatalog(){
    const query=$("catalogSearch").value.trim().toLowerCase();
    const mode=$("catalogMode").value,severity=$("catalogSeverity").value;
    return items.map((item,index)=>({item,index})).filter(({item})=>{
      const truth=item.expected_findings;
      if(mode==="unscored"&&truth!==null)return false;
      if(mode==="zero"&&(truth===null||truth.length!==0))return false;
      if(mode==="planted"&&(!truth||!truth.length))return false;
      if(severity!=="all"&&(!truth||!truth.some(f=>f.severity===severity)))return false;
      if(query&&!([item.scenario_id,item.name,...(truth||[]).map(f=>f.capability_id)]
        .some(value=>value.toLowerCase().includes(query))))return false;
      return true;
    });
  }
  function saveFiltered(){
    const result=visibleCatalog().map(x=>x.item);
    if(!result.length){notify("status","No matching PRIVATE scenario to export.",true);return;}
    try{
      validateCatalog(documentCatalog(result));
      if(!confirm("Download "+result.length+
        " PRIVATE source scenarios including target addresses and expected findings?"))return;
      download(fictional?"lightup-FICTIONAL-private-subset.json":
        "lightup-PRIVATE-lab-scenario-subset.json",
        JSON.stringify(documentCatalog(result),null,2)+"\n","application/json");
      notify("exportStatus","Selected PRIVATE lab subset downloaded. Protect original target addresses.");
    }catch(_){notify("status","HOLD: filtered source subset failed canonical admission.",true);}
  }
  function render(){
    const v=catalogSummary();
    $("stats").innerHTML="";
    $("printSummary").textContent="REVIEW ONLY / DRAFT_ONLY / no permissions. Scored scenarios: "+
      v.scored_scenarios+"; unscored: "+v.unscored_scenarios+
      "; planted: "+v.planted_findings+
      "; severity totals: "+LEVELS.map(n=>n+" "+v.findings_by_severity[n]).join(", ")+
      ". No finding or target identity is shown. ABSENT is not remediation.";
    [["Scenarios",v.scenarios],["Numeric lab targets",v.targets],
      ["Explicitly scored",v.scored_scenarios],
      ["Ground-truth planted",v.planted_findings]].forEach(([title,count])=>{
      const span=document.createElement("span");span.className="stat";
      span.textContent=title+": "+count;$("stats").append(span);
    });
    for(const id of ["savePrivate","summary","brief","runbook","print"])$(id).disabled=!items.length;
    $("appendCatalog").disabled=!items.length||items.length>=32||fictional;
    renderCoverage();
    const visible=visibleCatalog();
    $("exportFiltered").disabled=!visible.length;
    $("filterSummary").textContent=visible.length+" matching PRIVATE scenario(s) of "+
      items.length+". Filters never change the underlying catalog or ground truth.";
    if(!items.length){$("catalog").innerHTML='<p class="empty">No scenarios yet.</p>';return;}
    if(!visible.length){$("catalog").innerHTML='<p class="empty">No PRIVATE scenarios match the current filters.</p>';return;}
    $("catalog").innerHTML="";
    const table=document.createElement("table");table.innerHTML=
      "<thead><tr><th>Slot</th><th>Private scenario</th><th>Lab IPs</th><th>Ground truth</th><th>Action</th></tr></thead>";
    const body=document.createElement("tbody");
    visible.forEach(({item,index})=>{
      const row=document.createElement("tr");
      const content=[String(index+1).padStart(2,"0"),item.name,
        String(item.targets.length),item.expected_findings===null?"Unscored":
          item.expected_findings.length?item.expected_findings.length+" planted":"Scored: zero expected"];
      for(const t of content){const td=document.createElement("td");td.textContent=t;row.append(td);}
      const td=document.createElement("td");
      for(const [label,click,disabled] of [
        ["Edit",()=>edit(index),false],
        ["Up",()=>moveScenario(index,-1),index===0],
        ["Down",()=>moveScenario(index,1),index===items.length-1],
        ["Copy unscored",()=>cloneScenario(index),items.length>=32]]){
        const button=document.createElement("button");
        button.type="button";button.className="outline";
        button.textContent=label;button.disabled=disabled;
        button.addEventListener("click",click);td.append(button);
      }
      row.append(td);body.append(row);
    });
    table.append(body);$("catalog").append(table);
  }
  function moveScenario(index,direction){
    const target=index+direction;
    if(index<0||index>=items.length||target<0||target>=items.length)return;
    const next=[...items];[next[index],next[target]]=[next[target],next[index]];
    validateCatalog(documentCatalog(next));
    clearStage();items=next;
    if(editing===index)editing=target;
    else if(editing===target)editing=index;
    render();notify("status","PRIVATE lab scenario order changed; no runtime execution.");
  }
  function cloneScenario(index){
    if(index<0||index>=items.length||items.length>=32)return;
    const original=items[index];
    let newId=null;
    for(let n=1;n<=99;n++){
      const suffix="-copy-"+n;
      const candidate=original.scenario_id.slice(0,64-suffix.length)+suffix;
      if(!items.some(r=>r.scenario_id===candidate)){newId=candidate;break;}
    }
    if(!newId){notify("status","HOLD: no available duplicate scenario ID.",true);return;}
    const replica=validateScenario({...original,
      scenario_id:newId,name:("COPY: "+original.name).slice(0,160),
      targets:[...original.targets],
      // Never automatically claim planted or zero ground truth on a copy.
      expected_findings:null});
    const next=[...items,replica];
    validateCatalog(documentCatalog(next));
    clearStage();items=next;render();
    notify("status","PRIVATE copy created as UNSCORED. Review and enter fresh ground truth before using.");
  }
  function saveForm(event){
    event.preventDefault();
    invalidateCatalogReads();
    try{
      const row=formScenario();const next=[...items];
      fail(editing<0?next.length<32:editing<next.length);
      fail(!next.some((old,index)=>old.scenario_id===row.scenario_id&&index!==editing));
      if(editing<0)next.push(row);else next[editing]=row;
      validateCatalog(documentCatalog(next));clearStage();items=next;
      notify("editorStatus","Saved private lab scenario (NO EXECUTION).");
      resetEditor();notify("status","Catalog edited locally; exports remain DRAFT_ONLY.");
      render();
    }catch(_){notify("editorStatus","HOLD: invalid, nonprivate, duplicate or incomplete scenario. Catalog unchanged.",true);}
  }
  function deleteScenario(){
    if(editing<0||!items[editing])return;
    if(!confirm("Delete this private lab scenario from local memory?"))return;
    clearStage();items=items.filter((_,i)=>i!==editing);resetEditor();render();
    notify("status","Selected scenario deleted from local memory.");
  }
  function clearStage(invalidate=true){
    if(invalidate)invalidateCatalogReads();
    selectedStage.clear();staged=null;$("staging").hidden=true;$("stageRows").replaceChildren();
    $("stageSummary").textContent="";
  }
  function showStage(){
    if(!staged){clearStage();return;}
    selectedStage.clear();
    const earlier=new Map(items.map(r=>[r.scenario_id,r]));
    const after=new Map(staged.map(r=>[r.scenario_id,r]));
    const changes=[];
    for(const [id,row] of after){
      const old=earlier.get(id);
      const status=!old?"ADDED":JSON.stringify(old)===JSON.stringify(row)?"UNCHANGED":"CHANGED";
      const detail=!old?"New private design":
        status==="UNCHANGED"?"Same declared source fields":
        ["name","description","targets","expected_findings"].filter(key=>
          JSON.stringify(old[key])!==JSON.stringify(row[key])).join(", ")+" changed";
      changes.push([id,status,detail]);
    }
    for(const id of earlier.keys())if(!after.has(id))
      changes.push([id,"ABSENT (not fixed)","Absent from imported source; retained by selective merge"]);
    $("staging").hidden=false;
    $("mergeStage").disabled=fictional;
    $("stageSummary").textContent="Current "+items.length+" scenarios → proposed "+
      staged.length+". "+changes.filter(([,s])=>s==="ADDED").length+" added; "+
      changes.filter(([,s])=>s==="CHANGED").length+" changed; "+
      changes.filter(([,s])=>s.startsWith("ABSENT")).length+" absent. "+
      (fictional?"Selective merge disabled for fictional demo. ":"")+
      "No imported row is applied automatically.";
    const table=document.createElement("table");
    table.innerHTML="<thead><tr><th>Select</th><th>PRIVATE ID</th><th>Change</th><th>Source fields</th></tr></thead>";
    const body=document.createElement("tbody");
    for(const [id,status,detail] of changes.sort(([a],[b])=>a.localeCompare(b))){
      const row=document.createElement("tr"),td=document.createElement("td");
      if((status==="ADDED"||status==="CHANGED")&&!fictional){
        const input=document.createElement("input");
        input.type="checkbox";input.title="Select PRIVATE scenario for local merge";
        input.addEventListener("change",()=>{
          if(input.checked)selectedStage.add(id);else selectedStage.delete(id);
        });
        td.append(input);
      }else td.textContent="—";
      row.append(td);
      for(const value of [id,status,detail]){
        const cell=document.createElement("td");cell.textContent=value;row.append(cell);
      }
      body.append(row);
    }
    table.append(body);$("stageRows").replaceChildren(table);
  }
  function mergeStage(){
    if(!staged||fictional||!selectedStage.size){
      notify("status","Select one or more ADDED/CHANGED non-fictional source entries.",true);return;
    }
    try{
      const old=new Map(items.map(r=>[r.scenario_id,r]));
      const imported=new Map(staged.map(r=>[r.scenario_id,r]));
      fail([...selectedStage].every(id=>{
        const row=imported.get(id);return row&&
          (!old.has(id)||JSON.stringify(old.get(id))!==JSON.stringify(row));
      }));
      const merged=items.map(row=>selectedStage.has(row.scenario_id)?
        imported.get(row.scenario_id):row);
      for(const candidate of staged){
        if(selectedStage.has(candidate.scenario_id)&&!old.has(candidate.scenario_id))
          merged.push(candidate);
      }
      const result=validateCatalog(documentCatalog(merged));
      if(!confirm("Apply "+selectedStage.size+
        " selected private scenario additions/updates, without deleting existing rows?"))return;
      const count=selectedStage.size;
      clearStage();items=result;resetEditor();render();
      notify("status","Applied "+count+
        " selected source entries. All other private scenarios retained; no execution.");
    }catch(_){
      notify("status","HOLD: selection conflict or scenario limit exceeded. Existing catalog preserved.",true);
    }
  }
  function acceptStage(){
    if(!staged)return;
    if(items.length&&!confirm("Replace the current PRIVATE catalog with the reviewed source?"))return;
    items=staged;fictional=false;clearStage();resetEditor();render();
    notify("status","Explicitly accepted staged PRIVATE catalog. No target contacted.");
  }
  async function importCatalog(file){
    const ticket=invalidateCatalogReads();
    try{
      fail(file&&file.size>0&&file.size<=262144);
      const bytes=await file.arrayBuffer();
      if(ticket!==catalogReadGeneration)return;
      fail(bytes.byteLength>0&&bytes.byteLength<=262144);
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const next=validateCatalog(parseJSON(raw));
      if(ticket!==catalogReadGeneration)return;
      staged=next;showStage();
      notify("status","Validated candidate imported for HUMAN comparison only; existing catalog unchanged.");
    }catch(_){
      if(ticket===catalogReadGeneration)
        notify("status","HOLD: malformed, oversized, public-target or forged-authority catalog. Existing work preserved.",true);
    }
  }
  async function appendCatalog(file){
    const ticket=invalidateCatalogReads();
    try{
      fail(!fictional&&items.length>=1&&items.length<32&&
        file&&file.size>0&&file.size<=262144);
      const bytes=await file.arrayBuffer();
      if(ticket!==catalogReadGeneration)return;
      fail(bytes.byteLength>0&&bytes.byteLength<=262144);
      const source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const incoming=validateCatalog(parseJSON(source));
      if(ticket!==catalogReadGeneration)return;
      const together=[...items,...incoming];
      const next=validateCatalog(documentCatalog(together));
      if(ticket!==catalogReadGeneration)return;
      clearStage(false);items=next;render();
      notify("status","Appended "+incoming.length+
        " privately authored scenarios. Existing editor work preserved; no target accessed.");
    }catch(_){
      if(ticket===catalogReadGeneration)
        notify("status","HOLD: duplicated ID, invalid source or over-capacity append. Prior catalog preserved.",true);
    }
  }
  function originalProfiles(){
    invalidateCatalogReads();
    try{
      const pack=globalThis.LightUpOriginalFixturePack;
      fail(pack&&pack.version==="lightup.installed_fixture_pack.v1"&&
        pack.status==="DRAFT_ONLY"&&pack.source_identity_authenticated===false&&
        pack.fixture_started===false&&pack.built_in_fixtures_only===true&&
        ["authorized","consent_verified","dispatch_allowed","release_allowed"]
          .every(k=>pack[k]===false));
      const source=pack.source_sha256;
      fail(source&&typeof source==="object"&&!Array.isArray(source)&&
        Object.keys(source).length===2&&Object.values(source).every(
          value=>typeof value==="string"&&/^[a-f0-9]{64}$/.test(value)));
      staged=validateCatalog(pack.catalog);
      showStage();
      notify("status","ORIGINAL source declarations bundled at build time: "+
        staged.length+" named fixture profiles staged, not applied. "+
        "Source SHA-256 values are UNSIGNED byte fingerprints; no fixture or scan started.");
    }catch(_){
      notify("status","HOLD: bundled source declarations unavailable or malformed. Existing catalog preserved.",true);
    }
  }
  function demo(){
    if(items.length&&!confirm("Replace existing PRIVATE catalog with fictional demo? Save your original first."))return;
    const next=[
      {scenario_id:"fictional-login",name:"FICTIONAL isolated login fixture",
        description:"Invented lab only. No reachable service assumed.",
        targets:["127.0.0.1"],expected_findings:[
          {identifier:"mock-auth-1",title:"Fictional cookie policy",capability_id:"lab.web.mock",severity:"medium"}]},
      {scenario_id:"fictional-api",name:"FICTIONAL IPv6 API fixture",
        description:"Invented no-network setup; scored zero planted findings.",
        targets:["::1"],expected_findings:[]},
      {scenario_id:"fictional-private",name:"FICTIONAL private scoring exercise",
        description:"Invented private IPv4 example; metrics unspecified.",
        targets:["10.20.0.7"],expected_findings:null}
    ];
    clearStage();items=validateCatalog(documentCatalog(next));fictional=true;resetEditor();render();
    notify("status","FICTIONAL DEMO ONLY: invented addresses and findings. No system accessed.");
  }
  function forget(){
    if(items.length&&!confirm("Forget all PRIVATE lab scenarios from this browser session? Download a private backup first."))return;
    clearStage();items=[];fictional=false;resetEditor();$("load").value="";
    render();notify("status","Catalog forgotten from this browser session.");
  }
  function download(name,source,type){
    const url=URL.createObjectURL(new Blob([source],{type}));
    const link=document.createElement("a");link.href=url;link.download=name;
    document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),2500);
  }
  function redacted(){
    const info=catalogSummary();
    return {schema:"lightup.lab_design_redacted_review.v1",status:"REVIEW_ONLY",
      fictional_demo_only:fictional,
      disclaimer:"Unsigned, manually authored lab-only assumptions. No target access, consent, scan, grant, or release.",
      ...FLAGS(),aggregate:info};
  }
  function savePrivate(){
    try{validateCatalog(documentCatalog());
      download("lightup-PRIVATE-lab-design-catalog.json",
        JSON.stringify(documentCatalog(),null,2)+"\n","application/json");
      notify("exportStatus","PRIVATE catalog downloaded. Protect original lab target and finding details.");
    }catch(_){notify("exportStatus","HOLD: nothing canonical to export.",true);}
  }
  function saveRedacted(){
    if(!items.length)return;
    download("lightup-lab-design-REVIEW-ONLY.json",
      JSON.stringify(redacted(),null,2)+"\n","application/json");
    notify("exportStatus","Redacted summary downloaded; original targets and finding identifiers omitted.");
  }
  $("acceptStage").addEventListener("click",acceptStage);
  $("mergeStage").addEventListener("click",mergeStage);
  $("rejectStage").addEventListener("click",()=>{
    clearStage();notify("status","Staged replacement discarded; original catalog preserved.");
  });
  function saveRunbook(){
    if(!items.length)return;
    if(!confirm("Download a PRIVATE runbook including lab IP addresses, scenario IDs and expected findings?"))return;
    try{validateCatalog(documentCatalog());}catch(_){
      notify("exportStatus","HOLD: invalid private catalog; no runbook generated.",true);return;
    }
    const esc=value=>String(value).replace(/[&<>"']/g,c=>
      ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
    const style="body{font:15px/1.6 system-ui,sans-serif;color:#18303a;max-width:980px;margin:30px auto;padding:0 24px}"+
      "h1,h2,h3{color:#153b4d}h1{font-size:2rem}.warn{padding:12px;border-left:5px solid #b44040;background:#fff2f2}"+
      ".page{page-break-before:always;border-top:2px solid #346273;margin-top:32px;padding-top:24px}"+
      "table{width:100%;border-collapse:collapse}th,td{border:1px solid #b4c2c8;padding:8px;text-align:left;vertical-align:top}"+
      "th{background:#e9f1f5}.tick{list-style-type:square}.small{font-size:.82rem}";
    const paper=items.map((row,index)=>{
      const mode=row.expected_findings===null?"UNSCORED — no ground truth assumed":
        row.expected_findings.length?"PLANTED findings — unverified source declaration":
        "SCORED ZERO — explicit original ground truth";
      const facts=row.expected_findings===null?"<p>No expected findings provided; this is NOT a negative result.</p>":
        !row.expected_findings.length?"<p>Explicit zero planted findings. Not proof of a clean target.</p>":
        "<table><thead><tr><th>Declared check</th><th>Title</th><th>Capability</th><th>Severity</th></tr></thead><tbody>"+
        row.expected_findings.map(f=>"<tr><td>"+esc(f.identifier)+"</td><td>"+esc(f.title)+
          "</td><td>"+esc(f.capability_id)+"</td><td>"+esc(f.severity)+"</td></tr>").join("")+
        "</tbody></table>";
      return "<section class='page'><h2>Scenario "+(index+1)+": "+esc(row.name)+"</h2>"+
        "<p><b>Private original ID:</b> "+esc(row.scenario_id)+"</p>"+
        "<p><b>Declared IP literals (not a permission grant):</b> "+row.targets.map(esc).join(", ")+"</p>"+
        "<p><b>Design notes:</b> "+esc(row.description||"None supplied")+"</p>"+
        "<p><b>Ground truth mode:</b> "+esc(mode)+"</p>"+facts+
        "<h3>Human discussion worksheet</h3><ul class='tick'>"+
        "<li>Confirm source/fixture identity independently: __________________</li>"+
        "<li>Confirm isolated environment owner and purpose: __________________</li>"+
        "<li>Review ground truth with lab author, or leave unscored: __________________</li>"+
        "<li>Record revised catalog privately if assumptions change: __________________</li>"+
        "<li>Keep real client/operator consent, at-use revocation and scan authority external.</li>"+
        "</ul><p class='small'>PRIVATE LAB PLAN ONLY. No scan, grant, dispatch, retest, authorization or release.</p></section>";
    }).join("");
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'none'; connect-src 'none';"+
      " img-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"+
      "<title>PRIVATE LightUp lab scenario workbook</title><style>"+style+"</style></head><body>"+
      "<h1>PRIVATE LightUp / lab scenario workbook</h1>"+
      "<p class='warn'><b>"+(fictional?"FICTIONAL DEMO":"UNVERIFIED HUMAN LAB PLANNING")+
      "</b> · INCUBATE M3/M7 · DRAFT/HOLD. Authorized: false. Consent verified: false."+
      " Dispatch allowed: false. Release allowed: false. This contains sensitive declared targets."+
      " It cannot start a fixture or assess a real asset.</p>"+
      "<p>Scenarios: "+items.length+". Ordered slot numbers are not authenticated chronology or priority."+
      " All findings are declared expectations only; none were scanned or reproduced.</p>"+paper+
      "<p>Original security, distinct client/operator consent and revocation-at-use, independent review,"+
      " full exact-HEAD required hosted and registered VPS CI and explicit HUMAN GO remain mandatory.</p></body></html>";
    download("lightup-PRIVATE-lab-scenario-workbook.html",html,"text/html");
    notify("exportStatus","PRIVATE full lab workbook saved; target IPs and finding identities INCLUDED.");
  }
  function saveBrief(){
    if(!items.length)return;
    const v=catalogSummary();
    const style="body{font:16px/1.5 system-ui,sans-serif;margin:35px auto;max-width:900px;"+
      "padding:0 16px;color:#223}h1{color:#153850}table{border-collapse:collapse;width:100%}"+
      "td,th{border:1px solid #bbcbd0;padding:9px;text-align:left}"+
      ".warning{border-left:5px solid #a44;padding:12px;background:#fff1f1}";
    const rows=[["Scenarios",v.scenarios],["Private target count (no addresses)",v.targets],
      ["IPv6 target count",v.ipv6_targets],["Scored with explicit ground truth",v.scored_scenarios],
      ["Unscored (not zero)",v.unscored_scenarios],["Planted lab findings",v.planted_findings],
      ...LEVELS.map(n=>[n+" planted finding count",v.findings_by_severity[n]])];
    const table=rows.map(([label,count])=>"<tr><td>"+label+"</td><td>"+count+"</td></tr>").join("");
    const kind=fictional?"FICTIONAL DEMO ONLY":"UNVERIFIED MANUALLY AUTHORED LAB DRAFT";
    const html="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'none';"+
      " connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"+
      "<title>LightUp lab design · REVIEW ONLY</title><style>"+style+"</style></head><body>"+
      "<h1>LightUp / human lab design summary</h1><p class='warning'><strong>"+kind+
      "</strong>. INCUBATE M3/M7 · DRAFT/HOLD. Authorized false; consent verified false;"+
      " dispatch allowed false; release allowed false. NO SCAN OR RELEASE.</p>"+
      "<p>Private scenario identifiers, target IPs, descriptions, titles, planted finding identities"+
      " and capability IDs are intentionally excluded.</p><table><thead><tr><th>Human topic</th>"+
      "<th>Unverified count</th></tr></thead><tbody>"+table+"</tbody></table>"+
      "<p>Source data is manually authored, unsigned and not proof of original lab"+
      " provenance, coverage, safety, remediation, authority or approval.</p></body></html>";
    download("lightup-lab-design-REVIEW-ONLY-brief.html",html,"text/html");
    notify("exportStatus","Redacted no-script, no-network HTML brief downloaded.");
  }
  for(const id of ["catalogSearch","catalogMode","catalogSeverity"]){
    $(id).addEventListener("input",render);
    $(id).addEventListener("change",render);
  }
  $("clearFilters").addEventListener("click",()=>{
    $("catalogSearch").value="";$("catalogMode").value="all";
    $("catalogSeverity").value="all";render();
  });
  $("exportFiltered").addEventListener("click",saveFiltered);
  $("editor").addEventListener("submit",saveForm);
  $("clear").addEventListener("click",resetEditor);
  $("delete").addEventListener("click",deleteScenario);
  $("groundMode").addEventListener("change",toggleFindingMode);
  $("originalProfiles").addEventListener("click",originalProfiles);
  $("demo").addEventListener("click",demo);
  $("forget").addEventListener("click",forget);
  $("appendCatalog").addEventListener("change",e=>{
    if(e.target.files.length)void appendCatalog(e.target.files[0]);
    e.target.value="";
  });
  $("load").addEventListener("change",e=>{
    if(e.target.files.length)void importCatalog(e.target.files[0]);
    e.target.value="";
  });
  $("savePrivate").addEventListener("click",savePrivate);
  $("summary").addEventListener("click",saveRedacted);
  $("brief").addEventListener("click",saveBrief);
  $("runbook").addEventListener("click",saveRunbook);
  $("print").addEventListener("click",()=>{if(items.length)window.print();});
  toggleFindingMode();render();
})();