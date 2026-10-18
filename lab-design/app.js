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
  let items=[],editing=-1,fictional=false;
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
  function render(){
    const v=catalogSummary();
    $("stats").innerHTML="";
    [["Scenarios",v.scenarios],["Numeric lab targets",v.targets],
      ["Explicitly scored",v.scored_scenarios],
      ["Ground-truth planted",v.planted_findings]].forEach(([title,count])=>{
      const span=document.createElement("span");span.className="stat";
      span.textContent=title+": "+count;$("stats").append(span);
    });
    for(const id of ["savePrivate","summary","print"])$(id).disabled=!items.length;
    if(!items.length){$("catalog").innerHTML='<p class="empty">No scenarios yet.</p>';return;}
    $("catalog").innerHTML="";
    const table=document.createElement("table");table.innerHTML=
      "<thead><tr><th>Slot</th><th>Private scenario</th><th>Lab IPs</th><th>Ground truth</th><th>Action</th></tr></thead>";
    const body=document.createElement("tbody");
    items.forEach((item,index)=>{
      const row=document.createElement("tr");
      const content=[String(index+1).padStart(2,"0"),item.name,
        String(item.targets.length),item.expected_findings===null?"Unscored":
          item.expected_findings.length?item.expected_findings.length+" planted":"Scored: zero expected"];
      for(const t of content){const td=document.createElement("td");td.textContent=t;row.append(td);}
      const td=document.createElement("td"),button=document.createElement("button");
      button.type="button";button.className="outline";button.textContent="Edit";
      button.addEventListener("click",()=>edit(index));td.append(button);row.append(td);body.append(row);
    });
    table.append(body);$("catalog").append(table);
  }
  function saveForm(event){
    event.preventDefault();
    try{
      const row=formScenario();const next=[...items];
      fail(editing<0?next.length<32:editing<next.length);
      fail(!next.some((old,index)=>old.scenario_id===row.scenario_id&&index!==editing));
      if(editing<0)next.push(row);else next[editing]=row;
      validateCatalog(documentCatalog(next));items=next;
      notify("editorStatus","Saved private lab scenario (NO EXECUTION).");
      resetEditor();notify("status","Catalog edited locally; exports remain DRAFT_ONLY.");
      render();
    }catch(_){notify("editorStatus","HOLD: invalid, nonprivate, duplicate or incomplete scenario. Catalog unchanged.",true);}
  }
  function deleteScenario(){
    if(editing<0||!items[editing])return;
    if(!confirm("Delete this private lab scenario from local memory?"))return;
    items=items.filter((_,i)=>i!==editing);resetEditor();render();
    notify("status","Selected scenario deleted from local memory.");
  }
  async function importCatalog(file){
    try{
      fail(file&&file.size>0&&file.size<=262144);
      const bytes=await file.arrayBuffer();fail(bytes.byteLength<=262144);
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const next=validateCatalog(parseJSON(raw));
      items=next;fictional=false;resetEditor();render();
      notify("status","Imported "+items.length+" PRIVATE lab scenarios, source untrusted; no target contacted.");
    }catch(_){notify("status","HOLD: malformed, oversized, public-target or forged-authority catalog. Existing work preserved.",true);}
  }
  function demo(){
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
    items=validateCatalog(documentCatalog(next));fictional=true;resetEditor();render();
    notify("status","FICTIONAL DEMO ONLY: invented addresses and findings. No system accessed.");
  }
  function forget(){
    items=[];fictional=false;resetEditor();$("load").value="";
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
  $("editor").addEventListener("submit",saveForm);
  $("clear").addEventListener("click",resetEditor);
  $("delete").addEventListener("click",deleteScenario);
  $("groundMode").addEventListener("change",toggleFindingMode);
  $("demo").addEventListener("click",demo);
  $("forget").addEventListener("click",forget);
  $("load").addEventListener("change",e=>{
    if(e.target.files.length)void importCatalog(e.target.files[0]);
    e.target.value="";
  });
  $("savePrivate").addEventListener("click",savePrivate);
  $("summary").addEventListener("click",saveRedacted);
  $("print").addEventListener("click",()=>{if(items.length)window.print();});
  toggleFindingMode();render();
})();