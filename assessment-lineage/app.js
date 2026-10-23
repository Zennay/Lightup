"use strict";
/* LightUp Assessment Lineage Desk: offline, untrusted, non-authorizing, read-only. */
(() => {
  const $ = id => document.getElementById(id);
  const METRICS = ["valid_findings","invalid_findings","missed_findings","coverage_assessed",
    "coverage_unknown","scope_violations","policy_violations","human_interventions",
    "tool_calls","evidence_quality","reproducibility","remediation_quality",
    "retest_correctness","runtime_seconds","compute_cost_usd"];
  const COUNTS = new Set(METRICS.slice(0,9));
  const SCORES = new Set(METRICS.slice(9,13));
  const HIGH = new Set(["valid_findings","coverage_assessed","evidence_quality",
    "reproducibility","remediation_quality","retest_correctness"]);
  const LOW = new Set(["invalid_findings","missed_findings","scope_violations","policy_violations"]);
  const FLAGS = ["authorized","consent_verified","dispatch_allowed","release_allowed"];
  const LEVELS = ["critical","high","medium","low","info"];
  const STAGES = ["needs_review","in_discussion","documented"];
  const ROUTES = ["unrouted","source_owner","scope_policy","finding_quality",
    "evidence_scoring","operations"];
  const ACTIONS = ["verify_original_source","request_original_evidence",
    "discuss_lab_method","document_human_followup","none_recorded"];
  const ROUTE_LABELS = {
    unrouted:"Not routed",source_owner:"Original source owner",
    scope_policy:"Scope / policy reviewer",finding_quality:"Findings / coverage reviewer",
    evidence_scoring:"Evidence / scoring reviewer",operations:"Operations reviewer"
  };
  const ACTION_LABELS = {
    verify_original_source:"Verify original source files",
    request_original_evidence:"Request original supporting evidence",
    discuss_lab_method:"Discuss lab method with source owner",
    document_human_followup:"Document human follow-up",
    none_recorded:"No next human action recorded"
  };
  const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const MAX_CATALOG = 1048576, MAX_REPORT = 262144;
  let catalog=null, reports=[], reviews=new Map(), humanNotes=new Map(), noteScratch=new Map(), humanRoutes=new Map(), humanActions=new Map(), fictional=false;
  let mismatchRevealed=false,undoRouteBatch=null;
  let catalogHash=null, reportHashes=[];
  // Each async PRIVATE local intake belongs to one current user decision.
  // Old file completions cannot resurrect forgotten source data or old HUMAN plans.
  let importGeneration=0;
  const startImport=()=>++importGeneration;
  const cancelOldImports=()=>{importGeneration++;};
  const admitCurrent=generation=>admit(generation===importGeneration);
  function admit(ok){if(!ok)throw Error("Incompatible or unsafe private source");}
  function exact(v,keys){return v!==null && typeof v==="object" && !Array.isArray(v) &&
    Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));}
  function finite(v){return typeof v==="number" && Number.isFinite(v);}
  function approx(a,b){return Math.abs(a-b)<=Math.max(1,Math.abs(a),Math.abs(b))*1e-8;}
  function ascii(v,min,max){return typeof v==="string" && v.length>=min && v.length<=max &&
    v===v.trim() && /^[\x20-\x7e]*$/.test(v);}
  function sourceId(v){return ascii(v,1,256);}
  function flags(v){return FLAGS.every(k=>v[k]===false);}
  // Strict bounded JSON parser: duplicate decoded keys rejected, including \u escapes.
  function parse(raw){
    let pos=0,nodes=0;
    const ws=()=>{while(pos<raw.length && /\s/.test(raw[pos]))pos++;};
    function quoted(){
      admit(raw[pos]==='"');const start=pos++;let escaped=false;
      while(pos<raw.length){
        const c=raw[pos++];
        if(c==='"'&&!escaped)return JSON.parse(raw.slice(start,pos));
        if(c==="\\"&&!escaped)escaped=true;else escaped=false;
      }admit(false);
    }
    function value(depth){
      admit(depth<=28 && ++nodes<=70000);ws();const c=raw[pos];
      if(c==='"')return quoted();
      if(c==="{"){
        pos++;ws();const v=Object.create(null),seen=new Set();
        if(raw[pos]==="}"){pos++;return v;}
        for(;;){
          ws();const key=quoted();admit(!seen.has(key));seen.add(key);
          ws();admit(raw[pos++] === ":");v[key]=value(depth+1);ws();
          if(raw[pos]==="}"){pos++;return v;}admit(raw[pos++] === ",");
        }
      }
      if(c==="["){
        pos++;ws();const arr=[];
        if(raw[pos]==="]"){pos++;return arr;}
        for(;;){
          arr.push(value(depth+1));admit(arr.length<=70000);ws();
          if(raw[pos]==="]"){pos++;return arr;}admit(raw[pos++] === ",");
        }
      }
      for(const [token,val] of [["true",true],["false",false],["null",null]]){
        if(raw.startsWith(token,pos)){pos+=token.length;return val;}
      }
      const n=raw.slice(pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      admit(!!n);pos+=n[0].length;const v=Number(n[0]);admit(finite(v));return v;
    }
    const result=value(0);ws();admit(pos===raw.length);return result;
  }
  function privateIP(value){
    admit(typeof value==="string"&&value.length<=45&&value===value.trim()&&
      value.length>0&&!/[/%\s]/.test(value));
    if(value.includes(".")){
      admit(!value.includes(":"));
      const p=value.split(".");
      admit(p.length===4&&p.every(n=>/^(?:0|[1-9][0-9]{0,2})$/.test(n)&&Number(n)<=255));
      const [a,b]=p.map(Number);
      admit(a===127||a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168));
      return value;
    }
    admit(value.includes(":")&&/^[0-9a-fA-F:]+$/.test(value));
    let url;try{url=new URL("http://["+value+"]/");}catch(_){admit(false);}
    const head=value.split(":").find(Boolean)||"0",first=parseInt(head,16);
    admit(url.hostname.startsWith("[")&&url.hostname.endsWith("]") &&
      (value==="::1"||value==="0:0:0:0:0:0:0:1"||
      (first>=0xfc00&&first<=0xfdff)||(first>=0xfe80&&first<=0xfebf)));
    return url.hostname.slice(1,-1).toLowerCase();
  }
  function parseCatalog(v){
    admit(exact(v,["schema","status",...FLAGS,"scenarios"]) &&
      v.schema==="lightup.lab_design_catalog.v1"&&v.status==="DRAFT_ONLY"&&
      flags(v)&&Array.isArray(v.scenarios)&&v.scenarios.length>=1&&v.scenarios.length<=32);
    const ids=new Set(),out=[];
    for(const s of v.scenarios){
      admit(exact(s,["scenario_id","name","description","targets","expected_findings"])&&
        typeof s.scenario_id==="string"&&TOKEN.test(s.scenario_id)&&
        ascii(s.name,1,160)&&ascii(s.description,0,500)&&
        Array.isArray(s.targets)&&s.targets.length>=1&&s.targets.length<=16&&
        !ids.has(s.scenario_id));
      const targets=s.targets.map(privateIP);
      admit(new Set(targets).size===targets.length);
      ids.add(s.scenario_id);
      admit(s.expected_findings===null||(Array.isArray(s.expected_findings)&&
        s.expected_findings.length<=64));
      let expected=null;
      if(s.expected_findings!==null){
        const fids=new Set();
        expected=s.expected_findings.map(f=>{
          admit(exact(f,["identifier","title","capability_id","severity"])&&
            typeof f.identifier==="string"&&TOKEN.test(f.identifier)&&
            typeof f.capability_id==="string"&&TOKEN.test(f.capability_id)&&
            ascii(f.title,1,160)&&LEVELS.includes(f.severity)&&!fids.has(f.identifier));
          fids.add(f.identifier);
          return {severity:f.severity};
        });
      }
      // Never retain IP addresses, finding identifiers or descriptions beyond admission.
      out.push({id:s.scenario_id,mode:expected===null?"unscored":
        expected.length===0?"declared_zero":"planted",
        planted:expected===null?null:expected.length,
        severity:expected===null?null:Object.fromEntries(LEVELS.map(n=>[
          n,expected.filter(f=>f.severity===n).length]))});
    }
    return out;
  }
  function change(v){
    admit(exact(v,["name","baseline","candidate","delta","regression"])&&
      METRICS.includes(v.name)&&finite(v.baseline)&&finite(v.candidate)&&
      finite(v.delta)&&v.baseline>=0&&v.candidate>=0&&
      typeof v.regression==="boolean"&&approx(v.candidate-v.baseline,v.delta));
    if(COUNTS.has(v.name)){
      admit([v.baseline,v.candidate,v.delta].every(Number.isSafeInteger)&&
        v.baseline<=1e9&&v.candidate<=1e9&&
        v.candidate-v.baseline===v.delta);
    }
    if(SCORES.has(v.name))admit(v.baseline<=1&&v.candidate<=1);
    if(v.name==="runtime_seconds"||v.name==="compute_cost_usd")
      admit(v.baseline<=1e12&&v.candidate<=1e12);
    admit(v.regression===((HIGH.has(v.name)&&v.candidate<v.baseline)||
      (LOW.has(v.name)&&v.candidate>v.baseline)));
    return {baseline:v.baseline,candidate:v.candidate,regression:v.regression};
  }
  function parseReport(v){
    admit(exact(v,["status","regressed_scenarios","comparisons",...FLAGS])&&
      flags(v)&&(v.status==="HOLD"||v.status==="REVIEW_ONLY")&&
      Array.isArray(v.comparisons)&&v.comparisons.length>=1&&v.comparisons.length<=64&&
      Array.isArray(v.regressed_scenarios)&&v.regressed_scenarios.length<=64);
    const cases=new Map();
    for(const c of v.comparisons){
      admit(exact(c,["scenario_id","status","regressions","changes"])&&
        sourceId(c.scenario_id)&&!cases.has(c.scenario_id)&&
        Array.isArray(c.regressions)&&Array.isArray(c.changes)&&
        c.changes.length===METRICS.length&&c.regressions.length<=METRICS.length);
      const metrics=new Map();
      for(const item of c.changes){
        admit(item!==null&&typeof item==="object"&&
          typeof item.name==="string"&&!metrics.has(item.name));
        metrics.set(item.name,change(item));
      }
      admit(METRICS.every(n=>metrics.has(n)));
      const observed=METRICS.filter(n=>metrics.get(n).regression);
      admit(c.regressions.length===observed.length &&
        c.regressions.every((n,i)=>n===observed[i])&&
        c.status===(observed.length?"HOLD":"REVIEW_ONLY"));
      cases.set(c.scenario_id,{metrics,adverse:observed});
    }
    const flagged=[...cases].filter(([,c])=>c.adverse.length).map(([id])=>id);
    admit(v.regressed_scenarios.length===flagged.length&&
      new Set(v.regressed_scenarios).size===flagged.length&&
      v.regressed_scenarios.every(id=>sourceId(id)&&flagged.includes(id))&&
      v.status===(flagged.length?"HOLD":"REVIEW_ONLY"));
    return {cases,status:v.status};
  }
  function harmonize(items){
    const baseline=new Map();
    for(const report of items)for(const [id,row] of report.cases){
      for(const name of METRICS){
        const key=JSON.stringify([id,name]),value=row.metrics.get(name).baseline;
        if(baseline.has(key))admit(baseline.get(key)===value);
        else baseline.set(key,value);
      }
    }
    // A different filename or JSON key order is not a new experimental candidate.
    const signatures=new Set();
    for(const r of items){
      const sig=JSON.stringify([...r.cases].sort(([a],[b])=>a.localeCompare(b))
        .map(([id,c])=>[id,METRICS.map(n=>c.metrics.get(n).candidate)]));
      admit(!signatures.has(sig));signatures.add(sig);
    }
  }
  // Local file:// contexts may not expose Web Crypto. The fallback binds only
  // the exact local bytes; it is not a signature, source authentication or permission.
  function portableSHA256(bytes){
    const data=Array.from(new Uint8Array(bytes)),bitLength=data.length*8;
    data.push(0x80);while(data.length%64!==56)data.push(0);
    data.push(0,0,0,0,(bitLength>>>24)&255,(bitLength>>>16)&255,(bitLength>>>8)&255,bitLength&255);
    const K=[
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const rotate=(x,n)=>(x>>>n)|(x<<(32-n));
    for(let offset=0;offset<data.length;offset+=64){
      const w=new Array(64);
      for(let i=0;i<16;i++){const p=offset+i*4;w[i]=((data[p]<<24)|(data[p+1]<<16)|(data[p+2]<<8)|data[p+3])>>>0;}
      for(let i=16;i<64;i++){const x=w[i-15],y=w[i-2],s0=rotate(x,7)^rotate(x,18)^(x>>>3),s1=rotate(y,17)^rotate(y,19)^(y>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}
      let[a,b,c,d,e,f,g,h]=H;
      for(let i=0;i<64;i++){const s1=rotate(e,6)^rotate(e,11)^rotate(e,25),ch=(e&f)^(~e&g),t1=(h+s1+ch+K[i]+w[i])>>>0,s0=rotate(a,2)^rotate(a,13)^rotate(a,22),maj=(a&b)^(a&c)^(b&c),t2=(s0+maj)>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
      H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
    }
    return H.map(word=>word.toString(16).padStart(8,"0")).join("");
  }
  async function hashOriginal(bytes){
    if(globalThis.crypto?.subtle){
      try{const digest=await globalThis.crypto.subtle.digest("SHA-256",bytes);
        return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
      }catch(_){/* Use deterministic local fallback below. */}
    }
    return portableSHA256(bytes);
  }
  async function read(file,max){
    admit(file instanceof File&&file.size>0&&file.size<=max);
    const bytes=await file.arrayBuffer(),str=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(bytes);
    if(str.charCodeAt(0)===0xfeff)throw Error("A leading UTF-8 BOM is not canonical for original source JSON.");
    admit(str.length>0&&str.length<=max);
    const result=parse(str),digest=await hashOriginal(bytes);
    return {result,digest};
  }
  function message(value,bad=false){$("message").textContent=value;$("message").className=bad?"error":"";}
  function td(tr,value){const col=document.createElement("td");col.textContent=String(value);tr.append(col);return col;}
  function button(text,fn){
    const b=document.createElement("button");b.type="button";b.textContent=text;b.addEventListener("click",fn);return b;
  }
  function table(node,columns,rows){
    node.replaceChildren();const grid=document.createElement("table"),head=document.createElement("thead"),
      hr=document.createElement("tr");
    for(const h of columns){const cell=document.createElement("th");cell.scope="col";cell.textContent=h;hr.append(cell);}
    head.append(hr);grid.append(head);
    const body=document.createElement("tbody");
    for(const row of rows){const tr=document.createElement("tr");
      for(const val of row)td(tr,val);body.append(tr);}grid.append(body);node.append(grid);
  }
  function consistency(){
    if(!catalog||!reports.length)return {exact:false,missing:0,unexpected:0};
    const ids=new Set(catalog.map(s=>s.id));let missing=0,unexpected=0;
    for(const r of reports){
      for(const id of ids)if(!r.cases.has(id))missing++;
      for(const id of r.cases.keys())if(!ids.has(id))unexpected++;
    }
    return {exact:missing===0&&unexpected===0,missing,unexpected};
  }
  function aggregates(){
    admit(catalog&&reports.length);
    const match=consistency(),stage=Object.fromEntries(STAGES.map(s=>[s,0]));
    let unknown=0,zero=0,planted=0,findings=0,adverse=0,affected=0;
    const severity=Object.fromEntries(LEVELS.map(n=>[n,0]));
    const routeCounts=Object.fromEntries(ROUTES.map(n=>[n,0]));
    const actionCounts=Object.fromEntries(ACTIONS.map(n=>[n,0]));
    for(const s of catalog){
      routeCounts[humanRouteFor(s)]++;
      actionCounts[humanActionFor(s)]++;
      stage[reviews.get(s.id)||"needs_review"]++;
      if(s.mode==="unscored")unknown++;
      else if(s.mode==="declared_zero")zero++;
      else{planted++;findings+=s.planted;
        for(const level of LEVELS)severity[level]+=s.severity[level];}
    }
    const byReport=reports.map((r,i)=>{
      const flagged=[...r.cases.values()].filter(c=>c.adverse.length);
      const bad=flagged.reduce((n,c)=>n+c.adverse.length,0);
      adverse+=bad;affected+=flagged.length;
      return {slot:i+1,status:r.status,case_count:r.cases.size,
        source_reported_adverse_cases:flagged.length,source_reported_adverse_metrics:bad,
        scope_policy_flag_instances:[...r.cases.values()].reduce((n,c)=>
          n+Number(c.adverse.includes("scope_violations"))+
          Number(c.adverse.includes("policy_violations")),0)};
    });
    return {schema:"lightup.assessment_lineage_review.v1",status:"REVIEW_ONLY_HOLD",
      authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,
      fictional_demo_only:fictional,scenario_count:catalog.length,report_count:reports.length,
      source_membership_exact:match.exact,missing_report_cases:match.missing,
      unexpected_report_cases:match.unexpected,declared_unscored:unknown,
      declared_zero_findings:zero,declared_planted_scenarios:planted,
      declared_planted_findings:findings,declared_severity_totals:severity,
      human_discussion_stages:stage,source_reported_adverse_cases:affected,
      source_reported_adverse_metric_instances:adverse,
      human_queue_priorities:queueRollup().map(({category,cases,human_stages})=>
        ({category,cases,human_stages})),
      proposed_human_route_totals:routeCounts,
      next_human_action_totals:actionCounts,
      reports:byReport};
  }

  const FAMILIES={
    scope:["scope_violations","policy_violations"],
    findings:["valid_findings","invalid_findings","missed_findings","coverage_assessed","coverage_unknown"],
    evidence:["evidence_quality","reproducibility","remediation_quality","retest_correctness"],
    operations:["human_interventions","tool_calls","runtime_seconds","compute_cost_usd"]
  };
  let undoBatch=null;
  function caseFlags(item){
    const flags=new Set();let missing=false;
    for(const report of reports){
      const c=report.cases.get(item.id);
      if(!c){missing=true;continue;}
      for(const flag of c.adverse)flags.add(flag);
    }
    return {flags,missing};
  }
  function priority(item){
    const f=caseFlags(item);
    if(f.missing)return 0;
    if(FAMILIES.scope.some(n=>f.flags.has(n)))return 1;
    if(FAMILIES.findings.some(n=>f.flags.has(n)))return 2;
    if(FAMILIES.evidence.some(n=>f.flags.has(n)))return 3;
    if(FAMILIES.operations.some(n=>f.flags.has(n)))return 4;
    return 5;
  }

  const QUEUE_LABELS=["Missing source membership","Scope / policy",
    "Findings / coverage","Evidence / scoring","Informational operations",
    "No source-reported flags"];
  const QUEUE_KEYS=["missing_source","scope_policy","findings_coverage",
    "evidence_scoring","operations_info","no_source_flags"];
  const QUEUE_FILTERS=["missing","scope","findings","evidence","operations","no_flags"];

  function renderMismatchDetails(){
    const node=$("mismatchDetails"),button=$("revealMismatch");
    node.replaceChildren();
    const match=consistency();
    const hasMismatches=Boolean(catalog&&reports.length&&!match.exact);
    button.hidden=!hasMismatches;
    button.textContent=mismatchRevealed?"Hide PRIVATE mismatch identifiers":
      "Reveal exact PRIVATE mismatch identifiers";
    if(!hasMismatches){
      mismatchRevealed=false;
      node.textContent=catalog&&reports.length?
        "Original scenario memberships match. No mismatch identifiers needed.":
        "Load original completed sources first.";
      return;
    }
    if(!mismatchRevealed){
      node.textContent="HOLD: exact original case IDs are intentionally hidden. "+
        "Reveal privately only if needed for original-source reconciliation.";
      return;
    }
    const catalogIds=new Set(catalog.map(s=>s.id)),rows=[];
    for(let i=0;i<reports.length;i++){
      const report=reports[i];
      for(const item of catalog){
        if(!report.cases.has(item.id))rows.push([
          "Source "+(i+1),"Catalog source missing from report",item.id
        ]);
      }
      for(const id of report.cases.keys()){
        if(!catalogIds.has(id))rows.push([
          "Source "+(i+1),"Unexpected in completed report",id
        ]);
      }
    }
    table(node,["Private original source slot","Exact source mismatch","PRIVATE source case ID"],rows);
    const caution=document.createElement("p");
    caution.textContent="PRIVATE original identifiers shown locally for human source correction. "+
      "Never copy into anonymous reports. ABSENT does not mean remediated. "+
      "Changing input sources automatically hides this sensitive view.";
    node.append(caution);
  }
  function toggleMismatch(){
    if(!catalog||!reports.length||consistency().exact)return;
    if(mismatchRevealed){mismatchRevealed=false;renderMismatchDetails();return;}
    if(!confirm("Reveal exact ORIGINAL PRIVATE scenario identifiers on this local "+
      "screen? Keep this information away from screen sharing or printed reports."))return;
    mismatchRevealed=true;renderMismatchDetails();
  }

  function queueRollup(){
    const rows=QUEUE_KEYS.map((key,i)=>({
      category:key,label:QUEUE_LABELS[i],cases:0,
      human_stages:Object.fromEntries(STAGES.map(stage=>[stage,0]))
    }));
    if(!catalog)return rows;
    for(const scenario of catalog){
      const row=rows[priority(scenario)];
      row.cases++;
      row.human_stages[reviews.get(scenario.id)||"needs_review"]++;
    }
    return rows;
  }
  function renderHumanActionBoard(){
    const node=$("humanActionBoard"),summary=$("humanActionBoardStatus");
    node.replaceChildren();
    if(!catalog||!reports.length){
      summary.textContent="Load existing completed original reports to review local human actions.";
      return;
    }
    const filter=$("boardStatus").value,scope=$("boardRoute").value;
    const cases=catalog.map((item,i)=>({item,i}))
      .filter(({item})=>humanActionFor(item)!=="none_recorded")
      .filter(({item})=>filter==="all"||(reviews.get(item.id)||"needs_review")===filter)
      .filter(({item})=>scope==="all"||humanRouteFor(item)===scope)
      .sort((a,b)=>priority(a.item)-priority(b.item)||a.i-b.i);
    summary.textContent=cases.length+" private proposed HUMAN actions shown · "+
      "not authenticated staff assignments or automatic work orders.";
    const heading=["Private ordinal","Original source discussion priority","Human review group",
      "Proposed next action","Local discussion stage","Open private inspector"];
    const tableNode=document.createElement("table"),head=document.createElement("thead"),
      tr=document.createElement("tr");
    for(const label of heading){
      const th=document.createElement("th");th.textContent=label;tr.append(th);
    }
    head.append(tr);tableNode.append(head);
    const tbody=document.createElement("tbody");
    for(const {item,i} of cases){
      const row=document.createElement("tr");
      td(row,"Lab case "+String(i+1).padStart(2,"0"));
      td(row,QUEUE_LABELS[priority(item)]);
      td(row,ROUTE_LABELS[humanRouteFor(item)]);
      td(row,ACTION_LABELS[humanActionFor(item)]);
      td(row,(reviews.get(item.id)||"needs_review").replaceAll("_"," "));
      const next=document.createElement("td");
      next.append(button("Open private case",()=>{
        $("inspectCase").value=String(i);renderInspector();
        $("inspectorSection").scrollIntoView({block:"start",behavior:"smooth"});
      }));
      row.append(next);tbody.append(row);
    }
    tableNode.append(tbody);
    node.append(tableNode);
    const explanation=document.createElement("p");
    explanation.textContent="No human owner identity, contact channel, authorization, scanner "+
      "or target instruction is inferred or sent. Original source data stays untouched.";
    node.append(explanation);
  }

  function renderQueueOverview(){
    const node=$("queueOverview");node.replaceChildren();
    if(!catalog||!reports.length){
      node.textContent="Load original finished comparison files to summarize private source flags.";
      return;
    }
    for(let i=0;i<QUEUE_KEYS.length;i++){
      const entry=queueRollup()[i],card=document.createElement("article");
      card.className="queue-card";
      const name=document.createElement("h3");name.textContent=entry.label;
      const counts=document.createElement("p");
      counts.textContent=entry.cases+" original lab case(s) · "+
        STAGES.map(stage=>stage.replaceAll("_"," ")+" "+entry.human_stages[stage]).join(" / ");
      const action=button("View "+entry.label.toLowerCase(),()=>{
        $("familyFilter").value=QUEUE_FILTERS[i];render();
        $("caseTitle").scrollIntoView({block:"start",behavior:"smooth"});
      });
      card.append(name,counts,action);node.append(card);
    }
  }

  function visibleCases(){
    if(!catalog)return [];
    const family=$("familyFilter").value;
    const stage=$("stageFilter").value,truth=$("truthFilter").value;
    const route=$("routeFilter").value,action=$("actionFilter").value;
    return catalog.map((item,i)=>({item,i})).filter(({item})=>{
      if(stage!=="all"&&(reviews.get(item.id)||"needs_review")!==stage)return false;
      if(truth!=="all"&&item.mode!==truth)return false;
      if(route!=="all"&&humanRouteFor(item)!==route)return false;
      if(action!=="all"&&humanActionFor(item)!==action)return false;
      if(family!=="all"){
        const current=caseFlags(item);
        if(family==="no_flags")return !current.flags.size&&!current.missing;
        if(family==="missing"){if(!current.missing)return false;}
        else if(!FAMILIES[family]?.some(n=>current.flags.has(n)))return false;
      }
      return true;
    }).sort((a,b)=>priority(a.item)-priority(b.item)||a.i-b.i);
  }
  function filteredHumanQueue(){
    safeExport();
    const rows=visibleCases();
    admit(rows.length>0);
    return {rows,filters:{
      flag_family:$("familyFilter").value,ground_truth:$("truthFilter").value,
      human_stage:$("stageFilter").value,proposed_route:$("routeFilter").value,
      next_action:$("actionFilter").value
    },catalog_count:catalog.length,report_count:reports.length,fictional_demo_only:fictional};
  }
  function exportFilteredQueueCsv(){
    try{
      const handoff=filteredHumanQueue();
      const columns=["record","case_ordinal","source_priority","source_membership",
        "declared_ground_truth_mode","planted_count","source_reported_flags","human_stage",
        "proposed_route","proposed_next_action","loaded_report_count","filter_flag_family",
        "filter_ground_truth","filter_human_stage","filter_proposed_route","filter_next_action",
        "fictional_demo_only","authorized","consent_verified","dispatch_allowed","release_allowed"];
      const rows=[columns];
      for(const {item,i} of handoff.rows){
        const flags=caseFlags(item);
        rows.push(["case","Lab case "+String(i+1).padStart(2,"0"),QUEUE_LABELS[priority(item)],
          flags.missing?"missing_from_loaded_reports":"present_in_all_loaded_reports",
          item.mode,item.planted===null?"unknown":item.planted,
          flags.flags.size?[...flags.flags].sort().join(";"):"none",
          reviews.get(item.id)||"needs_review",humanRouteFor(item),humanActionFor(item),
          handoff.report_count,handoff.filters.flag_family,handoff.filters.ground_truth,
          handoff.filters.human_stage,handoff.filters.proposed_route,handoff.filters.next_action,
          handoff.fictional_demo_only,false,false,false,false]);
      }
      download("lightup-lineage-filtered-human-queue.csv",csv(rows),"text/csv;charset=utf-8");
      message("Exported "+handoff.rows.length+" currently visible anonymous HUMAN queue rows. No original IDs, targets, hashes or private notes were included.");
    }catch(_){message("HOLD: filtered handoff requires exact canonical source membership and at least one visible case.",true);}
  }
  function exportFilteredQueueHtml(){
    try{
      const handoff=filteredHumanQueue();
      const esc=value=>String(value).replace(/[&<>"']/g,c=>c==="&"?"&amp;":c==="<"?"&lt;":c===">"?"&gt;":c===String.fromCharCode(34)?"&quot;":"&#39;");
      const filterSummary=[
        "source flag family: "+$("familyFilter").selectedOptions[0].textContent,
        "ground truth: "+$("truthFilter").selectedOptions[0].textContent,
        "human stage: "+$("stageFilter").selectedOptions[0].textContent,
        "proposed route: "+$("routeFilter").selectedOptions[0].textContent,
        "next action: "+$("actionFilter").selectedOptions[0].textContent
      ].join(" · ");
      const headings=["Anonymous case ordinal","Source-reported priority","Source membership",
        "Declared ground-truth mode","Planted finding count","Source-reported metric flags",
        "Human discussion stage","Proposed human route","Proposed next action"];
      const rows=handoff.rows.map(({item,i})=>{
        const flags=caseFlags(item);
        const values=["Lab case "+String(i+1).padStart(2,"0"),QUEUE_LABELS[priority(item)],
          flags.missing?"Missing from a loaded report":"Present in every loaded report",
          item.mode,item.planted===null?"Unknown":item.planted,
          flags.flags.size?[...flags.flags].sort().join(", "):"None",
          reviews.get(item.id)||"needs_review",ROUTE_LABELS[humanRouteFor(item)],ACTION_LABELS[humanActionFor(item)]];
        return "<tr>"+values.map(value=>"<td>"+esc(value)+"</td>").join("")+"</tr>";
      }).join("");
      const output="<!doctype html><html lang='en'><head><meta charset='utf-8'>"+
        "<meta name='referrer' content='no-referrer'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; img-src 'none'; style-src 'none'; script-src 'none'\">"+
        "<title>LightUp filtered HUMAN queue</title></head><body>"+
        "<h1>LightUp · filtered anonymous HUMAN queue</h1>"+
        "<p><strong>UNSIGNED HUMAN PLANNING ONLY · REVIEW_ONLY / HOLD"+
        (handoff.fictional_demo_only?" · FICTIONAL DEMO":" · SOURCE UNVERIFIED")+"</strong></p>"+
        "<p>Visible cases: "+handoff.rows.length+" of "+handoff.catalog_count+" original scenario slots; loaded completed comparison reports: "+handoff.report_count+".</p>"+
        "<p>Filters applied: "+esc(filterSummary)+"</p>"+
        "<p>No original scenario IDs, targets, source filenames/hashes, raw source values or private notes. Original source flags and ground-truth declarations are untrusted retrospective lab data.</p>"+
        "<table><thead><tr>"+headings.map(value=>"<th>"+esc(value)+"</th>").join("")+"</tr></thead><tbody>"+rows+"</tbody></table>"+
        "<p>authorized=false · consent_verified=false · dispatch_allowed=false · release_allowed=false. This report is not a scan, authenticated finding, staff assignment, grant or release approval.</p>"+
        "</body></html>";
      download("lightup-lineage-filtered-human-queue.html",output,"text/html;charset=utf-8");
      message("Exported a scriptless filtered HUMAN queue. Only visible anonymous ordinals and declared review fields are included.");
    }catch(_){message("HOLD: filtered handoff requires exact canonical source membership and at least one visible case.",true);}
  }
  function humanBulk(){
    if(!catalog||!reports.length){message("Load sources before changing review stages.",true);return;}
    const selected=visibleCases(),stage=$("bulkStage").value;
    if(!STAGES.includes(stage)||!selected.length){
      message("No visible case or valid human discussion stage selected.",true);return;
    }
    if(!confirm("Set "+selected.length+" currently visible PRIVATE human cases to "+
      stage+"? This is NOT an approval or assignment."))return;
    undoBatch=new Map(reviews);
    for(const {item} of selected)reviews.set(item.id,stage);
    render();message("Updated "+selected.length+" PRIVATE human stages; one-step Undo available.");
  }
  function undoHumanBulk(){
    if(!undoBatch){message("No local bulk action to undo.");return;}
    reviews=undoBatch;undoBatch=null;render();
    message("Previous human discussion stages restored in memory only.");
  }
  function bulkSuggestHumanRoutes(){
    if(!catalog||!reports.length){
      message("Load original completed comparison sources first.",true);return;
    }
    const selected=visibleCases().filter(({item})=>humanRouteFor(item)==="unrouted");
    if(!selected.length){
      message("No currently visible unrouted human cases need a proposal.",true);return;
    }
    if(!confirm("Suggest source-derived HUMAN discussion groups for "+selected.length+
      " currently visible UNROUTED private cases only? No employees are assigned; "+
      "no scan or permission is initiated. Existing human choices remain unchanged."))return;
    undoRouteBatch=new Map(humanRoutes);
    for(const {item} of selected){
      const hint=sourceRouteHint(item);
      if(hint!=="unrouted")humanRoutes.set(item.id,hint);
    }
    render();
    message("Local human discussion proposals added; existing routes unchanged. "+
      "One-step route Undo available.");
  }
  function undoHumanRoutes(){
    if(!undoRouteBatch){message("No proposed route batch to undo.");return;}
    humanRoutes=undoRouteBatch;undoRouteBatch=null;render();
    message("Previous PRIVATE human route proposals restored without modifying sources.");
  }

  function resetFilters(){
    for(const id of ["familyFilter","stageFilter","truthFilter","routeFilter","actionFilter"])$(id).value="all";
  }



  function renderSourceOrder(){
    const select=$("sourceOrder"),old=select.value;
    select.replaceChildren();
    reports.forEach((r,i)=>{
      const option=document.createElement("option");option.value=String(i);
      option.textContent="Original source "+(i+1)+" · "+r.cases.size+" cases · "+r.status;
      select.append(option);
    });
    if(reports.length){
      select.value=old!==""&&Number.isSafeInteger(Number(old))&&Number(old)>=0&&
        Number(old)<reports.length?old:"0";
    }
    for(const id of ["sourceEarlier","sourceLater","removeSource"])
      $(id).disabled=!reports.length;
    $("sourceEarlier").disabled=!reports.length||select.value==="0";
    $("sourceLater").disabled=!reports.length||
      Number(select.value)===reports.length-1;
  }
  function chooseSource(delta){
    const i=Number($("sourceOrder").value),j=i+delta;
    if(!Number.isSafeInteger(i)||i<0||j<0||j>=reports.length)return;
    [reports[i],reports[j]]=[reports[j],reports[i]];
    [reportHashes[i],reportHashes[j]]=[reportHashes[j],reportHashes[i]];
    mismatchRevealed=false;clearPendingDraft();
    undoBatch=null;undoRouteBatch=null;
    render();$("sourceOrder").value=String(j);renderSourceOrder();
    message("Changed private source DISPLAY order only. Not proven chronology. "+
      "Private source-bound resume must be saved again.");
  }
  function removeSource(){
    const i=Number($("sourceOrder").value);
    if(!Number.isSafeInteger(i)||i<0||i>=reports.length)return;
    if(!confirm("Remove original source slot "+(i+1)+" from this in-memory review? "+
      "The original private file is NOT deleted. No measurement or scan is repeated."))return;
    reports.splice(i,1);reportHashes.splice(i,1);mismatchRevealed=false;clearPendingDraft();reopenHumanStages();
    render();message("One original completed report removed from private memory; "+
      "catalog and private notes preserved. Human stages reopened for source review.");
  }


  function humanNote(value){
    return typeof value==="string"&&value.length<=400&&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
  }
  function reopenHumanStages(){
    if(!catalog)return;
    for(const s of catalog)reviews.set(s.id,"needs_review");
    // Different completed source sets invalidate unverified proposed human routes/actions.
    humanRoutes.clear();humanActions.clear();
    undoBatch=null;undoRouteBatch=null;
  }
  function saveCaseNote(){
    if(!catalog||!catalog.length)return;
    const index=Number($("inspectCase").value);
    if(!Number.isSafeInteger(index)||index<0||index>=catalog.length)return;
    const note=$("privateCaseNote").value;
    if(!humanNote(note)){
      message("HOLD: PRIVATE human note is too long or contains forbidden controls.",true);return;
    }
    if(note.trim())humanNotes.set(catalog[index].id,note);
    else humanNotes.delete(catalog[index].id);
    noteScratch.delete(catalog[index].id);
    $("privateNoteState").textContent=note.trim()?
      "PRIVATE note saved only in memory. Include it only in PRIVATE source-bound draft.":
      "Private note removed from memory.";
  }

  function humanRouteFor(s){return humanRoutes.get(s.id)||"unrouted";}
  function humanActionFor(s){return humanActions.get(s.id)||"none_recorded";}
  function sourceRouteHint(s){
    const p=priority(s);
    return ["source_owner","scope_policy","finding_quality","evidence_scoring",
      "operations","unrouted"][p];
  }
  function setHumanPlan(){
    if(!catalog||!reports.length){message("Load genuine completed source reports first.",true);return;}
    const index=Number($("inspectCase").value);
    if(!Number.isSafeInteger(index)||index<0||index>=catalog.length)return;
    const route=$("humanRoute").value,action=$("humanAction").value;
    if(!ROUTES.includes(route)||!ACTIONS.includes(action)){
      message("HOLD: unknown human planning option.",true);return;
    }
    const id=catalog[index].id;
    if(route==="unrouted")humanRoutes.delete(id);else humanRoutes.set(id,route);
    if(action==="none_recorded")humanActions.delete(id);else humanActions.set(id,action);
    undoBatch=null;undoRouteBatch=null;
    render();
    $("inspectCase").value=String(index);renderInspector();
    message("Private proposed human reviewer route and next human action saved in memory. "+
      "This is not an assignment, verified finding, grant or execution request.");
  }
  function adoptSourceHint(){
    if(!catalog||!reports.length)return;
    const index=Number($("inspectCase").value);
    if(!Number.isSafeInteger(index)||index<0||index>=catalog.length)return;
    $("humanRoute").value=sourceRouteHint(catalog[index]);
    $("humanPlanState").textContent="Suggested human discussion group only. "+
      "Click Save human plan to adopt locally; no staff are contacted.";
  }

  function numberLabel(n){
    return Number.isInteger(n)?String(n):n.toPrecision(6).replace(/\.?0+($|e)/,"$1");
  }
  function renderInspector(){
    const selector=$("inspectCase"),panel=$("metricInspector"),old=selector.value;
    selector.replaceChildren();panel.replaceChildren();
    if(!catalog||!reports.length){
      panel.textContent="Import the original scenario catalog and a completed comparator report first.";
      $("privateCaseNote").value="";
      $("humanRoute").value="unrouted";$("humanAction").value="none_recorded";
      $("sourceRouteHint").textContent="";
      $("humanPlanState").textContent="Load original sources first.";
      $("privateNoteState").textContent="Load original sources first.";
      return;
    }
    catalog.forEach((s,i)=>{
      const option=document.createElement("option");option.value=String(i);
      option.textContent="Lab case "+String(i+1).padStart(2,"0");selector.append(option);
    });
    selector.value=old!==""&&Number.isSafeInteger(Number(old))&&Number(old)>=0&&
      Number(old)<catalog.length?old:"0";
    const index=Number(selector.value),scenario=catalog[index];
    $("privateCaseNote").value=noteScratch.has(scenario.id)?
      noteScratch.get(scenario.id):humanNotes.get(scenario.id)||"";
    $("humanRoute").value=humanRouteFor(scenario);
    $("humanAction").value=humanActionFor(scenario);
    $("sourceRouteHint").textContent="Proposed source-flag discussion group: "+
      ROUTE_LABELS[sourceRouteHint(scenario)]+". Never an authenticated assignment.";
    $("humanPlanState").textContent="Human planning fields are PRIVATE and unsigned.";
    $("privateNoteState").textContent=noteScratch.has(scenario.id)?
      "UNSAVED private note draft retained in tab memory for this case. "+
        "Click Save note before private draft/dossier export.":
      "PRIVATE human notes are local and never appear in anonymous exports.";
    const rows=METRICS.map(metric=>[
      metric.replaceAll("_"," "),
      ...reports.map(report=>{
        const row=report.cases.get(scenario.id);
        if(!row)return "ABSENT — HOLD";
        const v=row.metrics.get(metric);
        return "source baseline "+numberLabel(v.baseline)+
          " → candidate "+numberLabel(v.candidate)+
          " (delta "+numberLabel(v.candidate-v.baseline)+")"+
          (v.regression?" · ORIGINAL SOURCE FLAG":" · no original adverse flag");
      })
    ]);
    table(panel,["Original metric",...reports.map((_,i)=>"Completed report "+(i+1))],rows);
  }

  function render(){
    const ready=Boolean(catalog&&reports.length),match=consistency();
    $("catalogState").textContent=catalog?catalog.length+" private design scenario slots loaded":"No private catalog loaded";
    $("reportState").textContent=reports.length+" canonical completed lab comparison sources loaded";
    $("summary").textContent=ready?(match.exact?
      "SOURCE MEMBERSHIP ALIGNED. Read-only, untrusted results. Every consent/release authority is false.":
      "HOLD — "+match.missing+" absent expected comparison cases; "+
      match.unexpected+" extra comparison cases. Reconcile original sources, not an automatic finding."):
      "Load one PRIVATE Lab Scenario Studio catalog and at least one previously completed canonical cohort comparison.";
    $("summary").className=ready&&!match.exact?"error":"";
    const reportRows=reports.map((r,i)=>[i+1,r.status,r.cases.size,
      [...r.cases.values()].filter(c=>c.adverse.length).length,
      [...r.cases.values()].reduce((n,c)=>n+c.adverse.length,0)]);
    table($("reports"),["Source slot","Original source status","Cases","Adverse cases","Adverse metric flags"],reportRows);
    renderSourceOrder();
    renderMismatchDetails();
    renderQueueOverview();
    renderHumanActionBoard();
    renderAnonymousPrint();
    $("cases").replaceChildren();
    const all=catalog?.length||0,visible=visibleCases();
    $("exportFilteredQueueCsv").disabled=!(ready&&match.exact&&visible.length);
    $("exportFilteredQueueHtml").disabled=!(ready&&match.exact&&visible.length);
    $("queueCount").textContent=visible.length+" visible of "+all+
      " private source cases. Sorted: missing originals → scope/policy → findings → "+
      "evidence → informational operations → no source flags. This is an analyst review order, not a verified risk score.";
    $("undoStage").disabled=!undoBatch;
    $("undoRoute").disabled=!undoRouteBatch;
    if(!catalog){renderInspector();return;}
    const grid=document.createElement("table"),head=document.createElement("thead"),h=document.createElement("tr");
    for(const text of ["Private scenario","Original source priority","Declared ground truth","Planted count",
      ...reports.map((_,i)=>"Source "+(i+1)+" flags"),"Human discussion",
      "Human proposal","Inspect originals"]){
      const th=document.createElement("th");th.textContent=text;h.append(th);
    }
    head.append(h);grid.append(head);
    const body=document.createElement("tbody");
    visible.forEach(({item,i})=>{
      const row=document.createElement("tr");
      td(row,"Lab case "+String(i+1).padStart(2,"0"));
      td(row,["MISSING source","scope / policy","findings / coverage","evidence / scoring",
        "operations / informational","no source flags"][priority(item)]);
      td(row,item.mode==="unscored"?"UNSCORED / UNKNOWN":item.mode==="declared_zero"?
        "Declared zero (not verified)":"Declared planted (not verified)");
      td(row,item.planted===null?"unknown":item.planted);
      for(const r of reports){
        const c=r.cases.get(item.id);
        td(row,!c?"ABSENT — HOLD":c.adverse.length?
          c.adverse.length+" adverse: "+c.adverse.join(", "):"No source-reported adverse flag");
      }
      const cell=document.createElement("td"),selector=document.createElement("select");
      selector.setAttribute("aria-label","Human discussion stage for lab case "+(i+1));
      for(const stage of STAGES){
        const option=document.createElement("option");option.value=stage;
        option.textContent=stage.replaceAll("_"," ");selector.append(option);
      }
      selector.value=reviews.get(item.id)||"needs_review";
      selector.addEventListener("change",()=>{
        cancelOldImports();
        reviews.set(item.id,selector.value);undoBatch=null;
        render();message("Private human stage updated in memory only.");
      });
      cell.append(selector);row.append(cell);
      td(row,ROUTE_LABELS[humanRouteFor(item)]+" · "+ACTION_LABELS[humanActionFor(item)]);
      const jump=document.createElement("td");
      jump.append(button("Inspect",()=>{
        $("inspectCase").value=String(i);renderInspector();
        $("inspectorSection").scrollIntoView({block:"start",behavior:"smooth"});
      }));
      row.append(jump);body.append(row);
    });
    grid.append(body);$("cases").append(grid);
    const extras=document.createElement("p");
    extras.textContent=match.unexpected+" extra original report case memberships omitted from private scenario rows. "+
      "No identities appear in public exports. Filtering never changes original imports.";
    $("cases").append(extras);
    renderInspector();
  }
  function download(name,content,type){
    const url=URL.createObjectURL(new Blob([content],{type}));
    const a=document.createElement("a");a.href=url;a.download=name;a.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function csv(rows){
    return rows.map(row=>row.map(val=>'"'+String(val).replaceAll('"','""')+'"').join(",")).join("\r\n")+"\r\n";
  }
  function safeExport(){
    admit(catalog&&reports.length&&consistency().exact);
    const a=aggregates();admit(a.authorized===false&&a.release_allowed===false);return a;
  }

  function privateSourceBound(){
    admit(catalog && reports.length && !fictional &&
      typeof catalogHash==="string"&&/^[0-9a-f]{64}$/.test(catalogHash)&&
      reportHashes.length===reports.length&&
      reportHashes.every(v=>typeof v==="string"&&/^[0-9a-f]{64}$/.test(v)));
  }
  function exportPrivateDraft(){
    try{
      privateSourceBound();
      const draft={
        schema:"lightup.assessment_lineage_private_draft.v3",
        status:"PRIVATE_HUMAN_DRAFT_ONLY",
        authorized:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,
        source_catalog_sha256:catalogHash,
        source_report_sha256:[...reportHashes],
        discussion_stages:catalog.map(s=>reviews.get(s.id)||"needs_review"),
        private_case_notes:catalog.map(s=>humanNotes.get(s.id)||""),
        proposed_review_routes:catalog.map(humanRouteFor),
        next_human_actions:catalog.map(humanActionFor)
      };
      if(!confirm("Download a PRIVATE draft with the SHA-256 fingerprints of original "+
        "private file bytes, human stages, PRIVATE notes and proposed human plans? Protect this file; it is not a consent or grant."))return;
      download("lightup-PRIVATE-lineage-human-draft.json",
        JSON.stringify(draft,null,2)+"\n","application/json");
      message("PRIVATE SHA-256 source-bound human draft downloaded. Never share as anonymous handoff.");
    }catch(_){message("HOLD: private draft needs readable original source bytes and a local SHA-256 digest.",true);}
  }
  async function restorePrivateDraft(file){
    const generation=startImport();
    try{
      privateSourceBound();
      const input=await read(file,65536);admitCurrent(generation);
      const draft=input.result;
      const version=draft?.schema;
      const withPlan=version==="lightup.assessment_lineage_private_draft.v3";
      const withNotes=withPlan||version==="lightup.assessment_lineage_private_draft.v2";
      admit((version==="lightup.assessment_lineage_private_draft.v1"||withNotes)&&
        exact(draft,["schema","status",...FLAGS,"source_catalog_sha256",
          "source_report_sha256","discussion_stages",
          ...(withNotes?["private_case_notes"]:[]),
          ...(withPlan?["proposed_review_routes","next_human_actions"]:[])])&&
        draft.status==="PRIVATE_HUMAN_DRAFT_ONLY"&&flags(draft)&&
        draft.source_catalog_sha256===catalogHash&&
        Array.isArray(draft.source_report_sha256)&&
        draft.source_report_sha256.length===reportHashes.length&&
        draft.source_report_sha256.every((v,i)=>v===reportHashes[i])&&
        Array.isArray(draft.discussion_stages)&&
        draft.discussion_stages.length===catalog.length&&
        draft.discussion_stages.every(v=>STAGES.includes(v)));
      if(withNotes)admit(Array.isArray(draft.private_case_notes)&&
        draft.private_case_notes.length===catalog.length&&
        draft.private_case_notes.every(humanNote));
      if(withPlan)admit(Array.isArray(draft.proposed_review_routes)&&
        draft.proposed_review_routes.length===catalog.length&&
        draft.proposed_review_routes.every(v=>ROUTES.includes(v))&&
        Array.isArray(draft.next_human_actions)&&
        draft.next_human_actions.length===catalog.length&&
        draft.next_human_actions.every(v=>ACTIONS.includes(v)));
      // Entire local human workspace changes only after exact original byte provenance
      // and every private field have been checked; older drafts remain readable.
      const nextReviews=new Map(catalog.map((s,i)=>[s.id,draft.discussion_stages[i]]));
      const nextNotes=withNotes?new Map(catalog.flatMap((s,i)=>
        draft.private_case_notes[i]?[[s.id,draft.private_case_notes[i]]]:[])):new Map();
      const nextRoutes=withPlan?new Map(catalog.flatMap((s,i)=>
        draft.proposed_review_routes[i]!=="unrouted"?
          [[s.id,draft.proposed_review_routes[i]]]:[])):new Map();
      const nextActions=withPlan?new Map(catalog.flatMap((s,i)=>
        draft.next_human_actions[i]!=="none_recorded"?
          [[s.id,draft.next_human_actions[i]]]:[])):new Map();
      admitCurrent(generation);
      reviews=nextReviews;humanNotes=nextNotes;noteScratch=new Map();
      humanRoutes=nextRoutes;humanActions=nextActions;undoBatch=null;undoRouteBatch=null;render();
      message("PRIVATE stages, notes and proposed human plans restored for original "+
        "exact source bytes. Legacy v1/v2 drafts have no proposed plans.");
    }catch(_){if(generation===importGeneration)message("HOLD: draft or original source bytes do not match. Existing stages preserved.",true);}
  }


  function renderAnonymousPrint(){
    const node=$("printAnonymous"),button=$("printAnonymousButton");
    node.replaceChildren();let a;
    try{a=safeExport();}
    catch(_){
      node.textContent="HOLD — no anonymous print without exact original source membership.";
      button.disabled=true;return;
    }
    button.disabled=false;
    const title=document.createElement("h2");
    title.textContent="LightUp · ANONYMOUS human lab review · REVIEW_ONLY / HOLD";
    const origin=document.createElement("p");
    origin.textContent=a.fictional_demo_only?"FICTIONAL DEMONSTRATION ONLY":
      "Unsigned original-source human discussion, not authenticated assessment evidence.";
    node.append(title,origin);
    const entries=[
      ["Original private scenario count",a.scenario_count],
      ["Original completed source slots",a.report_count],
      ["Author-declared unscored/unknown",a.declared_unscored],
      ["Author-declared scored zero (not verified)",a.declared_zero_findings],
      ["Author-declared planted findings (not verified)",a.declared_planted_findings],
      ["Original reported adverse metric instances",a.source_reported_adverse_metric_instances],
      ...a.human_queue_priorities.map(q=>["Source priority "+q.category,q.cases]),
      ...Object.entries(a.proposed_human_route_totals).map(([k,v])=>
        ["Proposed human discussion route "+k,v]),
      ...Object.entries(a.next_human_action_totals).map(([k,v])=>
        ["Proposed next human action "+k,v]),
      ...Object.entries(a.human_discussion_stages).map(([stage,count])=>
        ["Human "+stage,count])];
    const tableArea=document.createElement("div");node.append(tableArea);
    table(tableArea,["Anonymous human discussion summary","Source-reported count"],entries);
    const footer=document.createElement("p");
    footer.textContent="All authorized / consent_verified / dispatch_allowed / release_allowed "+
      "flags false. No original case IDs, host/IP/URL, original report values, "+
      "source hashes or private notes. No scans, grants, deployments or HUMAN GO.";
    node.append(footer);
  }


  function exportPrivateActionBrief(){
    try{
      privateSourceBound();
      admit(catalog.length>=1&&catalog.length<=32&&reports.length<=8);
      // Sensitive export: original case IDs, raw source-byte fingerprints, private
      // text, and proposed human follow-up. Never part of anonymous exports/print.
      if(!confirm("Download a SENSITIVE PRIVATE human action dossier containing "+
        "original scenario IDs, source SHA-256 hashes, private case notes and "+
        "proposed human follow-up? Keep it on protected storage; not an approval."))return;
      const escape=x=>String(x).replaceAll("&","&amp;").replaceAll("<","&lt;")
        .replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
      const snapshot=consistency();
      const rows=catalog.map((item,i)=>{
        const flags=caseFlags(item),stage=reviews.get(item.id)||"needs_review";
        const labels=[
          "Lab case "+String(i+1).padStart(2,"0"),item.id,
          QUEUE_LABELS[priority(item)],
          flags.missing?"Missing original completed source":"Present in every original source",
          item.mode,
          stage,ROUTE_LABELS[humanRouteFor(item)],ACTION_LABELS[humanActionFor(item)],
          humanNotes.get(item.id)||""
        ];
        return "<tr>"+labels.map(value=>"<td>"+escape(value)+"</td>").join("")+"</tr>";
      }).join("");
      const heads=["Ordinal","PRIVATE original case ID","Source-reported priority",
        "Membership","Author-declared ground truth","Local human stage",
        "Proposed discussion group","Proposed next human action","PRIVATE human note"];
      const hashes=reportHashes.map((digest,i)=>
        "<li>Completed source "+(i+1)+": "+escape(digest)+"</li>").join("");
      const html="<!doctype html><html lang='en'><meta charset='utf-8'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "+
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"+
        "<meta name='referrer' content='no-referrer'>"+
        "<title>PRIVATE LightUp human action dossier</title>"+
        "<style>body{font:15px/1.5 system-ui;max-width:1300px;margin:2rem auto;padding:1rem}"+
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #777;"+
        "padding:.45rem;vertical-align:top;overflow-wrap:anywhere}"+
        "th{background:#eee}p{max-width:85ch}code{overflow-wrap:anywhere}"+
        "@media print{tr{break-inside:avoid}}</style>"+
        "<h1>PRIVATE LightUp original-source human review dossier</h1>"+
        "<p><strong>SENSITIVE · HUMAN REVIEW ONLY · INCUBATE M3/M7 · DRAFT/HOLD"+
        (fictional?" · FICTIONAL":"")+"</strong></p>"+
        "<p>Source membership: "+(snapshot.exact?"Aligned format — unverified authenticity":
          "HOLD — "+snapshot.missing+" missing and "+snapshot.unexpected+" extra memberships")+
        ". Original findings and flags are untrusted retrospective lab declarations, "+
        "not evidence of remediation, staff assignment, consent or execution permission.</p>"+
        "<p>All authorized, consent_verified, dispatch_allowed and release_allowed "+
        "remain false. No scanner, active target or tool is operated by this file.</p>"+
        "<p>PRIVATE raw original catalog SHA-256: <code>"+escape(catalogHash)+"</code></p>"+
        "<p>PRIVATE completed source byte-hashes (human display order):</p><ol>"+
        hashes+"</ol><table><thead><tr>"+
        heads.map(value=>"<th>"+escape(value)+"</th>").join("")+
        "</tr></thead><tbody>"+rows+"</tbody></table>"+
        "<p><strong>HOLD:</strong> Internal human discussion notes are unsigned, "+
        "may include sensitive original references, and must be independently "+
        "checked with the genuine source owners. Do not share or use as a grant.</p>"+
        "</html>";
      download("lightup-PRIVATE-human-action-dossier.html",html,"text/html");
      message("Sensitive PRIVATE human action dossier downloaded. Protect it separately.");
    }catch(_){message("HOLD: no PRIVATE action dossier without real source-byte fingerprints.",true);}
  }

  function exportJson(){
    try{const a=safeExport();download("lightup-lineage-aggregate.json",
      JSON.stringify(a,null,2)+"\n","application/json");message("Anonymous aggregate JSON downloaded. No source identities.");}
    catch(_){message("HOLD: exports require exact source membership and canonical imports.",true);}
  }
  function exportCsv(){
    try{const a=safeExport();
      const rows=[["record","slot","metric","count"]];
      for(const key of ["scenario_count","report_count","declared_unscored",
        "declared_zero_findings","declared_planted_scenarios","declared_planted_findings",
        "source_reported_adverse_cases","source_reported_adverse_metric_instances"]){
        rows.push(["summary",0,key,a[key]]);
      }
      for(const [key,value] of Object.entries(a.declared_severity_totals))
        rows.push(["declared severity",0,key,value]);
      for(const [key,value] of Object.entries(a.human_discussion_stages))
        rows.push(["human discussion",0,key,value]);
      for(const [route,count] of Object.entries(a.proposed_human_route_totals))
        rows.push(["proposed human discussion route",0,route,count]);
      for(const [action,count] of Object.entries(a.next_human_action_totals))
        rows.push(["next human discussion action",0,action,count]);
      for(const q of a.human_queue_priorities){
        rows.push(["review priority",0,q.category,q.cases]);
        for(const [stage,count] of Object.entries(q.human_stages))
          rows.push(["review priority stage",0,q.category+" / "+stage,count]);
      }
      for(const r of a.reports)
        for(const field of ["case_count","source_reported_adverse_cases",
          "source_reported_adverse_metrics","scope_policy_flag_instances"])
          rows.push(["source report",r.slot,field,r[field]]);
      rows.push(["authority",0,"authorized",false],["authority",0,"consent_verified",false],
        ["authority",0,"dispatch_allowed",false],["authority",0,"release_allowed",false],
        ["provenance",0,"fictional_demo_only",a.fictional_demo_only]);
      download("lightup-lineage-aggregate.csv",csv(rows),"text/csv");
      message("Anonymous aggregate CSV downloaded.");
    }catch(_){message("HOLD: no anonymous handoff from mismatched or missing source.",true);}
  }
  function brief(){
    try{
      const a=safeExport(),esc=x=>String(x).replaceAll("&","&amp;")
        .replaceAll("<","&lt;").replaceAll(">","&gt;");
      const row=(key,value)=>"<tr><th>"+esc(key)+"</th><td>"+esc(value)+"</td></tr>";
      const cells=[
        ["Designed lab cases",a.scenario_count],["Original completed comparison files",a.report_count],
        ["Unknown/unscored source ground truth",a.declared_unscored],
        ["Declared explicitly zero findings",a.declared_zero_findings],
        ["Declared planted expected findings",a.declared_planted_findings],
        ["Original source adverse metric instances",a.source_reported_adverse_metric_instances],
        ...Object.entries(a.human_discussion_stages).map(([k,v])=>["Human "+k,v]),
        ...a.human_queue_priorities.map(q=>["Human priority "+q.category,q.cases]),
        ...Object.entries(a.proposed_human_route_totals).map(([k,v])=>
          ["Proposed human route "+k,v]),
        ...Object.entries(a.next_human_action_totals).map(([k,v])=>
          ["Human next action "+k,v])];
      const html="<!doctype html><html lang='en'><meta charset='utf-8'>"+
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"+
        "<title>LightUp anonymous lineage brief</title><style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:1rem}"+
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:.7rem;text-align:left}</style>"+
        "<h1>LightUp · private lab lineage · anonymous human brief</h1>"+
        "<p><strong>"+(a.fictional_demo_only?"FICTIONAL DEMONSTRATION ONLY":"SOURCE UNVERIFIED")+
        " · REVIEW_ONLY / HOLD</strong></p><p>No original scenario IDs, target IPs, finding IDs, names, hashes, notes or raw source data included.</p>"+
        "<table>"+cells.map(([k,v])=>row(k,v)).join("")+"</table>"+
        "<p>Declared ground truth is not verified detection or remediation. Original metrics are retrospective, untrusted lab summaries. "+
        "All authorization, consent, dispatch and release flags are false. No scans, grants or release are supported.</p></html>";
      download("lightup-lineage-anonymous-brief.html",html,"text/html");
      message("Script-free, target-free human brief downloaded.");
    }catch(_){message("HOLD: brief not available until sources match exactly.",true);}
  }
  function forget(){cancelOldImports();catalog=null;reports=[];reviews=new Map();humanNotes=new Map();noteScratch=new Map();humanRoutes=new Map();humanActions=new Map();mismatchRevealed=false;catalogHash=null;
    reportHashes=[];undoBatch=null;undoRouteBatch=null;clearPendingDraft();
    if(privateTemplate instanceof HTMLTemplateElement){
      privateTemplate.content.replaceChildren();
      $("loadPrivateBundle").disabled=true;
      $("embeddedAvailability").textContent="Any embedded PRIVATE original source has been cleared "+
        "from this browser document. The sensitive original HTML file on disk "+
        "must be deleted separately by its owner.";
    }
    resetFilters();fictional=false;render();
    message("Private source, notes, human plans and embedded draft cleared from the active browser document.");
  }
  function makeDemo(){
    cancelOldImports();
    const names=["scenario-FAKE-01","scenario-FAKE-02","scenario-FAKE-03"];
    catalog=names.map((id,i)=>({id,mode:i===0?"unscored":i===1?
      "declared_zero":"planted",planted:i===0?null:i===1?0:2,
      severity:i===2?{critical:0,high:1,medium:1,low:0,info:0}:null}));
    const candidate=(variant)=>({
      status:variant?"HOLD":"REVIEW_ONLY",
      cases:new Map(names.map((id,i)=>{
        const metrics=new Map(METRICS.map(n=>{
          const base=COUNTS.has(n)?3:SCORES.has(n)?.8:4;
          const val=variant&&i===2&&n==="scope_violations"?base+1:base;
          return [n,{baseline:base,candidate:val,regression:val>base&&n==="scope_violations"}];
        }));
        return [id,{metrics,adverse:variant&&i===2?["scope_violations"]:[]}];
      }))
    });
    reports=[candidate(0),candidate(1)];reviews=new Map();humanNotes=new Map();noteScratch=new Map();humanRoutes=new Map();humanActions=new Map();mismatchRevealed=false;catalogHash=null;
    reportHashes=[];undoBatch=null;undoRouteBatch=null;clearPendingDraft();resetFilters();fictional=true;
    render();message("FICTIONAL offline demonstration loaded; no source evidence or permission.");
  }

  // A PRIVATE workroom contains only inert base64 template text; never eval it.
  // No original data loads until the operator explicitly chooses to import it.
  let pendingPrivateDraft=null;
  const privateTemplate=document.getElementById("originalPrivateBundle");
  function clearPendingDraft(){
    pendingPrivateDraft=null;
    $("restoreEmbeddedDraft").hidden=true;
    $("restoreEmbeddedDraft").disabled=true;
  }
  const hasPrivateBundle=privateTemplate instanceof HTMLTemplateElement;
  $("loadPrivateBundle").hidden=!hasPrivateBundle;
  $("embeddedAvailability").textContent=hasPrivateBundle?
    "A PRIVATE original-source workroom is attached to this file. Its sources "+
    "remain inert until you explicitly load them. Never upload or share this HTML.":
    "This is the public offline standalone; no private source data is embedded.";
  function exactBundleShape(bundle){
    const includesDraft=bundle?.schema==="lightup.private_lineage_bundle.v2";
    admit((bundle?.schema==="lightup.private_lineage_bundle.v1"||includesDraft)&&
      exact(bundle,["schema","status",...FLAGS,"catalog_b64","reports_b64",
        ...(includesDraft?["human_draft_b64"]:[])])&&
      bundle.status==="PRIVATE_UNTRUSTED_SOURCE_ONLY"&&flags(bundle)&&
      typeof bundle.catalog_b64==="string"&&Array.isArray(bundle.reports_b64)&&
      bundle.reports_b64.length>=1&&bundle.reports_b64.length<=8);
    if(includesDraft)admit(typeof bundle.human_draft_b64==="string"&&
      bundle.human_draft_b64.length>=4&&bundle.human_draft_b64.length<=90000);
    return includesDraft;
  }
  function decodedPrivateFile(value,index,maximum){
    admit(typeof value==="string"&&value.length>0&&
      value.length<=Math.ceil(maximum/3)*4+4&&
      value.length%4===0&&/^[A-Za-z0-9+/]*={0,2}$/.test(value));
    const binary=atob(value);
    admit(binary.length>=1&&binary.length<=maximum);
    const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
    return new File([bytes],"PRIVATE-original-slot-"+index+".json",
      {type:"application/json"});
  }
  async function loadPrivateBundle(){
    if(!hasPrivateBundle)return;
    if((catalog||reports.length)&&!confirm(
      "Clear current private work and replace it with the original source files "+
      "inside this PRIVATE HTML? This does not scan, grant or evaluate."))return;
    const generation=startImport();
    try{
      const raw=privateTemplate.content.textContent;
      admit(typeof raw==="string"&&raw.length>0&&raw.length<=5_000_000);
      const bundle=parse(raw),hasDraft=exactBundleShape(bundle);
      const sourceCatalog=await read(decodedPrivateFile(bundle.catalog_b64,0,MAX_CATALOG),
        MAX_CATALOG);
      admitCurrent(generation);
      const nextCatalog=parseCatalog(sourceCatalog.result),nextReports=[],nextHashes=[];
      for(let i=0;i<bundle.reports_b64.length;i++){
        const imported=await read(decodedPrivateFile(bundle.reports_b64[i],i+1,MAX_REPORT),
          MAX_REPORT);
        admitCurrent(generation);
        nextReports.push(parseReport(imported.result));
        nextHashes.push(imported.digest);
      }
      harmonize(nextReports);
      // All source files and the original generation must still be current.
      admitCurrent(generation);
      catalog=nextCatalog;reports=nextReports;catalogHash=sourceCatalog.digest;
      reportHashes=nextHashes;reviews=new Map();humanNotes=new Map();noteScratch=new Map();humanRoutes=new Map();humanActions=new Map();mismatchRevealed=false;undoBatch=null;undoRouteBatch=null;fictional=false;
      clearPendingDraft();
      pendingPrivateDraft=hasDraft?bundle.human_draft_b64:null;
      $("restoreEmbeddedDraft").hidden=!pendingPrivateDraft;
      $("restoreEmbeddedDraft").disabled=!pendingPrivateDraft;
      resetFilters();render();
      // The template is no longer needed after import and should not linger in DOM.
      privateTemplate.content.replaceChildren();
      $("loadPrivateBundle").disabled=true;
      $("embeddedAvailability").textContent=
        "PRIVATE original files admitted in memory. Embedded template cleared. "+
        (pendingPrivateDraft?"An additional original-byte-bound PRIVATE human draft is "+
          "available for separate explicit restore. ":"")+
        "Source report membership is not verified until reviewed below.";
      message("Private originals loaded from inert offline HTML. No network, scanner, "+
        "authenticated consent or grants used.");
    }catch(_){
      if(generation===importGeneration)message("HOLD: embedded PRIVATE original source rejected. "+
        "Existing review workspace preserved.",true);
    }
  }
  $("loadPrivateBundle").addEventListener("click",loadPrivateBundle);
  $("restoreEmbeddedDraft").addEventListener("click",async()=>{
    if(!pendingPrivateDraft)return;
    if(!confirm("Restore the exact-original-source-bound PRIVATE human work state "+
      "from this owner-private HTML? Existing local stage, notes and planning "+
      "labels would be replaced; this grants NO permission."))return;
    const source=pendingPrivateDraft;clearPendingDraft();
    try{
      await restorePrivateDraft(decodedPrivateFile(source,99,65536));
    }catch(_){message("HOLD: embedded PRIVATE human draft could not be admitted.",true);}
  });

  $("catalogFile").addEventListener("change",async e=>{
    const file=e.target.files?.[0];if(!file)return;e.target.value="";
    const generation=startImport();
    try{
      const imported=await read(file,MAX_CATALOG);admitCurrent(generation);
      const candidate=parseCatalog(imported.result);
      if((catalog||reports.length)&&!confirm("Replace private catalog and clear previously imported lab comparisons and human stage work?"))return;
      admitCurrent(generation);
      catalog=candidate;reports=[];reviews=new Map();humanNotes=new Map();noteScratch=new Map();humanRoutes=new Map();humanActions=new Map();mismatchRevealed=false;catalogHash=imported.digest;
      reportHashes=[];undoBatch=null;undoRouteBatch=null;clearPendingDraft();resetFilters();fictional=false;render();
      message("PRIVATE lab design admitted. Targets and finding IDs were discarded after validation.");
    }catch(_){if(generation===importGeneration)message("HOLD: incompatible PRIVATE Lab Scenario Studio source. Existing data preserved.",true);}
  });
  $("reportFiles").addEventListener("change",async e=>{
    const files=[...(e.target.files||[])];e.target.value="";
    if(!files.length)return;
    const generation=startImport();
    try{
      admit(catalog&&!fictional&&files.length>=1&&reports.length+files.length<=8);
      const add=[],digests=[];
      for(const file of files){
        const imported=await read(file,MAX_REPORT);admitCurrent(generation);
        add.push(parseReport(imported.result));digests.push(imported.digest);
      }
      harmonize([...reports,...add]);admitCurrent(generation);
      reports=[...reports,...add];reportHashes=[...reportHashes,...digests];mismatchRevealed=false;clearPendingDraft();
      reopenHumanStages();render();
      message("Canonical summaries admitted; all human stages reopened for source review. "+
        "Private notes kept locally. Original benchmark data is not authenticated.");
    }catch(_){if(generation===importGeneration)message("HOLD: contradictory, duplicate, oversized or incompatible comparison source. Workspace preserved.",true);}
  });
  $("demo").addEventListener("click",()=>{
    if((catalog||reports.length)&&!confirm("Replace current PRIVATE workspace with invented example?"))return;
    makeDemo();
  });
  $("forget").addEventListener("click",()=>{
    if((catalog||reports.length)&&!confirm("Permanently forget in-memory private inputs and local discussion stages?"))return;
    forget();
  });
  for(const id of ["familyFilter","stageFilter","truthFilter","routeFilter","actionFilter"])
    $(id).addEventListener("change",render);
  for(const id of ["boardStatus","boardRoute"])$(id).addEventListener("change",renderHumanActionBoard);
  $("inspectCase").addEventListener("change",renderInspector);
  $("privateCaseNote").addEventListener("input",()=>{
    cancelOldImports();
    const index=Number($("inspectCase").value);
    if(!catalog||!Number.isSafeInteger(index)||index<0||index>=catalog.length)return;
    const id=catalog[index].id,raw=$("privateCaseNote").value;
    if(raw===(humanNotes.get(id)||""))noteScratch.delete(id);
    else noteScratch.set(id,raw);
    $("privateNoteState").textContent=noteScratch.has(id)?
      "UNSAVED PRIVATE note draft retained in memory across case navigation. "+
      "Not included in any output until Save note is clicked.":
      "PRIVATE note matches saved local version.";
  });
  $("saveCaseNote").addEventListener("click",()=>{cancelOldImports();saveCaseNote();});
  $("saveHumanPlan").addEventListener("click",()=>{cancelOldImports();setHumanPlan();});
  $("adoptSourceHint").addEventListener("click",()=>{cancelOldImports();adoptSourceHint();});
  $("revealMismatch").addEventListener("click",toggleMismatch);
  $("sourceOrder").addEventListener("change",renderSourceOrder);
  $("sourceEarlier").addEventListener("click",()=>{cancelOldImports();chooseSource(-1);});
  $("sourceLater").addEventListener("click",()=>{cancelOldImports();chooseSource(1);});
  $("removeSource").addEventListener("click",()=>{cancelOldImports();removeSource();});
  $("applyStage").addEventListener("click",()=>{cancelOldImports();humanBulk();});
  $("undoStage").addEventListener("click",()=>{cancelOldImports();undoHumanBulk();});
  $("suggestRoutes").addEventListener("click",()=>{cancelOldImports();bulkSuggestHumanRoutes();});
  $("undoRoute").addEventListener("click",()=>{cancelOldImports();undoHumanRoutes();});
  $("exportDraft").addEventListener("click",exportPrivateDraft);
  $("exportPrivateActionBrief").addEventListener("click",exportPrivateActionBrief);
  $("restoreDraft").addEventListener("change",async e=>{
    const f=e.target.files?.[0];e.target.value="";
    if(f)await restorePrivateDraft(f);
  });
  $("printAnonymousButton").addEventListener("click",()=>{
    renderAnonymousPrint();if(!$("printAnonymousButton").disabled)window.print();
  });
  $("exportJson").addEventListener("click",exportJson);
  $("exportCsv").addEventListener("click",exportCsv);
  $("exportFilteredQueueCsv").addEventListener("click",exportFilteredQueueCsv);
  $("exportFilteredQueueHtml").addEventListener("click",exportFilteredQueueHtml);
  $("exportBrief").addEventListener("click",brief);
  render();
})();