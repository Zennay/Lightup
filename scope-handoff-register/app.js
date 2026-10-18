"use strict";
(() => {
  // Offline preparation only: no fetch, storage, authentication or authorization surface.
  const KIND = "lightup.scope_proposal_draft";
  const MAX = 16, SIZE = 65536, RESTORE_SIZE = 131072;
  const DENIAL = Object.freeze({
    authenticated: false, consent: false, authorized: false, grant: false,
    execution: false, scan: false, dispatch: false, deploy: false, release: false
  });
  const TASKS = Object.freeze([
    ["owner", "Ownership/contact route", "Identify who must independently prove authority over each asset."],
    ["assets", "Asset and exclusion boundaries", "Review identities, explicit exclusions, CIDR and DNS ambiguities."],
    ["risk", "Risk and permitted activities", "Discuss the requested mode and risk with the authorized operator."],
    ["schedule", "Time zone and maintenance window", "Resolve UTC, DST and actual appointment independently."],
    ["stops", "Emergency stop and incident route", "Agree on who can stop work and how incidents are reported."],
    ["privacy", "Evidence retention and privacy", "Agree on minimization, access and deletion routes."],
    ["client", "Authenticated client request path", "Plan separate, actual client sign-in and request submission."],
    ["operator", "Independent operator review path", "Plan actual operator authentication, review and revocation checks."]
  ]);
  const STATUSES = Object.freeze(["open", "working", "prepared", "needs_revision"]);
  const STATUS_TEXT = Object.freeze({open:"Open",working:"In gesprek",prepared:"Voor overdracht voorbereid",needs_revision:"Herziening nodig"});
  const records = [];
  let active = null;
  const $ = id => document.getElementById(id);
  const show = (message, error=false) => {
    $("notice").textContent = message;
    $("notice").classList.toggle("error", error);
  };
  const node = (tag, className, value) => {
    const n = document.createElement(tag);
    if (className) n.className=className;
    if (value !== undefined) n.textContent=String(value);
    return n;
  };
  const isPlain = value => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  const digestBytes = async original => {
    assert(original instanceof Uint8Array && globalThis.crypto && crypto.subtle && crypto.subtle.digest,
      "Originele SHA-256 bronbytes niet beschikbaar in deze browsercontext.");
    const array = new Uint8Array(await crypto.subtle.digest("SHA-256",original));
    return Array.from(array,b=>b.toString(16).padStart(2,"0")).join("");
  };
  // Do not use file.text(): lossy UTF-8 replacement corrupts source-byte identity.
  async function readOriginalBytes(file,max) {
    assert(file instanceof File && file.size>0 && file.size<=max,"Bestand leeg of boven de toegestane bytegrens.");
    const sourceBytes=new Uint8Array(await file.arrayBuffer());
    assert(sourceBytes.byteLength===file.size && sourceBytes.byteLength<=max,"Originele bronbytegrootte komt niet overeen.");
    assert(!(sourceBytes[0]===0xef && sourceBytes[1]===0xbb && sourceBytes[2]===0xbf),
      "UTF-8 BOM niet ondersteund: gebruik het originele Studio JSON.");
    let raw;
    try {raw=new TextDecoder("utf-8",{fatal:true}).decode(sourceBytes);}
    catch(_) {throw new Error("Ongeldige UTF-8-bronbytes; geen verliesgevende vervangingsdecodering.");}
    return {raw,sha:await digestBytes(sourceBytes)};
  }
  // JSON.parse alone silently accepts duplicate object keys. Enforce unique decoded names first.
  function parseUnique(s) {
    const value = JSON.parse(s);
    let i=0;
    const ws = () => { while (i<s.length && /\s/.test(s[i])) i++; };
    function readString() {
      assert(s[i]==='"',"JSON-string verwacht.");
      const begin=i++;
      while (i<s.length) {
        if (s[i]==="\\") { i+=2; continue; }
        if (s[i++]==='"') return JSON.parse(s.slice(begin,i));
      }
      throw new Error("Onafgesloten JSON-string.");
    }
    function walk(depth) {
      assert(depth<=24,"JSON te diep genest.");
      ws();
      if (s[i]==="{") {
        i++; ws();
        const keys = new Set();
        if (s[i]==="}") {i++; return;}
        while (true) {
          ws(); const k=readString();
          assert(!keys.has(k),"Dubbele JSON-sleutel geweigerd.");
          keys.add(k); ws(); assert(s[i++]===":","JSON-structuur.");
          walk(depth+1); ws();
          if (s[i]==="}") {i++; return;}
          assert(s[i++]===",","JSON-structuur.");
        }
      }
      if (s[i]==="[") {
        i++; ws(); if (s[i]==="]") {i++;return;}
        while (true) {
          walk(depth+1); ws();
          if (s[i]==="]") {i++;return;}
          assert(s[i++]===",","JSON-structuur.");
        }
      }
      if (s[i]==='"') {readString();return;}
      const begin=i;
      while (i<s.length && !/[\s,}\]]/.test(s[i])) i++;
      assert(i>begin,"JSON-waarde verwacht.");
    }
    walk(0); ws(); assert(i===s.length,"Onverwachte data na JSON.");
    return value;
  }
  function strictArray(value,name,limit,length=255) {
    assert(Array.isArray(value)&&value.length<=limit,name+" ongeldig of te groot.");
    for (const item of value) assert(typeof item==="string" && item.length>0 && item.length<=length,name+" heeft ongeldige tekst.");
  }
  function validateDraft(o) {
    assert(isPlain(o),"Studio-v1 object verwacht.");
    assert(o.kind===KIND && o.schema_version===1 && o.state==="DRAFT_ONLY","Alleen ongewijzigde Studio-v1 DRAFT_ONLY concepten.");
    assert(o.requested_mode==="analysis_only"||o.requested_mode==="authorized_assessment","Ongeldige conceptmodus.");
    assert(Number.isInteger(o.requested_risk)&&o.requested_risk>=1&&o.requested_risk<=4,"Ongeldig risiconiveau.");
    strictArray(o.requested_assets,"Assets",80,253);
    strictArray(o.excluded_assets,"Exclusions",80,253);
    const canonicalAssets=o.requested_assets.map(v=>LightUpScopeNetwork.parse(v));
    const canonicalExclusions=o.excluded_assets.map(v=>LightUpScopeNetwork.parse(v));
    assert(canonicalAssets.every(Boolean) && canonicalExclusions.every(Boolean),
      "Asset of uitsluiting voldoet niet aan het Studio-v1 hostname/IP/CIDR-contract.");
    assert(new Set(canonicalAssets.map(v=>v.canonical)).size===canonicalAssets.length &&
      new Set(canonicalExclusions.map(v=>v.canonical)).size===canonicalExclusions.length,
      "Dubbel canoniek asset-/uitsluitingsrecord.");
    const utcValid=LightUpPlanningWindow.validateStored(o.proposed_window_local,o.proposed_window_utc);
    assert(utcValid,"Planning en UTC-offset komen niet overeen met de bron.");
    assert(o.requested_assets.length>0,"Een concept zonder voorgestelde assets kan niet worden geregistreerd.");
    assert(isPlain(o.proposed_activities) &&
      Object.keys(o.proposed_activities).length===3 &&
      ["passive_analysis","configuration_review","private_lab_network_checks"].every(k=>typeof o.proposed_activities[k]==="boolean"),
      "Ongeldig Studio-v1 activiteitenobject.");
    const immutableDenials=["authorization","client_consent","operator_consent","grant","execution","revocation_checked"];
    assert(immutableDenials.every(k=>Object.hasOwn(o,k) && o[k]===false),
      "Studio-concept met ontbrekende of afwijkende autorisatie-/consentstatus geweigerd.");
    assert(isPlain(o.proposed_window_local)&&
      ["start","end"].every(k=>o.proposed_window_local[k]===null || typeof o.proposed_window_local[k]==="string"),
      "Ongeldige lokale planning.");
    const forbidden = ["grant_id","access_token","password","session_token","approved","authorized","consent","signature","execution_permit"];
    const scan = (x,depth=0) => {
      assert(depth<=24,"Concept te diep genest.");
      if (Array.isArray(x)) {x.forEach(y=>scan(y,depth+1));return;}
      if (isPlain(x)) for (const [k,v] of Object.entries(x)) {
        assert(!forbidden.includes(k.toLowerCase()),"Autorisatie-/geheimveld niet toegestaan in het concept.");
        scan(v,depth+1);
      }
    };
    scan(o);
    return {
      assets:o.requested_assets.slice(),
      excluded:o.excluded_assets.slice(),
      risk:o.requested_risk, mode:o.requested_mode,
      utcWindow:o.proposed_window_utc || null,
      hasWindow:!!o.proposed_window_utc && o.proposed_window_utc.status==="resolved",
      studioDigest:null
    };
  }
  function newRecord(sha,source) {
    return {sha,source,reference:"Dossier "+String(records.length+1),replaces:null,tasks:Object.fromEntries(TASKS.map(([id])=>[id,"open"]))};
  }
  function localCoverage(r) {
    return LightUpScopeNetwork.effectiveCoverage(r.source.assets,r.source.excluded);
  }
  function sharedHints(r) {
    const current=localCoverage(r), spatial=[],clock=[];
    for(const other of records) {
      if(other===r) continue;
      if(LightUpScopeNetwork.coverageOverlap(current,localCoverage(other))) spatial.push(other.sha);
      if(LightUpPlanningWindow.overlaps(r.source.utcWindow,other.source.utcWindow)===true) clock.push(other.sha);
    }
    return {spatial_count:spatial.length,utc_window_count:clock.length};
  }
  function meetingPairs() {
    const pairs=[];
    const effective=records.map(localCoverage);
    for(let i=0;i<records.length;i++)for(let j=i+1;j<records.length;j++){
      const a=records[i],b=records[j];
      const scope_overlap=LightUpScopeNetwork.coverageOverlap(effective[i],effective[j]);
      const utc_overlap=LightUpPlanningWindow.overlaps(a.source.utcWindow,b.source.utcWindow)===true;
      if(!scope_overlap&&!utc_overlap) continue;
      pairs.push({left:a.sha,right:b.sha,scope_overlap,utc_overlap,
        priority:scope_overlap&&utc_overlap?"combined":scope_overlap?"scope":"schedule"});
    }
    const weight={combined:0,scope:1,schedule:2};
    return pairs.sort((a,b)=>weight[a.priority]-weight[b.priority] ||
      Math.max(records.find(x=>x.sha===b.left).source.risk,records.find(x=>x.sha===b.right).source.risk)-
      Math.max(records.find(x=>x.sha===a.left).source.risk,records.find(x=>x.sha===a.right).source.risk));
  }
  function renderMeetingAgenda() {
    const area=$("conflicts"),counts=$("conflictStats");area.replaceChildren();counts.replaceChildren();
    const pairs=meetingPairs();
    const count=(caption,n)=>{
      const m=node("span","metric");m.append(node("strong","",n),node("span","",caption));counts.append(m);
    };
    count("Voorstellenparen met overlegpunt",pairs.length);
    count("Mogelijke scope-overlap",pairs.filter(x=>x.scope_overlap).length);
    count("UTC-vensteroverlap",pairs.filter(x=>x.utc_overlap).length);
    if(!pairs.length){area.append(node("p","small","Geen berekende paren. Dit bewijst geen geldige toestemming, veilig netwerk of conflictvrije planning."));return;}
    for(const p of pairs){
      const left=records.find(x=>x.sha===p.left),right=records.find(x=>x.sha===p.right);
      const card=node("article","conflict-card");
      const title=node("h3","",left.reference+" ↔ "+right.reference);
      const meta=node("p","small","Bronnen "+p.left.slice(0,12)+"… / "+p.right.slice(0,12)+"… · max. voorgesteld risico "+Math.max(left.source.risk,right.source.risk));
      const codes=node("div","chips");
      if(p.scope_overlap)codes.append(node("span","chip alert","Numerieke/literale scope-overlap na uitsluitingen"));
      if(p.utc_overlap)codes.append(node("span","chip alert","Gelijktijdige voorgestelde UTC-vensters"));
      card.append(title,meta,codes,node("p","small","Menselijke actie: controleer onafhankelijk eigendom, uitzonderingen, tenant-scheiding, daadwerkelijk gereserveerde tijden en noodstop. Geen claim dat dit dezelfde klant is."));
      const jump=node("div","actions");
      for(const r of [left,right]){
        const btn=node("button","",r.reference+" openen");
        btn.type="button";btn.addEventListener("click",()=>{
          active=r.sha;render();$("detail").scrollIntoView({block:"start",behavior:"smooth"});
        });jump.append(btn);
      }
      card.append(jump);area.append(card);
    }
  }
  // Explicit human-declared revision lineage. Shared file contents never prove shared client identity.
  function revisionDelta(r) {
    const old=records.find(x=>x.sha===r.replaces);
    if(!old)return null;
    const count=(from,to)=>({added:[...new Set(to)].filter(x=>!new Set(from).has(x)).length,
      removed:[...new Set(from)].filter(x=>!new Set(to).has(x)).length});
    const coverageDiff=LightUpScopeNetwork.coverageDifference(localCoverage(old),localCoverage(r));
    const changedTime=JSON.stringify(old.source.utcWindow)!==JSON.stringify(r.source.utcWindow);
    return {assets:count(old.source.assets,r.source.assets),
      exclusions:count(old.source.excluded,r.source.excluded),
      effective_added_segments:coverageDiff?.added.length ?? null,
      effective_removed_segments:coverageDiff?.removed.length ?? null,
      effective_truncated:coverageDiff?.truncated ?? true,
      risk_changed:old.source.risk!==r.source.risk,
      risk_increased:r.source.risk>old.source.risk,
      mode_changed:old.source.mode!==r.source.mode,
      time_window_presence_changed:old.source.hasWindow!==r.source.hasWindow,
      time_window_changed:changedTime,
      possible_expansion:(coverageDiff?.added.length ?? 0)>0 || (coverageDiff?.truncated ?? true) ||
        r.source.risk>old.source.risk ||
        (old.source.mode==="analysis_only" && r.source.mode==="authorized_assessment")};
  }
  function setRevision(r,priorSha) {
    if (!priorSha) {r.replaces=null;return;}
    assert(priorSha!==r.sha && records.some(x=>x.sha===priorSha),"Ongeldige revisierelatie.");
    assert(!records.some(x=>x!==r&&x.replaces===priorSha),"De voorganger is al gekoppeld aan een andere opvolger.");
    let cursor=priorSha;
    const visited=new Set();
    while(cursor) {
      assert(cursor!==r.sha && !visited.has(cursor),"Cyclische revisiehistorie geweigerd.");
      visited.add(cursor); cursor=records.find(x=>x.sha===cursor)?.replaces??null;
    }
    r.replaces=priorSha;
  }
  function warnings(r) {
    const w=[];
    const rev=revisionDelta(r);
    if (rev?.possible_expansion) w.push("revisie_mogelijke_scopeuitbreiding");
    if (rev?.mode_changed) w.push("revisie_modusgewijzigd");
    if (r.source.risk===4) w.push("hoog_risico");
    if (r.source.mode==="authorized_assessment") w.push("actieve_modus_voorgesteld");
    if (!r.source.excluded.length) w.push("geen_exclusies_opgegeven");
    if (!r.source.hasWindow) w.push("tijdvenster_te_bespreken");
    for(const issue of LightUpScopeNetwork.inspect(r.source.assets,r.source.excluded))
      if(["included_overlap","exclusion_overlap","global_range","ipv6"].includes(issue.code))
        if(!w.includes("scope_"+issue.code))w.push("scope_"+issue.code);
    const related=sharedHints(r);
    if(related.spatial_count>0)w.push("effectieve_numerieke_of_host_scope_overlap");
    if(related.utc_window_count>0)w.push("utc_planningsoverlap");
    return w;
  }
  const prepared = r => TASKS.filter(([id])=>r.tasks[id]==="prepared").length;
  function visibleRecords() {
    const query=$("search").value.trim().toLowerCase();
    const filter=$("filter").value;
    return records.filter(r=>{
      if(filter==="attention" && prepared(r)===TASKS.length)return false;
      if(filter==="ready" && prepared(r)!==TASKS.length)return false;
      if(filter==="high-risk" && r.source.risk!==4)return false;
      if(filter==="revision" && !r.replaces)return false;
      const searchable=(r.reference+" risk "+r.source.risk+" "+TASKS.filter(([id])=>r.tasks[id]!=="prepared").map(x=>x[1]).join(" ")).toLowerCase();
      return searchable.includes(query);
    }).sort((a,b)=>{
      const mode=$("sort").value;
      if(mode==="risk")return b.source.risk-a.source.risk || warnings(b).length-warnings(a).length;
      if(mode==="progress")return prepared(a)-prepared(b);
      return records.indexOf(a)-records.indexOf(b);
    });
  }
  function render() {
    $("stats").replaceChildren();
    const stats=[["Concepten",records.length],["Acties voorbereid",records.reduce((n,r)=>n+prepared(r),0)],["Open/vervolg",records.reduce((n,r)=>n+TASKS.length-prepared(r),0)],["Discussiepunten",records.reduce((n,r)=>n+warnings(r).length,0)]];
    for (const [label,val] of stats) {
      const m=node("div","metric");
      m.append(node("strong","",val),node("span","",label));$("stats").append(m);
    }
    const boards=$("boards");boards.replaceChildren();
    for (const r of visibleRecords()) {
      const card=node("button","card"+(active===r.sha?" selected":""));
      card.type="button";card.setAttribute("aria-pressed",String(active===r.sha));
      card.append(node("span","card-title",r.reference),node("span","meta","SHA-256 "+r.sha.slice(0,16)+"…"),node("span","meta","Risico "+r.source.risk+" · "+(r.source.mode==="analysis_only"?"Analysevoorstel":"Actieve modus voorgesteld")+" · "+r.source.assets.length+" assetregels"));
      const chips=node("span","chips");
      chips.append(node("span","chip",prepared(r)+"/"+TASKS.length+" voorbereidingen"));
      if(r.replaces) chips.append(node("span","chip","Revisie van "+r.replaces.slice(0,10)+"…"));
      for (const warning of warnings(r)) chips.append(node("span","chip alert",warning.replaceAll("_"," ")));
      card.append(chips);
      card.addEventListener("click",()=>{active=r.sha;render();});
      boards.append(card);
    }
    if (!boards.children.length) boards.append(node("p","small","Geen concepten gevonden voor deze selectie."));
    renderDetail();
    renderMeetingAgenda();
  }
  function renderDetail() {
    const detail=$("detail");detail.replaceChildren();
    const r=records.find(x=>x.sha===active);
    if (!r) {detail.append(node("p","","Selecteer een concept om voorbereidingsacties te bekijken."));return;}
    detail.append(node("h3","",r.reference+" — voorbereidingsroute"));
    detail.append(node("p","small","Dit betreft uitsluitend zelf bijgehouden voorbereiding. Een vinkje is geen verificatie en wordt nooit een autorisatieverklaring."));
    const controls=node("div","controls"), lab=node("label","","Interne referentie (alleen lokaal)");
    const input=node("input");input.maxLength=32;input.value=r.reference;
    input.addEventListener("change",()=>{r.reference=input.value.trim().slice(0,32)||"Naamloos dossier";render();});
    lab.append(input);controls.append(lab);
    const del=node("button","","Verwijder alleen dit concept");del.type="button";
    del.addEventListener("click",()=>{if(!confirm("Dit concept en de lokale voorbereidingsantwoorden verwijderen?"))return;records.splice(records.indexOf(r),1);for(const x of records)if(x.replaces===r.sha)x.replaces=null;active=records[0]?.sha??null;show("Concept en afhankelijke revisiekoppeling(en) uit deze browsersessie verwijderd; andere taakstatussen behouden.");render();});
    controls.append(del);detail.append(controls);
    const relation=node("div","controls");
    const revLabel=node("label","","Voorganger koppelen (handmatig, geen eigendomsbewijs)");
    const revSelect=node("select");
    const none=node("option","","Geen voorganger");none.value="";revSelect.append(none);
    for(const other of records) if(other.sha!==r.sha) {
      const opt=node("option","",other.reference+" · "+other.sha.slice(0,10)+"…");
      opt.value=other.sha;revSelect.append(opt);
    }
    revSelect.value=r.replaces||"";
    revSelect.addEventListener("change",()=>{
      if(revSelect.value && !confirm("Verklaar uitsluitend voor lokale review dat dit een nieuwe versie van dezelfde bron is. Bestaande voorbereiding wordt NIET geërfd. Koppelen?")) {revSelect.value=r.replaces||"";return;}
      try{setRevision(r,revSelect.value);show("Revisielijn bijgewerkt. Acties en toestemming van andere versies zijn niet gekopieerd.");render();}
      catch(err){show("Revisiekoppeling geweigerd: "+err.message,true);revSelect.value=r.replaces||"";}
    });
    revLabel.append(revSelect);relation.append(revLabel);detail.append(relation);
    const rev=revisionDelta(r);
    if(rev) detail.append(node("p","summary","Letterlijke revisieverschillen (geen eigendom of CIDR-dekking): assets +"+rev.assets.added+"/−"+rev.assets.removed+
      ", exclusies +"+rev.exclusions.added+"/−"+rev.exclusions.removed+
      ", risicotoename: "+(rev.risk_increased?"ja":"nee")+", modus gewijzigd: "+(rev.mode_changed?"ja":"nee")+
      ". Effectieve netwerk-/hostnameverschillen na exclusies (max 160 segmenten): +"+rev.effective_added_segments+"/−"+rev.effective_removed_segments+
      (rev.effective_truncated?" (afgekapt)":"")+
      ". UTC-venster gewijzigd: "+(rev.time_window_changed?"ja":"nee")+
      ". Mogelijke uitbreiding: "+(rev.possible_expansion?"JA — onafhankelijke herbeoordeling nodig":"niet uit deze signalen gebleken")+
      ". Voorbereidingsacties blijven apart; geen automatische overname. Geen DNS of autorisatiecontrole."));
    const hint=node("p","summary","Reviewpunten: "+(warnings(r).length?warnings(r).join(", ").replaceAll("_"," "):"Geen automatisch aangemerkte signalen. Dat bewijst geen veilige scope.")+". Exacte asset-overlap betekent niet gedeeld eigendom of geldige toestemming.");
    detail.append(hint);
    for (const [id,title,description] of TASKS) {
      const row=node("div","checkrow");const info=node("div"),titleEl=node("label","",title);
      titleEl.htmlFor="task-"+id;info.append(titleEl,node("small","",description));
      const select=node("select");select.id="task-"+id;
      for (const state of STATUSES) {const option=node("option","",STATUS_TEXT[state]);option.value=state;select.append(option);}
      select.value=r.tasks[id];select.addEventListener("change",()=>{r.tasks[id]=select.value;render();});
      row.append(info,select);detail.append(row);
    }
    detail.append(node("p","small","Status: "+prepared(r)+" van "+TASKS.length+" voorbereid. Zelfs bij 8/8 blijft dit REVIEW_ONLY_HOLD. Gebruik het originele geauthenticeerde proces voor toestemming en directe herroepingscontrole."));
  }
  async function readBounded(file,max) {
    const source=await readOriginalBytes(file,max);
    return parseUnique(source.raw);
  }
  async function importDrafts(files) {
    assert(files.length>0&&files.length<=MAX,"Selecteer maximaal 16 bestanden.");
    const incoming=[];const seen=new Set(records.map(x=>x.sha));
    // Validate every document before changing the live view.
    for (const file of files) {
      const fileSource=await readOriginalBytes(file,SIZE);
      const parsed=parseUnique(fileSource.raw);
      const source=validateDraft(parsed);
      const studioDigest=await LightUpScopeDigest.fingerprint(parsed);
      assert(studioDigest && /^[a-f0-9]{64}$/.test(studioDigest),
        "Studio-v1 scope-identiteit niet canoniek te berekenen.");
      if (Object.hasOwn(parsed,"scope_fingerprint_sha256"))
        assert(parsed.scope_fingerprint_sha256===studioDigest,
          "Studio-v1 scope-fingerprint komt niet overeen met het oorspronkelijke concept.");
      source.studioDigest=studioDigest;
      const sha=fileSource.sha;
      if (seen.has(sha)) continue;
      seen.add(sha);incoming.push({sha,source});
    }
    assert(records.length+incoming.length<=MAX,"Het register bevat maximaal 16 verschillende conceptversies.");
    incoming.forEach(x=>records.push(newRecord(x.sha,x.source)));
    if (!active && records.length) active=records[0].sha;
    show(incoming.length+" conceptversie(s) geladen. Identieke bronbytes zijn niet dubbel toegevoegd; wijzigingen moeten als afzonderlijke versie worden beoordeeld.");
    render();
  }
  function download(data,name,type) {
    const blob=new Blob([data],{type}),url=URL.createObjectURL(blob),link=document.createElement("a");
    link.href=url;link.download=name;document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
  }
  const json=(data,name)=>download(JSON.stringify(data,null,2)+"\n",name,"application/json;charset=utf-8");
  const authority=()=>({...DENIAL});
  function snapshot() {
    return {kind:"lightup.scope_handoff_local_progress",schema_version:1,state:"REVIEW_ONLY_HOLD",authority:authority(),
      entries:records.map(r=>({sha256:r.sha,reference:r.reference,replaces:r.replaces,tasks:{...r.tasks}}))};
  }
  function report() {
    return {kind:"lightup.scope_handoff_review_register",schema_version:1,state:"REVIEW_ONLY_HOLD",authority:authority(),
      notice:"Unverified local human preparation; no authorization, consent, identity or ownership assertion.",
      review_agenda:meetingPairs().map(p=>({
        dossier_a:"D"+String(records.findIndex(x=>x.sha===p.left)+1).padStart(2,"0"),
        dossier_b:"D"+String(records.findIndex(x=>x.sha===p.right)+1).padStart(2,"0"),
        numeric_or_literal_scope_overlap:p.scope_overlap,
        proposed_utc_overlap:p.utc_overlap,
        review_only:true
      })),
      entries:records.map((r,i)=>({
        dossier:"D"+String(i+1).padStart(2,"0"),source_sha256:r.sha,
        studio_revision_sha256:r.source.studioDigest,
        replaces_source_sha256:r.replaces,revision:revisionDelta(r),offline_shared_review_hints:sharedHints(r),
        proposed_risk:r.source.risk,proposed_mode:r.source.mode,
        asset_count:r.source.assets.length,excluded_count:r.source.excluded.length,
        review_codes:warnings(r),tasks:Object.fromEntries(TASKS.map(([id])=>[id,r.tasks[id]])),
        preparation_only:prepared(r)===TASKS.length
      }))};
  }
  function restore(o) {
    assert(isPlain(o)&&o.kind==="lightup.scope_handoff_local_progress"&&o.schema_version===1&&o.state==="REVIEW_ONLY_HOLD","Geen compatibele lokale voortgang.");
    assert(isPlain(o.authority)&&Object.keys(DENIAL).length===Object.keys(o.authority).length && Object.entries(DENIAL).every(([k,v])=>o.authority[k]===v),"Autorisatievlaggen mogen nooit waar zijn.");
    assert(Array.isArray(o.entries) && o.entries.length===records.length && records.length>0 && o.entries.length<=MAX,"Open eerst precies de oorspronkelijke conceptversies.");
    const shaMap=new Map(records.map(x=>[x.sha,x])),found=new Set(),updates=[];
    for (const entry of o.entries) {
      assert(isPlain(entry)&&typeof entry.sha256==="string" && /^[a-f0-9]{64}$/.test(entry.sha256) && shaMap.has(entry.sha256) && !found.has(entry.sha256),"Bron-SHA mist, is dubbel of niet gelijk.");
      assert(typeof entry.reference==="string"&&entry.reference.length>0&&entry.reference.length<=32 && isPlain(entry.tasks),"Ongeldige lokale label-/takenstructuur.");
      assert(Object.keys(entry).length===4 && ["sha256","reference","replaces","tasks"].every(k=>Object.hasOwn(entry,k)),"Onbekende of ontbrekende statusvelden.");
      assert(Object.keys(entry.tasks).length===TASKS.length && TASKS.every(([id])=>STATUSES.includes(entry.tasks[id])),"Taakset of status is vervormd.");
      assert(entry.replaces===null || (typeof entry.replaces==="string" && shaMap.has(entry.replaces)),"Vreemde revisievoorganger.");
      found.add(entry.sha256);updates.push([shaMap.get(entry.sha256),entry]);
    }
    // Validate the entire proposed revision graph before applying any local updates.
    const simulated=new Map(updates.map(([r,e])=>[r.sha,e.replaces]));
    for(const [sha] of simulated){const visited=new Set([sha]);let cursor=simulated.get(sha);while(cursor){assert(!visited.has(cursor),"Cyclische revisielijn.");visited.add(cursor);cursor=simulated.get(cursor)||null;}}
    const targets=updates.map(([,e])=>e.replaces).filter(Boolean);
    assert(new Set(targets).size===targets.length,"Dubbele voorganger kan niet twee opvolgers hebben.");
    if (!confirm("De huidige lokale voorbereidingsstatussen vervangen voor exact deze bronbestanden?"))return;
    updates.forEach(([r,e])=>{r.reference=e.reference;r.replaces=e.replaces;r.tasks={...e.tasks};});
    show("Lokale voorbereidingsstatussen atomisch hersteld voor identieke originele bestandsbytes.");
    render();
  }
  function fullHtmlPacket() {
    const data=report();
    const esc = value => String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
    const parts=[
      "<!doctype html><html lang=\"nl\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; connect-src 'none'; form-action 'none'\">",
      "<title>LightUp · lokale reviewoverdracht</title><style>",
      "body{font-family:system-ui,sans-serif;color:#142238;max-width:940px;margin:25px auto;padding:16px}article{border:1px solid #bcc7d7;border-radius:8px;margin:15px 0;padding:17px;break-inside:avoid}p{line-height:1.45}th,td{text-align:left;border-bottom:1px solid #bfc8d7;padding:8px}table{border-collapse:collapse;width:100%}.alert{color:#8e450e}.hold{padding:12px;border:2px solid #8e450e}@media print{body{max-width:100%;margin:0}article{break-inside:avoid}}",
      "</style></head><body><h1>LightUp · voorbereidingsregister</h1>",
      "<p class=\"hold\"><strong>REVIEW_ONLY_HOLD — GEEN toestemming, identiteit, asset-eigendom, grant, scan, handler, deploy of vrijgave.</strong> Dit is uitsluitend een lokale menselijke planning. Controleer cliënt en operator onafhankelijk via het echte geauthenticeerde proces en controleer herroeping op het moment van gebruik.</p>",
      "<p>Persoonsgegevens, bestandsnamen, vrije tekst en originele asset-identiteiten zijn niet opgenomen. Deze handoff heeft geen handtekening, actuele geldigheid of onafhankelijk herkomstbewijs.</p>",
      "<p>Conceptdossiers: "+data.entries.length+". De SHA-256 is een byte-identificatie, géén autorisatie- of identiteitshandtekening.</p>"
    ];
    if(data.review_agenda.length){
      parts.push("<h2>Gedeelde menselijke review-agenda</h2><table><thead><tr><th>Voorstellen</th><th>Lokale overlapindicatoren</th></tr></thead><tbody>");
      for(const x of data.review_agenda)parts.push("<tr><td>"+esc(x.dossier_a)+" / "+esc(x.dossier_b)+
        "</td><td>"+esc([x.numeric_or_literal_scope_overlap?"Netwerk/hostname na exclusies":null,x.proposed_utc_overlap?"UTC-venster":null].filter(Boolean).join("; "))+"</td></tr>");
      parts.push("</tbody></table><p>Deze paren bewijzen geen gedeeld eigendom, klant, toestemming of geboekt tijdslot; escaleer onafhankelijk.</p>");
    }
    for(const e of data.entries) {
      parts.push("<article><h2>"+esc(e.dossier)+" · voorgesteld risico "+esc(e.proposed_risk)+"</h2>");
      parts.push("<p>Bronbytes SHA-256: <code>"+esc(e.source_sha256)+"</code><br>Studio semantische revisie SHA-256: <code>"+esc(e.studio_revision_sha256)+"</code><br>Voorgestelde modus: "+esc(e.proposed_mode)+"<br>Inclusies: "+esc(e.asset_count)+", exclusies: "+esc(e.excluded_count)+
        "<br>Andere voorstellen met mogelijke effectieve scope-overlap: "+esc(e.offline_shared_review_hints.spatial_count)+
        "<br>Andere voorstellen met voorgestelde UTC-tijdoverlap: "+esc(e.offline_shared_review_hints.utc_window_count)+"</p>");
      if(e.replaces_source_sha256) {
        parts.push("<p>Zelfverklaarde revisie van <code>"+esc(e.replaces_source_sha256)+"</code>. Statussen van oudere concepten zijn niet overgenomen.</p>");
        if(e.revision) parts.push("<p>Letterlijke revisietellingen: assets toegevoegd "+esc(e.revision.assets.added)+", verwijderd "+esc(e.revision.assets.removed)+
          "; exclusies toegevoegd "+esc(e.revision.exclusions.added)+", verwijderd "+esc(e.revision.exclusions.removed)+
          ". Mogelijke uitbreiding: <strong>"+(e.revision.possible_expansion?"JA":"niet uit deze ruwe vergelijking vastgesteld")+"</strong>. Geen CIDR/DNS-verificatie.</p>");
      }
      parts.push("<p class=\"alert\">Lokale signalen: "+esc(e.review_codes.length?e.review_codes.join(", "):"geen automatisch signaal; geen veiligheidsbewijs")+"</p>");
      parts.push("<table><thead><tr><th>Menselijke voorbereidingsactie</th><th>Zelfgerapporteerde status</th></tr></thead><tbody>");
      for(const [id,title] of TASKS) parts.push("<tr><td>"+esc(title)+"</td><td>"+esc(STATUS_TEXT[e.tasks[id]])+"</td></tr>");
      parts.push("</tbody></table></article>");
    }
    parts.push("<p class=\"hold\">Elk veld authenticated, consent, authorized, grant, execution, scan, dispatch, deploy en release staat letterlijk FALSE. Ook 8/8 voorbereide acties hebben geen juridische of technische autoriteit.</p></body></html>");
    return parts.join("");
  }
  function csv() {
    const rows=[["dossier","scope_sha256","task","status","authority"]];
    report().entries.forEach(e=>TASKS.forEach(([id])=>rows.push([e.dossier,e.source_sha256,id,e.tasks[id],"REVIEW_ONLY_HOLD"])));
    const escape=x=>'"'+String(x).replaceAll('"','""')+'"';
    return "\ufeff"+rows.map(row=>row.map(escape).join(",")).join("\r\n")+"\r\n";
  }
  $("imports").addEventListener("change",async e=>{
    try{await importDrafts(Array.from(e.target.files));}catch(err){show("Import geweigerd; bestaande concepten behouden: "+err.message,true);}
    e.target.value="";
  });
  $("restore").addEventListener("change",async e=>{
    try{restore(await readBounded(e.target.files[0],RESTORE_SIZE));}catch(err){show("Herstel geweigerd zonder wijzigingen: "+err.message,true);}
    e.target.value="";
  });
  $("search").addEventListener("input",render);$("filter").addEventListener("change",render);$("sort").addEventListener("change",render);
  $("bulkStart").addEventListener("click",()=>{
    const task=$("bulkTask").value;
    assert(TASKS.some(([id])=>id===task),"Geen erkende actie.");
    const targets=visibleRecords().filter(r=>r.tasks[task]==="open");
    if(!targets.length){show("Geen zichtbare dossiers met een open status voor dit actiepunt.");return;}
    if(!confirm("Alleen actie '"+TASKS.find(([id])=>id===task)[1]+"' voor "+targets.length+" zichtbare dossiers op ‘In gesprek’ zetten? Dit verleent geen toestemming."))return;
    targets.forEach(r=>{r.tasks[task]="working";});
    show("Voorbereidingsoverleg gestart voor "+targets.length+" lokale dossiers; geen enkele actie op ‘voorbereid’ gezet.");
    render();
  });
  $("clear").addEventListener("click",()=>{
    if(!records.length || !confirm("Alle in-memory concepten en taakstatussen definitief vergeten?"))return;
    records.splice(0);active=null;show("Alle lokale conceptgegevens uit deze browserpagina gewist.");render();
  });
  $("save").addEventListener("click",()=>records.length?json(snapshot(),"lightup-local-progress.json"):show("Laad eerst concepten.",true));
  $("export").addEventListener("click",()=>records.length?json(report(),"lightup-review-only-handoff.json"):show("Laad eerst concepten.",true));
  $("csv").addEventListener("click",()=>records.length?download(csv(),"lightup-handoff-actions.csv","text/csv;charset=utf-8"):show("Laad eerst concepten.",true));
  $("printPack").addEventListener("click",()=>records.length?download(fullHtmlPacket(),"lightup-review-only-handoff.html","text/html;charset=utf-8"):show("Laad eerst concepten.",true));
  $("print").addEventListener("click",()=>records.length?window.print():show("Laad eerst concepten.",true));
  render();
})();
