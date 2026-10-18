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
  const bytes = s => new TextEncoder().encode(s);
  const digest = async s => {
    assert(globalThis.crypto && crypto.subtle && crypto.subtle.digest, "SHA-256 niet beschikbaar in deze browsercontext. Open lokaal in een moderne browser.");
    const array = new Uint8Array(await crypto.subtle.digest("SHA-256",bytes(s)));
    return Array.from(array,b=>b.toString(16).padStart(2,"0")).join("");
  };
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
    strictArray(o.requested_assets,"Assets",80);
    strictArray(o.excluded_assets,"Exclusions",80);
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
      assets:o.requested_assets.map(x=>x.toLowerCase().trim()),
      excluded:o.excluded_assets.map(x=>x.toLowerCase().trim()),
      risk:o.requested_risk, mode:o.requested_mode,
      hasWindow: isPlain(o.proposed_window_utc) && o.proposed_window_utc.status==="resolved" &&
        typeof o.proposed_window_utc.start==="string" &&
        typeof o.proposed_window_utc.end==="string" &&
        Number.isFinite(Date.parse(o.proposed_window_utc.start)) &&
        Number.isFinite(Date.parse(o.proposed_window_utc.end)) &&
        Date.parse(o.proposed_window_utc.end)>Date.parse(o.proposed_window_utc.start)
    };
  }
  function newRecord(sha,source) {
    return {sha,source,reference:"Dossier "+String(records.length+1),replaces:null,tasks:Object.fromEntries(TASKS.map(([id])=>[id,"open"]))};
  }
  // Explicit human-declared revision lineage. Shared file contents never prove shared client identity.
  function revisionDelta(r) {
    const old=records.find(x=>x.sha===r.replaces);
    if(!old)return null;
    const count=(from,to)=>({added:[...new Set(to)].filter(x=>!new Set(from).has(x)).length,
      removed:[...new Set(from)].filter(x=>!new Set(to).has(x)).length});
    return {assets:count(old.source.assets,r.source.assets),
      exclusions:count(old.source.excluded,r.source.excluded),
      risk_changed:old.source.risk!==r.source.risk,
      risk_increased:r.source.risk>old.source.risk,
      mode_changed:old.source.mode!==r.source.mode,
      time_window_presence_changed:old.source.hasWindow!==r.source.hasWindow,
      possible_expansion:count(old.source.assets,r.source.assets).added>0 ||
        count(old.source.excluded,r.source.excluded).removed>0 || r.source.risk>old.source.risk ||
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
    if (new Set(r.source.assets).size!==r.source.assets.length) w.push("dubbele_assetvermelding");
    const siblings=records.filter(x=>x.sha!==r.sha);
    if (siblings.some(x=>r.source.assets.some(a=>x.source.assets.includes(a)))) w.push("gedeelde_letterlijke_assetidentiteit");
    return w;
  }
  const prepared = r => TASKS.filter(([id])=>r.tasks[id]==="prepared").length;
  function render() {
    const query=$("search").value.trim().toLowerCase();
    const filter=$("filter").value;
    $("stats").replaceChildren();
    const stats=[["Concepten",records.length],["Acties voorbereid",records.reduce((n,r)=>n+prepared(r),0)],["Open/vervolg",records.reduce((n,r)=>n+TASKS.length-prepared(r),0)],["Discussiepunten",records.reduce((n,r)=>n+warnings(r).length,0)]];
    for (const [label,val] of stats) {
      const m=node("div","metric");
      m.append(node("strong","",val),node("span","",label));$("stats").append(m);
    }
    const boards=$("boards");boards.replaceChildren();
    for (const r of records) {
      if (filter==="attention" && prepared(r)===TASKS.length) continue;
      if (filter==="ready" && prepared(r)!==TASKS.length) continue;
      const searchable=(r.reference+" risk "+r.source.risk+" "+TASKS.filter(([id])=>r.tasks[id]!=="prepared").map(x=>x[1]).join(" ")).toLowerCase();
      if (!searchable.includes(query)) continue;
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
      ". Mogelijke uitbreiding: "+(rev.possible_expansion?"JA — onafhankelijke herbeoordeling nodig":"niet uit deze signalen gebleken")+
      ". Voorbereidingsacties blijven apart; geen automatische overname."));
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
    assert(file instanceof File && file.size<=max && file.size>0,"Bestand leeg of groter dan limiet.");
    const data=await file.text();
    assert(bytes(data).length<=max,"UTF-8 bestandslimiet overschreden.");
    return parseUnique(data);
  }
  async function importDrafts(files) {
    assert(files.length>0&&files.length<=MAX,"Selecteer maximaal 16 bestanden.");
    const incoming=[];const seen=new Set(records.map(x=>x.sha));
    // Validate every document before changing the live view.
    for (const file of files) {
      const raw=await file.text();
      assert(file.size>0 && file.size<=SIZE && bytes(raw).length<=SIZE,"Studio-concept overschrijdt 64 KiB.");
      const source=validateDraft(parseUnique(raw));
      const sha=await digest(raw);
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
      entries:records.map((r,i)=>({
        dossier:"D"+String(i+1).padStart(2,"0"),source_sha256:r.sha,replaces_source_sha256:r.replaces,revision:revisionDelta(r),
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
  $("search").addEventListener("input",render);$("filter").addEventListener("change",render);
  $("clear").addEventListener("click",()=>{
    if(!records.length || !confirm("Alle in-memory concepten en taakstatussen definitief vergeten?"))return;
    records.splice(0);active=null;show("Alle lokale conceptgegevens uit deze browserpagina gewist.");render();
  });
  $("save").addEventListener("click",()=>records.length?json(snapshot(),"lightup-local-progress.json"):show("Laad eerst concepten.",true));
  $("export").addEventListener("click",()=>records.length?json(report(),"lightup-review-only-handoff.json"):show("Laad eerst concepten.",true));
  $("csv").addEventListener("click",()=>records.length?download(csv(),"lightup-handoff-actions.csv","text/csv;charset=utf-8"):show("Laad eerst concepten.",true));
  $("print").addEventListener("click",()=>records.length?window.print():show("Laad eerst concepten.",true));
  render();
})();
