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
  const TASK_ROLES = Object.freeze({
    owner:"joint",assets:"joint",risk:"operator",schedule:"joint",
    stops:"joint",privacy:"joint",client:"client",operator:"operator"
  });
  const ROLE_LABELS = Object.freeze({client:"Cliënt",operator:"Operator",joint:"Samen"});
  const validDay = value => value===null || (
    typeof value==="string" && /^(20\d{2}|2100)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(value) &&
    !Number.isNaN(Date.parse(value)) && new Date(value+"T00:00:00.000Z").toISOString().slice(0,10)===value
  );
  const localDay = () => {
    const d=new Date();
    return [d.getFullYear(),String(d.getMonth()+1).padStart(2,"0"),String(d.getDate()).padStart(2,"0")].join("-");
  };
  const STATUSES = Object.freeze(["open", "working", "prepared", "needs_revision"]);
  const STATUS_TEXT = Object.freeze({open:"Open",working:"In gesprek",prepared:"Voor overdracht voorbereid",needs_revision:"Herziening nodig"});
  const records = [];
  const pairReviews = new Map();
  const WITHDRAWAL_ACTION_TEXT = Object.freeze({
    client_channel:"Contact cliënt via onafhankelijk geauthenticeerd kanaal; verifieer verzoek en scope.",
    operator_channel:"Waarschuw bevoegde operator via afgesproken onafhankelijke urgente route.",
    active_work:"Vraag operator om lopend werk te pauzeren of te stoppen en status onafhankelijk te controleren.",
    grant_revoke:"Vraag echte grant-eigenaar om betrokken rechten werkelijk in te trekken en controleer bij gebruik.",
    scope_schedule:"Laat verantwoordelijken werkelijke goedgekeurde scope en planning opnieuw afstemmen.",
    evidence_privacy:"Laat data-eigenaar toegang, bewaartermijn en delen van bewijsmateriaal opnieuw beoordelen.",
    human_ack:"Vraag onafhankelijke geauthenticeerde ontvangstbevestiging; app biedt die zelf niet.",
    incident_log:"Leg het besluit vast in het echte operationele audit-/incidentregister."
  });
  const WITHDRAWAL_STATUS_TEXT=Object.freeze({
    todo:"Nog niet lokaal voorbereid",drafted_local:"Alleen lokaal concept opgesteld",
    requested_unverified:"Zelfgerapporteerd verzoek, ontvangst NIET geverifieerd"
  });
  const PAIR_STATES = Object.freeze(["open","discussion_started","needs_followup","discussion_recorded"]);
  const PAIR_LABELS = Object.freeze({
    open:"Open voor overleg",discussion_started:"Bespreking gestart",
    needs_followup:"Vervolgactie nodig",discussion_recorded:"Bespreking vastgelegd (geen goedkeuring)"
  });
  const pairKey=(a,b)=>[a,b].sort().join(":");
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
      wantsNetwork:o.proposed_activities.private_lab_network_checks,
      hasSafetyNotes:typeof o.notes==="string" && o.notes.trim().length>0,
      utcWindow:o.proposed_window_utc || null,
      hasWindow:!!o.proposed_window_utc && o.proposed_window_utc.status==="resolved",
      studioDigest:null
    };
  }
  function newRecord(sha,source) {
    return {sha,source,reference:"Dossier "+String(records.length+1),replaces:null,
      tasks:Object.fromEntries(TASKS.map(([id])=>[id,"open"])),
      dueDates:Object.fromEntries(TASKS.map(([id])=>[id,null])),withdrawal:null,permission:null};
  }
  function localCoverage(r) {
    return LightUpScopeNetwork.effectiveCoverage(r.source.assets,r.source.excluded);
  }
  function isRevisionOf(a,b) {
    const seen=new Set();
    let cursor=a.replaces;
    while(cursor && !seen.has(cursor)) {
      if(cursor===b.sha)return true;
      seen.add(cursor);
      cursor=records.find(x=>x.sha===cursor)?.replaces??null;
    }
    return false;
  }
  function sameRevisionHistory(a,b) {
    return isRevisionOf(a,b)||isRevisionOf(b,a);
  }
  function relatedWithdrawalRequests(r) {
    return records.filter(x=>x!==r && x.withdrawal && sameRevisionHistory(r,x));
  }
  function sharedHints(r) {
    const current=localCoverage(r), spatial=[],clock=[];
    for(const other of records) {
      if(other===r || sameRevisionHistory(r,other)) continue;
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
      const revision_related=sameRevisionHistory(a,b);
      pairs.push({left:a.sha,right:b.sha,scope_overlap,utc_overlap,revision_related,
        human_status:pairReviews.get(pairKey(a.sha,b.sha))||"open",
        priority:revision_related?"revision":scope_overlap&&utc_overlap?"combined":scope_overlap?"scope":"schedule"});
    }
    const weight={combined:0,scope:1,schedule:2,revision:3};
    return pairs.sort((a,b)=>weight[a.priority]-weight[b.priority] ||
      Math.max(records.find(x=>x.sha===b.left).source.risk,records.find(x=>x.sha===b.right).source.risk)-
      Math.max(records.find(x=>x.sha===a.left).source.risk,records.find(x=>x.sha===a.right).source.risk));
  }
  const PERMISSION_QUESTIONS=Object.freeze({
    client_identity:"Identiteit van aanvrager",asset_ownership:"Eigendom en bevoegdheid per asset",
    purpose_limits:"Doel, verboden acties en bewaartermijnen",client_consent:"Echte cliënttoestemming langs beschermd kanaal",
    operator_independence:"Onafhankelijke operatorreview",enforceable_scope:"Handhaafbare host-/IP-/CIDR-scope",
    risk_approval:"Risico en beperkingen",stop_revocation:"STOP en intrekking bij gebruik",
    mandatory_gates:"Verplichte security- en vrijgavegates",high_risk:"Afzonderlijke hoogrisico-escalatie",
    lab_provenance:"Herkomst en eigendom privélab",no_exclusions:"Expliciete uitsluitingen",
    open_window:"UTC-planning en tijdvenster",safety_context:"Stopinstructies en veiligheid",
    network_activity:"Voorwaarden netwerkinteractie",revision_client:"Nieuwe cliëntscope herbeoordelen",
    revision_operator:"Nieuwe operatorscope herbeoordelen"
  });
  function coordination() {
    return LightUpHumanCoordination.build(records,meetingPairs());
  }
  function renderCoordination(){
    const board=$("coordBoard"),metrics=$("coordStats");board.replaceChildren();metrics.replaceChildren();
    const entries=records.length?coordination().entries:[],today=localDay();
    const kind=$("coordKind").value,p=$("coordPriority").value;
    const filtered=entries.filter(e=>(kind==="all"||kind===e.kind)&&(p==="all"||Number(p)===e.priority));
    const metric=(name,value)=>{const m=node("span","metric");m.append(node("strong","",value),node("span","",name));metrics.append(m);};
    metric("Open menselijke vervolgitems",entries.length);
    metric("Dringend",entries.filter(e=>e.priority===0).length);
    metric("Open vragen",entries.filter(e=>e.kind==="permission_question").length);
    metric("Open STOP-acties",entries.filter(e=>e.kind==="withdrawal_human_followup").length);
    if(!filtered.length){board.append(node("p","small","Geen lokale items in deze selectie. Dit is geen bewijs van veiligheid, consent of goedkeuring."));return;}
    for(const e of filtered.slice(0,75)){
      const item=node("article","action-row"+(e.priority===0?" urgent-row":""));
      const desc=node("div","action-main");
      desc.append(node("strong","",e.kind.replaceAll("_"," ")+" · "+e.code.replaceAll("_"," ")),
        node("span","small",e.dossier+" · "+e.role+" · "+e.action.replaceAll("_"," ")));
      const badge=node("span","chip"+(e.priority<=1?" alert":""),["DRINGEND","HOOG","NORMAAL","VOORBEREIDEND"][e.priority]);
      const meta=node("span","meta",e.state.replaceAll("_"," ")+(e.due_day?" · "+e.due_day+(e.due_day<today?" · ACHTERSTALLIG":""):""));
      const open=node("button","","Open dossier");open.type="button";
      open.addEventListener("click",()=>{
        const first=e.source_sha256.split(";")[0];active=first;
        render();$("detail").scrollIntoView({behavior:"smooth",block:"start"});
      });
      item.append(desc,badge,meta,open);board.append(item);
    }
    if(filtered.length>75)board.append(node("p","notice",(filtered.length-75)+
      " extra acties niet getoond; download de complete agenda of beperk de filters."));
  }
  function coordinationCsv(){
    const rows=[["dossier","source_sha256","kind","code","role","priority","reported_state","next_human_action","local_due_day","authority"]];
    for(const x of coordination().entries)rows.push([
      x.dossier,x.source_sha256,x.kind,x.code,x.role,String(x.priority),x.state,x.action,x.due_day||"","REVIEW_ONLY_HOLD"
    ]);
    const cell=v=>'"'+String(v).replaceAll('"','""')+'"';
    return "\ufeff"+rows.map(r=>r.map(cell).join(",")).join("\r\n")+"\r\n";
  }
  function coordinationIcs(){
    const dated=coordination().entries.filter(x=>x.kind==="local_preparation" && x.due_day);
    if(!dated.length) return null;
    const now=new Date().toISOString().replaceAll("-","").replaceAll(":","").replace(/\.\d{3}Z$/,"Z");
    const fold=value=>{
      const pieces=[];for(let i=0;i<value.length;i+=72)pieces.push((i>0?" ":"")+value.slice(i,i+72));
      return pieces.join("\r\n");
    };
    const ics=["BEGIN:VCALENDAR","VERSION:2.0","CALSCALE:GREGORIAN",
      "PRODID:-//LightUp//Offline Review Tasks//EN"];
    for(const t of dated){
      const day=t.due_day.replaceAll("-","");
      const next=new Date(Date.parse(t.due_day+"T00:00:00.000Z")+86400000).toISOString().slice(0,10).replaceAll("-","");
      ics.push("BEGIN:VEVENT",
        "UID:lightup-human-"+t.source_sha256+"-"+t.code+"@offline.invalid",
        "DTSTAMP:"+now,"DTSTART;VALUE=DATE:"+day,"DTEND;VALUE=DATE:"+next,
        "STATUS:TENTATIVE","TRANSP:TRANSPARENT","CLASS:PRIVATE",
        "SUMMARY:LightUp human scope review (REVIEW ONLY)",
        "DESCRIPTION:Human follow-up "+t.code+". No asset scan, authorization, client consent, grant or actual appointment.",
        "END:VEVENT");
    }
    ics.push("END:VCALENDAR");
    return ics.map(fold).join("\r\n")+"\r\n";
  }
  function renderPermission(){
    const area=$("permissionBoard");area.replaceChildren();
    const attached=records.filter(r=>r.permission);
    $("permissionFeedback").textContent=attached.length?
      attached.length+" gecombineerde, brongebonden maar NIET-GEAUTHENTICEERDE vragenoverzichten gekoppeld.":
      "Geen gecombineerd vragenoverzicht geladen. Open eerst het originele Studio-concept en importeer dan een Permission Brief-reconciliation export.";
    for(const r of attached){
      const p=r.permission,card=node("article","permission-card");
      card.append(node("h3","",r.reference+" · cliënt/operatoroverdracht"),
        node("p","small",p.needsAttention+" van "+p.total+
          " vragen vragen nog menselijke aandacht. Cliëntnotitie: "+(p.clientNoted?"zelfgerapporteerd":"ontbreekt")+
          "; operatornotitie: "+(p.operatorNoted?"zelfgerapporteerd":"ontbreekt")+
          ". Een antwoord is geen geverifieerde identiteit of toestemming."));
      const counts=node("div","chips");
      for(const role of ["client","operator"]){
        const items=p.questions.filter(x=>x.role===role);
        counts.append(node("span","chip",role==="client"?"Cliënt":"Operator"),node("span","chip alert",
          items.filter(x=>x.status!=="answered_unverified").length+"/"+items.length+" open"));
      }
      card.append(counts);
      const list=node("div","permission-questions");
      for(const q of p.questions){
        const row=node("div","permission-question");
        row.append(node("strong","",PERMISSION_QUESTIONS[q.code]||q.code),
          node("small","",q.role==="client"?"Cliëntvraag":"Operatorvraag"),
          node("span","chip"+(q.status==="answered_unverified"?"":" alert"),
            q.status==="answered_unverified"?"Antwoord ONGEVERIFIEERD":
            q.status==="question_sent"?"Vraag verstuurd, ontvangst niet geverifieerd":
            q.status==="unanswered"?"Niet beantwoord":"Geen antwoord ontvangen"));
        list.append(row);
      }
      card.append(list);
      const nav=node("div","actions"),open=node("button","","Open gekoppeld dossier");
      open.type="button";open.addEventListener("click",()=>{active=r.sha;render();$("detail").scrollIntoView({block:"start",behavior:"smooth"});});
      const clear=node("button","","Vergeet alleen deze lokale notitie");clear.type="button";
      clear.addEventListener("click",()=>{
        if(!confirm("Alleen de NIET-GEAUTHENTICEERDE Permission Brief-kopie wissen? Echte toestemming wordt niet gewijzigd."))return;
        r.permission=null;show("Lokale beantwoording vergeten. Herbeoordelingsstatussen blijven intact.");render();
      });
      nav.append(open,clear);card.append(nav);area.append(card);
    }
    if(!attached.length)area.append(node("p","small","Gebruik de gecombineerde reconciliation-JSON uit de afzonderlijke Permission Brief. Alleen overeenkomende exacte Studio-bronbytes worden geaccepteerd."));
  }
  async function importPermission(file){
    const raw=await readBounded(file,65536);
    const accepted=LightUpPermissionReplyImport.verify(raw,new Map(records.map(r=>[r.sha,r.source])));
    const r=records.find(x=>x.sha===accepted.sourceSha);
    if(r.permission && !confirm("Er is al een lokale Permission Brief-kopie voor deze bronversie. Overschrijven en herbeoordelen?"))return;
    const {sourceSha,...safe}=accepted;
    r.permission={...safe,questions:safe.questions.map(x=>({...x}))};
    for(const id of ["client","operator","owner","risk","assets"])
      if(r.tasks[id]==="prepared")r.tasks[id]="needs_revision";
    for(const key of pairReviews.keys())if(key.split(":").includes(r.sha))pairReviews.delete(key);
    show("Nieuwe brongebonden, NIET-GEAUTHENTICEERDE cliënt-/operatorvragen ontvangen. Betrokken lokaal voorbereide acties heropend. Geen consent, grant of toegang veranderd.");
    render();
  }
  function renderWithdrawals() {
    const area=$("withdrawalBoard");area.replaceChildren();
    const cases=records.filter(r=>r.withdrawal);
    $("withdrawalFeedback").textContent=cases.length?
      cases.length+" brongebonden ONGEVERIFIEERDE reviewverzoeken lokaal ingelezen. Er is geen daadwerkelijk stop- of herroepingscommando verstuurd.":
      "Er is nog geen externe review-only melding gekoppeld.";
    for(const r of cases){
      const x=r.withdrawal,card=node("article","withdrawal-card");
      card.append(node("h3","",r.reference+" · "+(x.urgency==="urgent"?"DRINGEND":"normaal")+
        " · "+x.intent.replaceAll("_"," ")),
        node("p","small","Bronbytes "+r.sha.slice(0,16)+"… · "+x.outstanding+
          " van 8 externe menselijke stop-/wijzigingsacties nog zonder zelfs een ongeverifieerd verzoek. "+
          (x.effective?"Voorgesteld UTC-moment: "+x.effective+". ":"")+
          "Geen geauthenticeerde cliënt, echte grant-intrekking, dispatchstop of toestemming vastgesteld."));
      const checklist=node("div","withdrawal-checklist");
      for(const [id,description] of Object.entries(WITHDRAWAL_ACTION_TEXT)){
        const row=node("div","withdrawal-step");
        row.append(node("strong","",id.replaceAll("_"," ")),
          node("span","small",description),
          node("span","meta",WITHDRAWAL_STATUS_TEXT[x.statuses[id]]));
        checklist.append(row);
      }
      card.append(checklist);
      const actions=node("div","actions");
      const open=node("button","","Dossier / stopacties bekijken");open.type="button";
      open.addEventListener("click",()=>{active=r.sha;render();$("detail").scrollIntoView({block:"start",behavior:"smooth"});});
      const remove=node("button","","Alleen lokale kopie wissen");remove.type="button";
      remove.addEventListener("click",()=>{
        if(!confirm("Alleen deze ongeverifieerde offline reviewkopie wissen? Dit heft GEEN echt stopverzoek of revocation op."))return;
        r.withdrawal=null;show("Alleen lokale reviewkopie gewist; status 'Herziening nodig' blijft waar van toepassing.");render();
      });
      const handoff=node("button","","Download anonieme STOP-overdracht");handoff.type="button";
      handoff.addEventListener("click",()=>{
        const lines=[
          "LIGHTUP — SELF-REPORTED HUMAN STOP/SCOPE-CHANGE REQUEST — REVIEW_ONLY_HOLD",
          "NO VERIFIED CLIENT/OPERATOR IDENTITY, ACTUAL REVOCATION, HANDLER STOP OR PERMISSION.",
          "Source bytes SHA-256: "+r.sha,
          "Self-reported urgency: "+x.urgency,
          "Self-reported intent: "+x.intent,
          "Proposed UTC effective moment: "+(x.effective||"not supplied"),
          "Next actions (must use real authenticated channels):",
          ...Object.entries(WITHDRAWAL_ACTION_TEXT).map(([id,description])=>
            "- "+id+" ["+x.statuses[id]+"] "+description),
          "This note does not stop a service or revoke any grant. Confirm status independently."
        ];
        download(lines.join("\n")+"\n","lightup-offline-stop-handoff.txt","text/plain;charset=utf-8");
      });
      actions.append(open,handoff,remove);card.append(actions);area.append(card);
    }
    if(!cases.length)area.append(node("p","small","Importeer een REVIEW_ONLY-export vanuit de zelfstandige Withdrawal Desk, na openen van dezelfde exacte Studio-bronbytes. Dit register kan geen echte operatie stoppen."));
  }
  async function importWithdrawal(file) {
    const obj=await readBounded(file,131072);
    const items=LightUpWithdrawalImport.parse(obj,new Map(records.map(r=>[r.sha,r.source])));
    if(items.some(x=>records.find(r=>r.sha===x.sha).withdrawal) &&
      !confirm("Een bron heeft al een lokaal stop-/wijzigingsverzoek. Alleen de ongeverifieerde reviewnotities vervangen?"))return;
    for(const item of items){
      const r=records.find(x=>x.sha===item.sha);
      const {sha,...safe}=item;
      r.withdrawal={...safe,statuses:{...safe.statuses}};
      const touched=safe.intent==="stop_all" ?
        new Set(TASKS.map(([id])=>id)) : new Set(["client","operator","stops","owner"]);
      if(safe.intent==="narrow_scope"){touched.add("assets");touched.add("risk");}
      if(safe.intent==="postpone")touched.add("schedule");
      if(safe.intent==="withdraw_share")touched.add("privacy");
      for(const id of touched)if(r.tasks[id]==="prepared")r.tasks[id]="needs_revision";
      for(const key of pairReviews.keys())if(key.split(":").includes(r.sha))pairReviews.delete(key);
    }
    // A self-declared revision never inherits revocation authority, but cannot silently
    // retain a 'prepared' human review after a related version reports STOP.
    for(const r of records)if(relatedWithdrawalRequests(r).length){
      for(const id of ["client","operator","owner","stops","assets","risk","schedule"])
        if(r.tasks[id]==="prepared")r.tasks[id]="needs_revision";
      for(const key of pairReviews.keys())if(key.split(":").includes(r.sha))pairReviews.delete(key);
    }
    show(items.length+" echte brongebonden, maar NIET geauthenticeerde Withdrawal Desk-melding(en) ingelezen. Relevante menselijke voorbereiding heropend. Geen operaties geraakt.");
    render();
  }
  function actionRows() {
    const all=[];
    for(const r of records)for(const [id,title] of TASKS){
      if(r.tasks[id]==="prepared")continue;
      all.push({r,id,title,status:r.tasks[id],role:TASK_ROLES[id],due:r.dueDates[id]});
    }
    const priority={needs_revision:0,working:1,open:2};
    return all.sort((a,b)=>{
      const urgentA=a.r.withdrawal?.urgency==="urgent"?1:0,urgentB=b.r.withdrawal?.urgency==="urgent"?1:0;
      if(urgentA!==urgentB)return urgentB-urgentA;
      if(a.due!==b.due)return a.due===null?1:b.due===null?-1:a.due.localeCompare(b.due);
      if(a.status!==b.status)return priority[a.status]-priority[b.status];
      return b.r.source.risk-a.r.source.risk;
    });
  }
  function renderActionQueue(){
    const area=$("actionQueue"),counts=$("actionStats");area.replaceChildren();counts.replaceChildren();
    const role=$("taskRoleFilter").value,dueFilter=$("taskDueFilter").value,today=localDay();
    const week=new Date(today+"T12:00:00Z");
    week.setUTCDate(week.getUTCDate()+7);
    const weekEnd=week.toISOString().slice(0,10);
    const all=actionRows();
    const filtered=all.filter(t=>{
      if(role!=="all"&&t.role!==role)return false;
      if(dueFilter==="overdue")return t.due!==null&&t.due<today;
      if(dueFilter==="week")return t.due!==null&&t.due>=today&&t.due<=weekEnd;
      if(dueFilter==="undated")return t.due===null;
      if(dueFilter==="revision")return t.status==="needs_revision";
      if(dueFilter==="withdrawal")return t.r.withdrawal!==null;
      return true;
    });
    const metric=(label,value)=>{
      const m=node("span","metric");m.append(node("strong","",value),node("span","",label));counts.append(m);
    };
    metric("Nog te bespreken",all.length);
    metric("Doeldatum verstreken",all.filter(x=>x.due&&x.due<today).length);
    metric("Herziening nodig",all.filter(x=>x.status==="needs_revision").length);
    metric("Zichtbaar na filters",filtered.length);
    if(!filtered.length){area.append(node("p","small","Geen open actiepunten voor deze selectie; dit bewijst geen machtiging of afgeronde securityreview."));return;}
    for(const t of filtered.slice(0,64)){
      const card=node("article","action-row");
      const meta=node("div","action-main");
      meta.append(node("strong","",t.title),node("span","small",t.r.reference+" · "+ROLE_LABELS[t.role]+" · risico "+t.r.source.risk));
      const status=node("span","chip"+(t.status==="needs_revision"?" alert":""),STATUS_TEXT[t.status]);
      const day=node("span","meta",t.due?("Doeldatum "+t.due+(t.due<today?" · VERSTREKEN":"")):"Geen doeldatum");
      const open=node("button","","Open dossier");
      open.type="button";open.addEventListener("click",()=>{active=t.r.sha;render();$("detail").scrollIntoView({behavior:"smooth",block:"start"});});
      card.append(meta,status,day,open);area.append(card);
    }
    if(filtered.length>64) area.append(node("p","notice",(filtered.length-64)+" overige acties niet in deze lijst getoond. Gebruik rol-/datumfilters om ze te tonen of exporteer de volledige actielijst."));
  }
  function renderMeetingAgenda() {
    const area=$("conflicts"),counts=$("conflictStats");area.replaceChildren();counts.replaceChildren();
    const pairs=meetingPairs();
    const count=(caption,n)=>{
      const m=node("span","metric");m.append(node("strong","",n),node("span","",caption));counts.append(m);
    };
    count("Voorstellenparen met overlegpunt",pairs.length);
    count("Onafhankelijke scope-overlap",pairs.filter(x=>x.scope_overlap&&!x.revision_related).length);
    count("Onafhankelijke UTC-overlap",pairs.filter(x=>x.utc_overlap&&!x.revision_related).length);
    count("Revisieparen (niet gelijktijdig veronderstellen)",pairs.filter(x=>x.revision_related).length);
    count("Overleg nog niet vastgelegd",pairs.filter(x=>x.human_status!=="discussion_recorded").length);
    if(!pairs.length){area.append(node("p","small","Geen berekende paren. Dit bewijst geen geldige toestemming, veilig netwerk of conflictvrije planning."));return;}
    for(const p of pairs){
      const left=records.find(x=>x.sha===p.left),right=records.find(x=>x.sha===p.right);
      const card=node("article","conflict-card");
      const title=node("h3","",left.reference+" ↔ "+right.reference);
      const meta=node("p","small","Bronnen "+p.left.slice(0,12)+"… / "+p.right.slice(0,12)+"… · max. voorgesteld risico "+Math.max(left.source.risk,right.source.risk));
      const codes=node("div","chips");
      if(p.revision_related) codes.append(node("span","chip","Historische revisierelatie (zelfverklaard)"));
      if(p.scope_overlap)codes.append(node("span","chip"+(p.revision_related?"":" alert"),"Numerieke/literale scope-overlap na uitsluitingen"));
      if(p.utc_overlap)codes.append(node("span","chip"+(p.revision_related?"":" alert"),"Overlappende voorgestelde UTC-vensters"));
      card.append(title,meta,codes,node("p","small",p.revision_related ?
        "Dit paar behoort volgens de lokaal opgegeven revisielijn tot hetzelfde voorstel. Vergelijk wijzigingen en heropen relevante voorbereidingsacties; leid er geen gemeenschappelijk eigendom of actuele toestemming uit af." :
        "Menselijke actie: controleer onafhankelijk eigendom, uitzonderingen, tenant-scheiding, werkelijk gereserveerde tijden en noodstop. Geen claim dat dit dezelfde klant is."));
      const statusLabel=node("label","pair-status","Lokale overlegstatus (geen goedkeuring)");
      const selector=node("select");
      for(const status of PAIR_STATES){const option=node("option","",PAIR_LABELS[status]);option.value=status;selector.append(option);}
      selector.value=p.human_status;
      selector.addEventListener("change",()=>{
        const key=pairKey(p.left,p.right);
        if(selector.value==="open")pairReviews.delete(key);
        else pairReviews.set(key,selector.value);
        show("Zelfgerapporteerde overlegstatus bijgewerkt; geen scopebesluit, consent, grant of autorisatie.");
        render();
      });
      statusLabel.append(selector);card.append(statusLabel);
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
  function revisionTaskRechecks(delta) {
    if(!delta)return [];
    const keys=new Set(["owner","client","operator","privacy"]);
    if(delta.effective_added_segments || delta.effective_removed_segments ||
       delta.effective_truncated || delta.assets.added || delta.assets.removed ||
       delta.exclusions.added || delta.exclusions.removed) {
      keys.add("assets");keys.add("stops");
    }
    if(delta.risk_changed || delta.mode_changed){keys.add("risk");keys.add("stops");}
    if(delta.time_window_changed || delta.time_window_presence_changed){keys.add("schedule");keys.add("stops");}
    return [...keys];
  }
  function setRevision(r,priorSha) {
    if((priorSha||null)===r.replaces)return [];
    if(priorSha) {
      assert(priorSha!==r.sha && records.some(x=>x.sha===priorSha),"Ongeldige revisierelatie.");
      assert(!records.some(x=>x!==r&&x.replaces===priorSha),"De voorganger is al gekoppeld aan een andere opvolger.");
      let cursor=priorSha;
      const visited=new Set();
      while(cursor) {
        assert(cursor!==r.sha && !visited.has(cursor),"Cyclische revisiehistorie geweigerd.");
        visited.add(cursor); cursor=records.find(x=>x.sha===cursor)?.replaces??null;
      }
    }
    const prevPairs=new Map(meetingPairs().map(p=>[pairKey(p.left,p.right),p.revision_related]));
    r.replaces=priorSha||null;
    const nextPairs=new Map(meetingPairs().map(p=>[pairKey(p.left,p.right),p.revision_related]));
    for(const key of pairReviews.keys())
      if(!nextPairs.has(key)||prevPairs.get(key)!==nextPairs.get(key)||key.split(":").includes(r.sha))
        pairReviews.delete(key);
    const delta=revisionDelta(r),changed=[];
    if(relatedWithdrawalRequests(r).length){
      for(const id of ["client","operator","owner","stops","assets","risk","schedule"])
        if(r.tasks[id]==="prepared"){r.tasks[id]="needs_revision";changed.push(id);}
    }
    if(delta){
      for(const key of revisionTaskRechecks(delta)){
        if(r.tasks[key]==="prepared"){r.tasks[key]="needs_revision";changed.push(key);}
      }
    }
    return changed;
  }
  function warnings(r) {
    const w=[];
    const rev=revisionDelta(r);
    if (rev?.possible_expansion) w.push("revisie_mogelijke_scopeuitbreiding");
    if (rev?.mode_changed) w.push("revisie_modusgewijzigd");
    if (rev?.time_window_changed) w.push("revisie_planning_gewijzigd");
    if (rev && revisionTaskRechecks(rev).some(id=>r.tasks[id]==="needs_revision"))
      w.push("revisie_menselijke_herbeoordeling_nodig");
    if(relatedWithdrawalRequests(r).length)w.push("stopverzoek_bij_zelfgekoppelde_scopeversie_onafhankelijk_beoordelen");
    if(r.permission && r.permission.needsAttention>0)w.push("vragen_client_operator_onbevestigd");
    if(r.permission && (!r.permission.clientNoted||!r.permission.operatorNoted))w.push("rolantwoord_ontbreekt");
    if(r.withdrawal){
      w.push(r.withdrawal.urgency==="urgent"?"dringend_niet_geauthenticeerd_stopverzoek":"onbevestigd_stop_of_scopewijzigingsverzoek");
    }
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
    renderCoordination();
    renderPermission();
    renderWithdrawals();
    renderActionQueue();
    renderMeetingAgenda();
  }
  function renderDetail() {
    const detail=$("detail");detail.replaceChildren();
    const r=records.find(x=>x.sha===active);
    if (!r) {detail.append(node("p","","Selecteer een concept om voorbereidingsacties te bekijken."));return;}
    detail.append(node("h3","",r.reference+" — voorbereidingsroute"));
    const relatedStops=relatedWithdrawalRequests(r);
    if(relatedStops.length)detail.append(node("p","warning",
      "Er is een ONGEVERIFIEERD STOP-/wijzigingsverzoek bij "+relatedStops.length+
      " zelfgekoppelde historische scopeversie(s). Vraag via het echte geauthenticeerde proces of dit verzoek ook deze exacte versie betreft. Geen daadwerkelijke intrekking is vastgesteld."));
    detail.append(node("p","small","Dit betreft uitsluitend zelf bijgehouden voorbereiding. Een vinkje is geen verificatie en wordt nooit een autorisatieverklaring."));
    const controls=node("div","controls"), lab=node("label","","Interne referentie (alleen lokaal)");
    const input=node("input");input.maxLength=32;input.value=r.reference;
    input.addEventListener("change",()=>{r.reference=input.value.trim().slice(0,32)||"Naamloos dossier";render();});
    lab.append(input);controls.append(lab);
    const del=node("button","","Verwijder alleen dit concept");del.type="button";
    del.addEventListener("click",()=>{if(!confirm("Dit concept en de lokale voorbereidingsantwoorden verwijderen?"))return;records.splice(records.indexOf(r),1);for(const x of records)if(x.replaces===r.sha)x.replaces=null;for(const key of pairReviews.keys())if(key.split(":").includes(r.sha))pairReviews.delete(key);active=records[0]?.sha??null;show("Concept en afhankelijke revisiekoppeling(en) uit deze browsersessie verwijderd; andere taakstatussen behouden.");render();});
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
      if(revSelect.value && !confirm("Koppelen als zelfverklaarde nieuwe scopeversie? Eerder 'voorbereide' relevante acties worden dan automatisch HERZIENING NODIG; getroffen overlegnotities worden gereset. Geen toestemming/claims worden overgenomen.")) {revSelect.value=r.replaces||"";return;}
      try{const changed=setRevision(r,revSelect.value);show("Revisielijn bijgewerkt; "+changed.length+" voorbereide actie(s) op 'Herziening nodig' gezet. Betrokken overlegstatussen zijn heropend. Geen echte consent of autorisatie overgenomen.");render();}
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
      ". Voorbereidingsacties blijven apart; eerder afgeronde toepasselijke acties krijgen 'Herziening nodig' na koppeling. Geen DNS of autorisatiecontrole."));
    const hint=node("p","summary","Reviewpunten: "+(warnings(r).length?warnings(r).join(", ").replaceAll("_"," "):"Geen automatisch aangemerkte signalen. Dat bewijst geen veilige scope.")+". Exacte asset-overlap betekent niet gedeeld eigendom of geldige toestemming.");
    detail.append(hint);
    for (const [id,title,description] of TASKS) {
      const row=node("div","checkrow");const info=node("div"),titleEl=node("label","",title);
      titleEl.htmlFor="task-"+id;info.append(titleEl,node("small","",description));
      const select=node("select");select.id="task-"+id;
      for (const state of STATUSES) {const option=node("option","",STATUS_TEXT[state]);option.value=state;select.append(option);}
      select.value=r.tasks[id];select.addEventListener("change",()=>{r.tasks[id]=select.value;render();});
      const controls=node("div","task-controls");
      const dueLabel=node("label","small","Lokale doeldatum");
      const due=node("input");due.type="date";due.min="2020-01-01";due.max="2100-12-31";
      due.value=r.dueDates[id]||"";due.setAttribute("aria-label","Doeldatum "+title);
      due.addEventListener("change",()=>{
        const val=due.value||null;
        if(!validDay(val)){show("Ongeldige lokale datum; datum niet overgenomen.",true);due.value=r.dueDates[id]||"";return;}
        r.dueDates[id]=val;render();
      });
      dueLabel.append(due);controls.append(select,dueLabel);
      info.append(node("small","","Menselijke rol: "+ROLE_LABELS[TASK_ROLES[id]]));
      row.append(info,controls);detail.append(row);
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
    const seenSemantic=new Set(records.map(x=>x.source.studioDigest));
    let formatOnlyDuplicates=0;
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
      if (seenSemantic.has(studioDigest)) {
        formatOnlyDuplicates++;
        continue; // Edited export time/format is not a new scope revision.
      }
      seen.add(sha);seenSemantic.add(studioDigest);incoming.push({sha,source});
    }
    assert(records.length+incoming.length<=MAX,"Het register bevat maximaal 16 verschillende conceptversies.");
    incoming.forEach(x=>records.push(newRecord(x.sha,x.source)));
    if (!active && records.length) active=records[0].sha;
    show(incoming.length+" nieuwe Studio-scopeversie(s) geladen; "+formatOnlyDuplicates+" herexport(s) met identieke semantische scope genegeerd. Exacte bronbytes blijven nodig voor herstel van bestaande taakstatussen.");
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
    return {kind:"lightup.scope_handoff_local_progress",schema_version:5,state:"REVIEW_ONLY_HOLD",authority:authority(),
      entries:records.map(r=>({sha256:r.sha,reference:r.reference,replaces:r.replaces,tasks:{...r.tasks},
        due_dates:{...r.dueDates},withdrawal:r.withdrawal?{...r.withdrawal,statuses:{...r.withdrawal.statuses}}:null,
        permission:r.permission?{...r.permission,questions:r.permission.questions.map(q=>({...q}))}:null})),
      pair_reviews:meetingPairs().map(p=>({sources:[p.left,p.right].sort(),status:p.human_status}))};
  }
  function report() {
    return {kind:"lightup.scope_handoff_review_register",schema_version:3,state:"REVIEW_ONLY_HOLD",authority:authority(),
      notice:"Unverified local human preparation; no authorization, consent, identity or ownership assertion.",
      review_agenda:meetingPairs().map(p=>({
        dossier_a:"D"+String(records.findIndex(x=>x.sha===p.left)+1).padStart(2,"0"),
        dossier_b:"D"+String(records.findIndex(x=>x.sha===p.right)+1).padStart(2,"0"),
        numeric_or_literal_scope_overlap:p.scope_overlap,
        proposed_utc_overlap:p.utc_overlap,
        relation:p.revision_related?"self_reported_revision":"independent_review",
        self_reported_discussion_status:p.human_status,
        review_only:true
      })),
      entries:records.map((r,i)=>({
        dossier:"D"+String(i+1).padStart(2,"0"),source_sha256:r.sha,
        studio_revision_sha256:r.source.studioDigest,
        replaces_source_sha256:r.replaces,revision:revisionDelta(r),offline_shared_review_hints:sharedHints(r),
        proposed_risk:r.source.risk,proposed_mode:r.source.mode,
        asset_count:r.source.assets.length,excluded_count:r.source.excluded.length,
        review_codes:warnings(r),tasks:Object.fromEntries(TASKS.map(([id])=>[id,r.tasks[id]])),
        task_roles:{...TASK_ROLES},task_due_dates:{...r.dueDates},
        permission_questions_review_only:r.permission?{
          client_response_reported:r.permission.clientNoted,
          operator_response_reported:r.permission.operatorNoted,
          outstanding_unverified_questions:r.permission.needsAttention,
          question_count:r.permission.total,
          question_statuses:r.permission.questions.map(q=>({code:q.code,role:q.role,status:q.status}))
        }:null,
        external_withdrawal_review_only:r.withdrawal?{
          intent:r.withdrawal.intent,urgency:r.withdrawal.urgency,
          suggested_utc:r.withdrawal.effective,paperwork_prepared:r.withdrawal.paperwork,
          outstanding_unverified_human_actions:r.withdrawal.outstanding
        }:null,
        preparation_only:prepared(r)===TASKS.length
      }))};
  }
  function restore(o) {
    assert(isPlain(o)&&o.kind==="lightup.scope_handoff_local_progress"&&[1,2,3,4,5].includes(o.schema_version)&&o.state==="REVIEW_ONLY_HOLD","Geen compatibele lokale voortgang.");
    assert(isPlain(o.authority)&&Object.keys(DENIAL).length===Object.keys(o.authority).length && Object.entries(DENIAL).every(([k,v])=>o.authority[k]===v),"Autorisatievlaggen mogen nooit waar zijn.");
    assert(Array.isArray(o.entries) && o.entries.length===records.length && records.length>0 && o.entries.length<=MAX,"Open eerst precies de oorspronkelijke conceptversies.");
    const shaMap=new Map(records.map(x=>[x.sha,x])),found=new Set(),updates=[];
    for (const entry of o.entries) {
      assert(isPlain(entry)&&typeof entry.sha256==="string" && /^[a-f0-9]{64}$/.test(entry.sha256) && shaMap.has(entry.sha256) && !found.has(entry.sha256),"Bron-SHA mist, is dubbel of niet gelijk.");
      assert(typeof entry.reference==="string"&&entry.reference.length>0&&entry.reference.length<=32 && isPlain(entry.tasks),"Ongeldige lokale label-/takenstructuur.");
      const expectedKeys=["sha256","reference","replaces","tasks",...(o.schema_version>=3?["due_dates"]:[]),...(o.schema_version>=4?["withdrawal"]:[]),...(o.schema_version===5?["permission"]:[])];
      assert(Object.keys(entry).length===expectedKeys.length && expectedKeys.every(k=>Object.hasOwn(entry,k)),"Onbekende of ontbrekende status-/doeldatumvelden.");
      if(o.schema_version>=3){
        assert(isPlain(entry.due_dates)&&Object.keys(entry.due_dates).length===TASKS.length &&
          TASKS.every(([id])=>Object.hasOwn(entry.due_dates,id)&&validDay(entry.due_dates[id])),
          "Onjuiste doeldatumset; import wordt geheel geweigerd.");
      }
      if(o.schema_version>=4 && entry.withdrawal!==null)
        assert(LightUpWithdrawalImport.safeSaved(entry.withdrawal,shaMap.get(entry.sha256)?.source),
          "Ongeldige, bronloze of verhoogde externe stopnotitie.");
      if(o.schema_version===5 && entry.permission!==null)
        assert(LightUpPermissionReplyImport.saved(entry.permission,shaMap.get(entry.sha256)?.source),
          "Ongeldige of verhoogde Permission Brief-notitie; alles blijft ongewijzigd.");
      assert(Object.keys(entry.tasks).length===TASKS.length && TASKS.every(([id])=>STATUSES.includes(entry.tasks[id])),"Taakset of status is vervormd.");
      assert(entry.replaces===null || (typeof entry.replaces==="string" && shaMap.has(entry.replaces)),"Vreemde revisievoorganger.");
      found.add(entry.sha256);updates.push([shaMap.get(entry.sha256),entry]);
    }
    // Validate the entire proposed revision graph before applying any local updates.
    const simulated=new Map(updates.map(([r,e])=>[r.sha,e.replaces]));
    for(const [sha] of simulated){const visited=new Set([sha]);let cursor=simulated.get(sha);while(cursor){assert(!visited.has(cursor),"Cyclische revisielijn.");visited.add(cursor);cursor=simulated.get(cursor)||null;}}
    const targets=updates.map(([,e])=>e.replaces).filter(Boolean);
    assert(new Set(targets).size===targets.length,"Dubbele voorganger kan niet twee opvolgers hebben.");
    const nextPairs=new Map();
    if(o.schema_version>=2) {
      const expected=new Set(meetingPairs().map(p=>pairKey(p.left,p.right)));
      assert(Array.isArray(o.pair_reviews)&&o.pair_reviews.length===expected.size,
        "Overlegpaarset komt niet overeen met de geopende bronbestanden.");
      for(const pair of o.pair_reviews) {
        assert(isPlain(pair) && Object.keys(pair).length===2 &&
          Array.isArray(pair.sources)&&pair.sources.length===2&&pair.sources.every(x=>typeof x==="string") &&
          PAIR_STATES.includes(pair.status),"Ongeldige brongebonden overlegstatus.");
        const key=pairKey(pair.sources[0],pair.sources[1]);
        assert(expected.has(key)&&!nextPairs.has(key),"Onbekend of dubbel overlegpaar.");
        nextPairs.set(key,pair.status);
      }
    }
    if (!confirm("De huidige lokale voorbereidings- en overlegstatussen vervangen voor exact deze bronbestanden?"))return;
    updates.forEach(([r,e])=>{r.reference=e.reference;r.replaces=e.replaces;r.tasks={...e.tasks};
      r.dueDates=o.schema_version>=3?{...e.due_dates}:Object.fromEntries(TASKS.map(([id])=>[id,null]));
      r.withdrawal=o.schema_version>=4&&e.withdrawal?{...e.withdrawal,statuses:{...e.withdrawal.statuses}}:null;
      r.permission=o.schema_version===5&&e.permission?{...e.permission,questions:e.permission.questions.map(q=>({...q}))}:null;
    });
    pairReviews.clear();
    for(const [key,status] of nextPairs)if(status!=="open")pairReviews.set(key,status);
    show("Dossier- en overlegstatussen atomisch hersteld voor identieke oorspronkelijke bronbytes.");
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
    const follow=coordination().entries;
    if(follow.length) {
      parts.push("<h2>Geprioriteerde menselijke opvolgagenda</h2>",
        "<p>Open lokale acties "+esc(follow.length)+". Eerste 40 prioriteitsitems hieronder; de volledige agenda is afzonderlijk als JSON/CSV beschikbaar.</p>",
        "<table><thead><tr><th>Dossier</th><th>Menselijke actie (geen uitvoermachtiging)</th><th>Prioriteit</th></tr></thead><tbody>");
      for(const x of follow.slice(0,40))parts.push("<tr><td>"+esc(x.dossier)+"</td><td>"+
        esc(x.kind+" / "+x.code+" / "+x.role+" / "+x.action)+(x.due_day?"<br>Doeldatum "+esc(x.due_day):"")+
        "</td><td>"+esc(x.priority)+"</td></tr>");
      parts.push("</tbody></table>");
    }
    if(data.review_agenda.length){
      parts.push("<h2>Gedeelde menselijke review-agenda</h2><table><thead><tr><th>Voorstellen</th><th>Lokale overlapindicatoren</th></tr></thead><tbody>");
      for(const x of data.review_agenda)parts.push("<tr><td>"+esc(x.dossier_a)+" / "+esc(x.dossier_b)+
        "</td><td>"+esc([x.numeric_or_literal_scope_overlap?"Netwerk/hostname na exclusies":null,x.proposed_utc_overlap?"UTC-venster":null].filter(Boolean).join("; "))+
        "<br>Relatie: "+esc(x.relation==="self_reported_revision"?"Zelfverklaarde revisie":"Apart te beoordelen voorstellen")+
        "<br>Menselijk overleg: "+esc(PAIR_LABELS[x.self_reported_discussion_status])+"</td></tr>");
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
      if(e.permission_questions_review_only){
        const p=e.permission_questions_review_only;
        parts.push("<p class=\"hold\">ONGEVERIFIEERDE CLIËNT-/OPERATORVRAGEN: "+esc(p.outstanding_unverified_questions)+
          "/"+esc(p.question_count)+" vragen vragen nog aandacht. Cliëntnotitie "+(p.client_response_reported?"zelfgerapporteerd":"ontbreekt")+
          "; operatornotitie "+(p.operator_response_reported?"zelfgerapporteerd":"ontbreekt")+
          ". Geen identiteit, toestemming of operator-goedkeuring vastgesteld.</p>");
      }
      if(e.external_withdrawal_review_only)parts.push("<p class=\"hold\">EXTERNE, ONGEVERIFIEERDE STOP-/WIJZIGINGSMELDING: "+
        esc(e.external_withdrawal_review_only.intent)+", urgentie "+esc(e.external_withdrawal_review_only.urgency)+
        ", open externe menselijke stappen "+esc(e.external_withdrawal_review_only.outstanding_unverified_human_actions)+
        ". Geen daadwerkelijke intrekking, uitvoeringstop of geauthenticeerd oordeel.</p>");
      parts.push("<table><thead><tr><th>Menselijke voorbereidingsactie</th><th>Zelfgerapporteerde status</th></tr></thead><tbody>");
      for(const [id,title] of TASKS) parts.push("<tr><td>"+esc(title)+" · "+esc(ROLE_LABELS[e.task_roles[id]])+
        "</td><td>"+esc(STATUS_TEXT[e.tasks[id]])+
        (e.task_due_dates[id]?" · lokale doeldatum "+esc(e.task_due_dates[id]):"")+"</td></tr>");
      parts.push("</tbody></table></article>");
    }
    parts.push("<p class=\"hold\">Elk veld authenticated, consent, authorized, grant, execution, scan, dispatch, deploy en release staat letterlijk FALSE. Ook 8/8 voorbereide acties hebben geen juridische of technische autoriteit.</p></body></html>");
    return parts.join("");
  }
  function csv() {
    const rows=[["dossier","scope_sha256","task","role","status","local_target_day","unverified_withdrawal_urgency","unverified_permission_questions_open","authority"]];
    report().entries.forEach(e=>TASKS.forEach(([id])=>rows.push([e.dossier,e.source_sha256,id,
      e.task_roles[id],e.tasks[id],e.task_due_dates[id]||"",e.external_withdrawal_review_only?.urgency||"",e.permission_questions_review_only?.outstanding_unverified_questions??"","REVIEW_ONLY_HOLD"])));
    const escape=x=>'"'+String(x).replaceAll('"','""')+'"';
    return "\ufeff"+rows.map(row=>row.map(escape).join(",")).join("\r\n")+"\r\n";
  }
  function agendaCsv() {
    const rows=[["dossier_a","dossier_b","effective_scope_overlap","proposed_utc_overlap","human_discussion_status","authority"]];
    for(const p of report().review_agenda)
      rows.push([p.dossier_a,p.dossier_b,String(p.numeric_or_literal_scope_overlap),
        String(p.proposed_utc_overlap),p.self_reported_discussion_status,"REVIEW_ONLY_HOLD"]);
    const cell=x=>'"'+String(x).replaceAll('"','""')+'"';
    return "\ufeff"+rows.map(row=>row.map(cell).join(",")).join("\r\n")+"\r\n";
  }
  $("imports").addEventListener("change",async e=>{
    try{await importDrafts(Array.from(e.target.files));}catch(err){show("Import geweigerd; bestaande concepten behouden: "+err.message,true);}
    e.target.value="";
  });
  $("permissionFile").addEventListener("change",async e=>{
    try{await importPermission(e.target.files[0]);}
    catch(err){show("Permission Brief-overdracht geweigerd zonder wijzigingen: "+err.message,true);}
    e.target.value="";
  });
  $("withdrawalFile").addEventListener("change",async e=>{
    try{await importWithdrawal(e.target.files[0]);}
    catch(err){show("Stopverzoekimport VOLLEDIG geweigerd zonder dossierwijziging: "+err.message,true);}
    e.target.value="";
  });
  $("restore").addEventListener("change",async e=>{
    try{restore(await readBounded(e.target.files[0],RESTORE_SIZE));}catch(err){show("Herstel geweigerd zonder wijzigingen: "+err.message,true);}
    e.target.value="";
  });
  $("search").addEventListener("input",render);$("filter").addEventListener("change",render);$("sort").addEventListener("change",render);
  $("coordKind").addEventListener("change",render);$("coordPriority").addEventListener("change",render);
  $("taskRoleFilter").addEventListener("change",render);$("taskDueFilter").addEventListener("change",render);
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
    records.splice(0);pairReviews.clear();active=null;show("Alle lokale concept- en overleggegevens uit deze browserpagina gewist.");render();
  });
  $("coordJson").addEventListener("click",()=>records.length?json(coordination(),"lightup-review-only-coordination.json"):show("Laad eerst concepten.",true));
  $("coordCsv").addEventListener("click",()=>records.length?download(coordinationCsv(),"lightup-review-only-coordination.csv","text/csv;charset=utf-8"):show("Laad eerst concepten.",true));
  $("coordIcs").addEventListener("click",()=>{
    if(!records.length){show("Laad eerst concepten.",true);return;}
    const body=coordinationIcs();
    if(!body){show("Er zijn geen open lokale taken met een doeldatum om als agenda te exporteren.");return;}
    if(!confirm("Dit exporteert uitsluitend ALLE-DAAGSE menselijke opvolgacties, geen scanmomenten. Kalenders kunnen bron-SHA's naar cloudaccounts synchroniseren. Dit bevestigt geen toestemming. Exporteren?"))return;
    download(body,"lightup-offline-human-followups.ics","text/calendar;charset=utf-8");
  });
  $("save").addEventListener("click",()=>records.length?json(snapshot(),"lightup-local-progress.json"):show("Laad eerst concepten.",true));
  $("export").addEventListener("click",()=>records.length?json(report(),"lightup-review-only-handoff.json"):show("Laad eerst concepten.",true));
  $("csv").addEventListener("click",()=>records.length?download(csv(),"lightup-handoff-actions.csv","text/csv;charset=utf-8"):show("Laad eerst concepten.",true));
  $("agendaCsv").addEventListener("click",()=>records.length?download(agendaCsv(),"lightup-review-meeting-agenda.csv","text/csv;charset=utf-8"):show("Laad eerst concepten.",true));
  $("printPack").addEventListener("click",()=>records.length?download(fullHtmlPacket(),"lightup-review-only-handoff.html","text/html;charset=utf-8"):show("Laad eerst concepten.",true));
  $("print").addEventListener("click",()=>records.length?window.print():show("Laad eerst concepten.",true));
  render();
})();
