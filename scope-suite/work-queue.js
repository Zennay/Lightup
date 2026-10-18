/* Unified, local-only human handoff queue for the LightUp offline workbench.
   It consumes only non-sensitive aggregate events; no scanner, DB, identity,
   grant, cookie, backend, storage or target interaction is reachable here. */
"use strict";
(() => {
  const $=id=>document.getElementById(id);
  const STATUS=Object.freeze({
    open:"Open voor gesprek",
    discussing:"Menselijke bespreking gestart",
    prepared:"Voorbereid voor handmatige overdracht"
  });
  const SORT_PRIORITY=Object.freeze({urgent:0,high:1,normal:2});
  const LINKS=Object.freeze({
    handoff:"apps/handoff/scope-handoff-register/standalone.html",
    withdrawal:"apps/withdrawal/withdrawal-desk/standalone.html",
    briefing:"apps/briefing/scope-briefing/standalone.html",
    permission:"apps/permission/scope-permission-brief/standalone.html",
    casework:"apps/casework/casework/index.html",
    readiness:"apps/readiness/coordination/scope-readiness-standalone.html"
  });
  const ROUTE_NAMES=Object.freeze({
    handoff:"Menselijke handoff",withdrawal:"Offline STOP-overdracht",
    briefing:"Scopebespreking",permission:"Onafhankelijke vragenlijst",
    casework:"Herstelplanner",readiness:"Scope-informatieoverzicht"
  });
  let scope=[],findings=[],actions=[],filter="all";
  let annotations=new Map(); // Local-only self-reported conversation status; never permission.
  const safe=(tag,cls,txt)=>{
    const e=document.createElement(tag);
    if(cls)e.className=cls;
    if(txt!==undefined)e.textContent=txt;
    return e;
  };
  function add(list,item){
    if(!/^[0-9a-f]{64}$/.test(item.sha))return;
    list.push({
      ...item,
      key:item.sha+":"+item.code,
      status:annotations.get(item.sha+":"+item.code)||"open"
    });
  }
  function recompute(){
    const items=[];
    for(const d of scope){
      if(d.kind==="lightup.scope_withdrawal_review_only")
        add(items,{sha:d.hash,code:"outside_stop_escalation",domain:"scope",priority:"urgent",
          title:"Controleer het gemelde STOP-verzoek via het ECHTE noodkanaal",
          detail:"Een lokaal importbestand kan geen uitvoering stoppen of grant intrekken. Neem via het authentieke cliënt-/operator-/incidentkanaal contact op. Zelfs 'voorbereid' bevestigt niet dat werkelijk is gestopt.",
          route:"withdrawal"});
      if(d.conflict)
        add(items,{sha:d.hash,code:"source_claim_conflict",domain:"scope",priority:"urgent",
          title:"Contradictoire scopebron — HOLD op handmatige doorgeleiding",
          detail:"De review vermeldt een risico, modus of aantal dat de exact gekoppelde Studio-bron tegenspreekt. Bespreek eerst met de onafhankelijke bronhouder; een SHA is geen identiteit.",
          route:"readiness"});
      if(d.missing)
        add(items,{sha:d.hash,code:"original_studio_missing",domain:"scope",priority:"high",
          title:"Originele Studio-bronbytes ontbreken",
          detail:"Vraag via het afgesproken private kanaal de exacte oorspronkelijke DRAFT_ONLY Studio-export op. Er mag geen eerdere toestemming worden gereconstrueerd of aangenomen.",
          route:"handoff"});
      if(d.source && d.risk===4)
        add(items,{sha:d.hash,code:"elevated_risk_discussion",domain:"scope",priority:"high",
          title:"Hoogrisicoconcept: onafhankelijke beoordeling nodig",
          detail:"Risk 4 is alleen een aangevraagd niveau. Organiseer apart cliënt-/operatoroverleg over noodstop, privacy en gewenste activiteiten; er is geen geauthenticeerde goedkeuring.",
          route:"briefing"});
      if(d.source)
        add(items,{sha:d.hash,code:"independent_scope_owner_discussion",domain:"scope",priority:"normal",
          title:"Verifieer scope, assets en uitsluitingen buiten de werkbank",
          detail:"Controleer de echte contact- en eigendomsroute voor alle assets voordat de afzonderlijke bestaande aanvraag- en grantflow wordt gebruikt. Dit is slechts een voorbereidende menselijke taak.",
          route:"permission"});
      if(d.kind==="lightup.scope_permission_reply_reconciliation")
        add(items,{sha:d.hash,code:"verify_untrusted_human_replies",domain:"scope",priority:"high",
          title:"Cliënt-/operatorantwoorden onafhankelijk opvolgen",
          detail:"Een lokaal antwoord 'answered_unverified' is geen geauthenticeerde cliënt- of operatorverklaring. Bevestig elk antwoord afzonderlijk.",
          route:"handoff"});
    }
    for(const f of findings){
      if(f.regression>0)
        add(items,{sha:f.hash,code:"retest_regression_critical_review",domain:"remediation",priority:"urgent",
          title:"Bron meldt mogelijke regressie — onafhankelijk opvolgen",
          detail:f.regression+" bronvermeldingen dragen een regressie-status; die claim is NIET live geverifieerd. Laat bevoegde beheerders onderzoek en eventuele echte retest in het bestaande veilige proces organiseren.",
          route:"casework"});
      if(f.critical>0||f.high>0)
        add(items,{sha:f.hash,code:"prioritize_high_severity_remediation",domain:"remediation",priority:"high",
          title:"Maak een concreet herstelplan voor hoge ernst",
          detail:f.critical+" critical en "+f.high+" high bevindingen in een aangeleverde CSV. Wijs offline teams en datums toe, zonder de bronreteststatus of de echt geauthenticeerde database te wijzigen.",
          route:"casework"});
      if(f.critical===0&&f.high===0&&f.count>0)
        add(items,{sha:f.hash,code:"plan_remaining_findings",domain:"remediation",priority:"normal",
          title:"Plan reparaties voor overige bevindingen",
          detail:f.count+" lokaal aangeleverde bevindingen. Maak een menselijke planning, niet een geverifieerde afmelding.",
          route:"casework"});
    }
    if(findings.length>1){
      for(const f of findings)
        add(items,{sha:f.hash,code:"verify_export_engagement",domain:"remediation",priority:"high",
          title:"Controleer engagement voordat exports worden vergeleken",
          detail:"Er zijn meerdere originele findings-CSV's geladen. Vergelijk alleen na onafhankelijke cliënt- en engagementcontrole. Een gelijke bestandsnaam of inhoud is geen herkomstbewijs.",
          route:"casework"});
    }
    items.sort((a,b)=>SORT_PRIORITY[a.priority]-SORT_PRIORITY[b.priority] ||
      a.domain.localeCompare(b.domain) || a.key.localeCompare(b.key));
    actions=items;
    annotations=new Map(items.filter(x=>x.status!=="open").map(x=>[x.key,x.status]));
    render();
  }
  function render(){
    const visible=actions.filter(a=>
      filter==="all" ||
      filter===a.priority ||
      filter===a.domain ||
      filter==="pending"&&a.status!=="prepared" ||
      filter==="prepared"&&a.status==="prepared");
    const high=actions.filter(x=>x.priority==="urgent").length;
    const totalOpen=actions.filter(x=>x.status!=="prepared").length;
    $("work-count").textContent=actions.length+" opdrachten voor menselijke voorbereiding";
    $("work-summary").textContent=high+" urgente bronmeldingen · "+totalOpen+
      " lokale voorbereidingstaken zonder gemelde overdracht · "+
      actions.filter(x=>x.domain==="scope").length+" scope · "+
      actions.filter(x=>x.domain==="remediation").length+" remediation";
    $("work-export").disabled=!actions.length;
    $("work-csv").disabled=!actions.length;
    const list=$("work-queue-list");list.replaceChildren();
    if(!visible.length){
      list.append(safe("div","work-empty",
        actions.length?"Geen taken met dit filter. Verander de weergave.":"Laad eerst zelf een origineel Studio-concept, reviewdocument of geautoriseerd geëxporteerde findings-CSV in de lokale laden."));
    }
    for(const a of visible){
      const card=safe("article","work-item");
      const head=safe("div","work-head");
      head.append(safe("span","work-priority "+a.priority,
        a.priority==="urgent"?"DRINGEND — NOG NIET UITGEVOERD":a.priority==="high"?"HOGE AANDACHT":"VOORBEREIDING"));
      head.append(safe("span","work-category",a.domain==="scope"?"SCOPE":"HERSTEL"));
      card.append(head,safe("h3",null,a.title),safe("p",null,a.detail));
      card.append(safe("p","tray-meta","Referentie SHA-256 "+a.sha.slice(0,20)+"… · bronclaim is ONGEVERIFIEERD"));
      const controls=safe("div","work-controls");
      const label=safe("label",null,"Alleen eigen menselijke voorbereidingsstatus");
      const select=safe("select");select.setAttribute("aria-label","Lokaal statusveld voor "+a.title);
      for(const [code,title] of Object.entries(STATUS)){
        const opt=safe("option",null,title);opt.value=code;select.append(opt);
      }
      select.value=a.status;
      select.addEventListener("change",()=>{
        annotations.set(a.key,select.value);
        a.status=select.value;
        render();
      });
      label.append(select);controls.append(label);
      const route=safe("a","work-route",ROUTE_NAMES[a.route]+" →");
      route.href=LINKS[a.route];route.target="_blank";route.rel="noopener";
      controls.append(route);
      card.append(controls);list.append(card);
    }
  }
  function exportPacket(){
    return {
      kind:"lightup.local_human_action_register",schema_version:1,state:"REVIEW_ONLY_HOLD",
      authenticated:false,client_consent:false,operator_consent:false,
      authorization:false,grant:false,execution:false,scan:false,deploy:false,release:false,
      actual_stop:false,retest_verified:false,
      notice:"These are local self-reported preparation statuses. None is an authenticated human consent, real STOP, valid scope, remediation or release attestation.",
      actions:actions.map(a=>({
        source_sha256:a.sha,category:a.domain,code:a.code,priority:a.priority,
        self_reported_preparation_status:a.status,authority:"REVIEW_ONLY_HOLD"
      }))
    };
  }
  function download(name,content,type){
    const url=URL.createObjectURL(new Blob([content],{type}));
    const link=safe("a");link.href=url;link.download=name;
    document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function approvedExport(){
    if(!actions.length)return false;
    return confirm("De SHA-referenties in dit verslag kunnen bronbestanden koppelen. Statussen zijn door u zelf gemelde voorbereiding, NOOIT toestemming, STOP, retest of release. Bewaar en deel uitsluitend privé.");
  }
  $("work-export").addEventListener("click",()=>{
    if(!approvedExport())return;
    download("lightup-local-handoff-workqueue-HOLD.json",
      JSON.stringify(exportPacket(),null,2)+"\n","application/json");
  });
  $("work-csv").addEventListener("click",()=>{
    if(!approvedExport())return;
    const rows=[["source_sha256","category","action_code","priority","local_preparation_status","authority"],
      ...actions.map(a=>[a.sha,a.domain,a.code,a.priority,a.status,"REVIEW_ONLY_HOLD"])];
    const content=rows.map(row=>row.map(x=>'"'+String(x).replaceAll('"','""')+'"').join(",")).join("\r\n")+"\r\n";
    download("lightup-local-handoff-workqueue-HOLD.csv",content,"text/csv;charset=utf-8");
  });
  $("work-filter").addEventListener("change",e=>{filter=e.target.value;render();});
  $("work-reset").addEventListener("click",()=>{
    if(!actions.length||!confirm("Alle tijdelijke menselijke gesprekstatussen terugzetten naar 'open'?"))return;
    annotations=new Map();actions.forEach(a=>a.status="open");render();
  });
  window.addEventListener("lightup:scope-documents",event=>{
    scope=Array.isArray(event.detail)?event.detail:[];
    recompute();
  });
  window.addEventListener("lightup:findings-sources",event=>{
    findings=Array.isArray(event.detail)?event.detail:[];
    recompute();
  });
  render();
})();