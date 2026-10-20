"use strict";
/**
 * Standalone, fictional, in-memory education aid.
 * Never read production sources, call an API, authenticate anyone, grant scope, or dispatch tools.
 */
(() => {
  const TYPES = Object.freeze({
    CLIENT_CONSENT: ["Fictieve clientverklaring", "Een zelf ingevoerde oefenverklaring; geen echte clientauthenticatie."],
    OPERATOR_CONSENT: ["Fictieve operatorverklaring", "Een zelf ingevoerde oefenverklaring; geen echte operatorauthenticatie."],
    SCOPE_CHANGED: ["Scopewijziging", "Vorige verklaringen zijn niet overgedragen naar gewijzigde scope."],
    RISK_CHANGED: ["Risicowijziging", "Vorige verklaringen zijn niet overgedragen naar hoger risico."],
    CLIENT_REVOKED: ["Fictieve clientintrekking", "De clientverklaring is vanaf dit oefenmoment ongeldig."],
    OPERATOR_REVOKED: ["Fictieve operatorintrekking", "De operatorverklaring is vanaf dit oefenmoment ongeldig."],
    WINDOW_EXPIRED: ["Venster verlopen", "Geen fictieve gebruiksgeldigheid meer."],
    NEW_WINDOW: ["Nieuw tijdvenster", "Een nieuw fictief venster vereist beide verklaringen opnieuw."],
    EMERGENCY_STOP: ["Noodstop", "De oefenstop blijft actief voor de rest van dit scenario."],
    DISPATCH_ATTEMPT: ["Gesimuleerde uitvoerpoging", "Alleen fictieve controle. Er wordt NOOIT een tool aangeroepen."]
  });
  const presets = Object.freeze({
    empty: [],
    happy: ["CLIENT_CONSENT","OPERATOR_CONSENT","DISPATCH_ATTEMPT"],
    revoke: ["CLIENT_CONSENT","OPERATOR_CONSENT","DISPATCH_ATTEMPT","CLIENT_REVOKED","DISPATCH_ATTEMPT"],
    scope: ["CLIENT_CONSENT","OPERATOR_CONSENT","SCOPE_CHANGED","DISPATCH_ATTEMPT","CLIENT_CONSENT","OPERATOR_CONSENT","DISPATCH_ATTEMPT"],
    stop: ["CLIENT_CONSENT","OPERATOR_CONSENT","EMERGENCY_STOP","DISPATCH_ATTEMPT","NEW_WINDOW","CLIENT_CONSENT","OPERATOR_CONSENT","DISPATCH_ATTEMPT"]
  });
  // Fixed fictional educational cases; neither these nor selections are security findings,
  // policy evaluations, authenticated identities or authorizations.
  const DRILLS = Object.freeze([
    {title:"Twee onafhankelijke partijen",events:["CLIENT_CONSENT","DISPATCH_ATTEMPT"],
      summary:"Een oefenclient is aangemeld; er ontbreekt een fictieve operatorverklaring.",
      question:"Wat is buiten de oefening de verantwoordelijke vervolgstap?",
      choices:["Echte afzonderlijk geauthenticeerde operatorverklaring en actuele scope laten bevestigen",
        "Alleen een eerdere clientverklaring als uitvoermachtiging gebruiken",
        "De simulatoruitkomst als toestemming registreren"],correct:0,
      explain:"De ene partij kan de andere niet vervangen. Werkelijke actuele identiteit, specifieke assets/risico en onafhankelijke operatorreview horen bij de oorspronkelijke LightUp-autorisatiecode."},
    {title:"Client trekt toestemming in",events:["CLIENT_CONSENT","OPERATOR_CONSENT","CLIENT_REVOKED","DISPATCH_ATTEMPT"],
      summary:"Na twee fictieve verklaringen trekt de oefenclient de verklaring in.",
      question:"Welke keuze is passend bij de uitvoergrens?",
      choices:["De oudere verklaring blijven vertrouwen tot de volgende dag",
        "Aan de feitelijke I/O-grens opnieuw intrekking controleren en uitvoering tegenhouden",
        "De intrekking als metadata markeren maar alsnog doorgaan"],correct:1,
      explain:"Een ingetrokken verklaring heeft geen restbevoegdheid. De echte uitvoeringspoort moet op het gebruiksmoment duurzaam en fail-closed hercontroleren; deze oefening controleert niets echt."},
    {title:"Scope verandert na goedkeuring",events:["CLIENT_CONSENT","OPERATOR_CONSENT","SCOPE_CHANGED","DISPATCH_ATTEMPT"],
      summary:"Een fictieve nieuwe asset-/capability-scope wordt voorgesteld nadat beide verklaringen waren ingevoerd.",
      question:"Wat is de aangewezen menselijke vervolgstap?",
      choices:["Oude verklaringen zonder herbeoordeling meenemen",
        "Alleen een lagere fictieve risicoscore invullen",
        "Nieuwe exacte scope door echte client én operator afzonderlijk laten beoordelen"],correct:2,
      explain:"Een scopewijziging is geen behoud van eerder verleende rechten. Vraag toestemming op de exacte vernieuwde scope en risico's; de demo genereert geen grants."},
    {title:"Geldigheidsvenster is voorbij",events:["CLIENT_CONSENT","OPERATOR_CONSENT","WINDOW_EXPIRED","DISPATCH_ATTEMPT"],
      summary:"De fictieve tijdslimiet is verlopen voordat een oefenuitvoerpoging plaatsvindt.",
      question:"Welke aanpak blijft binnen de veiligheidsgrens?",
      choices:["Een nieuwe geldige periode én actuele onafhankelijke toestemming verifiëren voordat echte uitvoering überhaupt overwogen wordt",
        "De lokale klok terugzetten en doorgaan",
        "Het oude venster stilzwijgend verlengen"],correct:0,
      explain:"Verlopen toestemming mag niet stilzwijgend worden verlengd. Een nieuwe periode vereist originele bron- en identiteitscontroles plus afzonderlijke actuele instemming."},
    {title:"Noodstop is geactiveerd",events:["CLIENT_CONSENT","OPERATOR_CONSENT","EMERGENCY_STOP","DISPATCH_ATTEMPT"],
      summary:"Er is een oefennoodstop gemeld, ook al waren daarvoor twee fictieve verklaringen ingevoerd.",
      question:"Welke actie is toegestaan?",
      choices:["Een andere operator aanwijzen en dezelfde uitvoering opnieuw starten",
        "Uitvoering tegenhouden en alleen via het oorspronkelijke geautoriseerde incident-/herstelproces vervolg bepalen",
        "Alleen de clientverklaring vernieuwen om de stop op te heffen"],correct:1,
      explain:"Een noodstop heeft voorrang. Deze trainingsapp kan hem niet opheffen en heeft geen koppeling met een echte stop, bronstatus of run."},
    {title:"Simulatie toont geen oefenblokkade",events:["CLIENT_CONSENT","OPERATOR_CONSENT","DISPATCH_ATTEMPT"],
      summary:"Beide fictieve verklaringen zijn handmatig ingevoerd; het speelgoedmodel toont geen ontbrekende fictieve voorwaarden.",
      question:"Wat mag je hieruit concluderen over echte targets?",
      choices:["Er is een echte vrijgegeven scan mogelijk",
        "Een lokale groenachtige tekst bewijst actuele toestemming",
        "Niets over echte toestemming: originele brongebonden authenticatie, revocatie, CI, onafhankelijke reviews en HUMAN GO blijven verplicht"],correct:2,
      explain:"Oefenprecondities zijn niet gelijk aan werkelijk bronbewijs of veiligheidsgoedkeuring. Geen enkele simulatoruitkomst verleent scan-, deploy- of grantbevoegdheid."}
  ]);
  const MAX = 64;
  const $ = id => document.getElementById(id);
  let events = [];
  let baseline = null;
  // Eight fixed slots; no names, external identifiers or automatic persistence.
  let slots = Array(8).fill(null);
  let replayCursor = null; // null follows the current final fictitious step.
  let momentFrom=0, momentTo=null; // display-only fictional comparison; not an authority decision.
  const HISTORY_MAX=48;
  let undoFrames=[],redoFrames=[];
  let workspaceVersion=0; // monotonic, including undo/redo: rejects import read-back ABA races.
  let activeDrill = null;
  let selectedDrill = 0;
  let drillAnswers = Array(DRILLS.length).fill(null);

  function fresh() {
    return {client:false,operator:false,scope:0,risk:0,window:true,stop:false,attempts:0,lastAttempt:null};
  }
  function blockers(s) {
    const list = [];
    if (s.stop) list.push("Fictieve noodstop staat aan");
    if (!s.window) list.push("Fictief geldigheidsvenster is verlopen");
    if (!s.client) list.push("Nieuwe fictieve clientverklaring ontbreekt");
    if (!s.operator) list.push("Nieuwe fictieve operatorverklaring ontbreekt");
    return list;
  }
  function apply(s, event) {
    switch (event) {
      case "CLIENT_CONSENT": s.client = true; break;
      case "OPERATOR_CONSENT": s.operator = true; break;
      case "SCOPE_CHANGED": s.scope += 1; s.client = false; s.operator = false; break;
      case "RISK_CHANGED": s.risk += 1; s.client = false; s.operator = false; break;
      case "CLIENT_REVOKED": s.client = false; break;
      case "OPERATOR_REVOKED": s.operator = false; break;
      case "WINDOW_EXPIRED": s.window = false; s.client = false; s.operator = false; break;
      case "NEW_WINDOW": s.window = true; s.client = false; s.operator = false; break;
      case "EMERGENCY_STOP": s.stop = true; break;
      case "DISPATCH_ATTEMPT":
        s.attempts += 1;
        s.lastAttempt = {step:s.attempts,missing:blockers(s)};
        break;
      default: throw new Error("Onbekende fictieve gebeurtenis");
    }
    return s;
  }
  function play(seq) {
    const s = fresh();
    const steps = [];
    for (const event of seq) {
      if (!Object.hasOwn(TYPES,event)) throw new Error("Onbekende gebeurtenis");
      apply(s,event);
      steps.push({event,missing:event === "DISPATCH_ATTEMPT" ? s.lastAttempt.missing.slice() : []});
    }
    return {state:s,steps};
  }
  function replayPosition() {
    return replayCursor===null ? events.length : Math.max(0,Math.min(events.length,replayCursor));
  }
  function replayContext(position) {
    const upto=events.slice(0,position);
    const view=play(upto),state=view.state;
    return {position,upto,state,missing:blockers(state),
      attempts:view.steps.filter(x=>x.event==="DISPATCH_ATTEMPT").length,
      last:position ? TYPES[events[position-1]][0] : "Begin van fictief scenario"};
  }
  function renderReplay() {
    const step=replayPosition(),preview=replayContext(step);
    const field=$("replay-step");
    field.max=String(events.length);
    field.value=String(step);
    write("replay-step-count",step+" / "+events.length);
    write("replay-description","Stap "+step+" van "+events.length+": "+preview.last+
      ". Dit is een fictieve momentopname, geen origineel bronbewijs of toestemming.");
    write("replay-client",preview.state.client?"Oefenverklaring aanwezig":"Ontbreekt / vervallen");
    write("replay-operator",preview.state.operator?"Oefenverklaring aanwezig":"Ontbreekt / vervallen");
    write("replay-window",preview.state.window?"Fictief open":"Verlopen");
    write("replay-stop",preview.state.stop?"ACTIEF (oefening)":"Niet actief");
    write("replay-version","v"+(preview.state.scope+1)+" / v"+(preview.state.risk+1));
    write("replay-holds",preview.missing.length+" — "+(preview.missing.length?
      preview.missing.join("; "):"geen in uitsluitend het oefenscenario"));
    $("replay-prev").disabled=step===0;
    $("replay-next").disabled=step===events.length;
    $("replay-end").disabled=step===events.length;
    $("replay-fork").disabled=!slots.some(x=>x===null);
    write("replay-hint",slots.some(x=>x===null)
      ? "Vrije fictieve scenario-slots: "+slots.filter(x=>x===null).length+
        ". Vertakking bewaart het geselecteerde voortraject en houdt het oorspronkelijke volledige scenario als nulmeting."
      : "Alle acht scenario-slots zijn gevuld. Wis eerst bewust een eigen slot om veilig te kunnen vertakken.");
  }
  function focusHistoricalAttempt(step){
    if(!Number.isSafeInteger(step) || step<1 || step>events.length ||
        events[step-1]!=="DISPATCH_ATTEMPT")return;
    momentFrom=step-1;
    momentTo=step;
    replayCursor=step;
    render();
    $("replay-step").focus();
    $("moment-title").scrollIntoView({block:"nearest"});
    feedback("Historische fictieve poging bij stap "+step+" geopend. "+
      "Vergelijk de oorspronkelijke situatie vóór en direct na de poging; nooit echte toestemming.");
  }
  function focusNextHistoricalHold(){
    const history=play(events).steps.flatMap((step,index)=>
      step.event==="DISPATCH_ATTEMPT" && step.missing.length?[index+1]:[]);
    if(!history.length){feedback("Geen historische fictieve HOLD-pogingen.");return;}
    const current=replayPosition();
    focusHistoricalAttempt(history.find(step=>step>current)||history[0]);
  }
  function momentComparison() {
    const start=Math.min(events.length,Math.max(0,momentFrom));
    const finish=Math.min(events.length,Math.max(0,momentTo===null?events.length:momentTo));
    const a=replayContext(start),b=replayContext(finish);
    const differences=[
      ["Client-oefenverklaring",a.state.client,b.state.client,x=>x?"fictief aanwezig":"ontbreekt"],
      ["Operator-oefenverklaring",a.state.operator,b.state.operator,x=>x?"fictief aanwezig":"ontbreekt"],
      ["Geldigheidsvenster",a.state.window,b.state.window,x=>x?"fictief open":"verlopen"],
      ["Noodstop",a.state.stop,b.state.stop,x=>x?"ACTIEF":"niet actief"],
      ["Scope-revisie",a.state.scope+1,b.state.scope+1,x=>"v"+x],
      ["Risico-revisie",a.state.risk+1,b.state.risk+1,x=>"v"+x],
      ["Uitvoerpogingen tot moment",a.attempts,b.attempts,String]
    ].map(([name,oldValue,newValue,fmt])=>
      name+": "+fmt(oldValue)+" → "+fmt(newValue)+(oldValue===newValue?" (onveranderd)":" (gewijzigd)"));
    const aMissing=new Set(a.missing),bMissing=new Set(b.missing);
    const added=b.missing.filter(x=>!aMissing.has(x));
    const removed=a.missing.filter(x=>!bMissing.has(x));
    differences.push("Nieuwe fictieve HOLD-redenen: "+(added.length?added.join("; "):"geen"));
    differences.push("Verdwenen fictieve HOLD-redenen: "+(removed.length?removed.join("; "):"geen"));
    const earlier=Math.min(start,finish),later=Math.max(start,finish);
    const interval=events.slice(earlier,later).map((type,i)=>
      "Stap "+(earlier+i+1)+": "+TYPES[type][0]);
    return {start,finish,differences,interval,from:a,to:b};
  }
  function renderMomentComparison() {
    const from=$("moment-from"),to=$("moment-to");
    momentFrom=Math.min(momentFrom,events.length);
    if(momentTo!==null)momentTo=Math.min(momentTo,events.length);
    for(const [select,value] of [[from,momentFrom],[to,momentTo===null?events.length:momentTo]]) {
      select.replaceChildren();
      for(let i=0;i<=events.length;i++){
        const option=document.createElement("option");
        option.value=String(i);
        option.textContent=i===0?"0 · begin":"Stap "+i+" · "+TYPES[events[i-1]][0];
        select.append(option);
      }
      select.value=String(value);
    }
    const report=momentComparison();
    write("moment-summary","Fictief moment "+report.start+" → "+report.finish+
      ". "+report.interval.length+" gebeurtenis(sen) tussen deze momenten, "+
      report.to.missing.length+" fictieve HOLD-redenen op eindmoment. NOOIT een echte vrijgave.");
    const list=$("moment-deltas");
    list.replaceChildren();
    report.differences.forEach(t=>list.append(el("li","",t)));
    if(!report.interval.length)list.append(el("li","","Geen tussenliggende fictieve gebeurtenissen."));
  }
  function momentBrief(){
    const report=momentComparison();
    return ["# LightUp — PRIVATE fictieve momentvergelijking","",
      "**Oefengegevens, geen bronidentiteit, toestemming, grant, daadwerkelijke scan of release.**","",
      "Van stap "+report.start+" naar stap "+report.finish+".",
      "Fictieve gebeurtenissen tussen gekozen momenten:",...(
        report.interval.length?report.interval.map(x=>"- "+x):["- Geen"]),"",
      "## Verschillen",...report.differences.map(x=>"- "+x),"",
      "## Werkelijke voorwaarden blijven buiten deze oefening",
      "Originele brongebonden scope/asset/capability, apart geauthenticeerde client- en operatorconsent, live revocation vóór I/O, onafhankelijke reviews, originele exacte CI en expliciete HUMAN GO.",
      "AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · DEPLOY_ALLOWED=false",""].join("\n");
  }
  function replayBrief() {
    const moment=replayContext(replayPosition()),final=replayContext(events.length);
    const lines=["# LightUp — fictieve stapbeslisbrief","",
      "**Dit is geen echte scope-, grant-, consent-, CI-, scan- of releasebeslissing.**",
      "",
      "Geselecteerde oefenstap: "+moment.position+" / "+events.length,
      "Laatste fictieve gebeurtenis: "+moment.last,
      "Client-oefenverklaring: "+(moment.state.client?"aanwezig":"ontbreekt"),
      "Operator-oefenverklaring: "+(moment.state.operator?"aanwezig":"ontbreekt"),
      "Venster: "+(moment.state.window?"fictief open":"verlopen"),
      "Noodstop: "+(moment.state.stop?"actief":"niet actief"),
      "Scope-/risicoversie: "+(moment.state.scope+1)+"/"+(moment.state.risk+1),
      "Fictieve blokkades bij deze stap: "+(moment.missing.length?moment.missing.join("; "):"geen in het speelgoedmodel"),
      "",
      "## Afzonderlijke volledige afloop",
      "Oefenstappen: "+final.position,
      "Fictieve eindblokkades: "+(final.missing.length?final.missing.join("; "):"geen in het speelgoedmodel"),
      "Fictieve eindnoodstop: "+(final.state.stop?"actief":"niet actief"),
      "",
      "## Origineel verplicht menselijk vervolg buiten de oefening",
      "Actuele onafhankelijke geauthenticeerde client- en operatorconsent; brongebonden exacte assets, capabilities, risico en tijd; oorspronkelijke duurzame revocation bij iedere I/O; source-owner en onafhankelijke security/privacy/browserreview; originele exact-head hosted plus permanently registered named VPS CI en expliciete HUMAN GO.",
      "",
      "AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · DEPLOY_ALLOWED=false",
      ""];
    return lines.join("\n");
  }
  function el(tag,cls,content) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (typeof content === "string") node.textContent = content;
    return node;
  }
  function write(id, text) { $(id).textContent = text; }
  function render() {
    const {state:s,steps} = play(events);
    const holder = $("timeline");
    holder.replaceChildren();
    const filter=$("timeline-filter").value;
    steps.forEach((step,i)=>{
      if(filter==="attempts" && step.event!=="DISPATCH_ATTEMPT")return;
      if(filter==="holds" && (step.event!=="DISPATCH_ATTEMPT" || !step.missing.length))return;
      if(filter==="revisions" && !["SCOPE_CHANGED","RISK_CHANGED","CLIENT_REVOKED","OPERATOR_REVOKED","WINDOW_EXPIRED","NEW_WINDOW","EMERGENCY_STOP"].includes(step.event))return;
      const item=el("li");
      if(i+1>replayPosition())item.classList.add("replay-future");
      if(i+1===replayPosition()){item.classList.add("replay-picked");item.setAttribute("aria-current","step");}
      item.append(el("span","number",String(i+1)));
      const inner=el("span");
      inner.append(el("span","event-name",TYPES[step.event][0]));
      const note=step.event==="DISPATCH_ATTEMPT"
        ? step.missing.length
          ? "OEFEN-HOLD: " + step.missing.join(" · ")
          : "OEFENPRECONDITIES AANWEZIG · geen echte toestemming"
        : TYPES[step.event][1];
      inner.append(el("span","event-note",note));
      item.append(inner);
      const actions=el("span","event-actions");
      const up=el("button","small-button","↑");
      up.type="button";up.disabled=i===0;
      up.setAttribute("aria-label","Verplaats stap "+(i+1)+" omhoog");
      up.addEventListener("click",()=>mutateWorkspace(()=>{[events[i-1],events[i]]=[events[i],events[i-1]];},"Stap verplaatst; fictieve beslisvolgorde opnieuw berekend."));
      const down=el("button","small-button","↓");
      down.type="button";down.disabled=i===events.length-1;
      down.setAttribute("aria-label","Verplaats stap "+(i+1)+" omlaag");
      down.addEventListener("click",()=>mutateWorkspace(()=>{[events[i],events[i+1]]=[events[i+1],events[i]];},"Stap verplaatst; fictieve beslisvolgorde opnieuw berekend."));
      const remove=el("button","small-button remove-button","×");
      remove.type="button";remove.setAttribute("aria-label","Verwijder stap "+(i+1));
      remove.addEventListener("click",()=>mutateWorkspace(()=>{events.splice(i,1);},"Fictieve stap verwijderd; herstel via ongedaan maken mogelijk."));
      actions.append(up,down,remove);
      item.append(actions);
      holder.append(item);
    });
    write("step-count",events.length+" / "+MAX);
    $("empty").hidden=events.length>0;
    $("undo").disabled=undoFrames.length===0;
    $("redo").disabled=redoFrames.length===0;
    write("undo-hint",undoFrames.length+" herstelbare lokale wijzigingen · "+redoFrames.length+
      " opnieuw uitvoerbaar. Bounded history, alleen in browsergeheugen.");
    $("add-event").disabled=events.length>=MAX;
    write("client-state",s.client ? "Fictief aanwezig" : "Ontbreekt / vervallen");
    write("operator-state",s.operator ? "Fictief aanwezig" : "Ontbreekt / vervallen");
    write("scope-state","Scope v"+(s.scope+1)+" · Risico v"+(s.risk+1));
    write("window-state",s.window ? "Fictief open" : "Verlopen");
    write("stop-state",s.stop ? "ACTIEF – niet heropenbaar" : "Niet geactiveerd");
    write("attempt-state",s.attempts ? s.attempts+" gesimuleerd; laatste "+(s.lastAttempt.missing.length ? "HOLD":"oefenprecondities aanwezig") : "Geen");
    const missing=blockers(s);
    const history=steps.flatMap((step,index)=>step.event==="DISPATCH_ATTEMPT"?
      [{number:index+1,missing:step.missing}]:[]);
    const blocked=history.filter(x=>x.missing.length).length;
    write("attempt-history-summary",history.length+" gesimuleerd · "+blocked+" oefen-HOLD · "+(history.length-blocked)+
      " uitsluitend fictief zonder oefenblokkade. GEEN daadwerkelijke uitvoering.");
    const historicList=$("attempt-history-details");
    historicList.replaceChildren();
    history.forEach(entry=>{
      const item=el("li");
      item.append(document.createTextNode("Stap "+entry.number+": "+(entry.missing.length
        ? "OEFEN-HOLD — "+entry.missing.join("; ")
        : "Geen fictieve blokkade op dit moment; NOOIT echte toestemming.")+" "));
      const jump=el("button","small-button",entry.missing.length?"Bekijk HOLD":"Bekijk poging");
      jump.type="button";
      jump.setAttribute("aria-label","Bekijk fictieve uitvoerpoging bij stap "+entry.number);
      jump.addEventListener("click",()=>focusHistoricalAttempt(entry.number));
      item.append(jump);
      historicList.append(item);
    });
    $("next-hold").disabled=blocked===0;
    if (!events.length) {
      write("status-title","Wacht op scenario");
      write("status-reason","Voeg gebeurtenissen toe of laad een fictief voorbeeld. Geen echte autorisatiecontrole.");
    } else if (missing.length) {
      write("status-title","OEFEN-HOLD · "+missing.length+" aandachtspunten");
      write("status-reason",missing.join(" · ")+". Dit geldt uitsluitend binnen het fictieve scenario.");
    } else {
      write("status-title","Oefenprecondities aanwezig");
      write("status-reason","Zelf ingevoerde scenarioverklaringen lijken compleet. Werkelijke authenticatie, actuele revocatie en uitvoergrenzen zijn NIET gecontroleerd. Geen toestemming tot handelen.");
    }
    write("status-icon",missing.length ? "!" : "i");
    const needs=$("needs");
    needs.replaceChildren();
    const messages=[
      "Echte onafhankelijke actuele client- en operatorauthenticatie buiten deze app.",
      "Werkelijk goedgekeurde asset, tenant, capability, risicoklasse en gebruiksperiode.",
      "Werkelijke duurzame intrekking + controle onmiddellijk vóór elke I/O/uitvoering.",
      "Oorspronkelijke source-owner en onafhankelijke security/privacy/browserreview.",
      "Originele exact-head hosted én permanente named VPS CI; expliciete HUMAN GO."
    ];
    missing.forEach(m=>messages.unshift("Fictief: "+m+"."));
    messages.forEach(t=>needs.append(el("li","",t)));
    const delta=$("compare-deltas");
    delta.replaceChildren();
    $("clear-baseline").disabled=baseline===null;
    if (baseline === null) {
      write("baseline-hint","Geen nulmeting vastgelegd.");
      write("compare-summary","Leg links een fictieve nulmeting vast om veranderingen te vergelijken.");
    } else {
      const base=play(baseline).state;
      const baseMissing=blockers(base);
      write("baseline-hint","Nulmeting met "+baseline.length+" vaste fictieve stappen vastgelegd; alleen in geheugen.");
      const countChange=events.length-baseline.length;
      const first=Math.min(events.length,baseline.length);
      let divergence=first;
      for (let i=0;i<first;i++) {if(events[i]!==baseline[i]){divergence=i;break;}}
      const same=events.length===baseline.length && divergence===first;
      write("compare-summary",same
        ? "Huidig scenario is gebeurtenis-voor-gebeurtenis identiek aan de nulmeting."
        : "Scenario is gewijzigd. Dit is alleen een vergelijking van eigen fictieve invoer, geen claim over echte autorisatie.");
      const details=[
        "Verschil aantal gebeurtenissen: "+(countChange>0?"+":"")+countChange,
        same ? "Geen gewijzigde gebeurtenissen." : "Eerste andere of afwezige gebeurtenis: stap "+(divergence+1),
        "Oefen-HOLD-punten: nulmeting "+baseMissing.length+" → huidig "+missing.length,
        "Noodstop: "+(base.stop?"actief":"niet actief")+" → "+(s.stop?"actief":"niet actief"),
        "Fictieve clientverklaring: "+(base.client?"aanwezig":"ontbreekt")+" → "+(s.client?"aanwezig":"ontbreekt"),
        "Fictieve operatorverklaring: "+(base.operator?"aanwezig":"ontbreekt")+" → "+(s.operator?"aanwezig":"ontbreekt"),
        "Scope-/risicoversies: "+(base.scope+1)+"/"+(base.risk+1)+" → "+(s.scope+1)+"/"+(s.risk+1),
        "Fictieve uitvoerpogingen: "+base.attempts+" → "+s.attempts
      ];
      details.forEach(t=>delta.append(el("li","",t)));
    }
    renderBank();
    renderLessonQueue();
    renderReplay();
    renderMomentComparison();
    refreshDrillStatus();
    return {s,steps,missing};
  }
  function slotEntry(seq,base) {
    return {events:seq.slice(),baseline_events:base===null?null:base.slice()};
  }
  function slotSummary(slot) {
    const state=play(slot.events).state;
    const holds=blockers(state).length;
    const attemptHolds=play(slot.events).steps.filter(x=>x.event==="DISPATCH_ATTEMPT" && x.missing.length).length;
    return {steps:slot.events.length,holds,attempts:state.attempts,attemptHolds,
      stop:state.stop,client:state.client,operator:state.operator,
      scope:state.scope+1,risk:state.risk+1};
  }
  function lessonQueue(){
    return slots.flatMap((slot,index)=>{
      if(!slot)return [];
      const report=slotSummary(slot),tips=[];
      if(report.stop)tips.push("Noodstop: bespreek dat een latere verklaring de fictieve STOP niet opheft.");
      if(report.attemptHolds)tips.push("Historische HOLD: open een destijds geblokkeerde poging en vergelijk de momenten direct ervoor en erna.");
      if(report.scope>1 || report.risk>1)tips.push("Scope/risico: licht toe waarom oude fictieve verklaringen na een revisie vervallen.");
      if(!report.client || !report.operator)tips.push("Twee partijen: bespreek apart ontbrekende of ingetrokken client- en operatorverklaringen.");
      if(!play(slot.events).state.window)tips.push("Geldigheidsvenster: verlengen of klok terugzetten levert nooit nieuwe oorspronkelijke toestemming.");
      if(!report.attempts)tips.push("Uitvoerpogingen: simuleer een fictieve poging om de toenmalige HOLD-redenen zichtbaar te maken.");
      if(!tips.length)tips.push("Schijnbaar compleet: bespreek waarom dit speelgoedmodel nooit echte autorisatie, CI of HUMAN GO aantoont.");
      const priority=report.stop?0:report.attemptHolds?1:report.holds?2:3;
      return [{index,priority,steps:report.steps,holdCount:report.attemptHolds,tips}];
    }).sort((a,b)=>a.priority-b.priority || a.index-b.index);
  }
  function renderLessonQueue(){
    const queue=lessonQueue(),list=$("lesson-queue-list");
    list.replaceChildren();
    write("lesson-queue-summary",queue.length?
      queue.length+" fictieve scenario's in didactische volgorde. "+
      queue.filter(x=>x.holdCount>0).length+" met eerdere oefen-HOLDs. Geen echte risico-inschatting.":
      "Geen opgeslagen scenario's. Bewaar eerst één of meer fictieve voorbeelden.");
    $("lesson-brief").disabled=!queue.length;
    queue.forEach(entry=>{
      const item=el("li");
      item.append(el("strong","", "Scenario "+(entry.index+1)+" · "+entry.steps+" fictieve stappen"));
      const notes=el("ul","needs");
      entry.tips.forEach(t=>notes.append(el("li","",t)));
      item.append(notes);
      const open=el("button","small-button","Open fictief scenario "+(entry.index+1));
      open.type="button";
      open.addEventListener("click",()=>{
        const saved=slots[entry.index];
        if(!saved)return;
        if((events.length || baseline!==null) &&
          !window.confirm("Editor vervangen door fictief scenario "+(entry.index+1)+"? Huidig werk is herstelbaar via undo."))return;
        mutateWorkspace(()=>{
          events=saved.events.slice();
          baseline=saved.baseline_events===null?null:saved.baseline_events.slice();
        },"Fictief scenario "+(entry.index+1)+" geopend voor HUMAN oefenbespreking.");
        $("timeline-filter").value="holds";
        render();
        $("timeline-filter").focus();
      });
      item.append(open);
      list.append(item);
    });
  }
  function lessonBrief(){
    const queue=lessonQueue(),lines=[
      "# LightUp — PRIVATE fictieve begeleidersagenda","",
      "**Uitsluitend offline menselijk onderwijs op zelfgemaakte scenario's. Geen echt bronbewijs, target, scope of autorisatie.**",""];
    queue.forEach(entry=>{
      lines.push("## Scenario "+(entry.index+1)+" · "+entry.steps+" stappen",
        "Historische oefen-HOLDs: "+entry.holdCount,
        ...entry.tips.map(t=>"- "+t),"");
    });
    lines.push("## Altijd nog onafhankelijk vereist",
      "Actuele authentieke client- en operatorconsent, exacte oorspronkelijke assets/capabilities/risico/venster, revocation onmiddellijk vóór daadwerkelijk I/O, originele CI, onafhankelijke reviews en expliciete HUMAN GO.",
      "AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · DEPLOY_ALLOWED=false","");
    return lines.join("\n");
  }
  function renderBank() {
    const root=$("bank-rows");
    root.replaceChildren();
    slots.forEach((slot,i)=>{
      const tr=el("tr");
      const label=el("td","slot-name","Scenario "+(i+1));
      const cell=el("td","slot-state",slot
        ? slot.events.length+" stappen · "+slotSummary(slot).holds+" huidige oefenblokkades · "+slotSummary(slot).attemptHolds+" historische oefen-HOLDs"
        : "Leeg");
      const actions=el("td","bank-buttons");
      const save=el("button","small-button bank-button",slot ? "Bijwerken":"Bewaren");
      save.type="button";save.setAttribute("aria-label","Bewaar huidig scenario in slot "+(i+1));
      save.addEventListener("click",()=>{
        if(slot && !window.confirm("Scenario "+(i+1)+" in lokaal geheugen vervangen?")) return;
        mutateWorkspace(()=>{slots[i]=slotEntry(events,baseline);},"Fictief scenario "+(i+1)+" in browsergeheugen bewaard.");
      });
      const load=el("button","small-button bank-button","Openen");
      load.type="button";load.disabled=!slot;
      load.setAttribute("aria-label","Open scenario uit slot "+(i+1));
      load.addEventListener("click",()=>{
        if (!slots[i])return;
        if ((events.length || baseline!==null) && !window.confirm("Editor vervangen door scenario "+(i+1)+"?"))return;
        mutateWorkspace(()=>{
          events=slots[i].events.slice();
          baseline=slots[i].baseline_events===null?null:slots[i].baseline_events.slice();
        },"Scenario "+(i+1)+" lokaal geopend; vorige editorversie via ongedaan maken herstelbaar.");
      });
      const erase=el("button","small-button remove-button bank-button","Wissen");
      erase.type="button";erase.disabled=!slot;
      erase.setAttribute("aria-label","Wis scenario uit slot "+(i+1));
      erase.addEventListener("click",()=>{
        if(!slots[i] || !window.confirm("Slot "+(i+1)+" uit lokaal geheugen wissen?"))return;
        mutateWorkspace(()=>{slots[i]=null;},"Fictief slot "+(i+1)+" uit lokaal geheugen gewist.");
      });
      actions.append(save,load,erase);tr.append(label,cell,actions);root.append(tr);
    });
    updateSlotSelectors();
    renderCoverage();
  }
  function renderCoverage() {
    const root=$("coverage-rows");
    root.replaceChildren();
    let filled=0,existingHolds=0,blockedAttempts=0;
    slots.forEach((slot,i)=>{
      const tr=el("tr");
      tr.append(el("th","",String(i+1)));
      if(slot===null) {
        for(let k=0;k<5;k++) tr.append(el("td","", "—"));
      } else {
        filled++;
        const state=play(slot.events).state;
        const count=blockers(state).length;
        const earlier=slotSummary(slot).attemptHolds;
        existingHolds+=count;blockedAttempts+=earlier;
        const cells=[
          [state.client,"Fictief ja","Ontbreekt"],
          [state.operator,"Fictief ja","Ontbreekt"],
          [state.window,"Open (fictief)","Verlopen"],
          [!state.stop,"Niet actief","Actief"],
          [earlier===0,"Geen geregistreerd",earlier+" oefen-HOLD"]
        ];
        cells.forEach(([ok,yes,no])=>{
          const td=el("td");
          td.append(el("span","matrix-tag "+(ok?"matrix-illustrative":"matrix-attention"),ok?yes:no));
          tr.append(td);
        });
      }
      root.append(tr);
    });
    write("coverage-summary",filled+" van 8 fictieve scenario's opgeslagen; "+
      existingHolds+" huidige oefenblokkades en "+blockedAttempts+
      " historische fictieve geblokkeerde pogingen in totaal. Dit is nooit toestemming of scanbewijs.");
  }
  function updateSlotSelectors() {
    const filled=slots.flatMap((x,i)=>x===null?[]:[i]);
    const first=$("compare-a"),second=$("compare-b");
    const rememberedA=first.value,rememberedB=second.value;
    first.replaceChildren();second.replaceChildren();
    for (const index of filled) {
      first.append(new Option("Scenario "+(index+1),String(index)));
      second.append(new Option("Scenario "+(index+1),String(index)));
    }
    first.disabled=filled.length===0;
    second.disabled=filled.length===0;
    if(filled.includes(Number(rememberedA)) && rememberedA!=="")first.value=rememberedA;
    if(filled.includes(Number(rememberedB)) && rememberedB!=="")second.value=rememberedB;
    else if(filled.length>1)second.value=String(filled[1]);
    renderSlotComparison();
  }
  function renderSlotComparison() {
    const container=$("slot-compare-details");
    container.replaceChildren();
    const ai=Number($("compare-a").value),bi=Number($("compare-b").value);
    if($("compare-a").value==="" || $("compare-b").value==="" || !slots[ai] || !slots[bi]) {
      write("slot-compare-summary","Bewaar minimaal twee fictieve scenario’s om ze te vergelijken.");
      return;
    }
    const a=slotSummary(slots[ai]),b=slotSummary(slots[bi]);
    const aEvents=slots[ai].events,bEvents=slots[bi].events;
    const n=Math.min(aEvents.length,bEvents.length);
    let changed=n;
    for(let i=0;i<n;i++){if(aEvents[i]!==bEvents[i]){changed=i;break;}}
    const equal=aEvents.length===bEvents.length && changed===n;
    write("slot-compare-summary",ai===bi ? "Hetzelfde fictieve scenario geselecteerd." :
      equal ? "Beide opgeslagen scenario’s bevatten dezelfde oefengebeurtenissen." :
      "Eerste afwijkende of ontbrekende oefengebeurtenis: stap "+(changed+1)+".");
    const lines=[
      "Stappen: "+a.steps+" versus "+b.steps,
      "Fictieve ontbrekende voorwaarden: "+a.holds+" versus "+b.holds,
      "Oefenuitvoerpogingen: "+a.attempts+" versus "+b.attempts,
      "Historische oefen-HOLDs: "+a.attemptHolds+" versus "+b.attemptHolds,
      "Oefennoodstop: "+(a.stop?"aan":"uit")+" versus "+(b.stop?"aan":"uit"),
      "Fictieve clientverklaring: "+(a.client?"aanwezig":"ontbreekt")+" versus "+(b.client?"aanwezig":"ontbreekt"),
      "Fictieve operatorverklaring: "+(a.operator?"aanwezig":"ontbreekt")+" versus "+(b.operator?"aanwezig":"ontbreekt"),
      "Scope/revisie: "+a.scope+" versus "+b.scope+"; risico/revisie: "+a.risk+" versus "+b.risk
    ];
    lines.forEach(t=>container.append(el("li","",t)));
  }
  function boardBrief() {
    const lines=["# LightUp — fictieve scenario-workshop","",
      "**Alle scenario's zijn uitsluitend zelf ingevoerde oefengegevens. Geen echte autorisatie, consent, scan, grant of release.**","",
      "| Slot | Stappen | Fictieve huidige HOLD-redenen | Oefenpogingen | Historische oefen-HOLDs | Noodstop |",
      "| ---: | ---: | ---: | ---: | ---: | --- |"];
    slots.forEach((slot,i)=>{
      if(!slot){lines.push("| "+(i+1)+" | — | — | — | — | Leeg |");return;}
      const r=slotSummary(slot);
      lines.push("| "+(i+1)+" | "+r.steps+" | "+r.holds+" | "+r.attempts+
        " | "+r.attemptHolds+" | "+(r.stop?"Actief":"Niet actief")+" |");
    });
    lines.push("","## Didactische leskaarten (niet geverifieerd)",progressText());
    DRILLS.forEach((d,i)=>lines.push("Kaart "+(i+1)+" — "+d.title+": "+
      (drillAnswers[i]===null?"niet besproken":("keuze "+String.fromCharCode(65+drillAnswers[i])+
      (drillAnswers[i]===d.correct?" (didactisch passend)":" (didactisch aandachtspunt)")))));
    lines.push("","## Menselijke vervolgvragen","Welke originele actuele, apart geauthenticeerde client- en operatorconsent zijn aantoonbaar?","Welke exacte goedgekeurde assets/capabilities en risico's zijn gebonden?","Hoe wordt revocation bij daadwerkelijk I/O-gebruik onafhankelijk gecontroleerd?","Is originele hosted plus permanente named-VPS CI op juiste SHA en HUMAN GO aanwezig?","",
      "**AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false**");
    return lines.join("\n")+"\n";
  }
  function progressText() {
    const attempted=drillAnswers.filter(x=>x!==null).length;
    return attempted+" van "+DRILLS.length+" fictieve oefenkaarten besproken; didactisch, geen CI- of securitybewijs.";
  }
  function scenarioMatchesDrill() {
    const card=DRILLS[selectedDrill];
    return activeDrill===selectedDrill && events.length===card.events.length &&
      card.events.every((e,i)=>e===events[i]);
  }
  function refreshDrillStatus() {
    write("drill-progress",progressText());
    const current=scenarioMatchesDrill();
    $("drill-choices").querySelectorAll("button").forEach(b=>{b.disabled=!current;});
    if (activeDrill===null) return;
    if (!current) {
      write("drill-feedback","De huidige fictieve tijdlijn wijkt af van de geladen oefenkaart. Laad de kaart opnieuw voordat je een didactisch antwoord bespreekt.");
    }
  }
  function selectDrill(index) {
    selectedDrill=index;
    const card=DRILLS[index];
    write("drill-heading",card.title);
    write("drill-description",card.summary);
    write("drill-question",card.question);
    write("drill-feedback","Laad deze fictieve oefenkaart in de tijdlijn. Geen van de antwoorden kan echte autorisatie geven.");
    const holder=$("drill-choices");
    holder.replaceChildren();
    card.choices.forEach((label,i)=>{
      const b=el("button","drill-choice",String.fromCharCode(65+i)+". "+label);
      b.type="button";
      b.addEventListener("click",()=>{
        if(!scenarioMatchesDrill()) {
          write("drill-feedback","Deze kaart is niet langer exact geladen. Herstart hem zonder andere scenario's aan te passen.");return;
        }
        mutateWorkspace(()=>{drillAnswers[selectedDrill]=i;},"Didactische keuze lokaal onthouden.");
        write("drill-feedback",(i===card.correct?"Didactisch passende keuze. ":"Didactisch aandachtspunt. ")+card.explain+
          " Alleen HUMAN oefenfeedback; nooit echte toestemming.");
        refreshDrillStatus();
      });
      holder.append(b);
    });
    refreshDrillStatus();
  }
  function facilitatorPack() {
    const lines=["# LightUp — PRIVATE trainingspakket scope-autorisatie",
      "",
      "**ZES VASTE FICTIEVE OEFENKAARTEN. DIT IS GEEN ORIGINEEL SCAN-/CONSENT-/CI-/VRIJGAVEBEWIJS.**",
      "",
      "Gescheiden echte huidige geauthenticeerde client- en operatortoestemming, brongebonden assets/capability/risico, action-time revocation, privacy/securityreview, originele hosted en permanente VPS CI en HUMAN GO zijn altijd verplicht.",
      "",
      "## Didactische voortgang van deze lokale browsersessie",
      progressText(),
      ""];
    DRILLS.forEach((d,i)=>{
      lines.push("## Kaart "+(i+1)+": "+d.title,
        "",d.summary,
        "Fictieve tijdlijn: "+d.events.map(e=>TYPES[e][0]).join(" → "),
        "",
        "**Vraag:** "+d.question);
      d.choices.forEach((c,n)=>lines.push(String.fromCharCode(65+n)+". "+c));
      lines.push("","**Didactisch passende bespreekkeuze:** "+String.fromCharCode(65+d.correct),
        "**Toelichting:** "+d.explain,
        "**Lokaal oefenantwoord:** "+(drillAnswers[i]===null?"Nog niet besproken":String.fromCharCode(65+drillAnswers[i])),
        "");
    });
    lines.push("## Geen uitvoermachtiging","Deze oefening kan geen identiteit, oorspronkelijke bron, actuele scope, werkelijk verleende toestemming, intrekking of doelwitrechten verifiëren.",
      "AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · DEPLOY_ALLOWED=false",
      "");
    return lines.join("\n");
  }
  function initDrills() {
    DRILLS.forEach((x,i)=>$("drill-select").append(new Option((i+1)+". "+x.title,String(i))));
    $("drill-select").addEventListener("change",()=>selectDrill(Number($("drill-select").value)));
    $("drill-start").addEventListener("click",()=>{
      const card=DRILLS[selectedDrill];
      if((events.length || baseline!==null) &&
         !window.confirm("Huidige oefentijdlijn en nulmeting vervangen? Opgeslagen scenario-slots blijven bestaan."))return;
      mutateWorkspace(()=>{events=card.events.slice();baseline=null;activeDrill=selectedDrill;},
        "Fictieve oefenkaart "+(selectedDrill+1)+" geladen. Geen externe uitvoer.");
      selectDrill(selectedDrill);
    });
    $("drill-clear").addEventListener("click",()=>{
      if(!window.confirm("Alleen didactische antwoordvoortgang uit dit browsergeheugen wissen?"))return;
      mutateWorkspace(()=>{drillAnswers=Array(DRILLS.length).fill(null);},
        "Lokale didactische antwoordvoortgang gewist; herstelbaar via ongedaan maken.");
      selectDrill(selectedDrill);
    });
    $("drill-print-pack").addEventListener("click",()=>{
      bytesDownload("lightup-fictional-facilitator-pack.md",facilitatorPack(),"text/markdown");
      feedback("PRIVATE fictief lespakket met didactische toelichting lokaal aangeboden.");
    });
    selectDrill(0);
  }
  function feedback(t) { write("feedback",t); }
  function add(e) {
    if (events.length>=MAX || !Object.hasOwn(TYPES,e)) { feedback("Geen gebeurtenis toegevoegd: maximum of onbekende code.");return; }
    mutateWorkspace(()=>{events.push(e);},"Fictieve gebeurtenis toegevoegd.");
  }
  function data() {
    return {schema:"lightup.fictional.scope-tabletop.v4",title:"Fictief scope-/intrekkingsoefenscenario",events:events.slice(),
      baseline_events:baseline===null?null:baseline.slice(),
      slots:slots.map(x=>x===null?null:slotEntry(x.events,x.baseline_events)),
      drill_answers:drillAnswers.slice(),
      authority:{authenticated_client:false,authenticated_operator:false,consent_verified:false,
        dispatch_allowed:false,release_allowed:false,deploy_allowed:false}};
  }
  function applyFrame(frame) {
    events=frame.events.slice();
    baseline=frame.baseline_events===null?null:frame.baseline_events.slice();
    slots=frame.slots.map(x=>x===null?null:slotEntry(x.events,x.baseline_events));
    drillAnswers=frame.drill_answers.slice();
    activeDrill=null;replayCursor=null;
  }
  function mutateWorkspace(fn,msg) {
    const old=data(),before=JSON.stringify(old);
    fn();
    if(JSON.stringify(data())!==before) {
      undoFrames.push(old);
      if(undoFrames.length>HISTORY_MAX)undoFrames.shift();
      redoFrames=[];
      workspaceVersion++;
    }
    feedback(msg||"");
    render();
  }
  function historyStep(backward) {
    const from=backward?undoFrames:redoFrames;
    if(!from.length)return;
    const current=data(),restore=from.pop(),other=backward?redoFrames:undoFrames;
    other.push(current);
    if(other.length>HISTORY_MAX)other.shift();
    applyFrame(restore);
    workspaceVersion++;
    selectDrill(selectedDrill);
    feedback(backward?"Laatste wijziging in de lokale fictieve werkruimte hersteld.":
      "Fictieve wijziging opnieuw toegepast.");
    render();
  }
  function bytesDownload(filename,text,mime) {
    const blob = new Blob([text],{type:mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href=url;a.download=filename;a.rel="noopener";document.body.append(a);a.click();a.remove();
    window.setTimeout(()=>URL.revokeObjectURL(url),30000);
  }
  function md() {
    const {s,steps,missing}=render();
    const lines=[
      "# LightUp — fictieve scope-/intrekkingsoefening",
      "",
      "**Uitsluitend PRIVATE, offline HUMAN review. Geen werkelijk bronbewijs, consent, grant, scan of release.**",
      "",
      "| Stap | Fictieve gebeurtenis | Simulatie-effect |",
      "| ---: | --- | --- |"
    ];
    steps.forEach((x,i)=>{
      const info=x.event==="DISPATCH_ATTEMPT" ? (x.missing.length?"OEFEN-HOLD":"Alleen fictieve precondities aanwezig, nooit uitvoeren") : TYPES[x.event][1];
      lines.push("| "+(i+1)+" | "+TYPES[x.event][0]+" | "+info+" |");
    });
    if (baseline!==null) {
      const before=play(baseline).state;
      lines.push("","## Wat-als vergelijking (uitsluitend fictief)",
        "Nulmetingstappen: "+baseline.length+"; actuele stappen: "+events.length,
        "Oefen-HOLD-aandachtspunten: "+blockers(before).length+" → "+missing.length,
        "Noodstop: "+(before.stop?"actief":"inactief")+" → "+(s.stop?"actief":"inactief"),
        "Clientverklaring: "+(before.client?"aanwezig":"ontbreekt")+" → "+(s.client?"aanwezig":"ontbreekt"),
        "Operatorverklaring: "+(before.operator?"aanwezig":"ontbreekt")+" → "+(s.operator?"aanwezig":"ontbreekt"));
    }
    lines.push("","## Samenvatting (uitsluitend fictief)",
      "Clientverklaring: "+(s.client?"ingevoerd":"niet geldig"),
      "Operatorverklaring: "+(s.operator?"ingevoerd":"niet geldig"),
      "Scope-revisie: "+(s.scope+1),
      "Risico-revisie: "+(s.risk+1),
      "Venster: "+(s.window?"open":"verlopen"),
      "Noodstop: "+(s.stop?"actief":"niet actief"),
      "Simulatiepogingen: "+s.attempts,
      "Fictieve huidige blokkades: "+(missing.length?missing.join("; "):"geen in deze zelf ingevoerde oefenprecondities"),
      "",
      "## Verplichte echte vervolgstappen",
      "Oorspronkelijke trusted scope-/tenant-/assetvalidatie, afzonderlijk geauthenticeerde huidige client- en operatorconsent, real-time revocation en uitvoergrens, onafhankelijke reviews, originele exact-head CI op permanente VPS, expliciete menselijke GO. Dit document is nooit autorisatiebewijs.",
      "",
      "AUTHENTICATED=false · CONSENT_VERIFIED=false · DISPATCH_ALLOWED=false · RELEASE_ALLOWED=false · DEPLOY_ALLOWED=false");
    return lines.join("\n")+"\n";
  }
  function validateImport(text) {
    if (text.length > 32768 || !text.length) throw new Error("Bestand buiten de 32 KiB limiet.");
    const parsed=JSON.parse(text);
    if (!parsed || typeof parsed!=="object" || Array.isArray(parsed)) throw new Error("Geen scenario-object.");
    const validSeq=x=>Array.isArray(x) && x.length<=MAX &&
      x.every(e=>typeof e==="string" && Object.hasOwn(TYPES,e));
    if (!validSeq(parsed.events)) throw new Error("Ongeldige fictieve gebeurtenissen.");
    if (parsed.title!=="Fictief scope-/intrekkingsoefenscenario") throw new Error("Onbekende titel.");
    if (!["lightup.fictional.scope-tabletop.v1","lightup.fictional.scope-tabletop.v2","lightup.fictional.scope-tabletop.v3","lightup.fictional.scope-tabletop.v4"].includes(parsed.schema))
      throw new Error("Onbekend scenarioformaat.");
    const v4=parsed.schema==="lightup.fictional.scope-tabletop.v4";
    const v3=v4||parsed.schema==="lightup.fictional.scope-tabletop.v3";
    const v2=v3||parsed.schema==="lightup.fictional.scope-tabletop.v2";
    if(v2 && parsed.baseline_events!==null && !validSeq(parsed.baseline_events))
      throw new Error("Ongeldige fictieve nulmeting.");
    if(v3 && (!Array.isArray(parsed.slots) || parsed.slots.length!==8 || parsed.slots.some(x=>
      x!==null && (!x || typeof x!=="object" || !validSeq(x.events) ||
        (x.baseline_events!==null && !validSeq(x.baseline_events))))))
      throw new Error("Ongeldige fictieve verzameling.");
    if (v4 && (!Array.isArray(parsed.drill_answers) || parsed.drill_answers.length!==DRILLS.length ||
        parsed.drill_answers.some(x=>x!==null && (!Number.isInteger(x) || x<0 || x>2))))
      throw new Error("Ongeldige fictieve lesvoortgang.");
    const normalized={schema:parsed.schema,title:parsed.title,events:parsed.events};
    if(v2) normalized.baseline_events=parsed.baseline_events;
    if(v3) normalized.slots=parsed.slots;
    if(v4) normalized.drill_answers=parsed.drill_answers;
    normalized.authority={authenticated_client:false,authenticated_operator:false,consent_verified:false,
      dispatch_allowed:false,release_allowed:false,deploy_allowed:false};
    // Exact own-export bytes only. Duplicate keys, unknown fields and authority changes fail closed.
    if (JSON.stringify(normalized,null,2)!==text) throw new Error("Niet-canoniek of gewijzigd exportbestand.");
    return {events:parsed.events.slice(),baseline:v2 && parsed.baseline_events!==null ? parsed.baseline_events.slice() : null,
      slots:v3?parsed.slots.map(x=>x===null?null:slotEntry(x.events,x.baseline_events)):Array(8).fill(null),
      drillAnswers:v4?parsed.drill_answers.slice():Array(DRILLS.length).fill(null)};
  }
  $("load-preset").addEventListener("click",()=>{
    const key=$("preset").value;
    if (!Object.hasOwn(presets,key)) return;
    if (events.length && !window.confirm("Bestaand oefenscenario vervangen?")) return;
    mutateWorkspace(()=>{events=presets[key].slice();},"Fictief voorbeeld geladen.");
  });
  $("add-event").addEventListener("click",()=>add($("event-type").value));
  $("set-baseline").addEventListener("click",()=>mutateWorkspace(()=>{baseline=events.slice();},
    "Fictieve nulmeting in lokaal geheugen vastgelegd."));
  $("clear-baseline").addEventListener("click",()=>mutateWorkspace(()=>{baseline=null;},
    "Nulmeting gewist; herstelbaar via ongedaan maken."));
  $("undo").addEventListener("click",()=>historyStep(true));
  $("redo").addEventListener("click",()=>historyStep(false));
  $("clear").addEventListener("click",()=>{
    if(events.length && !window.confirm("Alle fictieve stappen uit editor wissen? De andere lokale slots blijven bestaan."))return;
    mutateWorkspace(()=>{events=[];},"Fictieve editor leeg; herstelbaar via ongedaan maken.");
  });
  $("save-json").addEventListener("click",()=>{bytesDownload("lightup-fictional-scope-tabletop.json",JSON.stringify(data(),null,2),"application/json");feedback("Fictief scenario inclusief slotverzameling lokaal aangeboden.");});
  $("save-board").addEventListener("click",()=>{bytesDownload("lightup-fictional-workshop.json",JSON.stringify(data(),null,2),"application/json");feedback("PRIVATE fictieve workshop inclusief editor en slots lokaal aangeboden.");});
  $("lesson-brief").addEventListener("click",()=>{
    bytesDownload("lightup-fictional-facilitator-agenda.md",lessonBrief(),"text/markdown");
    feedback("PRIVATE fictieve begeleidersagenda aangeboden. Geen echte autorisatie, bronbewijs of release.");
  });
  $("save-board-brief").addEventListener("click",()=>{bytesDownload("lightup-fictional-workshop.md",boardBrief(),"text/markdown");feedback("Fictieve groepsbrief voor PRIVATE HUMAN review aangeboden.");});
  $("compare-a").addEventListener("change",renderSlotComparison);
  $("compare-b").addEventListener("change",renderSlotComparison);
  $("save-md").addEventListener("click",()=>{bytesDownload("lightup-fictional-scope-tabletop.md",md(),"text/markdown");feedback("PRIVATE, niet-autoriseren­de beslisbrief lokaal aangeboden.");});
  $("import-btn").addEventListener("click",()=>$("import-file").click());
  $("import-file").addEventListener("change",async event=>{
    const file=event.target.files?.[0];event.target.value="";if (!file)return;
    if (file.size>32768){feedback("HOLD: scenario groter dan 32 KiB.");return;}
    const oldSession=JSON.stringify(data()),oldVersion=workspaceVersion;
    try {
      const text=await file.text();
      const next=validateImport(text);
      // A local file read may finish after a HUMAN has edited the current scenario.
      // Never silently overwrite those newer choices, including all saved slots.
      if (workspaceVersion!==oldVersion || JSON.stringify(data())!==oldSession) {
        feedback("HOLD: lokale werkruimte gewijzigd tijdens inlezen; bestand niet toegepast.");
        return;
      }
      if ((events.length || baseline!==null || slots.some(x=>x!==null) || drillAnswers.some(x=>x!==null)) &&
          !window.confirm("Editor, nulmeting, acht slots én fictieve lesantwoorden vervangen?")) return;
      mutateWorkspace(()=>{
        events=next.events;baseline=next.baseline;slots=next.slots;
        drillAnswers=next.drillAnswers;activeDrill=null;
      },"Fictief scenario, lesantwoorden en slotverzameling atomair ingelezen; vorige workspace herstelbaar.");
      selectDrill(selectedDrill);
    } catch(_) {feedback("HOLD: alleen exact door deze tool geproduceerde, ongewijzigde fictieve JSON is toegestaan.");}
  });
  $("timeline-filter").addEventListener("change",render);
  $("next-hold").addEventListener("click",focusNextHistoricalHold);
  $("moment-from").addEventListener("change",event=>{
    momentFrom=Number(event.target.value);renderMomentComparison();
  });
  $("moment-to").addEventListener("change",event=>{
    momentTo=Number(event.target.value);renderMomentComparison();
  });
  $("moment-brief").addEventListener("click",()=>{
    bytesDownload("lightup-fictional-moment-comparison.md",momentBrief(),"text/markdown");
    feedback("PRIVATE fictieve momentvergelijking lokaal aangeboden. Geen echte toestemming of autorisatie.");
  });
  $("replay-step").addEventListener("input",event=>{replayCursor=Number(event.target.value);render();});
  $("replay-prev").addEventListener("click",()=>{replayCursor=Math.max(0,replayPosition()-1);render();});
  $("replay-next").addEventListener("click",()=>{replayCursor=Math.min(events.length,replayPosition()+1);render();});
  $("replay-end").addEventListener("click",()=>{replayCursor=null;render();});
  $("replay-fork").addEventListener("click",()=>{
    const first=slots.findIndex(x=>x===null);
    if(first<0){feedback("HOLD: alle acht fictieve scenario-slots bezet. Bestaande slots niet overschreven.");return;}
    const selected=replayPosition();
    if(!window.confirm("Fictief traject t/m stap "+selected+" als alternatieve vertakking in leeg slot "+
      (first+1)+" bewaren? Bestaande editor blijft intact."))return;
    mutateWorkspace(()=>{slots[first]=slotEntry(events.slice(0,selected),events.slice());},
      "Fictieve vertakking bij stap "+selected+" in leeg slot "+(first+1)+
      " opgeslagen; origineel scenario blijft als nulmeting en herstel via undo mogelijk.");
  });
  $("replay-brief").addEventListener("click",()=>{
    bytesDownload("lightup-fictional-step-review.md",replayBrief(),"text/markdown");
    feedback("Fictieve stapbeslisbrief lokaal aangeboden. Geen echte toestemming of bronbewijs.");
  });
  $("print").addEventListener("click",()=>window.print());
  initDrills();
  render();
})();
