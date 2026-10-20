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
  const MAX = 64;
  const $ = id => document.getElementById(id);
  let events = [];

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
    steps.forEach((step,i)=>{
      const item=el("li");
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
      up.addEventListener("click",()=>{[events[i-1],events[i]]=[events[i],events[i-1]];feedback("Stap verplaatst; simulatie volledig herberekend.");render();});
      const down=el("button","small-button","↓");
      down.type="button";down.disabled=i===events.length-1;
      down.setAttribute("aria-label","Verplaats stap "+(i+1)+" omlaag");
      down.addEventListener("click",()=>{[events[i],events[i+1]]=[events[i+1],events[i]];feedback("Stap verplaatst; simulatie volledig herberekend.");render();});
      const remove=el("button","small-button remove-button","×");
      remove.type="button";remove.setAttribute("aria-label","Verwijder stap "+(i+1));
      remove.addEventListener("click",()=>{events.splice(i,1);feedback("Stap verwijderd; simulatie volledig herberekend.");render();});
      actions.append(up,down,remove);
      item.append(actions);
      holder.append(item);
    });
    write("step-count",events.length+" / "+MAX);
    $("empty").hidden=events.length>0;
    $("undo").disabled=events.length===0;
    $("add-event").disabled=events.length>=MAX;
    write("client-state",s.client ? "Fictief aanwezig" : "Ontbreekt / vervallen");
    write("operator-state",s.operator ? "Fictief aanwezig" : "Ontbreekt / vervallen");
    write("scope-state","Scope v"+(s.scope+1)+" · Risico v"+(s.risk+1));
    write("window-state",s.window ? "Fictief open" : "Verlopen");
    write("stop-state",s.stop ? "ACTIEF – niet heropenbaar" : "Niet geactiveerd");
    write("attempt-state",s.attempts ? s.attempts+" gesimuleerd; laatste "+(s.lastAttempt.missing.length ? "HOLD":"oefenprecondities aanwezig") : "Geen");
    const missing=blockers(s);
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
    return {s,steps,missing};
  }
  function feedback(t) { write("feedback",t); }
  function add(e) {
    if (events.length>=MAX || !Object.hasOwn(TYPES,e)) { feedback("Geen gebeurtenis toegevoegd: maximum of onbekende code.");return; }
    events.push(e); feedback("");render();
  }
  function data() {
    return {schema:"lightup.fictional.scope-tabletop.v1",title:"Fictief scope-/intrekkingsoefenscenario",events:events.slice(),
      authority:{authenticated_client:false,authenticated_operator:false,consent_verified:false,
        dispatch_allowed:false,release_allowed:false,deploy_allowed:false}};
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
    if (text.length > 32768 || !text.length) throw new Error("Bestand buiten de toegestane limiet (32 KiB).");
    const parsed=JSON.parse(text);
    if (!parsed || typeof parsed!=="object" || Array.isArray(parsed)) throw new Error("Geen object.");
    if (!Array.isArray(parsed.events) || parsed.events.length>MAX || parsed.events.some(e=>typeof e!=="string" || !Object.hasOwn(TYPES,e))) throw new Error("Ongeldige fictieve gebeurtenislijst.");
    if (parsed.schema!=="lightup.fictional.scope-tabletop.v1" || parsed.title!=="Fictief scope-/intrekkingsoefenscenario") throw new Error("Onbekende of niet-fictieve inhoud.");
    const normalized={schema:parsed.schema,title:parsed.title,events:parsed.events,
      authority:{authenticated_client:false,authenticated_operator:false,consent_verified:false,dispatch_allowed:false,release_allowed:false,deploy_allowed:false}};
    // Byte-canonical own-file-only import: rejects duplicate JSON keys, unknown fields, altered authority flags and malformed formatting.
    if (JSON.stringify(normalized,null,2)!==text) throw new Error("Niet-canoniek of gewijzigd exportbestand.");
    return parsed.events.slice();
  }
  $("load-preset").addEventListener("click",()=>{
    const key=$("preset").value;
    if (!Object.hasOwn(presets,key)) return;
    if (events.length && !window.confirm("Bestaand oefenscenario vervangen?")) return;
    events=presets[key].slice(); feedback("Fictief voorbeeld geladen.");render();
  });
  $("add-event").addEventListener("click",()=>add($("event-type").value));
  $("undo").addEventListener("click",()=>{events.pop();feedback("Laatste gebeurtenis verwijderd.");render();});
  $("clear").addEventListener("click",()=>{if (events.length && !window.confirm("Alle fictieve stappen wissen?")) return;events=[];feedback("Scenario gewist.");render();});
  $("save-json").addEventListener("click",()=>{bytesDownload("lightup-fictional-scope-tabletop.json",JSON.stringify(data(),null,2),"application/json");feedback("Fictief scenario lokaal aangeboden voor opslag.");});
  $("save-md").addEventListener("click",()=>{bytesDownload("lightup-fictional-scope-tabletop.md",md(),"text/markdown");feedback("PRIVATE, niet-autoriseren­de beslisbrief lokaal aangeboden.");});
  $("import-btn").addEventListener("click",()=>$("import-file").click());
  $("import-file").addEventListener("change",async event=>{
    const file=event.target.files?.[0];event.target.value="";if (!file)return;
    if (file.size>32768){feedback("HOLD: scenario groter dan 32 KiB.");return;}
    try {
      const text=await file.text();
      const next=validateImport(text);
      if (events.length && !window.confirm("Bestaand fictief scenario vervangen door dit bestand?")) return;
      events=next;feedback("Oorspronkelijke fictieve JSON-indeling exact hersteld.");render();
    } catch(_) {feedback("HOLD: alleen exact door deze tool geproduceerde, ongewijzigde fictieve JSON is toegestaan.");}
  });
  $("print").addEventListener("click",()=>window.print());
  render();
})();
