"use strict";
// Product navigation only. No grant, consent, upload, storage or networking.
(() => {
  const $ = id => document.getElementById(id);
  const LINKS = Object.freeze({
    studio:"apps/studio/studio/index.html",
    briefing:"apps/briefing/scope-briefing/standalone.html",
    permission:"apps/permission/scope-permission-brief/standalone.html",
    schedule:"apps/schedule/studio/scope-schedule-board.html",
    handoff:"apps/handoff/scope-handoff-register/standalone.html",
    readiness:"apps/readiness/coordination/scope-readiness-standalone.html",
    withdrawal:"apps/withdrawal/withdrawal-desk/standalone.html",
    vault:"apps/vault/scope-vault/standalone.html",
    assessment:"apps/assessment/assessment-review/standalone.html",
    casework:"apps/casework/casework/index.html"
  });
  const NAMES = Object.freeze({
    studio:"Stel een voorstel op",
    briefing:"Bespreek scope en risico",
    permission:"Bereid beide partijen voor",
    schedule:"Bekijk een voorstelplanning",
    handoff:"Organiseer vervolgacties",
    readiness:"Inventariseer ontbrekende informatie",
    withdrawal:"Bespreek urgent STOP-verzoek",
    vault:"Bewaar een lokale kopie",
    assessment:"Beoordeel synthetische labresultaten",
    casework:"Werk een lokaal herstelplan uit"
  });
  const ROUTES = Object.freeze({
    proposal:{
      title:"Nieuw scopeconcept",
      help:"Begin met de originele DRAFT_ONLY Studio v1-export. Open de volgende offline app zelf en gebruik alleen de brongebonden bestandsimport/export. Er is geen gedeelde accountstatus.",
      steps:["studio","briefing","permission","schedule","handoff","readiness","vault"]
    },
    revision:{
      title:"Gewijzigde scope",
      help:"Een gewijzigde assetlijst, risico of periode kan eerdere menselijke voorbereiding ongeldig maken. Vergelijk beide concepten en vraag onafhankelijke herbeoordeling.",
      steps:["studio","briefing","schedule","handoff","permission","readiness"]
    },
    stop:{
      title:"Urgente STOP of herroeping",
      help:"Een lokale STOP-notitie kan geen toestemming intrekken of lopende taak stoppen. Gebruik eerst het echte geauthenticeerde noodkanaal; deze volgorde helpt uitsluitend achteraf bij menselijke dossieroverdracht.",
      steps:["withdrawal","handoff","readiness","vault"]
    },
    lab:{
      title:"Bestaande labvergelijkingen beoordelen",
      help:"Deze werkstroom leest alleen bestaande aangeleverde offline synthetic/labresultaten. Ze voert geen assessment uit en is niet gekoppeld aan een geldig client-grantbesluit.",
      steps:["assessment","handoff"]
    },
    repair:{
      title:"Bestaande bevindingen naar herstelacties",
      help:"Begin uitsluitend met een eerder via de echte LightUp-identiteits- en tenantcontroles geëxporteerd findings.csv. De lokale browser kan de herkomst niet verifiëren. Het actieplan is een kopie en stelt geen echte herstelstatus of retest vast.",
      steps:["casework"]
    }
  });
  function selectRoute(name){
    const route=ROUTES[name];
    if(!route) return;
    for(const btn of document.querySelectorAll(".journey")){
      const active=btn.dataset.route===name;
      btn.classList.toggle("active",active);
      btn.setAttribute("aria-pressed",String(active));
    }
    $("route-title").textContent=route.title;
    $("route-help").textContent=route.help;
    const list=$("route-steps");
    list.replaceChildren();
    for(const key of route.steps){
      const li=document.createElement("li");
      const a=document.createElement("a");
      a.href=LINKS[key];a.target="_blank";a.rel="noopener";
      a.textContent=NAMES[key];
      li.append(a);list.append(li);
    }
    $("route-warning").textContent=name==="stop"
      ?"BELANGRIJK: Gebruik eerst het echte geauthenticeerde STOP/revocatiekanaal. De offline apps voeren nooit een intrekking uit; na de overdracht blijft de autorisatiestatus onbekend."
      :"BELANGRIJK: Deze route eindigt altijd met REVIEW_ONLY / DRAFT / HOLD. Authentieke cliënt- en operatorbesluiten, herroeping op gebruiksmoment, privacy/security-review, bestaande CI en HUMAN GO blijven apart nodig.";
  }
  for(const btn of document.querySelectorAll(".journey"))
    btn.addEventListener("click",()=>selectRoute(btn.dataset.route));
  $("search").addEventListener("input",event=>{
    const term=event.target.value.toLocaleLowerCase("nl").trim();
    let shown=0;
    for(const card of document.querySelectorAll(".card")){
      const hay=(card.dataset.words+" "+card.querySelector("h3").textContent).toLocaleLowerCase("nl");
      card.hidden=!!term&&!hay.includes(term);
      shown+=Number(!card.hidden);
    }
    $("no-results").hidden=shown!==0;
  });
  selectRoute("proposal");
})();