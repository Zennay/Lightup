/* Local-only, non-authorizing Studio v1 briefing; never evaluate target scope or grant rights. */
"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const MAX_BYTES = 65536;
  const LIMIT = 128;
  const DENIAL_FLAGS = ["authorization","client_consent","operator_consent","grant","execution","revocation_checked"];
  const REPORT_DENIALS = ["authenticated_client","authenticated_operator","consent_verified","grant_issued","authorized","scan_allowed","dispatch_allowed","deploy_allowed","release_allowed"];
  const ACTIVITIES = {
    passive_analysis: "Passieve analyse",
    configuration_review: "Configuratiebespreking",
    private_lab_network_checks: "Private-lab netwerkvoorstel"
  };
  let current = null;
  let staged = null;
  let detailsVisible = false;

  // Unlike JSON.parse(), this limited parser refuses duplicate object keys at every level.
  function strictJson(src) {
    let i = 0;
    const spaces = () => { while (i < src.length && /\s/.test(src[i])) i++; };
    function quoted() {
      if (src[i] !== '"') throw Error("Ongeldige JSON-tekst.");
      const start = i++;
      while (i < src.length) {
        if (src[i] === '"') { i++; return JSON.parse(src.slice(start, i)); }
        if (src.charCodeAt(i) < 32) throw Error("Controlecode in JSON-tekst.");
        if (src[i] === "\\") i += 2;
        else i++;
      }
      throw Error("Onvoltooide JSON-tekst.");
    }
    function parse(depth) {
      if (depth > 16) throw Error("Te diepe JSON-structuur.");
      spaces();
      const ch = src[i];
      if (ch === '"') return quoted();
      if (ch === "{") {
        i++; spaces();
        const out = Object.create(null);
        if (src[i] === "}") { i++; return out; }
        let count = 0;
        while (i < src.length) {
          spaces();
          const key = quoted();
          if (Object.prototype.hasOwnProperty.call(out, key)) throw Error("Dubbele JSON-sleutel afgewezen.");
          if (++count > 128) throw Error("Te veel JSON-velden.");
          spaces();
          if (src[i++] !== ":") throw Error("Ongeldige JSON-sleutelscheiding.");
          out[key] = parse(depth + 1);
          spaces();
          const next = src[i++];
          if (next === "}") return out;
          if (next !== ",") throw Error("Ongeldige JSON-objectscheiding.");
        }
      }
      if (ch === "[") {
        i++; spaces();
        const out = [];
        if (src[i] === "]") { i++; return out; }
        while (i < src.length) {
          if (out.length >= LIMIT) throw Error("Te veel lijstitems.");
          out.push(parse(depth + 1));
          spaces();
          const next = src[i++];
          if (next === "]") return out;
          if (next !== ",") throw Error("Ongeldige JSON-lijstscheiding.");
        }
      }
      const rest = src.slice(i);
      const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(rest);
      if (!token) throw Error("Ongeldige JSON-waarde.");
      i += token[0].length;
      return JSON.parse(token[0]);
    }
    const parsed = parse(0);
    spaces();
    if (i !== src.length) throw Error("Extra JSON-bytes na het document.");
    return parsed;
  }
  const obj = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o,k);
  function proposal(raw) {
    if (!obj(raw) || raw.kind !== "lightup.scope_proposal_draft" ||
        raw.schema_version !== 1 || raw.state !== "DRAFT_ONLY")
      throw Error("Alleen oorspronkelijke Studio v1 DRAFT_ONLY-documenten zijn toegestaan.");
    if (raw.requested_mode !== "analysis_only" && raw.requested_mode !== "authorized_assessment")
      throw Error("Onbekende voorgestelde modus.");
    if (!Number.isInteger(raw.requested_risk) || raw.requested_risk < 1 || raw.requested_risk > 4)
      throw Error("Ongeldig risiconiveau (alleen 1–4).");
    const lists = ["requested_assets","excluded_assets"];
    for (const key of lists) {
      const a = raw[key];
      if (!Array.isArray(a) || a.length > LIMIT ||
          a.some(x => typeof x !== "string" || x.length > 512 || !x.trim() || /[\u0000-\u001f\u007f]/.test(x)))
        throw Error("Onveilige of onvolledige assetlijst.");
    }
    if (!obj(raw.proposed_activities) ||
        Object.keys(raw.proposed_activities).length !== 3 ||
        Object.keys(ACTIVITIES).some(k => !own(raw.proposed_activities,k) ||
          typeof raw.proposed_activities[k] !== "boolean"))
      throw Error("Activiteitenobject voldoet niet aan Studio v1.");
    for (const key of DENIAL_FLAGS) if (!own(raw,key) || raw[key] !== false)
      throw Error("Autoriteitsveld ontbreekt of is niet letterlijk false: HOLD.");
    if (!own(raw,"proposed_window_local") ||
        !(raw.proposed_window_local === null || obj(raw.proposed_window_local)))
      throw Error("Lokaal tijdvenster heeft een onverwacht type.");
    return raw;
  }
  function comparisons(p) {
    const norm = x => x.trim().toLowerCase();
    const a = p.requested_assets.map(norm);
    const e = p.excluded_assets.map(norm);
    const dup = x => new Set(x).size !== x.length;
    const overlap = a.filter(x => e.includes(x)).length;
    return {
      has_overlap: overlap > 0,
      overlap_count: overlap,
      duplicates_included: dup(a),
      duplicates_excluded: dup(e),
      missing_window: p.proposed_window_local === null ||
        Object.keys(p.proposed_window_local).length === 0,
      network_activity: p.proposed_activities.private_lab_network_checks
    };
  }
  const sha256 = async bytes => {
    if (!globalThis.crypto || !crypto.subtle) throw Error("Browser ondersteunt geen lokale SHA-256 in deze context. Gebruik een moderne browser met veilige lokale bestandscontext.");
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,"0")).join("");
  };
  function setStatus(message,good=false) {
    $("status").textContent=message;
    $("status").className="banner " + (good?"ok":"danger");
  }
  function showList(element,items) {
    element.replaceChildren();
    for (const name of items) {
      const li = document.createElement("li");
      li.textContent=name;
      element.append(li);
    }
  }
  function hideDetails() {
    detailsVisible=false;
    $("raw").hidden=true;
    $("reveal").textContent="Toon tijdelijk exacte vermeldingen";
    $("reveal").setAttribute("aria-pressed","false");
  }
  function questionList(p,facts) {
    const questions = [
      "Is de identiteit van de cliënt onafhankelijk geverifieerd?",
      "Is het eigendom of het recht op álle genoemde assets separaat bewezen?",
      "Zijn alle uitsluitingen daadwerkelijk beoordeeld met de cliënt?",
      "Is het risiconiveau met de operator besproken?",
      "Is een echt noodstop- en herroepingskanaal afgesproken?",
      "Zijn privacy, bewijsverwerking en bewaartermijnen beoordeeld?"
    ];
    if (p.requested_mode === "authorized_assessment")
      questions.push("Is een echte geauthenticeerde aanvraag apart ingediend, gevolgd door een afzonderlijke operatorbeslissing?");
    if (facts.missing_window)
      questions.push("Moet een concreet tijdvenster met juiste tijdzone nog menselijk worden vastgesteld?");
    if (facts.has_overlap) questions.push("Moet de letterlijke overlap van opgenomen en uitgesloten vermeldingen worden opgelost?");
    if (facts.network_activity) questions.push("Zijn de privéscope van het lab en grens van elk voorgesteld netwerkcontact expliciet besproken?");
    $("questions").replaceChildren();
    questions.forEach((txt,n)=>{
      const label=document.createElement("label");label.className="question";
      const cb=document.createElement("input");cb.type="checkbox";cb.id="talk-"+n;
      const span=document.createElement("span");span.textContent=txt;label.append(cb,span);$("questions").append(label);
    });
  }
  function warn(code,text,info=false) {
    const el=document.createElement("div");el.className="warning"+(info?" info":"");
    el.textContent=text;el.dataset.code=code;$("warnings").append(el);
  }
  function refresh() {
    if (!current) return;
    const {data:p,hash,facts}=current;
    $("workspace").hidden=false;
    $("count-assets").textContent=String(p.requested_assets.length);
    $("count-excluded").textContent=String(p.excluded_assets.length);
    $("risk").textContent=String(p.requested_risk)+" / 4";
    $("risk-desc").textContent=p.requested_risk===4?"Hoog: expliciete onafhankelijke beoordeling vereist.":"Alle risico's vragen aparte beoordeling.";
    $("mode").textContent=p.requested_mode==="analysis_only"?"Analyse":"Assessment";
    $("fingerprint").textContent=hash;
    $("window").textContent=facts.missing_window?"Niet volledig opgegeven; menselijke verduidelijking nodig.":"Lokaal tijdvoorstel aanwezig; UTC/offset is hier NIET geverifieerd.";
    $("activities").replaceChildren();
    for (const [key,title] of Object.entries(ACTIVITIES)) {
      const el=document.createElement("div");const planned=p.proposed_activities[key];
      el.className="activity"+(planned?"":" no");
      const s=document.createElement("strong");s.textContent=title;
      const span=document.createElement("span");span.textContent=planned?"Voorgesteld — niet toegestaan":"Niet voorgesteld";
      el.append(s,span);$("activities").append(el);
    }
    hideDetails();
    $("coverage").textContent="Exacte assets afgeschermd. Letterlijk gelijke opgenomen/uitgesloten vermeldingen: "+facts.overlap_count+". Dit is geen CIDR-, DNS- of eigendomscontrole.";
    showList($("assets"),p.requested_assets);
    showList($("excluded"),p.excluded_assets);
    $("warnings").replaceChildren();
    if (facts.has_overlap) warn("LITERAL_OVERLAP","Let op: één of meer vermeldingen staan zowel bij opgenomen als uitgesloten assets. Los dit op vóór enige autorisatie.");
    if (facts.duplicates_included || facts.duplicates_excluded)
      warn("DUPLICATE_LABELS","Herhaalde letterlijke assetvermeldingen vragen om controle; tellingen zijn geen aantallen unieke targets.");
    if (facts.missing_window) warn("WINDOW_UNRESOLVED","Geen bruikbaar lokaal planningstijdvenster aangetroffen. Er is geen goedgekeurd uitvoeringsvenster.");
    if (facts.network_activity) warn("LAB_CONTACT","Er wordt een private-lab netwerkactiviteit voorgesteld. Dit is geen bewijs dat hosts tot een veilig lab behoren.");
    if (p.requested_risk === 4) warn("RISK_FOUR","Risico 4 vereist uitdrukkelijke onafhankelijke risicobeoordeling en menselijke goedkeuring.");
    if (p.requested_mode === "authorized_assessment")
      warn("AUTH_REQUESTED","Het woord 'authorized' in de voorgestelde modus verleent geen toestemming of grant.");
    warn("UNVERIFIED_SOURCE","Bronidentiteit, toestemming, bezit, handtekening en actuele herroeping zijn allemaal ONGEVERIFIEERD.",true);
    questionList(p,facts);
    setStatus("Lokaal DRAFT-concept gelezen. Alle autorisatie-, consent- en uitvoeringsvelden zijn letterlijk false. Geen rechten verleend.",true);
  }
  function revisionDelta(oldDraft, newDraft) {
    const literals = values => new Set(values.map(x => x.trim().toLowerCase()));
    const before = literals(oldDraft.requested_assets);
    const after = literals(newDraft.requested_assets);
    const previousExclusions = literals(oldDraft.excluded_assets);
    const nextExclusions = literals(newDraft.excluded_assets);
    const countMissing = (left, right) => [...left].filter(x => !right.has(x)).length;
    return [
      ["Opgenomen erbij (letterlijk)", countMissing(after,before), countMissing(after,before)>0],
      ["Opgenomen verwijderd (letterlijk)", countMissing(before,after), false],
      ["Uitsluitingen toegevoegd", countMissing(nextExclusions,previousExclusions), false],
      ["Uitsluitingen verwijderd", countMissing(previousExclusions,nextExclusions), countMissing(previousExclusions,nextExclusions)>0],
      ["Risico", String(oldDraft.requested_risk) + " → " + String(newDraft.requested_risk), newDraft.requested_risk>oldDraft.requested_risk],
      ["Modus veranderd", oldDraft.requested_mode === newDraft.requested_mode ? "nee" : "ja", oldDraft.requested_mode !== newDraft.requested_mode],
      ["Activiteiten veranderd", Object.keys(ACTIVITIES).some(k => oldDraft.proposed_activities[k]!==newDraft.proposed_activities[k])?"ja":"nee",
       Object.keys(ACTIVITIES).some(k => !oldDraft.proposed_activities[k] && newDraft.proposed_activities[k])],
      ["Tijdvoorstel veranderd (letterlijk)", JSON.stringify(oldDraft.proposed_window_local)!==JSON.stringify(newDraft.proposed_window_local)?"ja":"nee",
       JSON.stringify(oldDraft.proposed_window_local)!==JSON.stringify(newDraft.proposed_window_local)]
    ];
  }
  function renderRevision() {
    $("revision-summary").replaceChildren();
    if (!current || !staged) { $("revision-panel").hidden=true; return; }
    $("revision-panel").hidden=false;
    const from=document.createElement("div");
    from.className="revision-delta";
    const old=document.createElement("strong");old.textContent="Huidige bron-SHA";
    const oldDigest=document.createElement("span");oldDigest.textContent=current.hash.slice(0,16)+"…";
    from.append(old,oldDigest);$("revision-summary").append(from);
    const to=document.createElement("div");to.className="revision-delta";
    const next=document.createElement("strong");next.textContent="Voorgestelde bron-SHA";
    const nextDigest=document.createElement("span");nextDigest.textContent=staged.hash.slice(0,16)+"…";
    to.append(next,nextDigest);$("revision-summary").append(to);
    for (const [title,value,attention] of revisionDelta(current.data,staged.data)) {
      const item=document.createElement("div");
      item.className="revision-delta"+(attention?" attention":"");
      const label=document.createElement("strong");label.textContent=title;
      const info=document.createElement("span");info.textContent=String(value);
      item.append(label,info);$("revision-summary").append(item);
    }
  }
  async function load(file) {
    if (!file || file.size > MAX_BYTES || file.size === 0) throw Error("Ongeldig bestand of groter dan 64 KiB.");
    const bytes=await file.arrayBuffer();
    const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
    const candidate=proposal(strictJson(raw));
    const hash=await sha256(bytes);
    const facts=comparisons(candidate);
    const incoming={data:candidate,hash,facts};
    if (current && current.hash === hash) {
      staged=null;
      renderRevision();
      setStatus("Identieke bronbytes: bestaand gesprek blijft ongewijzigd. Geen toestemming verleend.",true);
      return;
    }
    if (current) {
      staged=incoming;
      renderRevision();
      setStatus("Nieuwe bron ter menselijke beoordeling klaargezet; huidige briefing is nog steeds actief.",true);
      return;
    }
    current=incoming;
    refresh();
  }
  function report() {
    if (!current) throw Error("Geen concept.");
    const {data:p,hash,facts}=current;
    return {
      kind:"lightup.scope_briefing_handoff",version:1,state:"REVIEW_ONLY_HOLD",
      source_sha256:hash,source_kind:"lightup.scope_proposal_draft",source_schema_version:1,
      included_count:p.requested_assets.length,excluded_count:p.excluded_assets.length,
      proposed_risk:p.requested_risk,proposed_mode:p.requested_mode,
      proposed_activities:{...p.proposed_activities},
      window_declared:!facts.missing_window,
      literal_overlap_count:facts.overlap_count,
      duplicate_literal_labels:facts.duplicates_included||facts.duplicates_excluded,
      attention_codes:[...$("warnings").children].map(x=>x.dataset.code),
      human_conversation_only:true,
      ...Object.fromEntries(REPORT_DENIALS.map(k=>[k,false]))
    };
  }
  function download(name,content) {
    const url=URL.createObjectURL(new Blob([content],{type:"application/json;charset=utf-8"}));
    const anchor=document.createElement("a");anchor.href=url;anchor.download=name;
    document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  $("file").addEventListener("change",async e=>{
    try { const file=e.target.files?.[0]; if(file) await load(file); }
    catch(err){ staged=null;renderRevision();setStatus("HOLD — bestand afgewezen: "+String(err?.message||"onbekende fout"));}
    finally {e.target.value="";}
  });
  $("revision-discard").addEventListener("click",()=>{
    staged=null;renderRevision();
    setStatus("Voorgestelde wijziging verworpen. Het huidige gesprek is behouden.",true);
  });
  $("revision-apply").addEventListener("click",()=>{
    if(!staged || !current)return;
    if(!window.confirm("Vervang het huidige bespreekdocument en wis alle huidige vraagvinkjes? Dit verleent nooit toestemming."))return;
    current=staged;staged=null;renderRevision();refresh();
    setStatus("Nieuwe conceptversie lokaal geopend. Eerdere bespreekstatus is gewist. Geen rechten verleend.",true);
  });
  $("reveal").addEventListener("click",()=>{
    if (!current) return;
    detailsVisible=!detailsVisible;
    $("raw").hidden=!detailsVisible;
    $("reveal").setAttribute("aria-pressed",String(detailsVisible));
    $("reveal").textContent=detailsVisible?"Scherm exacte vermeldingen af":"Toon tijdelijk exacte vermeldingen";
  });
  $("export").addEventListener("click",()=>{
    if(!current)return;
    download("lightup-scope-review-"+current.hash.slice(0,12)+".json",JSON.stringify(report(),null,2)+"\n");
  });
  $("print").addEventListener("click",()=>{
    if(!current)return;
    hideDetails();window.print();
  });
  $("clear").addEventListener("click",()=>{
    current=null;staged=null;renderRevision();$("workspace").hidden=true;hideDetails();
    $("assets").replaceChildren();$("excluded").replaceChildren();$("questions").replaceChildren();
    $("fingerprint").textContent="—";
    setStatus("Concept verwijderd uit deze tijdelijke pagina. Geen rechten verleend.");
  });
  document.addEventListener("visibilitychange",()=>{if(document.hidden)hideDetails();});
  window.addEventListener("beforeprint",hideDetails);
})();