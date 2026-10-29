/* Offline original Casebook v1 -> bound current HUMAN desk. No grants, no network. */
(() => {
  "use strict";
  const FIELDS = ["original_engagement_id","original_next_action","original_attention",
    "human_stage","human_followup_route","human_blocker"];
  const STAGES = ["unreviewed","investigating","awaiting-owner","documented"];
  const ROUTES = ["unassigned","original-scope-owner","client-clarification",
    "independent-security-review","operator-followup"];
  const BLOCKERS = ["none","missing-source","missing-owner","needs-independent-consent",
    "requires-revocation-review","unresolved-tenant-lineage"];
  const utf8 = new TextDecoder("utf-8",{fatal:true});
  const MAX_HUMAN = 131072, MAX_ROWS = 200;
  let unsavedHumanEdits = false;
  const deny = message => {throw new Error(message);};
  function sourceDocs(records) {
    const source = records.filter(r => /^casebook-(?:0[1-9]|1[0-2])\.json$/.test(r.name));
    if (!source.length || source.length > 12) deny("Geen volledige Casebook-bronvolgorde.");
    return source.map(r => JSON.parse(utf8.decode(r.bytes)));
  }
  function sourceCurrent(docs) {
    // Ported from pinned original scope-casebook-history/history.py case_queue;
    // source-declared rows, ordering and counts are not security/authority proof.
    const history = new Map();
    docs.forEach((doc, index) => {
      if (!Array.isArray(doc.case_overview) || doc.case_overview.length > MAX_ROWS)
        deny("Oorspronkelijke bronlijst te groot.");
      const present = new Set();
      for (const c of doc.case_overview) {
        if (!c || typeof c !== "object" || typeof c.engagement_id !== "string" ||
            typeof c.attention !== "string" || typeof c.next_review_action !== "string" ||
            !Number.isInteger(c.grant_count) || c.grant_count < 0 || c.grant_count > MAX_ROWS ||
            present.has(c.engagement_id))
          deny("Onvolledige of dubbele oorspronkelijke Casebook-dossiers.");
        present.add(c.engagement_id);
        const all = history.get(c.engagement_id) || [];
        all.push({ordinal:index+1, value:c}); history.set(c.engagement_id,all);
      }
    });
    if (history.size > 12 * MAX_ROWS) deny("Teveel verschillende oorspronkelijke dossiers.");
    const last = docs.length;
    const output = [];
    for (const [id, snapshots] of history.entries()) {
      const current = snapshots.at(-1);
      if (current.ordinal !== last) continue;
      const c = current.value;
      const transitions = snapshots.slice(1).reduce((acc, entry, j) =>
        acc + Number(entry.value.attention !== snapshots[j].value.attention ||
          entry.value.next_review_action !== snapshots[j].value.next_review_action), 0);
      const priority = c.attention.startsWith("HOLD_") ? 0 :
        c.attention === "RISK_DECISION_PENDING_SOURCE_REVIEW" ? 1 :
        ["EXPIRED_GRANT_SOURCE_REVIEW","FUTURE_GRANT_SOURCE_REVIEW"].includes(c.attention) ? 2 : 3;
      const prior=snapshots.length>1 ? snapshots.at(-2).value : null;
      const observation=prior===null ? (last===1 ? "EERSTE BRONMOMENT" : "NIEUW IN BRONREEKS") :
        prior.attention !== c.attention || prior.next_review_action !== c.next_review_action ?
        "BRONACTIE/AANDACHT GEWIJZIGD" : prior.status !== c.status ?
        "BRONSTATUS GEWIJZIGD" : "GEEN LAATSTE BRONWIJZIGING";
      output.push({id,action:c.next_review_action,attention:c.attention,
        status:c.status,transitions,grantCount:c.grant_count,priority,observation});
    }
    output.sort((a,b) => a.priority - b.priority || b.transitions - a.transitions ||
      b.grantCount - a.grantCount || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return output;
  }
  function parseCSV(text) {
    if (text.length > MAX_HUMAN) deny("PRIVATE HUMAN CSV groter dan 128 KiB.");
    if (text.charCodeAt(0) === 65279) text = text.slice(1);
    const rows = []; let row = [], part = "", state = 0;
    for (let i=0; i<text.length; i++) {
      const ch = text[i];
      if (state === 1) {
        if (ch === '"') {
          if (text[i+1] === '"') {part += '"'; i++;}
          else state = 2;
        } else {part += ch;}
      } else if (ch === '"' && state === 0 && part === "") {state = 1;}
      else if (ch === "," && state !== 1) {row.push(part);part="";state=0;}
      else if (ch === "\r" || ch === "\n") {
        if (state === 2 || state === 0) {
          if (ch === "\r" && text[i+1] === "\n") i++;
          row.push(part); rows.push(row); row=[];part="";state=0;
        } else deny("CSV sluit een citaat niet correct.");
      } else {
        if (state === 2 || ch === '"') deny("HUMAN CSV heeft ambigue CSV-framing.");
        part += ch;
      }
      if (rows.length > MAX_ROWS + 1) deny("Teveel HUMAN-dossierregels.");
    }
    if (state === 1) deny("Niet-gesloten HUMAN CSV citaat.");
    if (row.length || part) {row.push(part);rows.push(row);}
    return rows;
  }
  function checkCSV(records, cases) {
    const found = records.filter(r => r.name === "workroom-current-template.csv");
    if (found.length > 1) deny("Dubbele HUMAN-CSV.");
    if (!found.length) return cases.map(c => [c.id,c.action,c.attention,
      "unreviewed","unassigned","none"]);
    const csv = parseCSV(utf8.decode(found[0].bytes));
    if (csv.length !== cases.length+1 || csv[0].length !== FIELDS.length ||
      !FIELDS.every((x,i)=>csv[0][i] === x)) deny("PRIVATE HUMAN-CSV kopregels/dossierhoeveelheid wijken af.");
    const rows=[];
    for(let i=0;i<cases.length;i++){
      const r=csv[i+1],c=cases[i];
      if (!r || r.length !== FIELDS.length ||
        r[0] !== c.id || r[1] !== c.action || r[2] !== c.attention ||
        !STAGES.includes(r[3]) || !ROUTES.includes(r[4]) || !BLOCKERS.includes(r[5]))
        deny("PRIVATE HUMAN-CSV verwijst naar andere, verouderde of gewijzigde bronregels.");
      rows.push(r);
    }
    return rows;
  }
  function admit(records) {
    const cases=sourceCurrent(sourceDocs(records));
    const rows=checkCSV(records,cases);
    return {cases,rows,hasCSV:records.some(r=>r.name==="workroom-current-template.csv")};
  }
  const make = (tag,text) => {const e=document.createElement(tag);e.textContent=text;return e;};
  function select(options,selected,kind) {
    const el=document.createElement("select");el.dataset.kind=kind;
    for(const option of options) {
      const node=document.createElement("option");node.value=option;node.textContent=option;
      if(option===selected)node.selected=true;
      el.append(node);
    }
    return el;
  }
  function render(records) {
    const root=document.getElementById("human-board");
    if(!root) return;
    root.replaceChildren();
    unsavedHumanEdits = false;
    if(!records) {root.append(make("p","Geen PRIVATE Casebook-bronset geopend."));return;}
    const {cases,rows,hasCSV}=admit(records);
    const notice=make("p",hasCSV ?
      "PRIVATE huidige HUMAN-CSV volledig aan de laatste geselecteerde bronset gekoppeld; wijzigingen alleen na expliciet Opslaan." :
      "Nog geen huidige HUMAN-CSV in de werkset. Je kunt hier een aan de laatste bronset gekoppelde concept-CSV maken; dit is geen door de oorspronkelijke bron geauthenticeerd document.");
    root.append(notice);
    if(!cases.length){root.append(make("p","Geen huidige dossiers in het laatst geselecteerde Casebook-bronmoment."));}
    const counters=make("p","");
    counters.className="metrics";counters.setAttribute("aria-live","polite");root.append(counters);
    const controls=document.createElement("div");controls.className="human-filters";
    const search=document.createElement("input");search.type="search";search.placeholder="Zoek PRIVATE dossier-ID of oorspronkelijke bronactie";
    search.setAttribute("aria-label","Zoek originele bronrecords");
    const filter=select(["alle-bronrecords","bron-HOLD","bron-veranderd","HUMAN-onbehandeld"],
      "alle-bronrecords","filter");
    filter.setAttribute("aria-label","Filter bronwijziging en HUMAN-status");
    controls.append(search,filter);root.append(controls);
    const filtered=make("p","");filtered.className="muted";root.append(filtered);
    const scroll=document.createElement("div");scroll.className="human-scroll";
    const table=document.createElement("table"),thead=document.createElement("thead"),tr=document.createElement("tr");
    for(const label of ["Origineel dossier (PRIVATE)","Bronactie (niet actueel geverifieerd)","Bronlabel","Laatste bronobservatie (niet geverifieerd)","HUMAN-fase","HUMAN-route","HUMAN-blokkade"]){
      tr.append(make("th",label));
    }thead.append(tr);table.append(thead);
    const tbody=document.createElement("tbody"),inputs=[];
    const visible=[];
    rows.forEach((row,index) => {
      const r=document.createElement("tr");
      for(let i=0;i<3;i++){r.append(make("td",row[i]));}
      r.append(make("td",cases[index].observation));
      visible.push(r);
      const controls=[select(STAGES,row[3],"stage"),select(ROUTES,row[4],"route"),select(BLOCKERS,row[5],"blocker")];
      controls.forEach(el=>{const td=document.createElement("td");td.append(el);r.append(td);});
      inputs.push(controls);tbody.append(r);
    });
    table.append(tbody);scroll.append(table);root.append(scroll);
    const actions=document.createElement("div");actions.className="section-heading";
    const save=document.createElement("button");save.type="button";save.id="save-human";
    save.textContent="Sla HUMAN-opvolging lokaal in de PRIVATE werkset op";
    actions.append(save);root.append(actions);
    const status=make("p","Geen wijziging in de oorspronkelijke bronbestanden.");status.className="muted";root.append(status);
    const update=()=>{
      const stages=Object.fromEntries(STAGES.map(s=>[s,0]));
      const blockers=Object.fromEntries(BLOCKERS.map(s=>[s,0]));
      for(const values of inputs){stages[values[0].value]++;blockers[values[2].value]++;}
      counters.textContent=Object.entries(stages).map(([k,n])=>k+": "+n).join(" · ") +
        " · consent/lineage-review: " + ((blockers["needs-independent-consent"]||0)+(blockers["unresolved-tenant-lineage"]||0));
      const term=search.value.trim().toLocaleLowerCase("nl-NL");
      let displayed=0;
      for (let i=0;i<rows.length;i++) {
        const kind=filter.value,c=cases[i],r=rows[i],stage=inputs[i][0].value;
        const hit=(!term || r.slice(0,3).some(v=>v.toLocaleLowerCase("nl-NL").includes(term))) &&
          (kind==="alle-bronrecords" || (kind==="bron-HOLD" && c.attention.startsWith("HOLD_")) ||
          (kind==="bron-veranderd" && c.observation!=="GEEN LAATSTE BRONWIJZIGING") ||
          (kind==="HUMAN-onbehandeld" && stage==="unreviewed"));
        visible[i].hidden=!hit;
        if(hit)displayed++;
      }
      filtered.textContent=displayed+" / "+rows.length+
        " actuele PRIVATE dossierregels zichtbaar; observaties zijn uitsluitend over de geselecteerde bronmomenten, niet over echte actuele toestemming.";
    };
    for(const values of inputs) for(const el of values) el.addEventListener("change",()=>{
      unsavedHumanEdits = true;
      update();status.textContent="Niet-opgeslagen HUMAN-wijzigingen. Deze wijzigen geen bron of grant.";
    });
    search.addEventListener("input",update);filter.addEventListener("change",update);
    update();
    save.addEventListener("click",async()=>{
      save.disabled=true;
      try {
        const now=rows.map((row,i)=>[...row.slice(0,3),...inputs[i].map(el=>el.value)]);
        if (!window.confirm("Maak/vervang uitsluitend de lokale HUMAN-CSV in de werkset? Originele Casebook JSON blijft onveranderd; pas na opnieuw versleutelen wordt dit verder gedeeld."))
          return;
        if (!window.LightUpTransfer?.setHumanCSV) deny("PRIVATE overdracht niet beschikbaar.");
        await window.LightUpTransfer.setHumanCSV(now);
        status.textContent="Nieuwe brongebonden PRIVATE HUMAN-CSV in lokale werkset opgeslagen. Versleutel opnieuw vóór overdracht.";
      }catch(e){status.textContent="HOLD: "+(e instanceof Error?e.message:"Ongeldige HUMAN-CSV");}
      finally{save.disabled=false;}
    });
  }
  function serialize(rows) {
    function cell(s) {
      if(typeof s !== "string" || /[\r\n]/.test(s)) deny("CSV-veld bevat nieuweregel.");
      if(/^[=+\-@\t]/.test(s)) deny("Onveilige CSV-celstart.");
      return /[",]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s;
    }
    return [...[FIELDS],...rows].map(row=>row.map(cell).join(",")).join("\r\n")+"\r\n";
  }
  window.LightUpCasebookHandoff=Object.freeze({admit,render,serialize,hasUnsavedEdits:()=>unsavedHumanEdits});
})();
