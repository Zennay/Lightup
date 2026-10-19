"use strict";
/* PRIVATELY compare only source-declared Casebook snapshots. Source continuity is NOT authorization. */
(() => {
  const KIND = Object.freeze({
    carry: "ONVERANDERDE BRON — OPGESLAGEN HUMAN-KEUZES OVERGENOMEN",
    unrecorded: "ONVERANDERDE BRON — GEEN EERDER OPGESLAGEN HUMAN-CSV",
    source_hold: "VERZOEK-/GRANTBRON ONVOLLEDIG — VERPLICHTE HUMAN-HERBEOORDELING",
    changed: "BRON GEWIJZIGD — HUMAN-KEUZES HEROPEND",
    appeared: "NIEUW BRONDOSSIER — HUMAN-REVIEW NODIG",
    absent: "ONTBREEKT IN NIEUW BRONMOMENT — GEEN BEWIJS VAN INTREKKING"
  });
  const deny = reason => {throw new Error(reason);};
  const decoder = new TextDecoder("utf-8",{fatal:true});
  const namePattern = /^casebook-(?:0[1-9]|1[0-2])\.json$/;

  function docs(records) {
    const selected = records.filter(r => namePattern.test(r.name));
    if (selected.length === 0 || selected.length > 12) deny("Oorspronkelijke Casebook-bronreeks ontbreekt.");
    return selected.map(r => {
      try {return JSON.parse(decoder.decode(r.bytes));}
      catch {deny("Ongeldige originele Casebook-JSON.");}
    });
  }
  function canonicalSourceCase(doc, id) {
    // Compare one complete case and all recorded engagement-linked original rows,
    // not only the display label. Source data are unsigned and unverified.
    const matchingEngagements = doc.engagements.filter(r => r && r.engagement_id === id);
    const matchingCases = doc.case_overview.filter(r => r && r.engagement_id === id);
    if (matchingEngagements.length !== 1 || matchingCases.length !== 1)
      deny("Oorspronkelijke bron bevat ontbrekende of dubbelzinnige dossieridentiteit.");
    const grants=doc.grants.filter(r => r && r.engagement_id === id)
      .sort((a,b)=>String(a.grant_id).localeCompare(String(b.grant_id),"en"));
    const risks=doc.risk_approvals.filter(r => r && r.engagement_id === id)
      .sort((a,b)=>String(a.approval_id).localeCompare(String(b.approval_id),"en"));
    const ids=new Set(grants.map(g=>g.approved_request_id).filter(x=>x!==null&&x!==undefined));
    const requests=doc.requests.filter(r=>r&&ids.has(r.request_id))
      .sort((a,b)=>String(a.request_id).localeCompare(String(b.request_id),"en"));
    // Original Casebook may legitimately be in HOLD for an unbound/missing
    // approved request (#177). Do not deny all human review; reset any carried
    // choices for this case even when the missing source is unchanged.
    const unbound = grants.some(g => g.approved_request_id === null ||
      g.approved_request_id === undefined || g.approved_request_id === "") ||
      requests.length !== ids.size;
    return {signature:JSON.stringify([matchingEngagements[0], matchingCases[0], grants, risks, requests]),
      unbound};
  }
  function prepare(beforeRecords, afterRecords) {
    const handoff=window.LightUpCasebookHandoff;
    if(!handoff) deny("Oorspronkelijke HUMAN-bronmodule ontbreekt.");
    const old=handoff.admit(beforeRecords), next=handoff.admit(afterRecords);
    const lastBefore=docs(beforeRecords).at(-1), lastAfter=docs(afterRecords).at(-1);
    if(lastBefore.client_id!==lastAfter.client_id)
      deny("Nieuwe bron is van andere zelfverklaarde oorspronkelijke cliënt.");
    const olderCases=new Map(old.cases.map((c,i)=>[c.id,{case:c,row:old.rows[i]}]));
    const newerCases=new Set(next.cases.map(c=>c.id));
    const updates=[], rows=[];
    const counts={carry:0,unrecorded:0,source_hold:0,changed:0,appeared:0,absent:0};
    for(const c of next.cases){
      const prior=olderCases.get(c.id);
      let status;
      if(!prior) status="appeared";
      else {
        const before=canonicalSourceCase(lastBefore,c.id);
        const after=canonicalSourceCase(lastAfter,c.id);
        status=before.unbound || after.unbound ? "source_hold" :
          before.signature===after.signature ?
          (old.hasCSV ? "carry" : "unrecorded") : "changed";
      }
      counts[status]++;
      const human=status==="carry" ? prior.row.slice(3) : ["unreviewed","unassigned","none"];
      rows.push([c.id,c.action,c.attention,...human]);
      updates.push({id:c.id,status,
        priorStage:prior ? prior.row[3] : "niet eerder aanwezig",
        nextStage:human[0],explanation:KIND[status]});
    }
    for(const c of old.cases){
      if(!newerCases.has(c.id)){
        counts.absent++;
        updates.push({id:c.id,status:"absent",priorStage:olderCases.get(c.id).row[3],
          nextStage:"niet in nieuwe bron",explanation:KIND.absent});
      }
    }
    const complete=handoff.serialize(rows);
    if(complete.length>131072) deny("Nieuwe HUMAN-CSV overschrijdt 128 KiB.");
    return {rows,updates,counts,oldHadCSV:old.hasCSV,newCount:next.cases.length,
      beforeCount:old.cases.length};
  }
  function render(preview) {
    const panel=document.getElementById("continuation-preview");
    if(!panel)return;
    panel.replaceChildren();
    if(!preview){panel.textContent="Geen nieuwe bronmomenten geselecteerd.";return;}
    const make=(tag,text)=>{const e=document.createElement(tag);e.textContent=text;return e;};
    const {counts,updates,oldHadCSV}=preview;
    panel.append(make("p",
      "Alleen retrospectieve menselijke bronvergelijking. "+
      (oldHadCSV ? "Bestaande opgeslagen HUMAN-keuzes kunnen onder strikte bronidentiteit doorlopen. " :
        "GEEN opgeslagen eerdere HUMAN-CSV; er kunnen dus geen bewaarde keuzes worden overgenomen. ")+
      "Bronverandering heropent de HUMAN-review; verdwenen dossiers zijn NIET ingetrokken of opgelost."));
    panel.append(make("p",
      "OVERGENOMEN "+counts.carry+" · ZONDER EERDERE CSV "+counts.unrecorded+" · BRON-HOLD "+counts.source_hold+" · HEROPEND "+counts.changed+
      " · NIEUW "+counts.appeared+" · NIET MEER IN NIEUWE BRON "+counts.absent));
    const area=document.createElement("div");area.className="human-scroll";
    const table=document.createElement("table"),tr=document.createElement("tr");
    for(const name of ["PRIVATE dossier-ID","Retrospectieve continuïteit","Eerdere HUMAN-fase","Voorgestelde HUMAN-fase"])
      tr.append(make("th",name));
    const head=document.createElement("thead");head.append(tr);table.append(head);
    const body=document.createElement("tbody");
    for(const item of updates){
      const row=document.createElement("tr");
      for(const val of [item.id,item.explanation,item.priorStage,item.nextStage])row.append(make("td",val));
      body.append(row);
    }
    table.append(body);area.append(table);panel.append(area);
  }
  window.LightUpCasebookContinuity=Object.freeze({prepare,render});
})();