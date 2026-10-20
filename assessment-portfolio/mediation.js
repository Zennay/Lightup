"use strict";
(() => {
  const model=JSON.parse(document.getElementById("lightupPrivateHumanSource").textContent);
  const get=id=>document.getElementById(id);
  const make=(tag,parent,value)=>{
    const element=document.createElement(tag);
    if(value!==undefined)element.textContent=String(value);
    if(parent)parent.appendChild(element);
    return element;
  };
  const selections=new Map();
  const key=(s,row)=>s.slot+":"+row.slot;
  const contested=(row)=>row.candidates.length>1;
  const compare=(a,b)=>a.agenda-b.agenda || a.slot-b.slot;
  const all=[];
  for(const source of model.sources) {
    for(const row of source.rows) {
      if(!row.candidates.length)continue;
      all.push({...row,agenda:source.slot});
      if(row.candidates.length===1)selections.set(key(source,row),"c0");
    }
  }
  all.sort(compare);
  get("agendaCount").textContent=model.source_count;
  get("contributorCount").textContent=model.contributor_count;
  get("conflictCount").textContent=model.conflict_slots;
  get("originalStatus").textContent=model.claimed_status;

  function valueText(item) {
    return item.stage+" / "+item.next_role+" / "+(item.review_date || "no date");
  }
  function status() {
    let unresolved=0,changed=0,retained=0,kept=0;
    for(const row of all){
      const selected=selections.get(row.agenda+":"+row.slot);
      if(contested(row)&&!selected){unresolved++;continue;}
      if(selected==="original"){kept++;continue;}
      if(selected&&selected.startsWith("c")) {
        retained++;
        const candidate=row.candidates[Number(selected.slice(1))];
        if(candidate && ["stage","next_role","review_date"].some(
          field=>candidate[field]!==row["prior_"+field]))changed++;
      }
    }
    get("unresolvedCount").textContent=unresolved;
    get("retainedCount").textContent=retained;
    get("keptCount").textContent=kept;
    get("diffCount").textContent=changed;
    get("export").disabled=unresolved>0;
    return unresolved;
  }
  function showMessage(message) {get("feedback").textContent=message;}
  function render() {
    const selection=get("filter").value, body=get("rows");
    body.replaceChildren();
    let visible=0;
    for(const row of all){
      const selected=selections.get(row.agenda+":"+row.slot);
      const conflict=contested(row);
      if(selection==="conflicts"&&!conflict)continue;
      if(selection==="resolved"&&(!conflict||!selected))continue;
      if(selection==="single"&&conflict)continue;
      visible++;
      const tr=make("tr",body);if(conflict)tr.classList.add("contested");
      const location=make("td",tr);
      make("strong",location,"Agenda "+row.agenda+" / slot "+row.slot);
      make("p",location,conflict?"HUMAN CHOICE REQUIRED":"Single human contributor");
      const prior=make("td",tr);
      const orig=make("div",prior);
      orig.className="orig";
      orig.textContent=valueText({
        stage:row.prior_stage,
        next_role:row.prior_next_role,
        review_date:row.prior_review_date
      });
      const proposals=make("td",tr);
      for(const cand of row.candidates){
        const card=make("div",proposals);
        card.className="candidate";
        make("strong",card,"Contributor #"+cand.contributor);
        make("div",card,valueText(cand));
        make("small",card,"Fields: "+cand.changed_fields.join(", "));
      }
      const choice=make("td",tr);
      const control=make("select",choice);
      control.setAttribute("aria-label","Human decision for agenda "+row.agenda+" original slot "+row.slot);
      if(conflict) {
        const placeholder=make("option",control,"Resolve this human conflict");
        placeholder.value="";placeholder.disabled=true;
      }
      const keep=make("option",control,"Keep original human values");
      keep.value="original";
      row.candidates.forEach((candidate,index)=>{
        const option=make("option",control,"Use human contributor #"+candidate.contributor);
        option.value="c"+index;
      });
      control.value=selected||"";
      control.addEventListener("change",()=>{
        const choice=control.value;
        if(choice!=="original"&&
           !row.candidates.some((_,index)=>choice==="c"+index))return;
        selections.set(row.agenda+":"+row.slot,choice);
        get("confirm").checked=false;
        showMessage("Local human planning selection recorded. This does not change any original source.");
        render();
      });
    }
    if(!visible){
      const tr=make("tr",body);
      const message=make("td",tr,"No human planning rows match this view.");
      message.colSpan=4;
    }
    status();
  }
  get("filter").addEventListener("change",render);
  get("reset").addEventListener("click",()=>{
    selections.clear();
    for(const row of all)if(!contested(row))selections.set(row.agenda+":"+row.slot,"c0");
    get("confirm").checked=false;
    showMessage("All contested human-only choices reset; prior originals unaffected.");
    render();
  });
  get("export").addEventListener("click",()=>{
    if(status()>0){
      showMessage("HOLD: resolve every contested original human slot first.");
      return;
    }
    if(!get("confirm").checked){
      showMessage("Explicitly confirm the complete private human conflict review before export.");
      return;
    }
    try {
      const sources=model.sources.map(source=>{
        const items=source.rows.map(row=>{
          const selected=selections.get(key(source,row));
          if(contested(row)&&!selected)
            throw Error("unresolved original human proposal");
          let chosen=null;
          if(selected&&selected!=="original"){
            if(!/^c\d+$/.test(selected))throw Error("invalid contributor slot");
            chosen=row.candidates[Number(selected.slice(1))];
            if(!chosen)throw Error("unrecognized human contributor choice");
          }
          const final=chosen||{
            stage:row.prior_stage,next_role:row.prior_next_role,
            review_date:row.prior_review_date
          };
          return {
            slot:row.slot,
            prior_stage:row.prior_stage,prior_next_role:row.prior_next_role,
            prior_review_date:row.prior_review_date,
            stage:final.stage,next_role:final.next_role,review_date:final.review_date
          };
        });
        const proposal={
          schema:"lightup.assessment_portfolio_human_proposal.v1",
          source_agenda_sha256:source.source_agenda_sha256,
          reference_date:model.reference_date,source_count:items.length,items,
          authorized:false,consent_verified:false,
          dispatch_allowed:false,release_allowed:false
        };
        return {slot:source.slot,
          source_agenda_sha256:source.source_agenda_sha256,proposal};
      });
      const bundle={
        schema:"lightup.assessment_portfolio_human_proposal_bundle.v1",
        reference_date:model.reference_date,source_count:sources.length,
        sources,planning_not_permission:true,
        authorized:false,consent_verified:false,
        dispatch_allowed:false,release_allowed:false
      };
      const bytes=JSON.stringify(bundle,null,2)+"\n";
      if(new TextEncoder().encode(bytes).length>4194304)
        throw Error("human proposal bundle too large");
      const blob=new Blob([bytes],{type:"application/json"});
      const url=URL.createObjectURL(blob);
      const download=make("a",document.body);
      download.href=url;
      download.download="lightup-PRIVATE-resolved-original-human-proposals.json";
      download.click();download.remove();
      setTimeout(()=>URL.revokeObjectURL(url),0);
      get("confirm").checked=false;
      showMessage("New owner-private human-only bundle downloaded. ORIGINAL sources, grants and consent unchanged.");
    } catch(_) {
      showMessage("HOLD: private human proposal could not be completed. No file exported.");
    }
  });
  render();
})();
