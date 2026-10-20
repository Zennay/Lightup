"use strict";
/* PRIVATE owner HUMAN adjudication. Stages are not grants, fixes, or consent.
 * No persistence, network, cookie, remote request, scanner or source mutation. */
(() => {
  const root=document.getElementById("owner");
  const records=[...root.querySelectorAll("tbody tr[data-original]")];
  const first=root.dataset.previous, second=root.dataset.current;
  const FIELDS=["previous_manifest_sha256","current_manifest_sha256","source_file_path",
    "change_status","previous_sha256","current_sha256",
    "human_stage","human_team","human_notes"];
  const STAGES=new Set(["unreviewed","investigating","escalated","documented"]);
  const status=document.getElementById("status");
  let dirty=false;
  const fail=msg=>{status.textContent="HOLD · "+msg;};
  const allowed=(value,max) => typeof value==="string"&&value.length<=max&&
    !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value)&&
    !/^[\s]*[=+\-@]/u.test(value);
  const identity=tr=>[first,second,tr.dataset.path,tr.dataset.change,
    tr.dataset.old,tr.dataset.new];
  function collect(){
    return records.map(tr=>{
      const choice=tr.querySelector("select.review-choice").value;
      const stage=choice==="accept"?tr.dataset.proposed:tr.dataset.original;
      const team=tr.dataset.team;
      const note=tr.querySelector("textarea.original-note").value;
      if(!["retain","accept"].includes(choice)||!STAGES.has(stage)||
         !allowed(team,80)||!allowed(note,500))throw Error("Invalid owner HUMAN decision or private original note");
      if(choice==="accept"&&!tr.hasAttribute("data-proposed"))throw Error("Cannot accept a nonexistent reviewer proposal");
      return [...identity(tr),stage,team,note];
    });
  }
  function csv(rows){
    return rows.map(row=>row.map(value=>'"'+value.replaceAll('"','""')+'"').join(",")).join("\n")+"\n";
  }
  function save(name,content){
    const url=URL.createObjectURL(new Blob([content],{type:"text/csv;charset=utf-8"}));
    const a=document.createElement("a");a.href=url;a.download=name;a.rel="noopener";
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),25000);
  }
  function update(){
    let proposals=0,accepted=0,visible=0;
    const filter=document.getElementById("show").value;
    for(const tr of records){
      const has=tr.hasAttribute("data-proposed");
      if(has)proposals++;
      if(tr.querySelector("select.review-choice").value==="accept")accepted++;
      const show=filter==="all"||filter==="proposals"&&has||
        filter==="accepted"&&tr.querySelector("select.review-choice").value==="accept"||
        filter==="pending"&&has&&tr.querySelector("select.review-choice").value!=="accept";
      tr.hidden=!show;if(show)visible++;
    }
    document.getElementById("summary").textContent=visible+" visible · "+
      proposals+" unverified team HUMAN proposals · "+accepted+" owner-selected HUMAN stage updates (not permission).";
  }
  document.getElementById("export").addEventListener("click",()=>{
    try{
      const data=collect();
      if(!confirm("Export a NEW PRIVATE human worksheet with only your explicitly accepted HUMAN stage proposals? This has NO impact on grants, consent, targets, verified fixes or scanner authorization."))return;
      save("LightUp-PRIVATE-owner-selected-HUMAN-draft.csv",csv([FIELDS,...data]));
      dirty=false;
      status.textContent="Owner-selected HUMAN CSV prepared locally. It remains a DRAFT and requires separate original-source review; confirm secure storage.";
    }catch(err){fail(err.message);}
  });
  document.getElementById("show").addEventListener("change",update);
  if(!/^[a-f0-9]{64}$/.test(first)||!/^[a-f0-9]{64}$/.test(second)||
     records.length<1||records.length>256){
    root.replaceChildren(document.createTextNode("HOLD — malformed original source owner workroom"));return;
  }
  for(const tr of records){
    const changed=tr.dataset.change,orig=tr.dataset.original;
    if(!["unchanged","changed","added","absent"].includes(changed)||
      !STAGES.has(orig)||!STAGES.has(tr.dataset.proposed||orig)){
      root.replaceChildren(document.createTextNode("HOLD — malformed source-bound HUMAN owner row"));return;
    }
    for(const input of tr.querySelectorAll("select,textarea")){
      input.addEventListener("input",()=>{dirty=true;update();});
    }
  }
  window.addEventListener("beforeunload",e=>{
    if(dirty){e.preventDefault();e.returnValue="";}
  });
  update();
})();
