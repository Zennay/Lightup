"use strict";
/* Source-minimized offline HUMAN recipient: no original file paths,
   source hashes, external scripts, network, cookies or storage. */
(() => {
  const root = document.getElementById("review");
  const rows = [...root.querySelectorAll("tbody tr[data-token]")];
  const token = root.dataset.token;
  const teamSlot = root.dataset.slot;
  const heading = ["exchange_token","team_slot","review_row","private_row_token",
    "declared_source_change","original_human_stage","proposed_human_stage","human_reply"];
  const stages = new Set(["unreviewed","investigating","escalated","documented"]);
  const status = document.getElementById("status");
  const selector = document.getElementById("filter");
  let unsaved = false;
  const notice = (message) => {status.textContent=message;};
  const hold = (message) => notice("HOLD · " + message);
  const acceptable = (text) => typeof text === "string" && text.length <= 400 &&
    !/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(text) &&
    !/^[\s]*[=+\-@]/u.test(text);
  function oldRow(tr) {
    return [token,teamSlot,tr.dataset.row,tr.dataset.token,
      tr.dataset.change,tr.dataset.original];
  }
  function capture() {
    return rows.map(tr => {
      const stage = tr.querySelector("select").value;
      const note = tr.querySelector("textarea").value;
      if (!stages.has(stage) || !acceptable(note)) {
        throw Error("Invalid HUMAN stage/notes: 400 characters max, no controls, newlines or spreadsheet formula prefix.");
      }
      return [...oldRow(tr),stage,note];
    });
  }
  function serialize(cells) {
    return cells.map(row => row.map(x=>'"'+x.replaceAll('"','""')+'"').join(",")).join("\n") + "\n";
  }
  function exportCsv() {
    try {
      const fields = capture();
      if (!confirm("Export a confidential HUMAN reply file? This self-report cannot approve a grant, fix, consent or real operator identity.")) return;
      const url = URL.createObjectURL(new Blob([serialize([heading,...fields])],{type:"text/csv;charset=utf-8"}));
      const a=document.createElement("a");
      a.href=url;a.download="LightUp-PRIVATE-HUMAN-recipient-"+teamSlot+".csv";
      a.rel="noopener";document.body.append(a);a.click();a.remove();
      setTimeout(()=>URL.revokeObjectURL(url),20000);
      unsaved=false;
      notice("A PRIVATE HUMAN return was prepared. Confirm it was saved locally and transfer only to the original authorized owner.");
    } catch(e) { hold(e.message); }
  }
  function readCsv(raw) {
    if (raw.length>300000) throw Error("CSV is too large");
    const parsed=[];let row=[];let cell="";let quoted=false;let closed=false;
    for(let i=0;i<raw.length;i++) {
      const ch=raw[i];
      if(quoted) {
        if(ch==='"') {
          if(raw[i+1]==='"'){cell+='"';i++;} else {quoted=false;closed=true;}
        } else cell+=ch;
      } else if(closed) {
        if(ch===","){row.push(cell);cell="";closed=false;}
        else if(ch==="\n"){row.push(cell);parsed.push(row);row=[];cell="";closed=false;}
        else throw Error("Invalid quoted field delimiter");
      } else if(ch==='"' && !cell) quoted=true;
      else if(ch===","){row.push(cell);cell="";}
      else if(ch==="\n"){row.push(cell);parsed.push(row);row=[];cell="";}
      else if(ch==="\r") throw Error("Carriage returns disallowed");
      else if(ch==='"') throw Error("Ambiguous unquoted quote");
      else cell+=ch;
      if(parsed.length>257) throw Error("Too many HUMAN rows");
    }
    if(quoted) throw Error("Unterminated CSV field");
    if(closed||cell||row.length){row.push(cell);parsed.push(row);}
    return parsed;
  }
  async function importCsv(event) {
    const file=event.target.files?.[0];event.target.value="";
    if(!file)return;
    try {
      if(file.size>300000) throw Error("CSV import exceeds 300KB");
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const data=readCsv(raw);
      if(data.length!==rows.length+1 || data[0].length!==heading.length ||
          !data[0].every((value,i)=>value===heading[i])) {
        throw Error("Reply row/column count does not match original assignment");
      }
      const prepared=[];
      rows.forEach((tr,i)=>{
        const entry=data[i+1];
        if(entry.length!==heading.length ||
            !oldRow(tr).every((orig,j)=>entry[j]===orig) ||
            !stages.has(entry[6]) || !acceptable(entry[7])) {
          throw Error("Original row binding, HUMAN stage or content mismatch at row " +(i+1));
        }
        prepared.push({stage:entry[6],note:entry[7]});
      });
      if(!confirm("Restore these exact source-minimized HUMAN replies? Existing unsaved local edits will be replaced."))return;
      rows.forEach((tr,i)=>{
        tr.querySelector("select").value=prepared[i].stage;
        tr.querySelector("textarea").value=prepared[i].note;
      });
      unsaved=true;update();
      notice("HUMAN replies restored in memory. No source owner, permission or grant has been verified. Export to save.");
    } catch(e) {hold(e.message);}
  }
  function update() {
    let visible=0,changed=0;
    const filter=selector.value;
    rows.forEach(tr=>{
      const stage=tr.querySelector("select").value;
      const show=!filter||tr.dataset.change===filter;
      tr.hidden=!show;
      if(show)visible++;
      if(stage!==tr.dataset.original)changed++;
    });
    document.getElementById("summary").textContent=visible+"/"+rows.length+
      " assigned HUMAN rows visible · "+changed+" proposed HUMAN stage changes (not authorizations).";
  }
  if (!/^[a-f0-9]{32}$/.test(token) || !/^[1-9][0-9]?$/.test(teamSlot) ||
      rows.length===0 || rows.length>256) {
    root.replaceChildren(document.createTextNode("HOLD: malformed source-minimized HUMAN exchange."));return;
  }
  for(const tr of rows) {
    if(!/^[a-f0-9]{32}$/.test(tr.dataset.token) ||
       !/^[1-9][0-9]{0,2}$/.test(tr.dataset.row) ||
       !["unchanged","changed","added","absent"].includes(tr.dataset.change) ||
       !stages.has(tr.dataset.original)) {
       root.replaceChildren(document.createTextNode("HOLD: invalid original HUMAN assignment row."));return;
    }
    for(const control of tr.querySelectorAll("select,textarea")){
      control.addEventListener("input",()=>{unsaved=true;update();});
    }
  }
  document.getElementById("export").addEventListener("click",exportCsv);
  document.getElementById("import").addEventListener("change",importCsv);
  selector.addEventListener("change",update);
  window.addEventListener("beforeunload",e=>{
    if(unsaved){e.preventDefault();e.returnValue="";}
  });
  update();
})();
