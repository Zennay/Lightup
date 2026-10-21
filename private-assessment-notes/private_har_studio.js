"use strict";
(() => {
  const states = ["PENDING_HUMAN","IN_PROGRESS","SOURCE_OWNER_NEEDED","WITHHOLD","HUMAN_REVIEWED"];
  const allowed = new Set(states);
  const bulkAllowed = new Set(states.filter(s => s !== "HUMAN_REVIEWED"));
  const header = ["original_ordinal","review_area","literal_cue_count",
    "next_human_action","human_status","human_notes"];
  const items = Array.from(document.querySelectorAll("tr[data-action]"));
  const notice = document.getElementById("notice");
  const counter = document.getElementById("counter");
  const filter = document.getElementById("filter");
  const search = document.getElementById("search");
  const bulk = document.getElementById("bulk");
  const undo = document.getElementById("undo");
  let checkpoint = null;
  const fields = row => [row.dataset.ordinal,row.dataset.area,
    row.dataset.count,row.dataset.task];
  const stage = row => row.querySelector("select[data-status]");
  const csv = value => '"' + String(value).replaceAll('"','""') + '"';

  function redraw() {
    let shown=0, done=0;
    const needle=search.value.trim().toLowerCase();
    for (const item of items) {
      const status=stage(item).value;
      if(status==="HUMAN_REVIEWED") done++;
      const matches=(filter.value==="ALL" || filter.value===status) &&
        (!needle || ("original #"+item.dataset.ordinal+" "+item.dataset.area+
          " "+item.dataset.task).toLowerCase().includes(needle));
      item.hidden=!matches;
      if(matches) shown++;
    }
    counter.textContent=shown+" of "+items.length+" tasks visible; "+done+
      " manually marked HUMAN_REVIEWED. Unverified; all remain HOLD.";
    undo.disabled=!checkpoint;
  }

  function download(name, content) {
    const blob=new Blob([content],{type:"text/csv;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;link.download=name;
    document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),12000);
  }

  function parseCSV(raw) {
    // Strict bounded RFC4180 fields, CRLF records only; no multiline fields.
    if(raw.charCodeAt(0)===0xFEFF || !raw.endsWith("\r\n"))
      throw Error("Unexpected CSV encoding or row endings");
    const records=[];let row=[],field="",quoted=false,ended=false;
    for(let i=0;i<raw.length;i++){
      const ch=raw[i];
      if(quoted){
        if(ch==='"'){
          if(raw[i+1]==='"'){field+='"';i++;}
          else {quoted=false;ended=true;}
        }else if(ch==="\n"||ch==="\r"||ch==="\0"){
          throw Error("Multiline or invalid CSV field");
        }else field+=ch;
      }else if(ch==='"'&&!field&&!ended){quoted=true;}
      else if(ch===','){row.push(field);field="";ended=false;}
      else if(ch==="\r"&&raw[i+1]==="\n"){
        row.push(field);records.push(row);row=[];field="";ended=false;i++;
        if(records.length>items.length+1)throw Error("Too many rows");
      }else if(ch==='"'||ch==="\n"||ch==="\r"||ch==="\0"||ended){
        throw Error("Malformed CSV");
      }else field+=ch;
    }
    if(quoted||row.length||field||!records.length)throw Error("Incomplete CSV");
    return records;
  }

  function admitted(rows) {
    if(rows.length!==items.length+1||rows[0].length!==6||
       rows[0].some((s,i)=>s!==header[i]))
      throw Error("Original action columns or row count changed");
    const statuses=[];
    for(let i=0;i<items.length;i++){
      const cells=rows[i+1],original=fields(items[i]);
      if(cells.length!==6 || original.some((v,j)=>v!==cells[j]) ||
         !allowed.has(cells[4]) || cells[5]!=="")
        throw Error("Original action identity/status does not match at row "+(i+1));
      statuses.push(cells[4]);
    }
    return statuses;
  }

  document.getElementById("resume").addEventListener("change",async ev=>{
    const file=ev.target.files && ev.target.files[0];
    ev.target.value="";
    if(!file)return;
    try {
      if(!file.size||file.size>65536)throw Error("CSV exceeds private 64 KiB limit");
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const next=admitted(parseCSV(raw)); // ALL original rows before any mutation
      if(!window.confirm("Restore "+next.length+" PRIVATE HUMAN statuses? All source-bound action fields match. No approval or consent will be granted."))return;
      checkpoint=null;
      items.forEach((item,i)=>stage(item).value=next[i]);
      notice.textContent="Original action statuses restored locally; native admission still required.";
      redraw();
    }catch(_error){
      notice.textContent="HOLD: invalid or changed PRIVATE original action CSV. No statuses modified.";
    }
  });

  document.getElementById("save").addEventListener("click",()=>{
    if(!items.every(row=>allowed.has(stage(row).value))) {
      notice.textContent="HOLD: invalid HUMAN stage; no CSV exported";return;
    }
    if(!window.confirm("Export ALL "+items.length+" original PRIVATE actions (including hidden rows) for native source-bound HOLD admission? No status is an approval."))return;
    const rows=[header.map(csv).join(",")];
    for(const item of items)
      rows.push([...fields(item),stage(item).value,""].map(csv).join(","));
    download("PRIVATE-HAR-ACTIONS-edited.csv",rows.join("\r\n")+"\r\n");
    notice.textContent="PRIVATE full CSV saved. Move to owner-only 0600 before native import; original cue files remain immutable.";
  });

  document.getElementById("apply").addEventListener("click",()=>{
    const target=bulk.value,visible=items.filter(item=>!item.hidden);
    if(!bulkAllowed.has(target)||!visible.length){
      notice.textContent="HOLD: bulk HUMAN_REVIEWED is forbidden; select another status and visible tasks.";
      return;
    }
    if(!window.confirm("Apply "+target+" to "+visible.length+" visible PRIVATE tasks only? Hidden rows remain unchanged."))return;
    checkpoint=items.map(item=>stage(item).value);
    visible.forEach(item=>stage(item).value=target);
    notice.textContent="Non-authorising bulk status proposal applied; review before complete export.";
    redraw();
  });
  undo.addEventListener("click",()=>{
    if(!checkpoint)return;
    items.forEach((item,i)=>stage(item).value=checkpoint[i]);
    checkpoint=null;
    notice.textContent="Last bulk status edit reverted locally.";
    redraw();
  });
  filter.addEventListener("change",redraw);
  search.addEventListener("input",redraw);
  items.forEach(item=>stage(item).addEventListener("change",()=>{
    checkpoint=null;
    redraw();
  }));
  redraw();
})();