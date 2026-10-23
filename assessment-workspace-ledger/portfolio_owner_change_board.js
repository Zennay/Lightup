/* LightUp original PRIVATE HUMAN proposed-change board — offline operator view.
 * Read only an original native PRIVATE operator board from 0700/0600 custody.
 * All source/admission and real authorization remain separate HUMAN gates.
 */
(() => {
  "use strict";
  const $=id=>document.getElementById(id);
    const LIGHTUP_SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  function lightupSha256Fallback(bytes) {
    const length = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(length);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(length - 8, Math.floor(bytes.length / 0x20000000), false);
    view.setUint32(length - 4, (bytes.length * 8) >>> 0, false);
    const state = new Uint32Array([
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ]);
    const words = new Uint32Array(64);
    const rotate = (x,n) => (x >>> n) | (x << (32 - n));
    for (let offset = 0; offset < length; offset += 64) {
      for (let i = 0; i < 16; i++) words[i] = view.getUint32(offset + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const x = words[i - 15], y = words[i - 2];
        const s0 = rotate(x,7) ^ rotate(x,18) ^ (x >>> 3);
        const s1 = rotate(y,17) ^ rotate(y,19) ^ (y >>> 10);
        words[i] = (words[i - 16] + s0 + words[i - 7] + s1) >>> 0;
      }
      let a=state[0], b=state[1], c=state[2], d=state[3];
      let e=state[4], f=state[5], g=state[6], h=state[7];
      for (let i = 0; i < 64; i++) {
        const s1 = rotate(e,6) ^ rotate(e,11) ^ rotate(e,25);
        const choose = (e & f) ^ (~e & g);
        const t1 = (h + s1 + choose + LIGHTUP_SHA256_K[i] + words[i]) >>> 0;
        const s0 = rotate(a,2) ^ rotate(a,13) ^ rotate(a,22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (s0 + majority) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      state[0]=(state[0]+a)>>>0; state[1]=(state[1]+b)>>>0;
      state[2]=(state[2]+c)>>>0; state[3]=(state[3]+d)>>>0;
      state[4]=(state[4]+e)>>>0; state[5]=(state[5]+f)>>>0;
      state[6]=(state[6]+g)>>>0; state[7]=(state[7]+h)>>>0;
    }
    return Array.from(state, word => word.toString(16).padStart(8,'0')).join('');
  }
  async function lightupSha256Hex(buffer) {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      try {
        const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
        return {hex:Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join(''),
          method:'Web Crypto SHA-256'};
      } catch (_) {}
    }
    return {hex:lightupSha256Fallback(new Uint8Array(buffer)), method:'portable local SHA-256'};
  }
const SCHEMA="lightup.private.workspace-ledger-human-owner-change-briefs.v1";
  const KEYS=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_history_sha256","original_owner_inbox_sha256","original_operator_followup_sha256","changed_only","human_only_proposed_owner_rows"];
  const AUTH=["authorization","consent","verified_finding","release_approval"];
  const GROUP=["original_proposed_human_owner_label","original_owner_slot_count","human_proposed_owner_rows"];
  const ROW=["original_proposed_human_owner_label","local_case","historical_transition","original_kit","original_round_human_stage","original_owner_human_reply_stage","human_operator_followup_stage","private_human_followup_note"];
  const STAGES=["needs_discussion","proposed_followup","hold"];
  const MAX=1048576;
  let full=null,rows=[],owners=[],hash="";
  const exact=(o,k)=>!!o&&typeof o==="object"&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
  const hex=s=>typeof s==="string"&&/^[a-f0-9]{64}$/.test(s);
  const label=s=>typeof s==="string"&&s.length>0&&s.length<=80&&s===s.trim()&&!/[\u0000-\u001f\u007f]/.test(s)&&!/^\s*[=+@-]/.test(s);
  const note=s=>typeof s==="string"&&s.length<=240&&!/[\u0000-\u001f\u007f]/.test(s)&&!/^\s*[=+@-]/.test(s);
  function parseUnique(source){
    let pos=0;
    const number=/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
    const literal=/(?:true|false|null)/y;
    const space=()=>{while(pos<source.length&&/[\r\n\t ]/.test(source[pos]))pos++;};
    function quoted(){
      if(source[pos]!=='"')throw Error("Invalid PRIVATE JSON key");
      const start=pos++;
      while(pos<source.length){const c=source[pos++];
        if(c==='"')return JSON.parse(source.slice(start,pos));
        if(c==="\\"){if(pos===source.length)throw Error("Malformed JSON escape");pos++;}
      }
      throw Error("Incomplete source JSON string");
    }
    function value(depth){
      if(depth>64)throw Error("PRIVATE JSON nesting limit");
      space();
      if(source[pos]==='{'){
        pos++;space();const seen=new Set();
        if(source[pos]==='}'){pos++;return;}
        while(true){
          space();const key=quoted();
          if(seen.has(key))throw Error("Duplicate PRIVATE source JSON key");
          seen.add(key);space();
          if(source[pos++]!==':')throw Error("Malformed source JSON member");
          value(depth+1);space();
          const end=source[pos++];
          if(end==='}')return;
          if(end!==',')throw Error("Malformed source JSON object");
        }
      }
      if(source[pos]==='['){
        pos++;space();if(source[pos]===']'){pos++;return;}
        while(true){
          value(depth+1);space();const end=source[pos++];
          if(end===']')return;
          if(end!==',')throw Error("Malformed source JSON array");
        }
      }
      if(source[pos]==='"'){quoted();return;}
      number.lastIndex=pos;const n=number.exec(source);
      if(n){pos=number.lastIndex;return;}
      literal.lastIndex=pos;const l=literal.exec(source);
      if(l){pos=literal.lastIndex;return;}
      throw Error("Malformed PRIVATE source token");
    }
    value(0);space();
    if(pos!==source.length)throw Error("Unexpected trailing source bytes");
    return JSON.parse(source);
  }
  function admit(doc){
    if(!exact(doc,KEYS)||doc.schema!==SCHEMA||!exact(doc.authority,AUTH)||
      !AUTH.every(k=>doc.authority[k]===false)||doc.historical_only!==true||
      !["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(k=>doc[k]===false)||
      !hex(doc.original_history_sha256)||!hex(doc.original_owner_inbox_sha256)||
      !hex(doc.original_operator_followup_sha256)||typeof doc.changed_only!=="boolean"||
      !Array.isArray(doc.human_only_proposed_owner_rows)||doc.human_only_proposed_owner_rows.length<1||
      doc.human_only_proposed_owner_rows.length>8)throw Error("Not a canonical native PRIVATE HUMAN change board");
    const groups=[],all=[],ids=new Set(),labels=new Set();
    for(const g of doc.human_only_proposed_owner_rows){
      if(!exact(g,GROUP)||!label(g.original_proposed_human_owner_label)||
        labels.has(g.original_proposed_human_owner_label)||
        !Number.isInteger(g.original_owner_slot_count)||g.original_owner_slot_count<1||g.original_owner_slot_count>2048||
        !Array.isArray(g.human_proposed_owner_rows)||
        g.human_proposed_owner_rows.length>g.original_owner_slot_count)
        throw Error("Invalid original proposed HUMAN owner group");
      labels.add(g.original_proposed_human_owner_label);
      groups.push(g.original_proposed_human_owner_label);
      for(const r of g.human_proposed_owner_rows){
        const id=r?.local_case+":"+r?.historical_transition+":"+r?.original_kit;
        if(!exact(r,ROW)||r.original_proposed_human_owner_label!==g.original_proposed_human_owner_label||
          !Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
          !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
          !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
          ids.has(id)||!STAGES.includes(r.original_round_human_stage)||
          !STAGES.includes(r.original_owner_human_reply_stage)||
          !STAGES.includes(r.human_operator_followup_stage)||
          !note(r.private_human_followup_note)||(
            doc.changed_only &&
            r.original_owner_human_reply_stage===r.human_operator_followup_stage &&
            !r.private_human_followup_note
          ))throw Error("Original HUMAN change row invalid");
        ids.add(id);all.push(r);
        if(all.length>2048)throw Error("PRIVATE HUMAN source slot limit");
      }
    }
    return {groups,all};
  }
  const el=(tag,value,cls)=>{const n=document.createElement(tag);
    if(value!==undefined)n.textContent=String(value);
    if(cls)n.className=cls;return n;
  };
  const status=s=>{$("status").textContent=s;};
  function clear(){
    full=null;rows=[];owners=[];hash="";
    $("source").value="";$("room").hidden=true;$("cards").replaceChildren();
    $("owner").replaceChildren(el("option","All proposed HUMAN owners"));
    $("owner").firstChild.value="";
    $("stage").value="";$("change").value="all";$("search").value="";
    status("PRIVATE HUMAN browser memory cleared. No source files modified.");
  }
  function selected(){
    const target=$("owner").value,stage=$("stage").value,change=$("change").value;
    const phrase=$("search").value.trim().toLocaleLowerCase();
    return rows.filter(r=>{
      if(target&&r.original_proposed_human_owner_label!==target)return false;
      if(stage&&r.human_operator_followup_stage!==stage)return false;
      if(change==="stage"&&r.original_owner_human_reply_stage===r.human_operator_followup_stage)return false;
      if(change==="note"&&!r.private_human_followup_note)return false;
      if(change==="both"&&!(r.private_human_followup_note&&r.original_owner_human_reply_stage!==r.human_operator_followup_stage))return false;
      if(change==="stable"&&(r.original_owner_human_reply_stage!==r.human_operator_followup_stage||r.private_human_followup_note))return false;
      return !phrase||(
        r.original_proposed_human_owner_label+" "+r.local_case+" "+
        r.historical_transition+" "+r.original_kit+" "+r.private_human_followup_note
      ).toLocaleLowerCase().includes(phrase);
    });
  }
  function render(){
    if(!full)return;
    const v=selected(), box=$("cards");box.replaceChildren();
    $("summary").textContent=owners.length+" original proposed HUMAN owner groups • "+
      rows.length+" original HUMAN rows in private operator board • "+
      (full.changed_only?"changes-only native source":"full native HUMAN source");
    $("visible").textContent=v.length+" visible HUMAN slots · "+
      STAGES.map(s=>s.replaceAll("_"," ")+": "+v.filter(r=>r.human_operator_followup_stage===s).length).join(" · ");
    for(const r of v){
      const article=el("article",undefined,"card");
      article.append(el("h3","Original HUMAN source "+r.local_case+"/"+r.historical_transition+"/"+r.original_kit));
      const facts=el("div",undefined,"facts");
      for(const [key,val] of [
        ["Proposed original HUMAN owner (not authenticated)",r.original_proposed_human_owner_label],
        ["Original received HUMAN proposal",r.original_owner_human_reply_stage],
        ["Operator HUMAN-only follow-up proposal",r.human_operator_followup_stage],
        ["PRIVATE follow-up note; not security evidence",r.private_human_followup_note||"—"]
      ]){const row=el("div",undefined,"fact");row.append(el("strong",key),el("span",val));facts.append(row);}
      article.append(facts);box.append(article);
    }
    if(!v.length)box.append(el("p","No matching historical HUMAN proposal. Not evidence of a fix."));
  }
  async function load(event){
    const file=event.target.files?.[0];
    if(!file||file.size<=0||file.size>MAX||!file.name.toLowerCase().endsWith(".json")){
      status("PRIVATE HOLD: choose one complete original native board JSON ≤1 MiB");return;
    }
    try{
      const bytes=await file.arrayBuffer();
      if(bytes.byteLength!==file.size)throw Error("Source byte mismatch");
      const doc=parseUnique(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
      const result=admit(doc);
      const digest=(await lightupSha256Hex(bytes)).hex;
      full=doc;hash=digest;rows=result.all;owners=result.groups;
      const sel=$("owner");sel.replaceChildren(el("option","All original proposed HUMAN owners"));
      sel.firstChild.value="";
      for(const name of owners){const opt=el("option",name);opt.value=name;sel.append(opt);}
      $("stage").value="";$("change").value="all";$("search").value="";
      $("room").hidden=false;render();
      status("Original PRIVATE HUMAN proposals opened locally. Unsigned source SHA-256: "+hash+". No actual authorization.");
    }catch(err){
      status("PRIVATE HOLD: original source rejected ("+(err?.message||"invalid")+"). Previous browser view retained.");
    }
  }
  function counts(){
    if(!full)return;
    const data=selected();
    const result={schema:"lightup.private.anonymous-owner-change-counts.v1",
      authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},
      historical_only:true,visible_human_proposals:data.length,
      proposed_human_statuses:Object.fromEntries(STAGES.map(k=>[
        k,data.filter(r=>r.human_operator_followup_stage===k).length])),
      human_stage_change_count:data.filter(r=>r.human_operator_followup_stage!==r.original_owner_human_reply_stage).length,
      private_human_note_present_count:data.filter(r=>!!r.private_human_followup_note).length};
    const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)+"\n"],
      {type:"application/json"}));
    const a=el("a");a.href=url;a.download="LightUp-anonymous-HUMAN-change-counts.json";
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),500);
    status("Only anonymous visible HUMAN counts exported. No labels, notes or original case IDs.");
  }
  $("source").addEventListener("change",load);
  $("owner").addEventListener("change",render);
  $("stage").addEventListener("change",render);
  $("change").addEventListener("change",render);
  $("search").addEventListener("input",render);
  $("counts").addEventListener("click",counts);
  $("clear").addEventListener("click",clear);
  window.addEventListener("pagehide",clear);
  status("Select locally generated PRIVATE-HUMAN-operator-change-board.json. No embedded HUMAN source data.");
})();
