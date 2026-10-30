/* LightUp PRIVATE historical HUMAN inbox explorer. Local operator review only.
 * Uses only explicitly selected native-derived PRIVATE history JSON bytes.
 * Browser import is an unsigned preview, not authoritative native admission.
 */
(() => {
 "use strict";
 const $ = id => document.getElementById(id);
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
const HISTORY="lightup.private.workspace-ledger-human-inbox-history.v1";
 const AUTH=["authorization","consent","verified_finding","release_approval"];
 const ROOT=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_inbox_sha256","selected_original_proposed_human_owner_label","owner_scoped_private_export","original_human_discussion_rounds","private_human_history_slots"];
 const ROUNDS=["round","original_discussion_sha256","original_review_csv_sha256"];
 const SLOT=["local_case","historical_transition","original_kit","original_proposed_human_owner","original_human_stage","original_owner_reply_stage","first_human_triage_stage","latest_human_triage_stage","stage_changed_rounds","private_note_changed_rounds","round_stages"];
 const STAGES=["needs_discussion","proposed_followup","hold"];
 const MAX_BYTES=1048576;
 let history=null, rawDigest="", rows=[], rounds=0;
 let ownerScoped=false;
 function exact(o,keys){return !!o && typeof o==="object" && !Array.isArray(o) && Object.keys(o).length===keys.length && keys.every(k=>Object.prototype.hasOwnProperty.call(o,k));}
 function hex(s){return typeof s==="string" && /^[a-f0-9]{64}$/.test(s);}
 function stage(s){return STAGES.includes(s);}
 function label(s){return typeof s==="string" && s.length>0 && s.length<=80 && s.trim()===s && !/[\u0000-\u001f\u007f]/.test(s) && !/^\s*[=+@-]/.test(s);}
 function id(r){return r.local_case+"/"+r.historical_transition+"/"+r.original_kit;}
 function changes(a,seq){return a.filter((n,i)=>Number.isInteger(n)&&n>=2&&n<=seq&& (i===0||n>a[i-1]));}
 function parseUniqueJSON(source) {
   // Mirror the original native duplicate-key refusal in the offline preview.
   // This is only parse hygiene; the native PRIVATE admission is authoritative.
   let pos=0;
   const number=/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
   const literal=/(?:true|false|null)/y;
   function space(){while(pos<source.length&&/[ \t\n\r]/.test(source[pos]))pos++;}
   function quoted(){
     if(source[pos]!=='"')throw Error("Malformed source JSON key");
     const start=pos++;
     while(pos<source.length){
       const ch=source[pos++];
       if(ch==='"')return JSON.parse(source.slice(start,pos));
       if(ch==="\\"){if(pos===source.length)throw Error("Malformed JSON escape");pos++;}
     }
     throw Error("Unterminated original source JSON string");
   }
   function value(depth){
     if(depth>60)throw Error("Original HUMAN history JSON too deeply nested");
     space();
     if(source[pos]==='{'){
       pos++;space();const seen=new Set();
       if(source[pos]==='}'){pos++;return;}
       while(true){
         space();const key=quoted();
         if(seen.has(key))throw Error("Duplicate original PRIVATE JSON key");
         seen.add(key);space();
         if(source[pos++]!==':')throw Error("Malformed JSON object");
         value(depth+1);space();
         const end=source[pos++];
         if(end==='}')return;
         if(end!==',')throw Error("Malformed original JSON object delimiter");
       }
     }
     if(source[pos]==='['){
       pos++;space();
       if(source[pos]===']'){pos++;return;}
       while(true){
         value(depth+1);space();const end=source[pos++];
         if(end===']')return;
         if(end!==',')throw Error("Malformed original JSON array delimiter");
       }
     }
     if(source[pos]==='"'){quoted();return;}
     number.lastIndex=pos;
     const n=number.exec(source);
     if(n){pos=number.lastIndex;return;}
     literal.lastIndex=pos;
     const l=literal.exec(source);
     if(l){pos=literal.lastIndex;return;}
     throw Error("Malformed PRIVATE HUMAN history JSON token");
   }
   value(0);space();
   if(pos!==source.length)throw Error("Trailing original PRIVATE history JSON data");
   return JSON.parse(source);
 }
 function verify(doc){
   if(!exact(doc,ROOT)||doc.schema!==HISTORY||!exact(doc.authority,AUTH)||!AUTH.every(k=>doc.authority[k]===false)||
     doc.historical_only!==true||!["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(k=>doc[k]===false)||
     !hex(doc.original_inbox_sha256) || typeof doc.owner_scoped_private_export!=="boolean" ||
     !Array.isArray(doc.original_human_discussion_rounds) || doc.original_human_discussion_rounds.length<2||doc.original_human_discussion_rounds.length>8 ||
     !Array.isArray(doc.private_human_history_slots) || doc.private_human_history_slots.length<1||doc.private_human_history_slots.length>2048) throw Error("Not the native PRIVATE HUMAN history schema");
   const scope=doc.selected_original_proposed_human_owner_label;
   if ((scope===null)!==!doc.owner_scoped_private_export || (scope!==null&&!label(scope))) throw Error("Owner-scoping boundary mismatch");
   const signatures=new Set();
   for(const [i,item] of doc.original_human_discussion_rounds.entries()){
      if(!exact(item,ROUNDS)||item.round!==i+1||!hex(item.original_discussion_sha256)||!hex(item.original_review_csv_sha256)||
        signatures.has(item.original_discussion_sha256)) throw Error("Original historical round identity or order invalid");
      signatures.add(item.original_discussion_sha256);
   }
   const size=doc.original_human_discussion_rounds.length, ids=new Set();
   for(const r of doc.private_human_history_slots){
     if(!exact(r,SLOT)||!label(r.original_proposed_human_owner)||
       (scope!==null&&r.original_proposed_human_owner!==scope)||
       !Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
       !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
       !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
       ids.has(id(r))||!stage(r.original_human_stage)||!stage(r.original_owner_reply_stage)||
       !stage(r.first_human_triage_stage)||!stage(r.latest_human_triage_stage)||
       !Array.isArray(r.round_stages)||r.round_stages.length!==size||!r.round_stages.every(stage)||
       r.round_stages[0]!==r.first_human_triage_stage||r.round_stages[size-1]!==r.latest_human_triage_stage||
       !Array.isArray(r.stage_changed_rounds)||!Array.isArray(r.private_note_changed_rounds)||
       changes(r.stage_changed_rounds,size).length!==r.stage_changed_rounds.length||
       changes(r.private_note_changed_rounds,size).length!==r.private_note_changed_rounds.length) throw Error("Original HUMAN case/round record invalid");
     const derived=[];
     for(let i=1;i<size;i++) if(r.round_stages[i]!==r.round_stages[i-1])derived.push(i+1);
     if(JSON.stringify(derived)!==JSON.stringify(r.stage_changed_rounds))throw Error("HUMAN stage transition does not match original rounds");
     ids.add(id(r));
   }
   return doc.private_human_history_slots.slice();
 }
 function element(tag,value,className){
   const e=document.createElement(tag);
   if(value!==undefined)e.textContent=String(value);
   if(className)e.className=className;
   return e;
 }
 function msg(s){$("status").textContent=s;}
 function clear(){
   history=null;rawDigest="";rows=[];rounds=0;ownerScoped=false;
   $("room").hidden=true;$("cards").replaceChildren();$("owner").replaceChildren();
   $("source").value="";$("ownerFilter").value="";$("search").value="";
   $("stage").value="";$("change").value="all";$("round").value="latest";
   msg("No PRIVATE source opened. Nothing stored by this page.");
 }
 function visibleRows(){
   const owner=$("ownerFilter").value;
   const stageValue=$("stage").value;
   const change=$("change").value;
   const term=$("search").value.trim().toLocaleLowerCase();
   const round=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   return rows.filter(r=>{
     const changed=!!(r.stage_changed_rounds.length||r.private_note_changed_rounds.length);
     if(owner && r.original_proposed_human_owner!==owner)return false;
     if(stageValue && r.round_stages[round]!==stageValue)return false;
     if(change==="changed"&&!changed)return false;
     if(change==="stable"&&changed)return false;
     if(change==="stage"&&!r.stage_changed_rounds.length)return false;
     if(change==="note"&&!r.private_note_changed_rounds.length)return false;
     if(term && !(r.original_proposed_human_owner+" "+id(r)+" "+r.round_stages.join(" ")).toLocaleLowerCase().includes(term))return false;
     return true;
   });
 }
 function render(){
   if(!history)return;
   const list=visibleRows(), box=$("cards"), byStage={};
   for(const s of STAGES)byStage[s]=0;
   const n=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   for(const r of list)byStage[r.round_stages[n]]++;
   $("total").textContent=rows.length+" original PRIVATE HUMAN slots · "+rounds+" explicitly ordered rounds · "+(ownerScoped?"original single-owner scope":"complete original owner set");
   $("shown").textContent=list.length+" visible of "+rows.length+" original private slots · "+STAGES.map(s=>s.replaceAll("_"," ")+": "+byStage[s]).join(" · ");
   box.replaceChildren();
   for(const r of list){
     const card=element("article",undefined,"card");
     card.append(element("h3","Original HUMAN slot "+id(r)));
     const facts=element("div",undefined,"facts");
     for(const [k,v] of [
       ["Proposed original HUMAN owner",r.original_proposed_human_owner],
       ["Original owner reply HUMAN proposal",r.original_owner_reply_stage],
       ["Selected HUMAN round proposal",r.round_stages[n]],
       ["Manual stages round 1–"+rounds,r.round_stages.join(" → ")],
       ["Proposed stage changed in rounds",r.stage_changed_rounds.join(", ")||"none"],
       ["PRIVATE note changed in rounds; text absent",r.private_note_changed_rounds.join(", ")||"none"]
     ]) {const fact=element("div",undefined,"fact");fact.append(element("strong",k),element("span",v));facts.append(fact);}
     card.append(facts);box.append(card);
   }
   if(!list.length)box.append(element("p","No original HUMAN proposal matches these filters; no remediation is implied."));
 }
 function csv(rows){
   // CSV is PRIVATE. Original source slot and owner are explicit; note contents excluded.
   const head=["original_history_sha256","selected_human_round","local_case","historical_transition","original_kit","original_proposed_human_owner","first_human_triage_stage","latest_human_triage_stage","stage_changed_rounds","private_note_changed_rounds"];
   const guarded=value=>{
      const s=String(value);
      if (/^\s*[=+@-]/.test(s))return "'"+s;
      return s;
   };
   const escape=value=>'"'+guarded(value).replaceAll('"','""')+'"';
   const selected=$("round").value==="latest"?rounds:Number($("round").value);
   return [head.join(","),...rows.map(r=>head.map(k=>escape(
       k==="original_history_sha256"?rawDigest:
       k==="selected_human_round"?selected:
       Array.isArray(r[k])?r[k].join(";"):r[k])).join(","))].join("\r\n")+"\r\n";
 }
 function download(name,type,data){
   const url=URL.createObjectURL(new Blob([data],{type}));const a=element("a");
   a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),500);
 }
 function minimal(){
   // Never include names, case slots or SHA. Aggregate currently VISIBLE scope only.
   const list=visibleRows(), n=$("round").value==="latest"?rounds-1:Number($("round").value)-1;
   const byStage=Object.fromEntries(STAGES.map(s=>[s,list.filter(r=>r.round_stages[n]===s).length]));
   const record={schema:"lightup.private.human-history-visible-counts.v1",authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},historical_only:true,original_round_count:rounds,filtered_visible_count:list.length,filtered_changed_human_slots:list.filter(r=>r.stage_changed_rounds.length||r.private_note_changed_rounds.length).length,selected_explicit_human_round:n+1,proposed_human_stages:byStage};
   download("LightUp-HUMAN-visible-counts.json","application/json",JSON.stringify(record,null,2)+"\n");
 }
 function privateCSV(){
   const list=visibleRows();
   const target=$("ownerFilter").value;
   if(!target || !window.confirm("PRIVATE handoff only for proposed HUMAN owner '"+target+"'. Original labels do not authenticate recipients. Confirm manual PRIVATE CSV creation?")) return;
   const mine=list.filter(r=>r.original_proposed_human_owner===target);
   if(!mine.length){msg("PRIVATE HOLD: no selected original HUMAN owner rows");return;}
   download("LightUp-PRIVATE-HUMAN-owner-visible.csv","text/csv;charset=utf-8",csv(mine));
   msg("PRIVATE owner-scoped CSV saved locally; verify recipient, original source and custody manually. Never authority.");
 }
 function safeSourceFile(file){
   return file && file.size>0 && file.size<=MAX_BYTES && file.name.toLowerCase().endsWith(".json");
 }
 async function load(evt){
   const file=evt.target.files?.[0];
   if(!safeSourceFile(file)){msg("PRIVATE HOLD: select one original native ≤1 MiB JSON history file");return;}
   try{
     const raw=await file.arrayBuffer();
     if(raw.byteLength!==file.size||!raw.byteLength||raw.byteLength>MAX_BYTES)throw Error("Source byte limit");
     const source=new TextDecoder("utf-8",{fatal:true}).decode(raw);
     const doc=parseUniqueJSON(source), parsed=verify(doc);
     
     const digest=(await lightupSha256Hex(raw)).hex;
     history=doc;rawDigest=digest;rows=parsed;rounds=doc.original_human_discussion_rounds.length;
     ownerScoped=doc.owner_scoped_private_export;
     $("ownerFilter").replaceChildren(element("option","All ORIGINAL owners (operator-only)"));
     $("ownerFilter").firstChild.value="";
     const names=[...new Set(rows.map(r=>r.original_proposed_human_owner))].sort();
     for(const name of names){const option=element("option",name);option.value=name;$("ownerFilter").append(option);}
     if(ownerScoped){$("ownerFilter").value=names[0];$("ownerFilter").disabled=true;}
     else $("ownerFilter").disabled=false;
     $("round").replaceChildren(element("option","Latest HUMAN proposal"));
     $("round").firstChild.value="latest";
     for(let i=1;i<=rounds;i++){const o=element("option","Original HUMAN round "+i);o.value=String(i);$("round").append(o);}
     $("change").value="all";$("stage").value="";$("search").value="";
     $("room").hidden=false;
     render();
     msg("PRIVATE HUMAN-only original derived history opened: SHA-256 "+rawDigest+". Browser preview is unsigned, not native authority.");
   }catch(e){msg("PRIVATE HOLD: local original history not admitted ("+(e?.message||"invalid input")+"). Existing preview retained.");}
 }
 ["ownerFilter","round","stage","change"].forEach(k=>$(k).addEventListener("change",render));
 $("search").addEventListener("input",render);
 $("source").addEventListener("change",load);
 $("clear").addEventListener("click",clear);
 $("counts").addEventListener("click",minimal);
 $("ownerCsv").addEventListener("click",privateCSV);
 window.addEventListener("beforeunload",()=>{rows=[];history=null;});
 window.addEventListener("pagehide",clear);
 msg("Select existing native PRIVATE-HUMAN-inbox-history.json; software has no embedded customer or HUMAN data.");
})();