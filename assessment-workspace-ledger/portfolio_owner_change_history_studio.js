/* Source-free LightUp PRIVATE original HUMAN operator history explorer.
 * Read-only preview of one original native single-owner history JSON. No
 * original HUMAN free-text notes, network, consent, identity or actual action.
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
const SCHEMA="lightup.private.workspace-ledger-human-operator-change-history.v1";
const KEYS=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_owner_inbox_sha256","original_history_sha256","original_proposed_human_owner_label","original_human_operator_rounds","human_proposed_history_rows"];
const AUTH=["authorization","consent","verified_finding","release_approval"];
const ROUND=["ordinal","receipt_sha256","original_csv_sha256"];
const ROW=["original_proposed_human_owner_label","local_case","historical_transition","original_kit","original_owner_human_reply_stage","first_human_operator_stage","latest_human_operator_stage","human_stage_changed_in_rounds","private_human_note_changed_in_rounds","human_operator_stage_by_round"];
const STAGES=["needs_discussion","proposed_followup","hold"];
const MAX=1048576;
let records=[],original=null,rawHash="";
const exact=(x,keys)=>!!x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const hexdigest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const safeName=x=>typeof x==="string"&&x.length>0&&x.length<=80&&x.trim()===x&&!/[\u0000-\u001f\u007f]/.test(x)&&!/^s*[=+@-]/.test(x);
function uniqueJson(raw){
 let at=0;
 const number=/-?(?:0|[1-9]d*)(?:.d+)?(?:[eE][+-]?d+)?/y;
 const word=/(?:true|false|null)/y;
 const ws=()=>{while(at<raw.length&&/[\r\n\t ]/.test(raw[at]))at++;};
 function quoted(){
   if(raw[at]!=='"')throw Error("Invalid source JSON quote");
   const first=at++;
   while(at<raw.length){
     let c=raw[at++];
     if(c==='"')return JSON.parse(raw.slice(first,at));
     if(c==="\\"){if(at===raw.length)throw Error("Invalid JSON escape");at++;}
   }
   throw Error("Incomplete source string");
 }
 function next(depth){
   if(depth>64)throw Error("Original source depth limit");
   ws();
   if(raw[at]==='{'){
     at++;ws();const seen=new Set();
     if(raw[at]==='}'){at++;return;}
     while(true){
       ws();const name=quoted();
       if(seen.has(name))throw Error("Duplicate original JSON key");
       seen.add(name);ws();if(raw[at++]!==':')throw Error("Invalid source JSON colon");
       next(depth+1);ws();const end=raw[at++];
       if(end==='}')return;
       if(end!==',')throw Error("Invalid source JSON object delimiter");
     }
   }
   if(raw[at]==='['){
     at++;ws();if(raw[at]===']'){at++;return;}
     while(true){
       next(depth+1);ws();const end=raw[at++];
       if(end===']')return;
       if(end!==',')throw Error("Invalid source JSON array delimiter");
     }
   }
   if(raw[at]==='"'){quoted();return;}
   number.lastIndex=at;const n=number.exec(raw);if(n){at=number.lastIndex;return;}
   word.lastIndex=at;const w=word.exec(raw);if(w){at=word.lastIndex;return;}
   throw Error("Invalid original source JSON token");
 }
 next(0);ws();
 if(at!==raw.length)throw Error("Trailing JSON bytes");
 return JSON.parse(raw);
}
function validate(doc){
 if(!exact(doc,KEYS)||doc.schema!==SCHEMA||!exact(doc.authority,AUTH)||
   !AUTH.every(k=>doc.authority[k]===false)||doc.historical_only!==true||
   !["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(k=>doc[k]===false)||
   !hexdigest(doc.original_owner_inbox_sha256)||!hexdigest(doc.original_history_sha256)||
   !safeName(doc.original_proposed_human_owner_label)||
   !Array.isArray(doc.original_human_operator_rounds)||
   doc.original_human_operator_rounds.length<2||doc.original_human_operator_rounds.length>8||
   !Array.isArray(doc.human_proposed_history_rows)||
   !doc.human_proposed_history_rows.length||doc.human_proposed_history_rows.length>2048)
   throw Error("Not native original private HUMAN operator history");
 const known=new Set(),roundHashes=new Set(),total=doc.original_human_operator_rounds.length;
 for(const [i,r] of doc.original_human_operator_rounds.entries()){
   if(!exact(r,ROUND)||r.ordinal!==i+1||
     !hexdigest(r.receipt_sha256)||!hexdigest(r.original_csv_sha256)||
     roundHashes.has(r.receipt_sha256))throw Error("Historical original HUMAN version invalid");
   roundHashes.add(r.receipt_sha256);
 }
 for(const r of doc.human_proposed_history_rows){
   const id=r?.local_case+":"+r?.historical_transition+":"+r?.original_kit;
   if(!exact(r,ROW)||r.original_proposed_human_owner_label!==doc.original_proposed_human_owner_label||
     !Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
     !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
     !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
     known.has(id)||!STAGES.includes(r.original_owner_human_reply_stage)||
     !STAGES.includes(r.first_human_operator_stage)||!STAGES.includes(r.latest_human_operator_stage)||
     !Array.isArray(r.human_operator_stage_by_round)||r.human_operator_stage_by_round.length!==total||
     !r.human_operator_stage_by_round.every(s=>STAGES.includes(s))||
     r.human_operator_stage_by_round[0]!==r.first_human_operator_stage||
     r.human_operator_stage_by_round[total-1]!==r.latest_human_operator_stage||
     !Array.isArray(r.human_stage_changed_in_rounds)||
     !Array.isArray(r.private_human_note_changed_in_rounds))
       throw Error("Original HUMAN historical row inconsistent");
   const expected=[];
   for(let i=1;i<total;i++){
     if(r.human_operator_stage_by_round[i]!==r.human_operator_stage_by_round[i-1])expected.push(i+1);
   }
   if(JSON.stringify(expected)!==JSON.stringify(r.human_stage_changed_in_rounds))
     throw Error("Stage changes do not match original source");
   const notes=r.private_human_note_changed_in_rounds;
   if(notes.some((v,i)=>!Number.isInteger(v)||v<2||v>total||(i>0&&v<=notes[i-1])))
     throw Error("Invalid PRIVATE HUMAN note change rounds");
   known.add(id);
 }
 return doc.human_proposed_history_rows.slice();
}
const element=(tag,text,cls)=>{
 const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);
 if(cls)e.className=cls;return e;
};
const say=x=>{$("status").textContent=x;};
function clear(){
 original=null;records=[];rawHash="";
 $("source").value="";$("room").hidden=true;$("cards").replaceChildren();
 $("query").value="";$("round").replaceChildren(element("option","Latest original HUMAN round"));
 $("round").firstChild.value="latest";$("stage").value="";$("changed").value="all";
 say("Original private HUMAN browser memory cleared.");
}
function choice(){
 return $("round").value==="latest"?original.original_human_operator_rounds.length-1:Number($("round").value)-1;
}
function filtered(){
 const n=choice(),stage=$("stage").value,changed=$("changed").value,
 term=$("query").value.trim().toLocaleLowerCase();
 return records.filter(r=>{
   if(stage&&r.human_operator_stage_by_round[n]!==stage)return false;
   if(changed==="stage"&&!r.human_stage_changed_in_rounds.length)return false;
   if(changed==="note"&&!r.private_human_note_changed_in_rounds.length)return false;
   if(changed==="both"&&!(r.human_stage_changed_in_rounds.length&&r.private_human_note_changed_in_rounds.length))return false;
   if(changed==="stable"&&(r.human_stage_changed_in_rounds.length||r.private_human_note_changed_in_rounds.length))return false;
   return !term||(
       r.local_case+" "+r.historical_transition+" "+r.original_kit+" "+
       r.human_operator_stage_by_round.join(" ")
   ).toLocaleLowerCase().includes(term);
 });
}
function render(){
 if(!original)return;
 const subset=filtered(),round=choice(),cards=$("cards");cards.replaceChildren();
 $("summary").textContent=records.length+" ORIGINAL HUMAN owner proposal slots • "+
 original.original_human_operator_rounds.length+" manually ordered HUMAN versions • "+
 "one original proposed owner (NOT authenticated)";
 $("visible").textContent=subset.length+" visible HUMAN slots · "+
 STAGES.map(s=>s.replaceAll("_"," ")+": "+subset.filter(r=>r.human_operator_stage_by_round[round]===s).length).join(" · ");
 for(const r of subset){
   const article=element("article",undefined,"card");
   article.append(element("h3","Original HUMAN source "+r.local_case+" / "+r.historical_transition+" / "+r.original_kit));
   const facts=element("div",undefined,"facts");
   for(const [k,v] of [
     ["Original received HUMAN owner stage",r.original_owner_human_reply_stage],
     ["HUMAN operator proposal in selected round",r.human_operator_stage_by_round[round]],
     ["Manual HUMAN stage progression",r.human_operator_stage_by_round.join(" → ")],
     ["HUMAN stage changed in rounds",r.human_stage_changed_in_rounds.join(", ")||"none"],
     ["PRIVATE note changed in rounds (not contents)",r.private_human_note_changed_in_rounds.join(", ")||"none"]
   ]){const row=element("div",undefined,"fact");
      row.append(element("strong",k),element("span",v));facts.append(row);}
   article.append(facts);cards.append(article);
 }
 if(!subset.length)cards.append(element("p","No original HUMAN proposal matches. This does NOT prove remediation."));
}
async function openFile(event){
 const file=event.target.files?.[0];
 if(!file||file.size<=0||file.size>MAX||!file.name.toLowerCase().endsWith(".json")){
   say("PRIVATE HOLD: one original owner-private native history JSON ≤1 MiB required");return;
 }
 try{
   const buffer=await file.arrayBuffer();
   if(buffer.byteLength!==file.size)throw Error("Source byte mismatch");
   const doc=uniqueJson(new TextDecoder("utf-8",{fatal:true}).decode(buffer));
   const items=validate(doc);
   const hash=(await lightupSha256Hex(buffer)).hex;
   original=doc;records=items;rawHash=hash;
   const s=$("round");s.replaceChildren(element("option","Latest HUMAN proposal"));
   s.firstChild.value="latest";
   for(let i=1;i<=doc.original_human_operator_rounds.length;i++){
      const option=element("option","Manually ordered HUMAN version "+i);option.value=String(i);s.append(option);
   }
   $("query").value="";$("stage").value="";$("changed").value="all";
   $("room").hidden=false;render();
   say("PRIVATE HUMAN-only history locally opened. Unsigned SHA-256: "+rawHash+". No authenticated person or security verdict.");
 }catch(e){say("PRIVATE HOLD: original history rejected ("+(e?.message||"invalid")+"). Existing view retained.");}
}
function exportCounts(){
 if(!original)return;
 const items=filtered(),at=choice();
 const summary={
    schema:"lightup.private.anonymous-human-operator-version-counts.v1",
    authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},
    historical_only:true,selected_human_round:at+1,
    visible_original_human_slots:items.length,
    proposed_human_stages:Object.fromEntries(STAGES.map(s=>[
       s,items.filter(r=>r.human_operator_stage_by_round[at]===s).length])),
    stage_changed_human_slots:items.filter(r=>r.human_stage_changed_in_rounds.length).length,
    private_note_changed_human_slots:items.filter(r=>r.private_human_note_changed_in_rounds.length).length,
 };
 const url=URL.createObjectURL(new Blob([JSON.stringify(summary,null,2)+"\n"],{type:"application/json"}));
 const a=element("a");a.href=url;a.download="LightUp-anonymous-HUMAN-operator-history-counts.json";
 document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),500);
 say("Anonymous HUMAN-only original counts exported; no owner labels or original source IDs.");
}
$("source").addEventListener("change",openFile);
$("round").addEventListener("change",render);
$("stage").addEventListener("change",render);
$("changed").addEventListener("change",render);
$("query").addEventListener("input",render);
$("clear").addEventListener("click",clear);
$("counts").addEventListener("click",exportCounts);
window.addEventListener("pagehide",clear);
say("Choose original PRIVATE-HUMAN-operator-version-history.json. Software contains no original client/HUMAN data.");
})();
