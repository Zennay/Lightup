/* LightUp source-free offline original HUMAN owner follow-up Studio.
 * Historical HUMAN proposals only; never authentication, verified remediation,
 * grant, consent, task dispatch, network or scan.
 */
(() => {
"use strict";
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

const $=id=>document.getElementById(id);
const SCHEMA="lightup.private.workspace-ledger-human-owner-return-inbox.v1";
const FLAGS=["authorization","consent","verified_finding","release_approval"];
const FIELDS=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_history_sha256","original_human_owner_replies_in_explicit_order"];
const GROUP=["original_proposed_human_owner_label","original_selected_human_round","original_selection_sha256","original_human_owner_reply_sha256","human_reply_rows"];
const ROW=["local_case","historical_transition","original_kit","original_round_human_stage","human_reply_stage","private_human_reply_note"];
const STAGES=["needs_discussion","proposed_followup","hold"];
let rawHash="",groups=[],rows=[],dirty=false;
const CSV=["original_owner_inbox_sha256","original_proposed_human_owner_label","local_case","historical_transition","original_kit","original_round_human_stage","original_owner_human_reply_stage","human_operator_followup_stage","private_human_followup_note"];
const exact=(x,k)=>x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const hex=x=>typeof x==="string"&&/^[0-9a-f]{64}$/.test(x);
const name=x=>typeof x==="string"&&x.length>0&&x.length<=80&&x===x.trim()&&!/[\u0000-\u001f\u007f]/.test(x)&&!/^\s*[=+@-]/.test(x);
const note=x=>typeof x==="string"&&x.length<=240&&!/[\u0000-\u001f\u007f]/.test(x)&&!/^\s*[=+@-]/.test(x);
function parseUniqueJSON(source){
 let at=0;
 const number=/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
 const literal=/(?:true|false|null)/y;
 const space=()=>{while(at<source.length&&/[\r\n\t ]/.test(source[at]))at++;};
 function quoted(){
   if(source[at]!=='"')throw Error("Malformed original private JSON");
   const start=at++;
   while(at<source.length){
     const c=source[at++];
     if(c==='"')return JSON.parse(source.slice(start,at));
     if(c==="\\"){if(at===source.length)throw Error("Truncated JSON escape");at++;}
   }
   throw Error("Original JSON string incomplete");
 }
 function value(level){
   if(level>64)throw Error("Original JSON nesting limit");
   space();
   if(source[at]==='{'){
     at++;space();const found=new Set();
     if(source[at]==='}'){at++;return;}
     while(true){
       space();const key=quoted();
       if(found.has(key))throw Error("Duplicate key in original private JSON");
       found.add(key);space();
       if(source[at++]!==':')throw Error("Malformed original JSON member");
       value(level+1);space();
       const end=source[at++];if(end==='}')return;
       if(end!==',')throw Error("Malformed original JSON object");
     }
   }
   if(source[at]==='['){
     at++;space();if(source[at]===']'){at++;return;}
     while(true){
       value(level+1);space();
       const end=source[at++];if(end===']')return;
       if(end!==',')throw Error("Malformed original JSON array");
     }
   }
   if(source[at]==='"'){quoted();return;}
   number.lastIndex=at;const n=number.exec(source);if(n){at=number.lastIndex;return;}
   literal.lastIndex=at;const word=literal.exec(source);if(word){at=literal.lastIndex;return;}
   throw Error("Invalid original private JSON token");
 }
 value(0);space();
 if(at!==source.length)throw Error("Trailing original private JSON bytes");
 return JSON.parse(source);
}
function admit(doc){
 if(!exact(doc,FIELDS)||doc.schema!==SCHEMA||!exact(doc.authority,FLAGS)||
    !FLAGS.every(x=>doc.authority[x]===false)||doc.historical_only!==true||
    !["sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation"].every(k=>doc[k]===false)||
    !hex(doc.original_history_sha256)||!Array.isArray(doc.original_human_owner_replies_in_explicit_order)||
    doc.original_human_owner_replies_in_explicit_order.length<1||
    doc.original_human_owner_replies_in_explicit_order.length>8)
    throw Error("Not original native HUMAN owner reply inbox");
 const out=[],ownerNames=new Set(),ids=new Set();
 for(const g of doc.original_human_owner_replies_in_explicit_order){
   if(!exact(g,GROUP)||!name(g.original_proposed_human_owner_label)||
      ownerNames.has(g.original_proposed_human_owner_label)||
      !Number.isInteger(g.original_selected_human_round)||g.original_selected_human_round<1||g.original_selected_human_round>8||
      !hex(g.original_selection_sha256)||!hex(g.original_human_owner_reply_sha256)||
      !Array.isArray(g.human_reply_rows)||!g.human_reply_rows.length)throw Error("Invalid original proposed HUMAN owner group");
   ownerNames.add(g.original_proposed_human_owner_label);
   for(const r of g.human_reply_rows){
     if(!exact(r,ROW)||!Number.isInteger(r.local_case)||r.local_case<1||r.local_case>8||
        !Number.isInteger(r.historical_transition)||r.historical_transition<1||r.historical_transition>11||
        !Number.isInteger(r.original_kit)||r.original_kit<1||r.original_kit>12||
        !STAGES.includes(r.original_round_human_stage)||!STAGES.includes(r.human_reply_stage)||
        !note(r.private_human_reply_note))throw Error("Invalid original native HUMAN reply row");
     const id=r.local_case+":"+r.historical_transition+":"+r.original_kit;
     if(ids.has(id))throw Error("Duplicate original human source slot");
     ids.add(id);
     out.push({
       owner:g.original_proposed_human_owner_label,
       selectedRound:g.original_selected_human_round,
       selectedPacketSha:g.original_selection_sha256,
       replyPacketSha:g.original_human_owner_reply_sha256,
       ...r, followupStage:"needs_discussion", followupNote:""
     });
     if(out.length>2048)throw Error("Too many original native private HUMAN rows");
   }
 }
 return {owners:[...ownerNames],items:out};
}
const e=(tag,value,cls)=>{const x=document.createElement(tag);if(value!==undefined)x.textContent=String(value);if(cls)x.className=cls;return x;};
function status(text){$("status").textContent=text;}
function forget(){
 rawHash="";groups=[];rows=[];dirty=false;
 $("file").value="";$("restore").value="";$("room").hidden=true;$("cards").replaceChildren();
 $("owners").replaceChildren(e("option","All original proposed HUMAN owners"));
 $("owners").firstChild.value="";$("statusFilter").value="";$("query").value="";
 status("Original PRIVATE HUMAN owner response inbox cleared from this page.");
}
function filtered(){
 const selected=$("owners").value,stage=$("statusFilter").value,query=$("query").value.toLocaleLowerCase().trim();
 return rows.filter(r=>{
    if(selected&&r.owner!==selected)return false;
    if(stage&&r.followupStage!==stage)return false;
    const changed=$("changed").value;
    if(changed==="changed"&&r.original_round_human_stage===r.human_reply_stage)return false;
    if(changed==="same"&&r.original_round_human_stage!==r.human_reply_stage)return false;
    return !query||(r.owner+" "+r.local_case+" "+r.historical_transition+" "+r.original_kit+" "+r.private_human_reply_note+" "+r.followupNote).toLocaleLowerCase().includes(query);
 });
}
function renderCount(){
 if(!rawHash)return;
 $("summary").textContent=rows.length+" original owner reply rows · "+
  STAGES.map(k=>k.replaceAll("_"," ")+": "+rows.filter(r=>r.followupStage===k).length).join(" · ")+
  " · "+rows.filter(r=>r.followupNote).length+" new PRIVATE HUMAN operator notes"+
  (dirty?" · local draft changed":"");
}
function render(){
 if(!rawHash)return;
 const visible=filtered(),cards=$("cards");
 cards.replaceChildren();
 const counts=STAGES.map(stage=>stage.replaceAll("_"," ")+": "+visible.filter(r=>r.followupStage===stage).length);
 renderCount();
 $("filtered").textContent=visible.length+" visible original slots · "+counts.join(" · ");
 for(const r of visible){
   const article=e("article",undefined,"card");
   article.append(e("h3","Original source "+r.local_case+" / "+r.historical_transition+" / "+r.original_kit));
   const div=e("div",undefined,"facts");
   for(const [key,value] of [
     ["Proposed HUMAN owner (NOT authenticated)",r.owner],
     ["Original HUMAN selected round",r.selectedRound],
     ["Original HUMAN proposal",r.original_round_human_stage],
     ["Received HUMAN-only reply proposal",r.human_reply_stage],
     ["Original PRIVATE owner note (not verified evidence)",r.private_human_reply_note||"—"]
   ]){const fact=e("div",undefined,"fact");fact.append(e("strong",key),e("span",value));div.append(fact);}
   article.append(div);
   const edit=e("div",undefined,"edit");
   const stageLabel=e("label","New HUMAN-only OPERATOR proposed follow-up");
   const select=e("select");
   for(const value of STAGES){
      const opt=e("option",value.replaceAll("_"," "));
      opt.value=value; opt.selected=r.followupStage===value;select.append(opt);
   }
   select.addEventListener("change",()=>{r.followupStage=select.value;dirty=true;renderCount();});
   stageLabel.append(select);
   const noteLabel=e("label","PRIVATE operator HUMAN note (max 240, no formulas)");
   const box=e("textarea");box.rows=3;box.maxLength=240;box.value=r.followupNote;
   box.addEventListener("input",()=>{
      if(!note(box.value)){box.value=r.followupNote;status("PRIVATE HOLD: invalid note, last safe HUMAN text retained");return;}
      r.followupNote=box.value;dirty=true;renderCount();
   });
   noteLabel.append(box);edit.append(stageLabel,noteLabel);
   article.append(edit);cards.append(article);
 }
 if(!visible.length)cards.append(e("p","No HUMAN response matches these filters; no real work state is implied."));
}
async function open(evt){
 const file=evt.target.files?.[0];
 if(!file||file.size<=0||file.size>1048576||!file.name.toLowerCase().endsWith(".json")){
   status("PRIVATE HOLD: one original native owner inbox JSON ≤1 MiB required");return;
 }
 try{
   const bytes=await file.arrayBuffer();
   if(bytes.byteLength!==file.size)throw Error("Source bytes changed during local read");
   const doc=parseUniqueJSON(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
   const parsed=admit(doc);
   const hexDigest=(await lightupSha256Hex(bytes)).hex;
   if(rawHash&&dirty&&!window.confirm("Discard unsaved PRIVATE HUMAN operator proposals?"))return;
   rawHash=hexDigest;groups=doc.original_human_owner_replies_in_explicit_order;rows=parsed.items;dirty=false;
   const select=$("owners");select.replaceChildren(e("option","All original proposed HUMAN owners"));select.firstChild.value="";
   for(const owner of parsed.owners){const opt=e("option",owner);opt.value=owner;select.append(opt);}
   $("query").value="";$("statusFilter").value="";$("changed").value="all";
   $("room").hidden=false;render();
   status("PRIVATE owner HUMAN inbox opened locally. Exact unsigned original SHA-256: "+rawHash+". No recipient, permission or security result verified.");
 }catch(error){status("PRIVATE HOLD: original inbox rejected ("+(error?.message||"invalid source")+"). Previously opened local data retained.");}
}
function parseCSV(text){
 // Strict RFC4180 fields; quotes escaped as doubled double quotes.
 let i=0,field="",record=[],result=[],inQuote=false,closedQuote=false;
 while(i<text.length){
   const c=text[i++];
   if(inQuote){
     if(c==='"'){
       if(text[i]==='"'){field+='"';i++;}
       else{inQuote=false;closedQuote=true;}
     }else field+=c;
   }else if(c==='"'){
     if(field!==""||closedQuote)throw Error("Malformed quoted CSV");
     inQuote=true;
   }else if(c===','){
     record.push(field);field="";closedQuote=false;
   }else if(c==='\r'||c==='\n'){
     if(c==='\r'){if(text[i]!=='\n')throw Error("Noncanonical CSV newline");i++;}
     record.push(field);result.push(record);record=[];field="";closedQuote=false;
   }else{
     if(closedQuote)throw Error("CSV text after closing quote");
     field+=c;
   }
 }
 if(inQuote||field||record.length)throw Error("CSV truncated");
 return result;
}
function csv(){
 const quote=x=>'"'+String(x).replaceAll('"','""')+'"';
 const records=[CSV.join(",")];
 for(const r of rows){
   if(!STAGES.includes(r.followupStage)||!note(r.followupNote))
     throw Error("Invalid HUMAN-only operator stage or PRIVATE note");
   records.push([
     rawHash,r.owner,r.local_case,r.historical_transition,r.original_kit,
     r.original_round_human_stage,r.human_reply_stage,
     r.followupStage,r.followupNote
   ].map(quote).join(","));
 }
 return records.join("\r\n")+"\r\n";
}
function exportReply(){
 if(!rawHash)return;
 if(!window.confirm("Export complete ORIGINAL source-bound PRIVATE HUMAN OPERATOR follow-up CSV? No real task or verified finding follows."))return;
 try{
   const data=csv(),url=URL.createObjectURL(new Blob([data],{type:"text/csv;charset=utf-8"}));
   const a=e("a");a.href=url;a.download="HUMAN-operator-followup-template.csv";
   document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),500);
   dirty=false;renderCount();
   status("PRIVATE complete HUMAN-only operator CSV saved. Original native receive required.");
 }catch(error){status("PRIVATE HOLD: HUMAN CSV rejected ("+(error?.message||"invalid")+").");}
}
async function restoreReply(event){
 const file=event.target.files?.[0];
 if(!rawHash||!file||file.size<=0||file.size>1048576){
   status("PRIVATE HOLD: open an ORIGINAL native inbox and bounded HUMAN draft first.");
   return;
 }
 try{
   const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
   const parsed=parseCSV(raw);
   if(parsed.length!==rows.length+1||JSON.stringify(parsed[0])!==JSON.stringify(CSV))
       throw Error("Incomplete or foreign original HUMAN draft");
   const pending=[];
   for(let i=0;i<rows.length;i++){
     const r=rows[i],item=parsed[i+1];
     const expected=[
       rawHash,r.owner,String(r.local_case),String(r.historical_transition),
       String(r.original_kit),r.original_round_human_stage,r.human_reply_stage
     ];
     if(item.length!==CSV.length||expected.some((value,j)=>item[j]!==value)||
       !STAGES.includes(item[7])||!note(item[8]))
       throw Error("Source-exact HUMAN owner slot/status mismatch");
     pending.push([item[7],item[8]]);
   }
   if(!window.confirm("Restore COMPLETE original source-bound HUMAN operator draft? Existing local proposals will be replaced; native receipt remains required."))return;
   for(let i=0;i<rows.length;i++){
      rows[i].followupStage=pending[i][0];
      rows[i].followupNote=pending[i][1];
   }
   dirty=true;render();
   status("Original source-exact HUMAN follow-up draft restored locally; no permission or task assigned.");
 }catch(err){
   status("PRIVATE HOLD: original HUMAN draft refused. Current choices preserved ("+
          (err?.message||"invalid source")+").");
 }finally{event.target.value="";}
}
function counts(){
 if(!rawHash)return;
 const v=filtered();
 const by=Object.fromEntries(STAGES.map(k=>[k,v.filter(r=>r.followupStage===k).length]));
 const obj={schema:"lightup.private.anonymous-human-reply-inbox-counts.v1",
   authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},
   historical_only:true,selected_visible_original_rows:v.length,
   human_proposed_statuses:by,
   human_proposed_changes:v.filter(r=>r.followupStage!==r.human_reply_stage).length};
 const url=URL.createObjectURL(new Blob([JSON.stringify(obj,null,2)+"\n"],{type:"application/json"}));
 const a=e("a");a.href=url;a.download="LightUp-HUMAN-visible-owner-reply-counts.json";
 document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),500);
 status("Anonymous counts-only HUMAN proposal overview saved locally; does not contain owner labels or note text.");
}
$("file").addEventListener("change",open);
$("owners").addEventListener("change",render);
$("statusFilter").addEventListener("change",render);
$("changed").addEventListener("change",render);
$("query").addEventListener("input",render);
$("counts").addEventListener("click",counts);
$("export").addEventListener("click",exportReply);
$("restore").addEventListener("change",restoreReply);
$("clear").addEventListener("click",forget);
window.addEventListener("beforeunload",event=>{
 if(dirty){event.preventDefault();event.returnValue="";}
});
window.addEventListener("pagehide",forget);
status("Open exact original PRIVATE-HUMAN-owner-inbox.json from native offline console 47.");
})();