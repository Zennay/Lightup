/* LightUp source-free offline original HUMAN multi-owner reply inbox review.
 * Historical HUMAN proposals only; never authentication, verified remediation,
 * grant, consent, task dispatch, network or scan.
 */
(() => {
"use strict";
const $=id=>document.getElementById(id);
const SCHEMA="lightup.private.workspace-ledger-human-owner-return-inbox.v1";
const FLAGS=["authorization","consent","verified_finding","release_approval"];
const FIELDS=["schema","authority","historical_only","sources_reopened","recipient_authenticated","consent_assumed","actions_dispatched","appointments_booked","verified_remediation","original_history_sha256","original_human_owner_replies_in_explicit_order"];
const GROUP=["original_proposed_human_owner_label","original_selected_human_round","original_selection_sha256","original_human_owner_reply_sha256","human_reply_rows"];
const ROW=["local_case","historical_transition","original_kit","original_round_human_stage","human_reply_stage","private_human_reply_note"];
const STAGES=["needs_discussion","proposed_followup","hold"];
let rawHash="",groups=[],rows=[];
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
       ...r
     });
     if(out.length>2048)throw Error("Too many original native private HUMAN rows");
   }
 }
 return {owners:[...ownerNames],items:out};
}
const e=(tag,value,cls)=>{const x=document.createElement(tag);if(value!==undefined)x.textContent=String(value);if(cls)x.className=cls;return x;};
function status(text){$("status").textContent=text;}
function forget(){
 rawHash="";groups=[];rows=[];
 $("file").value="";$("room").hidden=true;$("cards").replaceChildren();
 $("owners").replaceChildren(e("option","All original proposed HUMAN owners"));
 $("owners").firstChild.value="";$("statusFilter").value="";$("query").value="";
 status("Original PRIVATE HUMAN owner response inbox cleared from this page.");
}
function filtered(){
 const selected=$("owners").value,stage=$("statusFilter").value,query=$("query").value.toLocaleLowerCase().trim();
 return rows.filter(r=>{
    if(selected&&r.owner!==selected)return false;
    if(stage&&r.human_reply_stage!==stage)return false;
    const changed=$("changed").value;
    if(changed==="changed"&&r.original_round_human_stage===r.human_reply_stage)return false;
    if(changed==="same"&&r.original_round_human_stage!==r.human_reply_stage)return false;
    return !query||(r.owner+" "+r.local_case+" "+r.historical_transition+" "+r.original_kit+" "+r.private_human_reply_note).toLocaleLowerCase().includes(query);
 });
}
function render(){
 if(!rawHash)return;
 const visible=filtered(),cards=$("cards");
 cards.replaceChildren();
 const counts=STAGES.map(stage=>stage.replaceAll("_"," ")+": "+visible.filter(r=>r.human_reply_stage===stage).length);
 $("summary").textContent=rows.length+" original PRIVATE HUMAN slots · "+groups.length+" proposed HUMAN owners (labels not identities)";
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
     ["PRIVATE HUMAN note, not security evidence",r.private_human_reply_note||"—"]
   ]){const fact=e("div",undefined,"fact");fact.append(e("strong",key),e("span",value));div.append(fact);}
   article.append(div);cards.append(article);
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
   if(bytes.byteLength!==file.size||!crypto.subtle)throw Error("Original browser byte digest unavailable");
   const doc=parseUniqueJSON(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
   const parsed=admit(doc);
   const hexDigest=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),n=>n.toString(16).padStart(2,"0")).join("");
   rawHash=hexDigest;groups=doc.original_human_owner_replies_in_explicit_order;rows=parsed.items;
   const select=$("owners");select.replaceChildren(e("option","All original proposed HUMAN owners"));select.firstChild.value="";
   for(const owner of parsed.owners){const opt=e("option",owner);opt.value=owner;select.append(opt);}
   $("query").value="";$("statusFilter").value="";$("changed").value="all";
   $("room").hidden=false;render();
   status("PRIVATE owner HUMAN inbox opened locally. Exact unsigned original SHA-256: "+rawHash+". No recipient, permission or security result verified.");
 }catch(error){status("PRIVATE HOLD: original inbox rejected ("+(error?.message||"invalid source")+"). Previously opened local data retained.");}
}
function counts(){
 if(!rawHash)return;
 const v=filtered();
 const by=Object.fromEntries(STAGES.map(k=>[k,v.filter(r=>r.human_reply_stage===k).length]));
 const obj={schema:"lightup.private.anonymous-human-reply-inbox-counts.v1",
   authority:{authorization:false,consent:false,verified_finding:false,release_approval:false},
   historical_only:true,selected_visible_original_rows:v.length,
   human_proposed_statuses:by,
   human_proposed_changes:v.filter(r=>r.human_reply_stage!==r.original_round_human_stage).length};
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
$("clear").addEventListener("click",forget);
window.addEventListener("pagehide",forget);
status("Open exact original PRIVATE-HUMAN-owner-inbox.json from native offline console 47.");
})();