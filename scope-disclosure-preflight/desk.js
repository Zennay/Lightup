"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const ids = ["file","filename","filesize","originalHash","openStatus","rule","addRule","rules","review","clear","matches","residual","outputHash","warnings","preview","prevPage","nextPage","pageInfo","readAll","accept","confirm","exportText","exportReceipt","exportStatus"];
  const e = Object.fromEntries(ids.map(id => [id,$(id)]));
  const encoder = new TextEncoder();
  let source = null, rules = [], prepared = null, page = 0, seen = new Set(), ticket = 0;
  const message = (id,text) => { e[id].textContent = text; };
  const chars = text => [...text].length;
  const hash = async bytes => {
    if (!crypto?.subtle) throw Error("WebCrypto is unavailable");
    return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))].map(v=>v.toString(16).padStart(2,"0")).join("");
  };
  const hits = (text,word) => {
    let c = 0, pos = 0;
    while ((pos=text.indexOf(word,pos))!==-1) { c++; pos+=word.length; }
    return c;
  };
  function lock() {
    e.exportText.disabled = e.exportReceipt.disabled = true;
    e.readAll.checked = e.accept.checked = false; e.confirm.value = "";
    message("exportStatus","Exports require a fresh explicit human confirmation.");
  }
  function gate() {
    const total = prepared ? Math.max(1,Math.ceil(prepared.text.length/8000)) : 0;
    const ok = prepared && seen.size === total && e.readAll.checked && e.accept.checked &&
      e.confirm.value === "EXPORT REDACTED" && source && source.hash === prepared.originalHash;
    e.exportText.disabled = e.exportReceipt.disabled = !ok;
  }
  function invalidate() {
    prepared = null; seen = new Set(); page = 0; e.preview.value = "";
    ["matches","residual","outputHash"].forEach(id=>message(id,"—"));
    message("warnings","No preview prepared.");
    e.warnings.className="warnings";
    message("pageInfo","No pages");
    e.prevPage.disabled=e.nextPage.disabled=true;
    e.review.disabled = !source || rules.length===0;
    lock();
  }
  function clear() {
    ++ticket; source=null; rules=[];
    e.file.value=e.rule.value="";
    message("filename","None");message("filesize","—");message("originalHash","—");
    message("openStatus","Session cleared from application state. Previously downloaded files remain on disk.");
    showRules();invalidate();
  }
  function showRules() {
    e.rules.replaceChildren();
    if (!rules.length) {e.rules.textContent="No masking rules yet.";return;}
    rules.forEach((rule,index)=>{
      const row=document.createElement("div"), text=document.createElement("span"), button=document.createElement("button");
      row.className="rule";button.className="secondary";button.type="button";
      text.textContent="Mask "+(index+1)+" · "+chars(rule)+" characters · "+(source?hits(source.text,rule):0)+" literal hits before overlap";
      button.textContent="Remove "+(index+1);
      button.onclick=()=>{rules.splice(index,1);showRules();invalidate();};
      row.append(text,button);e.rules.append(row);
    });
  }
  e.file.addEventListener("change",async()=>{
    const file=e.file.files?.[0], current=++ticket;
    source=null;rules=[];showRules();invalidate();
    message("filename","None");message("filesize","—");message("originalHash","—");
    if (!file) return;
    if (!/^[^/\x00-\x1f]{1,120}\.(txt|csv|json|md|log)$/i.test(file.name) ||
        file.size===0 || file.size>2*1024*1024) {
      message("openStatus","HOLD: choose nonempty UTF-8 text with a safe filename, maximum 2 MiB.");
      e.file.value="";return;
    }
    try{
      const raw=new Uint8Array(await file.arrayBuffer());
      if (current!==ticket) return;
      const text=new TextDecoder("utf-8",{fatal:true}).decode(raw);
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) throw Error("Control bytes");
      const sha=await hash(raw);
      if(current!==ticket)return;
      source={text,hash:sha,bytes:raw.length};
      message("filename",file.name);message("filesize",raw.length.toLocaleString()+" bytes");
      message("originalHash",sha.slice(0,12)+"…");
      message("openStatus","PRIVATE original loaded into memory; original bytes are not modified.");
      e.file.value=""; invalidate();
    }catch(err){
      if(current!==ticket)return;
      message("openStatus","HOLD: invalid UTF-8, binary data, unreadable file or unavailable cryptography.");
      e.file.value="";
    }
  });
  e.addRule.onclick=()=>{
    if(!source){message("openStatus","Choose a PRIVATE source first.");return;}
    const raw=e.rule.value;e.rule.value="";
    if(chars(raw)<3 || chars(raw)>128 || /[\x00-\x1f]/.test(raw) ||
        raw.includes("[REDACTED]") || !raw.trim() || rules.includes(raw) ||
        rules.length>=30 || !source.text.includes(raw)){
      message("openStatus","HOLD: literal must be unique, present, single-line, 3–128 characters; at most 30 rules.");
      return;
    }
    rules.push(raw);showRules();invalidate();
    message("openStatus","Exact literal mask added. Rule content is never rendered in the list.");
  };
  const quote = text => text.replace(/[-/\\^$*+?.()|[\]{}]/g,"\\$&");
  function hints(text){
    const expressions=[
      ["email",/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
      ["URL",/\bhttps?:\/\/[^\s"'<>]+/gi],
      ["Bearer",/\bBearer\s+[a-z0-9._~+/-]{8,}/gi],
      ["credential-like",/\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;}]{3,}/gi],
      ["private key",/-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
      ["IPv4-like",/\b(?:\d{1,3}\.){3}\d{1,3}\b/g]
    ];
    return expressions.map(([label,re])=>{
      let count=0;
      while(re.exec(text)!==null && count<1000) count++;
      return [label,count];
    }).filter(v=>v[1]>0);
  }
  function showPage(n) {
    if(!prepared)return;
    const total=Math.max(1,Math.ceil(prepared.text.length/8000));
    page=Math.max(0,Math.min(total-1,n));seen.add(page);
    e.preview.value=prepared.text.slice(page*8000,(page+1)*8000);
    e.prevPage.disabled=page===0;e.nextPage.disabled=page===total-1;
    message("pageInfo","Page "+(page+1)+"/"+total+" · "+seen.size+" pages opened");
    e.readAll.checked=false;gate();
  }
  e.prevPage.onclick=()=>showPage(page-1);
  e.nextPage.onclick=()=>showPage(page+1);
  e.review.onclick=async()=>{
    if(!source || !rules.length)return;
    const current=++ticket;
    invalidate();e.review.disabled=true;
    try{
      const ordered=[...rules].sort((a,b)=>b.length-a.length);
      const rx=new RegExp(ordered.map(quote).join("|"),"g");
      let count=0;
      const text=source.text.replace(rx,()=>{count++;return "[REDACTED]";});
      if(count===0)throw Error("No replacements");
      const bytes=encoder.encode(text);
      if(bytes.length>8*1024*1024)throw Error("Output too large");
      const sha=await hash(bytes);
      if(current!==ticket || !source)return;
      const remaining=hints(text);
      prepared={text,sha,bytes:bytes.length,count,remaining,originalHash:source.hash};
      message("matches",String(count));
      message("residual",String(remaining.reduce((n,r)=>n+r[1],0)));
      message("outputHash",sha.slice(0,12)+"…");
      e.warnings.className=remaining.length?"warnings warn":"warnings good";
      message("warnings",remaining.length?
        "Potential sensitive patterns remain: "+remaining.map(x=>x[0]+" "+x[1]+(x[1]===1000?"+":"")).join("; ")+". Not exhaustive.":
        "No heuristic pattern matches; this does not imply safe sharing. Inspect the entire file.");
      seen=new Set();showPage(0);
      message("exportStatus","Review every page, then confirm privately.");
    }catch(err){
      if(current!==ticket)return;
      e.warnings.className="warnings warn";
      message("warnings","HOLD: failed to prepare a bounded full-file redacted preview.");
    }finally{if(current===ticket)e.review.disabled=!source || !rules.length;}
  };
  ["readAll","accept","confirm"].forEach(id=>{
    e[id].addEventListener("change",gate);
    e[id].addEventListener("input",gate);
  });
  function download(bytes,name,type){
    const uri=URL.createObjectURL(new Blob([bytes],{type}));
    const a=document.createElement("a");a.href=uri;a.download=name;a.style.display="none";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(uri),30000);
  }
  function verified(){
    gate();
    if(e.exportText.disabled || e.exportReceipt.disabled)throw Error("No approval");
  }
  function finish(label){
    lock();message("exportStatus",label+" downloaded locally. This is HUMAN preparation, not consent or authorization.");
  }
  e.exportText.onclick=()=>{
    try{verified();download(prepared.text,"lightup-private-redacted.txt","text/plain;charset=utf-8");finish("Redacted text");}
    catch(err){message("exportStatus","HOLD: review and reconfirm before exporting.");}
  };
  e.exportReceipt.onclick=()=>{
    try{
      verified();
      const report={
        schema:"lightup-private-disclosure-human-v1",
        purpose:"Local human disclosure preparation, not verified clearance or authenticated origin",
        output_sha256:prepared.sha,output_bytes:prepared.bytes,replacements:prepared.count,
        mask_rules:rules.length,residual_hints:Object.fromEntries(prepared.remaining),
        authorization:false,client_consent:false,operator_consent:false,
        revocation_at_use_verified:false,scanning_permitted:false,release_approved:false
      };
      download(JSON.stringify(report,null,2)+"\n","lightup-private-disclosure-receipt.json","application/json");
      finish("PRIVATE receipt");
    }catch(err){message("exportStatus","HOLD: review and reconfirm before exporting.");}
  };
  e.clear.onclick=clear;
  invalidate();
})();