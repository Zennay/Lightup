"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const ids = ["file","filename","filesize","originalHash","openStatus","rule","addRule","rules","suggestCredentials","suggestEmail","suggestNetwork","stageSuggestions","suggestStatus","maskPrivateBlocks","pemStatus","review","clear","matches","residual","outputHash","warnings","preview","prevPage","nextPage","pageInfo","reviewSearch","reviewFindPrev","reviewFindNext","reviewFindStatus","readAll","accept","confirm","exportText","exportReceipt","exportStatus","humanReplyFile","importHuman","humanReturnStatus","humanReturnOutcome","humanReturnNote"];
  const e = Object.fromEntries(ids.map(id => [id,$(id)]));
  const encoder = new TextEncoder();
  let source = null, rules = [], prepared = null, page = 0, seen = new Set(), ticket = 0, revision = 0;
  const message = (id,text) => { e[id].textContent = text; };
  const chars = text => [...text].length;
  // Reject visually deceptive invisible direction controls in PRIVATE notes;
  // preserve ordinary multilingual joiners and line breaks.
  const unsafeHumanText = value => /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/u.test(value);
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
    const ok = prepared && !prepared.highRisk && seen.size === total && e.readAll.checked && e.accept.checked &&
      e.confirm.value === "EXPORT REDACTED" && source && source.hash === prepared.originalHash;
    e.exportText.disabled = e.exportReceipt.disabled = !ok;
  }
  function invalidate() {
    revision++; // invalidate async preview calculations when the human changes masks or source
    prepared = null; seen = new Set(); page = 0; e.preview.value = "";
    e.reviewSearch.value="";searchMatches=[];searchIndex=-1;updateSearchNav();
    ["matches","residual","outputHash"].forEach(id=>message(id,"—"));
    message("warnings","No preview prepared.");
    e.warnings.className="warnings";
    message("pageInfo","No pages");
    e.prevPage.disabled=e.nextPage.disabled=true;
    e.review.disabled = !source || (rules.length===0 && !e.maskPrivateBlocks.checked);
    e.stageSuggestions.disabled = !source;
    e.maskPrivateBlocks.disabled = !source;
    e.importHuman.disabled = true;
    e.humanReplyFile.value="";
    e.humanReturnOutcome.textContent="";e.humanReturnNote.value="";
    message("humanReturnStatus","Prepare the exact current redacted preview before importing feedback.");
    lock();
  }
  function clear() {
    ++ticket; source=null; rules=[];e.maskPrivateBlocks.checked=false;
    e.file.value=e.rule.value="";
    message("filename","None");message("filesize","—");message("originalHash","—");
    message("openStatus","Session cleared from application state. Previously downloaded files remain on disk.");
    message("suggestStatus","Suggestions have not been requested.");
    message("pemStatus","Open a PRIVATE source before enabling block removal.");
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
    source=null;rules=[];e.maskPrivateBlocks.checked=false;showRules();invalidate();
    message("filename","None");message("filesize","—");message("originalHash","—");
    if (!file) return;
    if (!/^[^/\x00-\x1f]{1,120}\.(txt|csv|json|md|log|pem|key|asc)$/i.test(file.name) ||
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
      message("suggestStatus","Choose detection categories and request suggestions.");
      message("pemStatus","A complete PEM/PGP block can be masked by explicit opt-in. Unrecognized or incomplete keys remain HOLD.");
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
        rules.length>=30-(e.maskPrivateBlocks.checked?1:0) || !source.text.includes(raw)){
      message("openStatus","HOLD: literal must be unique, present, single-line, 3–128 characters; at most 30 rules.");
      return;
    }
    rules.push(raw);showRules();invalidate();
    message("openStatus","Exact literal mask added. Rule content is never rendered in the list.");
  };


  // Special-case whole multiline blocks, never partial short-value replacement.
  // The parser requires matching literal PEM BEGIN and END labels and refuses nested blocks.
  const privateKeyStart = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g;
  const sourcePrivateMarkers = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/g;
  const privateKeyWhole = /-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]{1,262144}?-----END \1-----/g;
  function privateBlocksRedacted(text) {
    const starts = text.match(privateKeyStart) || [];
    const allMarkers = text.match(sourcePrivateMarkers) || [];
    if(starts.length!==allMarkers.length) throw Error("Unrecognized private-key header");
    if (starts.length===0) throw Error("No recognized private-key block present");
    if (starts.length>16) throw Error("Too many private-key blocks");
    let replaced=0, ambiguous=false;
    privateKeyWhole.lastIndex=0;
    const redacted=text.replace(privateKeyWhole, original=>{
      if (original.slice(12).includes("-----BEGIN ")) ambiguous=true;
      replaced++;
      return "[REDACTED PRIVATE KEY BLOCK]";
    });
    if(ambiguous || replaced!==starts.length) throw Error("Incomplete or nested private-key block");
    return {text:redacted,count:replaced};
  }
  e.maskPrivateBlocks.addEventListener("change",()=>{
    if(!source){e.maskPrivateBlocks.checked=false;invalidate();return;}
    if(e.maskPrivateBlocks.checked && rules.length>=30){
      e.maskPrivateBlocks.checked=false;
      message("pemStatus","HOLD: 30 literal masks already exist. Remove one before enabling one whole-block mask category.");
      invalidate();return;
    }
    const enabled=e.maskPrivateBlocks.checked;
    invalidate();
    message("pemStatus",enabled?
      "Whole-block masking explicitly enabled. Prepare a fresh preview: unmatched or nested blocks HOLD.":
      "Whole-block masking disabled. Existing private-key markers must still be removed or export remains HOLD.");
  });

  // Optional HUMAN-triggered in-memory suggestions, never an automatic privacy verdict.
  const suggestionFamilies = Object.freeze({
    credentials: [
      /\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/g,
      /\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|token)\s*[:=]\s*(?:"[^"\r\n]{3,}"|'[^'\r\n]{3,}'|[^\s,;}]{3,})/gi,
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b/g,
      /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      /\bsk-[A-Za-z0-9_-]{20,}\b/g
    ],
    email: [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
    network: [/\bhttps?:\/\/[^\s"'<>]+/gi, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g]
  });
  e.stageSuggestions.addEventListener("click",()=>{
    if(!source){
      message("suggestStatus","HOLD: open a PRIVATE source first.");return;
    }
    const groups=[
      e.suggestCredentials.checked && "credentials",
      e.suggestEmail.checked && "email",
      e.suggestNetwork.checked && "network"
    ].filter(Boolean);
    if(!groups.length){
      message("suggestStatus","Select at least one category.");return;
    }
    const proposed=new Set();
    let hold=false;
    for(const category of groups){
      for(const regexp of suggestionFamilies[category]){
        regexp.lastIndex=0;
        let match;
        while((match=regexp.exec(source.text))!==null){
          const literal=match[0], n=chars(literal);
          if(n<3 || n>128 || literal.length>512 || literal.includes("[REDACTED]") ||
             /[\x00-\x1f]/.test(literal)){hold=true;break;}
          if(!rules.includes(literal)) proposed.add(literal);
          if(proposed.size>30-(e.maskPrivateBlocks.checked?1:0)-rules.length){hold=true;break;}
        }
        if(hold)break;
      }
      if(hold)break;
    }
    if(hold){
      message("suggestStatus","HOLD: candidates are oversized, invalid or over the 30-mask limit. No partial rules added. Narrow the categories or mask manually.");
      return;
    }
    if(!proposed.size){
      message("suggestStatus","No new candidate literals found in selected categories. This does NOT establish safe sharing.");return;
    }
    const count=proposed.size;
    rules.push(...proposed);showRules();invalidate();
    message("suggestStatus",count+" suggested literal masks added by HUMAN request, without displaying their values. Check the full redacted output.");
  });
  const quote = text => text.replace(/[-/\\^$*+?.()|[\]{}]/g,"\\$&");
  function hints(text){
    const expressions=[
      ["email",/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
      ["URL",/\bhttps?:\/\/[^\s"'<>]+/gi],
      ["Bearer",/\bBearer\s+[a-z0-9._~+/-]{8,}/gi],
      ["credential-like",/\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;}]{3,}/gi],
      ["private key",/-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----/g],
      ["JWT-like",/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
      ["GitHub token",/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g],
      ["AWS access key",/\bAKIA[A-Z0-9]{16}\b/g],
      ["API token prefix",/\bsk-[A-Za-z0-9_-]{20,}\b/g],
      ["IPv4-like",/\b(?:\d{1,3}\.){3}\d{1,3}\b/g]
    ];
    return expressions.map(([label,re])=>{
      let count=0;
      while(re.exec(text)!==null && count<1000) count++;
      return [label,count];
    }).filter(v=>v[1]>0);
  }

  // Search only the sanitized review copy. No original secret value is indexed or exported.
  let searchMatches=[], searchIndex=-1;
  function updateSearchNav(){
    const available=prepared!==null && searchMatches.length>0;
    e.reviewFindPrev.disabled=e.reviewFindNext.disabled=!available;
    message("reviewFindStatus",available?
      "Match "+(searchIndex+1)+" of "+searchMatches.length+" (PRIVATE local preview)":
      "No active matches. This is not a privacy-safety finding.");
  }
  function navigateMatch(direction) {
    if(!prepared || !searchMatches.length)return;
    searchIndex=(searchIndex+direction+searchMatches.length)%searchMatches.length;
    const position=searchMatches[searchIndex];
    showPage(Math.floor(position/8000));
    const within=position-page*8000;
    e.preview.focus();
    e.preview.setSelectionRange(within,within+e.reviewSearch.value.length);
    updateSearchNav();
  }
  e.reviewSearch.addEventListener("input",()=>{
    searchMatches=[];searchIndex=-1;
    if(!prepared){updateSearchNav();return;}
    const needle=e.reviewSearch.value;
    if(needle.length<2 || needle.length>120 || /[\x00-\x1f]/.test(needle)){updateSearchNav();return;}
    const haystack=prepared.text; // preserve exact UTF-16 offsets for precise page highlighting
    let offset=0,next;
    while((next=haystack.indexOf(needle,offset))!==-1){
      searchMatches.push(next);offset=next+needle.length;
      if(searchMatches.length>=500){
        searchMatches=[];message("reviewFindStatus","HOLD: too many private matches. Narrow the search.");return;
      }
    }
    if(searchMatches.length){searchIndex=-1;navigateMatch(1);}
    else updateSearchNav();
  });
  e.reviewFindPrev.addEventListener("click",()=>navigateMatch(-1));
  e.reviewFindNext.addEventListener("click",()=>navigateMatch(1));
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
    if(!source || (!rules.length && !e.maskPrivateBlocks.checked))return;
    const current=++ticket;
    invalidate();const snapshotRevision=revision;e.review.disabled=true;
    try{
      // Full PEM/PGP block masking happens first, preventing short literals from
      // breaking the key-block structural integrity check.
      let text=source.text, count=0;
      const originalKeyMarkers=source.text.match(sourcePrivateMarkers) || [];
      if(originalKeyMarkers.length && !e.maskPrivateBlocks.checked)
        throw Error("Whole private-key block removal required before any partial masks");
      if(e.maskPrivateBlocks.checked){
        const whole=privateBlocksRedacted(text);
        text=whole.text;count+=whole.count;
      }
      if(rules.length){
        const ordered=[...rules].sort((a,b)=>b.length-a.length);
        const rx=new RegExp(ordered.map(quote).join("|"),"g");
        text=text.replace(rx,()=>{count++;return "[REDACTED]";});
      }
      if(count===0)throw Error("No masking was applied");
      const bytes=encoder.encode(text);
      if(bytes.length>8*1024*1024)throw Error("Output too large");
      const sha=await hash(bytes);
      if(current!==ticket || snapshotRevision!==revision || !source)return;
      const remaining=hints(text);
      const highRisk=remaining.some(([kind])=>["private key","Bearer","credential-like","JWT-like","GitHub token","AWS access key","API token prefix"].includes(kind));
      prepared={text,sha,bytes:bytes.length,count,remaining,highRisk,originalHash:source.hash};
      e.importHuman.disabled=false;
      message("matches",String(count));
      message("residual",String(remaining.reduce((n,r)=>n+r[1],0)));
      message("outputHash",sha.slice(0,12)+"…");
      e.warnings.className=remaining.length?"warnings warn":"warnings good";
      message("warnings",remaining.length?
        "Potential sensitive patterns remain: "+remaining.map(x=>x[0]+" "+x[1]+(x[1]===1000?"+":"")).join("; ")+". Not exhaustive.":
        "No heuristic pattern matches; this does not imply safe sharing. Inspect the entire file.");
      seen=new Set();showPage(0);
      searchMatches=[];searchIndex=-1;updateSearchNav();
      message("exportStatus",highRisk ? "HOLD: possible key, Bearer token or credential remains. Mask it and prepare a new preview before export." : "Review every page, then confirm privately.");
    }catch(err){
      if(current!==ticket)return;
      e.warnings.className="warnings warn";
      message("warnings",e.maskPrivateBlocks.checked || source?.text.match(sourcePrivateMarkers)?.length ?
        "HOLD: entire private-key block removal is mandatory for any PRIVATE KEY header. Incomplete, nested, oversized or unsupported blocks cannot be partially disclosed." :
        "HOLD: failed to prepare a bounded full-file redacted preview.");
    }finally{if(current===ticket)e.review.disabled=!source || (!rules.length && !e.maskPrivateBlocks.checked);}
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
        mask_rules:rules.length+(e.maskPrivateBlocks.checked?1:0),residual_hints:Object.fromEntries(prepared.remaining),
        authorization:false,client_consent:false,operator_consent:false,
        revocation_at_use_verified:false,scanning_permitted:false,release_approved:false
      };
      download(JSON.stringify(report,null,2)+"\n","lightup-private-disclosure-receipt.json","application/json");
      finish("PRIVATE receipt");
    }catch(err){message("exportStatus","HOLD: review and reconfirm before exporting.");}
  };

  const returnKeys=[
    "schema","redacted_sha256","redacted_bytes","human_followup","human_note",
    "all_pages_displayed","sender_authenticated","client_consent","operator_consent",
    "revocation_at_use_verified","scanning_permitted","release_approved"
  ];
  e.humanReplyFile.addEventListener("change",()=>{
    e.humanReturnOutcome.textContent="";e.humanReturnNote.value="";
    message("humanReturnStatus","PRIVATE feedback file selection changed. Read it against the current redacted preview.");
  });
  e.importHuman.addEventListener("click",async()=>{
    e.humanReturnOutcome.textContent="";e.humanReturnNote.value="";
    const file=e.humanReplyFile.files?.[0], current=prepared;
    if(!current || !file || !/^[^/\x00-\x1f]{1,120}\.json$/i.test(file.name) ||
       file.size<1 || file.size>4096){
      message("humanReturnStatus","HOLD: prepare the current redacted preview and choose one bounded PRIVATE JSON reply.");
      return;
    }
    try{
      const bytes=new Uint8Array(await file.arrayBuffer());
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      const reply=JSON.parse(raw);
      if(!reply || Array.isArray(reply) || typeof reply!=="object" ||
         JSON.stringify(reply,null,2)+"\n"!==raw ||
         Object.keys(reply).join("|")!==returnKeys.join("|") ||
         reply.schema!=="lightup-private-disclosure-return-v1" ||
         reply.redacted_sha256!==current.sha ||
         reply.redacted_bytes!==current.bytes ||
         reply.all_pages_displayed!==true ||
         (current.highRisk && reply.human_followup!=="needs_more_masking") ||
         !["needs_more_masking","needs_context","read_only_notes"].includes(reply.human_followup) ||
         typeof reply.human_note!=="string" || reply.human_note.length>800 ||
         unsafeHumanText(reply.human_note) ||
         hints(reply.human_note).some(([name])=>["Bearer","credential-like","private key","JWT-like","GitHub token","AWS access key","API token prefix"].includes(name)) ||
         !["sender_authenticated","client_consent","operator_consent",
           "revocation_at_use_verified","scanning_permitted","release_approved"].every(k=>reply[k]===false)){
        throw Error("invalid recipient response");
      }
      if(prepared!==current || e.humanReplyFile.files?.[0]!==file || !source || source.hash!==current.originalHash)
        throw Error("source changed while reading");
      e.humanReturnOutcome.textContent="HUMAN follow-up: "+reply.human_followup.replaceAll("_"," ")+
        " · sender identity and consent UNVERIFIED";
      e.humanReturnNote.value=reply.human_note;
      message("humanReturnStatus","Source-bound PRIVATE HUMAN feedback opened. Nothing has been applied to masks, source, grant or authorization.");
    }catch(_){
      e.humanReturnOutcome.textContent="";e.humanReturnNote.value="";
      message("humanReturnStatus","HOLD: feedback invalid, noncanonical, source-mismatched, unauthenticated or unreadable. No prior HUMAN state carried over.");
    }
  });
  e.clear.onclick=clear;
  invalidate();
})();