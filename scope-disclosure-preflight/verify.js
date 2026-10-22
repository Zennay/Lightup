"use strict";
/* One-way file byte equality with the companion untrusted receipt, never authorization. */
(() => {
  const e=id=>document.getElementById(id), enc=new TextDecoder("utf-8",{fatal:true});

  let operation=0, receivedText=null, viewPage=0, viewedPages=new Set(), matched=null;
  let searchMatches=[], searchIndex=-1;
  function updateFindStatus(message){
    const available=receivedText!==null&&searchMatches.length>0;
    e("receivedFindPrev").disabled=e("receivedFindNext").disabled=!available;
    e("receivedFindStatus").textContent=message||(available?
      "Match "+(searchIndex+1)+" of "+searchMatches.length+" in the received redacted copy.":
      "No active matches. This is not a privacy-safety finding.");
  }
  function navigateMatch(direction){
    if(receivedText===null||!searchMatches.length)return;
    searchIndex=(searchIndex+direction+searchMatches.length)%searchMatches.length;
    const position=searchMatches[searchIndex];
    showPage(Math.floor(position/8000));
    const within=position-viewPage*8000;
    e("receivedPreview").focus();
    e("receivedPreview").setSelectionRange(within,within+e("receivedSearch").value.length);
    updateFindStatus();
  }
  e("receivedSearch").addEventListener("input",()=>{
    searchMatches=[];searchIndex=-1;
    const needle=e("receivedSearch").value;
    if(receivedText===null){updateFindStatus("Compare matching files before searching.");return;}
    if(needle.length<2||needle.length>120||/[\x00-\x1f\x7f-\x9f]/u.test(needle)){
      updateFindStatus("Enter a 2–120 character search without control characters.");return;
    }
    let offset=0,next;
    while((next=receivedText.indexOf(needle,offset))!==-1){
      searchMatches.push(next);offset=next+needle.length;
      if(searchMatches.length>500){
        searchMatches=[];searchIndex=-1;
        updateFindStatus("HOLD: more than 500 matches. Narrow the local search.");
        return;
      }
    }
    if(searchMatches.length){searchIndex=-1;navigateMatch(1);}
    else updateFindStatus("No matches in the received redacted copy.");
  });
  e("receivedFindPrev").addEventListener("click",()=>navigateMatch(-1));
  e("receivedFindNext").addEventListener("click",()=>navigateMatch(1));
  e("goReceivedPage").addEventListener("click",()=>{
    if(receivedText===null)return;
    const total=Math.max(1,Math.ceil(receivedText.length/8000));
    const target=Number(e("receivedPageJump").value);
    if(!Number.isSafeInteger(target)||target<1||target>total){
      e("receivedPage").textContent="HOLD: enter a page from 1 to "+total+".";
      return;
    }
    showPage(target-1);
  });
  function showPage(target){
    if(receivedText===null)return;
    const total=Math.max(1,Math.ceil(receivedText.length/8000));
    viewPage=Math.min(total-1,Math.max(0,target));
    viewedPages.add(viewPage);
    e("receivedPreview").value=receivedText.slice(viewPage*8000,(viewPage+1)*8000);
    e("receivedPrev").disabled=viewPage===0;
    e("receivedNext").disabled=viewPage===total-1;
    e("receivedPage").textContent="Page "+(viewPage+1)+" / "+total+" · "+viewedPages.size+" viewed";
    e("receivedSearch").disabled=false;
    e("receivedPageJump").disabled=e("goReceivedPage").disabled=false;
    e("receivedPageJump").min="1";e("receivedPageJump").max=String(total);
    e("receivedPageJump").value=String(viewPage+1);
    humanGate();
  }
  e("receivedPrev").addEventListener("click",()=>showPage(viewPage-1));
  e("receivedNext").addEventListener("click",()=>showPage(viewPage+1));
  function sourceHints(text){
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

  function hold(msg) {
    matched=null;
    e("humanOutcome").value="";e("humanNote").value="";e("humanAck").checked=false;
    e("exportHuman").disabled=true;
    e("humanStatus").textContent="No matched received file is available for human feedback.";
    receivedText=null;viewPage=0;viewedPages=new Set();searchMatches=[];searchIndex=-1;
    e("receivedPreview").value="";
    e("receivedPrev").disabled=e("receivedNext").disabled=true;
    e("receivedSearch").value="";e("receivedSearch").disabled=true;
    e("receivedFindPrev").disabled=e("receivedFindNext").disabled=true;
    e("receivedFindStatus").textContent="No active search.";
    e("receivedPageJump").value="";e("receivedPageJump").disabled=true;
    e("goReceivedPage").disabled=true;
    e("receivedPage").textContent="No pages";
    e("recipientHints").textContent="No matched content to inspect.";
    e("recipientHints").className="warnings";

    e("status").textContent="HOLD";
    e("bytes").textContent=e("hash").textContent="—";
    e("result").textContent=msg;
    e("details").textContent="No source identity, authenticated consent, risk approval or permission is established.";
  }
  async function digest(bytes) {
    if (!crypto?.subtle) throw Error("crypto unavailable");
    const data=await crypto.subtle.digest("SHA-256",bytes);
    return [...new Uint8Array(data)].map(x=>x.toString(16).padStart(2,"0")).join("");
  }
  const KEYS=[
    "schema","purpose","output_sha256","output_bytes","replacements","mask_rules",
    "residual_hints","authorization","client_consent","operator_consent",
    "revocation_at_use_verified","scanning_permitted","release_approved"
  ];
  const FALSE_KEYS=[
    "authorization","client_consent","operator_consent",
    "revocation_at_use_verified","scanning_permitted","release_approved"
  ];
  function admitReceipt(text) {
    const val=JSON.parse(text);
    if (!val || Array.isArray(val) || typeof val!=="object" ||
        JSON.stringify(val,null,2)+"\n"!==text ||
        Object.keys(val).join("|")!==KEYS.join("|")) throw Error("canonical receipt shape");
    if (val.schema!=="lightup-private-disclosure-human-v1" ||
        val.purpose!=="Local human disclosure preparation, not verified clearance or authenticated origin" ||
        !/^[0-9a-f]{64}$/.test(val.output_sha256) ||
        !Number.isSafeInteger(val.output_bytes) || val.output_bytes<1 || val.output_bytes>8*1024*1024 ||
        !Number.isSafeInteger(val.replacements) || val.replacements<1 ||
        !Number.isSafeInteger(val.mask_rules) || val.mask_rules<1 || val.mask_rules>30 ||
        !FALSE_KEYS.every(k=>val[k]===false)) throw Error("receipt semantic boundary");
    const hints=val.residual_hints;
    if (!hints || Array.isArray(hints) || typeof hints!=="object") throw Error("hints");
    const allowed=["email","URL","Bearer","credential-like","private key","JWT-like","GitHub token","AWS access key","API token prefix","IPv4-like"];
    const keys=Object.keys(hints);
    if (keys.length>10 || keys.some(k=>!allowed.includes(k)) ||
        keys.some(k=>!Number.isSafeInteger(hints[k]) || hints[k]<1 || hints[k]>1000)) {
      throw Error("bad counts");
    }
    return val;
  }

  const HUMAN_OUTCOMES=["needs_more_masking","needs_context","read_only_notes"];
  // Block invisible direction/format controls in HUMAN notes without rewriting text.
  const unsafeHumanText=value=>/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/u.test(value);
  function humanGate() {
    const total=receivedText===null?0:Math.max(1,Math.ceil(receivedText.length/8000));
    const note=e("humanNote").value;
    const unsafeNote=unsafeHumanText(note);
    const cleanNote=note.length<=800&&!unsafeNote;
    const stage=e("humanOutcome").value;
    const suspiciousNote=sourceHints(note).some(([name])=>["Bearer","credential-like","private key","JWT-like","GitHub token","AWS access key","API token prefix"].includes(name));
    if(unsafeNote)
      e("humanStatus").textContent="HOLD: PRIVATE follow-up note contains hidden direction or control characters. Remove them before export.";
    else if(suspiciousNote)
      e("humanStatus").textContent="HOLD: PRIVATE follow-up note appears to contain a credential, token or private-key marker. Remove it before export.";
    else if(matched?.highRisk)
      e("humanStatus").textContent="HOLD: only a request for more masking may be exported.";
    else if(matched)
      e("humanStatus").textContent="Read every page, select HUMAN follow-up and explicitly confirm. Heuristic note checks are not comprehensive.";
    const ok=!!matched && viewedPages.size===total && e("humanAck").checked &&
      HUMAN_OUTCOMES.includes(stage) && cleanNote && !suspiciousNote &&
      (!matched.highRisk || stage==="needs_more_masking");
    e("exportHuman").disabled=!ok;
  }
  for(const id of ["humanOutcome","humanNote","humanAck"]) {
    e(id).addEventListener("input",humanGate);
    e(id).addEventListener("change",humanGate);
  }
  e("exportHuman").addEventListener("click",()=>{
    humanGate();if(e("exportHuman").disabled)return;
    const feedback={
      schema:"lightup-private-disclosure-return-v1",
      redacted_sha256:matched.hash,
      redacted_bytes:matched.bytes,
      human_followup:e("humanOutcome").value,
      human_note:e("humanNote").value,
      all_pages_displayed:true,
      sender_authenticated:false,
      client_consent:false,
      operator_consent:false,
      revocation_at_use_verified:false,
      scanning_permitted:false,
      release_approved:false
    };
    const uri=URL.createObjectURL(new Blob([JSON.stringify(feedback,null,2)+"\n"],{type:"application/json"}));
    const a=document.createElement("a");a.href=uri;a.download="lightup-private-human-return.json";
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(uri),30000);
    e("humanAck").checked=false;humanGate();
    e("humanStatus").textContent="PRIVATE HUMAN reply downloaded. It is unauthenticated and grants no permission.";
  });
  e("compare").addEventListener("click",async()=>{
    const own=++operation;
    hold("Reading private files locally; no network request.");
    const f=e("receivedFile").files?.[0], r=e("receiptFile").files?.[0];
    if (!f || !r || !/^[^/\x00-\x1f]{1,120}\.txt$/i.test(f.name) ||
        !/^[^/\x00-\x1f]{1,120}\.json$/i.test(r.name) ||
        f.size===0 || f.size>8*1024*1024 || r.size===0 || r.size>8192){
      hold("HOLD: choose bounded local redacted text and a separate JSON receipt.");return;
    }
    try{
      const [a,b]=await Promise.all([f.arrayBuffer(),r.arrayBuffer()]);
      if (own!==operation)return;
      const bytes=new Uint8Array(a), receipt=admitReceipt(enc.decode(new Uint8Array(b)));
      const received=enc.decode(bytes);
      if(!received || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(received))
        throw Error("invalid text");
      const sha=await digest(bytes);
      if (own!==operation)return;
      if (sha!==receipt.output_sha256 || bytes.byteLength!==receipt.output_bytes) {
        hold("HOLD: received bytes do not match the independent HUMAN receipt.");return;
      }
      const observed=Object.fromEntries(sourceHints(received));
      const listed=receipt.residual_hints;
      if(Object.keys(observed).length!==Object.keys(listed).length ||
         Object.keys(observed).some(k=>observed[k]!==listed[k])){
        hold("HOLD: privacy hint counts differ from the actual matched bytes.");return;
      }
      receivedText=received;viewedPages=new Set();
      matched={hash:sha,bytes:bytes.length,highRisk:["Bearer","credential-like","private key","JWT-like","GitHub token","AWS access key","API token prefix"].some(k=>observed[k]>0)};
      showPage(0);
      const risky=["Bearer","credential-like","private key","JWT-like","GitHub token","AWS access key","API token prefix"].some(k=>observed[k]>0);
      e("recipientHints").className=risky||Object.keys(observed).length?"warnings warn":"warnings good";
      e("recipientHints").textContent=risky?
        "HOLD: possible credential, JWT, API token or private key material remains. Matching bytes cannot clear this. Request a corrected private handoff.":
        Object.keys(observed).length?
          "Possible sensitive references remain: "+Object.entries(observed).map(([k,v])=>k+" "+v).join("; ")+". Independently review all pages.":
          "No pattern hints matched. This NEVER proves safe disclosure.";
      e("status").textContent=risky?"HOLD / CONTENT ATTENTION":"MATCH / REVIEW ONLY";
      e("humanStatus").textContent=risky?"HOLD: only a request for more masking may be exported.":"Read every page, select HUMAN follow-up and explicitly confirm.";
      e("bytes").textContent=String(bytes.length);
      e("hash").textContent=sha.slice(0,12)+"…";
      e("result").textContent="Local file bytes match the declared redacted digest and length. HUMAN identity and disclosure clearance are still unknown.";
      e("details").textContent="Next: inspect actual received text privately, authenticate the human sender separately, obtain authentic current consent and action-time revocation confirmation. NO scans, grants or release.";
    }catch(_){
      if(own!==operation)return;
      hold("HOLD: malformed, noncanonical or unsafe receipt, invalid UTF-8, or browser cryptography unavailable.");
    }
  });
  for(const name of ["receivedFile","receiptFile"]) e(name).addEventListener("change",()=>{ ++operation;hold("File selection changed. Compare again."); });
  e("reset").addEventListener("click",()=>{
    ++operation;e("receivedFile").value=e("receiptFile").value="";
    hold("Local selections cleared. Previously downloaded files are not erased.");
  });
  hold("Choose two local files. A matched, unauthenticated receipt never grants authority.");
})();