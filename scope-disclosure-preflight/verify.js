"use strict";
/* One-way file byte equality with the companion untrusted receipt, never authorization. */
(() => {
  const e=id=>document.getElementById(id), enc=new TextDecoder("utf-8",{fatal:true});

  let operation=0, receivedText=null, viewPage=0, viewedPages=new Set();
  function showPage(target){
    if(receivedText===null)return;
    const total=Math.max(1,Math.ceil(receivedText.length/8000));
    viewPage=Math.min(total-1,Math.max(0,target));
    viewedPages.add(viewPage);
    e("receivedPreview").value=receivedText.slice(viewPage*8000,(viewPage+1)*8000);
    e("receivedPrev").disabled=viewPage===0;
    e("receivedNext").disabled=viewPage===total-1;
    e("receivedPage").textContent="Page "+(viewPage+1)+" / "+total+" · "+viewedPages.size+" viewed";
  }
  e("receivedPrev").addEventListener("click",()=>showPage(viewPage-1));
  e("receivedNext").addEventListener("click",()=>showPage(viewPage+1));
  function sourceHints(text){
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

  function hold(msg) {
    receivedText=null;viewPage=0;viewedPages=new Set();
    e("receivedPreview").value="";
    e("receivedPrev").disabled=e("receivedNext").disabled=true;
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
    const allowed=["email","URL","Bearer","credential-like","private key","IPv4-like"];
    const keys=Object.keys(hints);
    if (keys.length>6 || keys.some(k=>!allowed.includes(k)) ||
        keys.some(k=>!Number.isSafeInteger(hints[k]) || hints[k]<1 || hints[k]>1000)) {
      throw Error("bad counts");
    }
    return val;
  }
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
      receivedText=received;viewedPages=new Set();showPage(0);
      const risky=["Bearer","credential-like","private key"].some(k=>observed[k]>0);
      e("recipientHints").className=risky||Object.keys(observed).length?"warnings warn":"warnings good";
      e("recipientHints").textContent=risky?
        "HOLD: possible credential, Bearer token or private key marker remains. Matching bytes cannot clear this. Request a corrected private handoff.":
        Object.keys(observed).length?
          "Possible sensitive references remain: "+Object.entries(observed).map(([k,v])=>k+" "+v).join("; ")+". Independently review all pages.":
          "No pattern hints matched. This NEVER proves safe disclosure.";
      e("status").textContent=risky?"HOLD / CONTENT ATTENTION":"MATCH / REVIEW ONLY";
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