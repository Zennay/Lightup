"use strict";
/* Complete PRIVATE HUMAN workroom vault: original bytes + HUMAN notes, encrypted offline.
 * No assessment execution, no grant, no network, no browser persistence. */
function createPrivateWorkspaceVault(api) {
  const {$,fail,shape,int,parseStrict,message,download,getRawFiles,getOriginalCount,getOriginalByteTotal,
    getPrivatePlan,getSessionSnapshot,sessionStillCurrent,
    prepareFullWorkspace,commitFullWorkspace} = api;
  const cryptoBox=createPrivatePlanCrypto();
  const MAX_SOURCE_TOTAL=24*1024*1024; // bounded, intentionally smaller than the 8x8MiB import limit
  const MAX_ENCRYPTED_FILE=65*1024*1024;
  const MAX_PLAN_CHARS=3*1024*1024;
  let busy=false, operationEpoch=0, pending=null;
  const KIND="lightup.private_original_lab_complete_workspace_payload";
  const FIELDS=["kind","version","authorized","consent_verified",
    "dispatch_allowed","release_allowed","original_source_bytes_b64","human_plan",
    "interpretation"];
  const clearPasses=()=>{
    $("vaultSavePass").value="";$("vaultOpenPass").value="";
  };
  const asciiBase64=bytes=>{
    let raw="";
    for(let offset=0;offset<bytes.length;offset+=16384)
      raw+=String.fromCharCode(...bytes.subarray(offset,offset+16384));
    return btoa(raw);
  };
  const decodeBase64=value=>{
    fail(typeof value==="string"&&value.length>=4&&
      value.length<=Math.ceil(8*1024*1024/3)*4+4&&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),
      "Invalid original source encoding");
    const raw=atob(value);
    fail(raw.length>=1&&raw.length<=8*1024*1024,"Original file exceeds source bound");
    const bytes=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
    fail(asciiBase64(bytes)===value,"Noncanonical PRIVATE source-byte envelope");
    return bytes;
  };
  function available() {
    const originals=getRawFiles();
    return cryptoBox.supported()&&originals.length>=2&&
      originals.length<=8&&originals.every(x=>x instanceof Uint8Array)&&
      originals.every(x=>x.length>0&&x.length<=8*1024*1024);
  }
  function update() {
    const sources=getRawFiles(),total=getOriginalByteTotal();
    const allowed=available()&&total<=MAX_SOURCE_TOTAL;
    $("vaultSave").disabled=busy||!allowed;
    $("vaultOpen").disabled=busy||!cryptoBox.supported();
    $("vaultApply").disabled=busy||!pending;
    $("vaultDiscard").disabled=busy||!pending;
    $("vaultAvailable").textContent=!cryptoBox.supported()
      ?"Browser WebCrypto is unavailable. Encrypted PRIVATE workspace import/export disabled."
      :getOriginalCount()===0
      ?"No ORIGINAL PRIVATE source files opened. You can still open an existing encrypted workspace."
      :total>MAX_SOURCE_TOTAL
      ?"Current original batch exceeds the 24 MiB total encrypted workspace export limit. The ordinary source+plan workflow still works. Importing a smaller batch is optional."
      :"Private workspace available: "+sources.length+" original source slots, "+
        total+" original bytes (encrypted, not published as filenames or target labels).";
  }
  function discardPreview() {
    operationEpoch++;
    if(pending) {
      // Best-effort clear of staged source buffers, not a promise of physical memory erasure.
      pending.prepared.bytes.forEach(bytes=>bytes.fill(0));
      pending=null;
    }
    $("vaultPreview").textContent="No decrypted PRIVATE workroom staged.";
    update();
  }
  async function save() {
    if(busy)return;
    if(!available()){message("Open and admit original PRIVATE source files first.",true);return;}
    const session=getSessionSnapshot(),operation=operationEpoch;
    busy=true;update();
    try {
      const sources=getRawFiles(),total=sources.reduce((n,b)=>n+b.length,0);
      fail(total<=MAX_SOURCE_TOTAL,"Combined original bytes exceed the 24 MiB workspace vault export bound");
      const plan=getPrivatePlan();
      const content={kind:KIND,version:1,authorized:false,consent_verified:false,
        dispatch_allowed:false,release_allowed:false,
        original_source_bytes_b64:sources.map(asciiBase64),human_plan:plan,
        interpretation:"PRIVATE offline original source bytes plus local HUMAN categories. Signed authorization, client identity, actual scan and finding authenticity remain unproven."};
      const raw=JSON.stringify(content);
      fail(raw.length<=48*1024*1024&&JSON.stringify(plan).length<=MAX_PLAN_CHARS,
        "PRIVATE original+HUMAN workspace exceeds bounded encryption input");
      if(!confirm("Encrypt and download ALL original PRIVATE lab source bytes together with HUMAN choices? This will store highly sensitive ORIGINAL targets and evidence inside a password-encrypted local file. No grant/assessment authority or independent security audit is implied. Protect your passphrase and device."))return;
      const password=$("vaultSavePass").value;
      const encrypted=await cryptoBox.encryptWorkspace(raw,password);
      fail(operation===operationEpoch&&sessionStillCurrent(session),
        "Original sources or HUMAN choices changed while encrypting; stale export discarded");
      const wrapped=JSON.stringify(encrypted)+"\n";
      fail(new Blob([wrapped]).size<=MAX_ENCRYPTED_FILE,"Encrypted PRIVATE workspace exceeds safe download limit");
      download("lightup-PRIVATE-original-workroom-ENCRYPTED.json",wrapped,"application/json");
      message("Complete PRIVATE original+HUMAN workspace encrypted and downloaded locally. Passphrase was not saved. Source ownership, vulnerability claims and assessment authorization remain unverified.");
    } catch(error) {
      message("Complete PRIVATE workspace encryption HOLD: "+error.message,true);
    } finally {
      busy=false;clearPasses();update();
    }
  }
  async function open() {
    if(busy)return;
    const file=$("vaultFile").files[0];
    if(!file){message("Select one existing PRIVATE encrypted complete workspace first.",true);return;}
    discardPreview();
    const operation=operationEpoch,session=getSessionSnapshot();
    busy=true;update();
    try {
      fail(file.size>0&&file.size<=MAX_ENCRYPTED_FILE,"Encrypted PRIVATE workspace outside 65 MiB bound");
      const raw=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const outer=parseStrict(raw);
      fail(cryptoBox.isWorkspace(outer),"Expected a complete encrypted PRIVATE lab workspace, not an ordinary HUMAN plan");
      const password=$("vaultOpenPass").value;
      const plaintext=await cryptoBox.decryptWorkspace(outer,password);
      const payload=parseStrict(plaintext);
      fail(shape(payload,FIELDS)&&payload.kind===KIND&&payload.version===1,
        "Not a supported PRIVATE original+HUMAN workspace");
      for(const key of ["authorized","consent_verified","dispatch_allowed","release_allowed"])
        fail(payload[key]===false,"A complete workspace can never imply assessment authority");
      fail(typeof payload.interpretation==="string"&&payload.interpretation.length<=1024,
        "Invalid PRIVATE workroom interpretation");
      const entries=payload.original_source_bytes_b64;
      fail(Array.isArray(entries)&&entries.length>=2&&entries.length<=8,
        "Complete workspace must hold 2–8 original PRIVATE sources");
      const decoded=entries.map(decodeBase64);
      fail(decoded.reduce((sum,b)=>sum+b.length,0)<=MAX_SOURCE_TOTAL,
        "Complete PRIVATE sources exceed the 24 MiB total admission bound");
      // Prepare all originals and the source-bound HUMAN plan before any replacement.
      const prepared=await prepareFullWorkspace(decoded,payload.human_plan);
      fail(operation===operationEpoch&&sessionStillCurrent(session),
        "Local source or HUMAN decisions changed while decrypting; staged import discarded");
      const humanCount=prepared.notes.filter(p=>
        p.stage!=="needs_review"||p.route!=="unassigned"||p.action!=="none").length;
      pending={prepared,session,operation};
      $("vaultPreview").textContent="ADMITTED PRIVATE preview (unverified): "+
        decoded.length+" original source files · "+
        decoded.reduce((sum,b)=>sum+b.length,0)+" total source bytes · "+
        prepared.newRows.length+" source-declared groups · "+humanCount+
        " non-default HUMAN planning rows. Existing originals and notes remain unchanged. "+
        "Use APPLY to replace or DISCARD to release the staged workroom.";
      message("PRIVATE encrypted workroom fully decrypted and source-bound. Preview staged only; nothing replaced or authorized.");
    } catch(error) {
      message("Complete PRIVATE workspace HOLD: "+error.message+
        ". The active original source selection and HUMAN plan have not been replaced.",true);
    } finally {
      busy=false;$("vaultFile").value="";clearPasses();update();
    }
  }
  function applyPreview(){
    if(busy||!pending)return;
    const candidate=pending;
    if(candidate.operation!==operationEpoch||!sessionStillCurrent(candidate.session)){
      discardPreview();
      message("PRIVATE preview HOLD: current original files or HUMAN choices changed; re-open the encrypted workroom.",true);
      return;
    }
    if(!confirm("APPLY fully admitted PRIVATE workroom? Replace ALL current original source bytes and HUMAN planning choices? No scan, consent, source authentication or authority is inferred."))return;
    if(candidate.operation!==operationEpoch||!sessionStillCurrent(candidate.session)){
      discardPreview();
      message("PRIVATE preview HOLD: local state changed before application.",true);
      return;
    }
    // Ownership of the admitted buffers passes to the active workspace on successful commit.
    pending=null;operationEpoch++;
    commitFullWorkspace(candidate.prepared);
    $("vaultPreview").textContent="Admitted PRIVATE workroom applied. No decrypted preview remains staged.";
    message("Exact-source PRIVATE originals and HUMAN choices now open locally. No network, grant, scan, authenticated identity or release.");
    update();
  }
  $("vaultSave").addEventListener("click",save);
  $("vaultOpen").addEventListener("click",open);
  $("vaultApply").addEventListener("click",applyPreview);
  $("vaultDiscard").addEventListener("click",()=>{
    discardPreview();
    message("Staged decrypted PRIVATE preview discarded; active workspace kept unchanged.");
  });
  $("vaultFile").addEventListener("change",discardPreview);
  window.addEventListener("pagehide",()=>{discardPreview();clearPasses();});
  update();
  return {update,discardPreview};
}
