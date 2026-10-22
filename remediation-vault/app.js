"use strict";
(() => {
  const MAX_FILE = 2 * 1024 * 1024, MAX_TOTAL = 6 * 1024 * 1024, MAX_VAULT = 12 * 1024 * 1024;
  const MAX_COUNT = 8, ROUNDS = 310000;
  const TYPES = new Set(["json", "csv", "md", "txt"]);
  const $ = id => document.getElementById(id);
  const encode = new TextEncoder(), decode = new TextDecoder("utf-8", {fatal: true});
  let selected = [], restored = [], busy = false, restoredLabel = '', receiptState = null, comparison = null, restoredCipherSha = '';
  const say = (message, bad = false) => { $("status").textContent = message; $("status").dataset.kind = bad ? "error" : "ok"; };
  const clearNode = el => { while (el.firstChild) el.removeChild(el.firstChild); };
  const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, "0")).join("");
  const digest = async b => hex(await crypto.subtle.digest("SHA-256", b));
  const to64 = bytes => {
    let result = "";
    const size = 16384;
    for (let i=0; i<bytes.length; i+=size) result += String.fromCharCode(...bytes.subarray(i, i+size));
    return btoa(result);
  };
  const from64 = s => {
    if (typeof s !== "string" || !s || s.length > MAX_VAULT * 2 ||
        s.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
      throw new Error("Non-canonical base64 data.");
    }
    const bin = atob(s);
    const bytes = Uint8Array.from(bin, x => x.charCodeAt(0));
    if (to64(bytes) !== s) throw new Error("Non-canonical base64 encoding.");
    return bytes;
  };
  const validName = name => typeof name === "string" && name.length > 0 && name.length <= 100 &&
    !/[\/\\\u0000-\u001f\u007f]/.test(name) && name !== "." && name !== ".." &&
    !name.startsWith(".") && TYPES.has(name.split(".").pop().toLowerCase());
  const fail = (condition, message) => { if (!condition) throw new Error(message); };
  const humanSize = n => (n/1024).toFixed(1) + " KiB";
  function forgetReceipt() {
    receiptState=null;
    $("receiptDownload").disabled=true;
    $("receiptDigest").textContent="No encrypted packet prepared.";
  }
  function clearComparison() {
    comparison=null;
    $("comparePrivateAck").checked=false;
    $("comparePrivateExport").disabled=true;
    clearNode($("compareRows"));
    $("compareStats").textContent="No private comparison loaded.";
    $("compareExport").disabled=true;
    $("comparepass").value="";
    $("compareack").checked=false;
  }
  async function prepareReceipt(bytes) {
    receiptState={format:"lightup.remediation_vault_receipt.v1",vault_bytes:bytes.length,
      vault_sha256:await digest(bytes),authority:false};
    $("receiptDownload").disabled=false;
    $("receiptDigest").textContent="Encrypted vault SHA-256: "+receiptState.vault_sha256;
  }

  const table = (container, entries, action) => {
    clearNode(container);
    for (const [index, entry] of entries.entries()) {
      const row = document.createElement("div");
      row.className = "file-row";
      const name = document.createElement("span"); name.textContent = entry.name;
      const size = document.createElement("small"); size.textContent = humanSize(entry.bytes.length);
      if (action) {
        const check = document.createElement("input");
        check.type = "checkbox"; check.checked = false; check.className = "handoff-select";
        check.dataset.fileIndex = String(index);
        check.setAttribute("aria-label","Include " + entry.name + " in next encrypted private handoff");
        check.addEventListener("change",()=>{$("rekeyack").checked=false;});
        row.append(check);
      }
      row.append(name, size);
      if (action) {
        const btn = document.createElement("button"); btn.className="secondary small";
        btn.type="button"; btn.textContent="Download";
        btn.addEventListener("click", () => save(entry.bytes, entry.name, "application/octet-stream"));
        row.append(btn);
      }
      container.append(row);
    }
  };
  function save(bytes, filename, mime) {
    const blob = new Blob([bytes], {type:mime});
    const url = URL.createObjectURL(blob);
    const anchor=document.createElement("a");
    anchor.href=url; anchor.download=filename; document.body.append(anchor);
    anchor.click(); anchor.remove(); setTimeout(()=>URL.revokeObjectURL(url), 30000);
  }
  function resetPrivate() {
    selected=[]; restored=[]; restoredLabel=''; restoredCipherSha='';
    $("files").value=""; $("vaultfile").value="";
    $("secret").value=""; $("unlock").value="";
    $("label").value=""; $("ack").checked=false;
    $("rekeysecret").value=""; $("rekeyack").checked=false;
    $("receiptfile").value=""; $("receiptVerify").textContent="No receipt selected.";
    forgetReceipt();
    $("comparefile").value="";
    clearComparison();
    clearNode($("filelist")); clearNode($("restored"));
    $("summary").textContent="Nothing loaded.";
    $("vaultDetails").textContent="";
    say("Private in-memory session cleared.");
  }
  async function withBusy(fn) {
    if (busy) return;
    busy=true;
    $("pack").disabled=true; $("restore").disabled=true;
    try {
      fail(!!(window.crypto && crypto.subtle && crypto.getRandomValues), "WebCrypto unavailable. Open this offline file in a browser with a secure context.");
      await fn();
    } catch (e) {
      say("HOLD: " + (e instanceof Error ? e.message : "Unable to process private packet."), true);
    } finally {busy=false; $("pack").disabled=false; $("restore").disabled=false;}
  }
  const deriveKey = async (pass, salt, usages) => {
    const base = await crypto.subtle.importKey("raw", encode.encode(pass), {name:"PBKDF2"}, false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ROUNDS,hash:"SHA-256"},
      base,{name:"AES-GCM",length:256},false,usages);
  };
  $("files").addEventListener("change", () => withBusy(async () => {
    selected=[]; $("ack").checked=false; forgetReceipt(); clearNode($("filelist"));
    const files=Array.from($("files").files || []);
    fail(files.length>0 && files.length<=MAX_COUNT, "Select 1–8 private source/export files.");
    const names = new Set(); let total=0;
    const pending=[];
    for (const file of files) {
      fail(validName(file.name), "Use files with safe names and .json, .csv, .md or .txt extensions.");
      fail(!names.has(file.name.toLowerCase()), "Duplicate file name.");
      names.add(file.name.toLowerCase());
      fail(file.size>0 && file.size<=MAX_FILE, "Every file must be 1 byte to 2 MiB.");
      total+=file.size; fail(total<=MAX_TOTAL, "Combined contents exceed 6 MiB.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      fail(bytes.length===file.size, "Source changed while opening.");
      decode.decode(bytes);
      pending.push({name:file.name, bytes});
    }
    selected=pending;
    table($("filelist"),selected,false);
    say(String(selected.length) + " locally selected; nothing uploaded or saved. Encryption requires explicit confirmation.");
  }));
  $("pack").addEventListener("click", () => withBusy(async () => {
    fail(selected.length>0, "Select source/export files first.");
    const pass=$("secret").value;
    fail(pass.length>=12 && pass.length<=256, "Use a private passphrase of 12–256 characters.");
    fail($("ack").checked, "Confirm files were separately authorized for this exact recipient and engagement.");
    const label=$("label").value.trim();
    fail(label.length<=100 && !/[\u0000-\u001f\u007f]/.test(label), "Use a short single-line private handoff label.");
    let total=0;
    const entries=[];
    for(const item of selected) {
      fail(validName(item.name) && item.bytes.length>0 && item.bytes.length<=MAX_FILE, "Selected file is invalid.");
      total+=item.bytes.length; fail(total<=MAX_TOTAL,"Packet is too large.");
      entries.push({name:item.name, bytes:item.bytes.length, sha256:await digest(item.bytes),
        data:to64(item.bytes)});
    }
    const payload = {format:"lightup.remediation_vault_payload.v1",
      notice:"PRIVATE OFFLINE HUMAN TRANSFER ONLY — NOT AUTHORIZATION OR VERIFIED REMEDIATION",
      label, savedAt:new Date().toISOString(), entries};
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveKey(pass,salt,["encrypt"]);
    const plain=encode.encode(JSON.stringify(payload));
    const crypt=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,
      additionalData:encode.encode("lightup.remediation_vault.v1")},key,plain));
    const envelope={format:"lightup.remediation_vault.v1",kdf:"PBKDF2-SHA256",
      iterations:ROUNDS,cipher:"AES-256-GCM",salt:to64(salt),iv:to64(iv),data:to64(crypt)};
    const output=encode.encode(JSON.stringify(envelope,null,2)+"\n");
    fail(output.length<=MAX_VAULT,"Encrypted vault exceeds 12 MiB.");
    await prepareReceipt(output);
    save(output, "lightup-private-handoff.vault.json", "application/json");
    $("secret").value="";
    say("Encrypted local vault downloaded. Share the passphrase separately; this file is not permission to act.");
  }));
  async function decryptPacket(bytes,password) {
    fail(bytes.length>0 && bytes.length<=MAX_VAULT, "Encrypted vault size limit exceeded.");
    const serialized=decode.decode(bytes);
    let env;
    try {env=JSON.parse(serialized);} catch {throw new Error("Not a valid vault envelope.");}
    fail(env!==null && typeof env==="object" && !Array.isArray(env), "Invalid vault envelope.");
    fail(serialized===JSON.stringify(env,null,2)+"\n","Noncanonical or duplicate-key vault envelope.");
    fail(Object.keys(env).sort().join(",")==="cipher,data,format,iterations,iv,kdf,salt",
      "Unexpected or missing vault envelope fields.");
    fail(env.format==="lightup.remediation_vault.v1" &&
      env.cipher==="AES-256-GCM" && env.kdf==="PBKDF2-SHA256" &&
      env.iterations===ROUNDS, "Unsupported vault format or encryption settings.");
    const salt=from64(env.salt), iv=from64(env.iv), crypt=from64(env.data);
    fail(salt.length===16 && iv.length===12 && crypt.length>16 && crypt.length<=MAX_VAULT,
      "Malformed encrypted material.");
    const key=await deriveKey(password,salt,["decrypt"]);
    let plain;
    try { plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv,
      additionalData:encode.encode("lightup.remediation_vault.v1")},key,crypt)); }
    catch { throw new Error("Unable to unlock: wrong passphrase or modified vault."); }
    fail(plain.length<=MAX_VAULT,"Decrypted packet too large.");
    let doc;
    const decoded=decode.decode(plain);
    try {doc=JSON.parse(decoded);} catch {throw new Error("Encrypted payload is malformed.");}
    fail(decoded===JSON.stringify(doc),"Noncanonical or duplicate-key private payload.");
    fail(doc && typeof doc==="object" && !Array.isArray(doc) &&
      Object.keys(doc).sort().join(",")==="entries,format,label,notice,savedAt",
      "Unsupported encrypted payload fields.");
    fail(doc.format==="lightup.remediation_vault_payload.v1" &&
      doc.notice==="PRIVATE OFFLINE HUMAN TRANSFER ONLY — NOT AUTHORIZATION OR VERIFIED REMEDIATION",
      "Not a LightUp human-only payload.");
    fail(typeof doc.label==="string" && doc.label.length<=100 &&
      !/[\u0000-\u001f\u007f]/.test(doc.label) &&
      typeof doc.savedAt==="string" && /^\d{4}-\d\d-\d\dT/.test(doc.savedAt),
      "Invalid internal handoff metadata.");
    fail(Array.isArray(doc.entries) && doc.entries.length>0 && doc.entries.length<=MAX_COUNT,
      "Invalid number of private files.");
    const names=new Set(), pending=[];let total=0;
    for(const entry of doc.entries) {
      fail(entry && typeof entry==="object" && !Array.isArray(entry) &&
        Object.keys(entry).sort().join(",")==="bytes,data,name,sha256",
        "Invalid encrypted entry structure.");
      fail(validName(entry.name) && !names.has(entry.name.toLowerCase()),"Invalid or duplicate recovered file name.");
      names.add(entry.name.toLowerCase());
      const item=from64(entry.data);
      fail(Number.isSafeInteger(entry.bytes) && entry.bytes===item.length &&
        item.length>0 && item.length<=MAX_FILE,"Recovered file size mismatch.");
      total+=item.length; fail(total<=MAX_TOTAL,"Recovered packet exceeds size limit.");
      fail(typeof entry.sha256==="string" && /^[a-f0-9]{64}$/.test(entry.sha256) &&
        await digest(item)===entry.sha256, "Recovered content fingerprint mismatch.");
      decode.decode(item);
      pending.push({name:entry.name,bytes:item});
    }
    return {pending,doc,total};
  }
  $("vaultfile").addEventListener("change", () => {restored=[];restoredLabel="";restoredCipherSha="";clearComparison();clearNode($("restored"));$("summary").textContent="Nothing unlocked.";});
  $("restore").addEventListener("click", () => withBusy(async () => {
    restored=[]; restoredCipherSha=""; clearComparison(); clearNode($("restored")); $("summary").textContent="Nothing unlocked.";
    const f=$("vaultfile").files?.[0];
    fail(!!f && ($("vaultfile").files||[]).length===1 && f.size>0 && f.size<=MAX_VAULT,
      "Select exactly one local .vault.json of at most 12 MiB.");
    fail(f.name.endsWith(".vault.json"),"Vault name must end in .vault.json.");
    const password=$("unlock").value;
    fail(password.length>=12 && password.length<=256, "Enter your private passphrase.");
    const bytes = new Uint8Array(await f.arrayBuffer());
    const receiptFile=$("receiptfile").files?.[0];
    $("receiptVerify").textContent="No optional receipt checked.";
    if (receiptFile) {
      fail(($("receiptfile").files||[]).length===1 && receiptFile.size>0 &&
        receiptFile.size<=2048 && receiptFile.name.endsWith(".receipt.json"),
        "Expected one anonymous .receipt.json of at most 2 KiB.");
      const receiptText=decode.decode(new Uint8Array(await receiptFile.arrayBuffer()));
      let record;
      try {record=JSON.parse(receiptText);} catch {throw new Error("Invalid receipt JSON.");}
      fail(record && typeof record==="object" && !Array.isArray(record) &&
        receiptText===JSON.stringify(record,null,2)+"\n" &&
        Object.keys(record).sort().join(",")==="authority,format,vault_bytes,vault_sha256" &&
        record.format==="lightup.remediation_vault_receipt.v1" && record.authority===false &&
        Number.isSafeInteger(record.vault_bytes) && record.vault_bytes>0 &&
        record.vault_bytes<=MAX_VAULT && typeof record.vault_sha256==="string" &&
        /^[a-f0-9]{64}$/.test(record.vault_sha256), "Invalid or unsupported unsigned receipt.");
      fail(record.vault_bytes===bytes.length && await digest(bytes)===record.vault_sha256,
        "Vault does not match the supplied unsigned SHA-256 transfer receipt.");
      $("receiptVerify").textContent="Ciphertext matched the supplied unsigned SHA-256 receipt. Sender identity and consent remain UNVERIFIED.";
    }
    const {pending,doc,total}=await decryptPacket(bytes,password);
    restored=pending; restoredLabel=doc.label; restoredCipherSha=await digest(bytes);
    table($("restored"),restored,true);
    $("summary").textContent=String(restored.length)+" original file(s), "+humanSize(total)+
      ". PRIVATE original contents; source authority and recipient permission NOT verified.";
    $("vaultDetails").textContent="Private label (local only): "+doc.label+" · Saved: "+doc.savedAt;
    $("unlock").value="";
    say("Vault unlocked locally. Select each download only after independently verifying recipient and exact engagement.");
  }));
  $("comparefile").addEventListener("change",clearComparison);
  $("compare").addEventListener("click",()=>withBusy(async()=>{
    comparison=null; $("comparePrivateAck").checked=false; $("comparePrivateExport").disabled=true; clearNode($("compareRows")); $("compareStats").textContent="Comparing private original bytes..."; $("compareExport").disabled=true;
    fail(restored.length>0, "Unlock the original baseline vault first.");
    fail($("compareack").checked, "Confirm the two privately received vaults concern the exact same real client and engagement.");
    const f=$("comparefile").files?.[0];
    fail(!!f && ($("comparefile").files||[]).length===1 &&
      f.name.endsWith(".vault.json") && f.size>0 && f.size<=MAX_VAULT,
      "Select one bounded encrypted comparison vault.");
    const password=$("comparepass").value;
    fail(password.length>=12 && password.length<=256, "Enter the comparison vault's private passphrase.");
    const compareBytes=new Uint8Array(await f.arrayBuffer());
    const {pending}=await decryptPacket(compareBytes,password);
    const original=new Map(restored.map(r=>[r.name.toLowerCase(),r]));
    const received=new Map(pending.map(r=>[r.name.toLowerCase(),r]));
    const rows=[]; const counts={unchanged:0,changed:0,added:0,absent:0};
    for(const [key,left] of original.entries()) {
      const right=received.get(key);
      const beforeSha=await digest(left.bytes);
      const afterSha=right?await digest(right.bytes):null;
      const category=!right?"absent":beforeSha===afterSha?"unchanged":"changed";
      counts[category]++;
      rows.push({name:left.name,category,before_sha256:beforeSha,after_sha256:afterSha,
        before_bytes:left.bytes.length,after_bytes:right?.bytes.length??null});
    }
    for(const [key,right] of received.entries()) if (!original.has(key)) {
      counts.added++;rows.push({name:right.name,category:"added",
        before_sha256:null,after_sha256:await digest(right.bytes),
        before_bytes:null,after_bytes:right.bytes.length});
    }
    rows.sort((a,b)=>a.category.localeCompare(b.category)||a.name.localeCompare(b.name));
    comparison={counts,rows,baseline_files:restored.length,candidate_files:pending.length,
      baseline_vault_sha256:restoredCipherSha,
      candidate_vault_sha256:await digest(compareBytes)};
    const dest=$("compareRows");clearNode(dest);
    for(const entry of rows) {
      const line=document.createElement("div");line.className="file-row";
      const name=document.createElement("span");name.textContent=entry.name;
      const state=document.createElement("small");state.textContent=entry.category.toUpperCase();
      line.append(name,state);dest.append(line);
    }
    $("compareStats").textContent="UNCHANGED "+counts.unchanged+" · CHANGED "+counts.changed+
      " · ADDED "+counts.added+" · ABSENT "+counts.absent+". Comparison uses private original filenames and SHA-256 bytes ONLY.";
    $("compareExport").disabled=false; $("comparePrivateExport").disabled=false;
    $("comparepass").value="";
    say("Private file-level comparison completed. Absent does NOT mean fixed. No actual finding or grant was changed.");
  }));
  $("compareExport").addEventListener("click",()=>{
    if (!comparison) {say("First compare two private vaults.",true);return;}
    const summary={format:"lightup.remediation_vault_diff_summary.v1",
      baseline_files:comparison.baseline_files,candidate_files:comparison.candidate_files,
      counts:{...comparison.counts},
      verified_source:false,verified_client:false,verified_consent:false,
      verified_remediation:false,authorized_retest:false};
    save(encode.encode(JSON.stringify(summary,null,2)+"\n"),
      "lightup-anonymous-vault-diff.json","application/json");
    say("Anonymous counts-only comparison exported. No filenames, labels, hashes or client data exported.");
  });
  $("comparePrivateExport").addEventListener("click",()=>{
    if(!comparison){say("First compare two original private vaults.",true);return;}
    if(!$("comparePrivateAck").checked){
      say("Confirm the independently authorized recipient/channel for confidential file details.",true);
      return;
    }
    const report={
      format:"lightup.remediation_vault_private_revision.v1",
      classification:"PRIVATE HUMAN FILE VERSION REVIEW — NOT SECURITY FINDING STATUS",
      baseline_vault_sha256:comparison.baseline_vault_sha256,
      candidate_vault_sha256:comparison.candidate_vault_sha256,
      baseline_files:comparison.baseline_files,
      candidate_files:comparison.candidate_files,
      counts:{...comparison.counts},
      rows:comparison.rows.map(r=>({...r})),
      verified_client:false,verified_source:false,verified_consent:false,
      verified_remediation:false,authorized_retest:false
    };
    const bytes=encode.encode(JSON.stringify(report,null,2)+"\n");
    if(bytes.length>65536) {say("Private file-diff report exceeds 64 KiB.",true);return;}
    save(bytes,"lightup-PRIVATE-vault-file-diff.json","application/json");
    $("comparePrivateAck").checked=false;
    say("PRIVATE original file-level change index exported. Transfer only through independently authorized channels.");
  });
  $("rekey").addEventListener("click", () => withBusy(async () => {
    fail(restored.length>0, "Unlock the original local vault before re-encrypting.");
    fail($("rekeyack").checked, "Confirm that this private handoff is approved for its recipient.");
    const pass=$("rekeysecret").value;
    fail(pass.length>=12 && pass.length<=256, "New passphrase must have 12-256 characters.");
    const selectors=Array.from($("restored").querySelectorAll(".handoff-select"));
    fail(selectors.length===restored.length, "Recovered file selection is incomplete.");
    const indexes=selectors.filter(selector=>selector.checked).map(selector=>Number(selector.dataset.fileIndex));
    fail(indexes.length>0 && indexes.length<=MAX_COUNT &&
      indexes.every((n,i)=>Number.isSafeInteger(n) && n>=0 && n<restored.length &&
        (i===0 || n>indexes[i-1])), "Select at least one original file for re-encryption.");
    const entries=[]; let total=0;
    for (const index of indexes) {
      const item=restored[index];
      fail(validName(item.name) && item.bytes.length>0 && item.bytes.length<=MAX_FILE,
        "Recovered source files are not admissible.");
      total+=item.bytes.length; fail(total<=MAX_TOTAL,"Re-encrypted payload too large.");
      entries.push({name:item.name,bytes:item.bytes.length,
        sha256:await digest(item.bytes),data:to64(item.bytes)});
    }
    const payload={format:"lightup.remediation_vault_payload.v1",
      notice:"PRIVATE OFFLINE HUMAN TRANSFER ONLY — NOT AUTHORIZATION OR VERIFIED REMEDIATION",
      label:restoredLabel,savedAt:new Date().toISOString(),entries};
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveKey(pass,salt,["encrypt"]);
    const cipher=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,
      additionalData:encode.encode("lightup.remediation_vault.v1")},key,
      encode.encode(JSON.stringify(payload))));
    const envelope={format:"lightup.remediation_vault.v1",kdf:"PBKDF2-SHA256",
      iterations:ROUNDS,cipher:"AES-256-GCM",salt:to64(salt),iv:to64(iv),data:to64(cipher)};
    const bytes=encode.encode(JSON.stringify(envelope,null,2)+"\n");
    fail(bytes.length<=MAX_VAULT,"Re-encrypted vault is too large.");
    await prepareReceipt(bytes);
    save(bytes,"lightup-private-handoff-rotated.vault.json","application/json");
    $("rekeysecret").value=""; $("rekeyack").checked=false;
    say("Only " + entries.length + " selected original file(s) re-encrypted with fresh salt and IV. Prior copies and passwords are NOT revoked.");
  }));
  $("receiptDownload").addEventListener("click",()=>{
    if (!receiptState) { say("Prepare an encrypted vault first.",true); return; }
    const bytes=encode.encode(JSON.stringify(receiptState,null,2)+"\n");
    save(bytes,"lightup-private-handoff.receipt.json","application/json");
    say("Anonymous unsigned ciphertext fingerprint downloaded. Share it independently; it does not authenticate the sender.");
  });
  $("receiptfile").addEventListener("change",()=>{
    $("receiptVerify").textContent="Receipt selected; matching is checked only while unlocking.";
  });
  $("clear").addEventListener("click",resetPrivate);
  $("copy").addEventListener("click", () => withBusy(async () => {
    fail(restored.length>0,"Unlock a vault first.");
    const summary="LightUp private offline handoff: "+restored.length+
      " locally recovered file(s). No authority, source or remediation outcome attested.";
    await navigator.clipboard.writeText(summary);
    say("Only an anonymous file count was copied.");
  }));
  if (!window.isSecureContext || !crypto?.subtle) {
    say("HOLD: WebCrypto requires a secure local browser context. No fallback to plaintext.", true);
  }
})();
