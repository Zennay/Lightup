"use strict";
(() => {
  const model = JSON.parse(document.getElementById("seed").textContent);
  const STAGES = ["open_human", "ask_source_owner", "in_discussion_human", "answered_human_only"];
  const KDF = 600000, LIMIT = 4194304, AAD = "LIGHTUP_PRIVATE_SOURCE_FREE_HUMAN_SCHEDULE_V1";
  const textEncoder = new TextEncoder(), textDecoder = new TextDecoder("utf-8", {fatal:true});
  const el = id => document.getElementById(id);
  const sourceKeys = new Map(model.sources.map(x => [x.packet, x.source_sha256]));
  const original = model.tasks.map(x => ({packet:x.packet,slot:x.slot,reason:x.reason,count:x.count}));
  let rows = model.tasks.map(x => ({...x})), dirty = false, lastBatch = null;

  const fatal = reason => { throw new Error(reason); };
  const sameKeys = (obj,keys) => obj && typeof obj === "object" && !Array.isArray(obj) &&
    Object.keys(obj).length === keys.length && keys.every(k => Object.hasOwn(obj,k));
  // Mirror native Python's Unicode category C admission.  Original HUMAN
  // notes and textarea actions may contain LF; owner labels never may.
  const validText = (s,limit,bytes,multiline=false) => typeof s === "string" &&
    [...s].length <= limit && textEncoder.encode(s).length <= bytes &&
    [...s].every(ch => (multiline && ch === "\n") || !/\p{C}/u.test(ch));
  const validDate = d => {
    if (d === "") return true;
    if (typeof d !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
    const date = new Date(d + "T00:00:00Z");
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0,10) === d;
  };
  function validate(candidate) {
    if (!Array.isArray(candidate) || candidate.length !== original.length) fatal("Incomplete private source-free HUMAN plan");
    return candidate.map((task,i) => {
      const basis = original[i];
      if (!sameKeys(task, ["packet","slot","reason","count","stage","human_note","owner","due","next_action"]) ||
          task.packet !== basis.packet || task.slot !== basis.slot ||
          task.reason !== basis.reason || task.count !== basis.count ||
          !STAGES.includes(task.stage) || !validText(task.human_note,240,960,true) ||
          !validText(task.owner,64,256) || !validText(task.next_action,240,960,true) ||
          !validDate(task.due)) fatal("Unknown task or invalid HUMAN-only field; no plan was restored");
      return {...task};
    });
  }
  const today = () => {const d=new Date(), offset=d.getTimezoneOffset()*60000;return new Date(d.getTime()-offset).toISOString().slice(0,10);};
  const overdue = x => x.due && x.due < today() && x.stage !== "answered_human_only";
  const dueSoon = x => {
    if (!x.due || x.stage==="answered_human_only" || x.due<today()) return false;
    const d=new Date(today()+"T00:00:00Z");d.setUTCDate(d.getUTCDate()+7);
    return x.due<=d.toISOString().slice(0,10);
  };
  const status = msg => { el("notify").textContent = msg; };
  const change = () => {dirty = true;renderStats();};
  const dl = (bytes,name,mime) => {
    const blob = new Blob([bytes],{type:mime}), url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  const utf8 = o => textEncoder.encode(JSON.stringify(o));
  const b64 = u8 => {
    let out="";for(let i=0;i<u8.length;i+=8192)out+=String.fromCharCode(...u8.subarray(i,i+8192));return btoa(out);
  };
  const unb64 = s => {
    if(typeof s!=="string" || s.length>LIMIT*2 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) fatal("Invalid encrypted payload encoding");
    const binary=atob(s);return Uint8Array.from(binary,c=>c.charCodeAt(0));
  };
  async function keyFor(pass,salt,usages) {
    const root=await crypto.subtle.importKey("raw",textEncoder.encode(pass),"PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:KDF,hash:"SHA-256"},root,
      {name:"AES-GCM",length:256},false,usages);
  }
  function snapshot() {
    validate(rows);
    return {kind:model.kind, version:1, disposition:"PRIVATE_HUMAN_ONLY_NO_AUTHORITY",
      authority_granted:false, consent_verified:false, remediation_verified:false,
      warning:model.warning, sources:model.sources.map(x=>({...x})), tasks:rows.map(x=>({...x}))};
  }
  function admitPlan(p) {
    if(!sameKeys(p,["kind","version","disposition","authority_granted","consent_verified","remediation_verified","warning","sources","tasks"]) ||
        p.kind!==model.kind || p.version!==1 ||
        p.disposition!=="PRIVATE_HUMAN_ONLY_NO_AUTHORITY" || p.warning!==model.warning ||
        p.authority_granted!==false || p.consent_verified!==false || p.remediation_verified!==false ||
        !Array.isArray(p.sources) || p.sources.length!==model.sources.length) fatal("Different source-free HUMAN schedule or elevated authority");
    for(let i=0;i<model.sources.length;i++) {
      const s=p.sources[i], b=model.sources[i];
      if(!sameKeys(s,["packet","source_sha256","reason_groups"]) ||
         s.packet!==b.packet || s.source_sha256!==b.source_sha256 || s.reason_groups!==b.reason_groups)
        fatal("Original native source-free packet bytes changed; old HUMAN plan is not transferable");
    }
    return validate(p.tasks);
  }
  function input(label,value,onchange,kind="text",max=240) {
    const wrap=document.createElement("label"),name=document.createElement("span");
    name.textContent=label;wrap.append(name);
    const ctl=kind==="textarea"?document.createElement("textarea"):document.createElement("input");
    if(kind!=="textarea")ctl.type=kind;
    ctl.value=value;ctl.maxLength=max;ctl.addEventListener("change",()=>onchange(ctl.value));
    wrap.append(ctl);return wrap;
  }
  function renderOwnerBoard() {
    const board=el("ownerBoard"),select=el("ownerFilter"),previous=select.value;
    const grouped=new Map();
    for(const x of rows) {
      const owner=x.owner.trim(),key=owner||"";
      if(!grouped.has(key))grouped.set(key,{total:0,open:0,overdue:0,soon:0});
      const g=grouped.get(key);g.total++;
      if(x.stage!=="answered_human_only")g.open++;
      if(overdue(x))g.overdue++;
      if(dueSoon(x))g.soon++;
    }
    select.replaceChildren();
    const all=document.createElement("option");all.value="all";all.textContent="All HUMAN owners";select.append(all);
    const names=[...grouped.keys()].sort((a,b)=>a.localeCompare(b));
    if(names.length>32) {
      const note=document.createElement("p");note.textContent="Many locally declared HUMAN owners. Search by owner to narrow tasks.";
      board.replaceChildren(note);
    }else{
      board.replaceChildren();
    }
    for(const owner of names){
      const key=owner?"owner:"+owner:"unassigned",g=grouped.get(owner);
      const opt=document.createElement("option");opt.value=key;opt.textContent=owner||"(No HUMAN owner)";select.append(opt);
      if(names.length>32)continue;
      const card=document.createElement("button");card.type="button";card.className="owner-card";card.value=key;
      const label=document.createElement("strong");label.textContent=owner||"Unassigned HUMAN tasks";
      const metric=document.createElement("small");metric.textContent=`${g.open} pending · ${g.overdue} overdue · ${g.soon} due soon · ${g.total} groups`;
      card.append(label,metric);card.addEventListener("click",()=>{select.value=key;render();});
      board.append(card);
    }
    select.value=[...select.options].some(o=>o.value===previous)?previous:"all";
  }
  function renderStats() {
    const total=rows.length, unscheduled=rows.filter(x=>!x.due).length,
      unowned=rows.filter(x=>!x.owner.trim()).length,
      late=rows.filter(overdue).length, soon=rows.filter(dueSoon).length,
      done=rows.filter(x=>x.stage==="answered_human_only").length;
    el("stats").textContent=`${total} HUMAN-only reason groups · ${done} answered (self-reported) · ${late} overdue · ${soon} due within 7 days · ${unscheduled} unscheduled · ${unowned} unowned ${dirty?"· UNSAVED":""}`;
    renderOwnerBoard();
  }
  function render() {
    const shown=new Set(visibleIndices());
    const host=el("tasks");host.replaceChildren();let visible=0;
    for(let i=0;i<rows.length;i++) {
      const x=rows[i];
      if(!shown.has(i))continue;
      visible++;
      const card=document.createElement("article"),title=document.createElement("p");
      title.className="task-title";title.textContent=`Packet ${x.packet} · group ${i+1} · ${x.reason.replaceAll("_"," ")}`;
      const badge=document.createElement("p");badge.className="muted";
      badge.textContent=`Original source-free occurrence count: ${x.count}. Not distinct verified cases or fixes.`;
      const grid=document.createElement("div");grid.className="grid";
      const stage=document.createElement("label"),cap=document.createElement("span");cap.textContent="HUMAN stage";
      const select=document.createElement("select");
      for(const s of STAGES){const opt=document.createElement("option");opt.value=s;opt.textContent=s.replaceAll("_"," ");select.append(opt);}
      select.value=x.stage;select.addEventListener("change",()=>{x.stage=select.value;change();});stage.append(cap,select);
      grid.append(stage,
        input("Local HUMAN owner",x.owner,v=>{x.owner=v;change();},"text",64),
        input("Tentative due date",x.due,v=>{if(!validDate(v)){status("Invalid date; change not saved");return;}x.due=v;change();},"date",10),
        input("HUMAN next action",x.next_action,v=>{x.next_action=v;change();},"textarea",240),
        input("Prior original HUMAN note (private)",x.human_note,v=>{x.human_note=v;change();},"textarea",240)
      );
      card.append(title,badge,grid);host.append(card);
    }
    if(!visible){const p=document.createElement("p");p.textContent="No HUMAN tasks match your filters.";host.append(p);}
    renderStats();
  }
  // Bulk actions apply only to the presently visible, source-bound HUMAN rows.
  // Never rewrite source-free packet identity/counts, notes, or trusted chronology.
  function visibleIndices() {
    const q=el("search").value.trim().toLocaleLowerCase(), f=el("filter").value,
      p=el("source").value, own=el("ownerFilter").value;
    const result=[];
    for(let i=0;i<rows.length;i++){
      const x=rows[i];
      if(p!=="all"&&String(x.packet)!==p)continue;
      if(own==="unassigned"&&x.owner.trim())continue;
      if(own.startsWith("owner:")&&x.owner!==own.slice(6))continue;
      if(q&&![x.reason,x.owner,x.next_action,x.human_note,String(x.packet)].join(" ").toLocaleLowerCase().includes(q))continue;
      if(f==="overdue"&&!overdue(x))continue;
      if(f==="soon"&&!dueSoon(x))continue;
      if(f==="unscheduled"&&x.due)continue;
      if(f==="unowned"&&x.owner.trim())continue;
      if(f==="pending"&&x.stage==="answered_human_only")continue;
      result.push(i);
    }
    return result;
  }
  function applyBulk() {
    const indices=visibleIndices(), useOwner=el("batchUseOwner").checked,
      useDue=el("batchUseDue").checked,stage=el("batchStage").value,
      owner=el("batchOwner").value,due=el("batchDue").value;
    if(!indices.length)fatal("No currently visible HUMAN tasks");
    if(!useOwner&&!useDue&&stage==="keep")fatal("Choose at least one field to change");
    if(useOwner&&!validText(owner,64,256))fatal("Invalid bulk HUMAN owner");
    if(useDue&&!validDate(due))fatal("Invalid tentative bulk date");
    if(stage!=="keep"&&!STAGES.includes(stage))fatal("Unknown HUMAN stage");
    const candidate=rows.map(x=>({...x}));
    for(const i of indices) {
      if(useOwner) candidate[i].owner=owner;
      if(useDue) candidate[i].due=due;
      if(stage!=="keep")candidate[i].stage=stage;
    }
    validate(candidate);
    const changed=indices.filter(i=>JSON.stringify(rows[i])!==JSON.stringify(candidate[i])).length;
    if(!changed)fatal("Batch would make no HUMAN planning changes");
    const preview=`Apply to ${changed} of ${indices.length} visible source-bound HUMAN tasks? `+
      `Owner: ${useOwner?(owner||"[clear]"):"KEEP"}; tentative date: ${useDue?(due||"[clear]"):"KEEP"}; stage: ${stage}. `+
      "These are HUMAN proposals only, not remediation, authorization or verified fixes.";
    if(!confirm(preview))return;
    lastBatch={before:rows.map(x=>({...x})),after:JSON.stringify(candidate),wasDirty:dirty};
    rows=candidate;dirty=true;el("undo").disabled=false;render();
    status(`Applied HUMAN-only planning change to ${changed} task(s). Original source-free evidence and HUMAN notes untouched.`);
  }
  function undoBatch() {
    if(!lastBatch)fatal("No previous batch to undo");
    if(JSON.stringify(rows)!==lastBatch.after)fatal("HUMAN records changed since batch: do not overwrite newer edits");
    if(!confirm("Undo the entire last HUMAN bulk action?"))return;
    rows=validate(lastBatch.before);dirty=lastBatch.wasDirty;lastBatch=null;
    el("undo").disabled=true;render();status("Last HUMAN-only batch undone completely; original source untouched.");
  }
  // Passwords must never be echoed by a plain browser prompt or persisted in
  // localStorage/cookies. A short-lived password type=password dialog is used
  // for BOTH AES-GCM encryption and reopening/carry. No remote account exists.
  async function askPrivatePassword(creating) {
    if(typeof HTMLDialogElement==="undefined")fatal("Private masked password dialog unsupported by this offline browser");
    return new Promise(resolve => {
      const box=document.createElement("dialog"),form=document.createElement("form");
      form.method="dialog";
      const heading=document.createElement("h2");
      heading.textContent=creating?"Protect new PRIVATE HUMAN plan":"Open PRIVATE encrypted HUMAN plan";
      const info=document.createElement("p");
      info.textContent="Local-only password (12–256 characters). No recovery, no sender authentication or actual client permission.";
      const input=document.createElement("input");
      input.type="password";input.required=true;input.minLength=12;input.maxLength=256;
      input.autocomplete=creating?"new-password":"current-password";
      const label=document.createElement("label");
      const title=document.createElement("span");title.textContent="PRIVATE password";
      label.append(title,input);
      form.append(heading,info,label);
      let confirmation=null;
      if(creating){
        confirmation=document.createElement("input");
        confirmation.type="password";confirmation.required=true;
        confirmation.minLength=12;confirmation.maxLength=256;
        confirmation.autocomplete="new-password";
        const cl=document.createElement("label"),ct=document.createElement("span");
        ct.textContent="Confirm new PRIVATE password";cl.append(ct,confirmation);
        form.append(cl);
      }
      const message=document.createElement("p");message.setAttribute("role","alert");
      const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";
      cancel.addEventListener("click",()=>box.close("cancel"));
      const approve=document.createElement("button");approve.type="submit";
      approve.textContent=creating?"Encrypt private download":"Unlock in memory";
      form.append(message,cancel,approve);
      let answer=null;
      form.addEventListener("submit",event=>{
        event.preventDefault();
        if(input.value.length<12||input.value.length>256) {
          message.textContent="Password must contain 12–256 characters";return;
        }
        if(creating&&input.value!==confirmation.value) {
          message.textContent="The two passwords do not match";return;
        }
        answer=input.value;box.close("accepted");
      });
      box.addEventListener("close",()=>{
        input.value="";if(confirmation)confirmation.value="";
        box.remove();resolve(box.returnValue==="accepted"?answer:null);
      },{once:true});
      box.append(form);document.body.append(box);box.showModal();input.focus();
    });
  }

  async function saveEncrypted() {
    if(!crypto?.subtle) fatal("Web Crypto unavailable in this offline browser");
    const plan=snapshot(),phrase=await askPrivatePassword(true);
    if(phrase===null)return;
    const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
    const cipher=new Uint8Array(await crypto.subtle.encrypt(
      {name:"AES-GCM",iv,additionalData:textEncoder.encode(AAD)},
      await keyFor(phrase,salt,["encrypt"]),utf8(plan)));
    const envelope={kind:"lightup.source_free_human_schedule_encrypted.v1",
      disposition:"PRIVATE_HUMAN_ONLY_NO_AUTHORITY",authority_granted:false,
      consent_verified:false, remediation_verified:false,
      kdf:"PBKDF2-HMAC-SHA256",iterations:KDF,algorithm:"AES-256-GCM",
      salt_b64:b64(salt),nonce_b64:b64(iv),ciphertext_b64:b64(cipher),warning:model.warning};
    const bytes=utf8(envelope);if(bytes.length>LIMIT)fatal("Encrypted plan exceeds bound");
    dl(bytes,"lightup-private-human-schedule.lurp","application/json");
    if(confirm("Did you independently verify the encrypted PRIVATE .lurp was downloaded and stored in a protected local location? This is only a HUMAN storage acknowledgment, not sender/source/client/consent authentication.")){
      dirty=false;
      status("HUMAN storage acknowledged for this encrypted plan. No authenticated source, consent or remediation claim.");
    }else{
      status("Encrypted download requested but protected storage NOT acknowledged. Unsaved warning remains; repeat saving if necessary.");
    }
    renderStats();
  }
  async function decryptSealedPlan(file) {
    if(!file || file.size>LIMIT || file.size<100)fatal("Encrypted source-bound HUMAN plan missing or oversized");
    const raw=textDecoder.decode(await file.arrayBuffer()),doc=JSON.parse(raw);
    // Original software emits JSON.stringify exactly; reject duplicate-key or
    // structurally alternate envelopes before requesting a private password.
    if(raw!==JSON.stringify(doc) ||
        !sameKeys(doc,["kind","disposition","authority_granted","consent_verified","remediation_verified","kdf","iterations","algorithm","salt_b64","nonce_b64","ciphertext_b64","warning"]) ||
        doc.kind!=="lightup.source_free_human_schedule_encrypted.v1" ||
        doc.disposition!=="PRIVATE_HUMAN_ONLY_NO_AUTHORITY" ||
        doc.authority_granted!==false || doc.consent_verified!==false ||
        doc.remediation_verified!==false || doc.warning!==model.warning ||
        doc.kdf!=="PBKDF2-HMAC-SHA256" || doc.iterations!==KDF ||
        doc.algorithm!=="AES-256-GCM") fatal("Noncanonical encrypted HUMAN plan or elevated authority");
    const salt=unb64(doc.salt_b64),iv=unb64(doc.nonce_b64),cipher=unb64(doc.ciphertext_b64);
    if(salt.length!==16 || iv.length!==12 || cipher.length<17)fatal("Invalid encrypted HUMAN salt or nonce");
    const password=await askPrivatePassword(false);
    if(password===null)return null;
    const plaintext=await crypto.subtle.decrypt(
      {name:"AES-GCM",iv,additionalData:textEncoder.encode(AAD)},
      await keyFor(password,salt,["decrypt"]),cipher);
    const body=textDecoder.decode(plaintext),plan=JSON.parse(body);
    if(body!==JSON.stringify(plan))fatal("Noncanonical HUMAN plan or ambiguous JSON members");
    return plan;
  }
  async function openEncrypted(file) {
    const plan=await decryptSealedPlan(file);
    if(plan===null)return;
    const candidate=admitPlan(plan);
    if(dirty&&!confirm("Replace unsaved HUMAN schedule edits with the admitted encrypted plan?"))return;
    rows=candidate;dirty=false;lastBatch=null;el("undo").disabled=true;
    render();status("Original source-bound PRIVATE HUMAN schedule reopened. This is not authenticated sender or consent proof.");
  }
  function legacyPlanForCarry(plan) {
    if(!sameKeys(plan,["kind","version","disposition","authority_granted","consent_verified","remediation_verified","warning","sources","tasks"]) ||
        plan.kind!==model.kind || plan.version!==1 ||
        plan.disposition!=="PRIVATE_HUMAN_ONLY_NO_AUTHORITY" ||
        plan.authority_granted!==false || plan.consent_verified!==false ||
        plan.remediation_verified!==false || plan.warning!==model.warning ||
        !Array.isArray(plan.sources) || plan.sources.length<1 || plan.sources.length>12 ||
        !Array.isArray(plan.tasks) || plan.tasks.length>864)
      fatal("Unknown previous HUMAN-only planning schema or authority");
    const previousByPacket=new Map(),shaSet=new Set(),tasksByPacket=new Map();
    for(const [i,s] of plan.sources.entries()){
      if(!sameKeys(s,["packet","source_sha256","reason_groups"]) ||
          s.packet!==i+1 || !Number.isInteger(s.reason_groups) ||
          s.reason_groups<0 || s.reason_groups>72 ||
          typeof s.source_sha256!=="string" ||
          !/^[0-9a-f]{64}$/.test(s.source_sha256) || shaSet.has(s.source_sha256))
        fatal("Ambiguous prior original source-free packet identity");
      shaSet.add(s.source_sha256);previousByPacket.set(s.packet,s);
      tasksByPacket.set(s.packet,new Map());
    }
    for(const t of plan.tasks){
      if(!sameKeys(t,["packet","slot","reason","count","stage","human_note","owner","due","next_action"]) ||
          !Number.isInteger(t.packet) || !previousByPacket.has(t.packet) ||
          !Number.isInteger(t.slot) || t.slot<0 || t.slot>2048 ||
          !Number.isInteger(t.count) || t.count<1 || t.count>100000000 ||
          !validText(t.reason,128,512) || !t.reason ||
          !STAGES.includes(t.stage) || !validText(t.human_note,240,960,true) ||
          !validText(t.owner,64,256) || !validText(t.next_action,240,960,true) ||
          !validDate(t.due))fatal("Invalid or incomplete previous HUMAN task");
      const packet=tasksByPacket.get(t.packet),key=String(t.slot)+"|"+t.reason;
      if(packet.has(key))fatal("Duplicate previous HUMAN task in source-free packet");
      packet.set(key,t);
    }
    for(const s of plan.sources) {
      if(tasksByPacket.get(s.packet).size!==s.reason_groups)
        fatal("Missing or extra prior source-free HUMAN groups");
    }
    return {sourceByDigest:new Map(plan.sources.map(s=>[s.source_sha256,s])),
            tasksByPacket};
  }
  async function carryEncrypted(file) {
    const old=await decryptSealedPlan(file);
    if(old===null)return;
    const carried=legacyPlanForCarry(old);
    const previous=model.sources.map(s=>carried.sourceByDigest.get(s.source_sha256));
    const candidate=rows.map(t=>({...t}));
    let matching=0,carriedTasks=0;
    for(let i=0;i<previous.length;i++){
      const oldSource=previous[i];
      if(!oldSource)continue; // Never infer old absent or newer changed == fixed.
      const targetIndex=i+1,older=carried.tasksByPacket.get(oldSource.packet);
      const current=candidate.filter(t=>t.packet===targetIndex);
      // Source digest match alone is unsigned. Require the entire previously
      // saved HUMAN ordinal, reason, count membership to match again.
      if(older.size!==current.length)
        fatal("Previous HUMAN task membership changed despite a claimed identical source");
      for(const task of current){
        const prior=older.get(String(task.slot)+"|"+task.reason);
        if(!prior || prior.count!==task.count)
          fatal("Previous plan cannot bind exactly to this original HUMAN group");
      }
      for(const task of current){
        const prior=older.get(String(task.slot)+"|"+task.reason);
        for(const key of ["stage","human_note","owner","due","next_action"])
          task[key]=prior[key];
      }
      matching++;carriedTasks+=current.length;
    }
    if(!matching)fatal("No byte-identical original source-free packets to carry. New or changed packets stay HUMAN HOLD.");
    validate(candidate);
    const untouched=model.sources.length-matching;
    if(!confirm(
      `Source-exact HUMAN continuity preview: ${matching} identical packet(s), ${carriedTasks} HUMAN task(s) eligible. `+
      `${untouched} new/changed source-free packet(s) remain untouched and NOT FIXED. `+
      "Carry previously self-declared HUMAN fields into matching original packets? No sender or consent authentication is implied."))return;
    rows=candidate;dirty=true;lastBatch=null;el("undo").disabled=true;
    render();status(`HUMAN-only carry completed for ${matching} source-identical packet(s). ${untouched} new or changed packets unchanged. Save a NEW encrypted PRIVATE plan before leaving.`);
  }
  // Separate scriptless PRIVATE operator handoff, not a source finding report.
  function exportPrivateAgenda() {
    const selected=visibleIndices().map(i=>rows[i]);
    if(!selected.length)fatal("No visible HUMAN follow-ups to include");
    validate(rows);
    if(!confirm(`Export ${selected.length} visible HUMAN task(s) into a PRIVATE printable HTML agenda? Owner labels, actions, status and tentative deadlines are sensitive. No source identities, findings or evidence are included.`))return;
    const withNotes=confirm("INCLUDE HUMAN PRIVATE notes? Choose Cancel to exclude all notes (recommended for narrower recipients).");
    const escape = s => String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    const order=[...selected].sort((a,b)=>(a.due||"9999-12-31").localeCompare(b.due||"9999-12-31")||
      a.owner.localeCompare(b.owner)||a.packet-b.packet);
    const styles="body{font:15px/1.5 system-ui,sans-serif;color:#1e2b3a;max-width:960px;margin:2rem auto;padding:1rem}h1{font-size:1.6rem}article{break-inside:avoid;border:1px solid #aab8c6;padding:1rem;margin:1rem 0;border-radius:8px}aside{border:2px solid #956828;background:#fff8e8;padding:1rem}dt{font-weight:bold}dd{margin:0 0 .5rem;white-space:pre-wrap}small{color:#435366}@media print{body{margin:0}article{page-break-inside:avoid}}";
    const doc=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; connect-src \'none\'; img-src \'none\'; script-src \'none\'; style-src \'unsafe-inline\'"><title>PRIVATE HUMAN follow-up agenda</title><style>',styles,'</style></head><body><h1>PRIVATE HUMAN follow-up agenda</h1>',
      '<aside>HUMAN-only self-declared scheduling. Not verified findings, fixes, retests, client consent, authority, recipient identity or release approval. Source-free reason labels and HUMAN notes can still be sensitive. Share only after real separate approval.</aside>',
      '<p>Locally prepared ',new Date().toISOString().slice(0,10),' · ',String(order.length),' selected HUMAN task groups. Dates and owner assignments are tentative; missing source item does not prove remediation.</p>'];
    for(const t of order){
      doc.push('<article><h2>HUMAN follow-up · packet ',String(t.packet),'</h2><dl>',
        '<dt>Reason (anonymous source-free category)</dt><dd>',escape(t.reason),'</dd>',
        '<dt>HUMAN stage</dt><dd>',escape(t.stage),'</dd>',
        '<dt>Owner (self-declared)</dt><dd>',escape(t.owner||"Unassigned"),'</dd>',
        '<dt>Proposed due date</dt><dd>',escape(t.due||"Not scheduled"),'</dd>',
        '<dt>Next HUMAN action</dt><dd>',escape(t.next_action||"Not recorded"),'</dd>');
      if(withNotes)doc.push('<dt>Additional PRIVATE HUMAN note</dt><dd>',escape(t.human_note||"Not recorded"),'</dd>');
      doc.push('</dl><small>No original evidence/target, signed provenance, actual consent or security verdict.</small></article>');
    }
    doc.push('</body></html>');
    const data=textEncoder.encode(doc.join(""));
    if(data.length>4194304)fatal("PRIVATE printable agenda outside bounded size");
    dl(data,"lightup-private-human-followup-agenda.html","text/html");
    status("PRIVATE scriptless agenda created locally; no network or recipient delivery occurred.");
  }
  // Human-selected, source-redacted confidential follow-up. This is NOT an
  // evidence transfer, a signed originating workspace or a recipient grant.
  async function exportSelectiveHandoff() {
    if(!crypto?.subtle)fatal("Offline browser cryptography unavailable");
    const chosen=visibleIndices().map(i=>rows[i]);
    if(!chosen.length)fatal("No HUMAN follow-up tasks in current filters");
    validate(rows);
    if(!confirm(`Create a separate recipient-only PRIVATE handoff for the ${chosen.length} visible HUMAN follow-up group(s)? It will intentionally OMIT all original source packet hashes, slots, counts, case IDs and evidence. Local HUMAN reason/action/date may still be identifying; external recipient permission is NOT established.`))return;
    const includeOwners=confirm("Include self-declared PRIVATE HUMAN owner labels? Cancel to remove ALL owners (recommended by default).");
    const includeNotes=confirm("Include PRIVATE HUMAN notes? Cancel to remove ALL notes (recommended by default).");
    const handoff={
      kind:"lightup.selected_private_human_followup.v1",
      version:1, disposition:"SELECTED_HUMAN_DRAFT_HOLD",
      authority_granted:false,consent_verified:false,
      source_authenticated:false,remediation_verified:false,
      warning:"PRIVATE selected source-redacted HUMAN follow-up, not sender/client identity, consent, signed source, finding verification, remediation, retest, scan, grant or release.",
      includes_owner_labels:includeOwners,includes_private_notes:includeNotes,
      items:chosen.map(x=>({
        reason:x.reason,stage:x.stage,due:x.due,
        next_action:x.next_action,owner:includeOwners?x.owner:"",
        human_note:includeNotes?x.human_note:""
      }))
    };
    const clear=utf8(handoff);
    if(clear.length>262144)fatal("Selected PRIVATE HUMAN handoff exceeds bounded size");
    const phrase=await askPrivatePassword(true);
    if(phrase===null)return;
    const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
    const encrypted=new Uint8Array(await crypto.subtle.encrypt(
      {name:"AES-GCM",iv,additionalData:textEncoder.encode("LIGHTUP_PRIVATE_HUMAN_SELECTED_HANDOFF_V1")},
      await keyFor(phrase,salt,["encrypt"]),clear));
    const packageFile={
      kind:"lightup.selected_private_human_followup_encrypted.v1",
      version:1, disposition:"SELECTED_HUMAN_DRAFT_HOLD",
      authority_granted:false,consent_verified:false,
      source_authenticated:false,remediation_verified:false,
      kdf:"PBKDF2-HMAC-SHA256",iterations:KDF,algorithm:"AES-256-GCM",
      salt_b64:b64(salt),nonce_b64:b64(iv),ciphertext_b64:b64(encrypted),
      warning:handoff.warning
    };
    const bytes=utf8(packageFile);
    if(bytes.length>360000)fatal("Selected HUMAN encrypted handoff exceeds bounded size");
    dl(bytes,"lightup-selected-private-human-followup.luhq","application/json");
    status("Selected PRIVATE HUMAN handoff download requested. This is NOT authenticated sender, consent or verified evidence; protect the password in a separate channel. Existing full scheduler remains unchanged.");
  }
  function exportCalendar() {
    const due=validate(rows).filter(x=>x.due);
    if(!due.length)fatal("No tentative HUMAN deadlines entered");
    if(!confirm("Export tentative PRIVATE all-day calendar reminders with anonymous labels (no notes/owner/source identifiers)?"))return;
    const lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN schedule//EN","CALSCALE:GREGORIAN"];
    for(let i=0;i<due.length;i++){
      const x=due[i],dt=x.due.replaceAll("-",""),end=new Date(x.due+"T00:00:00Z");
      end.setUTCDate(end.getUTCDate()+1);
      lines.push("BEGIN:VEVENT","UID:"+crypto.randomUUID()+"@lightup-private.invalid",
        "DTSTAMP:"+new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/,"Z"),
        "DTSTART;VALUE=DATE:"+dt,"DTEND;VALUE=DATE:"+end.toISOString().slice(0,10).replaceAll("-",""),
        "SUMMARY:PRIVATE HUMAN follow-up (not verified)","CLASS:PRIVATE","TRANSP:TRANSPARENT",
        "DESCRIPTION:Human-only tentative date. No verification or authorization.","END:VEVENT");
    }
    lines.push("END:VCALENDAR");dl(lines.join("\r\n")+"\r\n","lightup-tentative-human.ics","text/calendar");
    status("Private calendar created from tentative local HUMAN dates; it was not sent to any calendar service.");
  }
  function exportCounts(){
    if(!confirm("Export anonymous aggregate HUMAN planning counts? Small cohort totals can still be sensitive."))return;
    const payload={kind:"lightup.human_schedule_anonymous_counts.v1",
      disposition:"REVIEW_ONLY",authority_granted:false,consent_verified:false,
      remediation_verified:false,source_free_packets:model.sources.length,
      human_reason_groups:rows.length,unassigned:rows.filter(x=>!x.owner.trim()).length,
      unscheduled:rows.filter(x=>!x.due).length,overdue:rows.filter(overdue).length,
      human_answered_self_reported:rows.filter(x=>x.stage==="answered_human_only").length,
      warning:model.warning};
    dl(utf8(payload),"lightup-anonymous-human-schedule-counts.json","application/json");
    status("Anonymous counts exported without packet hashes, sources, owners, notes or exact dates.");
  }
  for(const s of model.sources){const opt=document.createElement("option");opt.value=String(s.packet);
    opt.textContent=`Original source-free packet ${s.packet}`;el("source").append(opt);}
  el("search").addEventListener("input",render);
  el("filter").addEventListener("change",render);
  el("source").addEventListener("change",render);
  el("ownerFilter").addEventListener("change",render);
  el("bulk").addEventListener("click",()=>{try{applyBulk();}catch(e){status("HOLD: "+e.message);}});
  el("undo").addEventListener("click",()=>{try{undoBatch();}catch(e){status("HOLD: "+e.message);}});
  el("save").addEventListener("click",()=>saveEncrypted().catch(e=>status("HOLD: "+e.message)));
  el("open").addEventListener("click",()=>el("openfile").click());
  el("openfile").addEventListener("change",e=>{openEncrypted(e.target.files[0]).catch(err=>status("HOLD: "+err.message));e.target.value="";});
  el("carry").addEventListener("click",()=>el("carryfile").click());
  el("carryfile").addEventListener("change",e=>{carryEncrypted(e.target.files[0]).catch(err=>status("HOLD: "+err.message));e.target.value="";});
  el("agenda").addEventListener("click",()=>{try{exportPrivateAgenda();}catch(e){status("HOLD: "+e.message);}});
  el("selective").addEventListener("click",()=>exportSelectiveHandoff().catch(e=>status("HOLD: "+e.message)));
  el("calendar").addEventListener("click",()=>{try{exportCalendar();}catch(e){status("HOLD: "+e.message);}});
  el("counts").addEventListener("click",exportCounts);
  window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
  render();
})();
