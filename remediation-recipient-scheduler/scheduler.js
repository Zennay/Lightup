"use strict";
(() => {
  const model = JSON.parse(document.getElementById("seed").textContent);
  const STAGES = ["open_human", "ask_source_owner", "in_discussion_human", "answered_human_only"];
  const KDF = 600000, LIMIT = 262144, AAD = "LIGHTUP_PRIVATE_SOURCE_FREE_HUMAN_SCHEDULE_V1";
  const textEncoder = new TextEncoder(), textDecoder = new TextDecoder("utf-8", {fatal:true});
  const el = id => document.getElementById(id);
  const sourceKeys = new Map(model.sources.map(x => [x.packet, x.source_sha256]));
  const original = model.tasks.map(x => ({packet:x.packet,slot:x.slot,reason:x.reason,count:x.count}));
  let rows = model.tasks.map(x => ({...x})), dirty = false, lastBatch = null;

  const fatal = reason => { throw new Error(reason); };
  const sameKeys = (obj,keys) => obj && typeof obj === "object" && !Array.isArray(obj) &&
    Object.keys(obj).length === keys.length && keys.every(k => Object.hasOwn(obj,k));
  const validText = (s,limit,bytes) => typeof s === "string" &&
    [...s].length <= limit && textEncoder.encode(s).length <= bytes &&
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(s);
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
          !STAGES.includes(task.stage) || !validText(task.human_note,240,960) ||
          !validText(task.owner,64,256) || !validText(task.next_action,240,960) ||
          !validDate(task.due)) fatal("Unknown task or invalid HUMAN-only field; no plan was restored");
      return {...task};
    });
  }
  const today = () => {const d=new Date(), offset=d.getTimezoneOffset()*60000;return new Date(d.getTime()-offset).toISOString().slice(0,10);};
  const overdue = x => x.due && x.due < today() && x.stage !== "answered_human_only";
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
  function renderStats() {
    const total=rows.length, unscheduled=rows.filter(x=>!x.due).length,
      unowned=rows.filter(x=>!x.owner.trim()).length,
      late=rows.filter(overdue).length,
      done=rows.filter(x=>x.stage==="answered_human_only").length;
    el("stats").textContent=`${total} HUMAN-only reason groups · ${done} answered (self-reported) · ${late} overdue · ${unscheduled} unscheduled · ${unowned} unowned ${dirty?"· UNSAVED":""}`;
  }
  function render() {
    const query=el("search").value.trim().toLocaleLowerCase(), f=el("filter").value, p=el("source").value;
    const host=el("tasks");host.replaceChildren();let visible=0;
    for(let i=0;i<rows.length;i++) {
      const x=rows[i];
      if((p!=="all" && String(x.packet)!==p) ||
          (query && ![x.reason,x.owner,x.next_action,x.human_note,String(x.packet)].join(" ").toLocaleLowerCase().includes(query)) ||
          (f==="overdue"&&!overdue(x)) || (f==="unscheduled"&&x.due) ||
          (f==="unowned"&&x.owner.trim()) || (f==="pending"&&x.stage==="answered_human_only")) continue;
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
    const q=el("search").value.trim().toLocaleLowerCase(), f=el("filter").value, p=el("source").value;
    const result=[];
    for(let i=0;i<rows.length;i++){
      const x=rows[i];
      if(p!=="all"&&String(x.packet)!==p)continue;
      if(q&&![x.reason,x.owner,x.next_action,x.human_note,String(x.packet)].join(" ").toLocaleLowerCase().includes(q))continue;
      if(f==="overdue"&&!overdue(x))continue;
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
  async function saveEncrypted() {
    if(!crypto?.subtle) fatal("Web Crypto unavailable in this offline browser");
    const plan=snapshot(),phrase=prompt("Enter a NEW private plan password (at least 12 characters).");
    if(phrase===null)return;
    if(phrase.length<12 || phrase.length>256) fatal("Password must contain 12–256 characters");
    const confirm=prompt("Repeat password to confirm.");
    if(confirm!==phrase) fatal("Passwords differ; nothing downloaded");
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
    dl(bytes,"lightup-private-human-schedule.lurp","application/json");dirty=false;
    status("Encrypted PRIVATE plan downloaded. Verify that it is stored in a protected location; source/consent not authenticated.");
    renderStats();
  }
  async function openEncrypted(file) {
    if(!file || file.size>LIMIT || file.size<100)fatal("Encrypted plan file missing or oversized");
    const raw=await file.arrayBuffer(),doc=JSON.parse(textDecoder.decode(raw));
    if(!sameKeys(doc,["kind","disposition","authority_granted","consent_verified","remediation_verified","kdf","iterations","algorithm","salt_b64","nonce_b64","ciphertext_b64","warning"]) ||
        doc.kind!=="lightup.source_free_human_schedule_encrypted.v1" ||
        doc.disposition!=="PRIVATE_HUMAN_ONLY_NO_AUTHORITY" ||
        doc.authority_granted!==false || doc.consent_verified!==false ||
        doc.remediation_verified!==false || doc.warning!==model.warning ||
        doc.kdf!=="PBKDF2-HMAC-SHA256" || doc.iterations!==KDF ||
        doc.algorithm!=="AES-256-GCM")fatal("Encrypted plan format/authority mismatch");
    const salt=unb64(doc.salt_b64),iv=unb64(doc.nonce_b64),cipher=unb64(doc.ciphertext_b64);
    if(salt.length!==16 || iv.length!==12 || cipher.length<17)fatal("Invalid encrypted plan salt or nonce");
    const password=prompt("Password for this PRIVATE plan:");if(password===null)return;
    const plain=await crypto.subtle.decrypt(
      {name:"AES-GCM",iv,additionalData:textEncoder.encode(AAD)},
      await keyFor(password,salt,["decrypt"]),cipher);
    const candidate=admitPlan(JSON.parse(textDecoder.decode(plain)));
    if(dirty&&!confirm("Replace unsaved HUMAN schedule edits with the admitted encrypted plan?"))return;
    rows=candidate;dirty=false;lastBatch=null;el("undo").disabled=true;render();status("Original source-bound PRIVATE HUMAN schedule reopened. This is not authenticated sender or consent proof.");
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
  el("bulk").addEventListener("click",()=>{try{applyBulk();}catch(e){status("HOLD: "+e.message);}});
  el("undo").addEventListener("click",()=>{try{undoBatch();}catch(e){status("HOLD: "+e.message);}});
  el("save").addEventListener("click",()=>saveEncrypted().catch(e=>status("HOLD: "+e.message)));
  el("open").addEventListener("click",()=>el("openfile").click());
  el("openfile").addEventListener("change",e=>{openEncrypted(e.target.files[0]).catch(err=>status("HOLD: "+err.message));e.target.value="";});
  el("calendar").addEventListener("click",()=>{try{exportCalendar();}catch(e){status("HOLD: "+e.message);}});
  el("counts").addEventListener("click",exportCounts);
  window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
  render();
})();
