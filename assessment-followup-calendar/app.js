"use strict";
/* Offline PRIVATE, source-free HUMAN calendar companion; no network or storage.
 * Source authority is never inferred from a worksheet byte digest.
 */
(() => {
  const HEAD = ["original_ordinal","source_reported_severity","evidence_reference_count",
    "human_stage","human_owner_group","human_next_action","human_blocker"];
  const PLAN_HEAD = ["worksheet_sha256_unsigned","original_ordinal","local_date",
    "local_time","duration_minutes","reminder_minutes","time_zone"];
  const PLAN_HEAD_V2 = [...PLAN_HEAD, "private_calendar_series_id"];
  const SEVERITY = new Set(["critical","high","medium","low","info"]);
  const STAGE = new Set(["","needs_review","discussing","blocked","documented"]);
  const DURATION = new Set(["15","30","60","90"]);
  const REMINDER = new Set(["0","15","60","1440"]);
  const MAX_BYTES = 1024*1024, MAX_ROWS = 2048, PAGE = 35;
  const CAP_HEAD = ["worksheet_sha256_unsigned","private_calendar_series_id","time_zone",
    "human_owner_group","weekdays_iso","local_start","local_end","maximum_daily","blackout_dates"];
  const RECIPIENT_POLICY_HEAD_V1=["worksheet_sha256_unsigned","private_calendar_series_unsigned",
    "source_local_zone","recipient_iana_zone_unverified","human_window_start",
    "human_window_end","human_days","authorized","verified","consent"];
  const RECIPIENT_POLICY_HEAD=["worksheet_sha256_unsigned","private_calendar_series_unsigned",
    "source_local_zone","recipient_iana_zone_unverified","human_window_start",
    "human_window_end","human_days","recipient_blackout_dates_unverified",
    "authorized","verified","consent"];
  const RECIPIENT_COUNT_HEAD=["anonymous_group_slot","planned","within_declared_window",
    "outside_hours","outside_weekdays","unavailable_date","clock_change",
    "authorized","recipient_verified","consent_verified","dispatch_allowed","release_allowed"];
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  const $ = id => document.getElementById(id);
  let items = [], plan = new Map(), hash = "", active = false, changed = false, page = 0, agendaPage = 0;
  let seriesId = "", exportedPlan = false, selectedGroup = null, workloadPage = 0;
  let publicationBaseline = null, changesPage = 0;
  let weekAnchor = "", monthAnchor = "";
  let backlogPage=0, backlogProposal=null;
  let capacityRules = new Map(), capacityProposal = null, capacityDirty = false;
  let capacityEditorDirty = false, capacityEditingGroup = "";
  let workroomComparison = null, workroomComparePage = 0;
  let originalBytes = null;
  let workspaceReplacementGeneration = 0;
  const beginWorkspaceReplacement = () => ++workspaceReplacementGeneration;
  const currentWorkspaceReplacement = ticket => ticket === workspaceReplacementGeneration;
  let reconcileSelection = new Set(), reconcileGroupSelection = new Set(), reconcileProposal = null;
  let conflictProposal=null;
  let lastIcsSequence=0;
  let recipientPage=0,recipientGroupPage=0,recipientGroupFocus=null;
  let recipientGroupExportReady=false;
  let recipientCountBaseline=null, recipientCountImportToken=0;
  let recipientProposal=null;
  let recipientSelection=new Set();
  let recipientUndo=null;
  let recipientPreferenceSource="",recipientPolicyDirty=false;
  const decoder = new TextDecoder("utf-8", {fatal:true, ignoreBOM:true}); // Preserve U+FEFF so each admission boundary can reject a leading BOM.
  const control = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
  const unsafeText = s => /^[=+\-@\t\r\n]/u.test(
    s.normalize("NFKC").replace(/^[\u0009\u0020\u00a0\u2000-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+/gu,""));
  function hold(ok) {if (!ok) throw Error("PRIVATE format or source binding rejected (HOLD).");}
  function inform(s,bad=false){$("notice").textContent=s;$("notice").dataset.error=String(bad);}
  async function bytes(file) {
    hold(file && file.size>0 && file.size<=MAX_BYTES);
    const data = new Uint8Array(await file.arrayBuffer());
    hold(data.byteLength>0 && data.byteLength<=MAX_BYTES);
    return data;
  }
  function csv(raw, columns) {
    hold(raw.length <= 1100000 && !raw.includes("\0"));
    const all=[]; let row=[], cell="", quoted=false, closed=false, atStart=true;
    let budget=0;
    function field() {
      hold(cell.length<=5000 && row.length<columns);
      row.push(cell);cell="";closed=false;atStart=true;
    }
    function finish(){
      field();hold(row.length===columns);
      all.push(row);hold(all.length<=MAX_ROWS+1);row=[];
    }
    for(let i=0;i<raw.length;i++){
      const ch=raw[i];hold(++budget<1100000 && cell.length<=5000);
      if(quoted){
        if(ch==='"'){if(raw[i+1]==='"'){cell+='"';i++;}else {quoted=false;closed=true;}}
        else cell+=ch;
      }else if(ch===","){field();}
      else if(ch==="\r"||ch==="\n"){
        if(ch==="\r"){hold(raw[i+1]==="\n");i++;}
        finish();
      }else if(ch==='"' && atStart){quoted=true;atStart=false;}
      else{hold(ch!=='"'&&!closed);cell+=ch;atStart=false;}
    }
    hold(!quoted);
    if(row.length||cell||closed||!atStart)finish();
    hold(all.length>0);
    return all;
  }
  function original(parsed) {
    hold(JSON.stringify(parsed[0])===JSON.stringify(HEAD));
    const result=[];
    for(const v of parsed.slice(1)){
      const ordinal=Number(v[0]),evidence=Number(v[2]);
      hold(/^[1-9]\d*$/.test(v[0]) && ordinal===result.length+1 && ordinal<=MAX_ROWS);
      hold(SEVERITY.has(v[1]) && /^(0|[1-9]\d?)$/.test(v[2]) && evidence<=64);
      hold(STAGE.has(v[3]) && v[4].length<=120 && v[5].length<=600 && v[6].length<=600);
      hold(v.every(s=>!control.test(s)) && v.slice(3).every(s=>!unsafeText(s)));
      result.push({ordinal,severity:v[1],evidence,stage:v[3],group:v[4],action:v[5],blocker:v[6]});
    }
    return result;
  }
  const quote = v => /[",\r\n]/.test(String(v)) ? '"'+String(v).replaceAll('"','""')+'"' : String(v);
  const makeCsv = rows => rows.map(row=>row.map(quote).join(",")).join("\r\n")+"\r\n";
  function download(data,name,type){
    const blob=new Blob([data],{type});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=name;document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),30000);
  }
  const nowToday=() => {const d=new Date();return [d.getFullYear(),String(d.getMonth()+1).padStart(2,"0"),String(d.getDate()).padStart(2,"0")].join("-");};
  function assertLocalZone(){
    if((Intl.DateTimeFormat().resolvedOptions().timeZone||"")!==zone)
      throw Error("Local timezone changed; reopen PRIVATE HUMAN workroom in intended timezone (HOLD).");
  }
  function eventDate(day,time) {
    assertLocalZone();
    hold(/^20\d\d-(0[1-9]|1[0-2])-([0-2]\d|3[01])$/.test(day) && /^([01]\d|2[0-3]):[0-5]\d$/.test(time));
    const [y,m,d]=day.split("-").map(Number),[h,mi]=time.split(":").map(Number);
    const val=new Date(y,m-1,d,h,mi,0,0);
    hold(val.getFullYear()===y && val.getMonth()===m-1 && val.getDate()===d &&
      val.getHours()===h && val.getMinutes()===mi && Number.isFinite(val.getTime()));
    // The Date constructor silently chooses one of TWO local wall-clock instants
    // when autumn DST repeats an hour. A HUMAN reminder must never pick one
    // without an explicit offset, which this source-bound format does not carry.
    const before=new Date(val.getTime()-6*3600000).getTimezoneOffset();
    const after=new Date(val.getTime()+6*3600000).getTimezoneOffset();
    if(after>before){
      const alternate=new Date(val.getTime()+(after-before)*60000);
      if(alternate.getFullYear()===y && alternate.getMonth()===m-1 &&
          alternate.getDate()===d && alternate.getHours()===h &&
          alternate.getMinutes()===mi){
        throw Error("Ambiguous local HUMAN time during a clock change. Choose a non-repeated hour; no calendar event created (HOLD).");
      }
    }
    return val;
  }
  function admitSlot(day,time,duration,reminder){
    if(!day){hold(time==="" && duration==="" && reminder==="");return null;}
    const date=eventDate(day,time);
    hold(DURATION.has(duration) && REMINDER.has(reminder));
    hold(Number.isFinite(date.getTime()+Number(duration)*60000));
    // A HUMAN appointment spanning an actual UTC-offset transition cannot
    // be represented faithfully by one local start + wall-clock duration.
    // Fail closed rather than surprise the recipient with a shifted clock.
    if(new Date(date.getTime()+Number(duration)*60000).getTimezoneOffset() !==
        date.getTimezoneOffset()){
      throw Error("HUMAN appointment crosses a clock change. Move its start time or duration before exporting (HOLD).");
    }
    return {day,time,duration,reminder};
  }
  function newSeriesId(){const raw=new Uint8Array(16);crypto.getRandomValues(raw);return Array.from(raw,x=>x.toString(16).padStart(2,"0")).join("");}
  function applySlot(ordinal,slot){
    if(slot)plan.set(ordinal,slot);else plan.delete(ordinal);
    changed=true;exportedPlan=false;render();
  }
  function filtered(){
    const severity=$("severity").value,stage=$("stage").value,status=$("status").value;
    const q=$("query").value.trim().toLocaleLowerCase();
    return items.filter(r=>{
      if(selectedGroup!==null && r.group!==selectedGroup)return false;
      if(severity && r.severity!==severity)return false;
      if(stage && r.stage !== (stage==="(blank)"?"":stage))return false;
      const p=plan.get(r.ordinal);
      if(status==="scheduled"&&!p || status==="unscheduled"&&p)return false;
      if(status==="overdue"&&(!p||eventDate(p.day,p.time)>=new Date()))return false;
      if(q && ![r.group,r.action,r.blocker,String(r.ordinal)].some(v=>v.toLocaleLowerCase().includes(q)))return false;
      return true;
    });
  }
  function dom(tag,content,cls){
    const e=document.createElement(tag);
    if(content!==undefined)e.textContent=content;
    if(cls)e.className=cls;
    return e;
  }
  function select(options,value,change){
    const e=dom("select");
    options.forEach(v=>{let o=dom("option",v.text);o.value=v.value;e.append(o);});
    e.value=value;e.addEventListener("change",change);return e;
  }
  function clearRecipientWorkspace(){
    recipientPreferenceSource="";recipientPolicyDirty=false;recipientPage=0;
    recipientGroupPage=0;recipientGroupFocus=null;
    recipientProposal=null;recipientSelection.clear();recipientUndo=null;
    $("recipientZone").value="";$("recipientStart").value="09:00";
    $("recipientEnd").value="17:00";$("recipientDays").value="weekdays";
    $("recipientBlackouts").value="";
    $("recipientView").value="all";$("recipientQuery").value="";
    $("recipientPolicyImport").value="";
    for(const id of ["recipientRows","recipientProposalRows","recipientGroupRows"])
      $(id).replaceChildren();
    $("recipientSummary").textContent="No PRIVATE HUMAN worksheet or alternate recipient zone loaded.";
    $("recipientRemainder").textContent="";
    $("recipientGroupSummary").textContent="No HUMAN group preview loaded.";
    recipientGroupExportReady=false;
    recipientCountBaseline=null;recipientCountImportToken++;
    $("recipientCountImport").value="";
    $("recipientCountRows").replaceChildren();
    $("recipientCountSummary").textContent="No previous anonymous group counts loaded.";
    $("recipientProposalSummary").textContent="No pending HUMAN common-hours proposal.";
    $("recipientPolicyStatus").textContent="Recipient preference not loaded; this is not authenticated availability.";
    for(const id of ["recipientExport","recipientPolicyExport",
      "recipientPrev","recipientNext","recipientGroupPrev","recipientGroupNext",
      "recipientGroupClear","recipientGroupCsv","recipientGroupPrint",
      "recipientGroupNextAttention","recipientCountExport","recipientCountClear","recipientApply",
      "recipientProposalExport","recipientProposalPrint","recipientUndo"])
      $(id).disabled=true;
    $("recipientProposalDetails").open=false;
  }
  function render(){
    if(!active)return;
    // Do not carry manually declared recipient availability into a different
    // source worksheet or a newly imported PRIVATE calendar-series identity.
    const binding=hash+"|"+seriesId;
    if(recipientPreferenceSource!==binding){
      clearRecipientWorkspace();
      recipientPreferenceSource=binding;
    }
    $("recipientDesk").hidden=false;
    $("recipientPolicyExport").disabled=false;
    const due=items.filter(r=>plan.has(r.ordinal)).length;
    const late=items.filter(r=>{const p=plan.get(r.ordinal);return p && eventDate(p.day,p.time)<new Date();}).length;
    $("summary").textContent=`${items.length} original HUMAN rows · ${due} scheduled · ${items.length-due} unscheduled · ${late} past scheduled time · ${changed?"unsaved edits":"no unsaved plan edits"}.`;
    const visible=filtered(),pages=Math.max(1,Math.ceil(visible.length/PAGE));
    page=Math.max(0,Math.min(page,pages-1));
    $("paging").textContent=`${visible.length} rows match · page ${page+1} of ${pages} · dates interpreted in ${zone}`;
    $("prev").disabled=page===0;$("next").disabled=page>=pages-1;
    const body=$("rows");body.replaceChildren();
    visible.slice(page*PAGE,page*PAGE+PAGE).forEach(r=>{
      const tr=dom("tr"),slot=plan.get(r.ordinal);tr.dataset.ordinal=String(r.ordinal);
      tr.append(dom("td","#"+r.ordinal),dom("td",r.severity,"severity"),
        dom("td",r.stage+" / "+(r.group||"unassigned")),
        dom("td",r.action||"No HUMAN action supplied"));
      const d=dom("input");d.type="date";d.value=slot?.day||"";
      const t=dom("input");t.type="time";t.value=slot?.time||"09:00";
      const durations=["15","30","60","90"].map(v=>({value:v,text:v+" min"}));
      const reminders=[{value:"0",text:"None"},{value:"15",text:"15 min"},{value:"60",text:"1 hour"},{value:"1440",text:"1 day"}];
      const length=select(durations,slot?.duration||"30",update);
      const reminder=select(reminders,slot?.reminder||"15",update);
      function update(){
        try{
          if(!d.value){applySlot(r.ordinal,null);inform("Unscheduled HUMAN ordinal #"+r.ordinal);return;}
          const p=admitSlot(d.value,t.value,length.value,reminder.value);
          applySlot(r.ordinal,p);inform("PRIVATE reminder proposed for HUMAN ordinal #"+r.ordinal+".");
        }catch(err){inform(err.message,true);render();}
      }
      d.addEventListener("change",update);t.addEventListener("change",update);
      for(const element of [d,t,length,reminder]){let td=dom("td");td.append(element);tr.append(td);}
      body.append(tr);
    });
    renderAgenda();
    renderTransitionDesk();
    if($("recipientZone").value.trim())renderRecipientZone();
    renderWeek();
    renderMonth();
    renderBacklog();
    renderWorkload();
    renderChanges();
    renderCapacity();
    renderWorkspaceSaveStatus();
    renderWorkroomComparison();
  }
  function renderWorkspaceSaveStatus(){
    $("savePortableVault").disabled=!active || !originalBytes || capacityEditorDirty;
    $("vaultStatus").textContent=active?"Original HUMAN-only CSV retained in local browser memory; this unsigned SHA does not grant consent or verified findings.":"A private encrypted portable vault may be opened without any separate worksheet.";
    const label=$("workspaceSaveStatus");
    if(!label)return;
    label.textContent=(changed?"UNSAVED HUMAN appointments. ":"Appointments unchanged or saved. ")+
      (capacityDirty?"UNSAVED declared HUMAN availability. ":"Declared availability unchanged or saved. ")+
      (capacityEditorDirty?"GROUP EDITOR has unsaved field changes: save this group before exporting a full workroom. ":"")+
      "Complete encrypted .luhw saves both committed planning and group settings.";
  }
  function eventIntervals(from=plan){
    return items.filter(r=>from.has(r.ordinal)).map(r=>{
      const slot=from.get(r.ordinal),start=eventDate(slot.day,slot.time).getTime();
      return {ordinal:r.ordinal,start,end:start+Number(slot.duration)*60000};
    }).sort((a,b)=>a.start-b.start || a.ordinal-b.ordinal);
  }
  function collisionIds(from=plan){
    const active=[],found=new Set();
    for(const event of eventIntervals(from)){
      for(let i=active.length-1;i>=0;i--){if(active[i].end<=event.start)active.splice(i,1);}
      if(active.length){found.add(event.ordinal);for(const old of active)found.add(old.ordinal);}
      active.push(event);
    }
    return found;
  }
  function renderConflictPreview(){
    const body=$("conflictPreviewRows");body.replaceChildren();
    if(conflictProposal && (capacityEditorDirty ||
      conflictProposal.fingerprint!==workroomFingerprint()))conflictProposal=null;
    $("applyConflictResolution").disabled=!conflictProposal;
    $("exportConflictProposal").disabled=!conflictProposal;
    if(!conflictProposal){
      $("conflictPreviewSummary").textContent="No valid source-bound group-aware HUMAN conflict proposal prepared.";
      return;
    }
    $("conflictPreviewSummary").textContent=conflictProposal.slots.size+
      " exact HUMAN appointments in this local bounded proposal; "+
      conflictProposal.remaining+" other overlapping reminder ordinals may remain. "+
      "No plan, real calendar, source risk or consent has changed yet.";
    for(const [ordinal,slot] of conflictProposal.slots){
      const tr=dom("tr"),row=items[ordinal-1],previous=plan.get(ordinal);
      tr.append(dom("td","#"+ordinal),
        dom("td",previous.day+" "+previous.time+" · "+previous.duration+" min"),
        dom("td",slot.day+" "+slot.time+" · "+slot.duration+" min"),
        dom("td",row.group||"(unassigned)"));
      body.append(tr);
    }
  }
  function resolveConflicts(){
    assertLocalZone();
    hold(active && !capacityEditorDirty);
    const before=collisionIds();
    if(!before.size){
      conflictProposal=null;renderConflictPreview();
      inform("No overlapping HUMAN reminders in this local workroom.");return;
    }
    const snapshot=workroomFingerprint(),existing=eventIntervals();
    const projected=new Map(plan),proposed=new Map(),reserved=[];
    const today=nowToday(),now=Date.now();
    for(const event of existing){
      const previous=projected.get(event.ordinal),row=items[event.ordinal-1];
      if(!reserved.some(other=>event.start<other.end && other.start<event.end)){
        reserved.push(event);continue;
      }
      if(proposed.size>=32)break;
      hold(row && row.ordinal===event.ordinal);
      if(row.stage==="blocked"){
        conflictProposal=null;renderConflictPreview();
        inform("No automated local HUMAN conflict change for original #"+event.ordinal+
          ": its original HUMAN stage is blocked. Escalate this appointment to a human reviewer; all other reminders remain unchanged.",true);
        return;
      }
      const rule=capacityRules.get(row.group)||capacityDefaultRule();
      const start=eventDate(previous.day<today?today:previous.day,"12:00");
      const startMinute=Math.ceil((Number(rule.start.slice(0,2))*60+
        Number(rule.start.slice(3,5)))/15)*15;
      const endMinute=Number(rule.end.slice(0,2))*60+
        Number(rule.end.slice(3,5))-Number(previous.duration);
      const groupCounts=new Map();
      for(const candidate of items){
        const slot=projected.get(candidate.ordinal);
        if(candidate.ordinal===event.ordinal || candidate.group!==row.group || !slot)continue;
        groupCounts.set(slot.day,(groupCounts.get(slot.day)||0)+1);
      }
      const busy=eventIntervals(projected).filter(e=>e.ordinal!==event.ordinal);
      let found=null;
      for(let offset=0;offset<90&&!found;offset++){
        const calendarDay=new Date(start.getTime());
        calendarDay.setDate(start.getDate()+offset);
        const day=dayString(calendarDay);
        if(!day.startsWith("20"))break;
        if(!rule.days.includes(calendarDay.getDay())||rule.blackouts.includes(day))continue;
        if((groupCounts.get(day)||0)>=rule.maximum)continue;
        for(let minute=startMinute;minute<=endMinute;minute+=15){
          const time=String(Math.floor(minute/60)).padStart(2,"0")+":"+
            String(minute%60).padStart(2,"0");
          let startAt;
          try{startAt=eventDate(day,time).getTime();}catch(_){continue;}
          const until=startAt+Number(previous.duration)*60000;
          if(startAt<=now || busy.some(e=>startAt<e.end&&e.start<until))continue;
          try{found=admitSlot(day,time,previous.duration,previous.reminder);}
          catch(_){continue;} // Skip clock-shift-unsafe slot, seek the next free HUMAN slot.
          break;
        }
      }
      if(!found){
        conflictProposal=null;renderConflictPreview();
        inform("HUMAN conflict preview held: original #"+event.ordinal+
          " has no valid non-overlapping, declared-group-compliant proposal within 90 days. No partial changes made.",true);
        return;
      }
      projected.set(event.ordinal,found);proposed.set(event.ordinal,found);
      const startAt=eventDate(found.day,found.time).getTime();
      reserved.push({ordinal:event.ordinal,start:startAt,
        end:startAt+Number(found.duration)*60000});
    }
    const after=collisionIds(projected);
    hold(proposed.size>0 && proposed.size<=32 && after.size<before.size);
    hold(Array.from(after).every(ordinal=>before.has(ordinal)));
    const counts=new Map();
    for(const row of items){
      const slot=projected.get(row.ordinal);if(!slot)continue;
      const key=JSON.stringify([row.group,slot.day]);
      counts.set(key,(counts.get(key)||0)+1);
    }
    for(const [ordinal,slot] of proposed){
      const row=items[ordinal-1];
      hold(!weekAvailabilityFlags(row,slot,counts).length);
    }
    hold(snapshot===workroomFingerprint());
    conflictProposal={fingerprint:snapshot,slots:proposed,remaining:after.size};
    $("conflictPreviewDetails").open=true;renderConflictPreview();
    inform("Prepared "+proposed.size+
      " complete group-aware HUMAN collision adjustments. Review ALL proposed ordinals and confirm to apply. No changes have been made.");
  }
  function exportConflictProposalCsv(){
    hold(active && conflictProposal && !capacityEditorDirty &&
      conflictProposal.fingerprint===workroomFingerprint());
    const entries=Array.from(conflictProposal.slots);
    hold(entries.length>0 && entries.length<=32);
    if(!confirm("Download "+entries.length+" locally proposed PRIVATE HUMAN conflict changes? "+
      "It contains ordinal identifiers, unverified group labels and proposed old/new times. "+
      "Such information may be sensitive. No original security evidence, targets, authenticated consent "+
      "or real external calendar states are included."))return;
    hold(conflictProposal && conflictProposal.fingerprint===workroomFingerprint());
    const safe=v=>unsafeText(String(v))?"'"+String(v):String(v);
    const data=[["original_ordinal","human_group_unverified","previous_day","previous_time",
      "proposed_day","proposed_time","duration_minutes","review_status"],...entries.map(([ordinal,slot])=>{
      const old=plan.get(ordinal),row=items[ordinal-1];
      return [String(ordinal),safe(row.group),old.day,old.time,slot.day,slot.time,
        slot.duration,"REVIEW_ONLY_NOT_APPLIED"];
    })];
    download(makeCsv(data),"lightup-private-human-conflict-proposal.csv","text/csv;charset=utf-8");
    inform("PRIVATE HUMAN proposed conflict changes downloaded; current appointment plan remains unchanged.");
  }
  function applyConflictResolution(){
    hold(active && conflictProposal && !capacityEditorDirty &&
      conflictProposal.fingerprint===workroomFingerprint());
    const slots=conflictProposal.slots;
    hold(slots.size>0 && slots.size<=32);
    if(!confirm("Apply all "+slots.size+" individually reviewed PRIVATE HUMAN conflict adjustments "+
      "to this LOCAL draft only? Declared group hours, weekdays and blackout dates are local proposals, NOT "+
      "verified staff availability. External calendar entries will NOT be cancelled/moved; "+
      "save your revised source-bound complete workroom before any manual calendar change desk export."))return;
    hold(conflictProposal && conflictProposal.fingerprint===workroomFingerprint());
    const projected=new Map(plan);
    for(const [ordinal,slot] of slots)projected.set(ordinal,{...slot});
    hold(Array.from(collisionIds(projected)).every(id=>collisionIds(plan).has(id)));
    plan=projected;changed=true;exportedPlan=false;agendaPage=0;
    conflictProposal=null;render();
    inform("Applied "+slots.size+" reviewed HUMAN-only local conflict proposals. Save complete PRIVATE workroom; external appointments unchanged.");
  }
  function nearClockChanges(){
    assertLocalZone();
    return items.flatMap(row=>{
      const slot=plan.get(row.ordinal);if(!slot)return [];
      const date=eventDate(slot.day,slot.time),t=date.getTime();
      if(new Date(t-12*3600000).getTimezoneOffset()===
        new Date(t+12*3600000).getTimezoneOffset())return [];
      return [{ordinal:row.ordinal,group:row.group,slot,
        utc:date.toISOString(),offset:-date.getTimezoneOffset()}];
    }).sort((a,b)=>a.utc.localeCompare(b.utc)||a.ordinal-b.ordinal);
  }
  function renderTransitionDesk(){
    const rows=nearClockChanges(),body=$("transitionRows");
    $("transitionDesk").hidden=false;
    $("transitionSummary").textContent=rows.length+
      " HUMAN reminders within 12 hours of an OS-reported clock change in "+zone+
      ". Times are tentative, not independently confirmed with any recipient or calendar.";
    $("exportTransitions").disabled=!rows.length;body.replaceChildren();
    for(const r of rows.slice(0,24)){
      const tr=dom("tr"),b=dom("button","Edit #"+r.ordinal);
      b.type="button";b.addEventListener("click",()=>focusOrdinal(r.ordinal));
      tr.append(dom("td","#"+r.ordinal),
        dom("td",r.slot.day+" "+r.slot.time+" · UTC offset "+r.offset+" min"),
        dom("td",r.group||"(unassigned)"));
      const cell=dom("td");cell.append(b);tr.append(cell);body.append(tr);
    }
    $("transitionRemainder").textContent=rows.length>24?
      "Showing first 24 of "+rows.length+"; review all in PRIVATE CSV.":"";
  }
  function exportTransitionDesk(){
    hold(active && /^[a-f0-9]{64}$/.test(hash));
    const rows=nearClockChanges();hold(rows.length>0&&rows.length<=MAX_ROWS);
    if(!confirm("Export PRIVATE local HUMAN clock-change proposal CSV? Contains unsigned original worksheet hash, ordinal, human group, date/time. Never public; does NOT verify consent, calendar sync, risk or authority."))return;
    const values=[["worksheet_sha256_unsigned","series_unsigned","timezone","ordinal",
      "human_group_unverified","day","time","utc","offset_minutes",
      "authorized","verified","consent"]];
    for(const r of rows)values.push([hash,seriesId,zone,r.ordinal,r.group,
      r.slot.day,r.slot.time,r.utc,r.offset,"false","false","false"]);
    download(makeCsv(values),"lightup-private-human-clock-change-review.csv","text/csv;charset=utf-8");
    inform("PRIVATE HUMAN clock-change review CSV downloaded locally; no target or calendar contacted.");
  }
  // Display-only conversion of tentative HUMAN reminders using the
  // browser's installed IANA timezone database. No recipient is authenticated.
  function recipientFormatter(){
    const name=$("recipientZone").value.trim();
    hold(name.length>0 && name.length<=64 && /^[A-Za-z0-9_+./-]+$/.test(name));
    return new Intl.DateTimeFormat("en-GB",{
      timeZone:name,year:"numeric",month:"2-digit",day:"2-digit",
      hour:"2-digit",minute:"2-digit",hourCycle:"h23",timeZoneName:"shortOffset"
    });
  }
  function recipientPolicyExport(){
    hold(active&&recipientPreferenceSource===hash+"|"+seriesId);
    const target=recipientFormatter().resolvedOptions().timeZone;
    const rule=recipientHoursRule();
    if(!confirm("Save a PRIVATE, UNSIGNED recipient-window preference CSV bound to this exact HUMAN worksheet and opaque calendar series? It does NOT verify recipient identity, working hours, client/operator consent, findings or assessment authority."))return;
    const rows=[RECIPIENT_POLICY_HEAD,[hash,seriesId,zone,target,rule.from,rule.to,
      rule.days,recipientBlackoutText(),"false","false","false"]];
    download(makeCsv(rows),"lightup-private-human-recipient-window.csv",
      "text/csv;charset=utf-8");
    recipientPolicyDirty=false;
    $("recipientPolicyStatus").textContent="PRIVATE source-bound HUMAN recipient preference downloaded locally; keep it private with the saved original plan.";
  }
  async function recipientPolicyImport(file){
    hold(active&&file&&file.size>0&&file.size<=4096);
    const snapshot=workroomFingerprint(),raw=decoder.decode(await bytes(file));
    let rows,legacy=false;
    try{rows=csv(raw,RECIPIENT_POLICY_HEAD.length);}
    catch(_){rows=csv(raw,RECIPIENT_POLICY_HEAD_V1.length);legacy=true;}
    const expected=legacy?RECIPIENT_POLICY_HEAD_V1:RECIPIENT_POLICY_HEAD;
    hold(rows.length===2&&JSON.stringify(rows[0])===JSON.stringify(expected));
    const [original,series,source,target,start,end,days]=rows[1];
    const unavailability=legacy?"":rows[1][7];
    const [authorized,verified,consent]=rows[1].slice(legacy?7:8);
    hold(original===hash&&series===seriesId&&source===zone&&
      /^[A-Za-z0-9_+./-]{1,64}$/.test(target)&&
      [authorized,verified,consent].every(value=>value==="false"));
    const canonical=new Intl.DateTimeFormat("en-GB",{timeZone:target})
      .resolvedOptions().timeZone;
    hold(!!canonical);
    recipientHoursRule(start,end,days);
    hold(unavailability===[...recipientBlackouts(unavailability)].sort().join(";"));
    hold(snapshot===workroomFingerprint()&&recipientPreferenceSource===hash+"|"+seriesId);
    if(!confirm("Restore the HUMAN-declared recipient timezone, working window and unavailable dates from this PRIVATE unsigned file? Current recipient preview settings will be replaced; source worksheet, saved reminders, consent and external calendars will NOT change."))return;
    hold(snapshot===workroomFingerprint());
    $("recipientZone").value=canonical;$("recipientStart").value=start;
    $("recipientEnd").value=end;$("recipientDays").value=days;
    $("recipientBlackouts").value=unavailability.replaceAll(";",", ");
    recipientPage=0;recipientPolicyDirty=false;
    renderRecipientZone();
    $("recipientPolicyStatus").textContent="PRIVATE HUMAN recipient window restored against matching original SHA, series and timezone. Recipient availability remains UNVERIFIED.";
  }
  function recipientClock(){
    const target=recipientFormatter().resolvedOptions().timeZone;
    return new Intl.DateTimeFormat("en-US",{
      timeZone:target,weekday:"short",year:"numeric",month:"2-digit",
      day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23",
      timeZoneName:"shortOffset"
    });
  }
  function recipientHoursRule(from=$("recipientStart").value,
      to=$("recipientEnd").value,days=$("recipientDays").value){
    const toMinutes=value=>{
      hold(/^([01]\d|2[0-3]):[0-5]\d$/.test(value));
      return Number(value.slice(0,2))*60+Number(value.slice(3,5));
    };
    const first=toMinutes(from),last=toMinutes(to);
    hold(["weekdays","all"].includes(days) && first>=360 &&
      last<=1260 && first+30<=last && first%15===0 && last%15===0);
    return {from,to,first,last,days};
  }
  function recipientBlackouts(raw=$("recipientBlackouts").value){
    hold(typeof raw==="string"&&raw.length<=700);
    const entries=raw.trim()?raw.trim().split(/[\s,;]+/):[];
    hold(entries.length<=60&&new Set(entries).size===entries.length);
    for(const day of entries){
      hold(/^20\d{2}-(0[1-9]|1[0-2])-([0-2]\d|3[01])$/.test(day));
      const [y,m,d]=day.split("-").map(Number),parsed=new Date(Date.UTC(y,m-1,d));
      hold(parsed.getUTCFullYear()===y&&parsed.getUTCMonth()===m-1&&
        parsed.getUTCDate()===d);
    }
    return new Set(entries);
  }
  function recipientBlackoutText(){
    return [...recipientBlackouts()].sort().join(";");
  }
  function recipientWindow(start,duration,clock){
    const fields=date=>Object.fromEntries(clock.formatToParts(date)
      .filter(part=>part.type!=="literal").map(part=>[part.type,part.value]));
    const a=fields(start),end=new Date(start.getTime()+Number(duration)*60000),b=fields(end);
    const rule=recipientHoursRule(),first=Number(a.hour)*60+Number(a.minute);
    const last=Number(b.hour)*60+Number(b.minute);
    const sameDate=a.year===b.year&&a.month===b.month&&a.day===b.day;
    const blackouts=recipientBlackouts();
    if(a.timeZoneName!==b.timeZoneName)return "clock_change";
    const startDay=a.year+"-"+a.month+"-"+a.day,
      endDay=b.year+"-"+b.month+"-"+b.day;
    if(blackouts.has(startDay)||blackouts.has(endDay))return "unavailable_date";
    return rule.days==="weekdays" &&
      (["Sat","Sun"].includes(a.weekday)||["Sat","Sun"].includes(b.weekday))?
      "weekend":!sameDate||first<rule.first||last>rule.last?
      "outside_hours":"within_hours";
  }
  function recipientRows(){
    const fmt=recipientFormatter(),clock=recipientClock();
    return items.flatMap(row=>{
      const p=plan.get(row.ordinal);if(!p)return [];
      const start=eventDate(p.day,p.time);
      const end=new Date(start.getTime()+Number(p.duration)*60000);
      return [{ordinal:row.ordinal,group:row.group,day:p.day,time:p.time,
        utc:start.toISOString(),converted:fmt.format(start),
        endConverted:fmt.format(end),status:recipientWindow(start,p.duration,clock)}];
    });
  }
  function recipientFiltered(source=recipientRows()){
    const status=$("recipientView").value,q=$("recipientQuery").value.trim().toLocaleLowerCase();
    return source.filter(r=>
      (recipientGroupFocus===null||r.group===recipientGroupFocus) &&
      (status==="all"||r.status===status) &&
      (!q||[String(r.ordinal),r.group].some(v=>v.toLocaleLowerCase().includes(q))));
  }
  function recipientProposalIdentity(){
    return JSON.stringify([workroomFingerprint(),$("recipientZone").value,
      $("recipientView").value,$("recipientQuery").value,
      $("recipientStart").value,$("recipientEnd").value,$("recipientDays").value,
      recipientBlackoutText(),recipientGroupFocus]);
  }
  function renderRecipientProposal(){
    const body=$("recipientProposalRows");body.replaceChildren();
    if(recipientProposal && recipientProposal.identity!==recipientProposalIdentity())
      recipientProposal=null;
    $("recipientApply").disabled=!recipientProposal||!recipientSelection.size;
    $("recipientProposalExport").disabled=!recipientProposal||!recipientSelection.size;
    $("recipientProposalPrint").disabled=!recipientProposal||!recipientSelection.size;
    if(!recipientProposal){
      $("recipientProposalSummary").textContent="No pending HUMAN common-hours proposal.";
      return;
    }
    $("recipientProposalSummary").textContent=recipientSelection.size+" of "+
      recipientProposal.slots.size+" tentative HUMAN moves selected for HUMAN review; "+
      "current plan and external calendars unchanged.";
    for(const [ordinal,slot] of recipientProposal.slots){
      const row=items[ordinal-1],old=plan.get(ordinal),tr=dom("tr");
      const choice=dom("input");choice.type="checkbox";
      choice.checked=recipientSelection.has(ordinal);
      choice.setAttribute("aria-label","Include HUMAN ordinal #"+ordinal+" in PRIVATE handoff and apply");
      choice.addEventListener("change",()=>{
        if(choice.checked)recipientSelection.add(ordinal);
        else recipientSelection.delete(ordinal);
        renderRecipientProposal();
      });
      const cell=dom("td");cell.append(choice);tr.append(cell);
      tr.append(dom("td","#"+ordinal),dom("td",old.day+" "+old.time),
        dom("td",slot.day+" "+slot.time),dom("td",row.group||"(unassigned)"));
      body.append(tr);
    }
  }
  function prepareRecipientProposal(){
    assertLocalZone();hold(active&&!capacityEditorDirty);
    const identity=recipientProposalIdentity(),clock=recipientClock();
    const candidates=recipientFiltered().filter(r=>r.status!=="within_hours" &&
      items[r.ordinal-1]?.stage!=="blocked").slice(0,12);
    hold(candidates.length>0);
    const simulated=new Map(plan),changes=new Map();
    for(const row of candidates){
      const ordinal=row.ordinal,source=items[ordinal-1],previous=simulated.get(ordinal);
      const policy=capacityRules.get(source.group)||capacityDefaultRule();
      const duration=Number(previous.duration);
      const busy=eventIntervals(simulated).filter(event=>event.ordinal!==ordinal);
      const groupDaily=new Map();
      for(const other of items){
        if(other.ordinal===ordinal||other.group!==source.group)continue;
        const slot=simulated.get(other.ordinal);
        if(slot)groupDaily.set(slot.day,(groupDaily.get(slot.day)||0)+1);
      }
      const first=previous.day>nowToday()?previous.day:nowToday();
      const dayZero=eventDate(first,"12:00"),oldInstant=eventDate(previous.day,previous.time).getTime();
      let found=null;
      const minutes=value=>Number(value.slice(0,2))*60+Number(value.slice(3,5));
      for(let offset=0;offset<30&&!found;offset++){
        const dayDate=new Date(dayZero.getTime());dayDate.setDate(dayZero.getDate()+offset);
        const day=dayString(dayDate);
        if(!day.startsWith("20"))break;
        if(!policy.days.includes(dayDate.getDay())||policy.blackouts.includes(day)||
          (groupDaily.get(day)||0)>=policy.maximum)continue;
        for(let minute=Math.ceil(minutes(policy.start)/15)*15;
            minute+duration<=minutes(policy.end);minute+=15){
          const time=String(Math.floor(minute/60)).padStart(2,"0")+":"+
            String(minute%60).padStart(2,"0");
          let slot,start;
          try{
            slot=admitSlot(day,time,previous.duration,previous.reminder);
            start=eventDate(day,time);
          }catch(_){continue;}
          const ts=start.getTime(),end=ts+duration*60000;
          if(ts<=oldInstant||ts<=Date.now()||
            recipientWindow(start,duration,clock)!=="within_hours"||
            busy.some(event=>ts<event.end&&event.start<end))continue;
          found=slot;break;
        }
      }
      if(!found)throw Error("No full HUMAN common-hours proposal for an ordinal within the bounded 30-day horizon (HOLD).");
      simulated.set(ordinal,found);changes.set(ordinal,found);
    }
    hold(identity===recipientProposalIdentity());
    recipientProposal={identity,slots:changes};
    recipientSelection=new Set(changes.keys());
    renderRecipientProposal();$("recipientProposalDetails").open=true;
    inform("Prepared "+changes.size+" review-only HUMAN cross-zone moves; inspect before confirmation.");
  }
  function exportRecipientProposal(){
    hold(active&&recipientProposal&&!capacityEditorDirty &&
      recipientProposal.identity===recipientProposalIdentity());
    const selected=[...recipientProposal.slots].filter(([ordinal])=>
      recipientSelection.has(ordinal));
    hold(selected.length>0&&selected.length<=12);
    if(!confirm("Download "+selected.length+" selected, still-unapplied PRIVATE HUMAN common-hours proposals? Contains unsigned source SHA, unverified owner groups and both dates. HUMAN review only; external calendar events, scope, consent and findings remain unchanged."))return;
    hold(recipientProposal&&recipientProposal.identity===recipientProposalIdentity());
    const rows=[["worksheet_sha256_unsigned","private_series_unsigned","source_zone",
      "recipient_zone_unverified","original_ordinal","human_group_unverified",
      "previous_local_date","previous_local_time","proposed_local_date",
      "proposed_local_time","duration_minutes","reminder_minutes",
      "recipient_declared_start","recipient_declared_end",
      "recipient_declared_days","recipient_declared_unavailable_dates",
      "authority","consent","verified","applied"]];
    const target=recipientFormatter().resolvedOptions().timeZone;
    for(const [ordinal,next] of selected){
      const old=plan.get(ordinal),row=items[ordinal-1];
      hold(old&&row&&row.ordinal===ordinal);
      rows.push([hash,seriesId,zone,target,ordinal,row.group,old.day,old.time,
        next.day,next.time,next.duration,next.reminder,
        recipientHoursRule().from,recipientHoursRule().to,
        recipientHoursRule().days,recipientBlackoutText(),
        "false","false","false","false"]);
    }
    download(makeCsv(rows),"lightup-private-human-common-hours-proposals.csv",
      "text/csv;charset=utf-8");
    inform("Selected PRIVATE HUMAN planning proposals saved locally, not applied or sent.");
  }
  function printRecipientProposal(){
    hold(active&&recipientProposal&&!capacityEditorDirty &&
      recipientProposal.identity===recipientProposalIdentity());
    const selected=[...recipientProposal.slots].filter(([ordinal])=>
      recipientSelection.has(ordinal));
    hold(selected.length>0&&selected.length<=12);
    if(!confirm("Download a PRIVATE SCRIPTLESS HTML review sheet for "+selected.length+
      " selected, unapplied HUMAN proposals? It includes tentative dates, source hash and HUMAN group labels. Print/share only via an approved PRIVATE channel; this does NOT establish consent, scope or calendar delivery."))return;
    hold(recipientProposal&&recipientProposal.identity===recipientProposalIdentity());
    const cells=selected.map(([ordinal,next])=>{
      const old=plan.get(ordinal),row=items[ordinal-1];
      hold(old&&row&&row.ordinal===ordinal);
      return "<tr><td>#"+ordinal+"</td><td>"+htmlEsc(old.day+" "+old.time)+
        "</td><td>"+htmlEsc(next.day+" "+next.time)+
        "</td><td>"+htmlEsc(next.duration+" min")+"</td><td>"+
        htmlEsc(row.group||"(unassigned)")+"</td></tr>";
    }).join("");
    const content=['<!doctype html><html lang="en"><head><meta charset="utf-8">',
      '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;none&#39;; style-src &#39;none&#39;; connect-src &#39;none&#39;; img-src &#39;none&#39;; object-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
      '<title>PRIVATE HUMAN timezone proposal review</title></head><body>',
      '<h1>PRIVATE HUMAN proposed schedule changes</h1>',
      '<p>REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Unsigned HUMAN proposals, not source authentication, verified risk, calendar acceptance, consent, scope approval or permission to scan.</p>',
      '<p><strong>Original worksheet SHA256 (unsigned):</strong> '+htmlEsc(hash)+
        '<br><strong>Private calendar series (unsigned):</strong> '+htmlEsc(seriesId)+
        '<br><strong>Source local zone:</strong> '+htmlEsc(zone)+
        '<br><strong>Alternate display zone (unverified):</strong> '+
          htmlEsc(recipientFormatter().resolvedOptions().timeZone)+'</p>',
      '<p>HUMAN-declared alternate-zone window: '+htmlEsc(recipientHoursRule().from)+
        '–'+htmlEsc(recipientHoursRule().to)+' ('+
        htmlEsc(recipientHoursRule().days)+
        '). Unavailable local dates (HUMAN only): '+htmlEsc(recipientBlackoutText()||"(none declared)")+
        '. All availability is unverified; no external calendar contact.</p>',
      '<table border="1"><thead><tr><th>Ordinal</th><th>Previous source-zone proposal</th><th>Next source-zone proposal</th><th>Duration</th><th>Unverified HUMAN group</th></tr></thead><tbody>',
      cells,'</tbody></table><p>Authority: FALSE · Consent: FALSE · Verification: FALSE · Applied: FALSE.</p>',
      '<p>Review original private HUMAN worksheet/plan and approve separately before local changes. Retain PRIVATE; original HUMANS may reveal confidential schedule metadata.</p>',
      '</body></html>'].join("\n");
    download(content,"lightup-private-human-common-hours-review.html","text/html;charset=utf-8");
    inform("PRIVATE scriptless HUMAN proposal review HTML downloaded; no dates applied or remote services contacted.");
  }
  function applyRecipientProposal(){
    hold(active&&recipientProposal&&!capacityEditorDirty &&
      recipientProposal.identity===recipientProposalIdentity());
    const changedSlots=new Map([...recipientProposal.slots].filter(([id])=>
      recipientSelection.has(id))),simulated=new Map(plan);
    hold(changedSlots.size>0&&changedSlots.size<=12);
    for(const [ordinal,slot] of changedSlots){
      const row=items[ordinal-1],previous=simulated.get(ordinal);
      hold(row&&row.ordinal===ordinal&&previous&&row.stage!=="blocked");
      const admitted=admitSlot(slot.day,slot.time,slot.duration,slot.reminder);
      hold(eventDate(admitted.day,admitted.time)>eventDate(previous.day,previous.time));
      simulated.set(ordinal,admitted);
    }
    const intervals=eventIntervals(simulated);
    for(const [ordinal] of changedSlots){
      const current=intervals.find(e=>e.ordinal===ordinal);
      hold(current&&!intervals.some(e=>e.ordinal!==ordinal &&
        current.start<e.end&&e.start<current.end));
    }
    const daily=new Map();
    for(const row of items){
      const slot=simulated.get(row.ordinal);if(!slot)continue;
      const key=JSON.stringify([row.group,slot.day]);
      daily.set(key,(daily.get(key)||0)+1);
    }
    for(const [ordinal,slot] of changedSlots){
      const row=items[ordinal-1];
      hold(weekAvailabilityFlags(row,slot,daily).length===0 &&
        recipientWindow(eventDate(slot.day,slot.time),slot.duration,recipientClock())==="within_hours");
    }
    if(!confirm("Apply exactly "+changedSlots.size+" PRIVATE HUMAN draft reminder moves? These are NON-authorizing proposals using ONLY current HUMAN-declared recipient hours and locally declared source-group availability. Previously exported external appointments are NOT updated or cancelled."))return;
    hold(recipientProposal&&recipientProposal.identity===recipientProposalIdentity());
    const priorSlots=new Map([...changedSlots].map(([ordinal])=>
      [ordinal,{...plan.get(ordinal)}]));
    plan=simulated;recipientProposal=null;recipientSelection.clear();
    recipientUndo={fingerprint:workroomFingerprint(),before:priorSlots};
    changed=true;exportedPlan=false;
    page=0;agendaPage=0;render();$("recipientProposalDetails").open=false;
    inform("PRIVATE HUMAN planning moved locally. Save a new source-bound plan and manually reconcile any previous calendar imports.");
  }
  function undoRecipientProposal(){
    assertLocalZone();
    hold(active&&recipientUndo&&recipientUndo.fingerprint===workroomFingerprint());
    const previous=new Map(recipientUndo.before),restore=new Map(plan);
    hold(previous.size>0&&previous.size<=12);
    for(const [ordinal,slot] of previous){
      hold(items[ordinal-1]?.ordinal===ordinal&&plan.has(ordinal));
      restore.set(ordinal,admitSlot(slot.day,slot.time,slot.duration,slot.reminder));
    }
    if(!confirm("Undo exactly "+previous.size+" last PRIVATE HUMAN cross-zone draft moves? Only local tentative appointments will revert; externally exported calendars and recipient communications remain unchanged."))return;
    hold(recipientUndo&&recipientUndo.fingerprint===workroomFingerprint());
    plan=restore;recipientUndo=null;recipientProposal=null;recipientSelection.clear();
    changed=true;exportedPlan=false;render();
    inform("Last HUMAN cross-zone draft adjustment undone locally. Save the corrected PRIVATE workroom separately.");
  }

  function recipientGroupWorkload(source=recipientRows()){
    hold(active && source.length<=MAX_ROWS);
    const groups=new Map();
    for(const row of source){
      hold(["within_hours","outside_hours","weekend","unavailable_date","clock_change"].includes(row.status));
      if(!groups.has(row.group))groups.set(row.group,{group:row.group,total:0,
        within_hours:0,outside_hours:0,weekend:0,unavailable_date:0,clock_change:0});
      const record=groups.get(row.group);
      record.total++;record[row.status]++;
    }
    hold(groups.size<=MAX_ROWS);
    return [...groups.values()].sort((a,b)=>
      (b.total-b.within_hours)-(a.total-a.within_hours)||
      b.total-a.total||a.group.localeCompare(b.group));
  }
  function recipientGroupSnapshot(){
    const view=recipientGroupWorkload();
    hold(recipientPreferenceSource===hash+"|"+seriesId);
    const policy=recipientHoursRule(),target=recipientFormatter().resolvedOptions().timeZone;
    const key=JSON.stringify([workroomFingerprint(),recipientPreferenceSource,target,
      policy.from,policy.to,policy.days,recipientBlackoutText()]);
    return {view,target,key};
  }
  function recipientGroupReport(downloadHtml){
    let before;
    try{before=recipientGroupSnapshot();}catch(_){
      inform("HOLD: recipient timezone or unverified HUMAN availability is invalid. No group report exported.",true);return;
    }
    hold(before.view.length>0);
    if(!confirm("Create PRIVATE, UNSIGNED HUMAN recipient group workload ("+
      before.view.length+" anonymous groups)? Small-group counts may identify people in context. "+
      "Groups with fewer than three entries are pooled together. The file contains no group names, source identifiers, individual appointment dates or notes. "+
      "No recipient availability, consent or security decision is authenticated."))return;
    const after=recipientGroupSnapshot();
    hold(before.key===after.key && JSON.stringify(before.view)===JSON.stringify(after.view));
    const columns=RECIPIENT_COUNT_HEAD;
    // Aggregate cohorts smaller than three before export: never publish a
    // per-group low-count row that could be trivially associated with a person.
    // This is disclosure minimization, NOT a de-identification guarantee.
    const small=after.view.filter(g=>g.total<3);
    const material=after.view.filter(g=>g.total>=3);
    const rowFor=(label,g)=>[label,String(g.total),String(g.within_hours),
      String(g.outside_hours),String(g.weekend),String(g.unavailable_date),
      String(g.clock_change),"false","false","false","false","false"];
    const rows=material.map((g,i)=>rowFor("group_"+String(i+1).padStart(4,"0"),g));
    if(small.length){
      const aggregate={total:0,within_hours:0,outside_hours:0,weekend:0,
        unavailable_date:0,clock_change:0};
      for(const g of small)for(const key of Object.keys(aggregate))
        aggregate[key]+=g[key];
      rows.push(rowFor("small_groups_combined",aggregate));
    }
    hold(rows.length>0 && rows.length<=MAX_ROWS &&
      rows.reduce((n,row)=>n+Number(row[1]),0)===
        after.view.reduce((n,g)=>n+g.total,0));
    if(downloadHtml){
      const escapeValue=v=>String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;")
        .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
      const table=rows.map(row=>"<tr>"+row.slice(0,7).map(cell=>
        "<td>"+escapeValue(cell)+"</td>").join("")+"</tr>").join("");
      const th=columns.slice(0,7).map(label=>"<th scope=\"col\">"+
        escapeValue(label)+"</th>").join("");
      const documentText='<!doctype html><html lang="en"><head><meta charset="utf-8">'+
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\';'+
        ' connect-src \'none\'; style-src \'none\'; script-src \'none\';'+
        ' img-src \'none\'; base-uri \'none\'; form-action \'none\'">'+
        '<meta name="referrer" content="no-referrer"><title>PRIVATE HUMAN group review</title></head>'+
        '<body><h1>PRIVATE HUMAN group workload</h1><p>Unsigned; anonymous group slots '+
        'within this single export only. Source-reported, manually declared recipient windows; NOT authenticated.</p>'+
        '<p>'+rows.length+' groups, '+after.view.reduce((n,g)=>n+g.total,0)+
        ' proposed appointments. No actual calendar, identity, consent, grant or release is checked.</p>'+
        '<table border="1"><thead><tr>'+th+'</tr></thead><tbody>'+table+
        '</tbody></table><p>AUTHENTICATED=false; CONSENT_VERIFIED=false; DISPATCH_ALLOWED=false; RELEASE_ALLOWED=false.</p>'+
        '<p>Small cohorts can still reveal patterns. Do not publish without a separately authorized PRIVATE review.</p></body></html>';
      download(documentText,"lightup-private-anonymous-human-group-review.html","text/html;charset=utf-8");
    }else{
      download(makeCsv([columns,...rows]),"lightup-private-anonymous-human-group-workload.csv",
        "text/csv;charset=utf-8");
    }
    inform("PRIVATE aggregate HUMAN group review offered for local download; no source identity or consent proven.");
  }
  function focusNextRecipientGroupAttention(){
    let current;
    try{current=recipientGroupWorkload().filter(g=>g.total>g.within_hours);}
    catch(_){inform("HOLD: invalid HUMAN recipient window; nothing opened.",true);return;}
    if(!current.length)return;
    const index=current.findIndex(g=>g.group===recipientGroupFocus);
    recipientGroupFocus=current[(index+1)%current.length].group;
    recipientPage=0;
    $("recipientView").value="all";$("recipientQuery").value="";
    renderRecipientZone();
    $("recipientGroupSummary").scrollIntoView({block:"nearest"});
    inform("Opened next source-reported HUMAN group outside the declared window. This is not proof of real availability.");
  }

  const GROUP_COUNT_LABELS=[
    ["planned","Tentative HUMAN reminders"],
    ["within_hours","Within manually declared window"],
    ["outside_hours","Outside declared hours"],
    ["weekend","Outside declared weekdays"],
    ["unavailable_date","Unavailable recipient local day"],
    ["clock_change","Recipient clock change"]];
  function groupCategoryTotals(groups){
    const counts={total:0,within_hours:0,outside_hours:0,weekend:0,
      unavailable_date:0,clock_change:0};
    for(const group of groups)for(const key of Object.keys(counts))
      counts[key]+=group[key];
    hold(counts.total<=MAX_ROWS &&
      counts.total===counts.within_hours+counts.outside_hours+
        counts.weekend+counts.unavailable_date+counts.clock_change);
    return counts;
  }
  function renderRecipientCountComparison(){
    const body=$("recipientCountRows");body.replaceChildren();
    const valid=active && recipientGroupExportReady && !!recipientCountBaseline;
    $("recipientCountExport").disabled=!valid;
    $("recipientCountClear").disabled=!recipientCountBaseline;
    if(!valid){
      $("recipientCountSummary").textContent=recipientCountBaseline?
        "Previous anonymous counts retained in local memory; current recipient zone unavailable (HOLD).":
        "No previous anonymous group counts loaded.";
      return;
    }
    let current;
    try{current=groupCategoryTotals(recipientGroupWorkload());}
    catch(_){$("recipientCountExport").disabled=true;return;}
    $("recipientCountSummary").textContent="Two UNBOUND HUMAN count summaries. "+
      "The earlier imported file has no authenticated source identity: these may be different cohorts. "+
      "Current recipient zone and local availability are illustrative, not verified.";
    for(const [field,label] of GROUP_COUNT_LABELS){
      const a=recipientCountBaseline[field],b=current[field];
      const tr=dom("tr");
      tr.append(dom("td",label),dom("td",String(a)),dom("td",String(b)),
        dom("td",(b-a>0?"+":"")+String(b-a)));
      body.append(tr);
    }
  }
  async function importRecipientCounts(file){
    hold(active && file && file.size>0 && file.size<=150000);
    const ticket=++recipientCountImportToken,first=recipientGroupSnapshot();
    const raw=decoder.decode(await bytes(file));
    hold(ticket===recipientCountImportToken && first.key===recipientGroupSnapshot().key);
    hold(raw.length<=150000 && !raw.startsWith("\uFEFF") && !raw.includes("\0"));
    const parsed=csv(raw,RECIPIENT_COUNT_HEAD.length);
    hold(parsed.length>=2 && parsed.length<=MAX_ROWS+1 &&
      JSON.stringify(parsed[0])===JSON.stringify(RECIPIENT_COUNT_HEAD) &&
      makeCsv(parsed)===raw);
    const groups=[],seen=new Set();let prior=0,suppressed=false;
    for(const row of parsed.slice(1)){
      const label=row[0];
      if(label==="small_groups_combined"){
        hold(!suppressed);suppressed=true;
      }else{
        hold(!suppressed && /^group_[0-9]{4}$/.test(label));
        const id=Number(label.slice(6));
        hold(id===prior+1);prior=id;
      }
      hold(!seen.has(label));seen.add(label);
      hold(row.slice(7).every(value=>value==="false"));
      const values=row.slice(1,7).map(value=>{
        hold(/^(0|[1-9][0-9]{0,3})$/.test(value) && Number(value)<=MAX_ROWS);
        return Number(value);
      });
      hold(values[0]>=1 && values[0]===values.slice(1).reduce((x,y)=>x+y,0));
      if(label==="small_groups_combined")hold(values[0]>=1);
      else hold(values[0]>=3);
      groups.push({total:values[0],within_hours:values[1],outside_hours:values[2],
        weekend:values[3],unavailable_date:values[4],clock_change:values[5]});
    }
    const totals=groupCategoryTotals(groups);
    hold(ticket===recipientCountImportToken && first.key===recipientGroupSnapshot().key);
    if(!confirm("Use these UNBOUND source-free HUMAN category counts as an earlier comparison? "+
       "There is no group identity, original worksheet binding, timestamp or consent proof. "+
       "Different counts cannot establish a trend or security finding."))return;
    hold(ticket===recipientCountImportToken && first.key===recipientGroupSnapshot().key);
    recipientCountBaseline=totals;
    renderRecipientCountComparison();
    inform("Earlier anonymous count summary loaded into this tab only; no original source or identity is matched.");
  }
  function exportRecipientCountComparison(){
    const current=recipientGroupSnapshot();
    hold(recipientCountBaseline && current.view.length>0);
    const latest=groupCategoryTotals(current.view),lines=[
      ["human_category","earlier_unbound_count","current_unverified_count","difference",
      "same_cohort_verified","authorized","consent_verified","release_allowed"]];
    for(const [key,label] of GROUP_COUNT_LABELS){
      lines.push([label,String(recipientCountBaseline[key]),String(latest[key]),
        String(latest[key]-recipientCountBaseline[key]),"false","false","false","false"]);
    }
    if(!confirm("Export PRIVATE HUMAN counts comparison? Earlier and current counts are NOT source, group or cohort matched; no trend, verified improvement or consent is claimed."))return;
    hold(current.key===recipientGroupSnapshot().key);
    download(makeCsv(lines),"lightup-private-unbound-human-count-comparison.csv",
      "text/csv;charset=utf-8");
    inform("PRIVATE unbound aggregate comparison exported without source identifiers or HUMAN notes.");
  }

  function renderRecipientGroups(source){
    const ordered=recipientGroupWorkload(source);
    recipientGroupExportReady=ordered.length>0;
    for(const id of ["recipientGroupCsv","recipientGroupPrint"])
      $(id).disabled=!recipientGroupExportReady;
    $("recipientGroupNextAttention").disabled=!ordered.some(row=>row.total>row.within_hours);
    renderRecipientCountComparison();
    const pages=Math.max(1,Math.ceil(ordered.length/32));
    recipientGroupPage=Math.max(0,Math.min(recipientGroupPage,pages-1));
    $("recipientGroupPrev").disabled=recipientGroupPage===0;
    $("recipientGroupNext").disabled=recipientGroupPage===pages-1;
    $("recipientGroupClear").disabled=recipientGroupFocus===null;
    $("recipientGroupSummary").textContent=ordered.length+
      " unverified HUMAN groups with scheduled appointments in this PRIVATE workroom · "+
      "page "+(recipientGroupPage+1)+" of "+pages+
      " · exact group focus: "+(recipientGroupFocus===null?"all":
        recipientGroupFocus||"(unassigned)")+
      ". Counts use source-reported group labels, NOT identities or verified availability.";
    const body=$("recipientGroupRows");body.replaceChildren();
    for(const row of ordered.slice(recipientGroupPage*32,recipientGroupPage*32+32)){
      const tr=dom("tr"),focus=dom("button","Focus group","ghost");
      focus.type="button";
      focus.addEventListener("click",()=>{
        recipientGroupFocus=row.group;recipientPage=0;
        renderRecipientZone();$("recipientDesk").scrollIntoView({block:"start"});
      });
      for(const value of [row.group||"(unassigned)",row.total,
        row.within_hours,row.outside_hours,row.weekend,
        row.unavailable_date,row.clock_change])tr.append(dom("td",String(value)));
      const cell=dom("td");cell.append(focus);tr.append(cell);body.append(tr);
    }
  }
  function renderRecipientZone(){
    if(!active)return;
    if(recipientUndo && recipientUndo.fingerprint!==workroomFingerprint())
      recipientUndo=null;
    $("recipientUndo").disabled=!recipientUndo;
    const body=$("recipientRows");body.replaceChildren();
    let data,all;
    try{
      if(recipientProposal)renderRecipientProposal();
      all=recipientRows();data=recipientFiltered(all);
      renderRecipientGroups(all);
    }
    catch(_){
      recipientProposal=null;recipientSelection.clear();
      renderRecipientProposal();
      recipientGroupExportReady=false;
      renderRecipientCountComparison();
      for(const id of ["recipientGroupCsv","recipientGroupPrint","recipientGroupNextAttention"])
        $(id).disabled=true;
      $("recipientGroupRows").replaceChildren();
      for(const id of ["recipientGroupClear","recipientGroupPrev","recipientGroupNext"])
        $(id).disabled=true;
      $("recipientGroupSummary").textContent=
        "Invalid recipient IANA zone or HUMAN-declared date/window (HOLD).";
      $("recipientSummary").textContent="Invalid IANA zone or changed browser timezone (HOLD). No converted dates accepted.";
      $("recipientExport").disabled=true;
      $("recipientPrev").disabled=true;$("recipientNext").disabled=true;
      $("recipientRemainder").textContent="";return;
    }
    const pages=Math.max(1,Math.ceil(data.length/35));
    recipientPage=Math.max(0,Math.min(recipientPage,pages-1));
    $("recipientPrev").disabled=recipientPage===0;
    $("recipientNext").disabled=recipientPage>=pages-1;
    $("recipientExport").disabled=!data.length;
    const warns=all.filter(r=>r.status!=="within_hours").length;
    $("recipientSummary").textContent=all.length+" tentative HUMAN proposals · "+
      warns+" outside HUMAN-declared "+recipientHoursRule().from+"–"+
      recipientHoursRule().to+" ("+recipientHoursRule().days+") in "+
      recipientFormatter().resolvedOptions().timeZone+" · "+data.length+
      " matching filter. Illustrative hours are NOT authenticated recipient availability.";
    for(const r of data.slice(recipientPage*35,recipientPage*35+35)){
      const tr=dom("tr"),b=dom("button","Edit #"+r.ordinal);
      b.type="button";b.addEventListener("click",()=>focusOrdinal(r.ordinal));
      const notice=r.status==="clock_change"?"Recipient local clock change":
        r.status==="unavailable_date"?"Recipient unavailable local date":
        r.status==="weekend"?"Outside declared weekdays":
        r.status==="outside_hours"?"Outside declared hours":"Within declared window";
      tr.append(dom("td","#"+r.ordinal),
        dom("td",r.day+" "+r.time+" / "+zone),
        dom("td",r.converted+" → "+r.endConverted),
        dom("td",notice),dom("td",r.group||"(unassigned)"));
      const td=dom("td");td.append(b);tr.append(td);body.append(tr);
    }
    $("recipientRemainder").textContent="Showing page "+(recipientPage+1)+" of "+pages+
      " · "+data.length+" filtered private HUMAN proposals; no external calendar checked.";
  }
  function exportRecipientZone(){
    hold(active && /^[a-f0-9]{64}$/.test(hash));
    const rows=recipientFiltered(),target=recipientFormatter().resolvedOptions().timeZone;
    hold(rows.length>0 && rows.length<=MAX_ROWS);
    if(!confirm("Export PRIVATE unsigned HUMAN time-zone conversion for "+rows.length+
      " proposed reminders? Includes original worksheet digest, HUMAN group and private schedule. No consent, verified calendar delivery or security status is established."))return;
    const output=[["worksheet_sha256_unsigned","series_unsigned","source_zone",
      "display_zone_unverified","original_ordinal","human_group_unverified",
      "source_local_date","source_local_time","utc","other_zone_display",
      "other_zone_end","human_declared_window_start","human_declared_window_end",
      "human_declared_days","human_unavailable_dates_unverified",
      "window_status_unverified","authorized","verified","consent"]];
    for(const row of rows)output.push([hash,seriesId,zone,target,row.ordinal,row.group,
      row.day,row.time,row.utc,row.converted,row.endConverted,
      recipientHoursRule().from,recipientHoursRule().to,recipientHoursRule().days,
      recipientBlackoutText(),row.status,"false","false","false"]);
    download(makeCsv(output),"lightup-private-human-zone-handoff.csv","text/csv;charset=utf-8");
    inform("PRIVATE alternate-zone HUMAN schedule exported locally; no recipient or calendar contacted.");
  }
  function renderAgenda(){
    if(!active)return;
    const now=new Date(),days=$("agendaHorizon").value;
    const q=$("agendaQuery").value.trim().toLocaleLowerCase();
    const colliding=collisionIds();
    renderConflictPreview();
    $("conflictPanel").hidden=colliding.size===0;
    $("conflictSummary").textContent=colliding.size+" HUMAN reminders overlap in this workroom. These are timing clashes only; not a security or authorization verdict.";
    let upcoming=items.filter(r=>{
      const p=plan.get(r.ordinal);if(!p)return false;
      const at=eventDate(p.day,p.time);
      if(days==="overdue" && at>=now)return false;
      if(days==="conflicts" && !colliding.has(r.ordinal))return false;
      if(days==="7"||days==="30"){
        const limit=new Date(now.getTime()+Number(days)*86400000);
        if(at<now||at>limit)return false;
      }
      return !q || [r.group,r.action,r.blocker,String(r.ordinal)].some(v=>v.toLocaleLowerCase().includes(q));
    });
    upcoming.sort((a,b)=>{
      const p=plan.get(a.ordinal),v=plan.get(b.ordinal);
      return (p.day+"T"+p.time).localeCompare(v.day+"T"+v.time)||a.ordinal-b.ordinal;
    });
    const totalPages=Math.max(1,Math.ceil(upcoming.length/50));
    agendaPage=Math.max(0,Math.min(agendaPage,totalPages-1));
    $("agendaPrev").disabled=agendaPage===0;
    $("agendaNext").disabled=agendaPage>=totalPages-1;
    $("agendaSummary").textContent=upcoming.length+" scheduled HUMAN reminders in this view · page "+(agendaPage+1)+" of "+totalPages+" · "+zone+" · PRIVATE planning, not security evidence.";
    const body=$("agendaRows");body.replaceChildren();
    for(const r of upcoming.slice(agendaPage*50,agendaPage*50+50)){
      const p=plan.get(r.ordinal),tr=dom("tr"),edit=dom("button","Edit original #"+r.ordinal,"ghost");
      edit.type="button";
      edit.addEventListener("click",()=>focusOrdinal(r.ordinal));
      const cell=dom("td");cell.append(edit);
      tr.append(dom("td",p.day+" "+p.time),dom("td","#"+r.ordinal),
        dom("td",r.severity),dom("td",(r.stage||"unset")+" / "+(r.group||"unassigned")),
        dom("td",r.action||"No HUMAN action supplied"),cell);
      body.append(tr);
    }
  }
  function dayString(d){
    return [d.getFullYear(),String(d.getMonth()+1).padStart(2,"0"),
      String(d.getDate()).padStart(2,"0")].join("-");
  }
  function moveDay(day,days){
    const date=eventDate(day,"12:00");date.setDate(date.getDate()+days);
    return dayString(date);
  }
  function startWeek(day){
    const date=eventDate(day,"12:00");date.setDate(date.getDate()-(date.getDay()+6)%7);
    return dayString(date);
  }
  function focusOrdinal(ordinal){
    selectedGroup=null;
    $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
    page=Math.floor((ordinal-1)/PAGE);render();
    const source=document.querySelector('#rows tr[data-ordinal="'+ordinal+'"] input[type="date"]');
    $("desk").scrollIntoView({behavior:"smooth",block:"start"});
    if(source)source.focus({preventScroll:true});
  }
  function weekAvailabilityFlags(row,slot,dailyCounts,overrideRule=null){
    const rule=overrideRule||capacityRules.get(row.group)||capacityDefaultRule();
    const start=eventDate(slot.day,slot.time);
    const begin=start.getHours()*60+start.getMinutes();
    const mins=time=>Number(time.slice(0,2))*60+Number(time.slice(3,5));
    const flags=[];
    if(!rule.days.includes(start.getDay()))flags.push("outside HUMAN weekdays");
    if(rule.blackouts.includes(slot.day))flags.push("HUMAN blackout date");
    if(begin<mins(rule.start)||begin+Number(slot.duration)>mins(rule.end)){
      flags.push("outside HUMAN hours");
    }
    if((dailyCounts.get(JSON.stringify([row.group,slot.day]))||0)>rule.maximum){
      flags.push("above HUMAN group daily cap");
    }
    return flags;
  }
  function proposeLocalAlternative(ordinal){
    assertLocalZone();
    hold(active && Number.isSafeInteger(ordinal));
    const row=items[ordinal-1],old=plan.get(ordinal);
    hold(row && row.ordinal===ordinal && old);
    const rule=capacityRules.get(row.group)||capacityDefaultRule();
    const minuteOf=time=>Number(time.slice(0,2))*60+Number(time.slice(3,5));
    const occupied=eventIntervals().filter(event=>event.ordinal!==ordinal);
    const remaining=new Map();
    for(const candidate of items){
      if(candidate.ordinal===ordinal)continue;
      const p=plan.get(candidate.ordinal);
      if(p && candidate.group===row.group){
        remaining.set(p.day,(remaining.get(p.day)||0)+1);
      }
    }
    const current=eventDate(old.day,old.time);
    const now=new Date();
    const start=eventDate(current>now?old.day:nowToday(),"12:00");
    const duration=Number(old.duration),reminder=old.reminder;
    const earliest=Math.max(current.getTime(),now.getTime());
    let result=null;
    for(let offset=0;offset<31&&!result;offset++){
      const date=new Date(start.getTime());
      date.setDate(date.getDate()+offset);
      const day=dayString(date);
      if(!day.startsWith("20"))break;
      if(!rule.days.includes(date.getDay())||rule.blackouts.includes(day)||
          (remaining.get(day)||0)>=rule.maximum)continue;
      const first=Math.ceil(minuteOf(rule.start)/15)*15;
      const latest=minuteOf(rule.end)-duration;
      for(let minutes=first;minutes<=latest;minutes+=15){
        const time=String(Math.floor(minutes/60)).padStart(2,"0")+":"+
          String(minutes%60).padStart(2,"0");
        let proposed;
        try{proposed=eventDate(day,time).getTime();}catch(_){continue;}
        if(proposed<=earliest)continue;
        if(occupied.some(other=>proposed<other.end&&other.start<proposed+duration*60000))continue;
        try{result=admitSlot(day,time,old.duration,reminder);}
        catch(_){continue;} // A wall-time transition is not a valid alternative.
        break;
      }
    }
    if(!result){
      inform("No non-overlapping HUMAN proposal within the next 31 local days under declared group rules. The original appointment is unchanged.",true);
      return;
    }
    if(!confirm("Propose moving HUMAN reminder #"+ordinal+" from "+old.day+" "+old.time+
      " to "+result.day+" "+result.time+" ("+duration+" min)? This uses DECLARED HUMAN group hours, weekdays, blackout days and daily cap, and avoids overlaps within this one local workroom. Real availability, consent, source authenticity and original risk were NOT checked. This changes only the PRIVATE draft; save the whole v2 plan separately."))return;
    // Source and plan are synchronous in-memory state; the UI changes only after confirmation.
    plan.set(ordinal,result);
    changed=true;exportedPlan=false;page=0;render();
    inform("New HUMAN-only local time proposed for #"+ordinal+
      ". Previous calendar entry is not cancelled. Save the new plan and use explicit PRIVATE calendar change handoff if previously published.");
  }
  function jumpScheduledWeek(direction){
    hold(active && [1,-1].includes(direction));
    const groupSelector=$("weekGroup");
    const groups=capacityGroups();
    const group=groupSelector.value?groups[Number(groupSelector.value)-1]:null;
    const focusOverlap=$("weekConflicts").checked,focusRules=$("weekConstraints").checked;
    const overlaps=focusOverlap?collisionIds():null;
    const dailyCounts=new Map();
    for(const row of items){
      const slot=plan.get(row.ordinal);
      if(!slot)continue;
      const key=JSON.stringify([row.group,slot.day]);
      dailyCounts.set(key,(dailyCounts.get(key)||0)+1);
    }
    const current=startWeek(weekAnchor||nowToday());
    const matchingDays=items.flatMap(row=>{
      const slot=plan.get(row.ordinal);
      if(!slot||(group!==null&&row.group!==group)||
        (focusOverlap&&!overlaps.has(row.ordinal))||
        (focusRules&&!weekAvailabilityFlags(row,slot,dailyCounts).length))return [];
      const day=startWeek(slot.day);
      return [day];
    }).filter(day=>direction>0?day>current:day<current).sort();
    if(!matchingDays.length){
      inform("No "+(direction>0?"later":"earlier")+
        " HUMAN week matches the current group and warning filters. Current week unchanged.");
      return;
    }
    weekAnchor=direction>0?matchingDays[0]:matchingDays[matchingDays.length-1];
    renderWeek();
    $("week").scrollIntoView({behavior:"smooth",block:"start"});
  }
  function renderWeek(){
    if(!active)return;
    if(!weekAnchor)weekAnchor=nowToday();
    const groups=capacityGroups(), selectGroup=$("weekGroup"), prior=selectGroup.value;
    if(selectGroup.options.length!==groups.length+1 ||
      groups.some((g,i)=>selectGroup.options[i+1]?.textContent!== (g||"(unassigned)"))){
      selectGroup.replaceChildren();
      const all=dom("option","All HUMAN groups");all.value="";selectGroup.append(all);
      groups.forEach((g,i)=>{
        const option=dom("option",g||"(unassigned)");option.value=String(i+1);selectGroup.append(option);
      });
      selectGroup.value=prior;
      if(selectGroup.selectedIndex<0)selectGroup.value="";
    }
    const focus=selectGroup.value ? groups[Number(selectGroup.value)-1] : null;
    const monday=startWeek(weekAnchor),sunday=moveDay(monday,6),collisions=collisionIds();
    $("weekDate").value=weekAnchor;
    const body=$("weekDays");body.replaceChildren();
    const dailyCounts=new Map();
    for(const r of items){
      const p=plan.get(r.ordinal);
      if(!p)continue;
      const key=JSON.stringify([r.group,p.day]);
      dailyCounts.set(key,(dailyCounts.get(key)||0)+1);
    }
    const constraintFlags=new Map();
    for(const r of items){
      const p=plan.get(r.ordinal);
      if(p)constraintFlags.set(r.ordinal,weekAvailabilityFlags(r,p,dailyCounts));
    }
    const onlyConflicts=$("weekConflicts").checked;
    const onlyConstraints=$("weekConstraints").checked;
    const relevant=items.filter(r=>{
      if(!plan.has(r.ordinal))return false;
      if(focus!==null && r.group!==focus)return false;
      if(onlyConflicts && !collisions.has(r.ordinal))return false;
      if(onlyConstraints && !constraintFlags.get(r.ordinal).length)return false;
      const day=plan.get(r.ordinal).day;
      return day>=monday && day<=sunday;
    });
    const countConflict=relevant.filter(r=>collisions.has(r.ordinal)).length;
    const countUnavailable=relevant.filter(r=>constraintFlags.get(r.ordinal).length).length;
    $("weekSummary").textContent=monday+" — "+sunday+" · "+
      relevant.length+" proposed HUMAN reminders · "+countConflict+
      " local overlaps · "+countUnavailable+
      " declared HUMAN availability mismatches · "+zone+" · no real availability checked.";
    for(let offset=0;offset<7;offset++){
      const day=moveDay(monday,offset);
      const entries=relevant.filter(r=>plan.get(r.ordinal).day===day).sort((a,b)=>{
        const left=plan.get(a.ordinal),right=plan.get(b.ordinal);
        return left.time.localeCompare(right.time)||a.ordinal-b.ordinal;
      });
      const column=dom("section",undefined,"week-day");
      column.setAttribute("aria-label",day+" proposed HUMAN reminders");
      const title=dom("h3",["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][offset]+" · "+day.slice(5));
      column.append(title,dom("p",entries.length+" proposed appointments","subtle"));
      for(const r of entries.slice(0,24)){
        const p=plan.get(r.ordinal),colliding=collisions.has(r.ordinal);
        const declaredFlags=constraintFlags.get(r.ordinal);
        const button=dom("button",undefined,"week-event"+(colliding?" week-clash":"")+
          (declaredFlags.length?" week-unavailable":""));
        button.type="button";button.addEventListener("click",()=>focusOrdinal(r.ordinal));
        const time=dom("strong",p.time+" · "+p.duration+" min · #"+r.ordinal);
        const details=dom("span",(r.group||"(unassigned)")+" · "+r.severity+" (source-reported)");
        const status=dom("small",(colliding?"OVERLAP · ":"")+(r.stage||"HUMAN stage unset"));
        button.append(time,details,status);
        if(declaredFlags.length){
          button.append(dom("small","HUMAN rule mismatch: "+declaredFlags.join("; "),"week-warning"));
        }
        button.setAttribute("aria-label","Open original HUMAN ordinal "+r.ordinal+
          " in planner, "+p.time+" on "+day+(colliding?", local overlap":"")+
          (declaredFlags.length?", declared group availability mismatch: "+declaredFlags.join("; "):""));
        column.append(button);
        const alternative=dom("button","Find next HUMAN slot","ghost week-alternate");
        alternative.type="button";
        alternative.setAttribute("aria-label","Propose next locally available HUMAN time for original ordinal "+r.ordinal);
        alternative.addEventListener("click",()=>{
          try{proposeLocalAlternative(r.ordinal);}
          catch(_){inform("Could not construct a valid local HUMAN alternative; original reminder unchanged.",true);}
        });
        column.append(alternative);
      }
      if(entries.length>24)column.append(dom("p",(entries.length-24)+
        " more HUMAN reminders; use the full agenda to edit.","subtle"));
      if(!entries.length)column.append(dom("p","No proposed reminders","subtle"));
      body.append(column);
    }
  }
  function monthShift(month,diff){
    hold(/^20\d{2}-(0[1-9]|1[0-2])$/.test(month) && [-1,1].includes(diff));
    const year=Number(month.slice(0,4)),number=Number(month.slice(5,7));
    const target=new Date(year,number-1+diff,1,12);
    hold(target.getFullYear()>=2000 && target.getFullYear()<=2099);
    return dayString(target).slice(0,7);
  }
  function monthRows(){
    hold(active && /^20\d{2}-(0[1-9]|1[0-2])$/.test(monthAnchor));
    const groups=capacityGroups(),choice=$("monthGroup").value,
      focused=choice?groups[Number(choice)-1]:null;
    const collisions=collisionIds();
    const year=Number(monthAnchor.slice(0,4)),month=Number(monthAnchor.slice(5,7)),
      days=new Date(year,month,0,12).getDate();
    const rows=[];
    for(let date=1;date<=days;date++){
      const day=monthAnchor+"-"+String(date).padStart(2,"0");
      const matching=items.filter(row=>{
        const p=plan.get(row.ordinal);
        return p && p.day===day && (focused===null || row.group===focused);
      });
      rows.push({day,planned:matching.length,overlap:matching.filter(r=>
        collisions.has(r.ordinal)).length,blocked:matching.filter(r=>
        r.stage==="blocked").length});
    }
    return {rows,filtered:focused!==null};
  }
  function exportMonthBrief(kind){
    const snapshot=monthRows();
    const relevant=snapshot.rows;
    const summary=relevant.reduce((out,row)=>{
      out.planned+=row.planned;out.overlap+=row.overlap;out.blocked+=row.blocked;return out;
    },{planned:0,overlap:0,blocked:0});
    const filter=snapshot.filtered?"One locally chosen unverified HUMAN group":"All HUMAN groups";
    if(!confirm("Download "+monthAnchor+" HUMAN-only "+(kind==="csv"?"daily count CSV":"scriptless month report")+
      "? "+filter+". Daily totals can disclose small private cohort activity. No original targets, evidence or HUMAN action text will be included. Use only authorized PRIVATE storage."))return;
    if(kind==="csv"){
      const rows=[["date_local","proposed_human_reminders","local_overlap_markers","original_human_blocked_stages"],
        ...relevant.map(r=>[r.day,String(r.planned),String(r.overlap),String(r.blocked)])];
      download(makeCsv(rows),"lightup-private-human-month-counts.csv","text/csv;charset=utf-8");
    }else{
      const escaped=htmlEsc(monthAnchor),safeZone=htmlEsc(zone);
      const table=relevant.map(r=>"<tr><th>"+htmlEsc(r.day)+"</th><td>"+r.planned+
        "</td><td>"+r.overlap+"</td><td>"+r.blocked+"</td></tr>").join("");
      const page='<!doctype html><html lang="en"><head><meta charset="utf-8">'+
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'+
        '<meta name="viewport" content="width=device-width, initial-scale=1">'+
        "<title>PRIVATE HUMAN monthly planning summary</title>"+
        "<style>body{font:15px/1.5 system-ui;max-width:860px;margin:32px auto;padding:16px;color:#18212d}"+
        "table{border-collapse:collapse;width:100%}th,td{padding:8px;border:1px solid #778;text-align:left}"+
        "thead{background:#e6ecf2}p{max-width:80ch}@media print{body{margin:0}}</style></head><body>"+
        "<h1>PRIVATE HUMAN planning · "+escaped+"</h1><p><strong>REVIEW_ONLY · NO AUTHORITY · UNSIGNED.</strong> "+
        "This report is a proposal derived only from the currently open browser workroom; not an independent "+
        "security finding, approval, real staff availability, consent, completed follow-up or calendar synchronization.</p>"+
        "<p>Scope: "+htmlEsc(filter)+". Timezone: "+safeZone+". "+
        summary.planned+" tentative reminders, "+summary.overlap+" local overlap markers, "+
        summary.blocked+" source-declared HUMAN blocked stages.</p>"+
        "<table><thead><tr><th>Local date</th><th>HUMAN planned</th><th>Local overlap</th>"+
        "<th>HUMAN blocked stages</th></tr></thead><tbody>"+table+"</tbody></table>"+
        "<p>Original source details, identity labels, HUMAN action text, findings, targets and evidence "+
        "have not been included. Small totals may nevertheless be sensitive: keep this report PRIVATE.</p>"+
        "</body></html>";
      download(page,"lightup-private-human-month-summary.html","text/html;charset=utf-8");
    }
    inform("PRIVATE source-free month counts downloaded. No file uploaded, assessment executed or calendar updated.");
  }
  function renderMonth(){
    if(!active)return;
    if(!monthAnchor)monthAnchor=nowToday().slice(0,7);
    const groups=capacityGroups(),input=$("monthGroup"),previous=input.value;
    if(input.options.length!==groups.length+1 ||
       groups.some((group,i)=>input.options[i+1]?.textContent!==(group||"(unassigned)"))){
      input.replaceChildren();
      const option=dom("option","All HUMAN groups");option.value="";input.append(option);
      groups.forEach((group,i)=>{
        const option=dom("option",group||"(unassigned)");
        option.value=String(i+1);input.append(option);
      });
      input.value=previous;if(input.selectedIndex<0)input.value="";
    }
    const selected=input.value?groups[Number(input.value)-1]:null;
    const year=Number(monthAnchor.slice(0,4)),month=Number(monthAnchor.slice(5,7));
    const first=new Date(year,month-1,1,12),totalDays=new Date(year,month,0,12).getDate();
    hold(first.getFullYear()===year && first.getMonth()===month-1);
    const before=(first.getDay()+6)%7,collisions=collisionIds();
    const planned=items.filter(row=>plan.has(row.ordinal) &&
      (selected===null || row.group===selected) &&
      plan.get(row.ordinal).day.startsWith(monthAnchor));
    const byDay=new Map();
    for(const row of planned){
      const key=plan.get(row.ordinal).day;
      if(!byDay.has(key))byDay.set(key,[]);
      byDay.get(key).push(row);
    }
    const overlaps=planned.filter(r=>collisions.has(r.ordinal)).length;
    const blocked=planned.filter(r=>r.stage==="blocked").length;
    $("monthSelect").value=monthAnchor;
    $("monthSummary").textContent=planned.length+" proposed HUMAN reminders · "+
      overlaps+" overlap markers · "+blocked+" blocked HUMAN stages · "+
      byDay.size+" active dates · "+zone+" · no external calendar checked.";
    const grid=$("monthGrid");grid.replaceChildren();
    for(const label of ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"])
      grid.append(dom("strong",label,"month-weekday"));
    for(let x=0;x<before;x++){
      const blank=dom("div","","month-empty");blank.setAttribute("aria-hidden","true");grid.append(blank);
    }
    for(let day=1;day<=totalDays;day++){
      const key=monthAnchor+"-"+String(day).padStart(2,"0");
      const rows=byDay.get(key)||[],clashes=rows.filter(r=>collisions.has(r.ordinal)).length,
        blockedCount=rows.filter(r=>r.stage==="blocked").length;
      const button=dom("button",undefined,"month-day"+(key===nowToday()?" month-current":"")+
        (clashes?" month-overlap":""));
      button.type="button";button.append(dom("strong",String(day)),dom("span",rows.length+" HUMAN planned"));
      if(clashes)button.append(dom("small",clashes+" local overlap"));
      if(blockedCount)button.append(dom("small",blockedCount+" blocked stage"));
      button.setAttribute("aria-label",key+": "+rows.length+" proposed HUMAN reminders, "+
        clashes+" overlapping reminders, "+blockedCount+" blocked HUMAN stages. Open week.");
      button.addEventListener("click",()=>{
        weekAnchor=key;renderWeek();$("week").scrollIntoView({behavior:"smooth",block:"start"});
      });
      grid.append(button);
    }
  }
  function backlogFiltered(){
    const groups=capacityGroups(),selector=$("backlogGroup");
    const group=selector.value?groups[Number(selector.value)-1]:null;
    const q=$("backlogQuery").value.trim().toLocaleLowerCase();
    const view=$("backlogView").value;
    return items.filter(row=>{
      if(plan.has(row.ordinal))return false;
      if(group!==null && row.group!==group)return false;
      if(view==="open" && row.stage==="blocked")return false;
      if(view==="blocked" && row.stage!=="blocked")return false;
      if(q && ![String(row.ordinal),row.group,row.action,row.blocker].some(v=>
        v.toLocaleLowerCase().includes(q)))return false;
      return true;
    });
  }
  function proposalForUnscheduled(ordinal,fromDay,scheduled=plan){
    assertLocalZone();
    hold(active && Number.isSafeInteger(ordinal) && ordinal>=1&&ordinal<=items.length);
    const row=items[ordinal-1];
    hold(row.ordinal===ordinal && !scheduled.has(ordinal) && row.stage!=="blocked");
    eventDate(fromDay,"12:00");
    hold(fromDay>=nowToday());
    const rule=capacityRules.get(row.group)||capacityDefaultRule();
    const existing=eventIntervals(scheduled),daily=new Map();
    for(const other of items){
      const p=scheduled.get(other.ordinal);
      if(!p || other.group!==row.group)continue;
      daily.set(p.day,(daily.get(p.day)||0)+1);
    }
    const timeMin=time=>Number(time.slice(0,2))*60+Number(time.slice(3,5));
    const firstMinute=Math.ceil(timeMin(rule.start)/15)*15;
    const lastMinute=timeMin(rule.end)-30;
    const start=eventDate(fromDay,"12:00"),now=Date.now();
    for(let days=0;days<31;days++){
      const date=new Date(start.getTime());date.setDate(start.getDate()+days);
      const day=dayString(date);
      if(!day.startsWith("20"))break;
      if(!rule.days.includes(date.getDay())||rule.blackouts.includes(day)||
        (daily.get(day)||0)>=rule.maximum)continue;
      for(let minute=firstMinute;minute<=lastMinute;minute+=15){
        const time=String(Math.floor(minute/60)).padStart(2,"0")+":"+
          String(minute%60).padStart(2,"0");
        let candidate;
        try{candidate=eventDate(day,time).getTime();}catch(_){continue;}
        if(candidate<=now || existing.some(e=>candidate<e.end && e.start<candidate+30*60000))continue;
        try{return admitSlot(day,time,"30","15");}
        catch(_){continue;} // Try a later, unambiguous private reminder.
      }
    }
    return null;
  }
  function proposeBacklog(ordinal){
    const from=$("backlogStart").value;
    const slot=proposalForUnscheduled(ordinal,from);
    if(!slot){
      inform("No free tentative HUMAN slot under declared group rules within 31 local days. Original review row unchanged.",true);
      return;
    }
    const row=items[ordinal-1];
    if(!confirm("Add an UNSIGNED tentative HUMAN reminder for original #"+ordinal+
      " ("+(row.group||"unassigned")+") on "+slot.day+" "+slot.time+
      "? This is a local 30-minute HUMAN proposal only. Real availability, security status, consent and scope have not been verified. No external calendars will be modified."))return;
    hold(active && !plan.has(ordinal) && row.stage!=="blocked");
    plan.set(ordinal,slot);changed=true;exportedPlan=false;backlogPage=0;render();
    inform("Added PRIVATE HUMAN draft reminder for #"+ordinal+
      ". Save the original source-bound v2 plan before leaving the workroom.");
  }
  function backlogSignature(){
    return JSON.stringify([hash,seriesId,zone,
      Array.from(plan.entries()).sort((a,b)=>a[0]-b[0]),
      Array.from(capacityRules.entries()).sort((a,b)=>a[0].localeCompare(b[0])),
      $("backlogStart").value,$("backlogView").value,
      $("backlogGroup").value,$("backlogQuery").value,
      backlogFiltered().slice(0,12).map(row=>row.ordinal)]);
  }
  function renderBacklogPreview(){
    const valid=backlogProposal && backlogProposal.signature===backlogSignature();
    if(!valid)backlogProposal=null;
    const body=$("backlogPreviewRows");body.replaceChildren();
    $("backlogApply").disabled=!valid;
    if(!valid){
      $("backlogPreviewStatus").textContent=
        "No current source-bound proposal. Prepare a new one for this exact workroom and filter.";
      return;
    }
    $("backlogPreviewStatus").textContent=backlogProposal.slots.size+
      " UNSIGNED HUMAN-only proposals ready for explicit confirmation. No local plan or external calendar has changed.";
    for(const [ordinal,slot] of backlogProposal.slots){
      const row=items[ordinal-1],tr=dom("tr");
      tr.append(dom("td","#"+ordinal),dom("td",row.group||"(unassigned)"),
        dom("td",slot.day),dom("td",slot.time),dom("td",slot.duration+" minutes"));
      body.append(tr);
    }
  }
  function prepareBacklogBatch(){
    hold(active);
    const candidates=backlogFiltered().filter(row=>row.stage!=="blocked").slice(0,12);
    hold(candidates.length>0);
    const from=$("backlogStart").value;
    eventDate(from,"12:00");hold(from>=nowToday());
    const tentative=new Map(plan),prepared=new Map();
    for(const row of candidates){
      const next=proposalForUnscheduled(row.ordinal,from,tentative);
      if(!next){
        backlogProposal=null;renderBacklogPreview();
        inform("HUMAN group proposal held: no local valid slot within 31 days for original #"+
          row.ordinal+". Nothing changed, including earlier proposals.",true);return;
      }
      tentative.set(row.ordinal,next);prepared.set(row.ordinal,next);
    }
    backlogProposal={signature:backlogSignature(),slots:prepared};
    $("backlogPreviewDetails").open=true;renderBacklogPreview();
    inform("Prepared "+prepared.size+" complete PRIVATE HUMAN provisional reminders. Check every row before applying; no appointments have changed.");
  }
  function applyBacklogBatch(){
    hold(backlogProposal && backlogProposal.signature===backlogSignature());
    const proposals=backlogProposal.slots;
    hold(proposals.size>0 && proposals.size<=12);
    if(!confirm("Apply exactly "+proposals.size+" tentative HUMAN reminders to the PRIVATE local plan? "+
      "The original source fields, real calendars, people, authority and verified security state will NOT change. "+
      "These are entirely human-confirmed local drafts requiring an explicit full v2 plan save."))return;
    hold(backlogProposal && backlogProposal.signature===backlogSignature());
    for(const [ordinal,slot] of proposals){
      hold(!plan.has(ordinal) && items[ordinal-1]?.stage!=="blocked");
      admitSlot(slot.day,slot.time,slot.duration,slot.reminder);
    }
    const updated=new Map(plan);
    for(const [ordinal,slot] of proposals)updated.set(ordinal,{...slot});
    plan=updated;
    backlogProposal=null;changed=true;exportedPlan=false;backlogPage=0;
    render();
    inform("Applied "+proposals.size+" explicit PRIVATE HUMAN proposed reminders locally. Save complete source-bound v2 plan separately; no external calendar updated.");
  }
  function renderBacklog(){
    if(!active)return;
    const selector=$("backlogGroup"),groups=capacityGroups(),old=selector.value;
    if(selector.options.length!==groups.length+1 ||
      groups.some((group,i)=>selector.options[i+1]?.textContent!==(group||"(unassigned)"))){
      selector.replaceChildren();
      const all=dom("option","All HUMAN groups");all.value="";selector.append(all);
      groups.forEach((group,i)=>{
        const option=dom("option",group||"(unassigned)");option.value=String(i+1);
        selector.append(option);
      });
      selector.value=old;if(selector.selectedIndex<0)selector.value="";
    }
    renderBacklogPreview();
    const list=backlogFiltered(),pages=Math.max(1,Math.ceil(list.length/30));
    backlogPage=Math.min(Math.max(0,backlogPage),pages-1);
    const blocked=list.filter(row=>row.stage==="blocked").length;
    $("backlogSummary").textContent=list.length+" unscheduled HUMAN rows matching · "+
      blocked+" blocked stages in this view · page "+(backlogPage+1)+" of "+pages+
      " · source severity is unverified, no auto-dispatch.";
    $("backlogPrev").disabled=backlogPage===0;
    $("backlogNext").disabled=backlogPage>=pages-1;
    const body=$("backlogRows");body.replaceChildren();
    for(const row of list.slice(backlogPage*30,(backlogPage+1)*30)){
      const tr=dom("tr"),action=dom("button","Propose next HUMAN slot"),
        edit=dom("button","Open #"+row.ordinal,"ghost");
      action.type="button";edit.type="button";
      action.disabled=row.stage==="blocked";
      action.setAttribute("aria-label","Propose local review time for original HUMAN ordinal "+row.ordinal);
      action.addEventListener("click",()=>{
        try{proposeBacklog(row.ordinal);}catch(_){inform("HUMAN proposal refused; original source and plan unchanged.",true);}
      });
      edit.addEventListener("click",()=>focusOrdinal(row.ordinal));
      const actionCell=dom("td"),editCell=dom("td");
      actionCell.append(action);editCell.append(edit);
      tr.append(dom("td","#"+row.ordinal),dom("td",row.severity),
        dom("td",row.group||"(unassigned)"),
        dom("td",row.stage||"unset"),dom("td",row.action||"(none)"),actionCell,editCell);
      body.append(tr);
    }
  }
  function renderWorkload(){
    if(!active)return;
    const colliding=collisionIds(),now=Date.now(),groups=new Map();
    for(const r of items){
      const name=r.group||"",slot=plan.get(r.ordinal),g=groups.get(name)||{
        name,rows:0,unscheduled:0,past:0,blocked:0,collisions:0,next:Infinity
      };
      g.rows++;
      if(!slot)g.unscheduled++;
      if(r.stage==="blocked")g.blocked++;
      if(colliding.has(r.ordinal))g.collisions++;
      if(slot){
        const at=eventDate(slot.day,slot.time).getTime();
        if(at<now)g.past++;else g.next=Math.min(g.next,at);
      }
      groups.set(name,g);
    }
    const q=$("workloadQuery").value.trim().toLocaleLowerCase();
    const visible=Array.from(groups.values()).filter(g=>!q||g.name.toLocaleLowerCase().includes(q))
      .sort((a,b)=>b.unscheduled-a.unscheduled || b.collisions-a.collisions || b.rows-a.rows || a.name.localeCompare(b.name));
    const pages=Math.max(1,Math.ceil(visible.length/40));
    workloadPage=Math.max(0,Math.min(workloadPage,pages-1));
    $("workloadPrev").disabled=workloadPage===0;$("workloadNext").disabled=workloadPage>=pages-1;
    $("workloadSummary").textContent=visible.length+" HUMAN groups in this view · "+items.length+" original HUMAN rows · page "+(workloadPage+1)+" of "+pages+".";
    $("focusedGroup").textContent=selectedGroup===null?"All HUMAN groups":"Filtering planner by HUMAN group: "+(selectedGroup||"(unassigned)");
    const tbody=$("workloadRows");tbody.replaceChildren();
    for(const g of visible.slice(workloadPage*40,workloadPage*40+40)){
      const tr=dom("tr"),cell=dom("td"),button=dom("button","Focus group","ghost");
      button.type="button";
      button.addEventListener("click",()=>{
        selectedGroup=g.name;page=0;
        $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
        render();$("desk").scrollIntoView({behavior:"smooth",block:"start"});
      });
      cell.append(button);
      const calendarCell=dom("td");
      const exportGroup=dom("button","PRIVATE .ics","ghost");exportGroup.type="button";
      exportGroup.disabled=!exportedPlan || g.rows===g.unscheduled;
      exportGroup.addEventListener("click",()=>{
        try{exportGroupCalendar(g.name);}
        catch(_){inform("Group export held. Save/restore matching v2 plan with scheduled HUMAN reminders first.",true);}
      });
      calendarCell.append(exportGroup);
      tr.append(dom("td",g.name||"(unassigned)"),dom("td",String(g.rows)),
        dom("td",String(g.unscheduled)),dom("td",String(g.past)),
        dom("td",String(g.blocked)),dom("td",String(g.collisions)),
        dom("td",Number.isFinite(g.next)?new Date(g.next).toLocaleString():"—"),cell,calendarCell);
      tbody.append(tr);
    }
  }
  function exportGroupCalendar(group){
    hold(active && exportedPlan && typeof group==="string");
    const relevant=items.filter(row=>row.group===group && plan.has(row.ordinal));
    hold(relevant.length>0);
    const include=$("includeAction").checked;
    if(!confirm("Export exactly "+relevant.length+" PRIVATE proposed HUMAN follow-ups for the "+(group||"(unassigned)")+
      " group? Original group names are unverified HUMAN labels. "+
      (include?"Optional HUMAN action descriptions MAY reveal private targets/client details. ":"")+
      "Calendar clients may share data. Original assessment data, permission and source authenticity are NOT verified."))return;
    const stamp=icsTime(new Date()),sequence=nextIcsSequence();
    const lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN",
      "CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:LightUp PRIVATE HUMAN Group Follow-ups"];
    for(const row of relevant){
      const slot=plan.get(row.ordinal),start=eventDate(slot.day,slot.time),
        end=new Date(start.getTime()+Number(slot.duration)*60000);
      lines.push("BEGIN:VEVENT","UID:"+seriesId+"-"+row.ordinal+"@lightup-private.invalid",
        "SEQUENCE:"+sequence,"DTSTAMP:"+stamp,"DTSTART:"+icsTime(start),"DTEND:"+icsTime(end),
        "STATUS:TENTATIVE","TRANSP:TRANSPARENT",
        "SUMMARY:"+icsText("PRIVATE HUMAN follow-up #"+row.ordinal),
        "DESCRIPTION:"+icsText("REVIEW_ONLY: source-reported "+row.severity+
          "; HUMAN stage "+(row.stage||"unset")+
          "; not independently verified; not a permission or vulnerability verdict."+
          (include?" HUMAN next action: "+row.action:"")),
        "X-LIGHTUP-REVIEW-ONLY:TRUE");
      if(Number(slot.reminder)>0)lines.push("BEGIN:VALARM","ACTION:DISPLAY",
        "DESCRIPTION:PRIVATE HUMAN follow-up reminder",
        "TRIGGER:-PT"+slot.reminder+"M","END:VALARM");
      lines.push("END:VEVENT");
    }
    lines.push("END:VCALENDAR");
    download(lines.map(fold).join("\r\n")+"\r\n",
      "lightup-private-human-group-calendar.ics","text/calendar;charset=utf-8");
    inform("Exported "+relevant.length+" PRIVATE HUMAN group reminders. No external calendar modified.");
  }
  function capacityDefaultRule(){
    return {days:[1,2,3,4,5],start:"09:00",end:"17:00",maximum:4,blackouts:[]};
  }
  function capacityGroups(){return Array.from(new Set(items.map(item=>item.group))).sort((a,b)=>a.localeCompare(b));}
  function capacityMessage(message,denied=false){
    $("capacityMessage").textContent=message;
    $("capacityMessage").dataset.error=String(denied);
  }
  function admitCapacityRule(rule){
    hold(rule && Array.isArray(rule.days) && rule.days.length>=1 && rule.days.length<=7);
    hold(rule.days.every(day=>Number.isInteger(day)&&day>=0&&day<=6) &&
      new Set(rule.days).size===rule.days.length);
    const start=rule.start,end=rule.end;
    hold(typeof start==="string"&&typeof end==="string");
    hold(/^([01]\d|2[0-3]):[0-5]\d$/.test(start) &&
      /^([01]\d|2[0-3]):[0-5]\d$/.test(end));
    const minutes=t=>Number(t.slice(0,2))*60+Number(t.slice(3,5));
    hold(minutes(end)-minutes(start)>=30 && minutes(start)%15===0 &&
      minutes(end)%15===0);
    hold([1,2,4,6,8,12].includes(rule.maximum));
    hold(Array.isArray(rule.blackouts) && rule.blackouts.length<=60);
    const seen=new Set();
    for(const day of rule.blackouts){
      hold(typeof day==="string");
      eventDate(day,"12:00");
      hold(!seen.has(day));seen.add(day);
    }
    return {days:[...rule.days].sort((a,b)=>a-b),start,end,maximum:rule.maximum,
      blackouts:[...seen].sort()};
  }
  function resetCapacity(){
    capacityRules=new Map();capacityDirty=false;capacityEditorDirty=false;
    capacityProposal=null;
    $("capacityApply").disabled=true;
    const select=$("capacityGroup");
    select.replaceChildren();
    const groups=capacityGroups();
    for(const group of groups){
      const option=dom("option",group||"(unassigned)");
      option.value=group;select.append(option);
    }
    if(groups.length){
      select.value=groups[0];capacityLoadEditor();
    }
    $("capacityFirst").value=nowToday();
    $("capacityHorizon").value="30";$("capacityMode").value="unscheduled";
    capacityMessage("Original HUMAN group availability defaults loaded into local memory; no calendar or operator has been contacted.");
    renderCapacity();
  }
  function capacityLoadEditor(){
    capacityEditingGroup=$("capacityGroup").value;
    capacityEditorDirty=false;
    const rule=capacityRules.get(capacityEditingGroup)||capacityDefaultRule();
    $("capacityDaily").value=String(rule.maximum);
    $("capacityStart").value=rule.start;$("capacityEnd").value=rule.end;
    document.querySelectorAll('#capacityDays input[type="checkbox"]').forEach(box=>{
      box.checked=rule.days.includes(Number(box.value));
    });
    $("capacityBlackout").value=rule.blackouts.join(", ");
  }
  function capacityEditorRule(){
    const days=Array.from(document.querySelectorAll('#capacityDays input[type="checkbox"]'))
      .filter(box=>box.checked).map(box=>Number(box.value));
    const unavailable=$("capacityBlackout").value.trim();
    const blackouts=unavailable?unavailable.split(",").map(day=>day.trim()):[];
    return admitCapacityRule({days,start:$("capacityStart").value,
      end:$("capacityEnd").value,maximum:Number($("capacityDaily").value),blackouts});
  }
  function noteCapacityEditorChange(){
    if(!active)return;
    capacityEditorDirty=true;
    capacityProposal=null;$("capacityApply").disabled=true;
    renderWorkspaceSaveStatus();renderWorkroomComparison();
    capacityMessage("Uncommitted HUMAN availability fields: click Save local HUMAN group availability before whole-workroom export. Original appointments unchanged.");
  }
  function capacitySnapshot(){
    return JSON.stringify([hash,seriesId,zone,
      Array.from(plan.entries()).sort((a,b)=>a[0]-b[0]),
      Array.from(capacityRules.entries()).sort((a,b)=>a[0].localeCompare(b[0])),
      $("capacityFirst").value,$("capacityHorizon").value,$("capacityMode").value]);
  }
  function renderCapacityProposal(){
    const tbody=$("capacityPreviewRows");
    tbody.replaceChildren();
    if(!capacityProposal || !capacityProposal.slots.size){
      $("capacityPreviewSummary").textContent="No HUMAN proposal; load rules and preview.";
      return;
    }
    const rows=Array.from(capacityProposal.slots.entries())
      .sort((a,b)=>(a[1].day+"T"+a[1].time).localeCompare(b[1].day+"T"+b[1].time) || a[0]-b[0]);
    $("capacityPreviewSummary").textContent=rows.length+" local HUMAN-only appointment proposals "+
      "(source-reported severity is not independently validated). "+
      "All original ordinals remain unchanged until explicit HUMAN confirmation.";
    for(const [ordinal,slot] of rows){
      const source=items[ordinal-1],row=dom("tr");
      const previous=capacityProposal.previous.get(ordinal);
      row.append(dom("td","#"+ordinal),dom("td",source.group||"(unassigned)"),
        dom("td",source.severity),
        dom("td",previous?previous.day+" "+previous.time+" · "+previous.duration+" min":"(previously unscheduled)"),
        dom("td",slot.day+" "+slot.time),
        dom("td",slot.duration+" min"));
      tbody.append(row);
    }
  }
  function renderCapacity(){
    if(!active)return;
    renderCapacityProposal();
    const unscheduled=new Map();
    for(const row of items)if(!plan.has(row.ordinal)&&row.stage!=="blocked")
      unscheduled.set(row.group,(unscheduled.get(row.group)||0)+1);
    const body=$("capacityRows");body.replaceChildren();
    for(const group of capacityGroups()){
      const rule=capacityRules.get(group)||capacityDefaultRule();
      const row=dom("tr");
      const label=rule.days.map(n=>["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][n]).join(", ");
      row.append(dom("td",group||"(unassigned)"),
        dom("td",label+" · "+rule.start+"–"+rule.end+" · max "+rule.maximum+"/day"),
        dom("td",String(rule.blackouts.length)),
        dom("td",String(unscheduled.get(group)||0)));
      body.append(row);
    }
  }
  function privateCapacityCSV(){
    hold(active && capacityGroups().length<=256 && /^[0-9a-f]{32}$/.test(seriesId));
    return makeCsv([CAP_HEAD,...capacityGroups().map(group=>{
      const rule=admitCapacityRule(capacityRules.get(group)||capacityDefaultRule());
      return [hash,seriesId,zone,group,rule.days.join(";"),
        rule.start,rule.end,String(rule.maximum),rule.blackouts.join(";")];
    })]);
  }
  function admitCapacityText(raw, expectedSeries){
    hold(active && typeof raw==="string" && raw.length<=MAX_BYTES && !raw.startsWith("\uFEFF"));
    const parsed=csv(raw,CAP_HEAD.length);
    hold(JSON.stringify(parsed[0])===JSON.stringify(CAP_HEAD));
    const groups=capacityGroups();
    hold(groups.length<=256 && parsed.length===groups.length+1);
    const next=new Map();
    for(let i=0;i<groups.length;i++){
      const row=parsed[i+1];
      hold(row[0]===hash && row[1]===expectedSeries && row[2]===zone && row[3]===groups[i]);
      const days=row[4].split(";").map(n=>Number(n));
      hold(row[4]===days.join(";") && /^([1-9]|1[0-2])$/.test(row[7]));
      const blackouts=row[8]?row[8].split(";"):[];
      const rule=admitCapacityRule({days,start:row[5],end:row[6],
        maximum:Number(row[7]),blackouts});
      next.set(row[3],rule);
    }
    return next;
  }
  function capacityExport(){
    hold(!capacityEditorDirty);
    const snapshot=privateCapacityCSV();
    if(!confirm("Download the complete source-bound PRIVATE HUMAN group availability policy? This contains HUMAN group labels, time windows and holiday dates. It is UNSIGNED and authorizes no assessment or external calendar access."))return;
    hold(snapshot===privateCapacityCSV());
    download(snapshot,"lightup-private-human-capacity.csv","text/csv;charset=utf-8");
    capacityDirty=false;renderWorkspaceSaveStatus();
    capacityMessage("Source-bound PRIVATE HUMAN group rules downloaded. The source remains local; preserve this CSV securely.");
  }
  async function capacityImport(file){
    hold(active && capacityGroups().length<=256);
    const currentHash=hash,currentSeries=seriesId,currentPlan=plan;
    const initialRules=privateCapacityCSV();
    const raw=decoder.decode(await bytes(file));
    const next=admitCapacityText(raw,currentSeries);
    if(!confirm("Replace current local HUMAN group availability rules with this exact-worksheet/series/timezone PRIVATE policy? Existing HUMAN appointments and the original worksheet will not change."))return;
    hold(active && hash===currentHash && seriesId===currentSeries &&
      plan===currentPlan && initialRules===privateCapacityCSV());
    capacityRules=next;capacityDirty=true;capacityEditorDirty=false;
    capacityProposal=null;$("capacityApply").disabled=true;
    capacityLoadEditor();render();
    capacityMessage("PRIVATE group availability reloaded with unsaved changes. Download policy or encrypted whole workroom to preserve it.");
  }
  function capacityPreview(){
    assertLocalZone();
    hold(active && capacityGroups().length>0 && capacityGroups().length<=256);
    const from=$("capacityFirst").value;
    eventDate(from,"12:00");hold(from>=nowToday());
    const horizon=Number($("capacityHorizon").value);
    hold([14,30,60,90].includes(horizon));
    const rules=capacityGroups().map(group=>({group,rule:capacityRules.get(group)||capacityDefaultRule()}));
    const ranks={critical:0,high:1,medium:2,low:3,info:4};
    const mode=$("capacityMode").value;
    hold(["unscheduled","overdue","combined"].includes(mode));
    const now=Date.now();
    const candidates=items.filter(row=>{
      if(row.stage==="blocked")return false;
      const existing=plan.get(row.ordinal);
      const hasOverdue=existing && eventDate(existing.day,existing.time).getTime()<now;
      return (mode!=="overdue" && !existing)||(mode!=="unscheduled" && hasOverdue);
    }).sort((a,b)=>{
      // Human date order, not a finding/urgency inference, when moving past HUMAN appointments.
      const ap=plan.get(a.ordinal),bp=plan.get(b.ordinal);
      const ao=ap?eventDate(ap.day,ap.time).getTime():Infinity;
      const bo=bp?eventDate(bp.day,bp.time).getTime():Infinity;
      if(ao!==bo)return ao-bo;
      return ranks[a.severity]-ranks[b.severity] || a.ordinal-b.ordinal;
    });
    const byGroup=new Map();
    for(const row of candidates){
      if(!byGroup.has(row.group))byGroup.set(row.group,[]);
      byGroup.get(row.group).push(row);
    }
    const taken=new Map(),daily=new Map();
    const eligibleOld=new Set(candidates.filter(row=>plan.has(row.ordinal)).map(row=>row.ordinal));
    // The past-due HUMAN proposals are being moved, not double-booked into a new date.
    for(const event of eventIntervals().filter(event=>!eligibleOld.has(event.ordinal))){
      const date=plan.get(event.ordinal).day;
      if(!taken.has(date))taken.set(date,[]);
      taken.get(date).push(event);
      const group=items[event.ordinal-1].group;
      const key=JSON.stringify([group,date]);daily.set(key,(daily.get(key)||0)+1);
    }
    const proposed=new Map(),start=eventDate(from,"12:00");
    for(let d=0;d<horizon && proposed.size<128;d++){
      const date=new Date(start.getTime());date.setDate(start.getDate()+d);
      const day=[date.getFullYear(),String(date.getMonth()+1).padStart(2,"0"),
        String(date.getDate()).padStart(2,"0")].join("-");
      for(const {group,rule} of rules){
        if(proposed.size>=128)break;
        const queue=byGroup.get(group);
        if(!queue?.length || !rule.days.includes(date.getDay()) || rule.blackouts.includes(day))continue;
        const key=JSON.stringify([group,day]);
        let count=daily.get(key)||0;
        const startMin=Number(rule.start.slice(0,2))*60+Number(rule.start.slice(3,5));
        const endMin=Number(rule.end.slice(0,2))*60+Number(rule.end.slice(3,5));
        for(let minute=startMin;minute+30<=endMin && count<rule.maximum && queue.length && proposed.size<128;minute+=30){
          const time=String(Math.floor(minute/60)).padStart(2,"0")+":"+String(minute%60).padStart(2,"0");
          let slot,instant;
          try{
            slot=admitSlot(day,time,"30","15");
            instant=eventDate(day,time).getTime();
          }catch(_){continue;} // Never propose nonexistent/repeated/clock-crossing times.
          const last=instant+30*60000;
          if(instant<=Date.now())continue;
          const busy=taken.get(day)||[];
          if(busy.some(event=>instant<event.end && event.start<last))continue;
          const row=queue.shift();
          proposed.set(row.ordinal,slot);
          busy.push({ordinal:row.ordinal,start:instant,end:last});
          taken.set(day,busy);count++;daily.set(key,count);
        }
      }
    }
    capacityProposal={slots:proposed,snapshot:capacitySnapshot(),mode,previous:new Map(Array.from(proposed.keys()).map(ordinal=>[ordinal,plan.get(ordinal)||null]))};
    $("capacityApply").disabled=proposed.size===0;
    renderCapacityProposal();
    $("capacityProposalDetails").open=proposed.size>0;
    const pending=candidates.length-proposed.size;
    capacityMessage("Proposed "+proposed.size+" source-ordinal HUMAN reminders, "+
      pending+" eligible original HUMAN reminders remain without new dates in this bounded preview. "+
      "No existing appointments changed; 128 proposed changes maximum per confirmation. "+
      (pending?"Extend horizon/availability or repeat after saving this batch.":"Review dates before applying."));
  }
  function capacityApply(){
    hold(active && capacityProposal && capacityProposal.snapshot===capacitySnapshot());
    const preview=capacityProposal.slots;
    hold(preview.size>0 && preview.size<=128);
    const now=Date.now(),mode=capacityProposal.mode;
    hold(Array.from(preview).every(([ordinal])=>{
      const old=plan.get(ordinal),source=items[ordinal-1];
      if(!source || source.stage==="blocked")return false;
      if(old && mode==="unscheduled")return false;
      if(!old && mode==="overdue")return false;
      if(old && eventDate(old.day,old.time).getTime()>=now)return false;
      return capacityProposal.previous.get(ordinal)===old ||
        (!old && capacityProposal.previous.get(ordinal)===null);
    }));
    const replaced=Array.from(preview.keys()).filter(ordinal=>plan.has(ordinal)).length;
    if(!confirm("Apply "+preview.size+" proposed HUMAN-only dates in local memory? "+
      (replaced?replaced+" previously scheduled but PAST-DUE HUMAN reminder dates will be replaced (after this confirmation). ":"")+
      "No future-dated HUMAN reminder, original lab assessment, source worksheet or external calendar will be changed. "+
      "PAST DUE does not mean a verified unresolved vulnerability or authorization to execute."))return;
    hold(capacityProposal.snapshot===capacitySnapshot());
    for(const [ordinal,slot] of preview)plan.set(ordinal,slot);
    changed=true;exportedPlan=false;
    capacityProposal=null;$("capacityApply").disabled=true;
    page=0;render();
    capacityMessage("Applied "+preview.size+" PRIVATE HUMAN capacity proposals locally; "+replaced+" past-due reminder dates replaced. Save the full v2 plan before calendar export.");
  }
  function slotEquals(a,b){
    return !!a && !!b && a.day===b.day && a.time===b.time &&
      a.duration===b.duration && a.reminder===b.reminder;
  }
  function publishedChanges(){
    if(!publicationBaseline)return [];
    const delta=[];
    for(const r of items){
      const before=publicationBaseline.get(r.ordinal),now=plan.get(r.ordinal);
      if(slotEquals(before,now)||(!before&&!now))continue;
      const kind=!before?"Added":!now?"Cancelled":"Rescheduled / reminder changed";
      delta.push({ordinal:r.ordinal,kind,before,now,row:r});
    }
    return delta;
  }
  function slotLabel(slot){
    return slot?slot.day+" "+slot.time+" · "+slot.duration+" min · reminder "+slot.reminder+" min":"(none)";
  }
  function renderChanges(){
    const has=publicationBaseline!==null;
    $("clearBaseline").disabled=!has;
    const all=publishedChanges();
    const added=all.filter(v=>v.kind==="Added").length;
    const cancelled=all.filter(v=>v.kind==="Cancelled").length;
    const updated=all.length-added-cancelled;
    $("changesSummary").textContent=has?
      added+" new · "+updated+" rescheduled/reminder changed · "+cancelled+
      " removed from current HUMAN plan. All comparisons are PRIVATE schedule declarations only.":
      "Load a previously published PRIVATE plan to see source-bound differences.";
    const pages=Math.max(1,Math.ceil(all.length/60));changesPage=Math.max(0,Math.min(changesPage,pages-1));
    $("changePrev").disabled=!has||changesPage===0;
    $("changeNext").disabled=!has||changesPage>=pages-1;
    $("exportUpdated").disabled=!has||added+updated===0;
    $("exportCancelled").disabled=!has||cancelled===0;
    $("exportChangesCsv").disabled=!has||all.length===0;
    const tbody=$("changesRows");tbody.replaceChildren();
    for(const row of all.slice(changesPage*60,changesPage*60+60)){
      const tr=dom("tr");
      tr.append(dom("td","#"+row.ordinal),dom("td",row.kind),
        dom("td",slotLabel(row.before)),dom("td",slotLabel(row.now)));
      tbody.append(tr);
    }
  }
  async function readPublishedBaseline(file){
    hold(active);
    const originHash=hash,originSeries=seriesId;
    const raw=decoder.decode(await bytes(file));
    const imported=admitPlanText(raw);
    hold(!imported.legacy && hash===originHash &&
      seriesId===originSeries && imported.series===originSeries);
    if(!confirm("Load this historical PRIVATE HUMAN plan as a comparison baseline? This does not change current appointments, source fields or any calendar. The baseline is UNSIGNED, and calendar sync is not guaranteed."))return;
    hold(active && hash===originHash && seriesId===originSeries);
    publicationBaseline=imported.schedule;
    changesPage=0;
    $("baselineStatus").textContent="Original worksheet, timezone and calendar series matched. Comparison is HUMAN-only, unsigned.";
    renderChanges();
    inform("Previous PRIVATE HUMAN schedule loaded for local comparison, no changes published.");
  }
  function exportPrivateChangeRegister(){
    hold(active && publicationBaseline);
    const changes=publishedChanges();
    hold(changes.length>0);
    if(!confirm("Download "+changes.length+" source-bound PRIVATE HUMAN schedule changes as CSV? Contains original worksheet SHA-256, stable calendar series ID and before/after reminder times. Never publish openly; this is an unsigned HUMAN-only proposal, not proof of action."))return;
    const header=["status","worksheet_sha256_unsigned","private_calendar_series_id","original_ordinal",
      "human_schedule_change","before_date","before_time","before_minutes","before_reminder_minutes",
      "after_date","after_time","after_minutes","after_reminder_minutes","current_plan_saved"];
    const out=[header,...changes.map(change=>{
      const b=change.before,n=change.now;
      return ["REVIEW_ONLY",hash,seriesId,String(change.ordinal),change.kind,
        b?.day||"",b?.time||"",b?.duration||"",b?.reminder||"",
        n?.day||"",n?.time||"",n?.duration||"",n?.reminder||"",
        exportedPlan?"true":"false"];
    })];
    download(makeCsv(out),"lightup-private-human-calendar-change-register.csv","text/csv;charset=utf-8");
    inform("Source-bound PRIVATE HUMAN change register downloaded. No provider, scanner or approval contacted.");
  }
  function calendarDiffExport(cancelled){
    hold(active && publicationBaseline && exportedPlan);
    const delta=publishedChanges().filter(c=>cancelled?!c.now:!!c.now);
    hold(delta.length>0);
    const kind=cancelled?"cancellations":"new/changed HUMAN reminders";
    if(!confirm("Export "+delta.length+" PRIVATE "+kind+"? Calendar import is a manual action, providers may not recognize changes, and no existing external event is deleted by LightUp. "+(cancelled?"Cancellations will use historical HUMAN times.":"Opt-in HUMAN descriptions may include sensitive content.")))return;
    const now=icsTime(new Date()),sequence=nextIcsSequence();
    const lines=["BEGIN:VCALENDAR","VERSION:2.0",
      "PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN",
      "CALSCALE:GREGORIAN","METHOD:"+(cancelled?"CANCEL":"PUBLISH"),
      "X-WR-CALNAME:LightUp PRIVATE HUMAN Changes"];
    const include=$("includeAction").checked;
    for(const row of delta){
      const slot=cancelled?row.before:row.now;
      const start=eventDate(slot.day,slot.time),end=new Date(start.getTime()+Number(slot.duration)*60000);
      const uid=seriesId+"-"+row.ordinal+"@lightup-private.invalid";
      lines.push("BEGIN:VEVENT","UID:"+uid,"SEQUENCE:"+sequence,"DTSTAMP:"+now,
        "DTSTART:"+icsTime(start),"DTEND:"+icsTime(end),
        "STATUS:"+(cancelled?"CANCELLED":"TENTATIVE"),
        "TRANSP:TRANSPARENT",
        "SUMMARY:"+icsText("PRIVATE HUMAN follow-up #"+row.ordinal),
        "DESCRIPTION:"+icsText(cancelled?
          "REVIEW_ONLY: human-only withdrawal of a prior proposed reminder, not a security finding or authorization change.":
          "REVIEW_ONLY: self-reported "+row.row.severity+
          "; HUMAN stage "+(row.row.stage||"unset")+
          "; not a verified security or consent result."+
          (include?" HUMAN action: "+row.row.action:"")),
        "X-LIGHTUP-REVIEW-ONLY:TRUE");
      if(!cancelled&&Number(slot.reminder)>0)lines.push(
        "BEGIN:VALARM","ACTION:DISPLAY","DESCRIPTION:PRIVATE HUMAN follow-up reminder",
        "TRIGGER:-PT"+slot.reminder+"M","END:VALARM");
      lines.push("END:VEVENT");
    }
    lines.push("END:VCALENDAR");
    download(lines.map(fold).join("\r\n")+"\r\n",
      cancelled?"lightup-private-human-cancellations.ics":"lightup-private-human-calendar-updates.ics",
      "text/calendar;charset=utf-8");
    inform("PRIVATE "+kind+" exported. No external agenda was contacted. Preserve old baseline and new plan for manual review.");
  }
  function restore(parsed){
    const v2=JSON.stringify(parsed[0])===JSON.stringify(PLAN_HEAD_V2);
    hold(v2 || JSON.stringify(parsed[0])===JSON.stringify(PLAN_HEAD));
    hold(parsed.length===items.length+1);
    const next=new Map();
    let restoredSeries="";
    parsed.slice(1).forEach((r,i)=>{
      hold(r.length===(v2?8:7) && r[0]===hash && r[1]===String(i+1) && r[6]===zone);
      if(v2){
        hold(/^[0-9a-f]{32}$/.test(r[7]));
        if(i===0)restoredSeries=r[7];
        hold(r[7]===restoredSeries);
      }
      const slot=admitSlot(r[2],r[3],r[4],r[5]);
      if(slot)next.set(i+1,slot);
    });
    return {schedule:next,series:v2?(restoredSeries||newSeriesId()):newSeriesId(),legacy:!v2};
  }
  function privatePlanCSV(){
    hold(active && /^[0-9a-f]{32}$/.test(seriesId));
    return makeCsv([PLAN_HEAD_V2,...items.map(r=>{
      const p=plan.get(r.ordinal);
      return [hash,String(r.ordinal),p?.day||"",p?.time||"",p?.duration||"",p?.reminder||"",zone,seriesId];
    })]);
  }
  function admitPlanText(raw){
    hold(!raw.startsWith("\uFEFF"));
    const legacyHeader=PLAN_HEAD.join(","),modernHeader=PLAN_HEAD_V2.join(",");
    const first=raw.split(/\r?\n/,1)[0];
    hold(first===legacyHeader || first===modernHeader);
    return restore(csv(raw,first===modernHeader?8:7));
  }
  function clearPasswords(){
    $("handoffPassword").value="";
    $("handoffConfirm").value="";
  }
  async function handoffKey(password,salt){
    hold(typeof password==="string" && password.length>=16 && password.length<=256);
    hold(crypto.subtle && salt.length===16);
    const raw=new TextEncoder().encode(password);
    try{
      const base=await crypto.subtle.importKey("raw",raw,"PBKDF2",false,["deriveKey"]);
      return await crypto.subtle.deriveKey(
        {name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},
        base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    }finally{raw.fill(0);}
  }
  const ENC_MAGIC=new Uint8Array([76,85,72,67,49,10]); // LUHC1 + LF
  const ENC_AAD=new TextEncoder().encode("lightup.human_calendar.private_plan.v1|REVIEW_ONLY|NO_AUTHORITY");
  async function saveEncrypted(){
    hold(active && crypto.subtle);
    const password=$("handoffPassword").value,confirmation=$("handoffConfirm").value;
    hold(password.length>=16 && password.length<=256 && password===confirmation);
    const snapshotCSV=privatePlanCSV();
    const plain=new TextEncoder().encode(snapshotCSV);
    const salt=new Uint8Array(16),iv=new Uint8Array(12);
    crypto.getRandomValues(salt);crypto.getRandomValues(iv);
    try{
      const key=await handoffKey(password,salt);
      const cipher=new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv,additionalData:ENC_AAD,tagLength:128},key,plain));
      const result=new Uint8Array(ENC_MAGIC.length+salt.length+iv.length+cipher.length);
      result.set(ENC_MAGIC,0);result.set(salt,ENC_MAGIC.length);
      result.set(iv,ENC_MAGIC.length+16);result.set(cipher,ENC_MAGIC.length+28);
      hold(result.length<=MAX_BYTES);
      hold(active && privatePlanCSV()===snapshotCSV);
      if(!confirm("Download a separate encrypted PRIVATE plan? Save the passphrase out of band. This authenticates only the encrypted bytes, NOT their original producer, permission or client/operator identity."))return;
      download(result,"lightup-private-human-calendar.luhc","application/octet-stream");
      changed=false;exportedPlan=true;render();
      inform("Encrypted PRIVATE source-bound plan downloaded. Password cleared from input fields.");
    }finally{plain.fill(0);clearPasswords();}
  }
  const VAULT_MAGIC=new Uint8Array([76,85,72,86,49,10]); // LUHV1 + LF
  const VAULT_AAD=new TextEncoder().encode(
    "lightup.human_calendar.portable_original_workroom.v1|REVIEW_ONLY|NO_AUTHORITY");
  function clearVaultPasswords(){
    $("vaultPassword").value="";$("vaultConfirm").value="";
  }
  function vaultPack(source,planCSV,capacityCSV){
    hold(source instanceof Uint8Array && source.length>0 && source.length<=MAX_BYTES);
    const encoder=new TextEncoder(),p=encoder.encode(planCSV),c=encoder.encode(capacityCSV);
    const prefix=encoder.encode("LUHV-PRIVATE-1\n"+source.length+"\n"+p.length+"\n"+c.length+"\n");
    hold(p.length>0 && c.length>0 && prefix.length+source.length+p.length+c.length <= MAX_BYTES-80);
    const data=new Uint8Array(prefix.length+source.length+p.length+c.length);
    data.set(prefix,0);data.set(source,prefix.length);
    data.set(p,prefix.length+source.length);data.set(c,prefix.length+source.length+p.length);
    p.fill(0);c.fill(0);return data;
  }
  async function vaultUnpack(plaintext){
    hold(plaintext.length>0 && plaintext.length<=MAX_BYTES);
    let cursor=0;
    const line=()=>{
      const end=plaintext.indexOf(10,cursor);
      hold(end>cursor && end-cursor<=32 && end<110);
      const result=decoder.decode(plaintext.subarray(cursor,end));
      cursor=end+1;return result;
    };
    hold(line()==="LUHV-PRIVATE-1");
    const lengths=[line(),line(),line()];
    hold(lengths.every(v=>/^[1-9]\d{0,6}$/.test(v)));
    const [a,b,c]=lengths.map(Number);
    hold(a+b+c+cursor===plaintext.length && a>0 && b>0 && c>0);
    const source=plaintext.slice(cursor,cursor+a);
    cursor+=a;
    const planText=decoder.decode(plaintext.subarray(cursor,cursor+b));
    cursor+=b;
    const policyText=decoder.decode(plaintext.subarray(cursor,cursor+c));
    const raw=decoder.decode(source);
    hold(!raw.startsWith("\uFEFF"));
    const sourceRows=original(csv(raw,HEAD.length));
    hold(sourceRows.length>0 && sourceRows.length<=MAX_ROWS);
    const sourceHash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",source)),
      v=>v.toString(16).padStart(2,"0")).join("");
    const head=csv(planText,PLAN_HEAD_V2.length);
    hold(JSON.stringify(head[0])===JSON.stringify(PLAN_HEAD_V2) &&
      head.length===sourceRows.length+1);
    const schedule=new Map();let recoveredSeries="";
    head.slice(1).forEach((r,i)=>{
      hold(r[0]===sourceHash && r[1]===String(i+1) && r[6]===zone &&
        /^[0-9a-f]{32}$/.test(r[7]));
      if(i===0)recoveredSeries=r[7];
      hold(r[7]===recoveredSeries);
      const slot=admitSlot(r[2],r[3],r[4],r[5]);
      if(slot)schedule.set(i+1,slot);
    });
    const groups=Array.from(new Set(sourceRows.map(r=>r.group))).sort((a,b)=>a.localeCompare(b));
    hold(groups.length<=256);
    const policyRows=csv(policyText,CAP_HEAD.length);
    hold(JSON.stringify(policyRows[0])===JSON.stringify(CAP_HEAD) &&
      policyRows.length===groups.length+1);
    const policies=new Map();
    policyRows.slice(1).forEach((r,i)=>{
      hold(r[0]===sourceHash && r[1]===recoveredSeries &&
        r[2]===zone && r[3]===groups[i]);
      const days=r[4].split(";").map(v=>Number(v));
      hold(days.join(";")===r[4] && /^([1-9]|1[0-2])$/.test(r[7]));
      policies.set(r[3],admitCapacityRule({days,start:r[5],end:r[6],
        maximum:Number(r[7]),blackouts:r[8]?r[8].split(";"):[]}));
    });
    return {source,sourceRows,sourceHash,series:recoveredSeries,schedule,policies};
  }
  async function readPortableVault(file,password){
    hold(crypto.subtle && password.length>=16 && password.length<=256);
    let raw=null,cipher=null,plaintext=null;
    try{
      raw=await bytes(file);
      hold(raw.length>VAULT_MAGIC.length+16+12+16 &&
        VAULT_MAGIC.every((v,i)=>v===raw[i]));
      const salt=raw.slice(6,22),iv=raw.slice(22,34);cipher=raw.slice(34);
      const key=await handoffKey(password,salt);
      try{
        plaintext=new Uint8Array(await crypto.subtle.decrypt(
          {name:"AES-GCM",iv,additionalData:VAULT_AAD,tagLength:128},key,cipher));
      }catch(_){hold(false);}
      return await vaultUnpack(plaintext);
    }finally{
      if(plaintext)plaintext.fill(0);
      if(cipher)cipher.fill(0);
      if(raw)raw.fill(0);
    }
  }
  async function restorePortableVault(file,ticket){
    hold(crypto.subtle);
    const wasActive=active,priorSource=originalBytes;
    const snapshot=active?workroomFingerprint():null;
    const previousUnsaved=wasActive&&(changed||capacityDirty||capacityEditorDirty);
    const password=$("vaultPassword").value;
    let admitted=null;
    try{
      admitted=await readPortableVault(file,password);
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active===wasActive && originalBytes===priorSource &&
        (!active || snapshot===workroomFingerprint()));
      if(!confirm("Open encrypted PRIVATE ORIGINAL HUMAN worksheet ("+
        admitted.sourceRows.length+" rows), "+admitted.schedule.size+" proposed reminders and "+
        admitted.policies.size+" declared HUMAN group rules? "+
        (previousUnsaved?"WARNING: your current browser workroom has unsaved changes that will be LOST. ":"")+
        "This REPLACES the current browser workroom after full validation."+
        " All plaintext stays in browser memory. Original source is UNSIGNED;"+
        " possession of this vault does NOT verify its producer, client/operator consent,"+
        " security findings, scope or real calendar access. Continue?"))return;
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active===wasActive && originalBytes===priorSource &&
        (!active || snapshot===workroomFingerprint()));
      if(originalBytes)originalBytes.fill(0);
      originalBytes=admitted.source;
      items=admitted.sourceRows;hash=admitted.sourceHash;
      seriesId=admitted.series;plan=admitted.schedule;
      capacityRules=admitted.policies;
      active=true;changed=false;capacityDirty=false;capacityEditorDirty=false;
      exportedPlan=true;page=0;agendaPage=0;workloadPage=0;changesPage=0;
      selectedGroup=null;backlogPage=0;backlogProposal=null;
      capacityProposal=null;workroomComparison=null;workroomComparePage=0;
      reconcileSelection.clear();reconcileGroupSelection.clear();reconcileProposal=null;
      conflictProposal=null;publicationBaseline=null;
      $("baselineStatus").textContent="No previous publication loaded.";
      $("workroomCompareRows").replaceChildren();
      monthAnchor=nowToday().slice(0,7);weekAnchor=nowToday();
      $("monthGroup").value="";$("weekGroup").value="";
      $("weekConflicts").checked=false;$("weekConstraints").checked=false;
      $("backlogView").value="open";$("backlogGroup").value="";
      $("backlogQuery").value="";$("backlogStart").value=nowToday();
      $("severity").value="";$("stage").value="";$("status").value="";
      $("query").value="";$("agendaQuery").value="";
      $("agendaHorizon").value="7";$("workloadQuery").value="";
      $("identity").textContent=items.length+
        " HUMAN rows · private unsigned original digest "+hash.slice(0,12)+"…";
      $("tz").textContent=zone;
      for(const id of ["desk","agenda","week","month","backlog","workload",
        "capacity","brief","out"])$(id).hidden=false;
      $("reset").disabled=false;$("capacityApply").disabled=true;
      const select=$("capacityGroup");select.replaceChildren();
      capacityGroups().forEach(group=>{
        const option=dom("option",group||"(unassigned)");
        option.value=group;select.append(option);
      });
      if(select.options.length){select.value=capacityGroups()[0];capacityLoadEditor();}
      $("capacityFirst").value=nowToday();
      $("capacityMode").value="unscheduled";$("capacityHorizon").value="30";
      render();
      inform("One self-contained encrypted PRIVATE original HUMAN worksheet, all local reminders "+
        "and declared availability successfully reopened from an authenticated ciphertext."+
        " Original producer, consent and security claims remain UNVERIFIED. No external calendar changed.");
    }finally{
      if(admitted && originalBytes!==admitted.source)admitted.source.fill(0);
      if(currentWorkspaceReplacement(ticket))clearVaultPasswords();
    }
  }
  function portablePlanCSV(admitted){
    hold(admitted && admitted.sourceRows.length>0 &&
      /^[0-9a-f]{32}$/.test(admitted.series));
    return makeCsv([PLAN_HEAD_V2,...admitted.sourceRows.map(row=>{
      const slot=admitted.schedule.get(row.ordinal);
      return [admitted.sourceHash,String(row.ordinal),slot?.day||"",
        slot?.time||"",slot?.duration||"",slot?.reminder||"",zone,admitted.series];
    })]);
  }
  function portableCapacityCSV(admitted){
    const groups=Array.from(new Set(admitted.sourceRows.map(row=>row.group)))
      .sort((a,b)=>a.localeCompare(b));
    hold(groups.length<=256 && groups.length===admitted.policies.size);
    return makeCsv([CAP_HEAD,...groups.map(group=>{
      const rule=admitCapacityRule(admitted.policies.get(group));
      return [admitted.sourceHash,admitted.series,zone,group,rule.days.join(";"),
        rule.start,rule.end,String(rule.maximum),rule.blackouts.join(";")];
    })]);
  }
  async function recoverPortableVaultComponent(file){
    hold(crypto.subtle);
    const password=$("vaultPassword").value,kind=$("vaultExtractKind").value;
    hold(["source","plan","capacity"].includes(kind));
    let admitted=null;
    try{
      admitted=await readPortableVault(file,password);
      const description=kind==="source"?"exact original HUMAN worksheet bytes":
        kind==="plan"?"complete source-bound PRIVATE HUMAN appointment plan":
        "complete original self-declared HUMAN group availability policy";
      if(!confirm("Recover the "+description+" only from the encrypted portable vault? "+
        "This local CSV may reveal confidential people/group labels or HUMAN follow-up notes. "+
        "No current browser schedule, source, group policy, calendar, security scope or consent "+
        "will be modified. Continue with an explicit PRIVATE download?"))return;
      if(kind==="source"){
        download(admitted.source,"lightup-original-human-worksheet.csv","text/csv;charset=utf-8");
      }else if(kind==="plan"){
        download(portablePlanCSV(admitted),"lightup-private-human-vault-plan.csv",
          "text/csv;charset=utf-8");
      }else{
        download(portableCapacityCSV(admitted),"lightup-private-human-vault-capacity.csv",
          "text/csv;charset=utf-8");
      }
      inform("Recovered selected PRIVATE original HUMAN vault component locally. "+
        "No current browser workspace replaced or external target/calendar accessed.");
    }finally{
      if(admitted)admitted.source.fill(0);
      clearVaultPasswords();
    }
  }
  function clearVaultRekeyFields(){
    $("vaultNewPassword").value="";$("vaultNewConfirm").value="";
  }
  async function rekeyPortableVault(file){
    hold(crypto.subtle);
    const oldPassword=$("vaultPassword").value,newPassword=$("vaultNewPassword").value,
      confirmation=$("vaultNewConfirm").value;
    hold(newPassword.length>=16 && newPassword.length<=256 &&
      newPassword===confirmation && newPassword!==oldPassword);
    let opened=null,plaintext=null;
    try{
      opened=await readPortableVault(file,oldPassword);
      const originalPlan=portablePlanCSV(opened),originalCapacity=portableCapacityCSV(opened);
      plaintext=vaultPack(opened.source,originalPlan,originalCapacity);
      const salt=new Uint8Array(16),iv=new Uint8Array(12);
      crypto.getRandomValues(salt);crypto.getRandomValues(iv);
      const key=await handoffKey(newPassword,salt);
      const cipher=new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv,additionalData:VAULT_AAD,tagLength:128},key,plaintext));
      const output=new Uint8Array(VAULT_MAGIC.length+16+12+cipher.length);
      output.set(VAULT_MAGIC,0);output.set(salt,6);
      output.set(iv,22);output.set(cipher,34);
      hold(output.length<=MAX_BYTES);
      if(!confirm("Replace the PASSPHRASE of this separate portable PRIVATE HUMAN file for "+
        opened.sourceRows.length+" original HUMAN rows and "+opened.schedule.size+
        " proposed reminders? A fresh, independent encrypted file will be downloaded. "+
        "The source, proposed appointments, group policy and current opened browser workroom "+
        "are NOT modified. Older copies will STILL decrypt using the previous passphrase."))return;
      download(output,"lightup-private-original-human-vault-rekeyed.luhv",
        "application/octet-stream");
      inform("Separately re-encrypted PRIVATE HUMAN source and complete workroom downloaded with a new "+
        "passphrase. Old copies remain accessible under old credentials; current browser workroom unchanged.");
    }finally{
      if(plaintext)plaintext.fill(0);
      if(opened)opened.source.fill(0);
      clearVaultPasswords();clearVaultRekeyFields();
    }
  }
  async function savePortableVault(){
    hold(active && originalBytes && items.length>0 && !capacityEditorDirty && crypto.subtle &&
      /^[0-9a-f]{64}$/.test(hash));
    const passphrase=$("vaultPassword").value,confirmation=$("vaultConfirm").value;
    hold(passphrase.length>=16 && passphrase.length<=256 && passphrase===confirmation);
    const source=originalBytes,snapshot=workroomFingerprint();
    const digest=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",source)),
      b=>b.toString(16).padStart(2,"0")).join("");
    hold(active && originalBytes===source && snapshot===workroomFingerprint() && digest===hash);
    const plaintext=vaultPack(source,privatePlanCSV(),privateCapacityCSV());
    const salt=new Uint8Array(16),iv=new Uint8Array(12);
    crypto.getRandomValues(salt);crypto.getRandomValues(iv);
    try{
      const key=await handoffKey(passphrase,salt);
      const cipher=new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv,additionalData:VAULT_AAD,tagLength:128},key,plaintext));
      const output=new Uint8Array(VAULT_MAGIC.length+16+12+cipher.length);
      output.set(VAULT_MAGIC,0);output.set(salt,VAULT_MAGIC.length);
      output.set(iv,VAULT_MAGIC.length+16);output.set(cipher,VAULT_MAGIC.length+28);
      hold(output.length<=MAX_BYTES && active && originalBytes===source &&
        snapshot===workroomFingerprint() && !capacityEditorDirty);
      if(!confirm("Download ONE PORTABLE encrypted PRIVATE HUMAN file with ORIGINAL worksheet bytes, "+
        "all proposed appointments AND complete declared group rules? Even the original HUMAN text can "+
        "contain private operations; use only authorized storage and a separate passphrase. "+
        "Original producer, identity, scope, consent and findings are NOT authenticated."))return;
      hold(active && originalBytes===source && snapshot===workroomFingerprint() && !capacityEditorDirty);
      download(output,"lightup-private-original-human-vault.luhv","application/octet-stream");
      changed=false;capacityDirty=false;exportedPlan=true;render();
      inform("Portable PRIVATE original HUMAN worksheet, all reminders and all declared group rules encrypted "+
        "into one locally downloaded file. Store passphrase separately; no server or security target contacted.");
    }finally{plaintext.fill(0);clearVaultPasswords();}
  }
  const WORK_MAGIC=new Uint8Array([76,85,72,87,49,10]); // LUHW1 + LF
  const WORK_AAD=new TextEncoder().encode(
    "lightup.human_calendar.private_workroom.v1|REVIEW_ONLY|NO_AUTHORITY");
  function workroomFingerprint(){
    return JSON.stringify([hash,seriesId,zone,privatePlanCSV(),privateCapacityCSV()]);
  }
  function packWorkroom(planText,capacityText){
    const encoder=new TextEncoder(),a=encoder.encode(planText),b=encoder.encode(capacityText);
    const prefix=encoder.encode("LUHW-PRIVATE-1\n"+a.length+"\n"+b.length+"\n");
    hold(a.length>0 && b.length>0 && prefix.length+a.length+b.length<=MAX_BYTES-64);
    const all=new Uint8Array(prefix.length+a.length+b.length);
    all.set(prefix);all.set(a,prefix.length);all.set(b,prefix.length+a.length);
    a.fill(0);b.fill(0);
    return all;
  }
  function unpackWorkroom(plaintext){
    hold(plaintext.length>0 && plaintext.length<=MAX_BYTES);
    let cursor=0;
    function line(){
      const end=plaintext.indexOf(10,cursor);
      hold(end>cursor && end-cursor<36 && end<96);
      const text=decoder.decode(plaintext.subarray(cursor,end));cursor=end+1;return text;
    }
    hold(line()==="LUHW-PRIVATE-1");
    const count1=line(),count2=line();
    hold(/^[1-9]\d{0,6}$/.test(count1) && /^[1-9]\d{0,6}$/.test(count2));
    const len1=Number(count1),len2=Number(count2);
    hold(cursor+len1+len2===plaintext.length);
    const planText=decoder.decode(plaintext.subarray(cursor,cursor+len1));
    const ruleText=decoder.decode(plaintext.subarray(cursor+len1));
    const admitted=admitPlanText(planText);
    hold(!admitted.legacy && /^[0-9a-f]{32}$/.test(admitted.series));
    const rules=admitCapacityText(ruleText,admitted.series);
    return {schedule:admitted.schedule,series:admitted.series,rules};
  }
  async function saveEncryptedWorkroom(){
    hold(active && crypto.subtle && !capacityEditorDirty);
    const password=$("handoffPassword").value,confirmation=$("handoffConfirm").value;
    hold(password.length>=16 && password.length<=256 && password===confirmation);
    const snapshot=workroomFingerprint(),plain=packWorkroom(privatePlanCSV(),privateCapacityCSV());
    const salt=new Uint8Array(16),iv=new Uint8Array(12);
    crypto.getRandomValues(salt);crypto.getRandomValues(iv);
    try{
      const key=await handoffKey(password,salt);
      const cipher=new Uint8Array(await crypto.subtle.encrypt(
        {name:"AES-GCM",iv,additionalData:WORK_AAD,tagLength:128},key,plain));
      const result=new Uint8Array(WORK_MAGIC.length+salt.length+iv.length+cipher.length);
      result.set(WORK_MAGIC,0);result.set(salt,WORK_MAGIC.length);
      result.set(iv,WORK_MAGIC.length+16);result.set(cipher,WORK_MAGIC.length+28);
      hold(result.length<=MAX_BYTES && snapshot===workroomFingerprint());
      if(!confirm("Download complete encrypted PRIVATE HUMAN schedule AND declared group rules? Original security data, authority, consent and real availability are not authenticated."))return;
      hold(snapshot===workroomFingerprint());
      download(result,"lightup-private-human-complete-workroom.luhw","application/octet-stream");
      changed=false;capacityDirty=false;exportedPlan=true;render();
      inform("Both PRIVATE HUMAN scheduling and declared group rules saved in one encrypted local workroom. Preserve password separately.");
    }finally{plain.fill(0);clearPasswords();}
  }
  function reviewSlotSummary(slot){
    return slot ? slot.day+" "+slot.time+" · "+slot.duration+" min · "+slot.reminder+" min reminder" :
      "(unscheduled)";
  }
  function canonicalCapacity(rule){
    return admitCapacityRule(rule||capacityDefaultRule());
  }
  function reviewCapacitySummary(rule){
    const v=canonicalCapacity(rule);
    return "Days "+v.days.join("/")+" · "+v.start+"–"+v.end+
      " · max "+v.maximum+"/day · blackouts: "+
      (v.blackouts.length?v.blackouts.join(", "):"(none)");
  }
  function changedWorkroomRows(){
    hold(workroomComparison && !capacityEditorDirty &&
      workroomComparison.fingerprint===workroomFingerprint());
    const other=workroomComparison.admitted,rows=[];
    for(const row of items){
      const here=plan.get(row.ordinal),there=other.schedule.get(row.ordinal);
      if(!slotEquals(here,there) && (here||there))
        rows.push(["appointment","HUMAN proposed appointment","#"+row.ordinal,
          reviewSlotSummary(here),reviewSlotSummary(there)]);
    }
    for(const group of capacityGroups()){
      const current=canonicalCapacity(capacityRules.get(group)),
        compared=canonicalCapacity(other.rules.get(group));
      if(JSON.stringify(current)!==JSON.stringify(compared)){
        rows.push(["group","HUMAN declared availability",group||"(unassigned)",
          reviewCapacitySummary(current),reviewCapacitySummary(compared),group]);
      }
    }
    return rows;
  }
  function filteredWorkroomRows(){
    const kind=$("workroomCompareKind").value;
    const q=$("workroomCompareQuery").value.trim().toLocaleLowerCase();
    return changedWorkroomRows().filter(row=>
      (kind==="all"||row[0]===kind) &&
      (!q || row[2].toLocaleLowerCase().includes(q)));
  }
  function reconcileFingerprint(){
    hold(workroomComparison && workroomComparison.fingerprint===workroomFingerprint());
    return JSON.stringify([workroomComparison.fingerprint,
      workroomComparison.admitted.series,
      Array.from(reconcileSelection).sort((a,b)=>a-b),
      Array.from(reconcileGroupSelection).sort((a,b)=>a.localeCompare(b))]);
  }
  function renderReconcilePreview(){
    const body=$("workroomReconcileRows");body.replaceChildren();
    if(reconcileProposal && (!workroomComparison || capacityEditorDirty ||
      reconcileProposal.fingerprint!==reconcileFingerprint())){
      reconcileProposal=null;
    }
    $("applyWorkroomReconcile").disabled=!reconcileProposal ||
      reconcileProposal.warnings.length>0;
    if(!reconcileProposal){
      $("workroomReconcileSummary").textContent=reconcileSelection.size+
        " HUMAN appointments and "+reconcileGroupSelection.size+
        " declared group policies selected. Complete preview required before any local changes.";
      return;
    }
    $("workroomReconcileSummary").textContent=reconcileProposal.slots.size+
      " HUMAN appointments and "+reconcileProposal.rules.size+" declared group policy changes prepared; "+
      reconcileProposal.warnings.length+
      " scheduling warnings. New scheduling conflicts/blocked stages/group-rule violations BLOCK application. "+
      "No current plan or external calendar has been modified.";
    for(const [ordinal,slot] of reconcileProposal.slots){
      const tr=dom("tr"),row=items[ordinal-1];
      const violations=reconcileProposal.perRow.get(ordinal)||[];
      tr.append(dom("td","#"+ordinal+" · "+(row.group||"unassigned")),
        dom("td",reviewSlotSummary(plan.get(ordinal))),
        dom("td",reviewSlotSummary(slot)),
        dom("td",violations.length?violations.join("; "):"Local planning only; no external calendar check"));
      body.append(tr);
    }
    for(const [group,rule] of reconcileProposal.rules){
      const tr=dom("tr"),violations=reconcileProposal.perGroup.get(group)||[];
      tr.append(dom("td","GROUP · "+(group||"(unassigned)")),
        dom("td",reviewCapacitySummary(capacityRules.get(group))),
        dom("td",reviewCapacitySummary(rule)),
        dom("td",violations.length?violations.join("; "):
          "Only declared local HUMAN availability; not real verified owner availability"));
      body.append(tr);
    }
  }
  function prepareWorkroomReconcile(){
    hold(active && workroomComparison && !capacityEditorDirty &&
      workroomComparison.fingerprint===workroomFingerprint());
    const other=workroomComparison.admitted;
    hold(other.series===seriesId &&
      reconcileSelection.size<=32 && reconcileGroupSelection.size<=12 &&
      reconcileSelection.size+reconcileGroupSelection.size>0);
    const next=new Map(plan),slots=new Map(),rules=new Map();
    for(const group of reconcileGroupSelection){
      hold(capacityGroups().includes(group));
      const proposal=other.rules.get(group);
      hold(proposal);
      const current=capacityRules.get(group)||capacityDefaultRule();
      hold(JSON.stringify(admitCapacityRule(current))!==JSON.stringify(admitCapacityRule(proposal)));
      rules.set(group,admitCapacityRule(proposal));
    }
    for(const ordinal of Array.from(reconcileSelection).sort((a,b)=>a-b)){
      hold(Number.isSafeInteger(ordinal)&&ordinal>=1&&ordinal<=items.length);
      const row=items[ordinal-1],current=plan.get(ordinal),proposed=other.schedule.get(ordinal);
      hold(row?.ordinal===ordinal && (current||proposed) && !slotEquals(current,proposed));
      if(proposed)next.set(ordinal,admitSlot(proposed.day,proposed.time,
        proposed.duration,proposed.reminder));
      else next.delete(ordinal);
      slots.set(ordinal,proposed?{...proposed}:null);
    }
    const oldClashes=collisionIds(),newClashes=collisionIds(next);
    const counts=new Map();
    for(const row of items){
      const slot=next.get(row.ordinal);
      if(slot){
        const key=JSON.stringify([row.group,slot.day]);
        counts.set(key,(counts.get(key)||0)+1);
      }
    }
    const warnings=[],perRow=new Map(),perGroup=new Map();
    for(const [ordinal,slot] of slots){
      const row=items[ordinal-1],flags=[];
      if(row.stage==="blocked"){
        flags.push("original HUMAN stage is blocked");
      }
      if(slot){
        flags.push(...weekAvailabilityFlags(row,slot,counts,rules.get(row.group)||null));
        if(newClashes.has(ordinal))flags.push("local reminder overlaps another event");
        if(eventDate(slot.day,slot.time)<new Date())flags.push("compared reminder is in the past");
      }
      // A collision introduced for an existing non-selected ordinal is also disallowed.
      const added=Array.from(newClashes).filter(o=>!oldClashes.has(o));
      if(added.length && !flags.includes("new clashes with existing HUMAN reminders"))
        flags.push("new clashes with existing HUMAN reminders");
      if(flags.length)warnings.push("#"+ordinal+": "+flags.join(", "));
      perRow.set(ordinal,flags);
    }
    for(const [group,rule] of rules){
      const issues=[];
      const relevant=items.filter(row=>row.group===group && next.has(row.ordinal));
      for(const row of relevant){
        const slot=next.get(row.ordinal);
        const flags=weekAvailabilityFlags(row,slot,counts,rule);
        if(flags.length)issues.push("#"+row.ordinal+": "+flags.join(", "));
      }
      if(issues.length)warnings.push("HUMAN group "+(group||"(unassigned)")+
        " conflicts with "+issues.length+" locally scheduled reminders");
      perGroup.set(group,issues);
    }
    reconcileProposal={fingerprint:reconcileFingerprint(),slots,rules,warnings,perRow,perGroup};
    $("workroomReconcileDetails").open=true;
    renderReconcilePreview();
    inform(warnings.length?"Selected HUMAN reminder changes held due to "+warnings.length+
      " local scheduling conflict/policy warnings. Adjust the original HUMAN workroom or select other rows.":
      "Prepared "+slots.size+" exact HUMAN reminder changes and "+rules.size+
      " declared group rules. Review each proposed row and explicitly confirm.",Boolean(warnings.length));
  }
  function applyWorkroomReconcile(){
    hold(active && reconcileProposal && !reconcileProposal.warnings.length &&
      workroomComparison && !capacityEditorDirty &&
      reconcileProposal.fingerprint===reconcileFingerprint());
    const proposal=reconcileProposal.slots,updatedRules=reconcileProposal.rules;
    hold(proposal.size<=32 && updatedRules.size<=12 &&
      proposal.size+updatedRules.size>0);
    if(!confirm("Apply "+proposal.size+" HUMAN reminder changes and "+updatedRules.size+
      " DECLARED HUMAN group policy changes from the compared PRIVATE workroom? "+
      "Changes affect ONLY this unsaved local draft, NOT actual people, original source, security results, "+
      "consent, scope, risk or external calendars. Removed reminders are NOT cancelled externally. "+
      "Explicitly save the complete encrypted .luhw workroom separately afterward."))return;
    hold(reconcileProposal && reconcileProposal.fingerprint===reconcileFingerprint() &&
      !reconcileProposal.warnings.length);
    const upcoming=new Map(plan);
    for(const [ordinal,slot] of proposal){
      if(slot)upcoming.set(ordinal,{...slot});
      else upcoming.delete(ordinal);
    }
    const nextRules=new Map(capacityRules);
    for(const [group,rule] of updatedRules)nextRules.set(group,admitCapacityRule(rule));
    if(proposal.size){plan=upcoming;changed=true;exportedPlan=false;}
    if(updatedRules.size){capacityRules=nextRules;capacityDirty=true;capacityLoadEditor();}
    reconcileProposal=null;reconcileSelection.clear();reconcileGroupSelection.clear();
    workroomComparePage=0;page=0;render();
    inform("Applied "+proposal.size+" reviewed HUMAN appointment changes and "+updatedRules.size+
      " declared group rules locally. Save complete encrypted workroom; no external agenda, security action, or confirmation dispatched.");
  }
  function renderWorkroomComparison(){
    const output=$("workroomCompareRows");if(!output)return;
    output.replaceChildren();
    if(workroomComparison && (capacityEditorDirty ||
      workroomComparison.fingerprint!==workroomFingerprint())){
      workroomComparison=null;workroomComparePage=0;
      $("workroomCompareStatus").textContent=
        "Previous comparison cleared: PRIVATE schedule, declared group policy or editor changed.";
    }
    if(!workroomComparison){
      reconcileProposal=null;reconcileSelection.clear();reconcileGroupSelection.clear();
      renderReconcilePreview();
      $("workroomCompareStatus").textContent="No compared PRIVATE HUMAN workroom loaded. Any earlier private comparison is no longer available.";
      $("comparePrev").disabled=true;$("compareNext").disabled=true;
      $("exportWorkroomDiff").disabled=true;
      return;
    }
    const all=changedWorkroomRows(),visible=filteredWorkroomRows();
    renderReconcilePreview();
    const pages=Math.max(1,Math.ceil(visible.length/50));
    workroomComparePage=Math.max(0,Math.min(workroomComparePage,pages-1));
    $("comparePrev").disabled=workroomComparePage===0;
    $("compareNext").disabled=workroomComparePage>=pages-1;
    $("exportWorkroomDiff").disabled=visible.length===0;
    $("workroomCompareStatus").textContent=all.length+" overall PRIVATE HUMAN differences · "+
      visible.length+" match filter · page "+(workroomComparePage+1)+" of "+pages+
      " · matching original worksheet bytes are UNSIGNED · no automatic changes.";
    for(const row of visible.slice(workroomComparePage*50,(workroomComparePage+1)*50)){
      const tr=dom("tr"),box=dom("input");
      box.type="checkbox";box.disabled=workroomComparison.admitted.series!==seriesId;
      const isAppointment=row[0]==="appointment",ordinal=Number(row[2].replace(/^#/,""));
      const group=row[0]==="group"?row[5]:"";
      box.checked=isAppointment?reconcileSelection.has(ordinal):reconcileGroupSelection.has(group);
      box.setAttribute("aria-label","Select PRIVATE HUMAN "+(isAppointment?"appointment ":"group policy ")+
        row[2]+" for local reconciliation");
      box.addEventListener("change",()=>{
        const selection=isAppointment?reconcileSelection:reconcileGroupSelection;
        const key=isAppointment?ordinal:group;
        if(box.checked)selection.add(key);else selection.delete(key);
        reconcileProposal=null;renderReconcilePreview();
      });
      const cell=dom("td");cell.append(box);tr.append(cell);
      row.slice(1,5).forEach(value=>tr.append(dom("td",value)));
      output.append(tr);
    }
  }
  function exportWorkroomComparisonCsv(){
    const rows=filteredWorkroomRows();
    hold(rows.length>0 && rows.length<=items.length+capacityGroups().length);
    if(!confirm("Export "+rows.length+" filtered PRIVATE HUMAN workroom differences? The CSV contains source-ordinal identifiers and proposed group labels, dates and capacity policy. Even these can be confidential. This is an UNSIGNED HUMAN-only comparison, not independent risk, consent, remediation or source verification."))return;
    hold(rows.length===filteredWorkroomRows().length);
    const safeCell=v=>unsafeText(String(v))?"'"+String(v):String(v);
    const output=[["change_type","original_ordinal_or_unverified_group",
      "current_private_human_proposal","compared_private_human_proposal"],
      ...rows.map(row=>row.slice(1,5).map(safeCell))];
    download(makeCsv(output),"lightup-private-human-workroom-differences.csv","text/csv;charset=utf-8");
    inform("PRIVATE HUMAN changed-only comparison CSV downloaded locally; no file sent or live assessment performed.");
  }
  async function compareEncryptedWorkroom(file){
    hold(active && crypto.subtle && !capacityEditorDirty);
    const initial=workroomFingerprint(),password=$("handoffPassword").value;
    try{
      const admitted=await readEncryptedWorkroom(file,password);
      hold(active && initial===workroomFingerprint() && !capacityEditorDirty);
      if(!confirm("Compare an encrypted PRIVATE HUMAN workroom without changing original appointments or group policies? Matched source fingerprints are unsigned. The local differences may reveal private scheduling information."))return;
      hold(active && initial===workroomFingerprint() && !capacityEditorDirty);
      workroomComparison={fingerprint:initial,admitted};workroomComparePage=0;
      reconcileSelection.clear();reconcileGroupSelection.clear();reconcileProposal=null;
      $("workroomCompareKind").value="all";$("workroomCompareQuery").value="";
      renderWorkroomComparison();
      $("compareWorkroomDetails").open=true;
      inform("Encrypted comparison loaded in browser memory only. No current HUMAN plan, group rules or external calendar changed.");
    }finally{clearPasswords();}
  }
  async function readEncryptedWorkroom(file,password){
    hold(active && crypto.subtle && password.length>=16 && password.length<=256);
    let raw=null,cipher=null,plaintext=null;
    try{
      raw=await bytes(file);
      hold(raw.length>WORK_MAGIC.length+16+12+16 && WORK_MAGIC.every((v,i)=>raw[i]===v));
      const salt=raw.slice(6,22),iv=raw.slice(22,34);cipher=raw.slice(34);
      const key=await handoffKey(password,salt);
      try{
        plaintext=new Uint8Array(await crypto.subtle.decrypt(
          {name:"AES-GCM",iv,additionalData:WORK_AAD,tagLength:128},key,cipher));
      }catch(_){hold(false);}
      return unpackWorkroom(plaintext);
    }finally{
      if(plaintext)plaintext.fill(0);
      if(cipher)cipher.fill(0);
      if(raw)raw.fill(0);
    }
  }
  async function restoreEncryptedWorkroom(file,ticket){
    hold(active && crypto.subtle);
    const initial=workroomFingerprint(),oldPlan=plan,oldSeries=seriesId;
    const password=$("handoffPassword").value;
    try{
      const admitted=await readEncryptedWorkroom(file,password);
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active && initial===workroomFingerprint() && oldPlan===plan && oldSeries===seriesId);
      if(!confirm("Replace ALL local HUMAN appointments and declared group availability with complete encrypted PRIVATE workroom? This authenticates neither identity, consent nor original risk; existing unsaved choices will be overwritten."))return;
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active && initial===workroomFingerprint() && oldPlan===plan && oldSeries===seriesId);
      publicationBaseline=null;changesPage=0;
      $("baselineStatus").textContent="No previous publication loaded.";
      plan=admitted.schedule;seriesId=admitted.series;capacityRules=admitted.rules;
      capacityEditorDirty=false;capacityProposal=null;backlogProposal=null;$("capacityApply").disabled=true;
      changed=false;capacityDirty=false;exportedPlan=true;
      page=0;agendaPage=0;backlogPage=0;
      capacityLoadEditor();render();
      inform("Complete PRIVATE HUMAN schedule and declared group rules restored from original worksheet-bound encrypted file; no authorization conferred.");
    }finally{if(currentWorkspaceReplacement(ticket))clearPasswords();}
  }
  async function decryptPrivatePlan(file,password){
    hold(active && crypto.subtle && password.length>=16 && password.length<=256);
    let raw=null,cipher=null,plaintext=null;
    try{
      raw=await bytes(file);
      hold(raw.length>ENC_MAGIC.length+16+12+16);
      hold(ENC_MAGIC.every((v,i)=>raw[i]===v));
      const salt=raw.slice(6,22),iv=raw.slice(22,34);
      cipher=raw.slice(34);
      const key=await handoffKey(password,salt);
      try{
        plaintext=new Uint8Array(await crypto.subtle.decrypt(
          {name:"AES-GCM",iv,additionalData:ENC_AAD,tagLength:128},key,cipher));
      }catch(_){hold(false);}
      const admitted=admitPlanText(decoder.decode(plaintext));
      hold(!admitted.legacy);
      return admitted;
    }finally{
      if(plaintext)plaintext.fill(0);
      if(cipher)cipher.fill(0);
      if(raw)raw.fill(0);
    }
  }
  async function restoreEncryptedFile(file,ticket){
    hold(active && crypto.subtle);
    const fingerprint=workroomFingerprint(),oldPlan=plan;
    const password=$("handoffPassword").value;
    try{
      const admitted=await decryptPrivatePlan(file,password);
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active && fingerprint===workroomFingerprint() && plan===oldPlan);
      const replacingGroupPolicy=admitted.series!==seriesId;
      if(!confirm("Restore a separate encrypted PRIVATE plan-only file? All existing proposed HUMAN appointment dates will be replaced. "+
        (replacingGroupPolicy?"IMPORTANT: its calendar series differs, so ALL current declared group availability settings will reset to defaults. Save complete .luhw workroom first if needed. ":"Matching calendar series; saved local group rules will be retained. ")+
        "This file is not original source, identity, consent or security verification."))return;
      if(!currentWorkspaceReplacement(ticket))return;
      hold(active && fingerprint===workroomFingerprint() && plan===oldPlan);
      publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
      const previousSeries=seriesId;
      plan=admitted.schedule;seriesId=admitted.series;
      changed=false;exportedPlan=true;page=0;agendaPage=0;
      if(previousSeries!==seriesId)resetCapacity();
      else {capacityProposal=null;$("capacityApply").disabled=true;}
      render();
      inform("Encrypted PRIVATE calendar plan opened and exact original worksheet / timezone readmitted. No assessment authority.");
    }finally{if(currentWorkspaceReplacement(ticket))clearPasswords();}
  }
  async function readEncryptedBaseline(file){
    hold(active && crypto.subtle);
    const originHash=hash,originSeries=seriesId,oldPlan=plan;
    const password=$("baselinePassword").value;
    try{
      const admitted=await decryptPrivatePlan(file,password);
      hold(active && hash===originHash && seriesId===originSeries &&
        plan===oldPlan && admitted.series===originSeries);
      if(!confirm("Compare against this separate encrypted PRIVATE historical HUMAN plan? Its decrypted proposed dates remain solely in browser memory. Current HUMAN plan remains unchanged; no calendar is contacted."))return;
      hold(active && hash===originHash && seriesId===originSeries && plan===oldPlan);
      publicationBaseline=admitted.schedule;changesPage=0;
      $("baselineStatus").textContent="Encrypted historical PRIVATE plan admitted for local comparison; source SHA, series and timezone matched. Not independently authenticated producer.";
      renderChanges();inform("Encrypted prior HUMAN schedule opened for PRIVATE comparison, no current appointments changed.");
    }finally{$("baselinePassword").value="";}
  }
  async function onOriginal(file,ticket){
    const buffer=await bytes(file);
    if(!currentWorkspaceReplacement(ticket)){buffer.fill(0);return;}
    const raw=decoder.decode(buffer);
    hold(!raw.startsWith("\uFEFF"));
    const parsed=original(csv(raw,HEAD.length));
    const h=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",buffer)),b=>b.toString(16).padStart(2,"0")).join("");
    if(!currentWorkspaceReplacement(ticket)){buffer.fill(0);return;}
    if(active && (changed||capacityDirty||capacityEditorDirty) &&
      !confirm("Discard all unsaved PRIVATE HUMAN plan, group availability and group-editor changes?")){buffer.fill(0);return;}
    if(!currentWorkspaceReplacement(ticket)){buffer.fill(0);return;}
    publicationBaseline=null;changesPage=0;workroomComparison=null;
    $("workroomCompareRows").replaceChildren();
    $("baselineStatus").textContent="No previous publication loaded.";
    if(originalBytes)originalBytes.fill(0);
    originalBytes=new Uint8Array(buffer);
    buffer.fill(0);
    items=parsed;hash=h;plan=new Map();seriesId=newSeriesId();exportedPlan=false;active=true;changed=false;page=0;agendaPage=0;workloadPage=0;selectedGroup=null;
    monthAnchor=nowToday().slice(0,7);$("monthGroup").value="";
    backlogProposal=null;
    backlogPage=0;$("backlogView").value="open";$("backlogGroup").value="";$("backlogQuery").value="";$("backlogStart").value=nowToday();
    weekAnchor=nowToday();$("weekGroup").value="";
    $("weekConflicts").checked=false;$("weekConstraints").checked=false;
    $("desk").hidden=false;$("agenda").hidden=false;$("week").hidden=false;$("month").hidden=false;$("backlog").hidden=false;$("workload").hidden=false;$("capacity").hidden=false;$("brief").hidden=false;$("out").hidden=false;$("reset").disabled=false;
    $("identity").textContent=`${items.length} HUMAN rows · unsigned worksheet digest ${hash.slice(0,12)}…`;
    $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
    $("restore").value="";clearPasswords();clearVaultPasswords();clearVaultRekeyFields();
    $("baselinePassword").value="";$("tz").textContent=zone;
    $("agendaHorizon").value="7";$("agendaQuery").value="";$("workloadQuery").value="";
    resetCapacity();render();inform("Original HUMAN worksheet admitted in memory. No actual source authentication or grant verified.");
  }
  async function onRestore(file,ticket){
    hold(active);
    const snapshot=workroomFingerprint(),initialPlan=plan;
    const buffer=await bytes(file);
    if(!currentWorkspaceReplacement(ticket)){buffer.fill(0);return;}
    const raw=decoder.decode(buffer);buffer.fill(0);
    const imported=admitPlanText(raw);
    hold(active && snapshot===workroomFingerprint() && plan===initialPlan);
    const replacingGroupPolicy=imported.series!==seriesId;
    if(!confirm("Restore plan-only CSV and replace ALL local proposed HUMAN appointment dates? "+
      (replacingGroupPolicy?"IMPORTANT: this import changes calendar series and will RESET currently declared group availability to defaults. Save complete encrypted .luhw workroom first if needed. ":"Existing declared HUMAN group availability stays unchanged. ")+
      "Source SHA is unsigned and does not provide permission, identity, verified security status or actual calendar availability."))return;
    if(!currentWorkspaceReplacement(ticket))return;
    hold(active && snapshot===workroomFingerprint() && plan===initialPlan);
    publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
    const previousSeries=seriesId;
    plan=imported.schedule;seriesId=imported.series;exportedPlan=!imported.legacy;page=0;agendaPage=0;changed=false;
    if(previousSeries!==seriesId)resetCapacity();
    else {capacityProposal=null;$("capacityApply").disabled=true;}
    render();
    inform(`Restored ${plan.size} HUMAN reminders. ${imported.legacy?"Legacy plan: save the new v2 plan before repeatable calendar export.":"Stable private calendar identities restored."}`);
  }
  function planExport(){
    download(privatePlanCSV(),"lightup-private-human-followups.csv","text/csv;charset=utf-8");
    changed=false;exportedPlan=true;render();inform("PRIVATE v2 plan downloaded with stable opaque calendar identities; original worksheet unchanged.");
  }
  const icsText=s=>String(s).replaceAll("\\","\\\\").replace(/\r\n|\r|\n/g,"\\n").replaceAll(";","\\;").replaceAll(",","\\,");
  const icsTime=date=>[date.getUTCFullYear(),String(date.getUTCMonth()+1).padStart(2,"0"),
    String(date.getUTCDate()).padStart(2,"0")].join("")+"T"+[date.getUTCHours(),date.getUTCMinutes(),date.getUTCSeconds()].map(v=>String(v).padStart(2,"0")).join("")+"Z";
  function nextIcsSequence(){
    // Stable UID + increasing SEQUENCE lets manual calendar imports replace a prior
    // tentative event. Wall-clock epoch seconds span sessions; the in-memory floor
    // also orders multiple exports made during the same second.
    const wallClock=Math.floor(Date.now()/1000);
    lastIcsSequence=Math.max(wallClock,lastIcsSequence+1);
    return lastIcsSequence;
  }
  function fold(line){
    // RFC5545: fold at <=75 UTF-8 octets, never splitting a code point.
    const textEncoder=new TextEncoder();
    let lines=[],part="",size=0;
    for(const ch of line){
      const n=textEncoder.encode(ch).length;
      if(size+n>75){lines.push(part);part=" ";size=1;}
      part+=ch;size+=n;
    }
    lines.push(part);return lines.join("\r\n");
  }
  function calendarExport(){
    hold(active && plan.size>0);
    if(!exportedPlan){inform("Save or restore the PRIVATE v2 plan before exporting. It preserves stable calendar event IDs on future reopen.",true);return;}
    const include=$("includeAction").checked;
    const conflicts=collisionIds().size;
    if(!confirm(`Export ${plan.size} PRIVATE tentative HUMAN calendar events? ${include?"Your HUMAN next-action texts WILL be included.":"No HUMAN next-action texts will be included."} ${conflicts?conflicts+" overlapping HUMAN reminders remain; calendar export retains those overlaps. ":""} Only import into an authorized private calendar; cloud calendars may synchronize.`))return;
    const now=icsTime(new Date()),sequence=nextIcsSequence(),lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN","CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:LightUp PRIVATE HUMAN Follow-ups"];
    for(const r of items){
      const p=plan.get(r.ordinal);if(!p)continue;
      const start=eventDate(p.day,p.time),end=new Date(start.getTime()+Number(p.duration)*60000);
      const uid=seriesId+"-"+r.ordinal+"@lightup-private.invalid";
      lines.push("BEGIN:VEVENT","UID:"+uid,"SEQUENCE:"+sequence,"DTSTAMP:"+now,"DTSTART:"+icsTime(start),"DTEND:"+icsTime(end),
        "STATUS:TENTATIVE","TRANSP:TRANSPARENT",
        "SUMMARY:"+icsText("PRIVATE HUMAN follow-up #"+r.ordinal),
        "DESCRIPTION:"+icsText("REVIEW_ONLY: source-reported "+r.severity+"; HUMAN stage "+(r.stage||"unset")+"; not a verified security or consent result."+(include?" HUMAN action: "+r.action:"")),
        "X-LIGHTUP-REVIEW-ONLY:TRUE");
      if(Number(p.reminder)>0){lines.push("BEGIN:VALARM","ACTION:DISPLAY","DESCRIPTION:PRIVATE HUMAN follow-up reminder",
        "TRIGGER:-PT"+p.reminder+"M","END:VALARM");}
      lines.push("END:VEVENT");
    }
    lines.push("END:VCALENDAR");
    download(lines.map(fold).join("\r\n")+"\r\n","lightup-private-human-followups.ics","text/calendar;charset=utf-8");
    inform("PRIVATE local tentative events downloaded. Nothing sent or scheduled by LightUp.");
  }
  const htmlEsc=value=>String(value).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  function exportWeeklyBrief(){
    hold(active);
    const inputDate=$("briefDate").value;
    const anchorDate=eventDate(inputDate,"12:00");
    const monday=new Date(anchorDate.getTime());
    monday.setHours(0,0,0,0);
    monday.setDate(monday.getDate()-((monday.getDay()+6)%7));
    const sundayEnd=new Date(monday.getTime());
    sundayEnd.setDate(monday.getDate()+7);
    const dateLabel=date=>[date.getFullYear(),String(date.getMonth()+1).padStart(2,"0"),
      String(date.getDate()).padStart(2,"0")].join("-");
    const onlyFocused=$("briefScope").value==="focused";
    hold(!onlyFocused||selectedGroup!==null);
    const selected=items.filter(row=>!onlyFocused||row.group===selectedGroup);
    const events=selected.filter(row=>{
      const slot=plan.get(row.ordinal);
      if(!slot)return false;
      const when=eventDate(slot.day,slot.time);
      return when>=monday&&when<sundayEnd;
    }).sort((a,b)=>{
      const aSlot=plan.get(a.ordinal),bSlot=plan.get(b.ordinal);
      return (aSlot.day+"T"+aSlot.time).localeCompare(bSlot.day+"T"+bSlot.time)||a.ordinal-b.ordinal;
    });
    const includeNotes=$("briefNotes").checked;
    const notScheduled=selected.filter(row=>!plan.has(row.ordinal)).length;
    const blocked=selected.filter(row=>row.stage==="blocked").length;
    const earlier=selected.filter(row=>{
      const p=plan.get(row.ordinal);
      return p&&eventDate(p.day,p.time)<monday;
    }).length;
    if(!confirm("Download PRIVATE HUMAN weekly coordinator briefing for "+dateLabel(monday)+" – "+
      dateLabel(new Date(sundayEnd.getTime()-1))+"? "+events.length+" proposed appointments, "+
      notScheduled+" unscheduled, "+blocked+" HUMAN-blocked. "+
      (includeNotes?"Your HUMAN action/blocker notes WILL appear (they may include sensitive targets/client data). ":
        "HUMAN action and blocker text WILL NOT appear. ")+
      "Use only a trusted PRIVATE printer/device. No assessed target or grant is authenticated."))return;
    const status=[["Total HUMAN ordinals in selected workroom",selected.length],
      ["Proposed reminders during this week",events.length],
      ["No HUMAN appointment date",notScheduled],
      ["HUMAN stage marked blocked",blocked],
      ["Proposed appointments before this week",earlier]];
    const rows=events.map(row=>{
      const p=plan.get(row.ordinal);
      const main=["#"+row.ordinal,p.day+" "+p.time,p.duration+" min",
        row.severity,row.stage||"(unset)",row.group||"(unassigned)",
        includeNotes?row.action||"—":"(not included)",
        includeNotes?row.blocker||"—":"(not included)"];
      return "<tr>"+main.map(x=>"<td>"+htmlEsc(x)+"</td>").join("")+"</tr>";
    }).join("\n");
    const label=onlyFocused?(selectedGroup||"(unassigned)"):"all HUMAN groups";
    const doc=[
      "<!doctype html>","<html lang=\"en\"><head><meta charset=\"utf-8\">",
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'none'; style-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'\">",
      "<title>LightUp PRIVATE HUMAN weekly briefing</title></head><body>",
      "<header><h1>PRIVATE HUMAN follow-up briefing</h1>",
      "<p>REVIEW_ONLY · INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD · HUMAN proposals, NOT authorization or verified security findings.</p>",
      "<p>Original source, client/operator authentication, consent, risk and work completion are NOT proven by this file.</p></header>",
      "<h2>Local week and disclosure</h2><p>"+htmlEsc(dateLabel(monday))+" to "+
        htmlEsc(dateLabel(new Date(sundayEnd.getTime()-1)))+" · "+htmlEsc(zone)+
        " · selected "+htmlEsc(label)+" · HUMAN note detail "+(includeNotes?"INCLUDED":"OMITTED")+"</p>",
      "<h2>PRIVATE schedule overview (self-reported)</h2><ul>",
      ...status.map(([label,count])=>"<li>"+htmlEsc(label)+": "+count+"</li>"),"</ul>",
      "<h2>Proposed HUMAN reminders</h2><table border=\"1\" cellpadding=\"4\">",
      "<thead><tr><th>Original ordinal</th><th>Local date and time</th><th>Duration</th><th>Source-reported severity</th><th>HUMAN stage</th><th>HUMAN group</th><th>HUMAN next action</th><th>HUMAN blocker</th></tr></thead>",
      "<tbody>"+rows+"</tbody></table>",
      "<footer><p>PRIVATE offline print-only worksheet. No source target identifiers imported by LightUp; original HUMAN text may itself contain confidential details. No automatic sharing, network call or calendar import. Small counts may be sensitive.</p></footer>",
      "</body></html>"
    ].join("\n");
    hold(new TextEncoder().encode(doc).length<=2*MAX_BYTES);
    download(doc,"lightup-private-human-weekly-brief.html","text/html;charset=utf-8");
    inform("PRIVATE scriptless weekly HUMAN coordinator briefing downloaded. Nothing transmitted by LightUp.");
  }
  function countsExport(){
    const stageCounts={blank:0,needs_review:0,discussing:0,blocked:0,documented:0};
    const sevCounts={critical:0,high:0,medium:0,low:0,info:0};
    items.forEach(r=>{stageCounts[r.stage||"blank"]++;sevCounts[r.severity]++;});
    const data={schema:"lightup.human_followup_counts.v1",status:"REVIEW_ONLY",rows:items.length,
      scheduled:plan.size,unscheduled:items.length-plan.size,
      stage_counts:stageCounts,source_reported_severity_counts:sevCounts,
      source_authenticated:false,findings_verified:false,client_consent_verified:false,
      operator_consent_verified:false,authorization_granted:false,approved_for_execution:false};
    if(!confirm("Download counts only? Even small aggregate cohorts can be sensitive and remain PRIVATE."))return;
    download(JSON.stringify(data,null,2)+"\n","lightup-private-human-counts.json","application/json;charset=utf-8");
  }
  function hook(id,event,fn){$(id).addEventListener(event,fn);}
  hook("worksheet","change",async e=>{
    const file=e.target.files[0];if(!file)return;
    const ticket=beginWorkspaceReplacement();
    try{await onOriginal(file,ticket);}
    catch(err){if(currentWorkspaceReplacement(ticket))inform(err.message,true);}
    finally{if(currentWorkspaceReplacement(ticket))e.target.value="";}
  });
  hook("restore","change",async e=>{
    const file=e.target.files[0];if(!file)return;
    const ticket=beginWorkspaceReplacement();
    try{await onRestore(file,ticket);}
    catch(err){if(currentWorkspaceReplacement(ticket))inform(err.message,true);}
    finally{if(currentWorkspaceReplacement(ticket))e.target.value="";}
  });
  hook("encryptedBaseline","change",async e=>{
    try{if(e.target.files[0])await readEncryptedBaseline(e.target.files[0]);}
    catch(_){$("baselinePassword").value="";inform("Encrypted historical PRIVATE plan denied (HOLD); existing planning and comparison remain unchanged.",true);}
    finally{e.target.value="";}
  });
  hook("capacityGroup","change",()=>{
    if(capacityEditorDirty && !confirm("Discard the unsaved HUMAN group editor fields without saving this group?")){
      $("capacityGroup").value=capacityEditingGroup;return;
    }
    capacityLoadEditor();renderWorkspaceSaveStatus();
  });
  ["capacityDaily","capacityStart","capacityEnd"].forEach(id=>
    hook(id,"change",noteCapacityEditorChange));
  hook("capacityBlackout","input",noteCapacityEditorChange);
  document.querySelectorAll('#capacityDays input[type="checkbox"]').forEach(el=>
    el.addEventListener("change",noteCapacityEditorChange));
  hook("capacityStore","click",()=>{
    try{
      const group=$("capacityGroup").value;
      hold(active && capacityGroups().includes(group));
      capacityRules.set(group,capacityEditorRule());capacityDirty=true;capacityEditorDirty=false;
      capacityProposal=null;$("capacityApply").disabled=true;
      render();capacityMessage("PRIVATE HUMAN group availability changed locally. Download the policy or encrypted complete workroom to preserve it.");
    }catch(_){capacityMessage("Human group availability rejected (HOLD). Existing group policy unchanged.",true);}
  });
  hook("capacityDefault","click",()=>{
    if(!active)return;
    capacityRules.delete($("capacityGroup").value);capacityDirty=true;
    capacityProposal=null;$("capacityApply").disabled=true;
    capacityLoadEditor();render();
    capacityMessage("Selected HUMAN group returned to private default weekdays; original appointments unchanged.");
  });
  hook("capacityPreview","click",()=>{
    try{capacityPreview();}
    catch(_){capacityProposal=null;$("capacityApply").disabled=true;
      capacityMessage("HUMAN capacity preview held: check date/horizon/groups and original source state.",true);}
  });
  hook("capacityApply","click",()=>{
    try{capacityApply();}
    catch(_){capacityProposal=null;$("capacityApply").disabled=true;
      capacityMessage("HUMAN capacity proposal no longer matches current original workroom or rules. Preview again.",true);}
  });
  hook("capacityDownload","click",()=>{
    try{capacityExport();}catch(_){capacityMessage("PRIVATE availability policy export held.",true);}
  });
  hook("capacityImport","change",async e=>{
    try{if(e.target.files[0])await capacityImport(e.target.files[0]);}
    catch(_){capacityMessage("PRIVATE rules source binding or content invalid (HOLD). Original capacity rules and current plan unchanged.",true);}
    finally{e.target.value="";}
  });
  ["capacityFirst","capacityHorizon","capacityMode"].forEach(id=>hook(id,"change",()=>{
    capacityProposal=null;$("capacityApply").disabled=true;
    capacityMessage("HUMAN availability preview cleared after date/horizon change.");
  }));
  hook("baselinePlan","change",async e=>{
    try{if(e.target.files[0])await readPublishedBaseline(e.target.files[0]);}
    catch(_){inform("Previous PRIVATE schedule did not match exact worksheet, timezone or series (HOLD).",true);}
    finally{e.target.value="";}
  });
  hook("clearBaseline","click",()=>{
    publicationBaseline=null;changesPage=0;
    $("baselineStatus").textContent="No previous publication loaded.";
    renderChanges();inform("Previous PRIVATE comparison plan discarded from application memory.");
  });
  hook("changePrev","click",()=>{changesPage--;renderChanges();});
  hook("changeNext","click",()=>{changesPage++;renderChanges();});
  hook("exportUpdated","click",()=>{
    try{calendarDiffExport(false);}catch(_){inform("PRIVATE event updates held: save the current v2 plan and select a matching previous publication first.",true);}
  });
  hook("exportChangesCsv","click",()=>{
    try{exportPrivateChangeRegister();}
    catch(_){inform("PRIVATE change register held: load a matching earlier HUMAN plan first.",true);}
  });
  hook("exportCancelled","click",()=>{
    try{calendarDiffExport(true);}catch(_){inform("PRIVATE cancellations held: save the current v2 plan and select a matching previous publication first.",true);}
  });
  hook("compareWorkroom","change",async e=>{
    try{if(e.target.files[0])await compareEncryptedWorkroom(e.target.files[0]);}
    catch(_){clearPasswords();inform("Encrypted comparison refused (HOLD); current HUMAN schedule and group rules untouched.",true);}
    finally{e.target.value="";}
  });
  hook("prepareWorkroomReconcile","click",()=>{
    try{prepareWorkroomReconcile();}
    catch(_){reconcileProposal=null;renderReconcilePreview();
      inform("Selected HUMAN comparison cannot be applied (HOLD). Requires matching original private calendar series, 1–32 changed appointments and no uncommitted policy fields.",true);}
  });
  hook("applyWorkroomReconcile","click",()=>{
    try{applyWorkroomReconcile();}
    catch(_){reconcileProposal=null;renderReconcilePreview();
      inform("Selected HUMAN local reconciliation rejected: preview/source/group policy changed.",true);}
  });
  hook("discardWorkroomReconcile","click",()=>{
    reconcileSelection.clear();reconcileGroupSelection.clear();reconcileProposal=null;
    renderWorkroomComparison();
    inform("All provisional HUMAN comparison selections discarded; original plan unchanged.");
  });
  hook("workroomCompareKind","change",()=>{workroomComparePage=0;renderWorkroomComparison();});
  hook("workroomCompareQuery","input",()=>{workroomComparePage=0;renderWorkroomComparison();});
  hook("comparePrev","click",()=>{workroomComparePage--;renderWorkroomComparison();});
  hook("compareNext","click",()=>{workroomComparePage++;renderWorkroomComparison();});
  hook("exportWorkroomDiff","click",()=>{
    try{exportWorkroomComparisonCsv();}
    catch(_){inform("PRIVATE source-bound HUMAN workroom difference export refused (HOLD).",true);}
  });
  hook("clearWorkroomComparison","click",()=>{
    workroomComparison=null;workroomComparePage=0;
    $("workroomCompareRows").replaceChildren();
    $("workroomCompareStatus").textContent="Compared HUMAN workroom forgotten from browser memory.";
  });
  hook("extractPortableVault","change",async e=>{
    try{if(e.target.files[0])await recoverPortableVaultComponent(e.target.files[0]);}
    catch(_){inform("PRIVATE portable vault component recovery held. "+
      "Only an intact original HUMAN vault with correct passphrase can be extracted.",true);}
    finally{e.target.value="";clearVaultPasswords();}
  });
  hook("rekeyPortableVault","change",async e=>{
    try{if(e.target.files[0])await rekeyPortableVault(e.target.files[0]);}
    catch(_){inform("PRIVATE encrypted portable vault passphrase change refused (HOLD). "+
      "Confirm old/new passphrases, same original HUMAN source, capacity policy and file limit.",true);}
    finally{e.target.value="";clearVaultPasswords();clearVaultRekeyFields();}
  });
  hook("restorePortableVault","change",async e=>{
    const file=e.target.files[0];if(!file)return;
    const ticket=beginWorkspaceReplacement();
    try{await restorePortableVault(file,ticket);}
    catch(_){if(currentWorkspaceReplacement(ticket))inform("Portable PRIVATE ORIGINAL HUMAN vault rejected (HOLD)."+
      " Wrong password, corrupt/oversized data, unsupported version or invalid HUMAN"+
      " source/policy bindings. Prior browser workroom unchanged.",true);}
    finally{if(currentWorkspaceReplacement(ticket)){e.target.value="";clearVaultPasswords();}}
  });
  hook("savePortableVault","click",async()=>{
    try{await savePortableVault();}
    catch(_){inform("Portable PRIVATE original HUMAN workroom could not be encrypted (HOLD). "+
      "Check passphrase, current source, unsaved group editor fields and file size.",true);}
    finally{clearVaultPasswords();}
  });
  hook("encryptWorkroom","click",async()=>{
    try{await saveEncryptedWorkroom();}
    catch(_){clearPasswords();inform("Complete encrypted PRIVATE HUMAN workroom export refused (HOLD).",true);}
  });
  hook("restoreWorkroom","change",async e=>{
    const file=e.target.files[0];if(!file)return;
    const ticket=beginWorkspaceReplacement();
    try{await restoreEncryptedWorkroom(file,ticket);}
    catch(_){if(currentWorkspaceReplacement(ticket)){clearPasswords();inform("Complete workroom refused (HOLD), original source and schedule untouched.",true);}}
    finally{if(currentWorkspaceReplacement(ticket))e.target.value="";}
  });
  hook("encryptPlan","click",async()=>{
    try{await saveEncrypted();}catch(_){clearPasswords();inform("Encrypted PRIVATE plan export refused (HOLD).",true);}
  });
  hook("restoreEncrypted","change",async e=>{
    const file=e.target.files[0];if(!file)return;
    const ticket=beginWorkspaceReplacement();
    try{await restoreEncryptedFile(file,ticket);}
    catch(_){if(currentWorkspaceReplacement(ticket)){clearPasswords();inform("Encrypted PRIVATE plan could not be admitted (HOLD). Original local plans untouched.",true);}}
    finally{if(currentWorkspaceReplacement(ticket))e.target.value="";}
  });
  hook("reset","click",()=>{
    if((changed||capacityDirty||capacityEditorDirty||recipientPolicyDirty)&&
      !confirm("Discard unsaved PRIVATE plan, group availability, recipient window and editor field changes?"))return;
    beginWorkspaceReplacement();
    publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
    clearRecipientWorkspace();$("recipientDesk").hidden=true;
    capacityRules=new Map();capacityDirty=false;capacityEditorDirty=false;capacityProposal=null;$("capacityApply").disabled=true;
    if(originalBytes)originalBytes.fill(0);originalBytes=null;
    items=[];plan=new Map();hash="";seriesId="";exportedPlan=false;active=false;changed=false;agendaPage=0;selectedGroup=null;workloadPage=0;
    weekAnchor="";monthAnchor="";backlogPage=0;backlogProposal=null;workroomComparison=null;
    $("workroomCompareRows").replaceChildren();
    $("desk").hidden=true;$("agenda").hidden=true;$("week").hidden=true;$("month").hidden=true;$("backlog").hidden=true;$("workload").hidden=true;$("capacity").hidden=true;$("brief").hidden=true;$("out").hidden=true;$("reset").disabled=true;
    clearPasswords();clearVaultPasswords();clearVaultRekeyFields();
    $("baselinePassword").value="";$("identity").textContent="No worksheet loaded";inform("PRIVATE workroom discarded from application state.");
  });
  ["severity","stage","status","query"].forEach(id=>hook(id,id==="query"?"input":"change",()=>{page=0;render();}));
  hook("prev","click",()=>{page--;render();});hook("next","click",()=>{page++;render();});
  hook("weekDate","change",()=>{try{startWeek($("weekDate").value);
    weekAnchor=$("weekDate").value;renderWeek();}
    catch(_){$("weekDate").value=weekAnchor;inform("Select a valid local week date.",true);}});
  hook("weekBack","click",()=>{try{weekAnchor=moveDay(weekAnchor,-7);renderWeek();}
    catch(_){inform("Cannot navigate beyond valid local dates.",true);}});
  hook("weekForward","click",()=>{try{weekAnchor=moveDay(weekAnchor,7);renderWeek();}
    catch(_){inform("Cannot navigate beyond valid local dates.",true);}});
  hook("weekToday","click",()=>{weekAnchor=nowToday();renderWeek();});
  hook("monthBack","click",()=>{try{monthAnchor=monthShift(monthAnchor,-1);renderMonth();}
    catch(_){inform("Month range unavailable, no local changes made.",true);}});
  hook("monthNext","click",()=>{try{monthAnchor=monthShift(monthAnchor,1);renderMonth();}
    catch(_){inform("Month range unavailable, no local changes made.",true);}});
  hook("monthToday","click",()=>{monthAnchor=nowToday().slice(0,7);renderMonth();});
  hook("monthGroup","change",renderMonth);
  hook("monthBrief","click",()=>{try{exportMonthBrief("html");}
    catch(_){inform("PRIVATE month report refused; original local plan unchanged.",true);}});
  hook("monthCounts","click",()=>{try{exportMonthBrief("csv");}
    catch(_){inform("PRIVATE month count handoff refused; original local plan unchanged.",true);}});

  hook("backlogPrepare","click",()=>{
    try{prepareBacklogBatch();}catch(_){
      backlogProposal=null;renderBacklogPreview();inform("Complete HUMAN batch proposal rejected; no plan changes made.",true);
    }
  });
  hook("backlogApply","click",()=>{
    try{applyBacklogBatch();}catch(_){
      backlogProposal=null;renderBacklogPreview();inform("HUMAN batch became stale or invalid; no changes made.",true);
    }
  });
  hook("backlogDiscard","click",()=>{
    backlogProposal=null;renderBacklogPreview();$("backlogPreviewDetails").open=false;
    inform("Tentative HUMAN batch preview discarded; original local plan unchanged.");
  });
  hook("backlogStart","change",()=>{
    backlogProposal=null;renderBacklogPreview();
  });
  hook("backlogView","change",()=>{backlogPage=0;renderBacklog();});
  hook("backlogGroup","change",()=>{backlogPage=0;renderBacklog();});
  hook("backlogQuery","input",()=>{backlogPage=0;renderBacklog();});
  hook("backlogPrev","click",()=>{backlogPage--;renderBacklog();});
  hook("backlogNext","click",()=>{backlogPage++;renderBacklog();});

  hook("monthSelect","change",()=>{
    const candidate=$("monthSelect").value;
    if(!/^20\d{2}-(0[1-9]|1[0-2])$/.test(candidate)){
      $("monthSelect").value=monthAnchor;inform("Invalid HUMAN calendar month.",true);return;
    }
    monthAnchor=candidate;renderMonth();
  });
  hook("weekNextDue","click",()=>{try{jumpScheduledWeek(1);}
    catch(_){inform("Could not locate a later HUMAN week under current filters.",true);}});
  hook("weekPrevDue","click",()=>{try{jumpScheduledWeek(-1);}
    catch(_){inform("Could not locate an earlier HUMAN week under current filters.",true);}});

  hook("weekGroup","change",renderWeek);
  hook("weekConflicts","change",renderWeek);
  hook("weekConstraints","change",renderWeek);
  hook("recipientUndo","click",()=>{
    try{undoRecipientProposal();}
    catch(_){recipientUndo=null;$("recipientUndo").disabled=true;
      inform("Last HUMAN adjustment cannot be undone after a workroom change (HOLD).",true);}
  });
  hook("recipientPrepare","click",()=>{
    try{prepareRecipientProposal();}
    catch(err){recipientProposal=null;renderRecipientProposal();
      inform("No complete HUMAN cross-zone proposal: "+err.message,true);}
  });
  hook("recipientApply","click",()=>{
    try{applyRecipientProposal();}
    catch(err){recipientProposal=null;renderRecipientProposal();
      inform("PRIVATE HUMAN cross-zone move refused without changes (HOLD).",true);}
  });
  hook("recipientProposalPrint","click",()=>{
    try{printRecipientProposal();}
    catch(_){inform("PRIVATE HUMAN print handoff refused (HOLD).",true);}
  });
  hook("recipientProposalExport","click",()=>{
    try{exportRecipientProposal();}
    catch(_){inform("PRIVATE common-hours proposal export refused (HOLD).",true);}
  });
  hook("recipientDiscard","click",()=>{recipientProposal=null;recipientSelection.clear();
    renderRecipientProposal();
    $("recipientProposalDetails").open=false;inform("Unapplied HUMAN proposals discarded.");});
  for(const input of ["recipientStart","recipientEnd","recipientDays"]){
    hook(input,"change",()=>{recipientPolicyDirty=true;recipientPage=0;renderRecipientZone();});
  }
  hook("recipientBlackouts","input",()=>{
    recipientPolicyDirty=true;recipientPage=0;renderRecipientZone();
  });
  hook("recipientPolicyExport","click",()=>{
    try{recipientPolicyExport();}
    catch(_){$("recipientPolicyStatus").textContent="PRIVATE recipient preference export held. No external contact or file created."; }
  });
  hook("recipientPolicyImport","change",async e=>{
    try{if(e.target.files?.length)await recipientPolicyImport(e.target.files[0]);}
    catch(_){$("recipientPolicyStatus").textContent="PRIVATE recipient preference import rejected (HOLD). Current HUMAN window and schedule retained.";}
    finally{e.target.value="";}
  });
  hook("recipientCountImport","change",async event=>{
    const file=event.target.files?.[0];event.target.value="";
    if(!file)return;
    try{await importRecipientCounts(file);}
    catch(_){inform("HOLD: previous anonymous count CSV failed canonical, aggregate or current-context admission. No prior values changed.",true);}
  });
  hook("recipientCountExport","click",()=>{
    try{exportRecipientCountComparison();}
    catch(_){inform("HOLD: previous/current anonymous count comparison is no longer valid.",true);}
  });
  hook("recipientCountClear","click",()=>{
    recipientCountBaseline=null;recipientCountImportToken++;
    renderRecipientCountComparison();
    inform("Previous unbound HUMAN count summary discarded from this tab.");
  });
  hook("recipientGroupCsv","click",()=>{try{recipientGroupReport(false);}catch(_){
    inform("HOLD: recipient workload CSV no longer matches the private source.",true);
  }});
  hook("recipientGroupPrint","click",()=>{try{recipientGroupReport(true);}catch(_){
    inform("HOLD: private group review could not be safely created.",true);
  }});
  hook("recipientGroupNextAttention","click",focusNextRecipientGroupAttention);
  hook("recipientGroupClear","click",()=>{
    recipientGroupFocus=null;recipientPage=0;renderRecipientZone();
  });
  hook("recipientGroupPrev","click",()=>{
    recipientGroupPage=Math.max(0,recipientGroupPage-1);renderRecipientZone();
  });
  hook("recipientGroupNext","click",()=>{
    recipientGroupPage++;renderRecipientZone();
  });
  hook("recipientZone","input",()=>{recipientPolicyDirty=true;recipientPage=0;renderRecipientZone();});
  hook("recipientView","change",()=>{recipientPage=0;renderRecipientZone();});
  hook("recipientQuery","input",()=>{recipientPage=0;renderRecipientZone();});
  hook("recipientPrev","click",()=>{recipientPage--;renderRecipientZone();});
  hook("recipientNext","click",()=>{recipientPage++;renderRecipientZone();});
  hook("recipientExport","click",()=>{
    try{exportRecipientZone();}catch(_){inform("PRIVATE recipient-zone handoff not admitted (HOLD).",true);}
  });
  hook("exportTransitions","click",()=>{
    try{exportTransitionDesk();}catch(e){inform(e.message,true);}
  });
  hook("agendaHorizon","change",()=>{agendaPage=0;renderAgenda();});
  hook("agendaQuery","input",()=>{agendaPage=0;renderAgenda();});
  hook("workloadQuery","input",()=>{workloadPage=0;renderWorkload();});
  hook("workloadPrev","click",()=>{workloadPage--;renderWorkload();});
  hook("workloadNext","click",()=>{workloadPage++;renderWorkload();});
  hook("clearGroup","click",()=>{selectedGroup=null;page=0;render();$("desk").scrollIntoView({behavior:"smooth",block:"start"});});
  hook("agendaPrev","click",()=>{agendaPage--;renderAgenda();});
  hook("agendaNext","click",()=>{agendaPage++;renderAgenda();});
  hook("conflictFocus","click",()=>{$("agendaHorizon").value="conflicts";agendaPage=0;renderAgenda();$("agenda").scrollIntoView({behavior:"smooth",block:"start"});});
  hook("resolveConflicts","click",()=>{
    try{resolveConflicts();}
    catch(err){conflictProposal=null;renderConflictPreview();inform("HUMAN group-aware conflict proposal held: "+err.message,true);}
  });
  hook("applyConflictResolution","click",()=>{
    try{applyConflictResolution();}
    catch(_){conflictProposal=null;renderConflictPreview();inform("Conflict proposal is stale or invalid; no partial HUMAN edits applied.",true);}
  });
  hook("exportConflictProposal","click",()=>{
    try{exportConflictProposalCsv();}
    catch(_){inform("PRIVATE original source-bound conflict proposal CSV refused (HOLD).",true);}
  });
  hook("discardConflictResolution","click",()=>{
    conflictProposal=null;renderConflictPreview();$("conflictPreviewDetails").open=false;
    inform("Unapplied HUMAN conflict preview discarded. Current local plan unchanged.");
  });
  function bulk(clear=false){
    const candidates=filtered();
    if(!candidates.length){inform("No matching rows to schedule.",true);return;}
    let slot=null;
    try {if(!clear)slot=admitSlot($("bulkDate").value,$("bulkTime").value,$("bulkDuration").value,$("bulkReminder").value);
      if(!clear)hold(slot!==null);
    }catch(err){inform(err.message,true);return;}
    if(!confirm(`${clear?"Clear dates on":"Schedule"} exactly ${candidates.length} filtered HUMAN rows? Existing dates in this selection will be ${clear?"removed":"replaced"}. This does not change source worksheets.`))return;
    for(const row of candidates){if(clear)plan.delete(row.ordinal);else plan.set(row.ordinal,{...slot});}
    changed=true;exportedPlan=false;render();inform(candidates.length+" HUMAN reminder dates changed in local memory only.");
  }
  function suggestDates(){
    assertLocalZone();
    hold(active);
    const first=$("suggestDate").value,perDay=Number($("suggestDaily").value);
    hold(Number.isSafeInteger(perDay) && perDay>=4 && perDay<=16);
    const firstDate=eventDate(first,"12:00");
    hold(first>=nowToday());
    const unscheduled=filtered().filter(r=>!plan.has(r.ordinal) && r.stage!=="blocked");
    if(!unscheduled.length){inform("No eligible unblocked, unscheduled rows in the current filter.");return;}
    const ranks={critical:0,high:1,medium:2,low:3,info:4};
    unscheduled.sort((a,b)=>ranks[a.severity]-ranks[b.severity] || a.ordinal-b.ordinal);
    const perDate=new Map(),usedTimes=new Map();
    const occupied=eventIntervals();
    for(const p of plan.values()){
      perDate.set(p.day,(perDate.get(p.day)||0)+1);
      if(!usedTimes.has(p.day))usedTimes.set(p.day,new Set());
      usedTimes.get(p.day).add(p.time);
    }
    const proposal=new Map();
    const date=new Date(firstDate.getTime());let index=0;
    for(let n=0;n<850 && index<unscheduled.length;n++){
      const weekday=date.getDay();
      const key=[date.getFullYear(),String(date.getMonth()+1).padStart(2,"0"),String(date.getDate()).padStart(2,"0")].join("-");
      if(weekday!==0 && weekday!==6){
        let count=perDate.get(key)||0;
        const reserved=usedTimes.get(key)||new Set();
        for(let slot=0;slot<16 && count<perDay && index<unscheduled.length;slot++){
          const hour=9+Math.floor(slot*40/60),minute=(slot*40)%60;
          const time=String(hour).padStart(2,"0")+":"+String(minute).padStart(2,"0");
          if(reserved.has(time))continue;
          let suggestion,candidate;
          try{
            suggestion=admitSlot(key,time,"30","15");
            candidate=eventDate(key,time).getTime();
          }catch(_){continue;}
          const end=candidate+30*60000;
          if(occupied.some(o=>candidate<o.end && o.start<end))continue;
          const ordinal=unscheduled[index].ordinal;
          proposal.set(ordinal,suggestion);
          occupied.push({ordinal,start:candidate,end});
          reserved.add(time);count++;index++;
        }
      }
      date.setDate(date.getDate()+1);
    }
    hold(index===unscheduled.length);
    if(!confirm("Propose "+proposal.size+" PRIVATE HUMAN-only weekday reminders? This sorts solely by UNVERIFIED source-reported severity, skips HUMAN blocked rows, respects existing plans, and never changes the original worksheet. No verified urgency or permission is implied."))return;
    for(const [ordinal,slot] of proposal)plan.set(ordinal,slot);
    changed=true;exportedPlan=false;page=0;render();
    inform("Proposed "+proposal.size+" LOCAL HUMAN follow-ups. Review each date before exporting; no calendar was updated.");
  }
  hook("suggest","click",()=>{try{suggestDates();}catch(err){inform(err.message,true);}});
  $("suggestDate").value=nowToday();
  $("briefDate").value=nowToday();
  hook("exportBrief","click",()=>{try{exportWeeklyBrief();}catch(_){inform("PRIVATE weekly HUMAN briefing not admitted (HOLD).",true);}});
  hook("bulkApply","click",()=>bulk(false));hook("bulkClear","click",()=>bulk(true));
  hook("savePlan","click",()=>{try{hold(active);planExport();}catch(err){inform(err.message,true);}});
  hook("calendar","click",()=>{try{calendarExport();}catch(err){inform(err.message,true);}});
  hook("summaryExport","click",()=>{try{hold(active);countsExport();}catch(err){inform(err.message,true);}});
  window.addEventListener("beforeunload",e=>{if(changed||capacityDirty||capacityEditorDirty||recipientPolicyDirty){e.preventDefault();e.returnValue="";}});
  $("tz").textContent=zone;
})();