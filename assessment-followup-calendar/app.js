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
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  const $ = id => document.getElementById(id);
  let items = [], plan = new Map(), hash = "", active = false, changed = false, page = 0, agendaPage = 0;
  let seriesId = "", exportedPlan = false, selectedGroup = null, workloadPage = 0;
  let publicationBaseline = null, changesPage = 0;
  let capacityRules = new Map(), capacityProposal = null;
  const decoder = new TextDecoder("utf-8", {fatal:true});
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
  function eventDate(day,time) {
    hold(/^20\d\d-(0[1-9]|1[0-2])-([0-2]\d|3[01])$/.test(day) && /^([01]\d|2[0-3]):[0-5]\d$/.test(time));
    const [y,m,d]=day.split("-").map(Number),[h,mi]=time.split(":").map(Number);
    const val=new Date(y,m-1,d,h,mi,0,0);
    hold(val.getFullYear()===y && val.getMonth()===m-1 && val.getDate()===d &&
      val.getHours()===h && val.getMinutes()===mi && Number.isFinite(val.getTime()));
    return val;
  }
  function admitSlot(day,time,duration,reminder){
    if(!day){hold(time==="" && duration==="" && reminder==="");return null;}
    const date=eventDate(day,time);
    hold(DURATION.has(duration) && REMINDER.has(reminder));
    hold(Number.isFinite(date.getTime()+Number(duration)*60000));
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
  function render(){
    if(!active)return;
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
    renderWorkload();
    renderChanges();
    renderCapacity();
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
  function resolveConflicts(){
    hold(active);
    const existing=eventIntervals();
    if(!collisionIds().size){inform("No overlaps within this PRIVATE follow-up workroom.");return;}
    const occupied=[],proposal=new Map();
    const startToday=nowToday(),now=Date.now();
    for(const event of existing){
      const previous=plan.get(event.ordinal);
      let target=event;
      if(occupied.some(o=>target.start<o.end && o.start<target.end)){
        if(proposal.size>=32){occupied.push(target);continue;}
        let selected=null;
        const base=eventDate(previous.day,"12:00");
        if(previous.day<startToday)base.setTime(eventDate(startToday,"12:00").getTime());
        for(let day=0;day<90 && !selected;day++){
          const current=new Date(base.getTime());current.setDate(base.getDate()+day);
          if(current.getDay()===0||current.getDay()===6)continue;
          const y=current.getFullYear(),m=String(current.getMonth()+1).padStart(2,"0"),
            d=String(current.getDate()).padStart(2,"0"),date=y+"-"+m+"-"+d;
          for(let minute=9*60;minute<=18*60-Number(previous.duration);minute+=15){
            const hh=String(Math.floor(minute/60)).padStart(2,"0");
            const mm=String(minute%60).padStart(2,"0");
            const time=hh+":"+mm;
            const candidate=eventDate(date,time).getTime(),end=candidate+Number(previous.duration)*60000;
            if(candidate<now || occupied.some(o=>candidate<o.end && o.start<end))continue;
            // Protect all other original HUMAN reservations, not only those seen so far.
            if(existing.some(o=>o.ordinal!==event.ordinal && !proposal.has(o.ordinal) &&
                candidate<o.end && o.start<end))continue;
            selected={slot:{day:date,time,duration:previous.duration,reminder:previous.reminder},
              event:{ordinal:event.ordinal,start:candidate,end}};
            break;
          }
        }
        hold(selected!==null);
        proposal.set(event.ordinal,selected.slot);
        target=selected.event;
      }
      occupied.push(target);
    }
    if(!proposal.size){inform("No schedule changes required.");return;}
    const preview=Array.from(proposal).slice(0,5).map(([ordinal,slot])=>
      "#"+ordinal+" → "+slot.day+" "+slot.time).join("\\n");
    if(!confirm("Propose "+proposal.size+" changes (maximum 32 per confirmation) to overlapping PRIVATE HUMAN reminder dates? First existing appointment retains its slot. Proposed times are weekdays 09:00–18:00, non-overlapping within THIS LOCAL WORKROOM only. No external calendar has been checked or changed.\\n\\n"+preview))return;
    for(const [ordinal,slot] of proposal)plan.set(ordinal,slot);
    changed=true;exportedPlan=false;agendaPage=0;render();
    inform("Rescheduled "+proposal.size+" HUMAN-only reminder proposals. Remaining overlaps are shown; review and repeat if needed. Save the PRIVATE plan before calendar export.");
  }
  function renderAgenda(){
    if(!active)return;
    const now=new Date(),days=$("agendaHorizon").value;
    const q=$("agendaQuery").value.trim().toLocaleLowerCase();
    const colliding=collisionIds();
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
      edit.addEventListener("click",()=>{
        $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
        page=Math.floor((r.ordinal-1)/PAGE);
        render();
        const source=document.querySelector('#rows tr[data-ordinal="'+r.ordinal+'"] input[type="date"]');
        $("desk").scrollIntoView({behavior:"smooth",block:"start"});
        if(source)source.focus({preventScroll:true});
      });
      const cell=dom("td");cell.append(edit);
      tr.append(dom("td",p.day+" "+p.time),dom("td","#"+r.ordinal),
        dom("td",r.severity),dom("td",(r.stage||"unset")+" / "+(r.group||"unassigned")),
        dom("td",r.action||"No HUMAN action supplied"),cell);
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
    const stamp=icsTime(new Date());
    const lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN",
      "CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:LightUp PRIVATE HUMAN Group Follow-ups"];
    for(const row of relevant){
      const slot=plan.get(row.ordinal),start=eventDate(slot.day,slot.time),
        end=new Date(start.getTime()+Number(slot.duration)*60000);
      lines.push("BEGIN:VEVENT","UID:"+seriesId+"-"+row.ordinal+"@lightup-private.invalid",
        "DTSTAMP:"+stamp,"DTSTART:"+icsTime(start),"DTEND:"+icsTime(end),
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
    capacityRules=new Map();
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
    const rule=capacityRules.get($("capacityGroup").value)||capacityDefaultRule();
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
  function capacityExport(){
    hold(active && capacityGroups().length<=256 && /^[0-9a-f]{32}$/.test(seriesId));
    const rows=[CAP_HEAD,...capacityGroups().map(group=>{
      const rule=capacityRules.get(group)||capacityDefaultRule();
      return [hash,seriesId,zone,group,rule.days.join(";"),
        rule.start,rule.end,String(rule.maximum),rule.blackouts.join(";")];
    })];
    if(!confirm("Download the complete source-bound PRIVATE HUMAN group availability policy? This contains HUMAN group labels, time windows and holiday dates. It is UNSIGNED and authorizes no assessment or external calendar access."))return;
    download(makeCsv(rows),"lightup-private-human-capacity.csv","text/csv;charset=utf-8");
    capacityMessage("Source-bound PRIVATE HUMAN availability rules downloaded; not automatically persisted in the browser.");
  }
  async function capacityImport(file){
    hold(active && capacityGroups().length<=256);
    const currentHash=hash,currentSeries=seriesId,currentPlan=plan;
    const raw=decoder.decode(await bytes(file));
    hold(raw.charCodeAt(0)!==0xFEFF);
    const parsed=csv(raw,CAP_HEAD.length);
    hold(JSON.stringify(parsed[0])===JSON.stringify(CAP_HEAD));
    const groups=capacityGroups();
    hold(parsed.length===groups.length+1);
    const next=new Map();
    for(let i=0;i<groups.length;i++){
      const row=parsed[i+1];
      hold(row[0]===currentHash&&row[1]===currentSeries&&row[2]===zone&&row[3]===groups[i]);
      const days=row[4].split(";").map(n=>Number(n));
      hold(row[4]===days.join(";") && /^([1-9]|1[0-2])$/.test(row[7]));
      const blackouts=row[8]?row[8].split(";"):[];
      const rule=admitCapacityRule({days,start:row[5],end:row[6],
        maximum:Number(row[7]),blackouts});
      next.set(row[3],rule);
    }
    if(!confirm("Replace current local HUMAN group availability rules with this exact-worksheet/series/timezone PRIVATE policy? Existing HUMAN appointments and the original worksheet will not change."))return;
    hold(active&&hash===currentHash&&seriesId===currentSeries&&plan===currentPlan);
    capacityRules=next;
    capacityProposal=null;$("capacityApply").disabled=true;
    capacityLoadEditor();renderCapacity();
    capacityMessage("PRIVATE group availability reloaded; existing HUMAN reminders unchanged.");
  }
  function capacityPreview(){
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
          const instant=eventDate(day,time).getTime(),last=instant+30*60000;
          if(instant<=Date.now())continue;
          const busy=taken.get(day)||[];
          if(busy.some(event=>instant<event.end && event.start<last))continue;
          const row=queue.shift(),slot={day,time,duration:"30",reminder:"15"};
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
    const now=icsTime(new Date());
    const lines=["BEGIN:VCALENDAR","VERSION:2.0",
      "PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN",
      "CALSCALE:GREGORIAN","METHOD:"+(cancelled?"CANCEL":"PUBLISH"),
      "X-WR-CALNAME:LightUp PRIVATE HUMAN Changes"];
    const include=$("includeAction").checked;
    for(const row of delta){
      const slot=cancelled?row.before:row.now;
      const start=eventDate(slot.day,slot.time),end=new Date(start.getTime()+Number(slot.duration)*60000);
      const uid=seriesId+"-"+row.ordinal+"@lightup-private.invalid";
      lines.push("BEGIN:VEVENT","UID:"+uid,"SEQUENCE:1","DTSTAMP:"+now,
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
  async function restoreEncryptedFile(file){
    hold(active && crypto.subtle);
    const originHash=hash,originSeries=seriesId,oldPlan=plan;
    const password=$("handoffPassword").value;
    try{
      const admitted=await decryptPrivatePlan(file,password);
      hold(active && hash===originHash && seriesId===originSeries && plan===oldPlan);
      if(changed && !confirm("Replace current unsaved PRIVATE HUMAN reminder dates with the authenticated encrypted plan? This does not prove original-source authenticity."))return;
      hold(active && hash===originHash && seriesId===originSeries && plan===oldPlan);
      publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
      const previousSeries=seriesId;
      plan=admitted.schedule;seriesId=admitted.series;
      changed=false;exportedPlan=true;page=0;agendaPage=0;
      if(previousSeries!==seriesId)resetCapacity();
      else {capacityProposal=null;$("capacityApply").disabled=true;}
      render();
      inform("Encrypted PRIVATE calendar plan opened and exact original worksheet / timezone readmitted. No assessment authority.");
    }finally{clearPasswords();}
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
  async function onOriginal(file){
    const buffer=await bytes(file);
    const raw=decoder.decode(buffer);
    hold(!raw.startsWith("\uFEFF"));
    const parsed=original(csv(raw,HEAD.length));
    const h=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",buffer)),b=>b.toString(16).padStart(2,"0")).join("");
    if(active && changed && !confirm("Discard the current unsaved PRIVATE calendar workroom?"))return;
    publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
    items=parsed;hash=h;plan=new Map();seriesId=newSeriesId();exportedPlan=false;active=true;changed=false;page=0;agendaPage=0;workloadPage=0;selectedGroup=null;
    $("desk").hidden=false;$("agenda").hidden=false;$("workload").hidden=false;$("capacity").hidden=false;$("brief").hidden=false;$("out").hidden=false;$("reset").disabled=false;
    $("identity").textContent=`${items.length} HUMAN rows · unsigned worksheet digest ${hash.slice(0,12)}…`;
    $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
    $("restore").value="";clearPasswords();$("baselinePassword").value="";$("tz").textContent=zone;
    $("agendaHorizon").value="7";$("agendaQuery").value="";$("workloadQuery").value="";
    resetCapacity();render();inform("Original HUMAN worksheet admitted in memory. No actual source authentication or grant verified.");
  }
  async function onRestore(file){
    hold(active);
    const raw=decoder.decode(await bytes(file));
    const imported=admitPlanText(raw);
    if(changed && !confirm("Replace all current unsaved reminder dates with this exact-source PRIVATE plan?"))return;
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
    const now=icsTime(new Date()),lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN","CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:LightUp PRIVATE HUMAN Follow-ups"];
    for(const r of items){
      const p=plan.get(r.ordinal);if(!p)continue;
      const start=eventDate(p.day,p.time),end=new Date(start.getTime()+Number(p.duration)*60000);
      const uid=seriesId+"-"+r.ordinal+"@lightup-private.invalid";
      lines.push("BEGIN:VEVENT","UID:"+uid,"DTSTAMP:"+now,"DTSTART:"+icsTime(start),"DTEND:"+icsTime(end),
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
  hook("worksheet","change",async e=>{try{if(e.target.files[0])await onOriginal(e.target.files[0]);}catch(err){inform(err.message,true);}finally{e.target.value="";}});
  hook("restore","change",async e=>{try{if(e.target.files[0])await onRestore(e.target.files[0]);}catch(err){inform(err.message,true);}finally{e.target.value="";}});
  hook("encryptedBaseline","change",async e=>{
    try{if(e.target.files[0])await readEncryptedBaseline(e.target.files[0]);}
    catch(_){$("baselinePassword").value="";inform("Encrypted historical PRIVATE plan denied (HOLD); existing planning and comparison remain unchanged.",true);}
    finally{e.target.value="";}
  });
  hook("capacityGroup","change",capacityLoadEditor);
  hook("capacityStore","click",()=>{
    try{
      const group=$("capacityGroup").value;
      hold(active && capacityGroups().includes(group));
      capacityRules.set(group,capacityEditorRule());
      capacityProposal=null;$("capacityApply").disabled=true;
      renderCapacity();capacityMessage("PRIVATE HUMAN group availability changed locally. Download the policy to preserve it.");
    }catch(_){capacityMessage("Human group availability rejected (HOLD). Existing group policy unchanged.",true);}
  });
  hook("capacityDefault","click",()=>{
    if(!active)return;
    capacityRules.delete($("capacityGroup").value);
    capacityProposal=null;$("capacityApply").disabled=true;
    capacityLoadEditor();renderCapacity();
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
  hook("encryptPlan","click",async()=>{
    try{await saveEncrypted();}catch(_){clearPasswords();inform("Encrypted PRIVATE plan export refused (HOLD).",true);}
  });
  hook("restoreEncrypted","change",async e=>{
    try{if(e.target.files[0])await restoreEncryptedFile(e.target.files[0]);}
    catch(_){clearPasswords();inform("Encrypted PRIVATE plan could not be admitted (HOLD). Original local plans untouched.",true);}
    finally{e.target.value="";}
  });
  hook("reset","click",()=>{
    if(changed&&!confirm("Discard all unsaved PRIVATE workroom changes?"))return;
    publicationBaseline=null;changesPage=0;$("baselineStatus").textContent="No previous publication loaded.";
    capacityRules=new Map();capacityProposal=null;$("capacityApply").disabled=true;
    items=[];plan=new Map();hash="";seriesId="";exportedPlan=false;active=false;changed=false;agendaPage=0;selectedGroup=null;workloadPage=0;
    $("desk").hidden=true;$("agenda").hidden=true;$("workload").hidden=true;$("capacity").hidden=true;$("brief").hidden=true;$("out").hidden=true;$("reset").disabled=true;
    clearPasswords();$("baselinePassword").value="";$("identity").textContent="No worksheet loaded";inform("PRIVATE workroom discarded from application state.");
  });
  ["severity","stage","status","query"].forEach(id=>hook(id,id==="query"?"input":"change",()=>{page=0;render();}));
  hook("prev","click",()=>{page--;render();});hook("next","click",()=>{page++;render();});
  hook("agendaHorizon","change",()=>{agendaPage=0;renderAgenda();});
  hook("agendaQuery","input",()=>{agendaPage=0;renderAgenda();});
  hook("workloadQuery","input",()=>{workloadPage=0;renderWorkload();});
  hook("workloadPrev","click",()=>{workloadPage--;renderWorkload();});
  hook("workloadNext","click",()=>{workloadPage++;renderWorkload();});
  hook("clearGroup","click",()=>{selectedGroup=null;page=0;render();$("desk").scrollIntoView({behavior:"smooth",block:"start"});});
  hook("agendaPrev","click",()=>{agendaPage--;renderAgenda();});
  hook("agendaNext","click",()=>{agendaPage++;renderAgenda();});
  hook("conflictFocus","click",()=>{$("agendaHorizon").value="conflicts";agendaPage=0;renderAgenda();$("agenda").scrollIntoView({behavior:"smooth",block:"start"});});
  hook("resolveConflicts","click",()=>{try{resolveConflicts();}catch(err){inform(err.message,true);}});
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
          const candidate=eventDate(key,time).getTime(),end=candidate+30*60000;
          if(occupied.some(o=>candidate<o.end && o.start<end))continue;
          const suggestion=admitSlot(key,time,"30","15");
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
  window.addEventListener("beforeunload",e=>{if(changed){e.preventDefault();e.returnValue="";}});
  $("tz").textContent=zone;
})();