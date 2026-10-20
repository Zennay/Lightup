"use strict";
/* Offline PRIVATE, source-free HUMAN calendar companion; no network or storage.
 * Source authority is never inferred from a worksheet byte digest.
 */
(() => {
  const HEAD = ["original_ordinal","source_reported_severity","evidence_reference_count",
    "human_stage","human_owner_group","human_next_action","human_blocker"];
  const PLAN_HEAD = ["worksheet_sha256_unsigned","original_ordinal","local_date",
    "local_time","duration_minutes","reminder_minutes","time_zone"];
  const SEVERITY = new Set(["critical","high","medium","low","info"]);
  const STAGE = new Set(["","needs_review","discussing","blocked","documented"]);
  const DURATION = new Set(["15","30","60","90"]);
  const REMINDER = new Set(["0","15","60","1440"]);
  const MAX_BYTES = 1024*1024, MAX_ROWS = 2048, PAGE = 35;
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  const $ = id => document.getElementById(id);
  let items = [], plan = new Map(), hash = "", active = false, changed = false, page = 0;
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
  function applySlot(ordinal,slot){
    if(slot)plan.set(ordinal,slot);else plan.delete(ordinal);
    changed=true;render();
  }
  function filtered(){
    const severity=$("severity").value,stage=$("stage").value,status=$("status").value;
    const q=$("query").value.trim().toLocaleLowerCase();
    return items.filter(r=>{
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
      const tr=dom("tr"),slot=plan.get(r.ordinal);
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
  }
  function restore(parsed){
    hold(JSON.stringify(parsed[0])===JSON.stringify(PLAN_HEAD));
    hold(parsed.length===items.length+1);
    const next=new Map();
    parsed.slice(1).forEach((r,i)=>{
      hold(r.length===7 && r[0]===hash && r[1]===String(i+1) && r[6]===zone);
      const slot=admitSlot(r[2],r[3],r[4],r[5]);
      if(slot)next.set(i+1,slot);
    });
    return next;
  }
  async function onOriginal(file){
    const buffer=await bytes(file);
    const raw=decoder.decode(buffer);
    hold(!raw.startsWith("\uFEFF"));
    const parsed=original(csv(raw,HEAD.length));
    const h=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",buffer)),b=>b.toString(16).padStart(2,"0")).join("");
    if(active && changed && !confirm("Discard the current unsaved PRIVATE calendar workroom?"))return;
    items=parsed;hash=h;plan=new Map();active=true;changed=false;page=0;
    $("desk").hidden=false;$("out").hidden=false;$("reset").disabled=false;
    $("identity").textContent=`${items.length} HUMAN rows · unsigned worksheet digest ${hash.slice(0,12)}…`;
    $("severity").value="";$("stage").value="";$("status").value="";$("query").value="";
    $("restore").value="";$("tz").textContent=zone;
    render();inform("Original HUMAN worksheet admitted in memory. No actual source authentication or grant verified.");
  }
  async function onRestore(file){
    hold(active);
    const raw=decoder.decode(await bytes(file));
    hold(!raw.startsWith("\uFEFF"));
    const imported=restore(csv(raw,PLAN_HEAD.length));
    if(changed && !confirm("Replace all current unsaved reminder dates with this exact-source PRIVATE plan?"))return;
    plan=imported;page=0;changed=false;render();
    inform(`Restored ${plan.size} HUMAN-only reminders matched to the exact original worksheet and timezone.`);
  }
  function planExport(){
    const rows=[PLAN_HEAD,...items.map(r=>{
      const p=plan.get(r.ordinal);
      return [hash,String(r.ordinal),p?.day||"",p?.time||"",
        p?.duration||"",p?.reminder||"",zone];
    })];
    download(makeCsv(rows),"lightup-private-human-followups.csv","text/csv;charset=utf-8");
    changed=false;render();inform("PRIVATE exact-worksheet-bound plan downloaded; original worksheet unchanged.");
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
    const include=$("includeAction").checked;
    if(!confirm(`Export ${plan.size} PRIVATE tentative HUMAN calendar events? ${include?"Your HUMAN next-action texts WILL be included.":"No HUMAN next-action texts will be included."} Only import into an authorized private calendar; cloud calendars may synchronize.`))return;
    const now=icsTime(new Date()),lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//LightUp//PRIVATE HUMAN Followup Calendar//EN","CALSCALE:GREGORIAN","METHOD:PUBLISH","X-WR-CALNAME:LightUp PRIVATE HUMAN Follow-ups"];
    for(const r of items){
      const p=plan.get(r.ordinal);if(!p)continue;
      const start=eventDate(p.day,p.time),end=new Date(start.getTime()+Number(p.duration)*60000);
      const random=new Uint8Array(16);crypto.getRandomValues(random);
      const uid=Array.from(random,b=>b.toString(16).padStart(2,"0")).join("")+"@lightup-private.invalid";
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
  hook("reset","click",()=>{
    if(changed&&!confirm("Discard all unsaved PRIVATE workroom changes?"))return;
    items=[];plan=new Map();hash="";active=false;changed=false;
    $("desk").hidden=true;$("out").hidden=true;$("reset").disabled=true;
    $("identity").textContent="No worksheet loaded";inform("PRIVATE workroom discarded from application state.");
  });
  ["severity","stage","status","query"].forEach(id=>hook(id,id==="query"?"input":"change",()=>{page=0;render();}));
  hook("prev","click",()=>{page--;render();});hook("next","click",()=>{page++;render();});
  function bulk(clear=false){
    const candidates=filtered();
    if(!candidates.length){inform("No matching rows to schedule.",true);return;}
    let slot=null;
    try {if(!clear)slot=admitSlot($("bulkDate").value,$("bulkTime").value,$("bulkDuration").value,$("bulkReminder").value);
      if(!clear)hold(slot!==null);
    }catch(err){inform(err.message,true);return;}
    if(!confirm(`${clear?"Clear dates on":"Schedule"} exactly ${candidates.length} filtered HUMAN rows? Existing dates in this selection will be ${clear?"removed":"replaced"}. This does not change source worksheets.`))return;
    for(const row of candidates){if(clear)plan.delete(row.ordinal);else plan.set(row.ordinal,{...slot});}
    changed=true;render();inform(candidates.length+" HUMAN reminder dates changed in local memory only.");
  }
  hook("bulkApply","click",()=>bulk(false));hook("bulkClear","click",()=>bulk(true));
  hook("savePlan","click",()=>{try{hold(active);planExport();}catch(err){inform(err.message,true);}});
  hook("calendar","click",()=>{try{calendarExport();}catch(err){inform(err.message,true);}});
  hook("summaryExport","click",()=>{try{hold(active);countsExport();}catch(err){inform(err.message,true);}});
  window.addEventListener("beforeunload",e=>{if(changed){e.preventDefault();e.returnValue="";}});
  $("tz").textContent=zone;
})();