/* Local browser planning-time normalization only. No scheduling or authorization. */
(function(global){
'use strict';
const DATE=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
function localTimestamp(value){
 if(typeof value!=='string'||!DATE.test(value))return {valid:false,reason:'invalid'};
 const [,y,m,d,h,min]=DATE.exec(value).map(Number);
 if(y<2020||y>2100||m<1||m>12||d<1||d>31||h>23||min>59)return {valid:false,reason:'invalid'};
 const dt=new Date(y,m-1,d,h,min,0,0);
 if(!Number.isFinite(dt.valueOf())||dt.getFullYear()!==y||dt.getMonth()!==m-1||dt.getDate()!==d||
    dt.getHours()!==h||dt.getMinutes()!==min)return {valid:false,reason:'nonexistent_local_time'};
 // A falling DST clock can name two different UTC instants using the same wall time.
 const target=Date.UTC(y,m-1,d,h,min),offset=dt.getTimezoneOffset();
 for(const alt of [new Date(dt.getTime()-86400000).getTimezoneOffset(),new Date(dt.getTime()+86400000).getTimezoneOffset()]){
  if(alt===offset)continue;
  const candidate=new Date(target+alt*60000);
  if(candidate.getTime()!==dt.getTime() && candidate.getFullYear()===y &&
   candidate.getMonth()===m-1&&candidate.getDate()===d&&candidate.getHours()===h&&candidate.getMinutes()===min){
    return {valid:false,reason:'ambiguous_dst_hour'};
  }
 }
 return {valid:true,utc:dt.toISOString(),offset_minutes:offset};
}
function timezone(){
 try {return Intl.DateTimeFormat().resolvedOptions().timeZone||'Browser local (unknown IANA ID)';}
 catch(_){return 'Browser local (unknown IANA ID)';}
}
function resolve(start,end){
 const zone=timezone();
 if(!start&&!end)return {status:'unscheduled',timezone:zone,start:null,end:null};
 if(!start||!end)return {status:'incomplete',timezone:zone,start:null,end:null};
 const a=localTimestamp(start),b=localTimestamp(end);
 if(!a.valid||!b.valid)return {status:!a.valid?a.reason:b.reason,timezone:zone,start:null,end:null};
 if(a.utc>=b.utc)return {status:'reverse_window',timezone:zone,start:null,end:null};
 return {status:'resolved',timezone:zone,start:a.utc,end:b.utc,
  start_offset_minutes:a.offset_minutes,end_offset_minutes:b.offset_minutes};
}
function validateStored(local,window){
 if(window===undefined)return true; // legacy proposal: no absolute window evidence
 if(!window||typeof window!=='object'||Array.isArray(window))return false;
 const allowed=['status','timezone','start','end','start_offset_minutes','end_offset_minutes'];
 if(Object.keys(window).some(k=>!allowed.includes(k)))return false;
 const hasNull=window.status==='unscheduled'||window.status==='incomplete';
 if(hasNull){
   const emptyStart=local&&local.start===null,emptyEnd=local&&local.end===null;
   const correctState=window.status==='unscheduled'?(emptyStart&&emptyEnd):(emptyStart!==emptyEnd);
   return !!correctState&&window.start===null&&window.end===null&&typeof window.timezone==='string'&&window.timezone.length<=100;
 }
 if(window.status!=='resolved'||typeof window.timezone!=='string'||window.timezone.length>100||
    typeof window.start!=='string'||typeof window.end!=='string'||!Number.isInteger(window.start_offset_minutes)||
    !Number.isInteger(window.end_offset_minutes))return false;
 if(window.start_offset_minutes < -840||window.start_offset_minutes>840||
    window.end_offset_minutes < -840||window.end_offset_minutes>840)return false;
 const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/;
 if(!ISO.test(window.start)||!ISO.test(window.end)||window.start>=window.end)return false;
 if(Number.isNaN(Date.parse(window.start))||Number.isNaN(Date.parse(window.end)))return false;
 // Bind imported UTC instants to source-local wall times and recorded offsets.
 // This is a consistency check, not proof of the named timezone's authenticity.
 if(!local||typeof local!=='object'||typeof local.start!=='string'||typeof local.end!=='string')return false;
 const a=DATE.exec(local.start),b=DATE.exec(local.end);
 if(!a||!b)return false;
 const toUTC=(match,minutes)=>{
  const [,year,month,day,hour,minute]=match.map(Number);
  return new Date(Date.UTC(year,month-1,day,hour,minute)+minutes*60000).toISOString();
 };
 try {
  return toUTC(a,window.start_offset_minutes)===window.start &&
         toUTC(b,window.end_offset_minutes)===window.end;
 }catch(_){return false;}
}
function overlaps(a,b){
 if(!a||!b||a.status!=='resolved'||b.status!=='resolved')return null;
 // The import boundary validated wall time/UTC consistency. Compare only bounded ISO instants here.
 const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/;
 if(!ISO.test(a.start)||!ISO.test(a.end)||!ISO.test(b.start)||!ISO.test(b.end))return null;
 return a.start<b.end&&b.start<a.end;
}
global.LightUpPlanningWindow=Object.freeze({localTimestamp,resolve,validateStored,overlaps,timezone});
})(window);
